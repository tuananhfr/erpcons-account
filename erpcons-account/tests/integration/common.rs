use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use erpcons_account::{
    Account, BuiltinFeature, Clock, Config, MemorySecretStore, PinnedKey, Product,
    REFRESH_TOKEN_ENTRY, SecretStore, SignedIn, Status, Tier,
};
use pi_mock::{FREE_UBOTCAD, ORG_A, RecordedRequest, Scenario, Server, Tenant};

pub const T0: i64 = 1_792_828_800;
pub const DAY: i64 = 86_400;
pub const PRO: &str = "ubotbuild.cad-use";
pub const VIEW: &str = "ubotbuild.cad-view";
pub const EXPORT: &str = "ubotbuild.cad-export";

pub struct TestClock {
    unix: AtomicI64,
    mono_ms: AtomicU64,
}

impl TestClock {
    pub fn advance(&self, secs: i64) {
        self.unix.fetch_add(secs, Ordering::SeqCst);
        self.mono_ms
            .fetch_add(secs.unsigned_abs() * 1000, Ordering::SeqCst);
    }
    pub fn set_unix(&self, t: i64) {
        self.unix.store(t, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn unix_now(&self) -> i64 {
        self.unix.load(Ordering::SeqCst)
    }
    fn monotonic(&self) -> Duration {
        Duration::from_millis(self.mono_ms.load(Ordering::SeqCst))
    }
}

pub struct Env {
    pub server: Server,
    pub dir: tempfile::TempDir,
    pub store: Arc<MemorySecretStore>,
    pub clock: Arc<TestClock>,
    /// `Config::offline_licensing` of every account this environment makes.
    pub licensing: bool,
}

impl Env {
    pub fn new(scenario: Scenario) -> Self {
        Self::with_store(scenario, MemorySecretStore::new())
    }

    /// With offline licensing turned on (PI's device protocol).
    pub fn licensing(scenario: Scenario) -> Self {
        let mut env = Self::new(scenario);
        env.licensing = true;
        env
    }

    pub fn with_store(mut scenario: Scenario, store: MemorySecretStore) -> Self {
        scenario.now.get_or_insert(T0);
        Self {
            server: Server::start(scenario),
            dir: tempfile::tempdir().unwrap(),
            store: Arc::new(store),
            clock: Arc::new(TestClock {
                unix: AtomicI64::new(T0),
                mono_ms: AtomicU64::new(1_000_000),
            }),
            licensing: false,
        }
    }

    pub fn config(&self, product: Product) -> Config {
        let mut c = Config::new(self.server.issuer(), product, "0.6.5");
        c.platform_keys = vec![PinnedKey {
            kid: self.server.lease_key_id(),
            key: self.server.lease_public_key(),
        }];
        c.offline_licensing = self.licensing;
        c.state_dir = Some(self.dir.path().to_path_buf());
        c.clock = self.clock.clone();
        c.timeout = Duration::from_secs(2);
        c.max_retry_wait = Duration::from_secs(3);
        c.sign_in_timeout = Duration::from_secs(20);
        c.builtin_features.push(BuiltinFeature::new(
            format!("{}.advanced", product.id()),
            Tier::Free,
        ));
        c
    }

    pub fn account(&self) -> Account {
        self.account_for(Product::VanBan)
    }

    pub fn account_for(&self, product: Product) -> Account {
        Account::new(self.config(product), self.store.clone()).unwrap()
    }

    /// UbotCAD, the app that turns licensing on.
    pub fn cad(&self) -> Account {
        self.account_for(Product::UbotBuild)
    }

    /// Moves client wall clock, client monotonic clock and platform time together.
    pub fn advance(&self, secs: i64) {
        self.clock.advance(secs);
        let now = self.clock.unix_now();
        self.server.update_scenario(|s| s.now = Some(now));
    }

    pub fn refresh_token(&self) -> Option<String> {
        self.store.get(REFRESH_TOKEN_ENTRY).unwrap()
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Requests to `path`, oldest first.
    pub fn requests_to(&self, path: &str) -> Vec<RecordedRequest> {
        self.server
            .requests()
            .into_iter()
            .filter(|r| r.path == path)
            .collect()
    }

    /// Claims of the lease stored for `product`.
    pub fn lease_claims(&self, product: &str) -> serde_json::Value {
        let sealed = std::fs::read_to_string(self.file(&format!("lease-{product}.json"))).unwrap();
        let body: serde_json::Value = serde_json::from_str(sealed.lines().next().unwrap()).unwrap();
        let jws = body["lease"].as_str().unwrap();
        let payload = URL_SAFE_NO_PAD
            .decode(jws.split('.').nth(1).unwrap())
            .unwrap();
        serde_json::from_slice(&payload).unwrap()
    }

    pub fn count(&self, method: &str, path: &str) -> usize {
        self.server
            .requests()
            .iter()
            .filter(|r| r.method == method && r.path == path)
            .count()
    }

    /// Query strings of the authorization requests so far, oldest first.
    pub fn authorize_queries(&self) -> Vec<String> {
        self.server
            .requests()
            .into_iter()
            .filter(|r| r.path == "/id/authorize")
            .map(|r| r.query)
            .collect()
    }
}

/// The "system browser": follows the authorization redirect to the loopback listener.
pub fn browser(url: &str) -> Result<(), String> {
    let url = url.to_owned();
    thread::spawn(move || {
        let _ = ureq::get(&url).call();
    });
    Ok(())
}

pub fn sign_in(account: &Account) {
    account.sign_in(browser).unwrap();
}

pub fn signed_in(status: Status) -> SignedIn {
    match status {
        Status::SignedIn(s) => *s,
        other => panic!("expected signed in, got {other:?}"),
    }
}

pub const ACTIVATE: &str = "/api/v1/id/devices/activate";
pub const CHALLENGE: &str = "/api/v1/id/devices/challenge";
pub const REFRESH: &str = "/api/v1/id/licenses/refresh";
pub const ENTITLEMENTS: &str = "/api/v1/id/me/entitlements";

/// UbotBuild free plan of organization A.
pub fn free_tenant() -> Tenant {
    Tenant::new("ten_cad", ORG_A, "ubotbuild", &FREE_UBOTCAD)
}

/// Signed in to organization A, which holds the UbotBuild free plan.
pub fn licensed() -> Scenario {
    Scenario {
        org_choice: Some(ORG_A.into()),
        tenants: vec![free_tenant()],
        ..Scenario::default()
    }
}

/// Organization A's plan with `days`-day leases (pi-mock caps at 7 without `offline-extended`).
pub fn pro_scenario(days: u32) -> Scenario {
    let mut tenant = free_tenant().offline_days(days);
    if days > 7 {
        tenant.features.push("offline-extended".into());
    }
    Scenario {
        tenants: vec![tenant],
        ..licensed()
    }
}

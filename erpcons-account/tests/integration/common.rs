use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

use erpcons_account::{
    Account, BuiltinFeature, Clock, Config, MemorySecretStore, PinnedKey, Product,
    REFRESH_TOKEN_ENTRY, SecretStore, SignedIn, Status, Tier,
};
use pi_mock::{Catalog, Entitlement, Scenario, Server};

pub const T0: i64 = 1_792_828_800;
pub const DAY: i64 = 86_400;
pub const PRO: &str = "vanban.advanced";

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

    /// With the Office contract's offline licensing turned on (pi-mock's `/v1/` endpoints).
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

/// Catalog version 2 of vanban with `vanban.advanced` as `pro`.
pub fn pro_catalog() -> Catalog {
    Catalog {
        product_id: "vanban".into(),
        version: 2,
        features: [
            ("vanban.view", "free"),
            ("vanban.export", "free"),
            ("vanban.use", "free"),
            (PRO, "pro"),
        ]
        .iter()
        .map(|(f, t)| (f.to_string(), t.to_string()))
        .collect(),
    }
}

/// Default user holding `vanban.advanced` offline for `days`, in `org` or personal.
pub fn pro_scenario(org: Option<&str>, days: u32) -> Scenario {
    Scenario {
        entitlements: vec![
            Entitlement::new("ent_adv", pi_mock::DEFAULT_USER, org, PRO).offline_days(Some(days)),
        ],
        catalogs: vec![pro_catalog()],
        ..Scenario::default()
    }
}

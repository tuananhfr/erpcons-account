use std::{
    thread,
    time::{Duration, Instant},
};

use erpcons_account::{
    ApiCode, DEVICE_ENTRY, Error, LicenceState, MemorySecretStore, Product, SecretStore, Status,
};
use pi_mock::{Fault, Scenario};

use crate::common::{Env, PRO, pro_catalog, pro_scenario, sign_in, signed_in};

#[test]
fn refresh_rotates_and_stores_the_new_token() {
    let env = Env::new(Scenario::default());
    sign_in(&env.account());
    let first = env.refresh_token().unwrap();
    // A new process has no access token, so refresh() runs the refresh grant.
    env.account().refresh().unwrap();
    let second = env.refresh_token().unwrap();
    assert_ne!(first, second);
    assert!(!env.server.refresh_family_revoked(&second));
    // Offline licensing is off by default: no Office-contract endpoint is ever called.
    assert!(
        env.server
            .requests()
            .iter()
            .all(|r| !r.path.starts_with("/v1/"))
    );
}

#[test]
fn reuse_detection_signs_out() {
    let env = Env::new(Scenario::default());
    let account = env.account();
    sign_in(&account);
    let stolen = env.refresh_token().unwrap();
    env.account().refresh().unwrap();
    // The stolen, already rotated token is presented again: the platform revokes the family.
    let reply = ureq::post(&format!("{}/id/token", env.server.base_url()))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .config()
        .http_status_as_error(false)
        .build()
        .send(
            format!(
                "grant_type=refresh_token&client_id=erpcons-office-desktop&refresh_token={stolen}"
            )
            .as_bytes(),
        )
        .unwrap();
    assert_eq!(reply.status().as_u16(), 400);

    let next = env.account();
    assert_eq!(next.refresh(), Err(Error::InvalidGrant));
    assert_eq!(next.status(), Status::Guest);
    assert_eq!(env.refresh_token(), None);
    assert!(env.store.get(DEVICE_ENTRY).unwrap().is_some());
    assert!(!env.file("lease-vanban.json").exists());
    account.reload().unwrap();
    assert_eq!(account.status(), Status::Guest);
}

#[test]
fn two_processes_rotate_without_losing_the_session() {
    let env = Env::licensing(Scenario::default());
    let a = env.account();
    sign_in(&a);
    let b = env.account_for(Product::BangTinh);
    assert!(matches!(b.status(), Status::SignedIn(_)));
    for _ in 0..3 {
        // Access tokens expire after 10 min, so each refresh() rotates the shared refresh token.
        env.advance(7200);
        a.refresh().unwrap();
        b.refresh().unwrap();
    }
    for _ in 0..3 {
        env.advance(7200);
        thread::scope(|s| {
            let ha = s.spawn(|| a.refresh());
            let hb = s.spawn(|| b.refresh());
            ha.join().unwrap().unwrap();
            hb.join().unwrap().unwrap();
        });
    }
    let token = env.refresh_token().unwrap();
    assert!(!env.server.refresh_family_revoked(&token));
    assert!(matches!(a.status(), Status::SignedIn(_)));
    assert!(matches!(b.status(), Status::SignedIn(_)));
    assert_eq!(env.server.devices().len(), 1);

    a.sign_out().unwrap();
    b.reload().unwrap();
    assert_eq!(b.status(), Status::Guest);
}

#[test]
fn sign_out_wipes_session_but_keeps_device() {
    let env = Env::licensing(Scenario::default());
    let account = env.account();
    sign_in(&account);
    let token = env.refresh_token().unwrap();
    let device_entry = env.store.get(DEVICE_ENTRY).unwrap();
    let before = account.diagnostics();
    assert!(before.device_id.is_some());

    account.sign_out().unwrap();
    assert_eq!(account.status(), Status::Guest);
    assert_eq!(env.refresh_token(), None);
    assert_eq!(env.store.get(DEVICE_ENTRY).unwrap(), device_entry);
    assert!(!env.file("lease-vanban.json").exists());
    assert!(env.server.refresh_family_revoked(&token));
    assert_eq!(env.count("POST", "/id/revoke"), 1);
    let after = env.account().diagnostics();
    assert_eq!(after.installation_id, before.installation_id);
    assert_eq!(after.device_id, None);

    sign_in(&account);
    assert_eq!(account.diagnostics().device_id, before.device_id);
    assert_eq!(env.server.devices().len(), 1);
}

#[test]
fn credential_store_unavailable_gives_session_only_sign_in() {
    let mut env = Env::with_store(pro_scenario(None, 30), MemorySecretStore::unavailable());
    env.licensing = true;
    let account = env.account();
    sign_in(&account);
    let s = signed_in(account.status());
    assert!(s.session_only);
    assert_eq!(s.licence, LicenceState::SessionOnly);
    assert!(account.allowed(PRO), "online path");
    assert_eq!(env.count("POST", "/v1/devices/challenges"), 0);
    assert_eq!(env.count("POST", "/v1/devices/activate"), 0);
    assert!(!env.file("session.json").exists());
    // Not shared: another app on this machine stays a guest.
    assert_eq!(env.account().status(), Status::Guest);
    account.refresh().unwrap();
    account.sign_out().unwrap();
    assert_eq!(account.status(), Status::Guest);
}

#[test]
fn persistent_401_requires_reauthentication() {
    let env = Env::new(Scenario::default());
    let account = env.account();
    sign_in(&account);
    env.server
        .add_fault(Fault::problem("GET", "/api/v1/id/me", 401, ""));
    let err = account.refresh().unwrap_err();
    assert_eq!(err.api_code_for_test(), Some(ApiCode::Unauthenticated));
    let s = signed_in(account.status());
    assert!(s.reauth_required);
    env.server.clear_faults();
    sign_in(&account);
    assert!(!signed_in(account.status()).reauth_required);
}

#[test]
fn rate_limit_honours_retry_after() {
    let env = Env::new(Scenario::default());
    let account = env.account();
    sign_in(&account);
    env.server.add_fault(
        Fault::problem("GET", "/api/v1/id/me", 429, "")
            .retry_after(1)
            .times(1),
    );
    let started = Instant::now();
    account.refresh().unwrap();
    assert!(started.elapsed() >= Duration::from_secs(1));

    env.server.add_fault(
        Fault::problem("GET", "/api/v1/id/me", 429, "")
            .retry_after(120)
            .times(1),
    );
    let started = Instant::now();
    let err = account.refresh().unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(err.retry_after(), Some(Duration::from_secs(120)));
    assert!(err.is_transient());
}

#[test]
fn service_unavailable_keeps_the_lease() {
    let env = Env::licensing(Scenario::default());
    let account = env.account();
    sign_in(&account);
    let before = env.count("GET", "/v1/me/entitlements");
    env.server.add_fault(Fault::problem(
        "GET",
        "/v1/me/entitlements",
        503,
        "dependency_unavailable",
    ));
    let err = account.refresh().unwrap_err();
    assert_eq!(
        err.api_code_for_test(),
        Some(ApiCode::DependencyUnavailable)
    );
    assert_eq!(
        env.count("GET", "/v1/me/entitlements") - before,
        3,
        "bounded retries"
    );
    assert!(matches!(
        signed_in(account.status()).licence,
        LicenceState::Active { .. }
    ));
}

#[test]
fn guest_allows_free_features_only() {
    let mut catalog = pro_catalog();
    catalog.features[0].1 = "pro".into();
    let env = Env::licensing(Scenario {
        catalogs: vec![catalog],
        ..Scenario::default()
    });
    let account = env.account();
    assert!(account.allowed(PRO), "built-in tier before any catalog");
    account.refresh().unwrap();
    assert_eq!(account.status(), Status::Guest);
    assert!(
        account.allowed("vanban.view"),
        "pinned free beats the catalog"
    );
    assert!(account.allowed("vanban.export"));
    assert!(account.allowed("vanban.use"));
    assert!(!account.allowed(PRO));
    assert!(!account.allowed("vanban.unknown"));
    assert!(!account.allowed("bangtinh.use"));
    // The verified catalog is cached for the next start, offline.
    let offline = env.account();
    assert!(!offline.allowed(PRO));
}

trait CodeOf {
    fn api_code_for_test(&self) -> Option<ApiCode>;
}

impl CodeOf for Error {
    fn api_code_for_test(&self) -> Option<ApiCode> {
        match self {
            Error::Api(e) => Some(e.code.clone()),
            _ => None,
        }
    }
}

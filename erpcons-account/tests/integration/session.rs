use std::{
    thread,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use erpcons_account::{
    ApiCode, DEVICE_ENTRY, Error, LicenceState, MemorySecretStore, SecretStore, Status,
};
use pi_mock::{DEFAULT_USER, Fault, ORG_A, Scenario};
use serde_json::json;

use crate::common::{
    ACTIVATE, CHALLENGE, ENTITLEMENTS, EXPORT, Env, PRO, VIEW, licensed, pro_scenario, sign_in,
    signed_in,
};

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
    // Offline licensing is off by default: no device or entitlement endpoint is ever called.
    assert!(env.server.requests().iter().all(|r| {
        !r.path.starts_with("/api/v1/id/devices")
            && !r.path.starts_with("/api/v1/id/licenses")
            && r.path != ENTITLEMENTS
    }));
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
    let env = Env::licensing(licensed());
    let a = env.cad();
    sign_in(&a);
    let b = env.cad();
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
    assert_eq!(env.server.device_rows().len(), 1);

    a.sign_out().unwrap();
    b.reload().unwrap();
    assert_eq!(b.status(), Status::Guest);
}

#[test]
fn sign_out_wipes_session_but_keeps_device() {
    let env = Env::licensing(licensed());
    let account = env.cad();
    sign_in(&account);
    let token = env.refresh_token().unwrap();
    let device_entry = env.store.get(DEVICE_ENTRY).unwrap();
    let before = account.diagnostics();
    assert!(before.device_id.is_some());

    account.sign_out().unwrap();
    assert_eq!(account.status(), Status::Guest);
    assert_eq!(env.refresh_token(), None);
    assert_eq!(env.store.get(DEVICE_ENTRY).unwrap(), device_entry);
    assert!(!env.file("lease-ubotbuild.json").exists());
    assert!(env.server.refresh_family_revoked(&token));
    assert_eq!(env.count("POST", "/id/revoke"), 1);
    let after = env.cad().diagnostics();
    assert_eq!(after.installation_id, before.installation_id);
    assert_eq!(after.device_id, None);

    sign_in(&account);
    assert_eq!(account.diagnostics().device_id, before.device_id);
    assert_eq!(env.server.device_rows().len(), 1);
}

#[test]
fn credential_store_unavailable_gives_session_only_sign_in() {
    let mut env = Env::with_store(pro_scenario(30), MemorySecretStore::unavailable());
    env.licensing = true;
    let account = env.cad();
    sign_in(&account);
    let s = signed_in(account.status());
    assert!(s.session_only);
    assert_eq!(s.licence, LicenceState::SessionOnly);
    assert!(account.allowed(PRO), "online path");
    assert_eq!(env.count("GET", CHALLENGE), 0);
    assert_eq!(env.count("POST", ACTIVATE), 0);
    assert!(!env.file("session.json").exists());
    // Not shared: another app on this machine stays a guest.
    assert_eq!(env.cad().status(), Status::Guest);
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
    let env = Env::licensing(licensed());
    let account = env.cad();
    sign_in(&account);
    let before = env.count("GET", ENTITLEMENTS);
    env.server
        .add_fault(Fault::problem("GET", ENTITLEMENTS, 503, ""));
    let err = account.refresh().unwrap_err();
    assert_eq!(
        err.api_code_for_test(),
        Some(ApiCode::DependencyUnavailable)
    );
    assert_eq!(
        env.count("GET", ENTITLEMENTS) - before,
        3,
        "bounded retries"
    );
    assert!(matches!(
        signed_in(account.status()).licence,
        LicenceState::Active { .. }
    ));
}

#[test]
fn guest_allows_free_built_in_features_only() {
    let env = Env::licensing(licensed());
    let account = env.cad();
    assert!(account.allowed(VIEW));
    assert!(account.allowed(EXPORT));
    assert!(!account.allowed(PRO));
    account.refresh().unwrap();
    assert_eq!(account.status(), Status::Guest);
    // The built-in tiers decide: no catalog is fetched.
    assert!(env.server.requests().is_empty());
    assert!(!account.allowed("ubotbuild.unknown"));
    assert!(!account.allowed("vanban.use"));
}

#[test]
fn cached_signed_catalog_still_applies() {
    let env = Env::licensing(licensed());
    let key = SigningKey::from_bytes(&pi_mock::dev_lease_seed());
    let header =
        json!({"alg": "EdDSA", "kid": env.server.lease_key_id(), "typ": "pi-feature-catalog+jwt"});
    let payload = json!({
        "iss": env.server.issuer(), "product": "ubotbuild", "catalog_version": 2, "iat": 1,
        "features": [{"feature": PRO, "tier": "free"}, {"feature": VIEW, "tier": "pro"}]
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    let jws = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes())
    );
    std::fs::write(env.file("catalog-ubotbuild.jws"), jws).unwrap();
    let account = env.cad();
    assert!(account.allowed(PRO));
    assert!(account.allowed(VIEW), "pinned free beats the catalog");
}

/// A v0.3.0 session (one `device_id`, Office-contract lease) left on disk by the old wire.
#[test]
fn v030_state_is_discarded_on_upgrade() {
    let mut env = Env::licensing(licensed());
    env.licensing = false;
    sign_in(&env.cad());
    env.licensing = true;
    let entry: serde_json::Value =
        serde_json::from_str(&env.store.get(DEVICE_ENTRY).unwrap().unwrap()).unwrap();
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode(entry["key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let key = SigningKey::from_bytes(&seed);
    let seal = |body: String| {
        let sig = URL_SAFE_NO_PAD.encode(key.sign(body.as_bytes()).to_bytes());
        format!("{body}\n{sig}\n")
    };
    let session = json!({
        "user_id": DEFAULT_USER,
        "org_context": ORG_A,
        "device_id": "dev_old",
        "installation_id": entry["installation_id"],
        "trusted_floor": 0,
        "device_revoked": false,
        "device_cap_reached": false,
        "login_prompt": false,
    });
    std::fs::write(env.file("session.json"), seal(session.to_string())).unwrap();
    let lease = json!({"lease": V030_LEASE, "warnings_shown": []});
    std::fs::write(env.file("lease-ubotbuild.json"), seal(lease.to_string())).unwrap();

    let account = env.cad();
    assert!(!env.file("lease-ubotbuild.json").exists());
    assert_eq!(account.diagnostics().device_id, None);
    account.refresh().unwrap();
    assert_eq!(env.count("POST", ACTIVATE), 1);
    let row = env.server.device_rows().pop().unwrap();
    assert_eq!(account.diagnostics().device_id, Some(row.device_id));
    assert!(matches!(
        signed_in(account.status()).licence,
        LicenceState::Active { .. }
    ));
}

// Activation lease of the v0.3.0 test vectors (docs/contract.openapi.yaml).
const V030_LEASE: &str = "eyJhbGciOiJFZERTQSIsImtpZCI6InBpLWxlYXNlLWV4YW1wbGUtMSIsInR5cCI6InBpLWxlYXNlK2p3dCJ9.eyJpc3MiOiJodHRwczovL2lkLnBpLmludmFsaWQiLCJhdWQiOiJlcnBjb25zLW9mZmljZS1kZXNrdG9wIiwibGVhc2VfaWQiOiJsc2VfMDFKQjdBMkY0SDZLOE0wUDJSNFQ2VjhYMFoiLCJzdWIiOiJ1c3JfMDFKQjZaMks4UTRYTjNUNVY3VzlZMUEyQzMiLCJvcmciOiJvcmdfMDFKQjZaM001UjdUOVYxWDNaNUI3RDlGMUgiLCJkZXZpY2VfaWQiOiJkZXZfMDFKQjdBMEMyRTRHNko4TDBOMlE0UzZVOFciLCJpbnN0YWxsYXRpb25faWQiOiI2ZjFjMmQzZS00YjVhLTRjN2QtOGU5Zi0wYTFiMmMzZDRlNWYiLCJjbmYiOnsiamt0IjoibjVxU3hrSTl3WlcteG9LUU1qanBkbWt0WVRjTG1keUJfbEc5WGFRaHFMTSJ9LCJwcm9kdWN0IjoidmFuYmFuIiwiZmVhdHVyZXMiOlsidmFuYmFuLnVzZSJdLCJlbnRpdGxlbWVudF9pZHMiOlsiZW50XzAxSkI3QTFEM0Y1SDdLOU0xUDNSNVQ3VjlYIl0sIm5iZiI6MTc5MjgyODgwMCwiaWF0IjoxNzkyODI4ODAwLCJleHAiOjE3OTU0MjA4MDAsIm5vbmNlIjoiUkZJZTVHY2xqdUNfTk1mdWhBME1MZ1lFT1RjRGhwS2IyYU4wM3hUeEswQSIsInBvbGljeV92ZXJzaW9uIjoiMjAyNi0xMC0wMS4xIn0.9ErzrUmc2F-ASSgptBdMZXb1cBNDNKvfx1EkVAxGlStKg8wjASj7yZXzCf8yPcHJiaPB05YH7ce3TTBxg4qiAQ";

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

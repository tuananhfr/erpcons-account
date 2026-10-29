//! UbotCAD client family against pi-mock: own client id, product and feature ids.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use erpcons_account::{Error, LicenceState, Product, RevocationReason, Status, VerifyError};
use pi_mock::{DEFAULT_USER, Entitlement, LeaseTamper, Scenario};

use crate::common::{Env, sign_in, signed_in};

const USE: &str = "ubotbuild.cad.use";

fn scenario() -> Scenario {
    Scenario {
        entitlements: vec![Entitlement::new("ent_cad", DEFAULT_USER, None, USE)],
        ..Scenario::default()
    }
}

fn ubotcad(env: &Env) -> erpcons_account::Account {
    env.account_for(Product::UbotBuild)
}

fn lease_claims(env: &Env, product: &str) -> serde_json::Value {
    let sealed = std::fs::read_to_string(env.file(&format!("lease-{product}.json"))).unwrap();
    let body: serde_json::Value = serde_json::from_str(sealed.lines().next().unwrap()).unwrap();
    let jws = body["lease"].as_str().unwrap();
    let payload = URL_SAFE_NO_PAD
        .decode(jws.split('.').nth(1).unwrap())
        .unwrap();
    serde_json::from_slice(&payload).unwrap()
}

#[test]
fn ubotcad_sign_in_uses_its_client() {
    let env = Env::new(Scenario::default());
    let account = ubotcad(&env);
    sign_in(&account);
    let query = &env.authorize_queries()[0];
    assert!(query.contains("client_id=ubotcad-desktop"), "{query}");
    let agent = env
        .server
        .requests()
        .into_iter()
        .find(|r| r.path == "/id/token")
        .and_then(|r| r.user_agent);
    assert_eq!(agent.as_deref(), Some("UbotCAD/0.6.5"));
}

#[test]
fn ubotcad_lease_grants_cad_use() {
    let env = Env::licensing(scenario());
    let account = ubotcad(&env);
    sign_in(&account);
    assert!(account.allowed(USE));
    let claims = lease_claims(&env, "ubotbuild");
    assert_eq!(claims["aud"], "ubotcad-desktop");
    assert_eq!(claims["product"], "ubotbuild");
    let licences = signed_in(account.status()).licences;
    assert_eq!(
        licences.keys().copied().collect::<Vec<_>>(),
        [Product::UbotBuild]
    );
    assert!(matches!(
        licences[&Product::UbotBuild],
        LicenceState::Active { .. }
    ));
}

#[test]
fn ubotcad_revoked_device_keeps_view() {
    let env = Env::licensing(scenario());
    let account = ubotcad(&env);
    sign_in(&account);
    assert!(account.allowed(USE));
    let device = account.diagnostics().device_id.unwrap();
    assert!(env.server.revoke_device(&device));
    env.advance(13 * 3600);
    assert_eq!(
        account.refresh(),
        Err(Error::Revoked(RevocationReason::DeviceRevoked))
    );
    // Online entitlements still grant `use` while fresh; without a lease nothing outlives them.
    env.advance(11 * 60);
    assert!(!account.allowed(USE));
    assert!(account.allowed("ubotbuild.cad.view"));
    assert!(account.allowed("ubotbuild.cad.export"));
}

#[test]
fn ubotcad_suspended_user_signs_out() {
    let env = Env::licensing(scenario());
    let account = ubotcad(&env);
    sign_in(&account);
    env.server.update_scenario(|s| s.users[0].suspended = true);
    assert!(account.refresh().is_err());
    assert_eq!(account.status(), Status::Guest);
}

#[test]
fn office_lease_rejected_by_ubotcad() {
    let env = Env::licensing(Scenario {
        lease_tamper: Some(LeaseTamper::WrongAudience),
        ..scenario()
    });
    let account = ubotcad(&env);
    sign_in(&account);
    assert_eq!(account.refresh(), Err(Error::Lease(VerifyError::Audience)));
    env.advance(11 * 60);
    assert!(!account.allowed(USE));
}

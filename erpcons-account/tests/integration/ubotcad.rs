//! UbotCAD client family against pi-mock: own client id, product and feature ids.
use erpcons_account::{ApiCode, Error, LicenceState, Product, Status, VerifyError};
use pi_mock::{LeaseTamper, Scenario};

use crate::common::{EXPORT, Env, PRO as USE, VIEW, licensed, sign_in, signed_in};

fn scenario() -> Scenario {
    licensed()
}

fn ubotcad(env: &Env) -> erpcons_account::Account {
    env.cad()
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
    let claims = env.lease_claims("ubotbuild");
    assert_eq!(claims["aud"], "ubotcad-desktop");
    assert_eq!(claims["product"], "ubotbuild");
    assert_eq!(claims["features"], serde_json::json!(pi_mock::FREE_UBOTCAD));
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

/// UbotCAD's app id is its PI product code: the 0.5.0 clean-up of app-id files keeps its lease.
#[test]
fn ubotcad_lease_survives_a_new_process() {
    let env = Env::licensing(scenario());
    sign_in(&ubotcad(&env));
    let next = ubotcad(&env);
    assert!(env.file("lease-ubotbuild.json").exists());
    assert!(matches!(
        signed_in(next.status()).licence,
        LicenceState::Active { .. }
    ));
    assert!(next.allowed(USE));
    next.refresh().unwrap();
    assert_eq!(env.count("POST", crate::common::ACTIVATE), 1);
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
    let err = account.refresh().unwrap_err();
    assert!(
        matches!(&err, Error::Api(e) if e.code == ApiCode::DeviceRevoked),
        "{err:?}"
    );
    assert!(!env.file("lease-ubotbuild.json").exists());
    assert_eq!(
        signed_in(account.status()).licences[&Product::UbotBuild],
        LicenceState::DeviceRevoked
    );
    // PI's entitlements still say ALLOW, but they are per user, not per device.
    assert!(!account.allowed(USE));
    assert!(!account.take_refresh_request());
    env.advance(11 * 60);
    assert!(!account.allowed(USE));
    assert!(!account.take_refresh_request());
    // The refresh the app runs on a request must not bring `pro` back either.
    account.refresh().unwrap();
    assert!(!account.allowed(USE));
    assert!(account.allowed(VIEW));
    assert!(account.allowed(EXPORT));
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
    assert!(!env.file("lease-ubotbuild.json").exists());
    assert_eq!(
        signed_in(account.status()).licences[&Product::UbotBuild],
        LicenceState::NotActivated
    );
    // Online entitlements (fresh for 600 s) still grant `use`; the rejected lease adds nothing.
    assert!(account.allowed(USE));
    env.advance(11 * 60);
    assert!(!account.allowed(USE));
}

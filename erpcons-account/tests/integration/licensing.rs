use std::time::Duration;

use erpcons_account::{
    ApiCode, Error, LicenceState, Product, RevocationReason, Status, VerifyError, WarningStage,
};
use pi_mock::{Fault, LeaseTamper, ORG_A, ORG_B, Scenario};

use crate::common::{DAY, Env, PRO, pro_scenario, sign_in, signed_in};

fn licence(account: &erpcons_account::Account) -> LicenceState {
    signed_in(account.status()).licence
}

fn lease_id(account: &erpcons_account::Account) -> String {
    match licence(account) {
        LicenceState::Active { lease_id, .. } => lease_id,
        other => panic!("no active lease: {other:?}"),
    }
}

#[test]
fn four_apps_share_one_device_with_one_lease_each() {
    let env = Env::new(Scenario::default());
    let vanban = env.account();
    sign_in(&vanban);
    let bangtinh = env.account_for(Product::BangTinh);
    bangtinh.refresh().unwrap();
    assert!(matches!(licence(&bangtinh), LicenceState::Active { .. }));
    let devices = env.server.devices();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].products, ["vanban", "bangtinh"]);
    assert!(env.file("lease-vanban.json").exists());
    assert!(env.file("lease-bangtinh.json").exists());
    vanban.reload().unwrap();
    let all = signed_in(vanban.status()).licences;
    assert!(matches!(
        all[&Product::BangTinh],
        LicenceState::Active { .. }
    ));
    assert_eq!(all[&Product::Pdf], LicenceState::NotActivated);
}

#[test]
fn retry_after_timeout_reuses_the_idempotency_key() {
    let env = Env::new(Scenario {
        faults: vec![Fault::delay("POST", "/v1/devices/activate", Duration::from_secs(3)).times(1)],
        ..Scenario::default()
    });
    let account = env.account();
    sign_in(&account);
    assert!(matches!(licence(&account), LicenceState::Active { .. }));
    assert_eq!(env.server.devices().len(), 1);
    let keys: Vec<_> = env
        .server
        .requests()
        .into_iter()
        .filter(|r| r.path == "/v1/devices/activate")
        .map(|r| r.idempotency_key)
        .collect();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1]);
}

#[test]
fn device_cap_blocks_activation_until_user_retry() {
    let env = Env::new(Scenario {
        max_devices: 0,
        ..Scenario::default()
    });
    let account = env.account();
    sign_in(&account);
    assert_eq!(licence(&account), LicenceState::DeviceCapReached);
    let attempts = env.count("POST", "/v1/devices/activate");
    account.refresh().unwrap();
    assert_eq!(env.count("POST", "/v1/devices/activate"), attempts);
    let err = account.retry_activation().unwrap_err();
    assert!(
        matches!(&err, Error::Api(e) if e.code == ApiCode::DeviceCapReached && e.max_devices == Some(0))
    );
    env.server.update_scenario(|s| s.max_devices = 1);
    account.retry_activation().unwrap();
    assert!(matches!(licence(&account), LicenceState::Active { .. }));
}

#[test]
fn forged_or_mismatched_leases_are_rejected() {
    for (tamper, want) in [
        (LeaseTamper::AlteredPayload, VerifyError::Signature),
        (LeaseTamper::UnknownKid, VerifyError::UnknownKey),
        (LeaseTamper::WrongSigningKey, VerifyError::Signature),
        (LeaseTamper::WrongCnf, VerifyError::KeyBinding),
        (LeaseTamper::WrongProduct, VerifyError::Product),
        (LeaseTamper::NbfInFuture, VerifyError::NotYetValid),
        (LeaseTamper::WrongNonce, VerifyError::Nonce),
        (LeaseTamper::WrongIssuer, VerifyError::Issuer),
        (LeaseTamper::CopyMismatch, VerifyError::CopyMismatch),
        (LeaseTamper::OverlongWindow, VerifyError::Validity),
    ] {
        let env = Env::new(Scenario {
            lease_tamper: Some(tamper),
            ..Scenario::default()
        });
        let account = env.account();
        sign_in(&account);
        assert_eq!(licence(&account), LicenceState::NotActivated, "{tamper:?}");
        assert!(!env.file("lease-vanban.json").exists(), "{tamper:?}");
        assert_eq!(account.refresh(), Err(Error::Lease(want)), "{tamper:?}");
    }
}

#[test]
fn rejected_renewal_keeps_the_previous_lease() {
    let env = Env::new(Scenario::default());
    let account = env.account();
    sign_in(&account);
    let first = lease_id(&account);
    env.server
        .update_scenario(|s| s.lease_tamper = Some(LeaseTamper::WrongCnf));
    env.advance(13 * 3600);
    assert_eq!(
        account.refresh(),
        Err(Error::Lease(VerifyError::KeyBinding))
    );
    assert_eq!(lease_id(&account), first);
    env.server.update_scenario(|s| s.lease_tamper = None);
    account.refresh().unwrap();
    assert_ne!(lease_id(&account), first);
}

#[test]
fn expired_lease_denies_pro_and_keeps_free() {
    let env = Env::new(pro_scenario(None, 7));
    let account = env.account();
    sign_in(&account);
    assert!(account.allowed(PRO));
    env.advance(8 * DAY);
    assert!(
        !account.allowed(PRO),
        "offline, lease expired, entitlements stale"
    );
    assert!(account.take_refresh_request());
    for free in ["vanban.view", "vanban.export", "vanban.use"] {
        assert!(account.allowed(free), "{free}");
    }
    assert!(matches!(licence(&account), LicenceState::Inactive { .. }));
}

#[test]
fn clock_rollback_cannot_extend_a_lease() {
    let env = Env::new(pro_scenario(None, 7));
    let account = env.account();
    sign_in(&account);
    env.advance(8 * DAY);
    assert!(!account.allowed(PRO));
    drop(account);
    // Next start: the wall clock was set back to one day after activation.
    env.clock.set_unix(crate::common::T0 + DAY);
    let restarted = env.account();
    assert!(!restarted.allowed(PRO));
    assert!(restarted.diagnostics().clock_rolled_back);
    assert!(matches!(licence(&restarted), LicenceState::Inactive { .. }));
}

#[test]
fn expiry_warnings_at_7_3_1_days_once_each() {
    let env = Env::new(pro_scenario(None, 30));
    let account = env.account();
    sign_in(&account);
    assert_eq!(signed_in(account.status()).warning, None);
    env.advance(23 * DAY + 60);
    let warning = signed_in(account.status()).warning.unwrap();
    assert_eq!(warning.stage, WarningStage::Days7);
    account.mark_warning_shown(WarningStage::Days7).unwrap();
    assert_eq!(signed_in(account.status()).warning, None);
    env.advance(4 * DAY);
    assert_eq!(
        signed_in(account.status()).warning.map(|w| w.stage),
        Some(WarningStage::Days3)
    );
}

#[test]
fn no_warning_while_every_feature_is_free() {
    let mut scenario = pro_scenario(None, 30);
    scenario.catalogs.clear();
    let env = Env::new(scenario);
    let account = env.account();
    sign_in(&account);
    env.advance(29 * DAY);
    assert_eq!(signed_in(account.status()).warning, None);
}

#[test]
fn revoked_device_wipes_every_lease() {
    let env = Env::new(Scenario::default());
    let account = env.account();
    sign_in(&account);
    let other = env.account_for(Product::Pdf);
    other.refresh().unwrap();
    let device = account.diagnostics().device_id.unwrap();
    assert!(env.server.revoke_device(&device));
    env.advance(13 * 3600);
    assert_eq!(
        account.refresh(),
        Err(Error::Revoked(RevocationReason::DeviceRevoked))
    );
    assert!(!env.file("lease-vanban.json").exists());
    assert!(!env.file("lease-pdf.json").exists());
    assert_eq!(licence(&account), LicenceState::DeviceRevoked);
    let calls = env.count("POST", "/v1/devices/activate");
    account.refresh().unwrap();
    other.refresh().unwrap();
    assert_eq!(env.count("POST", "/v1/devices/activate"), calls);
    assert_eq!(licence(&other), LicenceState::DeviceRevoked);
}

#[test]
fn switching_org_switches_entitlements() {
    let env = Env::new(pro_scenario(Some(ORG_A), 30));
    let account = env.account();
    sign_in(&account);
    assert!(!account.allowed(PRO), "personal context holds nothing");

    account.select_org(Some(ORG_A)).unwrap();
    let s = signed_in(account.status());
    assert_eq!(s.active_org.as_deref(), Some(ORG_A));
    assert!(matches!(&s.licence, LicenceState::Active { features, .. } if features == &[PRO]));
    assert!(account.allowed(PRO));

    account.select_org(Some(ORG_B)).unwrap();
    assert!(
        matches!(&licence(&account), LicenceState::Active { features, .. } if features.is_empty())
    );
    assert!(!account.allowed(PRO));

    assert_eq!(
        account.select_org(Some("org_unknown")),
        Err(Error::UnknownOrg)
    );
    account.select_org(None).unwrap();
    assert_eq!(signed_in(account.status()).active_org, None);
    // One device record per context: personal, A and B.
    assert_eq!(env.server.devices().len(), 3);

    let other = env.account_for(Product::BangTinh);
    assert_eq!(signed_in(other.status()).active_org, None);
    assert!(matches!(account.status(), Status::SignedIn(_)));
}

use std::time::Duration;

use erpcons_account::{
    Account, ApiCode, BuiltinFeature, Error, LicenceState, Product, Status, Tier, VerifyError,
    WarningStage,
};
use pi_mock::{DEFAULT_USER, Fault, LeaseTamper, ORG_A, ORG_B, Scenario, Tenant};
use serde_json::Value;

use crate::common::{
    ACTIVATE, CHALLENGE, DAY, ENTITLEMENTS, EXPORT, Env, PRO, REFRESH, VIEW, browser, free_tenant,
    licensed, pro_scenario, sign_in, signed_in,
};

fn licence(account: &Account) -> LicenceState {
    signed_in(account.status()).licence
}

fn lease_id(account: &Account) -> String {
    match licence(account) {
        LicenceState::Active { lease_id, .. } => lease_id,
        other => panic!("no active lease: {other:?}"),
    }
}

fn bodies(env: &Env, path: &str) -> Vec<Value> {
    env.requests_to(path)
        .iter()
        .map(|r| serde_json::from_str(&r.body).unwrap())
        .collect()
}

fn keys(body: &Value) -> Vec<String> {
    let mut keys: Vec<String> = body.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

/// Changes organization A's plan so that its entitlements differ from the current lease.
fn change_plan(env: &Env, add: bool) {
    env.server.update_scenario(|s| {
        let features = &mut s.tenants[0].features;
        if add {
            features.push("cad-3d".into());
        } else {
            features.retain(|f| f != "cad-3d");
        }
    });
}

#[test]
fn activation_uses_pi_wire() {
    let env = Env::licensing(licensed());
    let account = env.cad();
    sign_in(&account);
    let device_calls: Vec<(String, String)> = env
        .server
        .requests()
        .into_iter()
        .filter(|r| r.path.starts_with("/api/v1/id/devices"))
        .map(|r| (r.method, r.path))
        .collect();
    assert_eq!(
        device_calls,
        [
            ("GET".to_owned(), CHALLENGE.to_owned()),
            ("POST".to_owned(), ACTIVATE.to_owned())
        ]
    );
    let body = &bodies(&env, ACTIVATE)[0];
    assert_eq!(
        keys(body),
        [
            "challengeId",
            "clientVersion",
            "devicePublicKey",
            "installationId",
            "platform",
            "productId",
            "signedChallenge"
        ]
    );
    assert_eq!(body["productId"], "ubotbuild");
    match licence(&account) {
        LicenceState::Active { features, .. } => assert_eq!(features, [VIEW, EXPORT, PRO]),
        other => panic!("{other:?}"),
    }
    assert!(account.allowed(PRO));
}

#[test]
fn refresh_sends_nonce_and_binds_lease() {
    let env = Env::licensing(licensed());
    let account = env.cad();
    sign_in(&account);
    env.advance(13 * 3600);
    account.refresh().unwrap();
    let body = bodies(&env, REFRESH).pop().unwrap();
    assert_eq!(keys(&body), ["deviceId", "nonce", "signature", "timestamp"]);
    let nonce = body["nonce"].as_str().unwrap();
    assert_eq!(nonce.len(), 43);
    assert_eq!(env.lease_claims("ubotbuild")["nonce"], nonce);

    let kept = lease_id(&account);
    env.server
        .update_scenario(|s| s.lease_tamper = Some(LeaseTamper::WrongNonce));
    env.advance(13 * 3600);
    assert_eq!(account.refresh(), Err(Error::Lease(VerifyError::Nonce)));
    assert_eq!(lease_id(&account), kept);
}

#[test]
fn refresh_survives_client_clock_skew() {
    let env = Env::licensing(licensed());
    let account = env.cad();
    sign_in(&account);
    env.advance(13 * 3600);
    let platform_now = env.server.scenario().now.unwrap();
    env.clock.set_unix(platform_now + 3600);
    account.refresh().unwrap();
    let body = bodies(&env, REFRESH).pop().unwrap();
    assert_eq!(body["timestamp"], platform_now);
    assert!(matches!(licence(&account), LicenceState::Active { .. }));
}

#[test]
fn refresh_recovers_from_a_timestamp_ahead_of_pi() {
    let env = Env::licensing(licensed());
    let account = env.cad();
    sign_in(&account);
    env.advance(13 * 3600);
    env.server
        .add_fault(Fault::skew_date("GET", ENTITLEMENTS, 3600).times(1));
    account.refresh().unwrap();
    let platform_now = env.server.scenario().now.unwrap();
    let sent: Vec<i64> = bodies(&env, REFRESH)
        .iter()
        .map(|b| b["timestamp"].as_i64().unwrap())
        .collect();
    assert_eq!(sent, [platform_now + 3600, platform_now]);
    assert!(matches!(licence(&account), LicenceState::Active { .. }));

    env.advance(13 * 3600);
    account.refresh().unwrap();
    let last = bodies(&env, REFRESH).pop().unwrap();
    assert_eq!(last["timestamp"], platform_now + 13 * 3600);
}

#[test]
fn refresh_retry_after_timeout_uses_new_timestamp() {
    let env = Env::licensing(licensed());
    let account = env.cad();
    sign_in(&account);
    env.advance(13 * 3600);
    env.server
        .add_fault(Fault::delay("POST", REFRESH, Duration::from_secs(3)).times(1));
    account.refresh().unwrap();
    let sent = bodies(&env, REFRESH);
    let (first, last) = (&sent[0], sent.last().unwrap());
    assert!(sent.len() >= 2);
    assert!(last["timestamp"].as_i64() > first["timestamp"].as_i64());
    assert_ne!(last["nonce"], first["nonce"]);
}

#[test]
fn refresh_twice_in_one_second() {
    let env = Env::licensing(licensed());
    let account = env.cad();
    sign_in(&account);
    env.advance(13 * 3600);
    account.refresh().unwrap();
    change_plan(&env, true);
    account.refresh().unwrap();
    let sent = bodies(&env, REFRESH);
    let first = sent[0]["timestamp"].as_i64().unwrap();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1]["timestamp"].as_i64(), Some(first + 1));

    drop(account);
    let restarted = env.cad();
    change_plan(&env, false);
    restarted.refresh().unwrap();
    let sent = bodies(&env, REFRESH);
    assert_eq!(sent.len(), 3);
    assert_eq!(sent[2]["timestamp"].as_i64(), Some(first + 2));
}

#[test]
fn personal_context_never_activates() {
    let env = Env::licensing(Scenario {
        org_choice: None,
        ..licensed()
    });
    let account = env.cad();
    sign_in(&account);
    account.refresh().unwrap();
    assert!(
        env.server
            .requests()
            .iter()
            .all(|r| !r.path.starts_with("/api/v1/id/devices/"))
    );
    assert_eq!(licence(&account), LicenceState::NotActivated);
}

#[test]
fn no_plan_is_not_entitled_and_keeps_free() {
    let env = Env::licensing(Scenario {
        tenants: Vec::new(),
        ..licensed()
    });
    let account = env.cad();
    sign_in(&account);
    assert_eq!(env.count("POST", ACTIVATE), 1);
    assert_eq!(licence(&account), LicenceState::NotEntitled);
    account.refresh().unwrap();
    assert_eq!(env.count("POST", ACTIVATE), 1);
    assert!(account.allowed(VIEW));
    assert!(account.allowed(EXPORT));
    assert!(!account.allowed(PRO));

    // An unlimited plan has no seat for this account until activation grants one, so
    // entitlements do not lift the block; only the user retry does.
    env.server
        .update_scenario(|s| s.tenants = vec![free_tenant()]);
    account.refresh().unwrap();
    assert_eq!(env.count("POST", ACTIVATE), 1);
    assert_eq!(licence(&account), LicenceState::NotEntitled);
    account.retry_activation().unwrap();
    assert!(matches!(licence(&account), LicenceState::Active { .. }));
    assert!(account.allowed(PRO));
}

#[test]
fn seated_plan_lifts_not_entitled_at_refresh() {
    let env = Env::licensing(Scenario {
        tenants: Vec::new(),
        ..licensed()
    });
    let account = env.cad();
    sign_in(&account);
    assert_eq!(licence(&account), LicenceState::NotEntitled);
    env.server
        .update_scenario(|s| s.tenants = vec![free_tenant().seats(&[DEFAULT_USER])]);
    account.refresh().unwrap();
    assert_eq!(env.count("POST", ACTIVATE), 2);
    assert!(matches!(licence(&account), LicenceState::Active { .. }));
}

#[test]
fn lost_plan_at_refresh_drops_lease() {
    let env = Env::licensing(licensed());
    let account = env.cad();
    sign_in(&account);
    assert!(env.file("lease-ubotbuild.json").exists());
    env.server.update_scenario(|s| s.tenants.clear());
    env.advance(13 * 3600);
    let err = account.refresh().unwrap_err();
    assert!(
        matches!(&err, Error::Api(e) if e.code == ApiCode::NoEntitlement),
        "{err:?}"
    );
    assert!(!env.file("lease-ubotbuild.json").exists());
    assert_eq!(licence(&account), LicenceState::NotEntitled);
    assert!(!account.allowed(PRO));
}

#[test]
fn revoked_at_refresh_blocks_until_sign_in() {
    let env = Env::licensing(licensed());
    let account = env.cad();
    sign_in(&account);
    let device = account.diagnostics().device_id.unwrap();
    assert!(env.server.revoke_device(&device));
    env.advance(13 * 3600);
    let err = account.refresh().unwrap_err();
    assert!(
        matches!(&err, Error::Api(e) if e.code == ApiCode::DeviceRevoked),
        "{err:?}"
    );
    assert_eq!(licence(&account), LicenceState::DeviceRevoked);
    let calls = env.count("POST", ACTIVATE);
    account.refresh().unwrap();
    assert_eq!(env.count("POST", ACTIVATE), calls);

    account.sign_out().unwrap();
    sign_in(&account);
    assert_eq!(env.count("POST", ACTIVATE), calls + 1);
    assert_eq!(licence(&account), LicenceState::DeviceRevoked);
}

#[test]
fn unknown_device_reactivates_once() {
    let env = Env::licensing(licensed());
    let account = env.cad();
    sign_in(&account);
    env.advance(13 * 3600);
    env.server
        .add_fault(Fault::problem("POST", REFRESH, 404, "").times(1));
    account.refresh().unwrap();
    assert_eq!(env.count("POST", ACTIVATE), 2);
    assert!(matches!(licence(&account), LicenceState::Active { .. }));
}

#[test]
fn bare_404_at_refresh_keeps_the_lease() {
    let env = Env::licensing(licensed());
    let account = env.cad();
    sign_in(&account);
    let kept = lease_id(&account);
    env.advance(13 * 3600);
    env.server
        .add_fault(Fault::raw("POST", REFRESH, 404).times(1));
    assert!(account.refresh().is_err());
    assert_eq!(env.count("POST", ACTIVATE), 1);
    assert_eq!(lease_id(&account), kept);
    assert!(env.file("lease-ubotbuild.json").exists());
}

#[test]
fn rejected_timestamps_are_all_undone() {
    let env = Env::licensing(licensed());
    let account = env.cad();
    sign_in(&account);
    env.advance(13 * 3600);
    env.server
        .add_fault(Fault::invalid("POST", REFRESH, "timestamp").times(2));
    let err = account.refresh().unwrap_err();
    assert!(matches!(&err, Error::Api(e) if e.status == 422), "{err:?}");
    // PI saw neither request, so nothing may stay persisted ahead of its clock.
    account.refresh().unwrap();
    let platform_now = env.server.scenario().now.unwrap();
    let sent: Vec<i64> = env
        .requests_to(REFRESH)
        .iter()
        .map(|r| {
            serde_json::from_str::<Value>(&r.body).unwrap()["timestamp"]
                .as_i64()
                .unwrap()
        })
        .collect();
    assert_eq!(sent, [platform_now; 3]);
    assert!(matches!(licence(&account), LicenceState::Active { .. }));
}

#[test]
fn four_apps_get_one_device_row_per_product() {
    let mut scenario = Scenario {
        tenants: vec![
            Tenant::new("ten_vb", ORG_A, "vanban", &["use", "offline"]),
            Tenant::new("ten_bt", ORG_A, "bangtinh", &["use", "offline"]),
        ],
        ..licensed()
    };
    scenario
        .products
        .extend(["vanban".into(), "bangtinh".into()]);
    let env = Env::licensing(scenario);
    let vanban = env.account();
    sign_in(&vanban);
    let bangtinh = env.account_for(Product::BangTinh);
    bangtinh.refresh().unwrap();
    assert!(matches!(licence(&bangtinh), LicenceState::Active { .. }));
    let rows = env.server.device_rows();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter().map(|r| r.product.as_str()).collect::<Vec<_>>(),
        ["vanban", "bangtinh"]
    );
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
    let env = Env::licensing(Scenario {
        faults: vec![Fault::delay("POST", ACTIVATE, Duration::from_secs(3)).times(1)],
        ..licensed()
    });
    let account = env.cad();
    sign_in(&account);
    assert!(matches!(licence(&account), LicenceState::Active { .. }));
    assert_eq!(env.server.device_rows().len(), 1);
    let keys: Vec<_> = env
        .requests_to(ACTIVATE)
        .into_iter()
        .map(|r| r.idempotency_key)
        .collect();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1]);
}

#[test]
fn device_cap_blocks_activation_until_user_retry() {
    let env = Env::licensing(Scenario {
        tenants: vec![free_tenant().device_cap(0)],
        ..licensed()
    });
    let account = env.cad();
    sign_in(&account);
    assert_eq!(licence(&account), LicenceState::DeviceCapReached);
    let attempts = env.count("POST", ACTIVATE);
    account.refresh().unwrap();
    assert_eq!(env.count("POST", ACTIVATE), attempts);
    let err = account.retry_activation().unwrap_err();
    assert!(matches!(&err, Error::Api(e) if e.code == ApiCode::DeviceCapReached));
    env.server
        .update_scenario(|s| s.tenants = vec![free_tenant().device_cap(1)]);
    account.retry_activation().unwrap();
    assert!(matches!(licence(&account), LicenceState::Active { .. }));
}

#[test]
fn device_cap_denies_pro_even_with_fresh_entitlements() {
    let env = Env::licensing(Scenario {
        tenants: vec![free_tenant().device_cap(0)],
        ..licensed()
    });
    let account = env.cad();
    sign_in(&account);
    assert_eq!(licence(&account), LicenceState::DeviceCapReached);
    assert!(!account.allowed(PRO));
    assert!(account.allowed(VIEW));
    // A refresh does not activate while the cap flag is set, so asking for one would only loop.
    assert!(!account.take_refresh_request());
    env.advance(11 * 60);
    account.refresh().unwrap();
    assert!(!account.allowed(PRO));
    env.server
        .update_scenario(|s| s.tenants = vec![free_tenant().device_cap(1)]);
    account.retry_activation().unwrap();
    assert!(account.allowed(PRO));
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
        (LeaseTamper::BadFeatureCode, VerifyError::Feature),
        (LeaseTamper::MissingAudience, VerifyError::Claims),
    ] {
        let env = Env::licensing(Scenario {
            lease_tamper: Some(tamper),
            ..licensed()
        });
        let account = env.cad();
        sign_in(&account);
        assert_eq!(licence(&account), LicenceState::NotActivated, "{tamper:?}");
        assert!(!env.file("lease-ubotbuild.json").exists(), "{tamper:?}");
        assert_eq!(account.refresh(), Err(Error::Lease(want)), "{tamper:?}");
    }
}

#[test]
fn rejected_renewal_keeps_the_previous_lease() {
    let env = Env::licensing(licensed());
    let account = env.cad();
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
    let env = Env::licensing(pro_scenario(7));
    let account = env.cad();
    sign_in(&account);
    assert!(account.allowed(PRO));
    env.advance(8 * DAY);
    assert!(
        !account.allowed(PRO),
        "offline, lease expired, entitlements stale"
    );
    assert!(account.take_refresh_request());
    for free in [VIEW, EXPORT] {
        assert!(account.allowed(free), "{free}");
    }
    assert!(matches!(licence(&account), LicenceState::Inactive { .. }));
}

#[test]
fn clock_rollback_cannot_extend_a_lease() {
    let env = Env::licensing(pro_scenario(7));
    let account = env.cad();
    sign_in(&account);
    env.advance(8 * DAY);
    assert!(!account.allowed(PRO));
    drop(account);
    // Next start: the wall clock was set back to one day after activation.
    env.clock.set_unix(crate::common::T0 + DAY);
    let restarted = env.cad();
    assert!(!restarted.allowed(PRO));
    assert!(restarted.diagnostics().clock_rolled_back);
    assert!(matches!(licence(&restarted), LicenceState::Inactive { .. }));
}

#[test]
fn expiry_warnings_at_7_3_1_days_once_each() {
    let env = Env::licensing(pro_scenario(30));
    let account = env.cad();
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
fn no_warning_while_every_built_in_feature_is_free() {
    let env = Env::licensing(pro_scenario(30));
    let mut config = env.config(Product::UbotBuild);
    for f in &mut config.builtin_features {
        *f = BuiltinFeature::new(f.feature.clone(), Tier::Free);
    }
    let account = Account::new(config, env.store.clone()).unwrap();
    sign_in(&account);
    assert!(matches!(licence(&account), LicenceState::Active { .. }));
    env.advance(29 * DAY);
    assert_eq!(signed_in(account.status()).warning, None);
}

#[test]
fn revoked_device_wipes_every_lease() {
    let mut scenario = Scenario {
        tenants: vec![
            Tenant::new("ten_vb", ORG_A, "vanban", &["use", "offline"]),
            Tenant::new("ten_pdf", ORG_A, "pdf", &["use", "offline"]),
        ],
        ..licensed()
    };
    scenario.products.extend(["vanban".into(), "pdf".into()]);
    let env = Env::licensing(scenario);
    let account = env.account();
    sign_in(&account);
    let other = env.account_for(Product::Pdf);
    other.refresh().unwrap();
    let device = account.diagnostics().device_id.unwrap();
    assert!(env.server.revoke_device(&device));
    env.advance(13 * 3600);
    let err = account.refresh().unwrap_err();
    assert!(
        matches!(&err, Error::Api(e) if e.code == ApiCode::DeviceRevoked),
        "{err:?}"
    );
    assert!(!env.file("lease-vanban.json").exists());
    assert!(!env.file("lease-pdf.json").exists());
    assert_eq!(licence(&account), LicenceState::DeviceRevoked);
    let calls = env.count("POST", ACTIVATE);
    account.refresh().unwrap();
    other.refresh().unwrap();
    assert_eq!(env.count("POST", ACTIVATE), calls);
    assert_eq!(licence(&other), LicenceState::DeviceRevoked);
}

#[test]
fn switching_org_switches_entitlements() {
    let env = Env::licensing(Scenario {
        org_choice: None,
        ..pro_scenario(30)
    });
    let account = env.cad();
    sign_in(&account);
    assert!(!account.allowed(PRO), "personal context holds nothing");

    account.select_org(Some(ORG_A), browser).unwrap();
    let s = signed_in(account.status());
    assert_eq!(s.active_org.as_deref(), Some(ORG_A));
    assert!(
        matches!(&s.licence, LicenceState::Active { features, .. } if features.iter().any(|f| f == PRO))
    );
    assert!(account.allowed(PRO));

    account.select_org(Some(ORG_B), browser).unwrap();
    assert_eq!(licence(&account), LicenceState::NotEntitled);
    assert!(!account.allowed(PRO));

    assert_eq!(
        account.select_org(Some("org_unknown"), browser),
        Err(Error::UnknownOrg)
    );
    account.select_org(None, browser).unwrap();
    assert_eq!(signed_in(account.status()).active_org, None);
    // PI keys a device by installation, product and account, whatever the organization.
    assert_eq!(env.server.device_rows().len(), 1);

    let other = env.cad();
    assert_eq!(signed_in(other.status()).active_org, None);
    assert!(matches!(account.status(), Status::SignedIn(_)));
}

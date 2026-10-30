//! The four Office apps as one PI product, `erpconsoffice` (ADR 0013), against pi-mock.
use std::thread;

use erpcons_account::{
    Account, ApiCode, Error, LicenceState, OFFICE_EXPORT, OFFICE_USE, OFFICE_VIEW, Product,
};
use pi_mock::{FREE_OFFICE, OFFICE_PRODUCT, ORG_OFFICE, Scenario};
use serde_json::{Value, json};

use crate::common::{ACTIVATE, CHALLENGE, ENTITLEMENTS, Env, REFRESH, sign_in, signed_in};

const LEASE: &str = "lease-erpconsoffice.json";

fn licence(account: &Account) -> LicenceState {
    signed_in(account.status()).licence
}

fn session_keys(env: &Env, field: &str) -> Vec<String> {
    env.session_json()[field]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect()
}

#[test]
fn one_activation_and_one_lease_serve_the_four_apps() {
    let env = Env::licensing(Scenario::office_free());
    let vanban = env.account();
    sign_in(&vanban);
    let s = signed_in(vanban.status());
    assert_eq!(s.active_org.as_deref(), Some(ORG_OFFICE));
    assert!(
        matches!(&s.licence, LicenceState::Active { features, .. }
            if features == &[OFFICE_VIEW, OFFICE_EXPORT, OFFICE_USE]),
        "{:?}",
        s.licence
    );
    assert!(vanban.allowed(OFFICE_USE));

    for path in [CHALLENGE, ENTITLEMENTS] {
        let query = &env.requests_to(path)[0].query;
        assert_eq!(query, "product_id=erpconsoffice", "{path}");
    }
    let body: Value = serde_json::from_str(&env.requests_to(ACTIVATE)[0].body).unwrap();
    assert_eq!(body["productId"], OFFICE_PRODUCT);
    let claims = env.lease_claims(OFFICE_PRODUCT);
    assert_eq!(claims["product"], OFFICE_PRODUCT);
    assert_eq!(claims["aud"], "erpcons-office-desktop");
    assert_eq!(claims["org"], ORG_OFFICE);
    assert_eq!(claims["policy_version"], "office-mien-phi@1");
    assert_eq!(claims["features"], json!(FREE_OFFICE));

    for p in [Product::BangTinh, Product::TrinhChieu, Product::Pdf] {
        let app = env.account_for(p);
        app.refresh().unwrap();
        assert!(app.allowed(OFFICE_USE), "{p:?}");
        assert_eq!(licence(&app), licence(&vanban), "{p:?}");
    }
    assert_eq!(env.count("POST", ACTIVATE), 1);
    assert_eq!(env.count("POST", REFRESH), 0);
    let rows = env.server.device_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].product, OFFICE_PRODUCT);
    let licences = signed_in(vanban.status()).licences;
    assert_eq!(
        licences.keys().copied().collect::<Vec<_>>(),
        Product::OFFICE
    );
    assert!(licences.values().all(|l| *l == licence(&vanban)));
    assert_eq!(session_keys(&env, "device_ids"), [OFFICE_PRODUCT]);
}

#[test]
fn edits_need_the_office_plan_view_and_export_never_do() {
    let env = Env::licensing(Scenario {
        tenants: Vec::new(),
        ..Scenario::office_free()
    });
    let account = env.account();
    assert!(account.allowed(OFFICE_VIEW) && account.allowed(OFFICE_EXPORT));
    assert!(!account.allowed(OFFICE_USE), "guest");

    sign_in(&account);
    assert_eq!(licence(&account), LicenceState::NotEntitled);
    assert!(!account.allowed(OFFICE_USE));
    assert!(account.allowed(OFFICE_VIEW) && account.allowed(OFFICE_EXPORT));
    assert!(!env.file(LEASE).exists());

    // PI ticks Office for the organization. The free plan has unlimited seats, so PI reports no
    // seat before an activation and a plain sync cannot tell: the user's Retry activates.
    env.server
        .update_scenario(|s| s.tenants = Scenario::office_free().tenants);
    account.refresh().unwrap();
    assert_eq!(licence(&account), LicenceState::NotEntitled);
    account.retry_activation().unwrap();
    assert!(matches!(licence(&account), LicenceState::Active { .. }));
    assert!(account.allowed(OFFICE_USE));
}

#[test]
fn licensing_off_denies_edits_and_calls_no_device_endpoint() {
    let env = Env::new(Scenario::office_free());
    let account = env.account();
    sign_in(&account);
    assert_eq!(licence(&account), LicenceState::NotActivated);
    assert!(!account.allowed(OFFICE_USE));
    assert!(!account.take_refresh_request());
    assert!(account.allowed(OFFICE_VIEW) && account.allowed(OFFICE_EXPORT));
    account.retry_activation().unwrap();
    for path in [CHALLENGE, ENTITLEMENTS, ACTIVATE, REFRESH] {
        assert!(env.requests_to(path).is_empty(), "{path}");
    }
}

#[test]
fn concurrent_apps_renew_the_shared_lease_once() {
    let env = Env::licensing(Scenario::office_free());
    sign_in(&env.account());
    let apps: Vec<Account> = Product::OFFICE.map(|p| env.account_for(p)).into();
    env.advance(13 * 3600);
    thread::scope(|s| {
        for app in &apps {
            s.spawn(|| app.refresh().unwrap());
        }
    });
    assert_eq!(env.count("POST", REFRESH), 1);
    assert_eq!(env.count("POST", ACTIVATE), 1);
    let renewed = licence(&apps[0]);
    assert!(matches!(renewed, LicenceState::Active { .. }));
    for app in &apps {
        app.reload().unwrap();
        assert_eq!(licence(app), renewed);
        assert!(app.allowed(OFFICE_USE));
    }
}

#[test]
fn a_revoked_device_stops_edits_in_every_app() {
    let env = Env::licensing(Scenario::office_free());
    let vanban = env.account();
    sign_in(&vanban);
    let pdf = env.account_for(Product::Pdf);
    assert!(pdf.allowed(OFFICE_USE));
    let device = vanban.diagnostics().device_id.unwrap();
    assert_eq!(pdf.diagnostics().device_id, Some(device.clone()));
    assert!(env.server.revoke_device(&device));
    env.advance(13 * 3600);
    let err = vanban.refresh().unwrap_err();
    assert!(
        matches!(&err, Error::Api(e) if e.code == ApiCode::DeviceRevoked),
        "{err:?}"
    );
    assert!(!env.file(LEASE).exists());

    pdf.reload().unwrap();
    assert_eq!(licence(&pdf), LicenceState::DeviceRevoked);
    assert!(!pdf.allowed(OFFICE_USE));
    assert!(pdf.allowed(OFFICE_VIEW) && pdf.allowed(OFFICE_EXPORT));
    let calls = env.count("POST", ACTIVATE);
    pdf.refresh().unwrap();
    assert_eq!(env.count("POST", ACTIVATE), calls);
}

/// 0.4.x keyed leases, device ids and refresh timestamps by app id.
#[test]
fn state_of_0_4_is_discarded_on_upgrade() {
    let mut env = Env::licensing(Scenario::office_free());
    env.licensing = false;
    sign_in(&env.account());
    env.licensing = true;
    let mut session = env.session_json();
    session["device_ids"] = json!({"vanban": "dev_old", "pdf": "dev_old"});
    session["last_refresh_ts"] = json!({"vanban": 1});
    session["not_entitled"] = json!(["bangtinh"]);
    std::fs::write(env.file("session.json"), env.seal(&session.to_string())).unwrap();
    let stale = [
        "lease-vanban.json",
        "lease-pdf.json",
        "catalog-trinhchieu.jws",
    ];
    for name in stale {
        std::fs::write(env.file(name), env.seal("{}")).unwrap();
    }

    let account = env.account();
    for name in stale {
        assert!(!env.file(name).exists(), "{name}");
    }
    assert_eq!(account.diagnostics().device_id, None);
    account.refresh().unwrap();
    assert_eq!(env.count("POST", ACTIVATE), 1);
    assert!(account.allowed(OFFICE_USE));
    assert_eq!(session_keys(&env, "device_ids"), [OFFICE_PRODUCT]);
    assert_eq!(env.session_json()["last_refresh_ts"], json!({}));
    assert_eq!(env.session_json()["not_entitled"], json!([]));
}

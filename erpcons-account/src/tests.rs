//! Unit tests: PI lease claims, JOSE profile, trusted time, catalog, entitlements, helpers.
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

use crate::{
    ApiCode, Backoff, BuiltinFeature, ClientProfile, DESKTOP_CLIENT_ID, Error, OFFICE_EXPORT,
    OFFICE_PI_PRODUCT, OFFICE_USE, OFFICE_VIEW, PLATFORM_KEYS, PinnedKey, Product, Tier,
    VerifyError,
    catalog::{self, is_pinned_free, is_valid_feature_id},
    device, entitlements, jose,
    lease::{self, Copies, Expect},
    pi_device::{
        INTERNAL_CODES, activate_message, compose_features, is_feature_code, is_nonce,
        refresh_message,
    },
    storage,
    time::{TrustedTime, parse_http_date, parse_rfc3339},
};

const ISSUER: &str = "https://id.pi.invalid";
const KID: &str = "pi-lease-example-1";
const PLATFORM_HEX: &str = "f4d62fdc454061bc8c0a7cb2c1d529254f7dc93492138e2d43f5c048c9e2d200";
const ACTIVATION_NOW: i64 = 1_792_828_800;

// v0.3.0 vectors from docs/contract.openapi.yaml: an Office-contract lease and catalog.
const LEASE_ACTIVATION: &str = "eyJhbGciOiJFZERTQSIsImtpZCI6InBpLWxlYXNlLWV4YW1wbGUtMSIsInR5cCI6InBpLWxlYXNlK2p3dCJ9.eyJpc3MiOiJodHRwczovL2lkLnBpLmludmFsaWQiLCJhdWQiOiJlcnBjb25zLW9mZmljZS1kZXNrdG9wIiwibGVhc2VfaWQiOiJsc2VfMDFKQjdBMkY0SDZLOE0wUDJSNFQ2VjhYMFoiLCJzdWIiOiJ1c3JfMDFKQjZaMks4UTRYTjNUNVY3VzlZMUEyQzMiLCJvcmciOiJvcmdfMDFKQjZaM001UjdUOVYxWDNaNUI3RDlGMUgiLCJkZXZpY2VfaWQiOiJkZXZfMDFKQjdBMEMyRTRHNko4TDBOMlE0UzZVOFciLCJpbnN0YWxsYXRpb25faWQiOiI2ZjFjMmQzZS00YjVhLTRjN2QtOGU5Zi0wYTFiMmMzZDRlNWYiLCJjbmYiOnsiamt0IjoibjVxU3hrSTl3WlcteG9LUU1qanBkbWt0WVRjTG1keUJfbEc5WGFRaHFMTSJ9LCJwcm9kdWN0IjoidmFuYmFuIiwiZmVhdHVyZXMiOlsidmFuYmFuLnVzZSJdLCJlbnRpdGxlbWVudF9pZHMiOlsiZW50XzAxSkI3QTFEM0Y1SDdLOU0xUDNSNVQ3VjlYIl0sIm5iZiI6MTc5MjgyODgwMCwiaWF0IjoxNzkyODI4ODAwLCJleHAiOjE3OTU0MjA4MDAsIm5vbmNlIjoiUkZJZTVHY2xqdUNfTk1mdWhBME1MZ1lFT1RjRGhwS2IyYU4wM3hUeEswQSIsInBvbGljeV92ZXJzaW9uIjoiMjAyNi0xMC0wMS4xIn0.9ErzrUmc2F-ASSgptBdMZXb1cBNDNKvfx1EkVAxGlStKg8wjASj7yZXzCf8yPcHJiaPB05YH7ce3TTBxg4qiAQ";
const CATALOG_VANBAN: &str = "eyJhbGciOiJFZERTQSIsImtpZCI6InBpLWxlYXNlLWV4YW1wbGUtMSIsInR5cCI6InBpLWZlYXR1cmUtY2F0YWxvZytqd3QifQ.eyJpc3MiOiJodHRwczovL2lkLnBpLmludmFsaWQiLCJwcm9kdWN0IjoidmFuYmFuIiwiY2F0YWxvZ192ZXJzaW9uIjoxLCJpYXQiOjE3OTI4Mjg4MDAsImZlYXR1cmVzIjpbeyJmZWF0dXJlIjoidmFuYmFuLnZpZXciLCJ0aWVyIjoiZnJlZSJ9LHsiZmVhdHVyZSI6InZhbmJhbi5leHBvcnQiLCJ0aWVyIjoiZnJlZSJ9LHsiZmVhdHVyZSI6InZhbmJhbi51c2UiLCJ0aWVyIjoiZnJlZSJ9XX0.8KO9EMOFTwp8lnncsJmUr2os3nqQJLQexN5RS-8BfCU00lHKM7wsTYlY8mZMx_rFsHrqmwMtN5T7luGA_9iIBg";

// A PI lease (pi_device `Devices::issueLease`) signed by a test key; the device is `seven_device`.
const PI_KID: &str = "lease-test-1";
const PI_SEED: [u8; 32] = [11; 32];
const PI_USER: &str = "6f3b1c2a-9d4e-4f8a-b1c7-2e5d8a9f0b13";
const PI_ORG: &str = "0c9e7a51-3b2d-4c6f-8e1a-5d7b9f2c4e60";
const PI_TENANT: &str = "7d3e9a10-5b2c-4f6d-8e1a-2c4b6d8f0a12";
const PI_DEVICE: &str = "3c2b1a09-8f7e-4d6c-b5a4-938271605f4e";
const PI_LEASE_ID: &str = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
const PI_NONCE: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz012345";
const PI_NOW: i64 = 1_793_232_000;
const PI_UNTIL: &str = "2026-11-05T00:00:00Z";
const UBOTCAD: &str = "ubotcad-desktop";

fn hex32(s: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

fn keys() -> Vec<PinnedKey> {
    vec![PinnedKey {
        kid: KID.into(),
        key: hex32(PLATFORM_HEX),
    }]
}

fn sign_compact(header: &str, payload: &str, key: &SigningKey) -> String {
    let input = format!(
        "{}.{}",
        jose::b64(header.as_bytes()),
        jose::b64(payload.as_bytes())
    );
    format!(
        "{input}.{}",
        jose::b64(&key.sign(input.as_bytes()).to_bytes())
    )
}

fn pi_keys() -> Vec<PinnedKey> {
    vec![PinnedKey {
        kid: PI_KID.into(),
        key: SigningKey::from_bytes(&PI_SEED).verifying_key().to_bytes(),
    }]
}

fn pi_claims() -> Value {
    json!({
        "iss": ISSUER,
        "jti": PI_LEASE_ID,
        "sub": PI_USER,
        "org": PI_ORG,
        "tenant": PI_TENANT,
        "product": "ubotbuild",
        "device": PI_DEVICE,
        "cnf": {"jkt": PI_JKT},
        "features": ["cad-view", "cad-export", "cad-use", "offline"],
        "offline_allowed": true,
        "policy_version": "ubb-mien-phi@1",
        "nonce": PI_NONCE,
        "iat": PI_NOW,
        "nbf": PI_NOW,
        "exp": PI_NOW + 7 * 86_400,
        "warn_days": [7, 3, 1],
        "after_expiry": "read_export",
        "aud": UBOTCAD,
    })
}

fn pi_lease(claims: &Value) -> String {
    let header = format!(r#"{{"alg":"EdDSA","typ":"pi-lease+jwt","kid":"{PI_KID}"}}"#);
    sign_compact(
        &header,
        &claims.to_string(),
        &SigningKey::from_bytes(&PI_SEED),
    )
}

fn pi_expect() -> Expect<'static> {
    Expect {
        issuer: ISSUER,
        audience: UBOTCAD,
        product: "ubotbuild",
        sub: PI_USER,
        org: Some(PI_ORG),
        jkt: PI_JKT,
        device_id: PI_DEVICE,
        nonce: Some(PI_NONCE),
    }
}

fn pi_verify(claims: &Value) -> Result<lease::Lease, VerifyError> {
    lease::verify(&pi_lease(claims), &pi_keys(), &pi_expect())
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn pi_copies<'a>(rights: &'a [String], entitlement: Option<&'a str>) -> Copies<'a> {
    Copies {
        entitlement_id: entitlement,
        rights,
        offline_valid_until: PI_UNTIL,
        policy_version: "ubb-mien-phi@1",
        lease_id: PI_LEASE_ID,
    }
}

#[test]
fn pi_lease_passes_and_composes_features() {
    let lease = pi_verify(&pi_claims()).unwrap();
    assert_eq!(lease.lease_id, PI_LEASE_ID);
    assert_eq!(lease.org, PI_ORG);
    assert_eq!(lease.tenant, PI_TENANT);
    assert_eq!(lease.device_id, PI_DEVICE);
    assert_eq!(
        lease.features,
        [
            "ubotbuild.cad-view",
            "ubotbuild.cad-export",
            "ubotbuild.cad-use"
        ]
    );
    lease.window(PI_NOW).unwrap();
    let rights = strings(&["cad-view", "cad-export", "cad-use", "offline"]);
    lease
        .check_copies(&pi_copies(&rights, Some(PI_TENANT)))
        .unwrap();
    // A refresh response has no `entitlementId`.
    lease.check_copies(&pi_copies(&rights, None)).unwrap();
    // Loaded from disk: no nonce to compare.
    let stored = Expect {
        nonce: None,
        ..pi_expect()
    };
    lease::verify(&pi_lease(&pi_claims()), &pi_keys(), &stored).unwrap();
}

#[test]
fn pi_lease_claim_checks_fail_in_order() {
    let cases: Vec<(Expect, VerifyError)> = vec![
        (
            Expect {
                issuer: "https://other.invalid",
                ..pi_expect()
            },
            VerifyError::Issuer,
        ),
        (
            Expect {
                audience: DESKTOP_CLIENT_ID,
                ..pi_expect()
            },
            VerifyError::Audience,
        ),
        (
            Expect {
                product: OFFICE_PI_PRODUCT,
                ..pi_expect()
            },
            VerifyError::Product,
        ),
        (
            Expect {
                sub: "2b7c4d1e-8f3a-4b6c-9d2e-1f0a3b5c7d94",
                ..pi_expect()
            },
            VerifyError::Subject,
        ),
        (
            Expect {
                org: Some("a4d2f6b8-1e3c-4a5b-9c7d-8e0f2a4b6c81"),
                ..pi_expect()
            },
            VerifyError::Org,
        ),
        (
            Expect {
                org: None,
                ..pi_expect()
            },
            VerifyError::Org,
        ),
        (
            Expect {
                jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ..pi_expect()
            },
            VerifyError::KeyBinding,
        ),
        (
            Expect {
                device_id: "00000000-0000-4000-8000-000000000000",
                ..pi_expect()
            },
            VerifyError::Device,
        ),
        (
            Expect {
                nonce: Some("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"),
                ..pi_expect()
            },
            VerifyError::Nonce,
        ),
    ];
    let jws = pi_lease(&pi_claims());
    for (e, want) in cases {
        assert_eq!(lease::verify(&jws, &pi_keys(), &e).unwrap_err(), want);
    }
    let other_kid = vec![PinnedKey {
        kid: "next".into(),
        ..pi_keys().remove(0)
    }];
    assert_eq!(
        lease::verify(&jws, &other_kid, &pi_expect()).unwrap_err(),
        VerifyError::UnknownKey
    );
    let mut forged = jws.clone();
    forged.pop();
    forged.push('B');
    assert!(matches!(
        lease::verify(&forged, &pi_keys(), &pi_expect()).unwrap_err(),
        VerifyError::Signature | VerifyError::Format
    ));
    let lease = lease::verify(&jws, &pi_keys(), &pi_expect()).unwrap();
    assert_eq!(lease.window(lease.nbf - 301), Err(VerifyError::NotYetValid));
    assert_eq!(lease.window(lease.nbf - 300), Ok(()));
    assert_eq!(lease.window(lease.exp), Err(VerifyError::Expired));
    let rights = strings(&["cad-view", "cad-export", "cad-use", "offline"]);
    let extra = strings(&["cad-view", "cad-export", "cad-use", "cad-3d"]);
    for copies in [
        pi_copies(&extra, Some(PI_TENANT)),
        pi_copies(&rights, Some("other-tenant")),
        Copies {
            offline_valid_until: "2026-11-06T00:00:00Z",
            ..pi_copies(&rights, None)
        },
        Copies {
            policy_version: "ubb-mien-phi@2",
            ..pi_copies(&rights, None)
        },
        Copies {
            lease_id: "other",
            ..pi_copies(&rights, None)
        },
    ] {
        assert_eq!(lease.check_copies(&copies), Err(VerifyError::CopyMismatch));
    }
}

#[test]
fn pi_lease_claim_shapes() {
    for name in [
        "iss",
        "jti",
        "sub",
        "org",
        "tenant",
        "product",
        "device",
        "cnf",
        "features",
        "policy_version",
        "nonce",
        "iat",
        "nbf",
        "exp",
        "aud",
    ] {
        let mut claims = pi_claims();
        claims.as_object_mut().unwrap().remove(name);
        assert_eq!(pi_verify(&claims), Err(VerifyError::Claims), "{name}");
    }
    for (name, value, want) in [
        ("org", Value::Null, Err(VerifyError::Claims)),
        ("org", json!(""), Err(VerifyError::Claims)),
        ("jti", json!(""), Err(VerifyError::Claims)),
        ("aud", json!([UBOTCAD]), Err(VerifyError::Claims)),
        ("features", json!(["CAD_USE"]), Err(VerifyError::Feature)),
        ("iat", json!(PI_NOW + 1), Err(VerifyError::Validity)),
        ("exp", json!(PI_NOW), Err(VerifyError::Validity)),
        ("exp", json!(PI_NOW + 7_776_001), Err(VerifyError::Validity)),
        ("exp", json!(PI_NOW + 7_776_000), Ok(())),
        ("policy_version", json!(""), Ok(())),
        ("installation_id", json!("ignored"), Ok(())),
        ("future_claim", json!({"x": 1}), Ok(())),
    ] {
        let mut claims = pi_claims();
        claims[name] = value;
        assert_eq!(pi_verify(&claims).map(|_| ()), want, "{name}");
    }
    let mut minimal = pi_claims();
    for name in ["offline_allowed", "warn_days", "after_expiry"] {
        minimal.as_object_mut().unwrap().remove(name);
    }
    pi_verify(&minimal).unwrap();
    // Composed ids may pass 64 characters; PI's code rule caps only the code.
    let code = format!("a{}", "b".repeat(63));
    let mut long = pi_claims();
    long["features"] = json!([code]);
    let lease = pi_verify(&long).unwrap();
    assert_eq!(lease.features, [format!("ubotbuild.{code}")]);
    assert!(lease.features[0].len() > 64);
}

#[test]
fn v030_lease_is_rejected() {
    let e = Expect {
        issuer: ISSUER,
        audience: DESKTOP_CLIENT_ID,
        product: OFFICE_PI_PRODUCT,
        sub: "usr_01JB6Z2K8Q4XN3T5V7W9Y1A2C3",
        org: Some("org_01JB6Z3M5R7T9V1X3Z5B7D9F1H"),
        jkt: "n5qSxkI9wZW-xoKQMjjpdmktYTcLmdyB_lG9XaQhqLM",
        device_id: "dev_01JB7A0C2E4G6J8L0N2Q4S6U8W",
        nonce: Some("RFIe5GcljuC_NMfuhA0MLgYEOTcDhpKb2aN03xTxK0A"),
    };
    assert_eq!(
        lease::verify(LEASE_ACTIVATION, &keys(), &e).unwrap_err(),
        VerifyError::Claims
    );
}

#[test]
fn device_thumbprint_is_pi_raw_key_hash() {
    assert_eq!(seven_device().thumbprint(), PI_JKT);
}

#[test]
fn v030_catalog_is_rejected() {
    // Signed for app id `vanban`: Office features are `erpconsoffice.*` since 0.5.0.
    assert_eq!(
        catalog::verify(CATALOG_VANBAN, &keys(), ISSUER, OFFICE_PI_PRODUCT, 0).unwrap_err(),
        VerifyError::Product
    );
    assert_eq!(
        catalog::verify(CATALOG_VANBAN, &keys(), ISSUER, "vanban", 0).unwrap_err(),
        VerifyError::Feature
    );
    // Explicit typing: a catalog is never a lease and a lease never a catalog.
    assert_eq!(
        lease::verify(CATALOG_VANBAN, &keys(), &pi_expect()).unwrap_err(),
        VerifyError::Header
    );
    assert_eq!(
        catalog::verify(LEASE_ACTIVATION, &keys(), ISSUER, OFFICE_PI_PRODUCT, 0).unwrap_err(),
        VerifyError::Header
    );
}

fn row(org: &str, product: &str, decision: &str, seat: bool, codes: &[&str]) -> Value {
    let features: Vec<Value> = codes
        .iter()
        .map(|c| json!({"code": c, "name": c, "source": "plan"}))
        .collect();
    json!({
        "organization": {"id": org, "name": "A", "role": "member"},
        "tenant": {"id": PI_TENANT, "code": "t", "product": product},
        "decision": decision,
        "reasonCode": "OK",
        "features": features,
        "quotas": [],
        "policyVersion": 1,
        "subscription": null,
        "evaluatedAt": "2026-10-29T00:00:00Z",
        "seat": seat,
        "offline": {"allowed": true, "days": 7, "deviceCap": 2},
    })
}

fn parse_rows(rows: Vec<Value>) -> Result<Vec<(String, bool)>, Error> {
    let body = json!({"ok": true, "items": rows}).to_string();
    entitlements::parse(body.as_bytes(), "ubotbuild", PI_ORG).map(|list| {
        list.into_iter()
            .map(|e| (e.feature, e.offline_allowed))
            .collect()
    })
}

#[test]
fn pi_entitlement_rows() {
    let allow = row(PI_ORG, "ubotbuild", "ALLOW", true, &["cad-view", "offline"]);
    assert_eq!(
        parse_rows(vec![allow.clone()]).unwrap(),
        [("ubotbuild.cad-view".to_owned(), true)]
    );
    let mut no_offline = allow.clone();
    no_offline["offline"]["allowed"] = json!(false);
    assert_eq!(
        parse_rows(vec![no_offline]).unwrap(),
        [("ubotbuild.cad-view".to_owned(), false)]
    );
    for ignored in [
        row(PI_ORG, "ubotbuild", "DENY", true, &["cad-use"]),
        row(PI_ORG, "ubotbuild", "ALLOW", false, &["cad-use"]),
    ] {
        assert!(parse_rows(vec![ignored]).unwrap().is_empty());
    }
    assert!(parse_rows(Vec::new()).unwrap().is_empty());
    for foreign in [
        row(
            "a4d2f6b8-1e3c-4a5b-9c7d-8e0f2a4b6c81",
            "ubotbuild",
            "ALLOW",
            true,
            &["cad-use"],
        ),
        row(PI_ORG, "erpcons", "ALLOW", true, &["cad-use"]),
    ] {
        assert_eq!(
            parse_rows(vec![allow.clone(), foreign]),
            Err(Error::TenantIsolation)
        );
    }
    // A row with a bad feature code is skipped; the others still count.
    let kept = parse_rows(vec![
        row(PI_ORG, "ubotbuild", "ALLOW", true, &["CAD_USE"]),
        allow.clone(),
    ])
    .unwrap();
    assert_eq!(kept.len(), parse_rows(vec![allow.clone()]).unwrap().len());
    assert!(
        parse_rows(vec![row(PI_ORG, "ubotbuild", "ALLOW", true, &["CAD_USE"])])
            .unwrap()
            .is_empty()
    );
}

fn signed(header: &serde_json::Value, payload: &str, key: &SigningKey) -> String {
    sign_compact(&header.to_string(), payload, key)
}

#[test]
fn jose_profile_rejects_headers_and_duplicates() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let pinned = vec![PinnedKey {
        kid: "k".into(),
        key: key.verifying_key().to_bytes(),
    }];
    let typ = "pi-lease+jwt";
    let good = json!({"alg": "EdDSA", "kid": "k", "typ": typ});
    assert!(jose::verify_platform(&signed(&good, "{}", &key), typ, &pinned).is_ok());
    for header in [
        json!({"alg": "none", "kid": "k", "typ": typ}),
        json!({"alg": "Ed25519", "kid": "k", "typ": typ}),
        json!({"alg": "EdDSA", "kid": "k", "typ": "JWT"}),
        json!({"alg": "EdDSA", "kid": "k", "typ": typ, "jku": "https://x"}),
        json!({"alg": "EdDSA", "kid": "k", "typ": typ, "crit": ["exp"]}),
        json!({"alg": "EdDSA", "typ": typ}),
    ] {
        assert_eq!(
            jose::verify_platform(&signed(&header, "{}", &key), typ, &pinned).unwrap_err(),
            VerifyError::Header,
            "{header}"
        );
    }
    let dup = signed(&good, r#"{"sub":"a","sub":"b"}"#, &key);
    assert_eq!(
        jose::verify_platform(&dup, typ, &pinned).unwrap_err(),
        VerifyError::Format
    );
    let big = signed(&good, &format!(r#"{{"x":"{}"}}"#, "a".repeat(9000)), &key);
    assert_eq!(
        jose::verify_platform(&big, typ, &pinned).unwrap_err(),
        VerifyError::Format
    );
    let padded = format!("{}=", signed(&good, "{}", &key));
    assert_eq!(
        jose::verify_platform(&padded, typ, &pinned).unwrap_err(),
        VerifyError::Format
    );
}

#[test]
fn strict_json_objects() {
    assert!(jose::strict_object(br#"{"a":1,"b":{"c":[1,2]}}"#).is_some());
    assert!(jose::strict_object(br#"{"a":1,"a":1}"#).is_none());
    assert!(jose::strict_object(br#"{"a":{"b":1,"b":2}}"#).is_none());
    assert!(jose::strict_object(br#"{"aa":1,"aa":2}"#).is_none());
    assert!(jose::strict_object(br#"[1]"#).is_none());
    assert!(jose::strict_object(br#"{"a":1} x"#).is_none());
}

#[test]
fn feature_ids_and_tiers() {
    for ok in [
        "erpconsoffice.view",
        "erpconsoffice.use",
        "erpconsoffice.a_b.c1",
    ] {
        assert!(is_valid_feature_id(ok), "{ok}");
    }
    for bad in [
        "erpconsoffice",
        "word.use",
        "erpconsoffice.",
        "erpconsoffice.Use",
        "erpconsoffice..x",
        // App ids stopped being feature prefixes in 0.5.0 (ADR 0013).
        "vanban.use",
        "pdf.view",
    ] {
        assert!(!is_valid_feature_id(bad), "{bad}");
    }
    assert!(is_pinned_free("erpconsoffice.export"));
    assert!(!is_pinned_free("erpconsoffice.use"));
    let builtin = vec![
        BuiltinFeature::new("erpconsoffice.view", Tier::Free),
        BuiltinFeature::new("erpconsoffice.advanced", Tier::Free),
    ];
    let key = SigningKey::from_bytes(&[9; 32]);
    let pinned = vec![PinnedKey {
        kid: "k".into(),
        key: key.verifying_key().to_bytes(),
    }];
    let payload = json!({
        "iss": ISSUER, "product": "erpconsoffice", "catalog_version": 2, "iat": 1,
        "features": [{"feature": "erpconsoffice.view", "tier": "pro"}, {"feature": "erpconsoffice.advanced", "tier": "pro"}]
    });
    let jws = signed(
        &json!({"alg": "EdDSA", "kid": "k", "typ": "pi-feature-catalog+jwt"}),
        &payload.to_string(),
        &key,
    );
    let c = catalog::verify(&jws, &pinned, ISSUER, OFFICE_PI_PRODUCT, 1).unwrap();
    assert_eq!(
        catalog::tier(&builtin, Some(&c), "erpconsoffice.view"),
        Some(Tier::Free)
    );
    assert_eq!(
        catalog::tier(&builtin, Some(&c), "erpconsoffice.advanced"),
        Some(Tier::Pro)
    );
    assert_eq!(
        catalog::tier(&builtin, None, "erpconsoffice.advanced"),
        Some(Tier::Free)
    );
    assert_eq!(
        catalog::tier(&builtin, Some(&c), "erpconsoffice.unknown"),
        None
    );
    assert_eq!(
        catalog::verify(&jws, &pinned, ISSUER, OFFICE_PI_PRODUCT, 3).unwrap_err(),
        VerifyError::Downgrade
    );
    assert_eq!(
        catalog::verify(&jws, &pinned, ISSUER, "ubotbuild", 0).unwrap_err(),
        VerifyError::Product
    );
}

#[test]
fn rfc3339_conversions() {
    assert_eq!(parse_rfc3339("2026-10-24T08:00:00Z"), Some(ACTIVATION_NOW));
    assert_eq!(
        parse_rfc3339("2026-10-24T10:00:00.250+02:00"),
        Some(ACTIVATION_NOW)
    );
    assert_eq!(parse_rfc3339("2000-02-29T00:00:00Z"), Some(951_782_400));
    assert_eq!(parse_rfc3339("2026-10-24 08:00:00Z"), None);
    assert_eq!(parse_rfc3339("2026-13-24T08:00:00Z"), None);
}

#[test]
fn trusted_time_rollback_frozen_clock_and_correction() {
    let t0 = ACTIVATION_NOW;
    let mut time = TrustedTime::new(0, Duration::ZERO);
    time.start(t0 + 1000, Duration::ZERO);
    // Rolled back: the floor wins and the rollback is recorded.
    assert_eq!(time.now(t0, Duration::from_secs(10)), t0 + 1010);
    assert!(time.rolled_back());
    // Frozen wall clock: running time still advances.
    assert_eq!(time.now(t0, Duration::from_secs(70)), t0 + 1070);
    // Server correction lowers a floor that ran too far ahead, and only then.
    assert!(time.correct(t0, Duration::from_secs(70)));
    assert_eq!(time.floor(), t0);
    assert!(!time.correct(t0 - 100, Duration::from_secs(70)));
    let mut ahead = TrustedTime::new(0, Duration::ZERO);
    ahead.start(t0, Duration::ZERO);
    ahead.merge(t0 + 50);
    assert_eq!(ahead.now(t0, Duration::ZERO), t0 + 50);
    assert!(!ahead.rolled_back());
}

#[test]
fn release_keys_exclude_development_keys() {
    let forbidden = [pi_mock::dev_lease_public_key(), hex32(PLATFORM_HEX)];
    for (kid, key) in PLATFORM_KEYS {
        assert!(!forbidden.contains(key), "development key pinned as {kid}");
        assert!(![pi_mock::DEV_LEASE_KID, KID].contains(kid));
    }
}

#[test]
fn sealed_files_detect_tampering() {
    let key = SigningKey::from_bytes(&[3; 32]);
    let sealed = storage::seal(br#"{"a":1}"#, &key);
    assert_eq!(
        storage::unseal(&sealed, &key.verifying_key()),
        Some(&br#"{"a":1}"#[..])
    );
    let mut changed = sealed.clone();
    changed[5] = b'2';
    assert_eq!(storage::unseal(&changed, &key.verifying_key()), None);
    let other = SigningKey::from_bytes(&[4; 32]);
    assert_eq!(storage::unseal(&sealed, &other.verifying_key()), None);
}

#[test]
fn backoff_and_error_codes() {
    let mut b = Backoff::new();
    let offline = Error::Network("down".into());
    let delays: Vec<u64> = (0..8).map(|_| b.next_delay(&offline).as_secs()).collect();
    assert_eq!(delays, [60, 120, 240, 480, 960, 1920, 3600, 3600]);
    let limited = Error::Api(crate::ApiError {
        status: 429,
        code: ApiCode::RateLimited,
        correlation_id: None,
        retry_after: Some(Duration::from_secs(7)),
        max_devices: None,
        active_devices: None,
        errors: Box::default(),
    });
    assert_eq!(b.next_delay(&limited), Duration::from_secs(7));
    assert_eq!(
        ApiCode::from_parts(429, Some("quota_exceeded")),
        ApiCode::QuotaExceeded
    );
    assert_eq!(
        ApiCode::from_parts(403, Some("brand_new")),
        ApiCode::Forbidden
    );
    assert_eq!(
        ApiCode::from_parts(409, Some("device_unknown")),
        ApiCode::Other("device_unknown".into())
    );
    assert_eq!(
        ApiCode::from_parts(503, None),
        ApiCode::DependencyUnavailable
    );
}

#[test]
fn uuid_v4_format() {
    let id = crate::random::uuid_v4().unwrap();
    let b = id.as_bytes();
    assert_eq!(id.len(), 36);
    assert_eq!(
        (b[8], b[13], b[14], b[18], b[23]),
        (b'-', b'-', b'4', b'-', b'-')
    );
    assert!(matches!(b[19], b'8' | b'9' | b'a' | b'b'));
}

#[test]
fn pi_error_codes_map_to_api_codes() {
    for (status, code, want) in [
        (403, "ACCOUNT_LOCKED", ApiCode::UserSuspended),
        (403, "INSUFFICIENT_SCOPE", ApiCode::InsufficientScope),
        (403, "MEMBERSHIP_INACTIVE", ApiCode::MembershipInactive),
        (409, "DEVICE_CAP", ApiCode::DeviceCapReached),
        (409, "DEVICE_REVOKED", ApiCode::DeviceRevoked),
        (409, "CHALLENGE_INVALID", ApiCode::ChallengeInvalid),
        (409, "IDEMPOTENCY_MISMATCH", ApiCode::IdempotencyKeyReused),
    ] {
        assert_eq!(ApiCode::from_parts(status, Some(code)), want, "{code}");
    }
    // PI's bare statuses: 401 without a code, unexpected failures as 500.
    assert_eq!(ApiCode::from_parts(401, None), ApiCode::Unauthenticated);
    assert_eq!(
        ApiCode::from_parts(500, None),
        ApiCode::DependencyUnavailable
    );
    assert_eq!(ApiCode::from_parts(429, None), ApiCode::RateLimited);
}

#[test]
fn pi_me_maps_to_identity() {
    let body = json!({
        "ok": true,
        "user": {"id": "6f3b1c2a-9d4e-4f8a-b1c7-2e5d8a9f0b13", "email": "", "displayName": "An", "status": "ACTIVE"},
        "organizations": [
            {"id": "0c9e7a51-3b2d-4c6f-8e1a-5d7b9f2c4e60", "name": "A", "myRole": "member", "myStatus": "ACTIVE"},
            {"id": "a4d2f6b8-1e3c-4a5b-9c7d-8e0f2a4b6c81", "name": "B", "myRole": "auditor", "myStatus": "SUSPENDED"},
            {"id": "c0ffee00-1e3c-4a5b-9c7d-8e0f2a4b6c81", "name": "C", "myRole": "member", "myStatus": "REVOKED"}
        ],
        "orgContext": "0c9e7a51-3b2d-4c6f-8e1a-5d7b9f2c4e60",
        "scopes": ["openid"],
        "meta": {}
    });
    let me = crate::me::parse(body.to_string().as_bytes()).unwrap();
    assert_eq!(me.user_id, "6f3b1c2a-9d4e-4f8a-b1c7-2e5d8a9f0b13");
    assert_eq!(me.email, None);
    assert!(!me.locked);
    assert_eq!(
        me.org_context.as_deref(),
        Some("0c9e7a51-3b2d-4c6f-8e1a-5d7b9f2c4e60")
    );
    let statuses: Vec<_> = me.memberships.iter().map(|m| m.status).collect();
    assert_eq!(
        statuses,
        [
            crate::MembershipStatus::Active,
            crate::MembershipStatus::Suspended
        ]
    );
    assert_eq!(me.memberships[1].role, "auditor");

    let locked = json!({"ok": true, "user": {"id": "x", "status": "LOCKED"}, "orgContext": null});
    assert!(
        crate::me::parse(locked.to_string().as_bytes())
            .unwrap()
            .locked
    );
    let failed = json!({"ok": false, "message": "Lỗi hệ thống."});
    assert!(crate::me::parse(failed.to_string().as_bytes()).is_err());
}

#[test]
fn ubotcad_profile_values() {
    let cfg = crate::Config::new(ISSUER, Product::UbotBuild, "0.9.0");
    assert_eq!(cfg.client_id, "ubotcad-desktop");
    assert_eq!(cfg.user_agent, "UbotCAD/0.9.0");
    assert_eq!(cfg.profile, crate::ClientProfile::UBOTCAD);
}

#[test]
fn config_rejects_product_or_client_outside_the_profile() {
    let cfg = crate::Config::new(ISSUER, Product::UbotBuild, "0.9.0");
    assert!(cfg.validate().is_ok());
    let mut other_product = cfg.clone();
    other_product.product = Product::VanBan;
    assert!(matches!(other_product.validate(), Err(Error::Config(_))));
    let mut other_client = cfg;
    other_client.client_id = DESKTOP_CLIENT_ID.into();
    assert!(matches!(other_client.validate(), Err(Error::Config(_))));
}

#[test]
fn office_profile_values() {
    let cfg = crate::Config::new(ISSUER, Product::VanBan, "0.6.5");
    assert_eq!(cfg.client_id, DESKTOP_CLIENT_ID);
    assert_eq!(cfg.user_agent, "ERPCons-VanBan/0.6.5");
    assert_eq!(cfg.profile.keyring_service, crate::SERVICE);
    assert!(!cfg.offline_licensing, "each app opts in");
    for p in Product::OFFICE {
        assert_eq!(p.pi_product(), "erpconsoffice", "{p:?}");
        assert_eq!(p.pinned_free_suffixes(), ["view", "export"]);
        assert_eq!(
            BuiltinFeature::defaults(p),
            vec![
                BuiltinFeature::new(OFFICE_VIEW, Tier::Free),
                BuiltinFeature::new(OFFICE_EXPORT, Tier::Free),
                BuiltinFeature::new(OFFICE_USE, Tier::Pro),
            ]
        );
    }
    assert_eq!(
        ClientProfile::for_pi_product(OFFICE_PI_PRODUCT),
        Some(ClientProfile::OFFICE)
    );
    assert_eq!(
        ClientProfile::for_pi_product("ubotbuild"),
        Some(ClientProfile::UBOTCAD)
    );
    assert_eq!(ClientProfile::for_pi_product("vanban"), None);
}

#[test]
fn ubotbuild_feature_ids() {
    assert!(is_valid_feature_id("ubotbuild.cad-use"));
    assert!(is_pinned_free("ubotbuild.cad-view"));
    assert!(is_pinned_free("ubotbuild.cad-export"));
    assert!(!is_pinned_free("ubotbuild.cad-use"));
    assert!(!is_pinned_free("ubotbuild.view"));
    assert!(is_pinned_free("erpconsoffice.view"));
    assert!(!is_pinned_free("erpconsoffice.cad-view"));
    assert!(!is_pinned_free("erpconsoffice.x.view"));
    assert!(!is_pinned_free("vanban.view"));
    assert_eq!(Product::UbotBuild.pi_product(), "ubotbuild");
}

#[test]
fn ubotbuild_builtin_defaults() {
    assert_eq!(
        BuiltinFeature::defaults(Product::UbotBuild),
        vec![
            BuiltinFeature::new("ubotbuild.cad-view", Tier::Free),
            BuiltinFeature::new("ubotbuild.cad-export", Tier::Free),
            BuiltinFeature::new("ubotbuild.cad-use", Tier::Pro),
        ]
    );
}

#[test]
fn default_dirs_per_profile() {
    fn last_two(p: std::path::PathBuf) -> Vec<String> {
        let mut parts: Vec<String> = p
            .components()
            .rev()
            .take(2)
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        parts.reverse();
        parts
    }
    let ubot = last_two(crate::storage::default_dir(&crate::ClientProfile::UBOTCAD).unwrap());
    let office = last_two(crate::storage::default_dir(&crate::ClientProfile::OFFICE).unwrap());
    if cfg!(windows) || cfg!(target_os = "macos") {
        assert_eq!(ubot, ["UbotCAD", "PI"]);
        assert_eq!(office, ["ERPCons", "PI"]);
    } else {
        assert_eq!(ubot, ["ubotcad", "pi"]);
        assert_eq!(office, ["erpcons", "pi"]);
    }
}

const PI_ACTIVATE_SIG: &str =
    "ARSxETbGfkPoTZOt5x1Hk2kq55REvRB6gWsMasmTzO6QjUEMfDEFR7k-vjv-N30uqQBCx2p8URGCm1Pr94RwBA";
const PI_REFRESH_SIG: &str =
    "DUWDs6iLGwGHtNJbD6H6bAlC7f1ot8YSJ1Yju76_OUOOjIprOBWY-5XwuBwRf3GPPrR63TyHGADC-4TdQ9M4AA";
const PI_JKT: &str = "_oEsEvOrTOasXbaaw1L5BssbEe9D-zPiUu9_9VImOIk";
const PI_REFRESH_NONCE: &str = "NonceNonceNonceNonce0123456789abcdefghijk";

fn seven_device() -> device::Device {
    let entry = json!({
        "installation_id": "9d1e5c2a-7b3f-4e6d-a1c8-5f2e9b7d3a10",
        "key": jose::b64(&[7u8; 32]),
    })
    .to_string();
    device::Device::from_entry(&entry).unwrap()
}

#[test]
fn pi_activate_message_matches_php() {
    let msg = activate_message(
        "0b6f1c1e-2a3b-4c5d-8e9f-001122334455",
        "AbCdEfGhIjKlMnOpQrStUvWxYz012345",
        "9d1e5c2a-7b3f-4e6d-a1c8-5f2e9b7d3a10",
        "ubotbuild",
    );
    assert_eq!(seven_device().sign(&msg), PI_ACTIVATE_SIG);
}

#[test]
fn pi_refresh_message_matches_php() {
    let msg = refresh_message(
        "3c2b1a09-8f7e-4d6c-b5a4-938271605f4e",
        1_792_828_800,
        PI_REFRESH_NONCE,
    );
    assert_eq!(seven_device().sign(&msg), PI_REFRESH_SIG);
}

#[test]
fn pi_raw_thumbprint_matches_php() {
    let public = SigningKey::from_bytes(&[7u8; 32])
        .verifying_key()
        .to_bytes();
    assert_eq!(jose::raw_key_thumbprint(&public), PI_JKT);
}

#[test]
fn compose_features_rules() {
    let codes: Vec<String> = [
        "cad-view",
        "cad-use",
        "offline",
        "offline-extended",
        "cad-3d",
    ]
    .map(String::from)
    .into();
    assert_eq!(
        compose_features("ubotbuild", &codes).unwrap(),
        [
            "ubotbuild.cad-view",
            "ubotbuild.cad-use",
            "ubotbuild.cad-3d"
        ]
    );
    assert_eq!(INTERNAL_CODES, ["offline", "offline-extended"]);
    for bad in ["CAD_USE", "-x", "a", &"a".repeat(65)] {
        assert_eq!(
            compose_features("ubotbuild", &[bad.to_string()]),
            Err(VerifyError::Feature),
            "{bad}"
        );
    }
}

#[test]
fn feature_ids_accept_dash() {
    assert!(is_valid_feature_id("ubotbuild.cad-use"));
    assert!(!is_valid_feature_id("ubotbuild.-cad"));
    assert!(is_feature_code("cad-3d"));
}

#[test]
fn nonce_rule() {
    assert!(is_nonce(&"a".repeat(16)));
    assert!(is_nonce(&"a".repeat(128)));
    assert!(!is_nonce(&"a".repeat(15)));
    assert!(!is_nonce(&"a".repeat(129)));
    assert!(!is_nonce(&format!("{}+", "a".repeat(16))));
}

#[test]
fn from_parts_pi_licensing_codes() {
    assert_eq!(
        ApiCode::from_parts(403, Some("ORG_CONTEXT_REQUIRED")),
        ApiCode::OrgContextRequired
    );
    assert_eq!(
        ApiCode::from_parts(403, Some("NO_ENTITLEMENT")),
        ApiCode::NoEntitlement
    );
    assert_eq!(ApiCode::from_parts(403, Some("NO_SEAT")), ApiCode::NoSeat);
    assert_eq!(
        ApiCode::from_parts(404, None),
        ApiCode::Other(String::new())
    );
}

#[test]
fn http_date_parses() {
    assert_eq!(
        parse_http_date("Thu, 29 Oct 2026 00:00:00 GMT"),
        Some(1_793_232_000)
    );
    assert_eq!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), None);
}

#[test]
fn problem_errors_are_field_names() {
    let reply = crate::http::Reply {
        status: 422,
        body: br#"{"ok":false,"message":"x","errors":{"timestamp":"..","nonce":".."}}"#.to_vec(),
        correlation_id: "c".into(),
        retry_after: None,
        date: None,
    };
    let Error::Api(e) = reply.error() else {
        panic!("not an API error");
    };
    assert_eq!(*e.errors, ["nonce", "timestamp"]);
}

#[test]
fn problem_with_non_object_errors_keeps_code() {
    let reply = crate::http::Reply {
        status: 409,
        body: br#"{"ok":false,"message":"x","code":"DEVICE_CAP","errors":[]}"#.to_vec(),
        correlation_id: "c".into(),
        retry_after: None,
        date: None,
    };
    let Error::Api(e) = reply.error() else {
        panic!("not an API error");
    };
    assert_eq!(e.code, ApiCode::DeviceCapReached);
    assert!(e.errors.is_empty());
}

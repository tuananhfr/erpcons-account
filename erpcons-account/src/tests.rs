//! Unit tests: lease.md §12 vectors, JOSE profile, trusted time, catalog, helpers.
use std::time::Duration;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde_json::json;

use crate::{
    ApiCode, Backoff, BuiltinFeature, DESKTOP_CLIENT_ID, Error, PLATFORM_KEYS, PinnedKey, Product,
    Tier, VerifyError,
    catalog::{self, is_pinned_free, is_valid_feature_id},
    device::{self, ProofClaims},
    jose,
    lease::{self, Copies, Expect},
    storage,
    time::{TrustedTime, parse_rfc3339},
};

const ISSUER: &str = "https://id.pi.invalid";
const KID: &str = "pi-lease-example-1";
const PLATFORM_HEX: &str = "f4d62fdc454061bc8c0a7cb2c1d529254f7dc93492138e2d43f5c048c9e2d200";
const DEVICE_X: &str = "l6OK4YIRw2jcSo2qqLHguJVk3hK-ESiS5OFGX5SAYsA";
const DEVICE_JKT: &str = "n5qSxkI9wZW-xoKQMjjpdmktYTcLmdyB_lG9XaQhqLM";
const USER: &str = "usr_01JB6Z2K8Q4XN3T5V7W9Y1A2C3";
const ORG: &str = "org_01JB6Z3M5R7T9V1X3Z5B7D9F1H";
const DEVICE_ID: &str = "dev_01JB7A0C2E4G6J8L0N2Q4S6U8W";
const INSTALLATION: &str = "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f";
const NONCE_ACTIVATE: &str = "RFIe5GcljuC_NMfuhA0MLgYEOTcDhpKb2aN03xTxK0A";
const NONCE_REFRESH: &str = "69kBNOzEoxD6att1omKEeRkHNBgs9uVXYSqVN_bqg_E";
const ACTIVATION_NOW: i64 = 1_792_828_800;
const REFRESH_NOW: i64 = 1_792_915_200;

// JWS strings from the examples of docs/contract.openapi.yaml.
const LEASE_ACTIVATION: &str = "eyJhbGciOiJFZERTQSIsImtpZCI6InBpLWxlYXNlLWV4YW1wbGUtMSIsInR5cCI6InBpLWxlYXNlK2p3dCJ9.eyJpc3MiOiJodHRwczovL2lkLnBpLmludmFsaWQiLCJhdWQiOiJlcnBjb25zLW9mZmljZS1kZXNrdG9wIiwibGVhc2VfaWQiOiJsc2VfMDFKQjdBMkY0SDZLOE0wUDJSNFQ2VjhYMFoiLCJzdWIiOiJ1c3JfMDFKQjZaMks4UTRYTjNUNVY3VzlZMUEyQzMiLCJvcmciOiJvcmdfMDFKQjZaM001UjdUOVYxWDNaNUI3RDlGMUgiLCJkZXZpY2VfaWQiOiJkZXZfMDFKQjdBMEMyRTRHNko4TDBOMlE0UzZVOFciLCJpbnN0YWxsYXRpb25faWQiOiI2ZjFjMmQzZS00YjVhLTRjN2QtOGU5Zi0wYTFiMmMzZDRlNWYiLCJjbmYiOnsiamt0IjoibjVxU3hrSTl3WlcteG9LUU1qanBkbWt0WVRjTG1keUJfbEc5WGFRaHFMTSJ9LCJwcm9kdWN0IjoidmFuYmFuIiwiZmVhdHVyZXMiOlsidmFuYmFuLnVzZSJdLCJlbnRpdGxlbWVudF9pZHMiOlsiZW50XzAxSkI3QTFEM0Y1SDdLOU0xUDNSNVQ3VjlYIl0sIm5iZiI6MTc5MjgyODgwMCwiaWF0IjoxNzkyODI4ODAwLCJleHAiOjE3OTU0MjA4MDAsIm5vbmNlIjoiUkZJZTVHY2xqdUNfTk1mdWhBME1MZ1lFT1RjRGhwS2IyYU4wM3hUeEswQSIsInBvbGljeV92ZXJzaW9uIjoiMjAyNi0xMC0wMS4xIn0.9ErzrUmc2F-ASSgptBdMZXb1cBNDNKvfx1EkVAxGlStKg8wjASj7yZXzCf8yPcHJiaPB05YH7ce3TTBxg4qiAQ";
const LEASE_REFRESH: &str = "eyJhbGciOiJFZERTQSIsImtpZCI6InBpLWxlYXNlLWV4YW1wbGUtMSIsInR5cCI6InBpLWxlYXNlK2p3dCJ9.eyJpc3MiOiJodHRwczovL2lkLnBpLmludmFsaWQiLCJhdWQiOiJlcnBjb25zLW9mZmljZS1kZXNrdG9wIiwibGVhc2VfaWQiOiJsc2VfMDFKQjlDNEg2SzhNMFAyUjRUNlY4WDBaMkIiLCJzdWIiOiJ1c3JfMDFKQjZaMks4UTRYTjNUNVY3VzlZMUEyQzMiLCJvcmciOiJvcmdfMDFKQjZaM001UjdUOVYxWDNaNUI3RDlGMUgiLCJkZXZpY2VfaWQiOiJkZXZfMDFKQjdBMEMyRTRHNko4TDBOMlE0UzZVOFciLCJpbnN0YWxsYXRpb25faWQiOiI2ZjFjMmQzZS00YjVhLTRjN2QtOGU5Zi0wYTFiMmMzZDRlNWYiLCJjbmYiOnsiamt0IjoibjVxU3hrSTl3WlcteG9LUU1qanBkbWt0WVRjTG1keUJfbEc5WGFRaHFMTSJ9LCJwcm9kdWN0IjoidmFuYmFuIiwiZmVhdHVyZXMiOlsidmFuYmFuLnVzZSJdLCJlbnRpdGxlbWVudF9pZHMiOlsiZW50XzAxSkI3QTFEM0Y1SDdLOU0xUDNSNVQ3VjlYIl0sIm5iZiI6MTc5MjkxNTIwMCwiaWF0IjoxNzkyOTE1MjAwLCJleHAiOjE3OTU1MDcyMDAsIm5vbmNlIjoiNjlrQk5PekVveEQ2YXR0MW9tS0VlUmtITkJnczl1VlhZU3FWTl9icWdfRSIsInBvbGljeV92ZXJzaW9uIjoiMjAyNi0xMC0wMS4xIn0.31UoZBsxzLXSTj-K4SjrT6uKyaEKGRiSiLwzY3wT7tsdqU04WTSrrdRXmzBiKhL0MB0fOMUDqizX1Xah1OUcCA";
const CATALOG_VANBAN: &str = "eyJhbGciOiJFZERTQSIsImtpZCI6InBpLWxlYXNlLWV4YW1wbGUtMSIsInR5cCI6InBpLWZlYXR1cmUtY2F0YWxvZytqd3QifQ.eyJpc3MiOiJodHRwczovL2lkLnBpLmludmFsaWQiLCJwcm9kdWN0IjoidmFuYmFuIiwiY2F0YWxvZ192ZXJzaW9uIjoxLCJpYXQiOjE3OTI4Mjg4MDAsImZlYXR1cmVzIjpbeyJmZWF0dXJlIjoidmFuYmFuLnZpZXciLCJ0aWVyIjoiZnJlZSJ9LHsiZmVhdHVyZSI6InZhbmJhbi5leHBvcnQiLCJ0aWVyIjoiZnJlZSJ9LHsiZmVhdHVyZSI6InZhbmJhbi51c2UiLCJ0aWVyIjoiZnJlZSJ9XX0.8KO9EMOFTwp8lnncsJmUr2os3nqQJLQexN5RS-8BfCU00lHKM7wsTYlY8mZMx_rFsHrqmwMtN5T7luGA_9iIBg";
const PROOF_ACTIVATE: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6InBpLWRldmljZS1wcm9vZitqd3QiLCJqd2siOnsia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJsNk9LNFlJUncyamNTbzJxcUxIZ3VKVmszaEstRVNpUzVPRkdYNVNBWXNBIn19.eyJub25jZSI6IlJGSWU1R2NsanVDX05NZnVoQTBNTGdZRU9UY0RocEtiMmFOMDN4VHhLMEEiLCJwdXJwb3NlIjoiYWN0aXZhdGUiLCJpbnN0YWxsYXRpb25faWQiOiI2ZjFjMmQzZS00YjVhLTRjN2QtOGU5Zi0wYTFiMmMzZDRlNWYiLCJwcm9kdWN0X2lkIjoidmFuYmFuIiwicGxhdGZvcm0iOiJ3aW5kb3dzIiwiY2xpZW50X3ZlcnNpb24iOiIwLjYuNSIsImlhdCI6MTc5MjgyODc5OH0.xmMHF-Cye5aX_-1vh-Ip9HamZwwTogdIB19m5UoA00NgYsE1tf8JChUPeB3gBep5mhF4j30Kc9kpAK_PN5tCCA";
const PROOF_REFRESH: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6InBpLWRldmljZS1wcm9vZitqd3QiLCJqd2siOnsia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJsNk9LNFlJUncyamNTbzJxcUxIZ3VKVmszaEstRVNpUzVPRkdYNVNBWXNBIn19.eyJub25jZSI6IjY5a0JOT3pFb3hENmF0dDFvbUtFZVJrSE5CZ3M5dVZYWVNxVk5fYnFnX0UiLCJwdXJwb3NlIjoicmVmcmVzaCIsImRldmljZV9pZCI6ImRldl8wMUpCN0EwQzJFNEc2SjhMME4yUTRTNlU4VyIsImluc3RhbGxhdGlvbl9pZCI6IjZmMWMyZDNlLTRiNWEtNGM3ZC04ZTlmLTBhMWIyYzNkNGU1ZiIsInByb2R1Y3RfaWQiOiJ2YW5iYW4iLCJwbGF0Zm9ybSI6IndpbmRvd3MiLCJjbGllbnRfdmVyc2lvbiI6IjAuNi41IiwiaWF0IjoxNzkyOTE1MTk4fQ.O6I8mHOcSFMtnxmQSuzARuBYdcj03B2z8hkbx8AXmb8ncSE-Bx7W5AKf_WmgOq6SiJcaBkRIAZzoKDhQPNCECw";

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

fn expect(nonce: &'static str) -> Expect<'static> {
    Expect {
        issuer: ISSUER,
        audience: DESKTOP_CLIENT_ID,
        product: Product::VanBan,
        sub: USER,
        org: Some(ORG),
        installation_id: INSTALLATION,
        jkt: DEVICE_JKT,
        device_id: DEVICE_ID,
        nonce: Some(nonce),
    }
}

fn copies(until: &'static str) -> (Vec<String>, Vec<String>, &'static str) {
    (
        vec!["ent_01JB7A1D3F5H7K9M1P3R5T7V9X".into()],
        vec!["vanban.use".into()],
        until,
    )
}

#[test]
fn vector_device_thumbprint() {
    assert_eq!(jose::thumbprint(DEVICE_X), DEVICE_JKT);
}

#[test]
fn vector_leases_pass_section_9() {
    for (jws, nonce, now, until, exp) in [
        (
            LEASE_ACTIVATION,
            NONCE_ACTIVATE,
            ACTIVATION_NOW,
            "2026-11-23T08:00:00Z",
            1_795_420_800,
        ),
        (
            LEASE_REFRESH,
            NONCE_REFRESH,
            REFRESH_NOW,
            "2026-11-24T08:00:00Z",
            1_795_507_200,
        ),
    ] {
        let lease = lease::verify(jws, &keys(), &expect(nonce)).unwrap();
        lease.window(now).unwrap();
        let (ids, rights, until) = copies(until);
        lease
            .check_copies(&Copies {
                entitlement_ids: &ids,
                rights: &rights,
                offline_valid_until: until,
                policy_version: "2026-10-01.1",
            })
            .unwrap();
        assert_eq!(lease.exp, exp);
        assert_eq!(lease.features, ["vanban.use"]);
        let mut time = TrustedTime::new(0, Duration::ZERO);
        time.now(now, Duration::ZERO);
        assert!(!time.correct(lease.iat, Duration::ZERO));
    }
}

#[test]
fn vector_catalog_verifies() {
    let c = catalog::verify(CATALOG_VANBAN, &keys(), ISSUER, Product::VanBan, 0).unwrap();
    assert_eq!(c.version, 1);
    assert_eq!(c.tiers.len(), 3);
    assert!(c.tiers.values().all(|t| *t == Tier::Free));
    assert_eq!(
        catalog::verify(CATALOG_VANBAN, &keys(), ISSUER, Product::VanBan, 2).unwrap_err(),
        VerifyError::Downgrade
    );
    assert_eq!(
        catalog::verify(CATALOG_VANBAN, &keys(), ISSUER, Product::Pdf, 0).unwrap_err(),
        VerifyError::Product
    );
    // Explicit typing: a catalog is never a lease and a lease never a catalog.
    assert_eq!(
        lease::verify(CATALOG_VANBAN, &keys(), &expect(NONCE_ACTIVATE)).unwrap_err(),
        VerifyError::Header
    );
    assert_eq!(
        catalog::verify(LEASE_ACTIVATION, &keys(), ISSUER, Product::VanBan, 0).unwrap_err(),
        VerifyError::Header
    );
}

#[test]
fn vector_proofs_match_client_encoding() {
    let key =
        VerifyingKey::from_bytes(&jose::unb64(DEVICE_X).unwrap().try_into().unwrap()).unwrap();
    for (jws, nonce, purpose, device_id, iat) in [
        (
            PROOF_ACTIVATE,
            NONCE_ACTIVATE,
            "activate",
            None,
            1_792_828_798,
        ),
        (
            PROOF_REFRESH,
            NONCE_REFRESH,
            "refresh",
            Some(DEVICE_ID),
            1_792_915_198,
        ),
    ] {
        let parts: Vec<&str> = jws.split('.').collect();
        let claims = ProofClaims {
            nonce,
            purpose,
            device_id,
            installation_id: INSTALLATION,
            product_id: "vanban",
            platform: "windows",
            client_version: "0.6.5",
            iat,
        };
        assert_eq!(
            parts[0],
            jose::b64(device::proof_header(DEVICE_X).as_bytes())
        );
        assert_eq!(
            parts[1],
            jose::b64(serde_json::to_string(&claims).unwrap().as_bytes())
        );
        let sig = Signature::from_slice(&jose::unb64(parts[2]).unwrap()).unwrap();
        key.verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .unwrap();
    }
}

#[test]
fn lease_claim_checks_fail_in_order() {
    let ok = expect(NONCE_ACTIVATE);
    let cases: Vec<(Expect, VerifyError)> = vec![
        (
            Expect {
                issuer: "https://other.invalid",
                ..expect(NONCE_ACTIVATE)
            },
            VerifyError::Issuer,
        ),
        (
            Expect {
                audience: "erpcons-office-web",
                ..expect(NONCE_ACTIVATE)
            },
            VerifyError::Audience,
        ),
        (
            Expect {
                product: Product::Pdf,
                ..expect(NONCE_ACTIVATE)
            },
            VerifyError::Product,
        ),
        (
            Expect {
                sub: "usr_other",
                ..expect(NONCE_ACTIVATE)
            },
            VerifyError::Subject,
        ),
        (
            Expect {
                org: None,
                ..expect(NONCE_ACTIVATE)
            },
            VerifyError::Org,
        ),
        (
            Expect {
                installation_id: "00000000-0000-4000-8000-000000000000",
                ..expect(NONCE_ACTIVATE)
            },
            VerifyError::Installation,
        ),
        (
            Expect {
                jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ..expect(NONCE_ACTIVATE)
            },
            VerifyError::KeyBinding,
        ),
        (
            Expect {
                device_id: "dev_other",
                ..expect(NONCE_ACTIVATE)
            },
            VerifyError::Device,
        ),
        (expect(NONCE_REFRESH), VerifyError::Nonce),
    ];
    for (e, want) in cases {
        assert_eq!(
            lease::verify(LEASE_ACTIVATION, &keys(), &e).unwrap_err(),
            want
        );
    }
    let other_kid = vec![PinnedKey {
        kid: "next".into(),
        key: hex32(PLATFORM_HEX),
    }];
    assert_eq!(
        lease::verify(LEASE_ACTIVATION, &other_kid, &ok).unwrap_err(),
        VerifyError::UnknownKey
    );
    let mut forged = LEASE_ACTIVATION.to_owned();
    forged.pop();
    forged.push('B');
    assert!(matches!(
        lease::verify(&forged, &keys(), &ok).unwrap_err(),
        VerifyError::Signature | VerifyError::Format
    ));
    let lease = lease::verify(LEASE_ACTIVATION, &keys(), &ok).unwrap();
    assert_eq!(lease.window(lease.nbf - 301), Err(VerifyError::NotYetValid));
    assert_eq!(lease.window(lease.nbf - 300), Ok(()));
    assert_eq!(lease.window(lease.exp), Err(VerifyError::Expired));
    let (ids, _, until) = copies("2026-11-23T08:00:00Z");
    let rights = vec!["vanban.use".to_owned(), "vanban.extra".to_owned()];
    assert_eq!(
        lease.check_copies(&Copies {
            entitlement_ids: &ids,
            rights: &rights,
            offline_valid_until: until,
            policy_version: "2026-10-01.1",
        }),
        Err(VerifyError::CopyMismatch)
    );
}

fn signed(header: &serde_json::Value, payload: &str, key: &SigningKey) -> String {
    jose::sign_compact(&header.to_string(), payload, key)
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
    for ok in ["vanban.view", "pdf.use", "bangtinh.a_b.c1"] {
        assert!(is_valid_feature_id(ok), "{ok}");
    }
    for bad in [
        "vanban",
        "word.use",
        "vanban.",
        "vanban.Use",
        "vanban..x",
        "pdf.a-b",
    ] {
        assert!(!is_valid_feature_id(bad), "{bad}");
    }
    assert!(is_pinned_free("trinhchieu.export"));
    assert!(!is_pinned_free("trinhchieu.use"));
    let builtin = vec![
        BuiltinFeature::new("vanban.view", Tier::Free),
        BuiltinFeature::new("vanban.advanced", Tier::Free),
    ];
    let key = SigningKey::from_bytes(&[9; 32]);
    let pinned = vec![PinnedKey {
        kid: "k".into(),
        key: key.verifying_key().to_bytes(),
    }];
    let payload = json!({
        "iss": ISSUER, "product": "vanban", "catalog_version": 2, "iat": 1,
        "features": [{"feature": "vanban.view", "tier": "pro"}, {"feature": "vanban.advanced", "tier": "pro"}]
    });
    let jws = signed(
        &json!({"alg": "EdDSA", "kid": "k", "typ": "pi-feature-catalog+jwt"}),
        &payload.to_string(),
        &key,
    );
    let c = catalog::verify(&jws, &pinned, ISSUER, Product::VanBan, 1).unwrap();
    assert_eq!(
        catalog::tier(&builtin, Some(&c), "vanban.view"),
        Some(Tier::Free)
    );
    assert_eq!(
        catalog::tier(&builtin, Some(&c), "vanban.advanced"),
        Some(Tier::Pro)
    );
    assert_eq!(
        catalog::tier(&builtin, None, "vanban.advanced"),
        Some(Tier::Free)
    );
    assert_eq!(catalog::tier(&builtin, Some(&c), "vanban.unknown"), None);
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
fn office_profile_unchanged() {
    let cfg = crate::Config::new(ISSUER, Product::VanBan, "0.6.5");
    assert_eq!(cfg.client_id, DESKTOP_CLIENT_ID);
    assert_eq!(cfg.user_agent, "ERPCons-VanBan/0.6.5");
    assert_eq!(cfg.profile.keyring_service, crate::SERVICE);
}

#[test]
fn ubotbuild_feature_ids() {
    assert!(is_valid_feature_id("ubotbuild.cad.use"));
    assert!(is_pinned_free("ubotbuild.cad.view"));
    assert!(is_pinned_free("ubotbuild.cad.export"));
    assert!(!is_pinned_free("ubotbuild.cad.use"));
    assert!(!is_pinned_free("ubotbuild.view"));
    assert!(is_pinned_free("vanban.view"));
    assert!(!is_pinned_free("vanban.x.view"));
}

#[test]
fn ubotbuild_builtin_defaults() {
    assert_eq!(
        BuiltinFeature::defaults(Product::UbotBuild),
        vec![
            BuiltinFeature::new("ubotbuild.cad.view", Tier::Free),
            BuiltinFeature::new("ubotbuild.cad.export", Tier::Free),
            BuiltinFeature::new("ubotbuild.cad.use", Tier::Pro),
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

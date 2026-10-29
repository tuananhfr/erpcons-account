//! PI's device protocol as the mock serves it, driven over HTTP and signed with ed25519-dalek
//! directly so the checks do not depend on erpcons-account.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use pi_mock::{
    DEFAULT_USER, DeviceStatus, FREE_UBOTCAD, ORG_A, ORG_B, Scenario, Server, Tenant,
    UBOTCAD_CLIENT,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const T0: i64 = 1_793_000_000;
const SCOPE: &str = "openid pi.devices pi.entitlements";
const INSTALLATION: &str = "5f0c2b7e-3a41-4d8e-9b6a-1c7d2e8f9a30";
const OTHER_INSTALLATION: &str = "a1b2c3d4-0000-4000-8000-00000000beef";

struct Out {
    status: u16,
    date: Option<String>,
    replayed: bool,
    json: Value,
}

struct Fx {
    server: Server,
    agent: ureq::Agent,
}

fn tenant() -> Tenant {
    Tenant::new("ten_cad", ORG_A, "ubotbuild", &FREE_UBOTCAD)
}

fn fx_with(tenants: Vec<Tenant>) -> Fx {
    let server = Server::start(Scenario {
        tenants,
        now: Some(T0),
        ..Default::default()
    });
    let agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    Fx { server, agent }
}

fn fx() -> Fx {
    fx_with(vec![tenant()])
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

impl Fx {
    fn token(&self, org: Option<&str>) -> String {
        self.server
            .issue_access_token(DEFAULT_USER, org, UBOTCAD_CLIENT, SCOPE)
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
        headers: &[(&str, &str)],
    ) -> Out {
        let url = format!("{}{path}", self.server.base_url());
        let mut resp = if method == "GET" {
            let mut r = self.agent.get(&url);
            if let Some(t) = token {
                r = r.header("Authorization", format!("Bearer {t}"));
            }
            r.call()
        } else {
            let mut r = self
                .agent
                .post(&url)
                .header("Content-Type", "application/json");
            if let Some(t) = token {
                r = r.header("Authorization", format!("Bearer {t}"));
            }
            for (k, v) in headers {
                r = r.header(*k, *v);
            }
            r.send(body.map(Value::to_string).unwrap_or_default())
        }
        .expect("transport");
        let status = resp.status().as_u16();
        let date = resp
            .headers()
            .get("date")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let replayed = resp.headers().contains_key("idempotent-replayed");
        let text = resp.body_mut().read_to_string().expect("body");
        Out {
            status,
            date,
            replayed,
            json: serde_json::from_str(&text).unwrap_or(Value::Null),
        }
    }

    fn challenge(&self, token: &str, product: &str) -> Out {
        self.call(
            "GET",
            &format!("/api/v1/id/devices/challenge?product_id={product}"),
            Some(token),
            None,
            &[],
        )
    }

    /// Activation body for an already fetched challenge, signed by `signer`.
    fn activation_body(
        &self,
        challenge: &Value,
        installation: &str,
        product: &str,
        device_key: &SigningKey,
        signer: &SigningKey,
    ) -> Value {
        let id = challenge["challengeId"].as_str().expect("challengeId");
        let nonce = challenge["nonce"].as_str().expect("nonce");
        let message = format!("pi-device-activate\n{id}\n{nonce}\n{installation}\n{product}");
        json!({
            "installationId": installation,
            "productId": product,
            "platform": "windows",
            "clientVersion": "0.1.0",
            "devicePublicKey": b64(device_key.verifying_key().as_bytes()),
            "challengeId": id,
            "signedChallenge": b64(&signer.sign(message.as_bytes()).to_bytes()),
        })
    }

    fn activate_as(&self, token: &str, installation: &str, product: &str, k: &SigningKey) -> Out {
        let challenge = self.challenge(token, product);
        assert_eq!(challenge.status, 201, "{}", challenge.json);
        let body = self.activation_body(&challenge.json, installation, product, k, k);
        self.call(
            "POST",
            "/api/v1/id/devices/activate",
            Some(token),
            Some(&body),
            &[],
        )
    }

    fn activate(&self, installation: &str) -> Out {
        let token = self.token(Some(ORG_A));
        self.activate_as(&token, installation, "ubotbuild", &key(1))
    }

    fn refresh(&self, body: &Value) -> Out {
        let token = self.token(Some(ORG_A));
        self.call(
            "POST",
            "/api/v1/id/licenses/refresh",
            Some(&token),
            Some(body),
            &[],
        )
    }
}

fn refresh_body(device_id: &str, timestamp: i64, nonce: &str, k: &SigningKey) -> Value {
    let message = format!("pi-license-refresh\n{device_id}\n{timestamp}\n{nonce}");
    json!({
        "deviceId": device_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": b64(&k.sign(message.as_bytes()).to_bytes()),
    })
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn parse_iso(s: &str) -> i64 {
    assert_eq!(s.len(), 20, "{s}");
    assert!(s.as_bytes()[10] == b'T' && s.ends_with('Z'), "{s}");
    let n = |r: std::ops::Range<usize>| s[r].parse::<i64>().expect("number");
    days_from_civil(n(0..4), n(5..7), n(8..10)) * 86_400
        + n(11..13) * 3600
        + n(14..16) * 60
        + n(17..19)
}

fn parse_http_date(s: &str) -> i64 {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let parts: Vec<&str> = s.split(' ').collect();
    assert!(
        parts.len() == 6 && parts[0].ends_with(',') && parts[5] == "GMT",
        "{s}"
    );
    let month = MONTHS.iter().position(|m| *m == parts[2]).expect("month") as i64 + 1;
    let time: Vec<i64> = parts[4]
        .split(':')
        .map(|n| n.parse().expect("time"))
        .collect();
    days_from_civil(
        parts[3].parse().expect("year"),
        month,
        parts[1].parse().expect("day"),
    ) * 86_400
        + time[0] * 3600
        + time[1] * 60
        + time[2]
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

fn jws_parts(lease: &str) -> (String, Value, Vec<u8>, String) {
    let parts: Vec<&str> = lease.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header = String::from_utf8(B64.decode(parts[0]).expect("header")).expect("utf8");
    let claims = serde_json::from_slice(&B64.decode(parts[1]).expect("payload")).expect("claims");
    let sig = B64.decode(parts[2]).expect("signature");
    (header, claims, sig, format!("{}.{}", parts[0], parts[1]))
}

fn keys(v: &Value) -> Vec<&str> {
    let mut k: Vec<&str> = v
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    k.sort_unstable();
    k
}

#[test]
fn challenge_is_201_with_32_char_nonce() {
    let fx = fx();
    let token = fx.token(Some(ORG_A));
    let out = fx.challenge(&token, "ubotbuild");
    assert_eq!(out.status, 201);
    assert!(is_uuid(out.json["challengeId"].as_str().unwrap()));
    let nonce = out.json["nonce"].as_str().unwrap();
    assert!(
        nonce.len() == 32
            && nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
    assert_eq!(parse_iso(out.json["expiresAt"].as_str().unwrap()), T0 + 300);

    let bad = fx.challenge(&token, "vanban");
    assert_eq!(bad.status, 422);
    assert!(bad.json["errors"]["productId"].is_string());
    assert!(bad.json.get("code").is_none());
}

#[test]
fn activation_returns_pi_lease() {
    let fx = fx();
    let token = fx.token(Some(ORG_A));
    let challenge = fx.challenge(&token, "ubotbuild");
    let k = key(1);
    let body = fx.activation_body(&challenge.json, INSTALLATION, "ubotbuild", &k, &k);
    let out = fx.call(
        "POST",
        "/api/v1/id/devices/activate",
        Some(&token),
        Some(&body),
        &[],
    );
    assert_eq!(out.status, 201, "{}", out.json);
    assert_eq!(
        keys(&out.json),
        [
            "deviceId",
            "entitlementId",
            "lease",
            "leaseId",
            "offlineAllowed",
            "offlineDays",
            "offlineValidUntil",
            "ok",
            "policyVersion",
            "rights",
        ]
    );
    assert_eq!(out.json["ok"], true);
    assert_eq!(out.json["entitlementId"], "ten_cad");
    assert_eq!(out.json["rights"], json!(FREE_UBOTCAD));
    assert_eq!(out.json["offlineDays"], 7);
    assert_eq!(out.json["policyVersion"], "ubb-mien-phi@1");

    let (header, claims, sig, signing_input) = jws_parts(out.json["lease"].as_str().unwrap());
    assert_eq!(
        header,
        format!(
            r#"{{"alg":"EdDSA","typ":"pi-lease+jwt","kid":"{}"}}"#,
            fx.server.lease_key_id()
        )
    );
    VerifyingKey::from_bytes(&fx.server.lease_public_key())
        .unwrap()
        .verify_strict(
            signing_input.as_bytes(),
            &ed25519_dalek::Signature::from_slice(&sig).unwrap(),
        )
        .expect("lease verifies with the published key");

    assert_eq!(claims["jti"], out.json["leaseId"]);
    assert_eq!(claims["device"], out.json["deviceId"]);
    assert_eq!(claims["tenant"], "ten_cad");
    assert_eq!(claims["org"], ORG_A);
    assert_eq!(claims["sub"], DEFAULT_USER);
    assert_eq!(claims["product"], "ubotbuild");
    assert_eq!(claims["iss"], fx.server.issuer());
    assert_eq!(claims["features"], json!(FREE_UBOTCAD));
    assert_eq!(
        claims["cnf"]["jkt"],
        b64(&Sha256::digest(k.verifying_key().as_bytes()))
    );
    assert_eq!(claims["nonce"], challenge.json["nonce"]);
    assert_eq!(claims["aud"], "ubotcad-desktop");
    assert_eq!(claims["policy_version"], "ubb-mien-phi@1");
    assert_eq!(claims["offline_allowed"], true);
    assert_eq!(claims["warn_days"], json!([7, 3, 1]));
    assert_eq!(claims["after_expiry"], "read_export");
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        604_800
    );
    assert_eq!(claims["nbf"], claims["iat"]);
    assert_eq!(fx.server.device_rows().len(), 1);
}

#[test]
fn lease_members_are_in_pi_order_with_aud_last() {
    let fx = fx();
    let out = fx.activate(INSTALLATION);
    let payload = out.json["lease"]
        .as_str()
        .unwrap()
        .split('.')
        .nth(1)
        .unwrap()
        .to_owned();
    let text = String::from_utf8(B64.decode(payload).unwrap()).unwrap();
    let positions: Vec<usize> = [
        "\"iss\"",
        "\"jti\"",
        "\"sub\"",
        "\"org\"",
        "\"tenant\"",
        "\"product\"",
        "\"device\"",
        "\"cnf\"",
        "\"features\"",
        "\"offline_allowed\"",
        "\"policy_version\"",
        "\"nonce\"",
        "\"iat\"",
        "\"nbf\"",
        "\"exp\"",
        "\"warn_days\"",
        "\"after_expiry\"",
        "\"aud\"",
    ]
    .iter()
    .map(|k| text.find(k).unwrap_or_else(|| panic!("{k} in {text}")))
    .collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{text}");
}

#[test]
fn activation_errors_follow_pi_order() {
    let fx = fx();
    let token = fx.token(Some(ORG_A));
    let k = key(1);

    let challenge = fx.challenge(&token, "ubotbuild");
    let body = fx.activation_body(&challenge.json, INSTALLATION, "ubotbuild", &k, &k);
    let url = "/api/v1/id/devices/activate";
    assert_eq!(
        fx.call("POST", url, Some(&token), Some(&body), &[]).status,
        201
    );
    let reused = fx.call("POST", url, Some(&token), Some(&body), &[]);
    assert_eq!(
        (reused.status, reused.json["code"].as_str()),
        (409, Some("CHALLENGE_INVALID"))
    );

    // A bad signature does not consume the challenge.
    let challenge = fx.challenge(&token, "ubotbuild");
    let forged = fx.activation_body(
        &challenge.json,
        OTHER_INSTALLATION,
        "ubotbuild",
        &k,
        &key(9),
    );
    let bad = fx.call("POST", url, Some(&token), Some(&forged), &[]);
    assert_eq!(bad.status, 422);
    assert!(bad.json["errors"]["signedChallenge"].is_string());
    let good = fx.activation_body(&challenge.json, OTHER_INSTALLATION, "ubotbuild", &k, &k);
    assert_eq!(
        fx.call("POST", url, Some(&token), Some(&good), &[]).status,
        201
    );

    let no_org = fx.token(None);
    let out = fx.activate_as(&no_org, "installation-three", "ubotbuild", &k);
    assert_eq!(
        (out.status, out.json["code"].as_str()),
        (403, Some("ORG_CONTEXT_REQUIRED"))
    );

    let other_org = fx.token(Some(ORG_B));
    let out = fx.activate_as(&other_org, "installation-three", "ubotbuild", &k);
    assert_eq!(
        (out.status, out.json["code"].as_str()),
        (403, Some("NO_ENTITLEMENT"))
    );
    assert_eq!(out.json["ok"], false);
}

#[test]
fn no_seat_revoked_and_cap() {
    let seatless = fx_with(vec![tenant().seats(&[])]);
    let out = seatless.activate(INSTALLATION);
    assert_eq!(
        (out.status, out.json["code"].as_str()),
        (403, Some("NO_SEAT"))
    );

    let fx = fx();
    let first = fx.activate(INSTALLATION);
    let id = first.json["deviceId"].as_str().unwrap().to_owned();
    assert!(fx.server.revoke_device(&id));
    assert_eq!(fx.server.device_rows()[0].status, DeviceStatus::Revoked);
    let out = fx.activate(INSTALLATION);
    assert_eq!(
        (out.status, out.json["code"].as_str()),
        (409, Some("DEVICE_REVOKED"))
    );

    let capped = fx_with(vec![tenant().device_cap(1)]);
    assert_eq!(capped.activate(INSTALLATION).status, 201);
    let out = capped.activate(OTHER_INSTALLATION);
    assert_eq!(
        (out.status, out.json["code"].as_str()),
        (409, Some("DEVICE_CAP"))
    );
    // The installation already holding the slot may activate again.
    assert_eq!(capped.activate(INSTALLATION).status, 201);
}

#[test]
fn devices_are_per_product() {
    let fx = fx_with(vec![
        tenant(),
        Tenant::new("ten_erp", ORG_A, "erpcons", &["erp-use"]),
    ]);
    let token = fx.token(Some(ORG_A));
    let k = key(1);
    assert_eq!(
        fx.activate_as(&token, INSTALLATION, "ubotbuild", &k).status,
        201
    );
    assert_eq!(
        fx.activate_as(&token, INSTALLATION, "erpcons", &k).status,
        201
    );
    let rows = fx.server.device_rows();
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].device_id, rows[1].device_id);
    assert_eq!(rows[0].installation_id, rows[1].installation_id);
}

#[test]
fn activation_is_idempotent_with_key() {
    let fx = fx();
    let token = fx.token(Some(ORG_A));
    let k = key(1);
    let challenge = fx.challenge(&token, "ubotbuild");
    let body = fx.activation_body(&challenge.json, INSTALLATION, "ubotbuild", &k, &k);
    let url = "/api/v1/id/devices/activate";
    let headers = [("Idempotency-Key", "idem-key-0001")];
    let first = fx.call("POST", url, Some(&token), Some(&body), &headers);
    assert_eq!(first.status, 201);
    let replay = fx.call("POST", url, Some(&token), Some(&body), &headers);
    assert!(replay.replayed);
    assert_eq!(replay.json, first.json);

    let other = fx.challenge(&token, "ubotbuild");
    let body2 = fx.activation_body(&other.json, INSTALLATION, "ubotbuild", &k, &k);
    let clash = fx.call("POST", url, Some(&token), Some(&body2), &headers);
    assert_eq!(
        (clash.status, clash.json["code"].as_str()),
        (409, Some("IDEMPOTENCY_MISMATCH"))
    );
}

#[test]
fn refresh_rules() {
    let fx = fx();
    let k = key(1);
    let device = fx.activate(INSTALLATION).json["deviceId"]
        .as_str()
        .unwrap()
        .to_owned();
    let second = fx.activate_as(&fx.token(Some(ORG_A)), OTHER_INSTALLATION, "ubotbuild", &k);
    let second_id = second.json["deviceId"].as_str().unwrap().to_owned();
    let nonce = "n".repeat(43);

    let ok = fx.refresh(&refresh_body(&device, T0, &nonce, &k));
    assert_eq!(ok.status, 200, "{}", ok.json);
    assert!(ok.json.get("entitlementId").is_none());
    assert_eq!(ok.json["deviceId"], device.as_str());
    let (_, claims, _, _) = jws_parts(ok.json["lease"].as_str().unwrap());
    assert_eq!(claims["nonce"], nonce.as_str());
    assert_eq!(fx.server.device_rows()[0].last_refresh_ts, T0);

    let replay = fx.refresh(&refresh_body(&device, T0, &nonce, &k));
    assert_eq!(replay.status, 422);
    assert!(replay.json["errors"]["timestamp"].is_string());

    let stale = fx.refresh(&refresh_body(&second_id, T0 - 301, &nonce, &k));
    assert_eq!(stale.status, 422);
    assert!(stale.json["errors"]["timestamp"].is_string());

    let three_lines = format!("pi-license-refresh\n{device}\n{}", T0 + 1);
    let mut body = refresh_body(&device, T0 + 1, &nonce, &k);
    body["signature"] = b64(&k.sign(three_lines.as_bytes()).to_bytes()).into();
    let bad = fx.refresh(&body);
    assert_eq!(bad.status, 422);
    assert!(bad.json["errors"]["signature"].is_string());

    let unknown = fx.refresh(&refresh_body(
        "00000000-0000-4000-8000-000000000000",
        T0 + 1,
        &nonce,
        &k,
    ));
    assert_eq!(unknown.status, 404);
    assert!(unknown.json.get("code").is_none());

    assert!(fx.server.revoke_device(&device));
    let revoked = fx.refresh(&refresh_body(&device, T0 + 2, &nonce, &k));
    assert_eq!(
        (revoked.status, revoked.json["code"].as_str()),
        (409, Some("DEVICE_REVOKED"))
    );

    fx.server.update_scenario(|s| s.tenants.clear());
    let gone = fx.refresh(&refresh_body(&second_id, T0 + 2, &nonce, &k));
    assert_eq!(
        (gone.status, gone.json["code"].as_str()),
        (403, Some("NO_ENTITLEMENT"))
    );
}

#[test]
fn lease_lifetime_follows_offline_feature_and_subscription_end() {
    let online = fx_with(vec![Tenant::new(
        "ten_cad",
        ORG_A,
        "ubotbuild",
        &["cad-view"],
    )]);
    let (_, claims, _, _) = jws_parts(
        online.activate(INSTALLATION).json["lease"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        86_400
    );
    assert_eq!(claims["offline_allowed"], false);

    let ending = fx_with(vec![tenant().valid_to(T0 + 3600)]);
    let (_, claims, _, _) = jws_parts(
        ending.activate(INSTALLATION).json["lease"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(claims["exp"], T0 + 3600);
}

#[test]
fn entitlements_row_shape() {
    let fx = fx();
    let token = fx.token(Some(ORG_A));
    let out = fx.call(
        "GET",
        "/api/v1/id/me/entitlements?product_id=ubotbuild",
        Some(&token),
        None,
        &[],
    );
    assert_eq!(out.status, 200);
    let items = out.json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    let row = &items[0];
    assert_eq!(row["decision"], "ALLOW");
    assert_eq!(row["seat"], true);
    assert_eq!(row["tenant"]["product"], "ubotbuild");
    let codes: Vec<&str> = row["features"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert_eq!(codes, FREE_UBOTCAD);
    assert_eq!(
        row["offline"],
        json!({ "allowed": true, "days": 7, "deviceCap": 2 })
    );
    assert_eq!(row["policyVersion"], 1);

    let none = fx.call(
        "GET",
        "/api/v1/id/me/entitlements?product_id=vanban",
        Some(&token),
        None,
        &[],
    );
    assert_eq!(none.json["items"], json!([]));
}

#[test]
fn lease_keys_publish_lease_key() {
    let fx = fx();
    let out = fx.call("GET", "/id/lease-keys.json", None, None, &[]);
    assert_eq!(out.status, 200);
    assert_eq!(
        out.json,
        json!({ "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64(&fx.server.lease_public_key()),
            "kid": fx.server.lease_key_id(),
            "use": "sig",
            "alg": "EdDSA",
        }] })
    );
}

#[test]
fn every_response_has_date() {
    let fx = fx();
    let token = fx.token(Some(ORG_A));
    let paths = [
        ("GET", "/.well-known/openid-configuration", None),
        ("GET", "/id/lease-keys.json", None),
        (
            "GET",
            "/api/v1/id/devices/challenge?product_id=ubotbuild",
            Some(&token),
        ),
        (
            "GET",
            "/api/v1/id/me/entitlements?product_id=ubotbuild",
            None,
        ),
        ("GET", "/v1/me/entitlements", None),
        ("GET", "/no/such/page", None),
    ];
    for (method, path, token) in paths {
        let out = fx.call(method, path, token.map(String::as_str), None, &[]);
        let date = out.date.unwrap_or_else(|| panic!("no Date on {path}"));
        assert_eq!(parse_http_date(&date), T0, "{path}: {date}");
    }
}

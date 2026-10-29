//! PI's device protocol (`pi_device`): challenge, activation, lease refresh, the entitlements
//! row and the lease-key publication, with PI's check order and error envelope.
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde_json::{Map, Value, json};

use super::{Ctx, bearer};
use crate::{
    LeaseTamper, Tenant, crypto,
    http::{Req, Resp},
    state::{Auth, Challenge, DeviceRow, DeviceStatus, Idempotency, State, Stored},
};

const CHALLENGE_TTL: i64 = 300;
const REFRESH_SKEW: i64 = 300;
const DAY: i64 = 86_400;
const DEFAULT_OFFLINE_DAYS: u32 = 7;
const PLATFORMS: [&str; 6] = ["windows", "macos", "linux", "android", "ios", "web"];
const INVALID: &str = "Giá trị không hợp lệ.";

fn token_like(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

fn raw_bytes<const N: usize>(v: Option<&str>) -> Option<[u8; N]> {
    crypto::unb64(v?)?.try_into().ok()
}

fn check<T>(errors: &mut Map<String, Value>, field: &str, v: Option<T>) -> Option<T> {
    if v.is_none() {
        errors.insert(field.into(), INVALID.into());
    }
    v
}

fn denied(st: &State, req: &Req, scope: &str) -> Result<Auth, Resp> {
    bearer::check(st, req, scope, false).map_err(|d| d.pi())
}

fn coded(status: u16, message: &str, code: &str) -> Resp {
    Resp::pi_error(status, message, Some(code))
}

/// The ALLOW tenant of (`org`, `product`), as `OrgEntitlement` resolves it.
fn tenant_of(st: &State, org: &str, product: &str) -> Option<Tenant> {
    let now = st.now();
    st.scenario
        .tenants
        .iter()
        .find(|t| {
            t.org_id == org && t.product_id == product && t.valid_to.is_none_or(|end| end > now)
        })
        .cloned()
}

fn has_seat(tenant: &Tenant, account: &str) -> bool {
    tenant
        .seats
        .as_ref()
        .is_none_or(|seats| seats.iter().any(|s| s == account))
}

/// `NO_ENTITLEMENT` or `NO_SEAT` for an organization that cannot hold a lease, else its tenant.
fn entitled(st: &State, org: &str, product: &str, account: &str) -> Result<Tenant, Resp> {
    let tenant = tenant_of(st, org, product).ok_or_else(|| {
        coded(
            403,
            "Tổ chức chưa có quyền sử dụng sản phẩm này.",
            "NO_ENTITLEMENT",
        )
    })?;
    if !has_seat(&tenant, account) {
        return Err(coded(
            403,
            "Bạn chưa được cấp chỗ ngồi cho sản phẩm này.",
            "NO_SEAT",
        ));
    }
    Ok(tenant)
}

pub(super) fn challenge(st: &mut State, req: &Req) -> Resp {
    let auth = match denied(st, req, "pi.devices") {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let product = req.query("product_id").unwrap_or_default();
    if !st.scenario.products.contains(&product) {
        return Resp::pi_invalid(json!({ "productId": INVALID }));
    }
    let id = crypto::uuid();
    let nonce = crypto::b64(&crypto::random::<24>());
    let expires = st.now() + CHALLENGE_TTL;
    st.challenges.insert(
        id.clone(),
        Challenge {
            nonce: nonce.clone(),
            user_id: auth.user_id,
            product,
            expires,
            used: false,
        },
    );
    Resp::pi_ok(
        201,
        json!({ "challengeId": id, "nonce": nonce, "expiresAt": crypto::rfc3339(expires) }),
    )
}

pub(super) fn activate(st: &mut State, ctx: &Ctx, req: &Req) -> Resp {
    let auth = match denied(st, req, "pi.devices") {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let key = req.header("Idempotency-Key").map(str::trim).unwrap_or("");
    if key.is_empty() {
        return activate_once(st, ctx, req, &auth);
    }
    let valid = (8..=128).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b));
    if !valid {
        return Resp::pi_invalid(
            json!({ "Idempotency-Key": "Khoá gồm 8–128 ký tự chữ, số, . _ : -" }),
        );
    }
    let slot = (auth.user_id.clone(), req.path.clone(), key.to_owned());
    let hash = crypto::sha256(&req.body);
    if let Some(stored) = st.idempotency.get(&slot) {
        if stored.body_hash != hash {
            return coded(
                409,
                "Idempotency-Key đã dùng cho một yêu cầu khác.",
                "IDEMPOTENCY_MISMATCH",
            );
        }
        if let Some(r) = &stored.response {
            let mut resp = Resp::json(r.status, &Value::Null);
            resp.body = r.body.clone();
            return resp.with_header("Idempotent-Replayed", "true");
        }
    }
    let resp = activate_once(st, ctx, req, &auth);
    if (200..300).contains(&resp.status) {
        st.idempotency.insert(
            slot,
            Idempotency {
                body_hash: hash,
                response: Some(Stored {
                    status: resp.status,
                    body: resp.body.clone(),
                }),
            },
        );
    }
    resp
}

fn activate_once(st: &mut State, ctx: &Ctx, req: &Req, auth: &Auth) -> Resp {
    let body = req.json().unwrap_or(Value::Null);
    let text = |k: &str| body.get(k).and_then(Value::as_str);
    let mut errors = Map::new();
    let installation_id = check(
        &mut errors,
        "installationId",
        text("installationId").filter(|v| token_like(v, 8, 64)),
    );
    let product = check(
        &mut errors,
        "productId",
        text("productId").filter(|p| st.scenario.products.iter().any(|q| q == p)),
    );
    check(
        &mut errors,
        "platform",
        text("platform").filter(|p| PLATFORMS.contains(p)),
    );
    check(
        &mut errors,
        "clientVersion",
        text("clientVersion").filter(|v| !v.is_empty() && v.len() <= 64 && v.is_ascii()),
    );
    if body
        .get("label")
        .is_some_and(|l| l.as_str().is_none_or(|l| l.chars().count() > 128))
    {
        errors.insert("label".into(), INVALID.into());
    }
    let public_key = check(
        &mut errors,
        "devicePublicKey",
        raw_bytes::<32>(text("devicePublicKey")),
    );
    let challenge_id = check(
        &mut errors,
        "challengeId",
        text("challengeId")
            .filter(|c| is_uuid(c))
            .map(str::to_lowercase),
    );
    let signature = check(
        &mut errors,
        "signedChallenge",
        raw_bytes::<64>(text("signedChallenge")),
    );
    let (
        Some(installation_id),
        Some(product),
        Some(public_key),
        Some(challenge_id),
        Some(signature),
        true,
    ) = (
        installation_id,
        product,
        public_key,
        challenge_id,
        signature,
        errors.is_empty(),
    )
    else {
        return Resp::pi_invalid(Value::Object(errors));
    };

    let now = st.now();
    let nonce = st
        .challenges
        .get(&challenge_id)
        .filter(|c| !c.used && c.expires > now && c.user_id == auth.user_id && c.product == product)
        .map(|c| c.nonce.clone());
    let Some(nonce) = nonce else {
        return coded(
            409,
            "Thử thách không hợp lệ hoặc đã hết hạn.",
            "CHALLENGE_INVALID",
        );
    };
    let message =
        format!("pi-device-activate\n{challenge_id}\n{nonce}\n{installation_id}\n{product}");
    if !signature_ok(&public_key, message.as_bytes(), &signature) {
        return Resp::pi_invalid(json!({ "signedChallenge": "Chữ ký không hợp lệ." }));
    }
    if let Some(c) = st.challenges.get_mut(&challenge_id) {
        c.used = true;
    }

    let Some(org) = auth.org.clone() else {
        return coded(
            403,
            "Token chưa gắn với tổ chức nào.",
            "ORG_CONTEXT_REQUIRED",
        );
    };
    let tenant = match entitled(st, &org, product, &auth.user_id) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let existing = st.pi_devices.iter().position(|d| {
        d.installation_id == installation_id && d.product == product && d.user_id == auth.user_id
    });
    if existing.is_some_and(|i| st.pi_devices[i].status == DeviceStatus::Revoked) {
        return coded(409, "Thiết bị đã bị thu hồi.", "DEVICE_REVOKED");
    }
    let active = st
        .pi_devices
        .iter()
        .filter(|d| {
            d.user_id == auth.user_id
                && d.product == product
                && d.org == org
                && d.status == DeviceStatus::Active
                && d.installation_id != installation_id
        })
        .count();
    if active >= tenant.device_cap {
        return coded(409, "Đã đạt số thiết bị tối đa của gói.", "DEVICE_CAP");
    }
    let index = match existing {
        Some(i) => {
            let row = &mut st.pi_devices[i];
            row.org = org.clone();
            row.public_key = public_key;
            row.client_id = auth.client_id.clone();
            i
        }
        None => {
            st.pi_devices.push(DeviceRow {
                device_id: crypto::uuid(),
                installation_id: installation_id.to_owned(),
                product: product.to_owned(),
                user_id: auth.user_id.clone(),
                org,
                public_key,
                client_id: auth.client_id.clone(),
                status: DeviceStatus::Active,
                last_refresh_ts: 0,
            });
            st.pi_devices.len() - 1
        }
    };
    let row = st.pi_devices[index].clone();
    let mut data = issue_lease(st, ctx, &row, &tenant, &nonce, &auth.client_id);
    data.insert("deviceId".into(), row.device_id.into());
    data.insert("entitlementId".into(), tenant.tenant_id.into());
    Resp::pi_ok(201, Value::Object(data))
}

pub(super) fn refresh(st: &mut State, ctx: &Ctx, req: &Req) -> Resp {
    let auth = match denied(st, req, "pi.devices") {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let body = req.json().unwrap_or(Value::Null);
    let mut errors = Map::new();
    let device_id = check(
        &mut errors,
        "deviceId",
        body.get("deviceId")
            .and_then(Value::as_str)
            .filter(|d| is_uuid(d))
            .map(str::to_lowercase),
    );
    let timestamp = check(
        &mut errors,
        "timestamp",
        match body.get("timestamp") {
            Some(Value::Number(n)) => n.as_i64(),
            Some(Value::String(s)) if s.bytes().all(|b| b.is_ascii_digit()) => s.parse().ok(),
            _ => None,
        },
    );
    let signature = check(
        &mut errors,
        "signature",
        raw_bytes::<64>(body.get("signature").and_then(Value::as_str)),
    );
    let nonce = match body.get("nonce") {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(n)) if token_like(n, 16, 128) => Some(Some(n.clone())),
        _ => None,
    };
    let nonce = check(&mut errors, "nonce", nonce);
    let (Some(device_id), Some(timestamp), Some(signature), Some(nonce), true) =
        (device_id, timestamp, signature, nonce, errors.is_empty())
    else {
        return Resp::pi_invalid(Value::Object(errors));
    };

    let Some(index) = st
        .pi_devices
        .iter()
        .position(|d| d.device_id == device_id && d.user_id == auth.user_id)
    else {
        return Resp::pi_status(404);
    };
    let row = st.pi_devices[index].clone();
    if row.status != DeviceStatus::Active {
        return coded(409, "Thiết bị đã bị thu hồi.", "DEVICE_REVOKED");
    }
    if (st.now() - timestamp).abs() > REFRESH_SKEW || timestamp <= row.last_refresh_ts {
        return Resp::pi_invalid(json!({ "timestamp": "Dấu thời gian không hợp lệ." }));
    }
    let message = match &nonce {
        Some(n) => format!("pi-license-refresh\n{device_id}\n{timestamp}\n{n}"),
        None => format!("pi-license-refresh\n{device_id}\n{timestamp}"),
    };
    if !signature_ok(&row.public_key, message.as_bytes(), &signature) {
        return Resp::pi_invalid(json!({ "signature": "Chữ ký không hợp lệ." }));
    }
    if !st.membership_active(&row.user_id, &row.org) {
        return coded(
            403,
            "Bạn không còn là thành viên hoạt động của tổ chức này.",
            "MEMBERSHIP_INACTIVE",
        );
    }
    let tenant = match entitled(st, &row.org, &row.product, &row.user_id) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    st.pi_devices[index].last_refresh_ts = timestamp;
    let nonce = nonce.unwrap_or_else(|| crypto::b64(&crypto::random::<16>()));
    let mut data = issue_lease(st, ctx, &row, &tenant, &nonce, &auth.client_id);
    data.insert("deviceId".into(), row.device_id.into());
    Resp::pi_ok(200, Value::Object(data))
}

fn signature_ok(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(public_key).is_ok_and(|key| {
        key.verify(message, &Signature::from_bytes(signature))
            .is_ok()
    })
}

fn set(claims: &mut [(&'static str, Value)], key: &str, value: Value) {
    if let Some(slot) = claims.iter_mut().find(|(k, _)| *k == key) {
        slot.1 = value;
    }
}

/// Lease claims in PI's member order, signed with the scenario's lease key, plus the response
/// fields that mirror them; `aud` is the token's `azp` and only left out when empty.
fn issue_lease(
    st: &State,
    ctx: &Ctx,
    row: &DeviceRow,
    tenant: &Tenant,
    nonce: &str,
    client_id: &str,
) -> Map<String, Value> {
    let now = st.now();
    let offline = tenant.features.iter().any(|f| f == "offline");
    let extended = tenant.features.iter().any(|f| f == "offline-extended");
    let days = match (offline, tenant.offline_days) {
        (false, _) => 1,
        (true, d) if d > DEFAULT_OFFLINE_DAYS && !extended => DEFAULT_OFFLINE_DAYS,
        (true, d) => d,
    };
    let exp = (now + i64::from(days) * DAY).min(tenant.valid_to.unwrap_or(i64::MAX));
    let lease_id = crypto::uuid();
    let tamper = st.scenario.lease_tamper;
    let mut rights = tenant.features.clone();
    let mut features = rights.clone();
    let mut claims: Vec<(&'static str, Value)> = vec![
        ("iss", ctx.issuer.into()),
        ("jti", lease_id.clone().into()),
        ("sub", row.user_id.clone().into()),
        ("org", row.org.clone().into()),
        ("tenant", tenant.tenant_id.clone().into()),
        ("product", row.product.clone().into()),
        ("device", row.device_id.clone().into()),
        (
            "cnf",
            json!({ "jkt": crypto::b64(&crypto::sha256(&row.public_key)) }),
        ),
        ("features", Value::Null),
        ("offline_allowed", offline.into()),
        ("policy_version", tenant.plan.clone().into()),
        ("nonce", nonce.into()),
        ("iat", now.into()),
        ("nbf", now.into()),
        ("exp", exp.into()),
        ("warn_days", json!([7, 3, 1])),
        ("after_expiry", "read_export".into()),
    ];
    let mut kid = st.scenario.lease_kid.clone();
    let mut key = SigningKey::from_bytes(&st.scenario.lease_seed);
    let mut aud = Some(client_id).filter(|a| !a.is_empty()).map(str::to_owned);
    match tamper {
        Some(LeaseTamper::UnknownKid) => kid = "pi-mock-unknown".into(),
        Some(LeaseTamper::WrongSigningKey) => key = SigningKey::from_bytes(&crypto::random()),
        Some(LeaseTamper::WrongCnf) => {
            let other = SigningKey::from_bytes(&crypto::random());
            let jkt = crypto::b64(&crypto::sha256(other.verifying_key().as_bytes()));
            set(&mut claims, "cnf", json!({ "jkt": jkt }));
        }
        Some(LeaseTamper::WrongProduct) => {
            let other = st.scenario.products.iter().find(|p| **p != row.product);
            set(
                &mut claims,
                "product",
                other.cloned().unwrap_or_default().into(),
            );
        }
        Some(LeaseTamper::NbfInFuture) => set(&mut claims, "nbf", (now + 3600).into()),
        Some(LeaseTamper::WrongNonce) => {
            set(
                &mut claims,
                "nonce",
                crypto::b64(&crypto::random::<24>()).into(),
            );
        }
        Some(LeaseTamper::WrongIssuer) => set(&mut claims, "iss", "https://evil.invalid".into()),
        Some(LeaseTamper::OverlongWindow) => set(&mut claims, "exp", (now + 91 * DAY).into()),
        Some(LeaseTamper::WrongAudience) => aud = Some("erpcons-office-desktop".into()),
        Some(LeaseTamper::BadFeatureCode) => features.push("CAD_USE".into()),
        Some(LeaseTamper::MissingAudience) => aud = None,
        Some(LeaseTamper::CopyMismatch) => rights.push("tampered".into()),
        Some(LeaseTamper::AlteredPayload) | None => {}
    }
    set(&mut claims, "features", json!(features));
    if let Some(aud) = aud {
        claims.push(("aud", aud.into()));
    }
    let header = crypto::ordered_object(&[
        ("alg", "EdDSA".into()),
        ("typ", "pi-lease+jwt".into()),
        ("kid", kid.into()),
    ]);
    let mut lease = crypto::sign_raw(&header, &crypto::ordered_object(&claims), &key);
    if tamper == Some(LeaseTamper::AlteredPayload) {
        features.push("forged".into());
        set(&mut claims, "features", json!(features));
        let parts: Vec<&str> = lease.split('.').collect();
        lease = format!(
            "{}.{}.{}",
            parts[0],
            crypto::b64(crypto::ordered_object(&claims).as_bytes()),
            parts[2]
        );
    }
    let exp = claims
        .iter()
        .find(|(k, _)| *k == "exp")
        .and_then(|(_, v)| v.as_i64())
        .unwrap_or(exp);
    let Value::Object(data) = json!({
        "rights": rights,
        "offlineAllowed": offline,
        "offlineDays": days,
        "offlineValidUntil": crypto::rfc3339(exp),
        "policyVersion": tenant.plan,
        "leaseId": lease_id,
        "lease": lease,
    }) else {
        unreachable!("object literal")
    };
    data
}

pub(super) fn entitlements(st: &State, req: &Req) -> Resp {
    let auth = match denied(st, req, "pi.entitlements") {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let product = req.query("product_id").unwrap_or_default();
    if !st.scenario.products.contains(&product) {
        return Resp::pi_ok(200, json!({ "items": [] }));
    }
    let orgs = match &auth.org {
        Some(org) => vec![org.clone()],
        None => st.active_orgs(&auth.user_id),
    };
    let now = st.now();
    let items: Vec<Value> = orgs
        .iter()
        .filter_map(|org| {
            let membership = st
                .user(&auth.user_id)?
                .memberships
                .iter()
                .find(|m| m.org_id == *org)?;
            let tenant = tenant_of(st, org, &product)?;
            let (plan_code, version) = tenant
                .plan
                .split_once('@')
                .map_or((tenant.plan.as_str(), None), |(c, v)| (c, v.parse::<u32>().ok()));
            let features: Vec<Value> = tenant
                .features
                .iter()
                .map(|f| json!({ "code": f, "name": f, "source": "plan" }))
                .collect();
            Some(json!({
                "organization": { "id": org, "name": membership.name, "role": membership.role },
                "tenant": { "id": tenant.tenant_id, "code": tenant.tenant_id, "product": tenant.product_id },
                "decision": "ALLOW",
                "reasonCode": "OK",
                "features": features,
                "quotas": [],
                "policyVersion": version,
                "subscription": {
                    "planCode": plan_code,
                    "planVersion": version,
                    "endsAt": tenant.valid_to.map(crypto::rfc3339),
                },
                "evaluatedAt": crypto::rfc3339(now),
                "seat": has_seat(&tenant, &auth.user_id),
                "offline": {
                    "allowed": tenant.features.iter().any(|f| f == "offline"),
                    "days": tenant.offline_days,
                    "deviceCap": tenant.device_cap,
                },
            }))
        })
        .collect();
    Resp::pi_ok(200, json!({ "items": items }))
}

/// `GET /id/lease-keys.json`: the key that signs PI leases, public half only.
pub(super) fn lease_keys(st: &State) -> Resp {
    let x = SigningKey::from_bytes(&st.scenario.lease_seed).verifying_key();
    Resp::json(
        200,
        &json!({ "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": crypto::b64(x.as_bytes()),
            "kid": st.scenario.lease_kid,
            "use": "sig",
            "alg": "EdDSA",
        }] }),
    )
    .with_header("Cache-Control", "public, max-age=300")
}

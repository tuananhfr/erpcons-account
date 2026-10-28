//! Office-contract device protocol, not PI's: challenges, activation and lease refresh with the
//! server checks of the contract (`activateDevice`, `refreshLease`) and lease.md §5.
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use super::{
    Ctx,
    contract::{PRODUCTS, effective},
};
use crate::{
    LeaseTamper, crypto,
    http::{Req, Resp},
    state::{Auth, DeviceRecord, NonceRecord, State},
};

const DAY: i64 = 86_400;

fn field(body: &Value, k: &str) -> Option<String> {
    body.get(k)?.as_str().map(str::to_owned)
}

fn version(v: &str) -> Option<(u64, u64, u64)> {
    let mut p = v.split('.').map(|n| n.parse::<u64>().ok());
    let r = (p.next()??, p.next()??, p.next()??);
    p.next().is_none().then_some(r)
}

pub(super) fn challenge(st: &mut State, ctx: &Ctx, req: &Req, auth: &Auth) -> Resp {
    let body = req.json().unwrap_or(Value::Null);
    let (Some(purpose), Some(installation_id), Some(product)) = (
        field(&body, "purpose"),
        field(&body, "installation_id"),
        field(&body, "product_id"),
    ) else {
        return ctx.problem(422, "validation_failed");
    };
    if !matches!(purpose.as_str(), "activate" | "refresh") || !PRODUCTS.contains(&product.as_str())
    {
        return ctx.problem(422, "validation_failed");
    }
    let nonce = crypto::token();
    let now = st.now();
    st.nonces.insert(
        nonce.clone(),
        NonceRecord {
            user_id: auth.user_id.clone(),
            org: auth.org.clone(),
            installation_id,
            product_id: product,
            purpose,
            expires: now + 120,
            used: false,
        },
    );
    Resp::json(
        201,
        &json!({ "nonce": nonce, "expires_at": crypto::rfc3339(now + 120) }),
    )
}

struct Request {
    installation_id: String,
    product: String,
    platform: String,
    client_version: String,
    proof: String,
    device_id: Option<String>,
}

fn parse(req: &Req, refresh: bool) -> Option<Request> {
    let body = req.json()?;
    let r = Request {
        installation_id: field(&body, "installation_id")?,
        product: field(&body, "product_id").filter(|p| PRODUCTS.contains(&p.as_str()))?,
        platform: field(&body, "platform")
            .filter(|p| matches!(p.as_str(), "windows" | "macos" | "linux"))?,
        client_version: field(&body, "client_version").filter(|v| version(v).is_some())?,
        proof: field(&body, "signed_challenge")?,
        device_id: field(&body, "device_id"),
    };
    (r.device_id.is_some() == refresh).then_some(r)
}

/// Proof checks in the contract's order; returns the key thumbprint and the nonce.
fn check_proof(
    st: &mut State,
    auth: &Auth,
    r: &Request,
    purpose: &str,
) -> Option<(String, String)> {
    let (x, claims) = crypto::verify_proof(&r.proof)?;
    let nonce = claims["nonce"].as_str()?.to_owned();
    let now = st.now();
    let rec = st.nonces.get_mut(&nonce)?;
    let bound = !rec.used
        && rec.expires > now
        && rec.purpose == purpose
        && rec.user_id == auth.user_id
        && rec.org == auth.org
        && rec.installation_id == r.installation_id
        && rec.product_id == r.product;
    rec.used = true;
    let same = claims["purpose"] == purpose
        && claims["installation_id"] == r.installation_id.as_str()
        && claims["product_id"] == r.product.as_str()
        && claims["platform"] == r.platform.as_str()
        && claims["client_version"] == r.client_version.as_str()
        && claims["iat"].is_i64()
        && claims.get("device_id").and_then(Value::as_str) == r.device_id.as_deref();
    (bound && same).then(|| (crypto::thumbprint(&x), nonce))
}

fn too_old(st: &State, r: &Request) -> bool {
    st.scenario
        .min_client_version
        .is_some_and(|min| version(&r.client_version).is_some_and(|v| v < min))
}

pub(super) fn activate(st: &mut State, ctx: &Ctx, req: &Req, auth: &Auth) -> Resp {
    let Some(r) = parse(req, false) else {
        return ctx.problem(422, "validation_failed");
    };
    if too_old(st, &r) {
        return ctx.problem(412, "client_version_unsupported");
    }
    let Some((jkt, nonce)) = check_proof(st, auth, &r, "activate") else {
        return ctx.problem(422, "challenge_invalid");
    };
    if st
        .devices
        .iter()
        .any(|d| d.installation_id == r.installation_id && d.jkt != jkt)
    {
        return ctx.problem(409, "installation_key_mismatch");
    }
    let existing = st.devices.iter().position(|d| {
        d.installation_id == r.installation_id && d.user_id == auth.user_id && d.org == auth.org
    });
    let index = match existing {
        Some(i) if st.devices[i].revoked => return ctx.problem(403, "device_revoked"),
        Some(i) => i,
        None => {
            let active = st
                .devices
                .iter()
                .filter(|d| d.user_id == auth.user_id && d.org == auth.org && !d.revoked)
                .count();
            if active >= st.scenario.max_devices {
                let mut resp = ctx.problem(409, "device_cap_reached");
                let mut body: Value = serde_json::from_slice(&resp.body).unwrap_or_default();
                body["max_devices"] = st.scenario.max_devices.into();
                body["active_devices"] = active.into();
                resp.body = body.to_string().into_bytes();
                return resp;
            }
            let device_id = st.next_id("dev");
            st.devices.push(DeviceRecord {
                device_id,
                installation_id: r.installation_id.clone(),
                user_id: auth.user_id.clone(),
                org: auth.org.clone(),
                jkt: jkt.clone(),
                revoked: false,
                products: Vec::new(),
            });
            st.devices.len() - 1
        }
    };
    if !st.devices[index].products.contains(&r.product) {
        st.devices[index].products.push(r.product.clone());
    }
    let device = st.devices[index].clone();
    Resp::json(200, &lease_response(st, ctx, &device, &r.product, &nonce))
}

pub(super) fn refresh(st: &mut State, ctx: &Ctx, req: &Req, auth: &Auth) -> Resp {
    let Some(r) = parse(req, true) else {
        return ctx.problem(422, "validation_failed");
    };
    if too_old(st, &r) {
        return ctx.problem(412, "client_version_unsupported");
    }
    let Some((jkt, nonce)) = check_proof(st, auth, &r, "refresh") else {
        return ctx.problem(422, "challenge_invalid");
    };
    let Some(device) = st
        .devices
        .iter()
        .find(|d| {
            Some(&d.device_id) == r.device_id.as_ref()
                && d.user_id == auth.user_id
                && d.org == auth.org
                && d.jkt == jkt
        })
        .cloned()
    else {
        return ctx.problem(403, "device_unknown");
    };
    let reason = if st.user(&auth.user_id).is_none_or(|u| u.suspended) {
        Some("user_suspended")
    } else if device.revoked {
        Some("device_revoked")
    } else if auth
        .org
        .as_ref()
        .is_some_and(|o| !st.membership_active(&auth.user_id, o))
    {
        Some("membership_revoked")
    } else {
        None
    };
    if let Some(reason) = reason {
        return Resp::json(
            200,
            &json!({
                "status": "revoked",
                "device_id": device.device_id,
                "reason": reason,
                "revoked_at": crypto::rfc3339(st.now()),
            }),
        );
    }
    let mut body = lease_response(st, ctx, &device, &r.product, &nonce);
    body["status"] = "active".into();
    Resp::json(200, &body)
}

/// Lease per lease.md §5, signed with the scenario key, with any injected tampering.
fn lease_response(
    st: &mut State,
    ctx: &Ctx,
    device: &DeviceRecord,
    product: &str,
    nonce: &str,
) -> Value {
    let now = st.now();
    let contributing: Vec<_> = effective(st, &device.user_id, device.org.as_deref(), product, now)
        .into_iter()
        .filter(|e| e.offline_allowed)
        .cloned()
        .collect();
    let window = contributing
        .iter()
        .filter_map(|e| e.offline_days)
        .min()
        .unwrap_or(30);
    let exp = contributing
        .iter()
        .filter_map(|e| e.valid_to)
        .fold(now + i64::from(window) * DAY, i64::min);
    let mut features: Vec<String> = contributing.iter().map(|e| e.feature.clone()).collect();
    let entitlement_ids: Vec<String> = contributing
        .iter()
        .map(|e| e.entitlement_id.clone())
        .collect();
    let tamper = st.scenario.lease_tamper;
    let lease_id = st.next_id("lse");
    let mut claims = json!({
        "iss": ctx.issuer,
        "aud": "erpcons-office-desktop",
        "lease_id": lease_id,
        "sub": device.user_id,
        "org": device.org,
        "device_id": device.device_id,
        "installation_id": device.installation_id,
        "cnf": { "jkt": device.jkt },
        "product": product,
        "features": features,
        "entitlement_ids": entitlement_ids,
        "nbf": now,
        "iat": now,
        "exp": exp,
        "nonce": nonce,
        "policy_version": st.scenario.policy_version,
    });
    let mut kid = st.scenario.lease_kid.clone();
    let mut key = SigningKey::from_bytes(&st.scenario.lease_seed);
    match tamper {
        Some(LeaseTamper::UnknownKid) => kid = "pi-mock-unknown".into(),
        Some(LeaseTamper::WrongSigningKey) => key = SigningKey::from_bytes(&crypto::random()),
        Some(LeaseTamper::WrongCnf) => {
            let other = SigningKey::from_bytes(&crypto::random());
            claims["cnf"]["jkt"] =
                crypto::thumbprint(&crypto::b64(other.verifying_key().as_bytes())).into();
        }
        Some(LeaseTamper::WrongProduct) => {
            let other = PRODUCTS
                .iter()
                .find(|p| **p != product)
                .copied()
                .unwrap_or("pdf");
            claims["product"] = other.into();
            claims["features"] = json!([format!("{other}.use")]);
        }
        Some(LeaseTamper::NbfInFuture) => claims["nbf"] = (now + 3600).into(),
        Some(LeaseTamper::WrongNonce) => claims["nonce"] = crypto::token().into(),
        Some(LeaseTamper::WrongIssuer) => claims["iss"] = "https://evil.invalid".into(),
        Some(LeaseTamper::OverlongWindow) => claims["exp"] = (now + 91 * DAY).into(),
        _ => {}
    }
    let header = json!({ "alg": "EdDSA", "kid": kid, "typ": "pi-lease+jwt" });
    let mut lease = crypto::sign(&header, &claims, &key);
    if tamper == Some(LeaseTamper::AlteredPayload) {
        let mut altered = claims.clone();
        altered["features"] = json!([format!("{product}.use"), format!("{product}.forged")]);
        let parts: Vec<&str> = lease.split('.').collect();
        lease = format!(
            "{}.{}.{}",
            parts[0],
            crypto::b64(altered.to_string().as_bytes()),
            parts[2]
        );
    }
    if tamper == Some(LeaseTamper::CopyMismatch) {
        features.push(format!("{product}.tampered"));
    }
    json!({
        "device_id": device.device_id,
        "entitlement_ids": entitlement_ids,
        "rights": features,
        "offline_valid_until": crypto::rfc3339(claims["exp"].as_i64().unwrap_or(exp)),
        "policy_version": st.scenario.policy_version,
        "lease": lease,
    })
}

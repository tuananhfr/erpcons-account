//! Office-contract endpoints PI does not have (`/v1/me/entitlements`, the signed feature
//! catalog), kept so the licensing code behind `Config::offline_licensing` stays testable.
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use super::{Ctx, bearer};
use crate::{
    crypto,
    http::{Req, Resp},
    scenario::Entitlement,
    state::State,
};

pub(crate) const PRODUCTS: [&str; 5] = ["vanban", "bangtinh", "trinhchieu", "pdf", "ubotbuild"];

/// Entitlements in force for `user` in `org` (personal ones always, plus the org's).
pub(crate) fn effective<'a>(
    st: &'a State,
    user: &str,
    org: Option<&str>,
    product: &str,
    now: i64,
) -> Vec<&'a Entitlement> {
    st.scenario
        .entitlements
        .iter()
        .filter(|e| {
            e.user_id == user
                && e.product_id == product
                && (e.org_id.is_none() || e.org_id.as_deref() == org)
                && e.valid_from <= now
                && e.valid_to.is_none_or(|t| now < t)
        })
        .collect()
}

pub(super) fn entitlements(st: &mut State, ctx: &Ctx, req: &Req) -> Resp {
    let auth = match bearer::check(st, req, "pi.entitlements", false) {
        Ok(a) => a,
        Err(denied) => return denied.problem(ctx),
    };
    let Some(product) = req
        .query("product_id")
        .filter(|p| PRODUCTS.contains(&p.as_str()))
    else {
        return ctx.problem(400, "invalid_request");
    };
    let now = st.now();
    let list: Vec<Value> = effective(st, &auth.user_id, auth.org.as_deref(), &product, now)
        .into_iter()
        .map(|e| {
            json!({
                "entitlement_id": e.entitlement_id,
                "product_id": e.product_id,
                "feature": e.feature,
                "scope": if e.org_id.is_some() { "organization" } else { "personal" },
                "org_id": e.org_id,
                "quota": null,
                "seats": e.seats,
                "valid_from": crypto::rfc3339(e.valid_from),
                "valid_to": e.valid_to.map(crypto::rfc3339),
                "offline_allowed": e.offline_allowed,
                "offline_days": e.offline_days,
                "policy_version": st.scenario.policy_version,
            })
        })
        .collect();
    Resp::json(
        200,
        &json!({ "product_id": product, "org_context": auth.org, "entitlements": list }),
    )
}

pub(super) fn catalog(st: &mut State, ctx: &Ctx, path: &str) -> Resp {
    let product = path
        .trim_start_matches("/v1/products/")
        .trim_end_matches("/feature-catalog");
    if !PRODUCTS.contains(&product) {
        return ctx.problem(400, "invalid_request");
    }
    let (version, features) = match st
        .scenario
        .catalogs
        .iter()
        .find(|c| c.product_id == product)
    {
        Some(c) => (c.version, c.features.clone()),
        None => (
            1,
            ["view", "export", "use"]
                .iter()
                .map(|n| (format!("{product}.{n}"), "free".to_owned()))
                .collect(),
        ),
    };
    let features: Vec<Value> = features
        .iter()
        .map(|(f, t)| json!({ "feature": f, "tier": t }))
        .collect();
    let payload = json!({
        "iss": ctx.issuer,
        "product": product,
        "catalog_version": version,
        "iat": st.now(),
        "features": features,
    });
    let header =
        json!({ "alg": "EdDSA", "kid": st.scenario.lease_kid, "typ": "pi-feature-catalog+jwt" });
    let jws = crypto::sign(
        &header,
        &payload,
        &SigningKey::from_bytes(&st.scenario.lease_seed),
    );
    Resp::json(200, &json!({ "catalog": jws })).with_header("Cache-Control", "public, max-age=3600")
}

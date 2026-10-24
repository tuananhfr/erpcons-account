//! Routing, faults, bearer authentication and idempotency (contract §2, §3).
mod api;
mod devices;
mod oidc;

use std::time::Duration;

use crate::{
    FaultAction, Shared, crypto,
    http::{Req, Resp},
    state::{AccessRecord, Idempotency, RecordedRequest, State, Stored},
};

pub(crate) struct Ctx<'a> {
    pub issuer: &'a str,
    pub cid: &'a str,
}

impl Ctx<'_> {
    pub(crate) fn problem(&self, status: u16, code: &str) -> Resp {
        Resp::problem(status, code, self.issuer, self.cid)
    }
}

pub(crate) fn handle(shared: &Shared, req: &Req, cid: &str) -> (Resp, Option<Duration>) {
    let mut st = shared.state();
    st.requests.push(RecordedRequest {
        method: req.method.clone(),
        path: req.path.clone(),
        query: req.query.clone(),
        idempotency_key: req.header("Idempotency-Key").map(str::to_owned),
        correlation_id: req.header("X-Correlation-Id").map(str::to_owned),
        user_agent: req.header("User-Agent").map(str::to_owned),
        authorized: req.header("Authorization").is_some(),
        body: String::from_utf8_lossy(&req.body).into_owned(),
    });
    let ctx = Ctx {
        issuer: &shared.issuer,
        cid,
    };
    if req.method == "OPTIONS" {
        let resp = Resp::text(204, "")
            .with_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            .with_header(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type, Idempotency-Key, X-Correlation-Id",
            )
            .with_header("Access-Control-Max-Age", "600");
        return (resp, None);
    }
    let mut delay = None;
    match st.take_fault(&req.method, &req.path) {
        Some(FaultAction::Problem {
            status,
            code,
            retry_after,
        }) => {
            let mut resp = ctx.problem(status, &code);
            if let Some(s) = retry_after {
                resp = resp.with_header("Retry-After", &s.to_string());
            }
            return (resp, None);
        }
        Some(FaultAction::OAuthError { status, error }) => {
            return (Resp::oauth_error(status, &error), None);
        }
        Some(FaultAction::Delay(d)) => delay = Some(d),
        None => {}
    }
    (route(&mut st, &ctx, req), delay)
}

fn route(st: &mut State, ctx: &Ctx, req: &Req) -> Resp {
    let path = req.path.as_str();
    match (req.method.as_str(), path) {
        ("GET", "/.well-known/openid-configuration") => oidc::discovery(ctx),
        ("GET", "/authorize") => oidc::authorize(st, ctx, req),
        ("POST", "/token") => oidc::token(st, ctx, req),
        ("POST", "/revoke") => oidc::revoke(st, req),
        ("GET", "/jwks") => oidc::jwks(),
        ("GET", "/logout") => Resp::text(200, ""),
        ("GET", "/v1/me") => api::me(st, ctx, req),
        ("GET", "/v1/me/entitlements") => api::entitlements(st, ctx, req),
        ("GET", p) if p.starts_with("/v1/products/") && p.ends_with("/feature-catalog") => {
            api::catalog(st, ctx, p)
        }
        ("POST", "/v1/devices/challenges") => idempotent(st, ctx, req, false, devices::challenge),
        ("POST", "/v1/devices/activate") => idempotent(st, ctx, req, false, devices::activate),
        ("POST", "/v1/licenses/refresh") => idempotent(st, ctx, req, true, devices::refresh),
        _ => ctx.problem(404, "not_found"),
    }
}

/// Bearer token check. `lenient` skips the suspension and membership checks, which lease
/// refresh reports as `status: revoked` instead.
pub(crate) fn bearer(
    st: &State,
    ctx: &Ctx,
    req: &Req,
    scope: &str,
    lenient: bool,
) -> Result<AccessRecord, Resp> {
    let token = req
        .header("Authorization")
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| ctx.problem(401, "unauthenticated"))?;
    let rec = st
        .access
        .get(token)
        .filter(|a| a.exp > st.now())
        .cloned()
        .ok_or_else(|| ctx.problem(401, "unauthenticated"))?;
    if !lenient {
        if st.user(&rec.user_id).is_none_or(|u| u.suspended) {
            return Err(ctx.problem(403, "user_suspended"));
        }
        if let Some(org) = &rec.org
            && st.membership_status(&rec.user_id, org).as_deref() != Some("active")
        {
            return Err(ctx.problem(403, "membership_inactive"));
        }
    }
    if !rec.scope.split(' ').any(|s| s == scope) {
        return Err(ctx.problem(403, "insufficient_scope"));
    }
    Ok(rec)
}

type Handler = fn(&mut State, &Ctx, &Req, &AccessRecord) -> Resp;

/// `Idempotency-Key` semantics: same key and body replays, another body is 422 (contract §2).
fn idempotent(st: &mut State, ctx: &Ctx, req: &Req, lenient: bool, handler: Handler) -> Resp {
    let auth = match bearer(st, ctx, req, "pi.devices", lenient) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let Some(key) = req.header("Idempotency-Key").map(str::to_owned) else {
        return ctx.problem(400, "idempotency_key_missing");
    };
    let slot = (
        auth.user_id.clone(),
        auth.client_id.clone(),
        req.path.clone(),
        key,
    );
    let hash = crypto::sha256(&req.body);
    match st.idempotency.get(&slot) {
        Some(r) if r.body_hash != hash => return ctx.problem(422, "idempotency_key_reused"),
        Some(Idempotency {
            response: Some(stored),
            ..
        }) => {
            let mut resp = Resp::json(stored.status, &serde_json::Value::Null);
            resp.body = stored.body.clone();
            if stored.status >= 400 {
                resp.headers[0].1 = "application/problem+json".into();
            }
            return resp;
        }
        Some(_) => {
            return ctx
                .problem(409, "idempotency_in_progress")
                .with_header("Retry-After", "1");
        }
        None => {}
    }
    st.idempotency.insert(
        slot.clone(),
        Idempotency {
            body_hash: hash,
            response: None,
        },
    );
    let resp = handler(st, ctx, req, &auth);
    if resp.status >= 500 || resp.status == 429 {
        st.idempotency.remove(&slot);
    } else if let Some(rec) = st.idempotency.get_mut(&slot) {
        rec.response = Some(Stored {
            status: resp.status,
            body: resp.body.clone(),
        });
    }
    resp
}

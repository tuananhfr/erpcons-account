//! Routing, faults and idempotency. PI's own paths (`/id/*`, `/api/v1/id/*`) answer as PI does;
//! `/v1/*` are the Office contract's licensing endpoints, which PI does not have (ADR 0011).
mod api;
pub(crate) mod bearer;
mod contract;
mod devices;
mod oidc;

use std::time::Duration;

use serde_json::json;

use crate::{
    FaultAction, Shared, crypto,
    http::{Req, Resp},
    state::{Auth, Idempotency, RecordedRequest, State, Stored},
};

pub(crate) const API_PREFIX: &str = "/api/";
pub(crate) const CONTRACT_PREFIX: &str = "/v1/";

pub(crate) struct Ctx<'a> {
    pub issuer: &'a str,
    pub cid: &'a str,
}

impl Ctx<'_> {
    pub(crate) fn problem(&self, status: u16, code: &str) -> Resp {
        Resp::problem(status, code, self.issuer, self.cid)
    }
}

/// Paths where PI's `CorsSubscriber` applies.
pub(crate) fn pi_cors_path(path: &str) -> bool {
    ["/id/token", "/id/revoke", "/id/userinfo"].contains(&path) || path.starts_with("/api/v1/id/")
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
        if !pi_cors_path(&req.path) && !req.path.starts_with(CONTRACT_PREFIX) {
            return (Resp::text(405, ""), None);
        }
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
            let mut resp = fault(&ctx, &req.path, status, &code);
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

/// An injected error in the format of the path's owner.
fn fault(ctx: &Ctx, path: &str, status: u16, code: &str) -> Resp {
    if path.starts_with(CONTRACT_PREFIX) {
        return ctx.problem(status, code);
    }
    let mut resp = Resp::pi_status(status);
    let mut body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_default();
    if !code.is_empty() {
        body["code"] = code.into();
    }
    // `ApiExceptionSubscriber` adds the correlation id to the body of every 5xx.
    if status >= 500 && path.starts_with(API_PREFIX) {
        body["correlationId"] = ctx.cid.into();
    }
    resp.body = body.to_string().into_bytes();
    resp
}

fn route(st: &mut State, ctx: &Ctx, req: &Req) -> Resp {
    let path = req.path.as_str();
    match (req.method.as_str(), path) {
        ("GET", "/.well-known/openid-configuration") => oidc::discovery(ctx),
        ("GET", "/id/jwks.json") => oidc::jwks(st),
        ("GET", "/id/authorize") => oidc::authorize(st, ctx, req),
        ("POST", "/id/token") => oidc::token(st, ctx, req),
        ("POST", "/id/revoke") => oidc::revoke(st, req),
        ("GET", "/id/userinfo") => oidc::userinfo(st, req),
        ("GET", "/id/logout") => oidc::logout(st, req),
        ("GET", "/api/v1/id/me") => api::me(st, req),
        ("GET", "/v1/me/entitlements") => contract::entitlements(st, ctx, req),
        ("GET", p) if p.starts_with("/v1/products/") && p.ends_with("/feature-catalog") => {
            contract::catalog(st, ctx, p)
        }
        ("POST", "/v1/devices/challenges") => idempotent(st, ctx, req, false, devices::challenge),
        ("POST", "/v1/devices/activate") => idempotent(st, ctx, req, false, devices::activate),
        ("POST", "/v1/licenses/refresh") => idempotent(st, ctx, req, true, devices::refresh),
        (_, p) if p.starts_with(API_PREFIX) => Resp::pi_status(404),
        (_, p) if p.starts_with(CONTRACT_PREFIX) => ctx.problem(404, "not_found"),
        _ => Resp::html(404, "Không tìm thấy", "Không tìm thấy trang."),
    }
}

type Handler = fn(&mut State, &Ctx, &Req, &Auth) -> Resp;

/// `Idempotency-Key` semantics of the Office contract: same key and body replays, another body
/// is 422 (contract §2).
fn idempotent(st: &mut State, ctx: &Ctx, req: &Req, lenient: bool, handler: Handler) -> Resp {
    let auth = match bearer::check(st, req, "pi.devices", lenient) {
        Ok(a) => a,
        Err(denied) => return denied.problem(ctx),
    };
    let Some(key) = req.header("Idempotency-Key").map(str::to_owned) else {
        return ctx.problem(400, "idempotency_key_missing");
    };
    let slot = (auth.user_id.clone(), req.path.clone(), key);
    let hash = crypto::sha256(&req.body);
    match st.idempotency.get(&slot) {
        Some(r) if r.body_hash != hash => return ctx.problem(422, "idempotency_key_reused"),
        Some(Idempotency {
            response: Some(stored),
            ..
        }) => {
            let mut resp = Resp::json(stored.status, &json!(null));
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

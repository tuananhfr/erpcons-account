//! Routing and faults. Every path (`/id/*`, `/api/v1/id/*`) answers as PI does.
mod api;
pub(crate) mod bearer;
mod oidc;
mod pi_devices;

use std::time::Duration;

use crate::{
    FaultAction, Shared, crypto,
    http::{Req, Resp},
    state::{RecordedRequest, State},
};

pub(crate) const API_PREFIX: &str = "/api/";

pub(crate) struct Ctx<'a> {
    pub issuer: &'a str,
    pub cid: &'a str,
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
        if !pi_cors_path(&req.path) {
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
        Some(FaultAction::SkewDate(secs)) => {
            let date = crypto::http_date(st.now() + secs);
            return (route(&mut st, &ctx, req).with_header("Date", &date), None);
        }
        None => {}
    }
    (route(&mut st, &ctx, req), delay)
}

/// An injected error in PI's envelope.
fn fault(ctx: &Ctx, path: &str, status: u16, code: &str) -> Resp {
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
        ("GET", "/id/lease-keys.json") => pi_devices::lease_keys(st),
        ("GET", "/api/v1/id/devices/challenge") => pi_devices::challenge(st, req),
        ("POST", "/api/v1/id/devices/activate") => pi_devices::activate(st, ctx, req),
        ("POST", "/api/v1/id/licenses/refresh") => pi_devices::refresh(st, ctx, req),
        ("GET", "/api/v1/id/me/entitlements") => pi_devices::entitlements(st, req),
        (_, p) if p.starts_with(API_PREFIX) => Resp::pi_status(404),
        _ => Resp::html(404, "Không tìm thấy", "Không tìm thấy trang."),
    }
}

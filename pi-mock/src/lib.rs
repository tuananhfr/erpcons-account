//! Mock of the real PI Platform (`pi_id`) as ERPCons Office uses it (ADR 0011): OIDC discovery,
//! PKCE S256 authorization with `org_hint`, EdDSA access and ID tokens with `/id/jwks.json`,
//! refresh rotation with family revocation on reuse, and `/api/v1/id/me` in PI's envelope.
//! It also serves PI's device protocol (`/api/v1/id/devices/*`, `licenses/refresh`,
//! `me/entitlements`, `/id/lease-keys.json`) behind `Config::offline_licensing` (ADR 0012).
//! In-process for tests, or the `pi-mock` binary for manual and E2E runs.
//!
//! Its signing and lease keys are fixed development keys ([`dev_signing_seed`],
//! [`dev_lease_public_key`]); release builds of the apps never trust them.
#[cfg(target_arch = "wasm32")]
compile_error!("pi-mock is a native test server");

mod crypto;
mod handlers;
mod http;
mod jwt;
mod scenario;
mod state;

use std::{
    io::Read,
    net::ToSocketAddrs,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    thread::{self, JoinHandle},
};

pub use scenario::{
    Authorize, Client, DEFAULT_USER, DESKTOP_CLIENT, DEV_LEASE_KID, DEV_SIGNING_KID, FREE_OFFICE,
    FREE_UBOTCAD, Fault, FaultAction, JwtKey, LeaseTamper, Membership, OFFICE_PRODUCT, ORG_A,
    ORG_B, ORG_OFFICE, Scenario, Tenant, UBOTCAD_CLIENT, User, WEB_CLIENT, dev_lease_public_key,
    dev_lease_seed, dev_signing_seed,
};
pub use state::{DeviceRow, DeviceStatus, RecordedRequest};

use http::Req;
use state::State;

pub(crate) struct Shared {
    pub state: Mutex<State>,
    pub issuer: String,
}

impl Shared {
    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A running mock; stops when dropped.
pub struct Server {
    shared: Arc<Shared>,
    http: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
    base_url: String,
}

impl Server {
    /// Starts on `127.0.0.1` with a random port; the issuer is the base URL.
    pub fn start(scenario: Scenario) -> Server {
        Self::bind("127.0.0.1:0", None, scenario).expect("bind pi-mock on 127.0.0.1")
    }

    /// Starts on `addr`; `issuer` overrides the advertised URL (for example behind Docker).
    pub fn bind(addr: &str, issuer: Option<&str>, scenario: Scenario) -> std::io::Result<Server> {
        let socket = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| std::io::Error::other("no address"))?;
        let http = Arc::new(tiny_http::Server::http(socket).map_err(std::io::Error::other)?);
        let port = http
            .server_addr()
            .to_ip()
            .map(|a| a.port())
            .ok_or_else(|| std::io::Error::other("not an IP listener"))?;
        let host = match socket.ip() {
            ip if ip.is_unspecified() => "127.0.0.1".to_owned(),
            std::net::IpAddr::V6(ip) => format!("[{ip}]"),
            ip => ip.to_string(),
        };
        let base_url = format!("http://{host}:{port}");
        let shared = Arc::new(Shared {
            state: Mutex::new(State::new(scenario)),
            issuer: issuer
                .map(|i| i.trim_end_matches('/').to_owned())
                .unwrap_or_else(|| base_url.clone()),
        });
        let thread = {
            let (http, shared) = (http.clone(), shared.clone());
            thread::spawn(move || {
                for request in http.incoming_requests() {
                    let shared = shared.clone();
                    thread::spawn(move || serve(&shared, request));
                }
            })
        };
        Ok(Server {
            shared,
            http,
            thread: Some(thread),
            base_url,
        })
    }

    /// Where the server listens.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// OIDC issuer: `iss` of tokens and leases.
    pub fn issuer(&self) -> &str {
        &self.shared.issuer
    }

    /// `kid` of the current lease-signing key.
    pub fn lease_key_id(&self) -> String {
        self.shared.state().scenario.lease_kid.clone()
    }

    /// Public half of the current lease-signing key.
    pub fn lease_public_key(&self) -> [u8; 32] {
        let seed = self.shared.state().scenario.lease_seed;
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
    }

    /// `kid` of the PI ID key that signs access and ID tokens.
    pub fn signing_key_id(&self) -> String {
        let state = self.shared.state();
        state
            .scenario
            .signing_keys
            .first()
            .map(|k| k.kid.clone())
            .unwrap_or_default()
    }

    /// Public half of the PI ID signing key, as `/id/jwks.json` publishes it.
    pub fn signing_public_key(&self) -> Option<[u8; 32]> {
        let state = self.shared.state();
        let seed = state.scenario.signing_keys.first()?.seed;
        Some(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        )
    }

    pub fn jwks_uri(&self) -> String {
        format!("{}/id/jwks.json", self.shared.issuer)
    }

    /// Signs `claims` as PI ID does (header `{alg, typ: "JWT", kid}`), for tokens a test forges.
    pub fn sign_jwt(&self, claims: &serde_json::Value) -> String {
        let state = self.shared.state();
        match state.scenario.signing_keys.first() {
            Some(key) => jwt::sign(&claims.to_string(), "JWT", key),
            None => String::new(),
        }
    }

    /// A PI access token for `user` in `org`, as `/id/token` would issue it to `client_id`.
    pub fn issue_access_token(
        &self,
        user: &str,
        org: Option<&str>,
        client_id: &str,
        scope: &str,
    ) -> String {
        let (now, ttl) = {
            let state = self.shared.state();
            (state.now(), state.scenario.access_token_ttl)
        };
        self.sign_jwt(&serde_json::json!({
            "iss": self.shared.issuer,
            "sub": user,
            "aud": [handlers::bearer::AUDIENCE],
            "azp": client_id,
            "scope": scope,
            "org_context": org,
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
            "jti": crypto::uuid(),
        }))
    }

    /// Replaces the scenario; tokens, devices and challenges are kept, fault counters reset.
    pub fn set_scenario(&self, scenario: Scenario) {
        self.shared.state().set_scenario(scenario);
    }

    /// Edits the current scenario in place.
    pub fn update_scenario(&self, f: impl FnOnce(&mut Scenario)) {
        let mut state = self.shared.state();
        let mut scenario = state.scenario.clone();
        f(&mut scenario);
        state.set_scenario(scenario);
    }

    pub fn scenario(&self) -> Scenario {
        self.shared.state().scenario.clone()
    }

    pub fn add_fault(&self, fault: Fault) {
        self.shared.state().faults.push((fault, 0));
    }

    pub fn clear_faults(&self) {
        self.shared.state().faults.clear();
    }

    /// Devices activated through PI's protocol.
    pub fn device_rows(&self) -> Vec<DeviceRow> {
        self.shared.state().pi_devices.clone()
    }

    /// Revokes a device as an admin would; its next lease refresh reports `device_revoked`.
    pub fn revoke_device(&self, device_id: &str) -> bool {
        let mut state = self.shared.state();
        let row = state
            .pi_devices
            .iter_mut()
            .find(|d| d.device_id == device_id);
        row.map(|d| d.status = DeviceStatus::Revoked).is_some()
    }

    /// True if `refresh_token` belongs to a family revoked by reuse detection or revocation.
    pub fn refresh_family_revoked(&self, refresh_token: &str) -> bool {
        let state = self.shared.state();
        state
            .refresh
            .get(refresh_token)
            .is_none_or(|r| state.revoked_families.contains(&r.family))
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.shared.state().requests.clone()
    }

    pub fn clear_requests(&self) {
        self.shared.state().requests.clear();
    }

    /// Blocks until the server stops (binary use).
    pub fn wait(mut self) {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.http.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn serve(shared: &Shared, mut request: tiny_http::Request) {
    let mut body = Vec::new();
    let _ = request.as_reader().take(256 << 10).read_to_end(&mut body);
    let url = request.url().to_owned();
    let (path, query) = url.split_once('?').unwrap_or((&url, ""));
    let req = Req {
        method: request.method().as_str().to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        headers: request
            .headers()
            .iter()
            .map(|h| {
                (
                    h.field.as_str().as_str().to_owned(),
                    h.value.as_str().to_owned(),
                )
            })
            .collect(),
        body,
    };
    let cid = correlation_id(&req);
    let (resp, delay) = handlers::handle(shared, &req, &cid);
    if let Some(d) = delay {
        thread::sleep(d);
    }
    let mut response = tiny_http::Response::from_data(resp.body.clone())
        .with_status_code(tiny_http::StatusCode(resp.status));
    let mut headers = resp.headers.clone();
    let now = shared.state().now();
    if !resp.has_header("Date") {
        headers.push(("Date".into(), crypto::http_date(now)));
    }
    if req.path.starts_with(handlers::API_PREFIX) {
        headers.push(("X-Correlation-Id".into(), cid));
    }
    if !resp.has_header("Cache-Control") {
        headers.push(("Cache-Control".into(), "no-store".into()));
    }
    let origin = req.header("Origin");
    if handlers::pi_cors_path(&req.path) {
        headers.push(("Vary".into(), "Origin".into()));
        if let Some(origin) = origin.filter(|o| allowed_origins(shared).iter().any(|a| a == o)) {
            headers.push(("Access-Control-Allow-Origin".into(), origin.to_owned()));
            headers.push((
                "Access-Control-Expose-Headers".into(),
                "X-Correlation-Id, Idempotent-Replayed".into(),
            ));
        }
    }
    for (k, v) in headers {
        if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            response.add_header(h);
        }
    }
    let _ = request.respond(response);
}

/// PI keeps a client's `X-Correlation-Id` only when it is 8–64 letters, digits or dashes.
fn correlation_id(req: &Req) -> String {
    req.header("X-Correlation-Id")
        .map(str::trim)
        .filter(|c| {
            (8..=64).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        .map_or_else(crypto::uuid, str::to_owned)
}

/// `CorsSubscriber::allowedOrigins`: scheme, host and port of every registered redirect URI.
fn allowed_origins(shared: &Shared) -> Vec<String> {
    shared
        .state()
        .clients()
        .iter()
        .flat_map(|c| c.redirect_uris.iter())
        .filter_map(|uri| {
            let (scheme, rest) = uri.split_once("://")?;
            let authority = rest.split(['/', '?', '#']).next()?;
            let authority = authority.rsplit('@').next()?;
            (matches!(scheme, "http" | "https") && !authority.is_empty())
                .then(|| format!("{scheme}://{authority}"))
        })
        .collect()
}

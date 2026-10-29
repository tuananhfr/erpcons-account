//! HTTP exchanges: correlation ids, idempotency keys, problem details, bounded retries
//! (contract §2, §3).
use std::{thread, time::Duration};

use serde::Deserialize;

use crate::{ApiCode, ApiError, Error, random};

const MAX_BODY: u64 = 256 << 10;
const MAX_ATTEMPTS: u32 = 3;
const BACKOFF_FIRST_MS: u64 = 1000;
const BACKOFF_CAP_MS: u64 = 300_000;

pub(crate) struct Http {
    agent: ureq::Agent,
    user_agent: String,
    max_wait: Duration,
}

pub(crate) struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
    pub correlation_id: String,
    pub retry_after: Option<Duration>,
    /// Unix seconds of the `Date` header.
    pub(crate) date: Option<i64>,
}

pub(crate) enum Body<'a> {
    Json(&'a [u8]),
    Form(&'a str),
}

/// Whether a failed exchange may be repeated with the same request.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Retry {
    /// GETs and POSTs carrying an `Idempotency-Key`: network errors, 429, 503, 409 in progress.
    Idempotent,
    /// Token grants: a lost response may already have rotated the token, so only 429 and 503.
    StatusOnly,
}

impl Http {
    pub(crate) fn new(timeout: Duration, user_agent: &str, max_wait: Duration) -> Self {
        let certs: Vec<_> = rustls_native_certs::load_native_certs()
            .certs
            .iter()
            .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
            .collect();
        let agent = ureq::Agent::config_builder()
            .timeout_connect(Some(timeout))
            .timeout_recv_response(Some(timeout))
            .timeout_recv_body(Some(timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::new_with_certs(&certs))
                    .build(),
            )
            .build()
            .new_agent();
        Self {
            agent,
            user_agent: user_agent.into(),
            max_wait,
        }
    }

    pub(crate) fn get(&self, url: &str, bearer: Option<&str>) -> Result<Reply, Error> {
        let cid = random::uuid_v4()?;
        let mut req = self
            .agent
            .get(url)
            .header("User-Agent", &self.user_agent)
            .header("Accept", "application/json")
            .header("X-Correlation-Id", &cid);
        if let Some(t) = bearer {
            req = req.header("Authorization", &format!("Bearer {t}"));
        }
        finish(req.call(), cid)
    }

    pub(crate) fn post(
        &self,
        url: &str,
        bearer: Option<&str>,
        body: &Body,
        idempotency_key: &str,
    ) -> Result<Reply, Error> {
        let cid = random::uuid_v4()?;
        let (content_type, bytes) = match body {
            Body::Json(b) => ("application/json", *b),
            Body::Form(f) => ("application/x-www-form-urlencoded", f.as_bytes()),
        };
        let mut req = self
            .agent
            .post(url)
            .header("User-Agent", &self.user_agent)
            .header("Accept", "application/json")
            .header("Content-Type", content_type)
            .header("Idempotency-Key", idempotency_key)
            .header("X-Correlation-Id", &cid);
        if let Some(t) = bearer {
            req = req.header("Authorization", &format!("Bearer {t}"));
        }
        finish(req.send(bytes), cid)
    }

    /// Repeats `exchange` within [`MAX_ATTEMPTS`] while the wait fits `max_retry_wait`.
    pub(crate) fn retrying(
        &self,
        retry: Retry,
        mut exchange: impl FnMut() -> Result<Reply, Error>,
    ) -> Result<Reply, Error> {
        let mut attempt = 0u32;
        loop {
            let result = exchange();
            let wait = match &result {
                Ok(r) if retryable(r) => Some(r.retry_after.unwrap_or_else(|| backoff(attempt))),
                Err(e) if retry == Retry::Idempotent && e.is_offline() => Some(backoff(attempt)),
                _ => None,
            };
            match wait {
                Some(w) if attempt + 1 < MAX_ATTEMPTS && w <= self.max_wait => {
                    thread::sleep(w);
                    attempt += 1;
                }
                _ => return result,
            }
        }
    }
}

fn finish(
    result: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    cid: String,
) -> Result<Reply, Error> {
    let mut resp = result.map_err(network)?;
    let headers = resp.headers();
    let header = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).map(str::trim);
    let correlation_id = header("x-correlation-id").map_or(cid, str::to_owned);
    let retry_after = header("retry-after")
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs);
    let date = header("date").and_then(crate::time::parse_http_date);
    let status = resp.status().as_u16();
    let body = resp
        .body_mut()
        .with_config()
        .limit(MAX_BODY)
        .read_to_vec()
        .map_err(network)?;
    Ok(Reply {
        status,
        body,
        correlation_id,
        retry_after,
        date,
    })
}

fn network(e: ureq::Error) -> Error {
    match e {
        ureq::Error::Timeout(_) => Error::Timeout,
        ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::TimedOut => Error::Timeout,
        other => Error::Network(other.to_string()),
    }
}

/// Full-jitter exponential backoff from 1 s to 5 min (contract §2).
fn backoff(attempt: u32) -> Duration {
    let ceiling = BACKOFF_FIRST_MS
        .saturating_mul(1 << attempt.min(16))
        .min(BACKOFF_CAP_MS);
    Duration::from_millis(random::below(ceiling))
}

fn retryable(r: &Reply) -> bool {
    match r.status {
        503 => true,
        429 => problem_code(r).as_deref() != Some("quota_exceeded"),
        409 => problem_code(r).as_deref() == Some("idempotency_in_progress"),
        _ => false,
    }
}

/// PI's `{ok:false, message, code?, correlationId?}` or an RFC 9457 problem: both carry `code`.
#[derive(Deserialize)]
struct Problem {
    ok: Option<bool>,
    code: Option<String>,
    #[serde(alias = "correlationId")]
    correlation_id: Option<String>,
    max_devices: Option<u64>,
    active_devices: Option<u64>,
    // PHP emits `[]` for an empty array, so only an object carries field names.
    errors: Option<serde_json::Value>,
}

fn problem(r: &Reply) -> Option<Problem> {
    serde_json::from_slice(&r.body).ok()
}

fn problem_code(r: &Reply) -> Option<String> {
    problem(r)?.code
}

impl Reply {
    pub(crate) fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Typed error for a non-2xx reply.
    pub(crate) fn error(&self) -> Error {
        let p = problem(self);
        let mut code = ApiCode::from_parts(self.status, p.as_ref().and_then(|p| p.code.as_deref()));
        // A 404 from a proxy or a missing route is not PI telling us the resource is gone.
        if self.status == 404
            && p.as_ref()
                .is_some_and(|p| p.ok == Some(false) && p.code.is_none())
        {
            code = ApiCode::DeviceUnknown;
        }
        let correlation_id = p
            .as_ref()
            .and_then(|p| p.correlation_id.clone())
            .unwrap_or_else(|| self.correlation_id.clone());
        log::warn!(
            "PI request failed: HTTP {} {code:?} correlation id {correlation_id}",
            self.status
        );
        Error::Api(ApiError {
            status: self.status,
            code,
            correlation_id: Some(correlation_id),
            retry_after: self.retry_after,
            max_devices: p.as_ref().and_then(|p| p.max_devices),
            active_devices: p.as_ref().and_then(|p| p.active_devices),
            errors: match p.and_then(|p| p.errors) {
                Some(serde_json::Value::Object(m)) => {
                    let mut names: Vec<String> = m.keys().cloned().collect();
                    names.sort();
                    names.into()
                }
                _ => Box::default(),
            },
        })
    }

    pub(crate) fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, Error> {
        serde_json::from_slice(&self.body).map_err(|e| Error::BadResponse(e.to_string()))
    }
}

/// `application/x-www-form-urlencoded` body.
pub(crate) fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", form_escape(k), form_escape(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn form_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Percent-encoding for query components.
pub(crate) fn query_escape(s: &str) -> String {
    form_escape(s)
}

/// Decodes `%XX` and `+` in a query component.
pub(crate) fn query_unescape(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = s.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

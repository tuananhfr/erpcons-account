//! OIDC discovery, authorization request, token grants, revocation and ID token checks
//! (contract §1).
use serde::Deserialize;
use serde_json::Value;

use crate::{
    Error,
    http::{Body, Http, Reply, Retry, form, query_escape},
    jose, random, time,
};

#[derive(Clone, Debug)]
pub(crate) struct Discovery {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: String,
}

/// `https`, or `http` on a loopback host when the issuer itself is loopback `http` (mock).
pub(crate) fn allowed_url(url: &str, issuer: &str) -> bool {
    let loopback = |u: &str| {
        ["http://127.0.0.1", "http://localhost", "http://[::1]"]
            .iter()
            .any(|p| {
                u.strip_prefix(p)
                    .is_some_and(|r| r.is_empty() || r.starts_with([':', '/']))
            })
    };
    let clean = !url.chars().any(|c| c.is_whitespace() || c.is_control()) && !url.contains('#');
    clean && (url.starts_with("https://") || (loopback(url) && loopback(issuer)))
}

pub(crate) fn discover(http: &Http, issuer: &str) -> Result<Discovery, Error> {
    #[derive(Deserialize)]
    struct Doc {
        issuer: String,
        authorization_endpoint: String,
        token_endpoint: String,
        revocation_endpoint: Option<String>,
        #[serde(default)]
        code_challenge_methods_supported: Vec<String>,
    }
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let reply = http.retrying(Retry::Idempotent, || http.get(&url, None))?;
    if !reply.ok() {
        return Err(reply.error());
    }
    let doc: Doc = reply.json()?;
    if doc.issuer != issuer {
        return Err(Error::IssuerMismatch);
    }
    if !doc
        .code_challenge_methods_supported
        .iter()
        .any(|m| m == "S256")
    {
        return Err(Error::BadResponse("discovery lacks PKCE S256".into()));
    }
    let revocation = doc
        .revocation_endpoint
        .ok_or_else(|| Error::BadResponse("discovery lacks revocation_endpoint".into()))?;
    for u in [
        &doc.authorization_endpoint,
        &doc.token_endpoint,
        &revocation,
    ] {
        if !allowed_url(u, issuer) {
            return Err(Error::BadResponse("insecure discovery endpoint".into()));
        }
    }
    Ok(Discovery {
        authorization_endpoint: doc.authorization_endpoint,
        token_endpoint: doc.token_endpoint,
        revocation_endpoint: revocation,
    })
}

pub(crate) fn pkce_challenge(verifier: &str) -> String {
    jose::sha256_b64(verifier.as_bytes())
}

pub(crate) struct AuthorizeRequest<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub state: &'a str,
    pub nonce: &'a str,
    pub code_challenge: &'a str,
    pub org_context: Option<&'a str>,
    pub ui_locale: Option<&'a str>,
}

pub(crate) fn authorize_url(d: &Discovery, r: &AuthorizeRequest) -> String {
    let mut params = vec![
        ("response_type", "code"),
        ("client_id", r.client_id),
        ("redirect_uri", r.redirect_uri),
        ("scope", r.scope),
        ("state", r.state),
        ("nonce", r.nonce),
        ("code_challenge", r.code_challenge),
        ("code_challenge_method", "S256"),
    ];
    if let Some(org) = r.org_context {
        params.push(("org_context", org));
    }
    if let Some(locale) = r.ui_locale {
        params.push(("ui_locales", locale));
    }
    let query: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{k}={}", query_escape(v)))
        .collect();
    let sep = if d.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    format!("{}{sep}{}", d.authorization_endpoint, query.join("&"))
}

pub(crate) struct Tokens {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
}

fn token_request(http: &Http, d: &Discovery, body: &str) -> Result<Tokens, Error> {
    #[derive(Deserialize)]
    struct Response {
        access_token: String,
        token_type: String,
        expires_in: Option<u64>,
        refresh_token: Option<String>,
        id_token: Option<String>,
    }
    let key = random::uuid_v4()?;
    let reply = http.retrying(Retry::StatusOnly, || {
        http.post(&d.token_endpoint, None, &Body::Form(body), &key)
    })?;
    if !reply.ok() {
        return Err(token_error(&reply));
    }
    let r: Response = reply.json()?;
    if !r.token_type.eq_ignore_ascii_case("bearer") || r.access_token.is_empty() {
        return Err(Error::BadResponse("token_type".into()));
    }
    // Windows credential blobs hold 2560 bytes; the contract caps refresh tokens at 1024.
    if r.refresh_token
        .as_ref()
        .is_some_and(|t| t.is_empty() || t.len() > 1024)
    {
        return Err(Error::BadResponse("refresh_token size".into()));
    }
    Ok(Tokens {
        access_token: r.access_token,
        expires_in: r.expires_in.unwrap_or(300),
        refresh_token: r.refresh_token,
        id_token: r.id_token,
    })
}

fn token_error(reply: &Reply) -> Error {
    #[derive(Deserialize)]
    struct OAuthError {
        error: String,
    }
    match reply.json::<OAuthError>() {
        Ok(e) if e.error == "invalid_grant" => Error::InvalidGrant,
        Ok(e) if !matches!(reply.status, 429 | 503) => Error::OAuth(e.error),
        _ => reply.error(),
    }
}

pub(crate) fn exchange_code(
    http: &Http,
    d: &Discovery,
    client_id: &str,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<Tokens, Error> {
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ]);
    token_request(http, d, &body)
}

/// Refresh grant; `org_context` is an `org_id` or `personal` (ADR 0008).
pub(crate) fn refresh(
    http: &Http,
    d: &Discovery,
    client_id: &str,
    refresh_token: &str,
    org_context: Option<&str>,
) -> Result<Tokens, Error> {
    let mut pairs = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(org) = org_context {
        pairs.push(("org_context", org));
    }
    token_request(http, d, &form(&pairs))
}

/// RFC 7009 revocation; one attempt, as sign-out proceeds whatever the outcome.
pub(crate) fn revoke(
    http: &Http,
    d: &Discovery,
    client_id: &str,
    refresh_token: &str,
) -> Result<(), Error> {
    let body = form(&[
        ("token", refresh_token),
        ("token_type_hint", "refresh_token"),
        ("client_id", client_id),
    ]);
    let reply = http.post(
        &d.revocation_endpoint,
        None,
        &Body::Form(&body),
        &random::uuid_v4()?,
    )?;
    if reply.ok() {
        Ok(())
    } else {
        Err(reply.error())
    }
}

/// Checks `iss`, `aud`, `exp` and `nonce`; returns `sub`. The token comes straight from the
/// token endpoint over TLS, so its signature is not verified (contract §1).
pub(crate) fn check_id_token(
    id_token: &str,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now: i64,
) -> Result<String, Error> {
    let claims = jose::unverified_payload(id_token).ok_or(Error::InvalidIdToken("format"))?;
    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(Error::InvalidIdToken("iss"));
    }
    let aud_ok = match claims.get("aud") {
        Some(Value::String(a)) => a == client_id,
        Some(Value::Array(list)) => {
            list.iter().any(|a| a.as_str() == Some(client_id))
                && (list.len() == 1 || claims.get("azp").and_then(Value::as_str) == Some(client_id))
        }
        _ => false,
    };
    if !aud_ok {
        return Err(Error::InvalidIdToken("aud"));
    }
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(Error::InvalidIdToken("exp"))?;
    if exp + time::SKEW <= now {
        return Err(Error::InvalidIdToken("exp"));
    }
    if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
        return Err(Error::InvalidIdToken("nonce"));
    }
    claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or(Error::InvalidIdToken("sub"))
}

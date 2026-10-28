//! PI ID's OIDC endpoints (`OidcController`, `AuthorizationServer`): discovery, JWKS, an
//! auto-approving authorize, token grants with rotation and reuse detection, revocation,
//! userinfo and logout.
use serde::Serialize;
use serde_json::{Value, json};

use super::{Ctx, bearer::AUDIENCE};
use crate::{
    Authorize, crypto,
    http::{Req, Resp, escape},
    jwt,
    scenario::{Client, User},
    state::{AUTH_CODE_TTL, Code, REFRESH_TTL, RefreshRecord, State},
};

/// `IdMeta::SCOPES`.
const SCOPES: [&str; 8] = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "pi.org",
    "pi.devices",
    "pi.entitlements",
    "pi.consents",
];
const PUBLIC_CACHE: &str = "public, max-age=300";

pub(super) fn discovery(ctx: &Ctx) -> Resp {
    let i = ctx.issuer;
    Resp::json(
        200,
        &json!({
            "issuer": i,
            "authorization_endpoint": format!("{i}/id/authorize"),
            "token_endpoint": format!("{i}/id/token"),
            "userinfo_endpoint": format!("{i}/id/userinfo"),
            "revocation_endpoint": format!("{i}/id/revoke"),
            "end_session_endpoint": format!("{i}/id/logout"),
            "jwks_uri": format!("{i}/id/jwks.json"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [jwt::ALG],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": SCOPES,
            "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "amr", "name", "email", "email_verified", "locale", "org_context"],
            "authorization_response_iss_parameter_supported": true,
        }),
    )
    .with_header("Cache-Control", PUBLIC_CACHE)
}

pub(super) fn jwks(st: &State) -> Resp {
    Resp::json(200, &jwt::jwks(&st.scenario.signing_keys))
        .with_header("Cache-Control", PUBLIC_CACHE)
}

fn loopback_host(uri: &str) -> Option<(&str, &str)> {
    let rest = uri.strip_prefix("http://")?;
    let end = if rest.starts_with('[') {
        rest.find(']')? + 1
    } else {
        rest.find([':', '/', '?']).unwrap_or(rest.len())
    };
    let host = rest[..end].trim_matches(['[', ']']).to_ascii_lowercase();
    ["127.0.0.1", "::1", "localhost"]
        .contains(&host.as_str())
        .then(|| rest.split_at(end))
}

/// `Clients::redirectAllowed`: exact, or loopback where the port is free (RFC 8252 §7.3).
fn redirect_allowed(client: &Client, uri: &str) -> bool {
    let without_port = |u: &str| {
        loopback_host(u).map(|(host, tail)| {
            let port = tail.strip_prefix(':').map_or(0, |t| {
                t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len())
            });
            let skip = if port > 0 { port + 1 } else { 0 };
            format!("http://{host}{}", &tail[skip..])
        })
    };
    client.redirect_uris.iter().any(|c| {
        c == uri || matches!((without_port(c), without_port(uri)), (Some(a), Some(b)) if a == b)
    })
}

/// `Clients::grantScopes`: every asked scope known and allowed, `openid` among them.
fn grant_scopes(client: &Client, requested: &str) -> Option<Vec<String>> {
    let mut asked: Vec<String> = Vec::new();
    for s in requested.split_whitespace() {
        if !asked.iter().any(|a| a == s) {
            asked.push(s.to_owned());
        }
    }
    let known = |s: &String| SCOPES.contains(&s.as_str()) && client.scopes.contains(s);
    (asked.iter().any(|s| s == "openid") && asked.iter().all(known)).then_some(asked)
}

fn truncate(s: &str, chars: usize) -> String {
    s.chars().take(chars).collect()
}

/// `AuthorizationServer::appendQuery`, without empty values.
fn append_query(uri: &str, params: &[(&str, &str)]) -> String {
    let query: Vec<String> = params
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", escape(v)))
        .collect();
    let sep = if uri.contains('?') { '&' } else { '?' };
    format!("{uri}{sep}{}", query.join("&"))
}

pub(super) fn authorize(st: &mut State, ctx: &Ctx, req: &Req) -> Resp {
    let q = |k: &str| {
        req.query(k)
            .map(|v| v.trim().to_owned())
            .unwrap_or_default()
    };
    let Some(client) = st.client(&q("client_id")) else {
        return Resp::html(
            400,
            "Không đăng nhập được",
            "Ứng dụng không được đăng ký hoặc đã bị tắt.",
        );
    };
    let redirect_uri = q("redirect_uri");
    if !redirect_allowed(&client, &redirect_uri) {
        return Resp::html(
            400,
            "Không đăng nhập được",
            "Địa chỉ chuyển về không khớp với ứng dụng.",
        );
    }
    let state = truncate(&q("state"), 500);
    let fail = |error: &str, description: &str| {
        Resp::redirect(&append_query(
            &redirect_uri,
            &[
                ("error", error),
                ("error_description", description),
                ("state", &state),
                ("iss", ctx.issuer),
            ],
        ))
    };
    if q("response_type") != "code" {
        return fail(
            "unsupported_response_type",
            "Chỉ hỗ trợ response_type=code.",
        );
    }
    let challenge = q("code_challenge");
    let challenge_ok = challenge.len() == 43
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if q("code_challenge_method") != "S256" || !challenge_ok {
        return fail(
            "invalid_request",
            "Bắt buộc PKCE với code_challenge_method=S256.",
        );
    }
    let Some(scopes) = grant_scopes(&client, &q("scope")) else {
        return fail(
            "invalid_scope",
            "Phạm vi không hợp lệ hoặc vượt quyền của ứng dụng (bắt buộc có openid).",
        );
    };
    let prompt = q("prompt");
    if !["", "login", "none", "select_account"].contains(&prompt.as_str()) {
        return fail("invalid_request", "prompt không hợp lệ.");
    }
    let hint = q("org_hint");
    let hint_ok = hint.len() == 36
        && hint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-');
    if st.scenario.authorize == Authorize::Deny {
        return fail("access_denied", "Người dùng từ chối.");
    }
    let user = st.scenario.sign_in_as.clone();
    if st.user(&user).is_none_or(|u| u.suspended) {
        // PI's login page refuses a locked account and never redirects back.
        return Resp::html(403, "Không đăng nhập được", "Tài khoản đã bị khoá.");
    }
    let org = choose_org(st, &user, hint_ok.then_some(hint.as_str()), &prompt);
    let code = crypto::token();
    let family = st.next_family();
    let now = st.now();
    st.codes.insert(
        code.clone(),
        Code {
            client_id: client.client_id.clone(),
            redirect_uri: redirect_uri.clone(),
            challenge,
            nonce: truncate(&q("nonce"), 255),
            user_id: user,
            org,
            scope: scopes.join(" "),
            family,
            created: now,
            used: false,
        },
    );
    let state = if st.scenario.authorize == Authorize::WrongState {
        format!("{state}x")
    } else {
        state
    };
    Resp::redirect(&append_query(
        &redirect_uri,
        &[("code", &code), ("state", &state), ("iss", ctx.issuer)],
    ))
    .with_header("Cache-Control", "no-store")
    .with_header("Referrer-Policy", "no-referrer")
}

/// `OidcController::afterLogin`: a matching `org_hint` wins; with two organizations, or one and
/// `prompt=select_account`, PI's organization page decides (`Scenario::org_choice`).
fn choose_org(st: &State, user: &str, hint: Option<&str>, prompt: &str) -> Option<String> {
    let orgs = st.active_orgs(user);
    if let Some(hint) = hint.filter(|h| orgs.iter().any(|o| o == h)) {
        return Some(hint.to_owned());
    }
    if orgs.len() >= 2 || (!orgs.is_empty() && prompt == "select_account") {
        return st.scenario.org_choice.clone().filter(|c| orgs.contains(c));
    }
    orgs.into_iter().next()
}

pub(super) fn token(st: &mut State, ctx: &Ctx, req: &Req) -> Resp {
    let form_type = req.header("Content-Type").unwrap_or_default();
    if !form_type.starts_with("application/x-www-form-urlencoded") {
        return Resp::oauth(
            400,
            "invalid_request",
            "Content-Type phải là application/x-www-form-urlencoded.",
        );
    }
    let f = |k: &str| req.form(k).map(|v| v.trim().to_owned()).unwrap_or_default();
    let Some(client) = st.client(&f("client_id")) else {
        return Resp::oauth(401, "invalid_client", "Ứng dụng không hợp lệ.");
    };
    match f("grant_type").as_str() {
        "authorization_code" => exchange_code(
            st,
            ctx,
            &client,
            &f("code"),
            &f("redirect_uri"),
            &f("code_verifier"),
        ),
        "refresh_token" => refresh(st, ctx, &client, &f("refresh_token"), &f("scope")),
        _ => Resp::oauth(
            400,
            "unsupported_grant_type",
            "Chỉ hỗ trợ authorization_code và refresh_token.",
        ),
    }
}

fn exchange_code(
    st: &mut State,
    ctx: &Ctx,
    client: &Client,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Resp {
    let invalid = || {
        Resp::oauth(
            400,
            "invalid_grant",
            "Mã uỷ quyền không hợp lệ hoặc đã hết hạn.",
        )
    };
    let verifier_ok = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b));
    if code.is_empty() {
        return invalid();
    }
    if !verifier_ok {
        return Resp::oauth(400, "invalid_request", "code_verifier không hợp lệ.");
    }
    let now = st.now();
    let Some(rec) = st.codes.get(code) else {
        return invalid();
    };
    if rec.used {
        // A replayed code may have leaked: everything issued from it goes.
        let family = rec.family;
        st.revoke_family(family);
        return invalid();
    }
    if rec.created + AUTH_CODE_TTL < now
        || rec.client_id != client.client_id
        || rec.redirect_uri != redirect_uri
    {
        return invalid();
    }
    if crypto::sha256_b64(verifier.as_bytes()) != rec.challenge {
        return Resp::oauth(400, "invalid_grant", "PKCE không khớp.");
    }
    let (user, org, scope, nonce, family, created) = (
        rec.user_id.clone(),
        rec.org.clone(),
        rec.scope.clone(),
        rec.nonce.clone(),
        rec.family,
        rec.created,
    );
    if let Some(rec) = st.codes.get_mut(code) {
        rec.used = true;
    }
    if let Some(problem) = st.ineligible(&user, org.as_deref()) {
        return Resp::oauth(400, "invalid_grant", problem);
    }
    let scopes: Vec<&str> = scope.split(' ').collect();
    let mut body = tokens(st, ctx, client, &user, &scopes, org, family);
    if let Some(account) = st.user(&user) {
        body["id_token"] = id_token(st, ctx, client, account, &scopes, &nonce, created).into();
    }
    Resp::json(200, &body)
}

fn refresh(st: &mut State, ctx: &Ctx, client: &Client, token: &str, scope: &str) -> Resp {
    let invalid = || {
        Resp::oauth(
            400,
            "invalid_grant",
            "Refresh token không hợp lệ hoặc đã bị thu hồi.",
        )
    };
    let now = st.now();
    let Some(rec) = st.refresh.get(token) else {
        return invalid();
    };
    if st.revoked_families.contains(&rec.family) || rec.client_id != client.client_id {
        return invalid();
    }
    if rec.rotated {
        // RFC 9700 §4.14.2: someone else holds a copy of a rotated token.
        let family = rec.family;
        st.revoke_family(family);
        return invalid();
    }
    if rec.expires < now {
        return invalid();
    }
    let granted: Vec<String> = rec.scope.split(' ').map(str::to_owned).collect();
    let mut scopes = granted.clone();
    if !scope.is_empty() {
        let mut asked: Vec<String> = Vec::new();
        for s in scope.split_whitespace() {
            if !asked.iter().any(|a| a == s) {
                asked.push(s.to_owned());
            }
        }
        if asked.iter().any(|s| !granted.contains(s)) {
            return Resp::oauth(
                400,
                "invalid_scope",
                "Không được xin rộng hơn phạm vi đã cấp.",
            );
        }
        scopes = asked;
    }
    let (family, user, org) = (rec.family, rec.user_id.clone(), rec.org.clone());
    if let Some(rec) = st.refresh.get_mut(token) {
        rec.rotated = true;
    }
    if let Some(problem) = st.ineligible(&user, org.as_deref()) {
        st.revoke_family(family);
        return Resp::oauth(400, "invalid_grant", problem);
    }
    let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
    Resp::json(200, &tokens(st, ctx, client, &user, &scopes, org, family))
}

/// Access-token claims in `AuthorizationServer::tokens` order.
#[derive(Serialize)]
struct AccessClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: Vec<&'a str>,
    azp: &'a str,
    scope: &'a str,
    org_context: Option<&'a str>,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
}

fn tokens(
    st: &mut State,
    ctx: &Ctx,
    client: &Client,
    user: &str,
    scopes: &[&str],
    org: Option<String>,
    family: u64,
) -> Value {
    let now = st.now();
    let ttl = st.scenario.access_token_ttl;
    let scope = scopes.join(" ");
    let mut aud = vec![AUDIENCE];
    aud.extend(client.product.as_deref().filter(|p| !p.is_empty()));
    let claims = AccessClaims {
        iss: ctx.issuer,
        sub: user,
        aud,
        azp: &client.client_id,
        scope: &scope,
        org_context: org.as_deref(),
        iat: now,
        nbf: now,
        exp: now + ttl,
        jti: crypto::uuid(),
    };
    let mut body = json!({
        "access_token": sign(st, &claims),
        "token_type": "Bearer",
        "expires_in": ttl,
        "scope": scope,
    });
    if scopes.contains(&"offline_access") {
        let refresh = crypto::token();
        st.refresh.insert(
            refresh.clone(),
            RefreshRecord {
                family,
                user_id: user.to_owned(),
                org,
                client_id: client.client_id.clone(),
                scope: scope.clone(),
                expires: now + REFRESH_TTL,
                rotated: false,
            },
        );
        body["refresh_token"] = refresh.into();
    }
    body
}

/// ID-token claims in `AuthorizationServer::idToken` order; PHP's `array_filter` drops empty
/// strings and nulls.
#[derive(Serialize)]
struct IdClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
    auth_time: i64,
    #[serde(skip_serializing_if = "str::is_empty")]
    nonce: &'a str,
    amr: [&'a str; 1],
    #[serde(flatten)]
    profile: Profile<'a>,
}

#[derive(Serialize)]
struct Profile<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locale: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
}

/// The mock's accounts all live in Vietnam.
const COUNTRY: &str = "VN";

/// `AuthorizationServer::profileClaims`.
fn profile<'a>(user: &'a User, scopes: &[&str]) -> Profile<'a> {
    let with_profile = scopes.contains(&"profile");
    let with_email = scopes.contains(&"email");
    Profile {
        name: Some(user.display_name.as_str()).filter(|n| with_profile && !n.is_empty()),
        locale: with_profile.then_some("vi-VN"),
        country: with_profile.then_some(COUNTRY),
        email: user
            .email
            .as_deref()
            .filter(|e| with_email && !e.is_empty()),
        email_verified: with_email.then_some(user.email.is_some()),
    }
}

fn id_token(
    st: &State,
    ctx: &Ctx,
    client: &Client,
    user: &User,
    scopes: &[&str],
    nonce: &str,
    auth_time: i64,
) -> String {
    let now = st.now();
    let claims = IdClaims {
        iss: ctx.issuer,
        sub: &user.user_id,
        aud: &client.client_id,
        iat: now,
        exp: now + st.scenario.access_token_ttl,
        auth_time,
        nonce,
        amr: ["otp"],
        profile: profile(user, scopes),
    };
    sign(st, &claims)
}

/// PI's `Jwt::sign`: `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE`, as serde_json writes.
fn sign(st: &State, claims: &impl Serialize) -> String {
    let payload = serde_json::to_string(claims).unwrap_or_default();
    match st.scenario.signing_keys.first() {
        Some(key) => jwt::sign(&payload, "JWT", key),
        None => String::new(),
    }
}

/// RFC 7009: always 200 `{}`; the family goes only when the client owns it.
pub(super) fn revoke(st: &mut State, req: &Req) -> Resp {
    let token = req.form("token").unwrap_or_default();
    let client_id = req.form("client_id").unwrap_or_default();
    let family = st
        .refresh
        .get(&token)
        .filter(|r| !token.is_empty() && r.client_id == client_id)
        .map(|r| r.family);
    if let Some(family) = family {
        st.revoke_family(family);
    }
    Resp::json(200, &json!({}))
}

/// `GET /id/userinfo`: any valid PI ID token, with no audience check, of an active account.
pub(super) fn userinfo(st: &State, req: &Req) -> Resp {
    let info = req
        .header("Authorization")
        .and_then(|h| h.strip_prefix("Bearer "))
        .and_then(|t| jwt::verify(t.trim(), st.now(), "JWT", &st.scenario.signing_keys))
        .and_then(|claims| {
            let user = st.user(claims["sub"].as_str()?).filter(|u| !u.suspended)?;
            let scopes: Vec<&str> = claims["scope"]
                .as_str()
                .unwrap_or_default()
                .split(' ')
                .collect();
            let mut info = serde_json::to_value(profile(user, &scopes)).ok()?;
            info["sub"] = user.user_id.clone().into();
            Some(info)
        });
    match info {
        Some(info) => Resp::json(200, &info),
        None => Resp::json(401, &json!({ "error": "invalid_token" }))
            .with_header("WWW-Authenticate", "Bearer error=\"invalid_token\""),
    }
}

/// `GET /id/logout`: back to a registered `post_logout_redirect_uri`, else PI's own page.
pub(super) fn logout(st: &State, req: &Req) -> Resp {
    let target = req.query("post_logout_redirect_uri").unwrap_or_default();
    let allowed = req
        .query("client_id")
        .and_then(|id| st.client(&id))
        .is_some_and(|c| !target.is_empty() && c.post_logout_uris.contains(&target));
    if allowed {
        let state = truncate(&req.query("state").unwrap_or_default(), 500);
        return Resp::redirect(&append_query(&target, &[("state", &state)]));
    }
    Resp::html(
        200,
        "Đã đăng xuất",
        "Bạn đã đăng xuất khỏi PI ID trên trình duyệt này.",
    )
}

//! Discovery, authorization (auto-approve), token grants with rotation and reuse detection,
//! revocation (contract §1).
use ed25519_dalek::SigningKey;
use serde_json::json;

use super::Ctx;
use crate::{
    Authorize, crypto,
    http::{Req, Resp, escape},
    state::{AccessRecord, Code, RefreshRecord, State},
};

const DESKTOP: &str = "erpcons-office-desktop";
const WEB: &str = "erpcons-office-web";
const DESKTOP_SCOPES: [&str; 6] = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "pi.entitlements",
    "pi.devices",
];
const ID_TOKEN_KID: &str = "pi-mock-id-1";

fn id_token_key() -> SigningKey {
    SigningKey::from_bytes(&crypto::sha256(b"pi-mock ID token key"))
}

pub(super) fn discovery(ctx: &Ctx) -> Resp {
    let i = ctx.issuer;
    Resp::json(
        200,
        &json!({
            "issuer": i,
            "authorization_endpoint": format!("{i}/authorize"),
            "token_endpoint": format!("{i}/token"),
            "revocation_endpoint": format!("{i}/revoke"),
            "end_session_endpoint": format!("{i}/logout"),
            "jwks_uri": format!("{i}/jwks"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "id_token_signing_alg_values_supported": ["EdDSA"],
            "subject_types_supported": ["public"],
            "scopes_supported": DESKTOP_SCOPES,
        }),
    )
}

pub(super) fn jwks() -> Resp {
    let x = crypto::b64(id_token_key().verifying_key().as_bytes());
    Resp::json(
        200,
        &json!({ "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": x, "kid": ID_TOKEN_KID, "use": "sig", "alg": "EdDSA" }] }),
    )
}

fn redirect_allowed(st: &State, client_id: &str, uri: &str) -> bool {
    match client_id {
        // RFC 8252 §7.3: any port on the IPv4 loopback literal.
        DESKTOP => uri
            .strip_prefix("http://127.0.0.1:")
            .and_then(|r| r.split_once('/'))
            .is_some_and(|(port, path)| {
                !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && path == "callback"
            }),
        WEB => st.scenario.web_redirect_uris.iter().any(|u| u == uri),
        _ => false,
    }
}

pub(super) fn authorize(st: &mut State, ctx: &Ctx, req: &Req) -> Resp {
    let q = |k: &str| req.query(k);
    let client_id = q("client_id").unwrap_or_default();
    let Some(redirect_uri) = q("redirect_uri").filter(|u| redirect_allowed(st, &client_id, u))
    else {
        return Resp::text(400, "invalid client_id or redirect_uri");
    };
    let state = q("state").unwrap_or_default();
    let back = |params: &[(&str, &str)]| {
        let mut all: Vec<(&str, &str)> = params.to_vec();
        all.push(("iss", ctx.issuer));
        let query: Vec<String> = all
            .iter()
            .map(|(k, v)| format!("{k}={}", escape(v)))
            .collect();
        Resp::redirect(&format!("{redirect_uri}?{}", query.join("&")))
    };
    let fail = |error: &str| back(&[("error", error), ("state", &state)]);
    if q("response_type").as_deref() != Some("code") {
        return fail("unsupported_response_type");
    }
    let challenge = q("code_challenge").unwrap_or_default();
    if challenge.len() != 43 || q("code_challenge_method").as_deref() != Some("S256") {
        return fail("invalid_request");
    }
    let Some(nonce) = q("nonce").filter(|n| !n.is_empty()) else {
        return fail("invalid_request");
    };
    if state.is_empty() {
        return fail("invalid_request");
    }
    let requested = q("scope").unwrap_or_default();
    if !requested.split(' ').any(|s| s == "openid") {
        return fail("invalid_scope");
    }
    let scope: Vec<&str> = requested
        .split(' ')
        .filter(|s| DESKTOP_SCOPES.contains(s) && !(client_id == WEB && *s == "pi.devices"))
        .collect();
    let user = st.scenario.sign_in_as.clone();
    let org = match q("org_context").as_deref() {
        None | Some("personal") => None,
        Some(org) if st.membership_status(&user, org).as_deref() == Some("active") => {
            Some(org.to_owned())
        }
        Some(_) => return fail("access_denied"),
    };
    if st.scenario.authorize == Authorize::Deny || st.user(&user).is_none_or(|u| u.suspended) {
        return fail("access_denied");
    }
    let code = crypto::token();
    st.codes.insert(
        code.clone(),
        Code {
            client_id,
            redirect_uri: redirect_uri.clone(),
            challenge,
            nonce,
            user_id: user,
            org,
            scope: scope.join(" "),
            used: false,
        },
    );
    let state = if st.scenario.authorize == Authorize::WrongState {
        format!("{state}x")
    } else {
        state.clone()
    };
    back(&[("code", &code), ("state", &state)])
}

struct Grant<'a> {
    family: u64,
    user: &'a str,
    org: Option<String>,
    client_id: &'a str,
    scope: &'a str,
    nonce: Option<&'a str>,
}

fn issue(st: &mut State, ctx: &Ctx, g: Grant) -> Resp {
    let Grant {
        family,
        user,
        org,
        client_id,
        scope,
        nonce,
    } = g;
    let now = st.now();
    let access = crypto::token();
    let refresh = crypto::token();
    st.access.insert(
        access.clone(),
        AccessRecord {
            user_id: user.into(),
            org: org.clone(),
            client_id: client_id.into(),
            scope: scope.into(),
            exp: now + st.scenario.access_token_ttl,
        },
    );
    st.refresh.insert(
        refresh.clone(),
        RefreshRecord {
            family,
            user_id: user.into(),
            org,
            client_id: client_id.into(),
            scope: scope.into(),
            active: true,
        },
    );
    let mut body = json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": st.scenario.access_token_ttl,
        "refresh_token": refresh,
        "scope": scope,
    });
    if let Some(nonce) = nonce {
        let email = st.user(user).and_then(|u| u.email.clone());
        let claims = json!({
            "iss": ctx.issuer, "aud": client_id, "sub": user, "iat": now,
            "exp": now + 600, "nonce": nonce, "email": email,
        });
        let header = json!({ "alg": "EdDSA", "kid": ID_TOKEN_KID, "typ": "JWT" });
        body["id_token"] = crypto::sign(&header, &claims, &id_token_key()).into();
    }
    Resp::json(200, &body)
}

pub(super) fn token(st: &mut State, ctx: &Ctx, req: &Req) -> Resp {
    let f = |k: &str| req.form(k);
    let client_id = f("client_id").unwrap_or_default();
    if client_id != DESKTOP && client_id != WEB {
        return Resp::oauth_error(401, "invalid_client");
    }
    match f("grant_type").as_deref() {
        Some("authorization_code") => {
            let (Some(code), Some(redirect_uri), Some(verifier)) =
                (f("code"), f("redirect_uri"), f("code_verifier"))
            else {
                return Resp::oauth_error(400, "invalid_request");
            };
            let Some(rec) = st.codes.get_mut(&code) else {
                return Resp::oauth_error(400, "invalid_grant");
            };
            let pkce_ok = (43..=128).contains(&verifier.len())
                && crypto::sha256_b64(verifier.as_bytes()) == rec.challenge;
            if rec.used
                || rec.client_id != client_id
                || rec.redirect_uri != redirect_uri
                || !pkce_ok
            {
                rec.used = true;
                return Resp::oauth_error(400, "invalid_grant");
            }
            rec.used = true;
            let (user, org, scope, nonce) = (
                rec.user_id.clone(),
                rec.org.clone(),
                rec.scope.clone(),
                rec.nonce.clone(),
            );
            st.counter += 1;
            let family = st.counter;
            let grant = Grant {
                family,
                user: &user,
                org,
                client_id: &client_id,
                scope: &scope,
                nonce: Some(&nonce),
            };
            issue(st, ctx, grant)
        }
        Some("refresh_token") => {
            let Some(token) = f("refresh_token") else {
                return Resp::oauth_error(400, "invalid_request");
            };
            let Some(rec) = st.refresh.get(&token) else {
                return Resp::oauth_error(400, "invalid_grant");
            };
            let (family, user, org, scope, active, owner) = (
                rec.family,
                rec.user_id.clone(),
                rec.org.clone(),
                rec.scope.clone(),
                rec.active,
                rec.client_id.clone(),
            );
            if st.revoked_families.contains(&family) || owner != client_id {
                return Resp::oauth_error(400, "invalid_grant");
            }
            if !active {
                // RFC 9700 §4.14.2: reuse of a rotated token revokes the whole family.
                st.revoked_families.insert(family);
                return Resp::oauth_error(400, "invalid_grant");
            }
            if st.user(&user).is_none_or(|u| u.suspended) {
                return Resp::oauth_error(400, "invalid_grant");
            }
            let org = match f("org_context").as_deref() {
                None => org,
                Some("personal") => None,
                Some(id) if st.membership_status(&user, id).as_deref() == Some("active") => {
                    Some(id.to_owned())
                }
                Some(_) => return Resp::oauth_error(400, "invalid_grant"),
            };
            if let Some(rec) = st.refresh.get_mut(&token) {
                rec.active = false;
            }
            let grant = Grant {
                family,
                user: &user,
                org,
                client_id: &client_id,
                scope: &scope,
                nonce: None,
            };
            issue(st, ctx, grant)
        }
        _ => Resp::oauth_error(400, "unsupported_grant_type"),
    }
}

pub(super) fn revoke(st: &mut State, req: &Req) -> Resp {
    if let Some(family) = req
        .form("token")
        .and_then(|t| st.refresh.get(&t).map(|r| r.family))
    {
        st.revoked_families.insert(family);
    }
    Resp::text(200, "")
}

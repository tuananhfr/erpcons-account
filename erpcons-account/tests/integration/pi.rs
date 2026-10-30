//! Behaviour specific to the real PI Platform (ADR 0011): prompts and `org_hint` sent by the
//! library, PI's error codes, and the token, JWKS and CORS formats pi-mock reproduces.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use erpcons_account::{ApiCode, Error, Product, Status};
use pi_mock::{DEFAULT_USER, DEV_SIGNING_KID, Membership, ORG_A, ORG_B, Scenario, Server, User};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::common::{Env, browser, sign_in, signed_in};

const REDIRECT: &str = "http%3A%2F%2F127.0.0.1%3A9%2Fcallback";

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .new_agent()
}

fn json_of(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn segment(jwt: &str, i: usize) -> String {
    let part = jwt.split('.').nth(i).unwrap();
    String::from_utf8(URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
}

/// Runs the desktop client's authorization and code exchange; returns the token response.
fn tokens(server: &Server, scope: &str) -> Value {
    let verifier = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let url = format!(
        "{}/id/authorize?response_type=code&client_id=erpcons-office-desktop&redirect_uri={REDIRECT}&scope={scope}&state=s&nonce=n&code_challenge={challenge}&code_challenge_method=S256",
        server.base_url()
    );
    let resp = agent().get(&url).call().unwrap();
    let location = resp.headers()["location"].to_str().unwrap().to_owned();
    assert!(location.ends_with(&format!("&state=s&iss={}", escape(server.issuer()))));
    let code = location
        .split(['?', '&'])
        .find_map(|p| p.strip_prefix("code="))
        .unwrap();
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}&client_id=erpcons-office-desktop&code_verifier={verifier}"
    );
    let mut resp = agent()
        .post(&format!("{}/id/token", server.base_url()))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(body.as_bytes())
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    json_of(&resp.body_mut().read_to_string().unwrap())
}

fn escape(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}

fn refresh(server: &Server, token: &str) -> (u16, Value) {
    let body =
        format!("grant_type=refresh_token&client_id=erpcons-office-desktop&refresh_token={token}");
    let mut resp = agent()
        .post(&format!("{}/id/token", server.base_url()))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(body.as_bytes())
        .unwrap();
    let status = resp.status().as_u16();
    (status, json_of(&resp.body_mut().read_to_string().unwrap()))
}

#[test]
fn sign_in_after_sign_out_asks_pi_for_a_fresh_login() {
    let env = Env::new(Scenario::default());
    let account = env.account();
    sign_in(&account);
    account.sign_out().unwrap();
    sign_in(&account);
    account.sign_out().unwrap();
    // Another process reads the request from the session file.
    let next = env.account();
    sign_in(&next);
    next.select_org(Some(ORG_A), browser).unwrap();

    let queries = env.authorize_queries();
    assert_eq!(queries.len(), 4);
    assert!(!queries[0].contains("prompt="), "{}", queries[0]);
    assert!(queries[1].contains("prompt=login"), "{}", queries[1]);
    assert!(queries[2].contains("prompt=login"), "{}", queries[2]);
    assert!(!queries[3].contains("prompt="), "{}", queries[3]);
}

#[test]
fn select_org_reauthorizes_with_org_hint_or_select_account() {
    let env = Env::new(Scenario::default());
    let account = env.account();
    sign_in(&account);
    let revokes = env.count("POST", "/id/revoke");

    account.select_org(Some(ORG_A), browser).unwrap();
    assert_eq!(
        signed_in(account.status()).active_org.as_deref(),
        Some(ORG_A)
    );
    let other = env.account_for(Product::Pdf);
    assert_eq!(signed_in(other.status()).active_org.as_deref(), Some(ORG_A));

    account.select_org(None, browser).unwrap();
    assert_eq!(signed_in(account.status()).active_org, None);

    let queries = env.authorize_queries();
    assert!(
        queries[1].contains(&format!("org_hint={ORG_A}")),
        "{}",
        queries[1]
    );
    assert!(!queries[1].contains("prompt="), "{}", queries[1]);
    assert!(
        queries[2].contains("prompt=select_account"),
        "{}",
        queries[2]
    );
    assert!(!queries[2].contains("org_hint="), "{}", queries[2]);
    // Each replaced token family is revoked.
    assert_eq!(env.count("POST", "/id/revoke") - revokes, 2);
    assert_eq!(
        account.select_org(Some("0c9e7a51-0000-4000-8000-000000000000"), browser),
        Err(Error::UnknownOrg)
    );

    // The user picks another organization on PI's page: the session follows PI.
    env.server
        .update_scenario(|s| s.org_choice = Some(ORG_B.into()));
    assert_eq!(
        account.select_org(None, browser),
        Err(Error::OrgUnavailable)
    );
    assert_eq!(
        signed_in(account.status()).active_org.as_deref(),
        Some(ORG_B)
    );
}

#[test]
fn select_org_refuses_another_user() {
    let env = Env::new(Scenario::default());
    let account = env.account();
    sign_in(&account);
    let token = env.refresh_token().unwrap();
    let revokes = env.count("POST", "/id/revoke");
    env.server.update_scenario(|s| {
        s.users.push(User {
            user_id: "2b7c4d1e-8f3a-4b6c-9d2e-1f0a3b5c7d94".into(),
            display_name: "Trần Thị Bình".into(),
            email: Some("binh.tran@example.com".into()),
            suspended: false,
            memberships: vec![Membership::new(ORG_A, "Công ty Xây dựng Ví dụ", "member")],
        });
        s.sign_in_as = "2b7c4d1e-8f3a-4b6c-9d2e-1f0a3b5c7d94".into();
    });

    assert_eq!(
        account.select_org(Some(ORG_A), browser),
        Err(Error::OrgUnavailable)
    );
    let s = signed_in(account.status());
    assert_eq!(s.user.unwrap().user_id, DEFAULT_USER);
    assert_eq!(s.active_org, None);
    assert_eq!(env.refresh_token().unwrap(), token);
    // The other user's new token family is revoked, not kept.
    assert_eq!(env.count("POST", "/id/revoke") - revokes, 1);
}

#[test]
fn inactive_membership_requires_a_new_sign_in() {
    let env = Env::new(Scenario::default());
    let account = env.account();
    sign_in(&account);
    account.select_org(Some(ORG_A), browser).unwrap();
    env.server.update_scenario(|s| {
        s.users[0].memberships[0].status = "SUSPENDED".into();
    });

    let err = account.refresh().unwrap_err();
    assert!(
        matches!(&err, Error::Api(e) if e.code == ApiCode::MembershipInactive && e.status == 403),
        "{err:?}"
    );
    assert!(signed_in(account.status()).reauth_required);
}

#[test]
fn locked_account_is_signed_out() {
    let env = Env::new(Scenario::default());
    let account = env.account();
    sign_in(&account);
    env.server.update_scenario(|s| s.users[0].suspended = true);

    let err = account.refresh().unwrap_err();
    assert!(
        matches!(&err, Error::Api(e) if e.code == ApiCode::UserSuspended && e.status == 403),
        "{err:?}"
    );
    assert_eq!(account.status(), Status::Guest);
    assert_eq!(env.refresh_token(), None);
}

#[test]
fn mock_tokens_match_pi_id() {
    let server = Server::start(Scenario::default());
    let body = tokens(&server, "openid%20profile%20email%20offline_access");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 600);
    assert_eq!(body["scope"], "openid profile email offline_access");
    assert!(
        body["refresh_token"]
            .as_str()
            .is_some_and(|t| t.len() == 43)
    );

    let access = body["access_token"].as_str().unwrap();
    assert_eq!(
        segment(access, 0),
        format!(r#"{{"alg":"EdDSA","typ":"JWT","kid":"{DEV_SIGNING_KID}"}}"#)
    );
    let payload = segment(access, 1);
    let order: Vec<usize> = [
        "iss",
        "sub",
        "aud",
        "azp",
        "scope",
        "org_context",
        "iat",
        "nbf",
        "exp",
        "jti",
    ]
    .iter()
    .map(|k| payload.find(&format!("\"{k}\":")).unwrap())
    .collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{payload}");
    let claims = json_of(&payload);
    assert_eq!(claims["iss"], server.issuer());
    assert_eq!(claims["sub"], DEFAULT_USER);
    // The Office clients carry product `erpconsoffice` (ADR 0013).
    assert_eq!(
        claims["aud"],
        serde_json::json!(["pi-platform", "erpconsoffice"])
    );
    assert_eq!(claims["azp"], "erpcons-office-desktop");
    assert_eq!(claims["org_context"], Value::Null);
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        600
    );

    let mut resp = agent().get(&server.jwks_uri()).call().unwrap();
    let jwks = json_of(&resp.body_mut().read_to_string().unwrap());
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert_eq!(key["kid"], DEV_SIGNING_KID);
    assert_eq!(key["use"], "sig");
    assert_eq!(key["alg"], "EdDSA");
    let x: [u8; 32] = URL_SAFE_NO_PAD
        .decode(key["x"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(Some(x), server.signing_public_key());
    let (input, signature) = access.rsplit_once('.').unwrap();
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).unwrap()).unwrap();
    VerifyingKey::from_bytes(&x)
        .unwrap()
        .verify(input.as_bytes(), &signature)
        .unwrap();

    let id = json_of(&segment(body["id_token"].as_str().unwrap(), 1));
    assert_eq!(id["aud"], "erpcons-office-desktop");
    assert_eq!(id["nonce"], "n");
    assert_eq!(id["amr"], serde_json::json!(["otp"]));
    assert_eq!(id["locale"], "vi-VN");
    assert_eq!(id["email"], "an.nguyen@example.com");
    assert_eq!(id["email_verified"], true);
}

#[test]
fn mock_refresh_reuse_revokes_the_family() {
    let server = Server::start(Scenario::default());
    let first = tokens(&server, "openid%20offline_access")["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, body) = refresh(&server, &first);
    assert_eq!(status, 200);
    let second = body["refresh_token"].as_str().unwrap().to_owned();
    assert!(!server.refresh_family_revoked(&second));

    let (status, body) = refresh(&server, &first);
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    assert!(server.refresh_family_revoked(&second));
    assert_eq!(refresh(&server, &second).0, 400);

    // Without offline_access PI issues no refresh token at all.
    assert!(tokens(&server, "openid").get("refresh_token").is_none());
}

#[test]
fn mock_api_envelope_correlation_and_cors_match_pi() {
    let server = Server::start(Scenario::default());
    let access = tokens(&server, "openid")["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let me = format!("{}/api/v1/id/me", server.base_url());

    let mut resp = agent()
        .get(&me)
        .header("Authorization", &format!("Bearer {access}"))
        .header("X-Correlation-Id", "test-correlation-1")
        .header("Origin", "https://office.erpcons.vn")
        .call()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let headers = resp.headers().clone();
    assert_eq!(headers["x-correlation-id"], "test-correlation-1");
    assert_eq!(
        headers["access-control-allow-origin"],
        "https://office.erpcons.vn"
    );
    let body = json_of(&resp.body_mut().read_to_string().unwrap());
    assert_eq!(body["ok"], true);
    assert_eq!(body["user"]["id"], DEFAULT_USER);
    assert_eq!(body["user"]["status"], "ACTIVE");
    assert_eq!(body["orgContext"], Value::Null);
    assert_eq!(body["organizations"][0]["myStatus"], "ACTIVE");

    let mut resp = agent()
        .get(&me)
        .header("Authorization", "Bearer not-a-token")
        .header("X-Correlation-Id", "bad id")
        .header("Origin", "https://evil.example")
        .call()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    let headers = resp.headers().clone();
    assert_ne!(headers["x-correlation-id"], "bad id");
    assert!(headers.get("access-control-allow-origin").is_none());
    assert_eq!(headers["vary"], "Origin");
    let body = json_of(&resp.body_mut().read_to_string().unwrap());
    assert_eq!(body["ok"], false);
    assert!(body["message"].is_string() && body.get("code").is_none());

    // Discovery and JWKS are not CORS endpoints at PI, and are cacheable for 5 min.
    let resp = agent()
        .get(&format!(
            "{}/.well-known/openid-configuration",
            server.base_url()
        ))
        .header("Origin", "https://office.erpcons.vn")
        .call()
        .unwrap();
    assert!(resp.headers().get("access-control-allow-origin").is_none());
    assert_eq!(resp.headers()["cache-control"], "public, max-age=300");
}

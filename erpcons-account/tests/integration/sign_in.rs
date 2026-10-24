use std::{thread, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use erpcons_account::{
    DEVICE_ENTRY, Error, LicenceState, REFRESH_TOKEN_ENTRY, SecretStore, Status,
};
use pi_mock::{Authorize, DEFAULT_USER, Scenario, Server};
use sha2::{Digest, Sha256};

use crate::common::{Env, browser, sign_in, signed_in};

#[test]
fn happy_path_signs_in_activates_and_sends_contract_headers() {
    let env = Env::new(Scenario::default());
    let account = env.account();
    assert_eq!(account.status(), Status::Guest);
    sign_in(&account);

    let s = signed_in(account.status());
    let user = s.user.clone().unwrap();
    assert_eq!(user.user_id, DEFAULT_USER);
    assert_eq!(user.email.as_deref(), Some("an.nguyen@example.com"));
    assert_eq!(s.orgs.len(), 2);
    assert_eq!(s.active_org, None);
    assert!(matches!(s.licence, LicenceState::Active { .. }));
    assert!(s.online && !s.session_only && !s.reauth_required);
    assert!(env.store.get(REFRESH_TOKEN_ENTRY).unwrap().is_some());
    assert!(env.store.get(DEVICE_ENTRY).unwrap().is_some());
    assert!(env.file("session.json").exists());
    assert!(env.file("lease-vanban.json").exists());
    assert!(env.file("catalog-vanban.jws").exists());
    assert_eq!(env.server.devices().len(), 1);

    let dir = env.dir.path().to_string_lossy().into_owned();
    for r in env.server.requests() {
        if r.path == "/authorize" {
            continue;
        }
        assert!(r.correlation_id.is_some(), "{} {}", r.method, r.path);
        assert_eq!(r.user_agent.as_deref(), Some("ERPCons-VanBan/0.6.5"));
        if r.method == "POST" {
            assert!(r.idempotency_key.is_some(), "{}", r.path);
        }
        assert!(!r.body.contains(&dir) && !r.query.contains(&dir));
    }
}

#[test]
fn state_mismatch_is_rejected() {
    let env = Env::new(Scenario {
        authorize: Authorize::WrongState,
        ..Scenario::default()
    });
    let account = env.account();
    assert_eq!(account.sign_in(browser), Err(Error::StateMismatch));
    assert_eq!(account.status(), Status::Guest);
    assert_eq!(env.refresh_token(), None);
    assert_eq!(env.count("POST", "/token"), 0);
}

#[test]
fn denied_authorization_is_reported() {
    let env = Env::new(Scenario {
        authorize: Authorize::Deny,
        ..Scenario::default()
    });
    let account = env.account();
    assert_eq!(
        account.sign_in(browser),
        Err(Error::AuthorizationDenied("access_denied".into()))
    );
    assert_eq!(account.status(), Status::Guest);
}

#[test]
fn cancel_sign_in_unblocks_the_caller() {
    let env = Env::new(Scenario::default());
    let account = env.account();
    thread::scope(|scope| {
        let waiting = scope.spawn(|| account.sign_in(|_| Ok(())));
        while account.status() != Status::SigningIn {
            thread::sleep(Duration::from_millis(10));
        }
        account.cancel_sign_in();
        assert_eq!(waiting.join().unwrap(), Err(Error::Cancelled));
    });
    assert_eq!(account.status(), Status::Guest);
}

fn authorize(server: &Server, challenge: &str, method: &str) -> String {
    let agent = ureq::Agent::config_builder()
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .new_agent();
    let url = format!(
        "{}/authorize?response_type=code&client_id=erpcons-office-desktop&redirect_uri=http%3A%2F%2F127.0.0.1%3A9%2Fcallback&scope=openid&state=s&nonce=n&code_challenge={challenge}&code_challenge_method={method}",
        server.base_url()
    );
    let resp = agent.get(&url).call().unwrap();
    resp.headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

fn exchange(server: &Server, code: &str, verifier: &str) -> u16 {
    let agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .new_agent();
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri=http%3A%2F%2F127.0.0.1%3A9%2Fcallback&client_id=erpcons-office-desktop&code_verifier={verifier}"
    );
    agent
        .post(&format!("{}/token", server.base_url()))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(body.as_bytes())
        .unwrap()
        .status()
        .as_u16()
}

fn code_of(location: &str) -> String {
    location
        .split(['?', '&'])
        .find_map(|p| p.strip_prefix("code="))
        .unwrap()
        .to_owned()
}

#[test]
fn mock_enforces_pkce_s256() {
    let server = Server::start(Scenario::default());
    let verifier = URL_SAFE_NO_PAD.encode([5u8; 32]);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let wrong = URL_SAFE_NO_PAD.encode([6u8; 32]);

    let code = code_of(&authorize(&server, &challenge, "S256"));
    assert_eq!(exchange(&server, &code, &wrong), 400);
    // A failed exchange burns the code.
    assert_eq!(exchange(&server, &code, &verifier), 400);

    let code = code_of(&authorize(&server, &challenge, "S256"));
    assert_eq!(exchange(&server, &code, &verifier), 200);
    assert_eq!(exchange(&server, &code, &verifier), 400);

    assert!(authorize(&server, &challenge, "plain").contains("error=invalid_request"));
}

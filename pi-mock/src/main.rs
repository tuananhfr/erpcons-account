//! `pi-mock [--host H] [--port N] [--issuer URL] [--web-redirect URI]...`
use std::process::ExitCode;

use pi_mock::{Scenario, Server};

const USAGE: &str =
    "usage: pi-mock [--host 127.0.0.1] [--port 8787] [--issuer URL] [--web-redirect URI]...";

fn main() -> ExitCode {
    let mut host = "127.0.0.1".to_owned();
    let mut port = "8787".to_owned();
    let mut issuer = None;
    let mut scenario = Scenario::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match (arg.as_str(), args.next()) {
            ("--host", Some(v)) => host = v,
            ("--port", Some(v)) => port = v,
            ("--issuer", Some(v)) => issuer = Some(v),
            ("--web-redirect", Some(v)) => scenario.web_redirect_uris.push(v),
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let server = match Server::bind(&format!("{host}:{port}"), issuer.as_deref(), scenario) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("pi-mock: {e}");
            return ExitCode::FAILURE;
        }
    };
    let key = server.lease_public_key();
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "{}",
        serde_json::json!({
            "listening": server.base_url(),
            "issuer": server.issuer(),
            "lease_kid": server.lease_key_id(),
            "lease_public_key_hex": hex,
            "signing_kid": server.signing_key_id(),
            "jwks_uri": server.jwks_uri(),
        })
    );
    server.wait();
    ExitCode::SUCCESS
}

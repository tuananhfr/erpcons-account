//! PI ID JWTs as `pi_id/src/Crypto/Jwt.php` makes and checks them: header `{alg, typ, kid}` in
//! that order, unpadded base64url, Ed25519 over `header.payload`, 30 s leeway on `exp`/`nbf`.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{JwtKey, crypto};

pub(crate) const ALG: &str = "EdDSA";
const LEEWAY: i64 = 30;

#[derive(Serialize)]
struct Header<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}

/// Compact JWS of `claims` (a serialized JSON object) with the first key, as PI signs.
pub(crate) fn sign(claims: &str, typ: &str, key: &JwtKey) -> String {
    let header = serde_json::to_string(&Header {
        alg: ALG,
        typ,
        kid: &key.kid,
    })
    .unwrap_or_default();
    let input = format!(
        "{}.{}",
        crypto::b64(header.as_bytes()),
        crypto::b64(claims.as_bytes())
    );
    let signature = SigningKey::from_bytes(&key.seed).sign(input.as_bytes());
    format!("{input}.{}", crypto::b64(&signature.to_bytes()))
}

/// Claims of a valid token of type `typ` signed by one of `keys`; checks no `aud`, as PI.
pub(crate) fn verify(token: &str, now: i64, typ: &str, keys: &[JwtKey]) -> Option<Value> {
    let [h, p, s] = token.split('.').collect::<Vec<_>>()[..] else {
        return None;
    };
    let header: Value = serde_json::from_slice(&crypto::unb64(h)?).ok()?;
    let header_typ = header.get("typ").map_or(Some("JWT"), Value::as_str);
    if header["alg"] != ALG || header_typ != Some(typ) {
        return None;
    }
    let kid = header["kid"].as_str()?;
    let key = keys.iter().find(|k| k.kid == kid)?;
    let signature = Signature::from_slice(&crypto::unb64(s)?).ok()?;
    SigningKey::from_bytes(&key.seed)
        .verifying_key()
        .verify(format!("{h}.{p}").as_bytes(), &signature)
        .ok()?;
    let claims: Value = serde_json::from_slice(&crypto::unb64(p)?).ok()?;
    let exp = claims.get("exp")?.as_i64()?;
    if exp + LEEWAY < now {
        return None;
    }
    if claims
        .get("nbf")
        .and_then(Value::as_i64)
        .is_some_and(|nbf| nbf - LEEWAY > now)
    {
        return None;
    }
    claims.is_object().then_some(claims)
}

/// `GET /id/jwks.json`: every configured key, public half only.
pub(crate) fn jwks(keys: &[JwtKey]) -> Value {
    let keys: Vec<Value> = keys
        .iter()
        .map(|k| {
            let x = SigningKey::from_bytes(&k.seed).verifying_key();
            json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": crypto::b64(x.as_bytes()),
                "kid": k.kid,
                "use": "sig",
                "alg": ALG,
            })
        })
        .collect();
    json!({ "keys": keys })
}

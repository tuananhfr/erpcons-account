//! JWS, thumbprints, random values and RFC 3339 times; an implementation independent of the
//! client's, so contract tests compare two readings of the docs.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn unb64(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

pub(crate) fn sha256_b64(data: &[u8]) -> String {
    b64(&Sha256::digest(data))
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS random source");
    b
}

pub(crate) fn token() -> String {
    b64(&random::<32>())
}

pub(crate) fn uuid() -> String {
    let mut b = random::<16>();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

pub(crate) fn sign(header: &Value, payload: &Value, key: &SigningKey) -> String {
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(payload.to_string().as_bytes())
    );
    let sig = key.sign(input.as_bytes());
    format!("{input}.{}", b64(&sig.to_bytes()))
}

pub(crate) fn thumbprint(x: &str) -> String {
    sha256_b64(format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#).as_bytes())
}

/// Verified device proof: `(jwk x, payload)` (lease.md §3).
pub(crate) fn verify_proof(jws: &str) -> Option<(String, Value)> {
    let parts: Vec<&str> = jws.split('.').collect();
    let [h, p, s] = parts.as_slice() else {
        return None;
    };
    let header: Value = serde_json::from_slice(&unb64(h)?).ok()?;
    if header["alg"] != "EdDSA" || header["typ"] != "pi-device-proof+jwt" {
        return None;
    }
    let jwk = header.get("jwk")?;
    if jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" || jwk.get("d").is_some() {
        return None;
    }
    let x = jwk["x"].as_str()?;
    let key: [u8; 32] = unb64(x)?.try_into().ok()?;
    let key = VerifyingKey::from_bytes(&key).ok()?;
    let sig = Signature::from_slice(&unb64(s)?).ok()?;
    key.verify_strict(format!("{h}.{p}").as_bytes(), &sig)
        .ok()?;
    let payload: Value = serde_json::from_slice(&unb64(p)?).ok()?;
    Some((x.to_owned(), payload))
}

pub(crate) fn rfc3339(t: i64) -> String {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// IMF-fixdate of the `Date` header (RFC 9110 5.6.7).
pub(crate) fn http_date(t: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{}, {d:02} {} {y:04} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[m as usize - 1],
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// Compact JWS over pre-serialized JSON, to keep the member order PI's `json_encode` gives.
pub(crate) fn sign_raw(header: &str, payload: &str, key: &SigningKey) -> String {
    let input = format!("{}.{}", b64(header.as_bytes()), b64(payload.as_bytes()));
    let sig = key.sign(input.as_bytes());
    format!("{input}.{}", b64(&sig.to_bytes()))
}

/// JSON object with its members in the given order.
pub(crate) fn ordered_object(members: &[(&str, Value)]) -> String {
    let body: Vec<String> = members
        .iter()
        .map(|(k, v)| format!("{}:{v}", Value::from(*k)))
        .collect();
    format!("{{{}}}", body.join(","))
}

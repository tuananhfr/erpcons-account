//! Compact JWS verification with EdDSA, strict JSON and device-key thumbprints (lease.md §2, §3).
use std::fmt;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use crate::{PinnedKey, VerifyError};

pub(crate) const MAX_JWS: usize = 8192;

pub(crate) fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strict base64url without padding; non-canonical trailing bits are rejected.
pub(crate) fn unb64(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// One JSON object with no duplicate member at any depth.
pub(crate) fn strict_object(bytes: &[u8]) -> Option<Map<String, Value>> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let Strict(value) = Strict::deserialize(&mut de).ok()?;
    de.end().ok()?;
    match value {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
        Ok(Strict(Value::Bool(v)))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
        Ok(Strict(Value::from(v)))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Strict, E> {
        Number::from_f64(v)
            .map(|n| Strict(Value::Number(n)))
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
        Ok(Strict(Value::String(v.into())))
    }
    fn visit_string<E>(self, v: String) -> Result<Strict, E> {
        Ok(Strict(Value::String(v)))
    }
    fn visit_unit<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            items.push(v);
        }
        Ok(Strict(Value::Array(items)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let Strict(v) = map.next_value()?;
            if out.insert(key, v).is_some() {
                return Err(de::Error::custom("duplicate member"));
            }
        }
        Ok(Strict(Value::Object(out)))
    }
}

/// Verifies a platform-signed JWS (lease or catalog) and returns its payload.
///
/// Order follows lease.md §9 steps 1 to 4: nothing from the payload is read before the
/// signature has been checked with a pinned key.
pub(crate) fn verify_platform(
    jws: &str,
    typ: &str,
    keys: &[PinnedKey],
) -> Result<Map<String, Value>, VerifyError> {
    if jws.len() > MAX_JWS {
        return Err(VerifyError::Format);
    }
    let mut parts = jws.split('.');
    let (Some(h64), Some(p64), Some(s64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(VerifyError::Format);
    };
    let header = unb64(h64)
        .and_then(|b| strict_object(&b))
        .ok_or(VerifyError::Format)?;
    let payload = unb64(p64).ok_or(VerifyError::Format)?;
    let signature = unb64(s64)
        .and_then(|s| Signature::from_slice(&s).ok())
        .ok_or(VerifyError::Format)?;
    if header.len() != 3
        || header.get("alg").and_then(Value::as_str) != Some("EdDSA")
        || header.get("typ").and_then(Value::as_str) != Some(typ)
    {
        return Err(VerifyError::Header);
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(VerifyError::Header)?;
    let pinned = keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or(VerifyError::UnknownKey)?;
    let key = VerifyingKey::from_bytes(&pinned.key).map_err(|_| VerifyError::UnknownKey)?;
    let input = format!("{h64}.{p64}");
    key.verify_strict(input.as_bytes(), &signature)
        .map_err(|_| VerifyError::Signature)?;
    strict_object(&payload).ok_or(VerifyError::Format)
}

/// Unverified payload of a compact JWS (ID tokens received directly over TLS, contract §1).
pub(crate) fn unverified_payload(jws: &str) -> Option<Map<String, Value>> {
    let mut parts = jws.split('.');
    let (Some(_), Some(p64), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    strict_object(&unb64(p64)?)
}

/// Thumbprint PI computes for a device key: SHA-256 of the raw 32-byte public key.
pub(crate) fn raw_key_thumbprint(key: &[u8; 32]) -> String {
    b64(&Sha256::digest(key))
}

pub(crate) fn sha256_b64(data: &[u8]) -> String {
    b64(&Sha256::digest(data))
}

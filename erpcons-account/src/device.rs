//! Device key, `installation_id` and device proofs (lease.md §3).
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{Error, jose, random};

pub(crate) const PROOF_TYP: &str = "pi-device-proof+jwt";

#[derive(Clone)]
pub(crate) struct Device {
    pub installation_id: String,
    key: SigningKey,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    installation_id: String,
    key: String,
}

/// Claims of `signed_challenge`, serialized in the contract's member order.
#[derive(Serialize)]
pub(crate) struct ProofClaims<'a> {
    pub nonce: &'a str,
    pub purpose: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<&'a str>,
    pub installation_id: &'a str,
    pub product_id: &'a str,
    pub platform: &'a str,
    pub client_version: &'a str,
    pub iat: i64,
}

impl Device {
    pub(crate) fn generate() -> Result<Self, Error> {
        Ok(Self {
            installation_id: random::uuid_v4()?,
            key: SigningKey::from_bytes(&random::bytes::<32>()?),
        })
    }

    pub(crate) fn from_entry(secret: &str) -> Option<Self> {
        let e: Entry = serde_json::from_str(secret).ok()?;
        let seed: [u8; 32] = jose::unb64(&e.key)?.try_into().ok()?;
        Some(Self {
            installation_id: e.installation_id,
            key: SigningKey::from_bytes(&seed),
        })
    }

    pub(crate) fn to_entry(&self) -> String {
        serde_json::json!({
            "installation_id": self.installation_id,
            "key": jose::b64(self.key.as_bytes()),
        })
        .to_string()
    }

    pub(crate) fn x(&self) -> String {
        jose::b64(self.key.verifying_key().as_bytes())
    }

    pub(crate) fn thumbprint(&self) -> String {
        jose::thumbprint(&self.x())
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub(crate) fn proof(&self, claims: &ProofClaims) -> Result<String, Error> {
        let payload = serde_json::to_string(claims).map_err(|e| Error::Internal(e.to_string()))?;
        Ok(jose::sign_compact(
            &proof_header(&self.x()),
            &payload,
            &self.key,
        ))
    }
}

pub(crate) fn proof_header(x: &str) -> String {
    format!(
        r#"{{"alg":"EdDSA","typ":"{PROOF_TYP}","jwk":{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}}}"#
    )
}

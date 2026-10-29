//! Device key and `installation_id` (lease.md §3), signing PI's device messages.
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{Error, jose, random};

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

    /// Raw public key, base64url: PI's `devicePublicKey`.
    pub(crate) fn x(&self) -> String {
        jose::b64(self.key.verifying_key().as_bytes())
    }

    /// Detached Ed25519 signature over `message`, base64url without padding.
    pub(crate) fn sign(&self, message: &str) -> String {
        jose::b64(&self.key.sign(message.as_bytes()).to_bytes())
    }

    /// The lease's `cnf.jkt` for this key.
    pub(crate) fn thumbprint(&self) -> String {
        jose::raw_key_thumbprint(self.key.verifying_key().as_bytes())
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

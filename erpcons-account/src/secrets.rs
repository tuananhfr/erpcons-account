//! Session secrets in the OS credential store (lease.md §11, ADR 0010).
use std::{collections::HashMap, fmt, sync::Mutex};

/// Credential store service shared by the four desktop apps.
pub const SERVICE: &str = "ERPCons Office PI";
/// Entry holding the refresh token.
pub const REFRESH_TOKEN_ENTRY: &str = "refresh_token";
/// Entry holding the device private key and `installation_id`.
pub const DEVICE_ENTRY: &str = "device";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// No usable credential store (for example no Secret Service on Linux).
    Unavailable(String),
    Failed(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(e) => write!(f, "credential store unavailable: {e}"),
            Self::Failed(e) => write!(f, "credential store failure: {e}"),
        }
    }
}

/// Secret entries of service [`SERVICE`]; implementations must be safe across processes.
pub trait SecretStore: Send + Sync {
    fn get(&self, entry: &str) -> Result<Option<String>, StoreError>;
    fn set(&self, entry: &str, secret: &str) -> Result<(), StoreError>;
    /// Deleting a missing entry succeeds.
    fn delete(&self, entry: &str) -> Result<(), StoreError>;
}

/// Windows Credential Manager, macOS Keychain or Linux Secret Service, through `keyring`.
#[derive(Debug, Default)]
pub struct OsSecretStore;

impl OsSecretStore {
    pub fn new() -> Self {
        Self
    }

    fn entry(name: &str) -> Result<keyring::Entry, StoreError> {
        keyring::Entry::new(SERVICE, name).map_err(map_keyring)
    }
}

fn map_keyring(e: keyring::Error) -> StoreError {
    match e {
        keyring::Error::NoStorageAccess(_) | keyring::Error::PlatformFailure(_) => {
            StoreError::Unavailable(e.to_string())
        }
        other => StoreError::Failed(other.to_string()),
    }
}

impl SecretStore for OsSecretStore {
    fn get(&self, entry: &str) -> Result<Option<String>, StoreError> {
        match Self::entry(entry)?.get_password() {
            Ok(s) => Ok(Some(s)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(map_keyring(e)),
        }
    }
    fn set(&self, entry: &str, secret: &str) -> Result<(), StoreError> {
        Self::entry(entry)?
            .set_password(secret)
            .map_err(map_keyring)
    }
    fn delete(&self, entry: &str) -> Result<(), StoreError> {
        match Self::entry(entry)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(map_keyring(e)),
        }
    }
}

/// In-memory store for tests; share one `Arc` between accounts to model one OS user.
#[derive(Debug, Default)]
pub struct MemorySecretStore {
    entries: Mutex<HashMap<String, String>>,
    unavailable: bool,
}

impl MemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// A store that behaves like a machine without a credential store.
    pub fn unavailable() -> Self {
        Self {
            unavailable: true,
            ..Self::default()
        }
    }

    fn map(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, String>>, StoreError> {
        if self.unavailable {
            return Err(StoreError::Unavailable("memory store disabled".into()));
        }
        self.entries
            .lock()
            .map_err(|_| StoreError::Failed("poisoned".into()))
    }
}

impl SecretStore for MemorySecretStore {
    fn get(&self, entry: &str) -> Result<Option<String>, StoreError> {
        Ok(self.map()?.get(entry).cloned())
    }
    fn set(&self, entry: &str, secret: &str) -> Result<(), StoreError> {
        self.map()?.insert(entry.into(), secret.into());
        Ok(())
    }
    fn delete(&self, entry: &str) -> Result<(), StoreError> {
        self.map()?.remove(entry);
        Ok(())
    }
}

//! PI account client for the ERPCons Office desktop apps: OIDC sign-in with PI ID, the shared
//! desktop session, organization context and `allowed(feature)`. Device activation and offline
//! leases are kept behind [`Config::offline_licensing`], off until PI serves them (ADR 0011).
//!
//! Blocking API meant for a worker thread. Specification: `docs/` of this repository.
#[cfg(target_arch = "wasm32")]
compile_error!("erpcons-account is only supported in native desktop applications");

mod account;
mod backoff;
mod catalog;
mod clock;
mod config;
mod device;
mod entitlements;
mod error;
mod http;
mod jose;
mod lease;
mod loopback;
mod me;
mod oidc;
mod random;
mod secrets;
mod status;
mod storage;
mod time;

pub use account::Account;
pub use backoff::Backoff;
pub use catalog::{BuiltinFeature, Tier, is_pinned_free, is_valid_feature_id};
pub use clock::{Clock, SystemClock};
pub use config::{
    ClientProfile, Config, DESKTOP_CLIENT_ID, DESKTOP_SCOPES, PI_API_PATH, PLATFORM_KEYS,
    PinnedKey, Platform, Product,
};
pub use error::{ApiCode, ApiError, Error, RevocationReason, VerifyError};
pub use secrets::{
    DEVICE_ENTRY, MemorySecretStore, OsSecretStore, REFRESH_TOKEN_ENTRY, SERVICE, SecretStore,
    StoreError,
};
pub use status::{
    Diagnostics, ExpiryWarning, LicenceState, Membership, MembershipStatus, SignedIn, Status, User,
    WarningStage,
};

#[cfg(test)]
mod tests;

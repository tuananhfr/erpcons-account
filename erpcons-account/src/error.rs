use std::{fmt, time::Duration};

/// Error kind of a failed API call: PI's `code` (ADR 0011) or the contract error table (§3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiCode {
    InvalidRequest,
    IdempotencyKeyMissing,
    Unauthenticated,
    InsufficientScope,
    MembershipInactive,
    UserSuspended,
    DeviceRevoked,
    DeviceUnknown,
    Forbidden,
    DeviceCapReached,
    InstallationKeyMismatch,
    IdempotencyInProgress,
    ClientVersionUnsupported,
    ValidationFailed,
    ChallengeInvalid,
    IdempotencyKeyReused,
    RateLimited,
    QuotaExceeded,
    DependencyUnavailable,
    OrgContextRequired,
    NoEntitlement,
    NoSeat,
    /// A status outside the contract's set, with the code it carried.
    Other(String),
}

impl ApiCode {
    /// Known code for its status; an unknown or absent code falls back to its HTTP status.
    ///
    /// PI's error envelope `{ok:false, message, code?}` carries UPPERCASE codes (ADR 0011); the
    /// lowercase ones are the retired Office contract's, kept because this function is public.
    pub fn from_parts(status: u16, code: Option<&str>) -> Self {
        let known = match (status, code.unwrap_or("")) {
            (403, "INSUFFICIENT_SCOPE") => Some(Self::InsufficientScope),
            (403, "MEMBERSHIP_INACTIVE") => Some(Self::MembershipInactive),
            (403, "ACCOUNT_LOCKED") => Some(Self::UserSuspended),
            (403, "ORG_CONTEXT_REQUIRED") => Some(Self::OrgContextRequired),
            (403, "NO_ENTITLEMENT") => Some(Self::NoEntitlement),
            (403, "NO_SEAT") => Some(Self::NoSeat),
            (409, "DEVICE_CAP") => Some(Self::DeviceCapReached),
            (409, "DEVICE_REVOKED") => Some(Self::DeviceRevoked),
            (409, "CHALLENGE_INVALID") => Some(Self::ChallengeInvalid),
            (409, "IDEMPOTENCY_MISMATCH") => Some(Self::IdempotencyKeyReused),
            (400, "invalid_request") => Some(Self::InvalidRequest),
            (400, "idempotency_key_missing") => Some(Self::IdempotencyKeyMissing),
            (401, "unauthenticated") => Some(Self::Unauthenticated),
            (403, "insufficient_scope") => Some(Self::InsufficientScope),
            (403, "membership_inactive") => Some(Self::MembershipInactive),
            (403, "user_suspended") => Some(Self::UserSuspended),
            (403, "device_revoked") => Some(Self::DeviceRevoked),
            (403, "device_unknown") => Some(Self::DeviceUnknown),
            (403, "forbidden") => Some(Self::Forbidden),
            (409, "device_cap_reached") => Some(Self::DeviceCapReached),
            (409, "installation_key_mismatch") => Some(Self::InstallationKeyMismatch),
            (409, "idempotency_in_progress") => Some(Self::IdempotencyInProgress),
            (412, "client_version_unsupported") => Some(Self::ClientVersionUnsupported),
            (422, "validation_failed") => Some(Self::ValidationFailed),
            (422, "challenge_invalid") => Some(Self::ChallengeInvalid),
            (422, "idempotency_key_reused") => Some(Self::IdempotencyKeyReused),
            (429, "rate_limited") => Some(Self::RateLimited),
            (429, "quota_exceeded") => Some(Self::QuotaExceeded),
            (503, "dependency_unavailable") => Some(Self::DependencyUnavailable),
            _ => None,
        };
        known.unwrap_or_else(|| match status {
            400 => Self::InvalidRequest,
            401 => Self::Unauthenticated,
            403 => Self::Forbidden,
            412 => Self::ClientVersionUnsupported,
            422 => Self::ValidationFailed,
            429 => Self::RateLimited,
            // PI answers unexpected failures with a bare 500 and has no 503 code: transient.
            500 | 502..=504 => Self::DependencyUnavailable,
            _ => Self::Other(code.unwrap_or_default().into()),
        })
    }
}

/// Failed API call: PI's error envelope, or an RFC 9457 problem of the Office contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub code: ApiCode,
    pub correlation_id: Option<String>,
    pub retry_after: Option<Duration>,
    /// Only with `device_cap_reached`.
    pub max_devices: Option<u64>,
    /// Only with `device_cap_reached`.
    pub active_devices: Option<u64>,
    /// Field names of a 422 `errors` object, sorted; empty otherwise.
    pub errors: Box<[String]>,
}

/// Why a lease, catalog or ID token was rejected (lease.md §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Size, segments, base64url or JSON.
    Format,
    /// Header members, `alg` or `typ`.
    Header,
    UnknownKey,
    Signature,
    /// Missing claim or wrong type.
    Claims,
    Issuer,
    Audience,
    Product,
    Feature,
    Subject,
    Org,
    Installation,
    KeyBinding,
    Device,
    Nonce,
    /// `iat <= nbf < exp` or the 90-day window.
    Validity,
    NotYetValid,
    Expired,
    /// Unsigned response copies differ from the claims.
    CopyMismatch,
    /// Catalog version lower than the cached one.
    Downgrade,
}

/// Reason of the Office contract's `status: revoked` refresh. PI never reports one: it answers
/// 409 `DEVICE_REVOKED` instead (ADR 0012).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationReason {
    DeviceRevoked,
    MembershipRevoked,
    UserSuspended,
}

/// Account error. Messages are for logs, never for the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    NotSignedIn,
    SignInInProgress,
    Cancelled,
    SignInTimedOut,
    /// The caller's browser launcher failed.
    Browser(String),
    /// The callback `state` differs from the request's.
    StateMismatch,
    /// Callback or discovery `issuer` differs from the configured issuer.
    IssuerMismatch,
    /// Authorization endpoint returned an OAuth `error` (for example `access_denied`).
    AuthorizationDenied(String),
    /// Refresh token or code rejected; the local session was cleared.
    InvalidGrant,
    /// Other OAuth error from the token endpoint.
    OAuth(String),
    InvalidIdToken(&'static str),
    Network(String),
    Timeout,
    Api(ApiError),
    BadResponse(String),
    Lease(VerifyError),
    Catalog(VerifyError),
    /// Entitlements for another product or tenant; discarded (products.md §4).
    TenantIsolation,
    /// Lease refresh reported the device revoked. Not produced with PI, which yields
    /// `Api` with [`ApiCode::DeviceRevoked`].
    Revoked(RevocationReason),
    /// Activation is blocked until the next sign-in or a user retry (lease.md §6).
    ActivationBlocked,
    /// No OS credential store: the session is memory-only and the device never activates.
    CredentialStoreUnavailable,
    CredentialStore(String),
    /// `select_org` with an org that is not an active membership.
    UnknownOrg,
    /// PI did not grant the requested organization context; the session holds the context PI
    /// did grant (`SignedIn::active_org`).
    OrgUnavailable,
    Config(String),
    Storage(String),
    Internal(String),
}

impl Error {
    /// Server-requested wait, from `Retry-After`.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Api(e) => e.retry_after,
            _ => None,
        }
    }

    /// Correlation id of the failed exchange, for logs and support.
    pub fn correlation_id(&self) -> Option<&str> {
        match self {
            Self::Api(e) => e.correlation_id.as_deref(),
            _ => None,
        }
    }

    /// The platform could not be reached; state was kept and a later retry may succeed.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Network(_) | Self::Timeout => true,
            Self::Api(e) => matches!(
                e.code,
                ApiCode::RateLimited
                    | ApiCode::DependencyUnavailable
                    | ApiCode::IdempotencyInProgress
            ),
            _ => false,
        }
    }

    pub(crate) fn is_offline(&self) -> bool {
        matches!(self, Self::Network(_) | Self::Timeout)
    }

    pub(crate) fn api_code(&self) -> Option<&ApiCode> {
        match self {
            Self::Api(e) => Some(&e.code),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSignedIn => f.write_str("not signed in"),
            Self::SignInInProgress => f.write_str("sign-in already in progress"),
            Self::Cancelled => f.write_str("sign-in cancelled"),
            Self::SignInTimedOut => f.write_str("sign-in timed out"),
            Self::Browser(e) => write!(f, "could not open the browser: {e}"),
            Self::StateMismatch => f.write_str("authorization response state mismatch"),
            Self::IssuerMismatch => f.write_str("issuer mismatch"),
            Self::AuthorizationDenied(e) => write!(f, "authorization failed: {e}"),
            Self::InvalidGrant => f.write_str("grant rejected; session cleared"),
            Self::OAuth(e) => write!(f, "token endpoint error: {e}"),
            Self::InvalidIdToken(e) => write!(f, "invalid ID token: {e}"),
            Self::Network(e) => write!(f, "network unavailable: {e}"),
            Self::Timeout => f.write_str("network timeout"),
            Self::Api(e) => write!(
                f,
                "HTTP {} {:?} (correlation id {})",
                e.status,
                e.code,
                e.correlation_id.as_deref().unwrap_or("-")
            ),
            Self::BadResponse(e) => write!(f, "invalid response: {e}"),
            Self::Lease(e) => write!(f, "lease rejected: {e:?}"),
            Self::Catalog(e) => write!(f, "feature catalog rejected: {e:?}"),
            Self::TenantIsolation => f.write_str("entitlements for another tenant discarded"),
            Self::Revoked(r) => write!(f, "device lease revoked: {r:?}"),
            Self::ActivationBlocked => f.write_str("activation blocked"),
            Self::CredentialStoreUnavailable => f.write_str("no OS credential store"),
            Self::CredentialStore(e) => write!(f, "credential store error: {e}"),
            Self::UnknownOrg => f.write_str("not an active membership"),
            Self::OrgUnavailable => f.write_str("organization context refused"),
            Self::Config(e) => write!(f, "invalid configuration: {e}"),
            Self::Storage(e) => write!(f, "storage error: {e}"),
            Self::Internal(e) => write!(f, "internal error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Storage(e.to_string())
    }
}

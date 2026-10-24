//! Test data and injected behaviour of the mock.
use std::time::Duration;

use sha2::{Digest, Sha256};

/// `kid` of the development lease key.
pub const DEV_LEASE_KID: &str = "pi-mock-dev-1";
const DEV_SEED_LABEL: &[u8] = b"pi-mock development lease key; never pin in a release build";

/// Deterministic seed of the development lease key, so dev builds and E2E images can pin it.
pub fn dev_lease_seed() -> [u8; 32] {
    Sha256::digest(DEV_SEED_LABEL).into()
}

/// Public half of the development lease key.
pub fn dev_lease_public_key() -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&dev_lease_seed())
        .verifying_key()
        .to_bytes()
}

/// Default user: two active organization memberships.
pub const DEFAULT_USER: &str = "usr_mock_an";
pub const ORG_A: &str = "org_mock_a";
pub const ORG_B: &str = "org_mock_b";

#[derive(Clone, Debug)]
pub struct Scenario {
    pub users: Vec<User>,
    /// User signed in by the auto-approving authorization endpoint.
    pub sign_in_as: String,
    pub authorize: Authorize,
    pub entitlements: Vec<Entitlement>,
    /// Signed catalogs; a product without one gets version 1 with every feature free.
    pub catalogs: Vec<Catalog>,
    /// Device cap per user and organization context.
    pub max_devices: usize,
    /// Fixed platform time (Unix seconds); `None` uses the system clock.
    pub now: Option<i64>,
    pub access_token_ttl: i64,
    pub lease_kid: String,
    pub lease_seed: [u8; 32],
    pub lease_tamper: Option<LeaseTamper>,
    pub policy_version: String,
    /// Minimum `client_version` (`412 client_version_unsupported` below it).
    pub min_client_version: Option<(u64, u64, u64)>,
    /// Exact redirect URIs accepted for `erpcons-office-web`.
    pub web_redirect_uris: Vec<String>,
    pub faults: Vec<Fault>,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            users: vec![User {
                user_id: DEFAULT_USER.into(),
                display_name: "Nguyễn Văn An".into(),
                email: Some("an.nguyen@example.com".into()),
                suspended: false,
                memberships: vec![
                    Membership::new(ORG_A, "Công ty Xây dựng Ví dụ", "member"),
                    Membership::new(ORG_B, "Văn phòng Kiến trúc Mẫu", "license_admin"),
                ],
            }],
            sign_in_as: DEFAULT_USER.into(),
            authorize: Authorize::Approve,
            entitlements: Vec::new(),
            catalogs: Vec::new(),
            max_devices: 3,
            now: None,
            access_token_ttl: 3600,
            lease_kid: DEV_LEASE_KID.into(),
            lease_seed: dev_lease_seed(),
            lease_tamper: None,
            policy_version: "2026-10-01.1".into(),
            min_client_version: None,
            web_redirect_uris: vec!["https://office.erpcons.ai/dang-nhap/callback/".into()],
            faults: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct User {
    pub user_id: String,
    pub display_name: String,
    pub email: Option<String>,
    pub suspended: bool,
    pub memberships: Vec<Membership>,
}

#[derive(Clone, Debug)]
pub struct Membership {
    pub org_id: String,
    pub name: String,
    pub role: String,
    /// `active`, `invited`, `suspended` or `revoked` (revoked ones are omitted from `/v1/me`).
    pub status: String,
}

impl Membership {
    pub fn new(org_id: &str, name: &str, role: &str) -> Self {
        Self {
            org_id: org_id.into(),
            name: name.into(),
            role: role.into(),
            status: "active".into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Entitlement {
    pub entitlement_id: String,
    pub user_id: String,
    /// `None`: a personal entitlement.
    pub org_id: Option<String>,
    pub product_id: String,
    pub feature: String,
    pub offline_allowed: bool,
    pub offline_days: Option<u32>,
    pub valid_from: i64,
    pub valid_to: Option<i64>,
    pub seats: Option<u32>,
}

impl Entitlement {
    /// Offline entitlement (30 days) of `user` for `feature`, in `org` or personal.
    pub fn new(id: &str, user: &str, org: Option<&str>, feature: &str) -> Self {
        Self {
            entitlement_id: id.into(),
            user_id: user.into(),
            org_id: org.map(str::to_owned),
            product_id: feature.split('.').next().unwrap_or_default().into(),
            feature: feature.into(),
            offline_allowed: true,
            offline_days: Some(30),
            valid_from: 0,
            valid_to: None,
            seats: org.map(|_| 50),
        }
    }

    pub fn offline_days(mut self, days: Option<u32>) -> Self {
        self.offline_allowed = days.is_some();
        self.offline_days = days;
        self
    }

    pub fn valid_to(mut self, t: i64) -> Self {
        self.valid_to = Some(t);
        self
    }
}

#[derive(Clone, Debug)]
pub struct Catalog {
    pub product_id: String,
    pub version: u64,
    /// `(feature, tier)`, tier `free` or `pro`.
    pub features: Vec<(String, String)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authorize {
    Approve,
    /// Redirects with `error=access_denied`.
    Deny,
    /// Approves but returns a different `state`.
    WrongState,
}

/// Leases the mock signs wrongly, to exercise client verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseTamper {
    /// Payload changed after signing.
    AlteredPayload,
    UnknownKid,
    /// Signed with another key under the pinned `kid`.
    WrongSigningKey,
    /// `cnf.jkt` of another device key.
    WrongCnf,
    WrongProduct,
    NbfInFuture,
    WrongNonce,
    WrongIssuer,
    /// Response `rights` differ from the lease `features`.
    CopyMismatch,
    /// `exp - iat` above 90 days.
    OverlongWindow,
}

/// A response injected for matching requests before normal handling.
#[derive(Clone, Debug)]
pub struct Fault {
    pub method: String,
    pub path: String,
    /// `None`: every matching request.
    pub times: Option<u32>,
    pub action: FaultAction,
}

#[derive(Clone, Debug)]
pub enum FaultAction {
    /// RFC 9457 problem with `code`.
    Problem {
        status: u16,
        code: String,
        retry_after: Option<u64>,
    },
    /// OAuth error body from the token endpoint.
    OAuthError { status: u16, error: String },
    /// Handle the request normally, then hold the response (client timeouts).
    Delay(Duration),
}

impl Fault {
    pub fn problem(method: &str, path: &str, status: u16, code: &str) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            times: None,
            action: FaultAction::Problem {
                status,
                code: code.into(),
                retry_after: None,
            },
        }
    }

    pub fn delay(method: &str, path: &str, delay: Duration) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            times: None,
            action: FaultAction::Delay(delay),
        }
    }

    pub fn oauth(path: &str, status: u16, error: &str) -> Self {
        Self {
            method: "POST".into(),
            path: path.into(),
            times: None,
            action: FaultAction::OAuthError {
                status,
                error: error.into(),
            },
        }
    }

    pub fn times(mut self, n: u32) -> Self {
        self.times = Some(n);
        self
    }

    pub fn retry_after(mut self, secs: u64) -> Self {
        if let FaultAction::Problem { retry_after, .. } = &mut self.action {
            *retry_after = Some(secs);
        }
        self
    }
}

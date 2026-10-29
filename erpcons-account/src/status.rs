//! Account state reported to the app; no UI text.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Product;

/// Account state of this app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Guest,
    SigningIn,
    SignedIn(Box<SignedIn>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedIn {
    /// `None` until PI's `/me` has answered once on this machine.
    pub user: Option<User>,
    pub orgs: Vec<Membership>,
    /// `orgContext` of PI's `/me`; `None` is the personal context.
    pub active_org: Option<String>,
    /// Licence of this app's product; `NotActivated` while `Config::offline_licensing` is off.
    pub licence: LicenceState,
    /// Licence of each of the four products on this device.
    pub licences: BTreeMap<Product, LicenceState>,
    /// Expiry warning still to show (lease.md §8).
    pub warning: Option<ExpiryWarning>,
    /// The last exchange with the platform succeeded.
    pub online: bool,
    /// No OS credential store: sign-in lasts for this process only and never activates.
    pub session_only: bool,
    /// The platform rejected the session's tokens or scopes; signing in again fixes it.
    pub reauth_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub user_id: String,
    pub display_name: String,
    pub email: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    pub org_id: String,
    pub name: String,
    pub role: String,
    pub status: MembershipStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipStatus {
    Active,
    Invited,
    Suspended,
}

/// Offline licence of one product.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LicenceState {
    NotActivated,
    Active {
        lease_id: String,
        features: Vec<String>,
        expires_at: i64,
    },
    /// Expired or not yet valid at the trusted time; only a refresh replaces it.
    Inactive {
        lease_id: String,
        expires_at: i64,
    },
    /// Device revoked; no activation until the next sign-in. Only a device the user retired
    /// themselves recovers then: PI has no un-revoke, so a staff- or organization-revoked
    /// installation answers 409 again at every sign-in.
    DeviceRevoked,
    /// Device cap reached; activation waits for a user retry.
    DeviceCapReached,
    /// The organization has no plan or seat for this product. No activation until sign-in, an
    /// organization switch, a user retry, or PI's entitlements granting the product again.
    NotEntitled,
    /// No OS credential store: no lease can be kept, so with licensing on `pro` features are
    /// denied; without it they use the online path.
    SessionOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WarningStage {
    Days7,
    Days3,
    Days1,
}

impl WarningStage {
    pub fn days(self) -> u32 {
        match self {
            Self::Days7 => 7,
            Self::Days3 => 3,
            Self::Days1 => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpiryWarning {
    pub stage: WarningStage,
    pub expires_at: i64,
}

/// Non-sensitive diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostics {
    pub credential_store: bool,
    pub clock_rolled_back: bool,
    pub effective_now: i64,
    pub installation_id: Option<String>,
    pub device_id: Option<String>,
}

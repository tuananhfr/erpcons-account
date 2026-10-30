//! Test data and injected behaviour of the mock.
use std::time::Duration;

use sha2::{Digest, Sha256};

/// `kid` of the development lease key that signs PI leases (`/id/lease-keys.json`).
pub const DEV_LEASE_KID: &str = "pi-mock-dev-1";
const DEV_SEED_LABEL: &[u8] = b"pi-mock development lease key; never pin in a release build";

/// `kid` of the development PI ID signing key (access and ID tokens, `/id/jwks.json`).
pub const DEV_SIGNING_KID: &str = "pi-mock-2026-10";
const DEV_SIGNING_LABEL: &[u8] = b"pi-mock PI ID signing key; never trust outside tests";

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

/// Deterministic seed of the development PI ID signing key.
pub fn dev_signing_seed() -> [u8; 32] {
    Sha256::digest(DEV_SIGNING_LABEL).into()
}

/// PI `account_id` of the default user (PI ids are UUIDs).
pub const DEFAULT_USER: &str = "6f3b1c2a-9d4e-4f8a-b1c7-2e5d8a9f0b13";
/// PI `org_id`s of the default user's two organizations; `org_hint` only takes UUIDs.
pub const ORG_A: &str = "0c9e7a51-3b2d-4c6f-8e1a-5d7b9f2c4e60";
pub const ORG_B: &str = "a4d2f6b8-1e3c-4a5b-9c7d-8e0f2a4b6c81";
/// The one-person organization PI creates with the Office free plan ([`Scenario::office_free`]).
pub const ORG_OFFICE: &str = "5b8e1d3f-7a2c-4e9b-a6d0-3f1c8e5b2a74";
/// PI product code of the four Office apps; both Office clients carry it.
pub const OFFICE_PRODUCT: &str = "erpconsoffice";

pub const DESKTOP_CLIENT: &str = "erpcons-office-desktop";
/// UbotCAD's desktop client; same scopes and loopback redirect as the Office one.
pub const UBOTCAD_CLIENT: &str = "ubotcad-desktop";
pub const WEB_CLIENT: &str = "erpcons-office-web";

#[derive(Clone, Debug)]
pub struct Scenario {
    pub users: Vec<User>,
    /// User signed in by the auto-approving login page.
    pub sign_in_as: String,
    pub authorize: Authorize,
    /// What the user picks on PI's organization page: an `org_id`, or `None` for "personal".
    pub org_choice: Option<String>,
    /// PI tenants (organization x product) served by the device protocol under `/api/v1/id/`.
    pub tenants: Vec<Tenant>,
    /// PI's product registry (`ProductRegistry`); other codes are 422 on its device endpoints.
    pub products: Vec<String>,
    /// Fixed platform time (Unix seconds); `None` uses the system clock.
    pub now: Option<i64>,
    /// Access and ID token lifetime; PI: 600 s.
    pub access_token_ttl: i64,
    /// PI ID signing keys: the first signs, all are published (PI rotates by prepending).
    pub signing_keys: Vec<JwtKey>,
    pub lease_kid: String,
    pub lease_seed: [u8; 32],
    pub lease_tamper: Option<LeaseTamper>,
    /// Redirect URIs registered for `erpcons-office-web` (exact match).
    pub web_redirect_uris: Vec<String>,
    /// Registered clients besides the two Office ones, for example another product's.
    pub extra_clients: Vec<Client>,
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
            org_choice: None,
            tenants: Vec::new(),
            products: [
                "erpcons",
                OFFICE_PRODUCT,
                "tekshot",
                "ubotbuild",
                "corporatehealth",
                "digitalhealth",
                "lpcvn",
                "erpconsvn",
                "aloubot",
                "ubotconnect",
                "ubotview",
            ]
            .map(str::to_owned)
            .to_vec(),
            now: None,
            access_token_ttl: 600,
            signing_keys: vec![JwtKey {
                kid: DEV_SIGNING_KID.into(),
                seed: dev_signing_seed(),
            }],
            lease_kid: DEV_LEASE_KID.into(),
            lease_seed: dev_lease_seed(),
            lease_tamper: None,
            web_redirect_uris: vec!["https://office.erpcons.vn/dang-nhap/callback/".into()],
            extra_clients: Vec::new(),
            faults: Vec::new(),
        }
    }
}

/// An Ed25519 key of `$settings['pi_id_signing_keys']`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JwtKey {
    pub kid: String,
    pub seed: [u8; 32],
}

/// A registered PI ID client (`pi_id_client`); every client is public with PKCE S256.
#[derive(Clone, Debug)]
pub struct Client {
    pub client_id: String,
    /// PI product code; when set, access tokens carry it in `aud` next to `pi-platform`.
    pub product: Option<String>,
    /// Exact URIs, except loopback ones where any port matches (RFC 8252 §7.3).
    pub redirect_uris: Vec<String>,
    /// `post_logout_redirect_uri`s accepted by `/id/logout` (exact match).
    pub post_logout_uris: Vec<String>,
    pub scopes: Vec<String>,
}

impl Client {
    pub fn new(client_id: &str, redirect_uris: &[&str], scopes: &str) -> Self {
        Self {
            client_id: client_id.into(),
            product: None,
            redirect_uris: redirect_uris.iter().map(|u| u.to_string()).collect(),
            post_logout_uris: Vec::new(),
            scopes: scopes.split(' ').map(str::to_owned).collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct User {
    /// PI `account_id`, the `sub` of its tokens.
    pub user_id: String,
    pub display_name: String,
    pub email: Option<String>,
    /// PI account status `LOCKED`.
    pub suspended: bool,
    pub memberships: Vec<Membership>,
}

#[derive(Clone, Debug)]
pub struct Membership {
    pub org_id: String,
    pub name: String,
    /// PI role: `org_owner`, `org_admin`, `license_admin`, `member` or `auditor`.
    pub role: String,
    /// PI member status `ACTIVE`, `SUSPENDED` or `REVOKED` (compared ignoring case).
    pub status: String,
}

impl Membership {
    pub fn new(org_id: &str, name: &str, role: &str) -> Self {
        Self {
            org_id: org_id.into(),
            name: name.into(),
            role: role.into(),
            status: "ACTIVE".into(),
        }
    }
}

/// Features of the UbotBuild free plan (`UbotbuildMeta`); `offline` is PI-internal.
pub const FREE_UBOTCAD: [&str; 4] = ["cad-view", "cad-export", "cad-use", "offline"];
/// Features of the Office free plan `office-mien-phi`; `offline` is PI-internal.
pub const FREE_OFFICE: [&str; 4] = ["view", "export", "use", "offline"];

impl Scenario {
    /// A PI ID that signed up through Office: its only organization is the one-person one PI
    /// created with the Office free plan, so sign-in lands in it. The auto-provisioning itself
    /// (PI's first Office sign-in) is not modelled.
    pub fn office_free() -> Self {
        let mut scenario = Self::default();
        for user in &mut scenario.users {
            user.memberships = vec![Membership::new(ORG_OFFICE, &user.display_name, "org_owner")];
        }
        scenario.tenants = vec![Tenant::office_free("ten_office", ORG_OFFICE)];
        scenario
    }
}

/// A PI tenant: an organization's subscription to a product, with its device policy.
#[derive(Clone, Debug)]
pub struct Tenant {
    pub tenant_id: String,
    pub org_id: String,
    pub product_id: String,
    pub features: Vec<String>,
    /// Lease lifetime in days when `features` has `offline`.
    pub offline_days: u32,
    pub device_cap: usize,
    /// Accounts holding a seat. An unlimited plan (`unlimited_seats`) grants one at activation.
    pub seats: Vec<String>,
    /// Plan without a seat cap: `seats` fills as accounts activate (PI `Seats::hasSeat` is false
    /// until then).
    pub unlimited_seats: bool,
    /// End of the subscription (Unix seconds); leases never outlive it.
    pub valid_to: Option<i64>,
    /// `<planCode>@<planVersion>`, the lease `policy_version`.
    pub plan: String,
}

impl Tenant {
    pub fn new(tenant_id: &str, org_id: &str, product_id: &str, features: &[&str]) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            org_id: org_id.into(),
            product_id: product_id.into(),
            features: features.iter().map(|f| f.to_string()).collect(),
            offline_days: 7,
            device_cap: 2,
            seats: Vec::new(),
            unlimited_seats: true,
            valid_to: None,
            plan: "ubb-mien-phi@1".into(),
        }
    }

    /// The Office free plan of `org`: 2 devices, 7-day leases, unlimited seats.
    pub fn office_free(tenant_id: &str, org_id: &str) -> Self {
        Self {
            plan: "office-mien-phi@1".into(),
            ..Self::new(tenant_id, org_id, OFFICE_PRODUCT, &FREE_OFFICE)
        }
    }

    pub fn offline_days(mut self, days: u32) -> Self {
        self.offline_days = days;
        self
    }

    pub fn device_cap(mut self, cap: usize) -> Self {
        self.device_cap = cap;
        self
    }

    pub fn seats(mut self, accounts: &[&str]) -> Self {
        self.seats = accounts.iter().map(|a| a.to_string()).collect();
        self.unlimited_seats = false;
        self
    }

    pub fn valid_to(mut self, t: i64) -> Self {
        self.valid_to = Some(t);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authorize {
    Approve,
    /// Redirects with `error=access_denied` (a test hook; PI's own page has no deny button).
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
    /// `aud` of another client family.
    WrongAudience,
    /// PI lease with an uppercase, invalid feature code.
    BadFeatureCode,
    /// PI lease without `aud`.
    MissingAudience,
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
    /// PI's error envelope `{ok:false, message, code?}`; an empty `code` is left out.
    Problem {
        status: u16,
        code: String,
        retry_after: Option<u64>,
    },
    /// PI's 422 envelope with one rejected request field and no `code`.
    Invalid { field: String },
    /// A plain-text body that is not PI's JSON envelope (proxy or maintenance page).
    Raw { status: u16 },
    /// OAuth error body from the token endpoint.
    OAuthError { status: u16, error: String },
    /// Handle the request normally, then hold the response (client timeouts).
    Delay(Duration),
    /// Handle the request normally, with `Date` this many seconds off (a stale clock offset).
    SkewDate(i64),
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

    pub fn invalid(method: &str, path: &str, field: &str) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            times: None,
            action: FaultAction::Invalid {
                field: field.into(),
            },
        }
    }

    pub fn raw(method: &str, path: &str, status: u16) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            times: None,
            action: FaultAction::Raw { status },
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

    pub fn skew_date(method: &str, path: &str, secs: i64) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            times: None,
            action: FaultAction::SkewDate(secs),
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

//! Mutable platform state: codes, token families, nonces, devices, idempotency records.
use std::collections::{HashMap, HashSet};

use crate::{
    Fault, FaultAction, Scenario,
    scenario::{Client, DESKTOP_CLIENT, Membership, UBOTCAD_CLIENT, User, WEB_CLIENT},
};

/// PI `IdMeta`: authorization code 60 s, refresh token 30 days (sliding).
pub(crate) const AUTH_CODE_TTL: i64 = 60;
pub(crate) const REFRESH_TTL: i64 = 30 * 86_400;

const DESKTOP_SCOPES: &str = "openid profile email offline_access pi.entitlements pi.devices";
const WEB_SCOPES: &str = "openid profile email offline_access";

pub(crate) struct Code {
    pub client_id: String,
    pub redirect_uri: String,
    pub challenge: String,
    pub nonce: String,
    pub user_id: String,
    pub org: Option<String>,
    pub scope: String,
    pub family: u64,
    pub created: i64,
    pub used: bool,
}

/// One refresh token; rotation keeps the family, reuse of a rotated one revokes it.
pub(crate) struct RefreshRecord {
    pub family: u64,
    pub user_id: String,
    pub org: Option<String>,
    pub client_id: String,
    pub scope: String,
    pub expires: i64,
    pub rotated: bool,
}

/// A verified PI access token, as `BearerAccessCheck` leaves it on the request.
#[derive(Clone)]
pub(crate) struct Auth {
    pub user_id: String,
    pub org: Option<String>,
    pub scope: String,
    /// `azp` of the access token.
    pub client_id: String,
}

pub(crate) struct NonceRecord {
    pub user_id: String,
    pub org: Option<String>,
    pub installation_id: String,
    pub product_id: String,
    pub purpose: String,
    pub expires: i64,
    pub used: bool,
}

/// A registered device, one per (`installation_id`, `sub`, `org_context`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    pub device_id: String,
    pub installation_id: String,
    pub user_id: String,
    pub org: Option<String>,
    pub jkt: String,
    /// Client that activated the device; the `aud` of its leases.
    pub client_id: String,
    pub revoked: bool,
    pub products: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceStatus {
    Active,
    Revoked,
}

/// A device of PI's protocol, one per (`installation_id`, `product`, account).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRow {
    pub device_id: String,
    pub installation_id: String,
    pub product: String,
    pub user_id: String,
    pub org: String,
    pub public_key: [u8; 32],
    /// Client that activated the device; the `aud` of its leases.
    pub client_id: String,
    pub status: DeviceStatus,
    pub last_refresh_ts: i64,
}

/// A challenge of `GET /devices/challenge`, bound to (account, product) as in PI.
pub(crate) struct Challenge {
    pub nonce: String,
    pub user_id: String,
    pub product: String,
    pub expires: i64,
    pub used: bool,
}

/// A request as the mock received it (for header and privacy assertions).
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub idempotency_key: Option<String>,
    pub correlation_id: Option<String>,
    pub user_agent: Option<String>,
    pub authorized: bool,
    pub body: String,
}

pub(crate) struct Stored {
    pub status: u16,
    pub body: Vec<u8>,
}

pub(crate) struct Idempotency {
    pub body_hash: [u8; 32],
    pub response: Option<Stored>,
}

pub(crate) struct State {
    pub scenario: Scenario,
    pub faults: Vec<(Fault, u32)>,
    pub codes: HashMap<String, Code>,
    pub refresh: HashMap<String, RefreshRecord>,
    pub revoked_families: HashSet<u64>,
    pub nonces: HashMap<String, NonceRecord>,
    pub devices: Vec<DeviceRecord>,
    pub pi_devices: Vec<DeviceRow>,
    pub challenges: HashMap<String, Challenge>,
    pub idempotency: HashMap<(String, String, String), Idempotency>,
    pub requests: Vec<RecordedRequest>,
    pub counter: u64,
}

impl State {
    pub(crate) fn new(scenario: Scenario) -> Self {
        let faults = scenario.faults.iter().cloned().map(|f| (f, 0)).collect();
        Self {
            scenario,
            faults,
            codes: HashMap::new(),
            refresh: HashMap::new(),
            revoked_families: HashSet::new(),
            nonces: HashMap::new(),
            devices: Vec::new(),
            pi_devices: Vec::new(),
            challenges: HashMap::new(),
            idempotency: HashMap::new(),
            requests: Vec::new(),
            counter: 0,
        }
    }

    pub(crate) fn set_scenario(&mut self, scenario: Scenario) {
        self.faults = scenario.faults.iter().cloned().map(|f| (f, 0)).collect();
        self.scenario = scenario;
    }

    pub(crate) fn now(&self) -> i64 {
        self.scenario.now.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64)
        })
    }

    pub(crate) fn next_id(&mut self, prefix: &str) -> String {
        self.counter += 1;
        format!("{prefix}_{:06}", self.counter)
    }

    pub(crate) fn next_family(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }

    /// The two Office clients of decision 1, UbotCAD's desktop client, then the scenario's extra clients.
    pub(crate) fn clients(&self) -> Vec<Client> {
        let mut web = Client::new(WEB_CLIENT, &[], WEB_SCOPES);
        web.redirect_uris = self.scenario.web_redirect_uris.clone();
        let mut ubotcad = Client::new(
            UBOTCAD_CLIENT,
            &["http://127.0.0.1/callback"],
            DESKTOP_SCOPES,
        );
        ubotcad.product = Some("ubotbuild".into());
        let mut all = vec![
            Client::new(
                DESKTOP_CLIENT,
                &["http://127.0.0.1/callback"],
                DESKTOP_SCOPES,
            ),
            ubotcad,
            web,
        ];
        all.extend(self.scenario.extra_clients.iter().cloned());
        all
    }

    pub(crate) fn client(&self, id: &str) -> Option<Client> {
        self.clients().into_iter().find(|c| c.client_id == id)
    }

    pub(crate) fn user(&self, id: &str) -> Option<&User> {
        self.scenario.users.iter().find(|u| u.user_id == id)
    }

    fn membership(&self, user: &str, org: &str) -> Option<&Membership> {
        self.user(user)?
            .memberships
            .iter()
            .find(|m| m.org_id == org)
    }

    pub(crate) fn membership_active(&self, user: &str, org: &str) -> bool {
        self.membership(user, org)
            .is_some_and(|m| m.status.eq_ignore_ascii_case("ACTIVE"))
    }

    /// Organizations PI offers at sign-in: ACTIVE memberships, by name.
    pub(crate) fn active_orgs(&self, user: &str) -> Vec<String> {
        let mut orgs: Vec<&Membership> = self
            .user(user)
            .map(|u| {
                u.memberships
                    .iter()
                    .filter(|m| m.status.eq_ignore_ascii_case("ACTIVE"))
                    .collect()
            })
            .unwrap_or_default();
        orgs.sort_by(|a, b| a.name.cmp(&b.name));
        orgs.into_iter().map(|m| m.org_id.clone()).collect()
    }

    /// Why PI would not issue tokens (`AuthorizationServer::eligibility`), `None` when it would.
    pub(crate) fn ineligible(&self, user: &str, org: Option<&str>) -> Option<&'static str> {
        if self.user(user).is_none_or(|u| u.suspended) {
            return Some("Tài khoản đã bị khoá.");
        }
        if org.is_some_and(|o| !self.membership_active(user, o)) {
            return Some("Bạn không còn là thành viên hoạt động của tổ chức này.");
        }
        None
    }

    pub(crate) fn revoke_family(&mut self, family: u64) {
        self.revoked_families.insert(family);
    }

    pub(crate) fn take_fault(&mut self, method: &str, path: &str) -> Option<FaultAction> {
        let (fault, used) = self.faults.iter_mut().find(|(f, used)| {
            f.method.eq_ignore_ascii_case(method)
                && f.path == path
                && f.times.is_none_or(|n| *used < n)
        })?;
        *used += 1;
        Some(fault.action.clone())
    }
}

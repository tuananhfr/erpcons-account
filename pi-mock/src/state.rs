//! Mutable platform state: codes, token families, nonces, devices, idempotency records.
use std::collections::{HashMap, HashSet};

use crate::{Fault, FaultAction, Scenario, scenario::User};

pub(crate) struct Code {
    pub client_id: String,
    pub redirect_uri: String,
    pub challenge: String,
    pub nonce: String,
    pub user_id: String,
    pub org: Option<String>,
    pub scope: String,
    pub used: bool,
}

pub(crate) struct RefreshRecord {
    pub family: u64,
    pub user_id: String,
    pub org: Option<String>,
    pub client_id: String,
    pub scope: String,
    pub active: bool,
}

#[derive(Clone)]
pub(crate) struct AccessRecord {
    pub user_id: String,
    pub org: Option<String>,
    pub client_id: String,
    pub scope: String,
    pub exp: i64,
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
    pub revoked: bool,
    pub products: Vec<String>,
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
    pub access: HashMap<String, AccessRecord>,
    pub nonces: HashMap<String, NonceRecord>,
    pub devices: Vec<DeviceRecord>,
    pub idempotency: HashMap<(String, String, String, String), Idempotency>,
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
            access: HashMap::new(),
            nonces: HashMap::new(),
            devices: Vec::new(),
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

    pub(crate) fn user(&self, id: &str) -> Option<&User> {
        self.scenario.users.iter().find(|u| u.user_id == id)
    }

    /// Status of `user`'s membership in `org` (`None` when there is none).
    pub(crate) fn membership_status(&self, user: &str, org: &str) -> Option<String> {
        self.user(user)?
            .memberships
            .iter()
            .find(|m| m.org_id == org)
            .map(|m| m.status.clone())
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

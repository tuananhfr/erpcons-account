//! `Account`: the facade the desktop apps call from a worker thread.
mod auth;
mod licensing;
mod shared;

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::Duration,
};

use crate::{
    Config, Error, Product, SecretStore, StoreError,
    catalog::{self, Catalog, Tier},
    device::Device,
    entitlements::Entitlement,
    http::Http,
    oidc::Discovery,
    secrets::{DEVICE_ENTRY, OsSecretStore},
    status::{Diagnostics, ExpiryWarning, LicenceState, SignedIn, Status, User, WarningStage},
    storage::{self, Paths},
    time::TrustedTime,
};
use shared::{LeaseSlot, SessionFile};

const ENTITLEMENTS_FRESH: Duration = Duration::from_secs(600);
const DAY: i64 = 86_400;

/// PI account of one desktop app, sharing its session with the other three (ADR 0010).
///
/// Every method that talks to the network blocks; call them from a worker thread. `status`,
/// `allowed` and `diagnostics` never block on the network.
pub struct Account {
    cfg: Config,
    store: Arc<dyn SecretStore>,
    persistent: bool,
    paths: Paths,
    http: Http,
    ops: Mutex<Ops>,
    view: RwLock<View>,
    time: Mutex<TrustedTime>,
    signing_in: AtomicBool,
    cancel: AtomicBool,
    refresh_wanted: AtomicBool,
    /// PI's `Date` minus the system clock at the last API reply; refresh timestamps use it.
    server_offset: AtomicI64,
}

/// State touched only by operations, serialized by `Account::ops`.
#[derive(Default)]
struct Ops {
    discovery: Option<Discovery>,
    access: Option<Access>,
    /// Refresh token of a session-only sign-in (no credential store).
    memory_refresh: Option<String>,
    device: Option<Device>,
    lock_held: bool,
    /// `prompt=login` due after a sign-out that `session.json` could not record.
    login_prompt: bool,
}

struct Access {
    token: String,
    expires: Duration,
}

/// What `status` and `allowed` read.
#[derive(Default)]
struct View {
    signed_in: bool,
    session: SessionFile,
    /// The family's one lease, shared by its apps (ADR 0013).
    lease: Option<LeaseSlot>,
    catalog: Option<Catalog>,
    entitlements: Option<(Vec<Entitlement>, Duration)>,
    online: bool,
    reauth: bool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Account {
    /// Opens the shared session. A store answering `Unavailable` makes sign-in session-only.
    pub fn new(config: Config, store: Arc<dyn SecretStore>) -> Result<Self, Error> {
        config.validate()?;
        let dir = config
            .state_dir
            .clone()
            .or_else(|| storage::default_dir(&config.profile))
            .ok_or_else(|| Error::Config("no shared PI directory".into()))?;
        let persistent = match store.get(DEVICE_ENTRY) {
            Err(StoreError::Unavailable(e)) => {
                log::warn!("no OS credential store, sign-in is session-only: {e}");
                false
            }
            _ => true,
        };
        let http = Http::new(config.timeout, &config.user_agent, config.max_retry_wait);
        let mono = config.clock.monotonic();
        let account = Self {
            paths: Paths::new(dir),
            http,
            persistent,
            store,
            ops: Mutex::default(),
            view: RwLock::default(),
            time: Mutex::new(TrustedTime::new(0, mono)),
            signing_in: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            refresh_wanted: AtomicBool::new(false),
            server_offset: AtomicI64::new(0),
            cfg: config,
        };
        // Leftovers are never read again, so a failed delete only costs disk space.
        if let Err(e) = account.remove_legacy_files() {
            log::warn!("0.4.x lease files not removed: {e}");
        }
        {
            let mut ops = lock(&account.ops);
            account.reload_with(&mut ops)?;
            let floor = account.view().session.trusted_floor;
            lock(&account.time).start(floor, account.mono());
        }
        Ok(account)
    }

    /// [`Account::new`] with the OS credential store.
    pub fn with_os_store(config: Config) -> Result<Self, Error> {
        let store = OsSecretStore::for_service(config.profile.keyring_service);
        Self::new(config, Arc::new(store))
    }

    pub fn status(&self) -> Status {
        if self.signing_in.load(Ordering::SeqCst) {
            return Status::SigningIn;
        }
        let view = self.view();
        if !view.signed_in {
            return Status::Guest;
        }
        let now = self.effective_now();
        let s = &view.session;
        let profile = s.profile.as_ref();
        let licence = self.licence(&view, now);
        let licences: BTreeMap<Product, LicenceState> = self
            .cfg
            .profile
            .products
            .iter()
            .map(|&p| (p, licence.clone()))
            .collect();
        Status::SignedIn(Box::new(SignedIn {
            user: s.user_id.as_ref().zip(profile).map(|(id, p)| User {
                user_id: id.clone(),
                display_name: p.display_name.clone(),
                email: p.email.clone(),
            }),
            orgs: profile.map(|p| p.memberships.clone()).unwrap_or_default(),
            active_org: s.org_context.clone(),
            licence,
            licences,
            warning: self.warning(&view, now),
            online: view.online,
            session_only: !self.persistent,
            reauth_required: view.reauth,
        }))
    }

    /// `allowed(feature)` of products.md §4; answers from cached state only.
    ///
    /// With [`Config::offline_licensing`] on, a `pro` feature needs this device: in
    /// `DeviceRevoked`, `DeviceCapReached` and `SessionOnly` the answer is false even while PI's
    /// per-user entitlements still say ALLOW (they do not know about device limits or revocation).
    /// None of those states is recovered by a refresh, so no refresh is requested for them.
    pub fn allowed(&self, feature: &str) -> bool {
        let view = self.view();
        let Some(tier) = catalog::tier(&self.cfg.builtin_features, view.catalog.as_ref(), feature)
        else {
            log::warn!("allowed() called with ungated feature {feature}");
            return false;
        };
        if tier == Tier::Free {
            return true;
        }
        if !view.signed_in {
            return false;
        }
        let now = self.effective_now();
        if self.cfg.offline_licensing
            && matches!(
                self.licence(&view, now),
                LicenceState::DeviceRevoked
                    | LicenceState::DeviceCapReached
                    | LicenceState::SessionOnly
            )
        {
            return false;
        }
        if let Some(slot) = &view.lease
            && slot.lease.window(now).is_ok()
            && slot.lease.features.iter().any(|f| f == feature)
        {
            return true;
        }
        match &view.entitlements {
            Some((list, at)) if self.mono().saturating_sub(*at) <= ENTITLEMENTS_FRESH => {
                list.iter().any(|e| e.feature == feature)
            }
            // Without licensing no refresh can grant a `pro` feature; asking for one would loop.
            _ if !self.cfg.offline_licensing => false,
            _ => {
                self.refresh_wanted.store(true, Ordering::SeqCst);
                false
            }
        }
    }

    /// True once after `allowed` met stale entitlements; the app then runs `refresh` on a worker.
    pub fn take_refresh_request(&self) -> bool {
        self.refresh_wanted.swap(false, Ordering::SeqCst)
    }

    /// Re-reads the shared session without network access, as on window focus (lease.md §11).
    pub fn reload(&self) -> Result<(), Error> {
        let mut ops = lock(&self.ops);
        self.reload_with(&mut ops)?;
        self.persist_floor(&mut ops, false)
    }

    /// Start-up and periodic sync: tokens and identity, plus entitlements and lease when
    /// [`Config::offline_licensing`] is on. Free features never depend on its outcome.
    pub fn refresh(&self) -> Result<(), Error> {
        let mut ops = lock(&self.ops);
        self.reload_with(&mut ops)?;
        let result = self.sync_signed_in(&mut ops);
        let _ = self.persist_floor(&mut ops, false);
        result
    }

    /// Signs out all four apps: revokes the refresh token, wipes session secrets and the lease.
    /// The device key, `installation_id` and `trusted_floor` stay; documents are never touched.
    /// The next sign-in asks PI for `prompt=login`, since PI's browser session outlives this.
    pub fn sign_out(&self) -> Result<(), Error> {
        let mut ops = lock(&self.ops);
        self.wipe(&mut ops, true)
    }

    /// Clears a `device_cap_reached` or not-entitled block and activates again (user action,
    /// lease.md §6). Does nothing while [`Config::offline_licensing`] is off.
    pub fn retry_activation(&self) -> Result<(), Error> {
        if !self.cfg.offline_licensing {
            return Ok(());
        }
        let mut ops = lock(&self.ops);
        self.reload_with(&mut ops)?;
        let product = self.cfg.profile.pi_product;
        self.update_session(&mut ops, |s| {
            s.device_cap_reached = false;
            s.not_entitled.remove(product);
        })?;
        self.activate(&mut ops)
    }

    /// Records that the app showed `stage` for the current lease (at most once per lease_id).
    pub fn mark_warning_shown(&self, stage: WarningStage) -> Result<(), Error> {
        let mut ops = lock(&self.ops);
        self.record_warning(&mut ops, stage)
    }

    pub fn diagnostics(&self) -> Diagnostics {
        let now = self.effective_now();
        let view = self.view();
        Diagnostics {
            credential_store: self.persistent,
            clock_rolled_back: lock(&self.time).rolled_back(),
            effective_now: now,
            installation_id: Some(view.session.installation_id.clone()).filter(|i| !i.is_empty()),
            device_id: view
                .session
                .device_ids
                .get(self.cfg.profile.pi_product)
                .cloned(),
        }
    }

    fn view(&self) -> RwLockReadGuard<'_, View> {
        self.view.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn view_mut(&self) -> RwLockWriteGuard<'_, View> {
        self.view.write().unwrap_or_else(PoisonError::into_inner)
    }

    fn mono(&self) -> Duration {
        self.cfg.clock.monotonic()
    }

    /// `effective_now` of lease.md §7.
    fn effective_now(&self) -> i64 {
        let system = self.cfg.clock.unix_now();
        let mono = self.mono();
        lock(&self.time).now(system, mono)
    }

    fn note(&self, e: &Error) {
        if e.is_offline() {
            self.view_mut().online = false;
        }
    }

    /// The family's licence: every app of it reads the same lease (ADR 0013).
    fn licence(&self, view: &View, now: i64) -> LicenceState {
        if !self.persistent {
            return LicenceState::SessionOnly;
        }
        if view.session.device_revoked {
            return LicenceState::DeviceRevoked;
        }
        match &view.lease {
            Some(slot) if slot.lease.window(now).is_ok() => LicenceState::Active {
                lease_id: slot.lease.lease_id.clone(),
                features: slot.lease.features.clone(),
                expires_at: slot.lease.exp,
            },
            Some(slot) => LicenceState::Inactive {
                lease_id: slot.lease.lease_id.clone(),
                expires_at: slot.lease.exp,
            },
            None if view
                .session
                .not_entitled
                .contains(self.cfg.profile.pi_product) =>
            {
                LicenceState::NotEntitled
            }
            None if view.session.device_cap_reached => LicenceState::DeviceCapReached,
            None => LicenceState::NotActivated,
        }
    }

    /// Warning at 7, 3 and 1 days, only while the lease grants a `pro` feature (lease.md §8).
    fn warning(&self, view: &View, now: i64) -> Option<ExpiryWarning> {
        let slot = view.lease.as_ref()?;
        slot.lease.window(now).ok()?;
        let grants_pro = slot.lease.features.iter().any(|f| {
            catalog::tier(&self.cfg.builtin_features, view.catalog.as_ref(), f) == Some(Tier::Pro)
        });
        if !grants_pro {
            return None;
        }
        let left = slot.lease.exp - now;
        let stage = [
            WarningStage::Days1,
            WarningStage::Days3,
            WarningStage::Days7,
        ]
        .into_iter()
        .find(|s| left <= i64::from(s.days()) * DAY)?;
        (!slot.warnings_shown.contains(&stage.days())).then_some(ExpiryWarning {
            stage,
            expires_at: slot.lease.exp,
        })
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        let mut ops = lock(&self.ops);
        if let Err(e) = self.persist_floor(&mut ops, true) {
            log::warn!("trusted time not persisted on exit: {e}");
        }
    }
}

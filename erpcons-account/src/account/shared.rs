//! Shared desktop session: credential entries, `session.json`, lease files, the lock
//! (lease.md §11, ADR 0010).
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{Account, Ops, lock};
use crate::{
    Error, StoreError, WarningStage,
    catalog::{self},
    device::Device,
    lease::{self, Expect, Lease},
    secrets::{DEVICE_ENTRY, REFRESH_TOKEN_ENTRY},
    status::Membership,
    storage,
};

/// `session.json`. `profile` caches PI's `/me` so an offline start can show the user.
///
/// The single `device_id` of v0.3.0 named a device of the old wire; unknown members are
/// ignored, so it is read and dropped. Maps are keyed by the family's PI product code; keys of
/// another code (0.4.x Office keyed them by app id) are dropped at the next write.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SessionFile {
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub org_context: Option<String>,
    /// PI device id per PI product: PI keys a device by installation, product and account.
    #[serde(default)]
    pub device_ids: BTreeMap<String, String>,
    /// Last refresh `timestamp` sent per PI product; PI rejects one that is not above it.
    #[serde(default)]
    pub last_refresh_ts: BTreeMap<String, i64>,
    /// PI products refused for want of a plan or seat (`LicenceState::NotEntitled`).
    #[serde(default)]
    pub not_entitled: BTreeSet<String>,
    #[serde(default)]
    pub installation_id: String,
    #[serde(default)]
    pub trusted_floor: i64,
    #[serde(default)]
    pub device_revoked: bool,
    #[serde(default)]
    pub device_cap_reached: bool,
    #[serde(default)]
    pub profile: Option<Profile>,
    /// Set by `sign_out`: PI's own browser session outlives it (12 h), so the next sign-in of any
    /// of the four apps asks PI for `prompt=login`.
    #[serde(default)]
    pub login_prompt: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Profile {
    pub display_name: String,
    pub email: Option<String>,
    pub memberships: Vec<Membership>,
}

impl SessionFile {
    /// Sign-out keeps `installation_id` and `trusted_floor` only.
    pub(super) fn clear_identity(&mut self) {
        self.user_id = None;
        self.org_context = None;
        self.device_ids.clear();
        self.last_refresh_ts.clear();
        self.not_entitled.clear();
        self.device_revoked = false;
        self.device_cap_reached = false;
        self.profile = None;
    }
}

/// `lease-<pi_product>.json`.
#[derive(Serialize, Deserialize)]
struct LeaseFile {
    lease: String,
    #[serde(default)]
    warnings_shown: Vec<u32>,
}

#[derive(Clone, Debug)]
pub(super) struct LeaseSlot {
    pub lease: Lease,
    pub warnings_shown: Vec<u32>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Floor {
    /// Store the maximum of the stored and the in-memory floor.
    Max,
    /// Store the in-memory floor after a server correction (lease.md §7).
    Exact,
}

pub(super) fn store_error(e: StoreError) -> Error {
    match e {
        StoreError::Unavailable(_) => Error::CredentialStoreUnavailable,
        StoreError::Failed(e) => Error::CredentialStore(e),
    }
}

impl Account {
    /// Runs `f` under `pi.lock`; nested calls reuse the held lock.
    pub(super) fn locked<T>(
        &self,
        ops: &mut Ops,
        f: impl FnOnce(&mut Ops) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if ops.lock_held {
            return f(ops);
        }
        let guard = self.paths.lock_exclusive()?;
        ops.lock_held = true;
        let result = f(ops);
        ops.lock_held = false;
        drop(guard);
        result
    }

    pub(super) fn refresh_token(&self) -> Result<Option<String>, Error> {
        self.store.get(REFRESH_TOKEN_ENTRY).map_err(store_error)
    }

    /// Re-reads credential entries, `session.json`, leases and catalog (no network).
    pub(super) fn reload_with(&self, ops: &mut Ops) -> Result<(), Error> {
        self.load_catalog_file();
        if !self.persistent {
            return Ok(());
        }
        let refresh_present = self.refresh_token()?.is_some();
        ops.device = self
            .store
            .get(DEVICE_ENTRY)
            .map_err(store_error)?
            .and_then(|s| Device::from_entry(&s));
        let session = self.read_session_disk(ops).unwrap_or_default();
        lock(&self.time).merge(session.trusted_floor);
        {
            let mut view = self.view_mut();
            let identity_changed = view.session.user_id != session.user_id
                || view.session.org_context != session.org_context;
            if identity_changed || !refresh_present {
                // A missing token means another app signed out; a new identity invalidates tokens.
                ops.access = None;
                view.entitlements = None;
            }
            if !refresh_present {
                view.reauth = false;
            }
            view.signed_in = refresh_present;
            view.session = session;
        }
        self.load_lease(ops)
    }

    pub(super) fn read_session_disk(&self, ops: &Ops) -> Option<SessionFile> {
        let device = ops.device.as_ref()?;
        let bytes = storage::read(&self.paths.session()).ok()??;
        let Some(body) = storage::unseal(&bytes, &device.verifying_key()) else {
            log::warn!("session.json signature invalid; ignored");
            return None;
        };
        serde_json::from_slice(body).ok()
    }

    /// Writes `session.json` (caller holds the lock) and makes it the in-memory session.
    pub(super) fn write_session(
        &self,
        ops: &mut Ops,
        s: &mut SessionFile,
        floor: Floor,
    ) -> Result<(), Error> {
        let device = ops
            .device
            .as_ref()
            .ok_or(Error::CredentialStoreUnavailable)?;
        {
            let mut time = lock(&self.time);
            s.trusted_floor = match floor {
                Floor::Max => time.floor().max(s.trusted_floor),
                Floor::Exact => time.floor(),
            };
            time.merge(s.trusted_floor);
            time.mark_persisted(self.mono());
        }
        s.installation_id = device.installation_id.clone();
        let own = self.cfg.profile.pi_product;
        s.device_ids.retain(|k, _| k == own);
        s.last_refresh_ts.retain(|k, _| k == own);
        s.not_entitled.retain(|k| k == own);
        let body = serde_json::to_vec(s).map_err(|e| Error::Internal(e.to_string()))?;
        storage::write_atomic(
            &self.paths.session(),
            &storage::seal(&body, device.signing_key()),
        )?;
        self.view_mut().session = s.clone();
        Ok(())
    }

    /// Read-modify-write of `session.json` under the lock.
    pub(super) fn update_session(
        &self,
        ops: &mut Ops,
        f: impl FnOnce(&mut SessionFile),
    ) -> Result<(), Error> {
        if !self.persistent {
            f(&mut self.view_mut().session);
            return Ok(());
        }
        self.locked(ops, |ops| {
            let mut s = self.read_session_disk(ops).unwrap_or_default();
            f(&mut s);
            self.write_session(ops, &mut s, Floor::Max)
        })
    }

    /// Device entry, created at the first need (lease.md §3). Caller holds the lock.
    pub(super) fn ensure_device(&self, ops: &mut Ops) -> Result<Device, Error> {
        if !self.persistent {
            return Err(Error::CredentialStoreUnavailable);
        }
        if let Some(d) = self
            .store
            .get(DEVICE_ENTRY)
            .map_err(store_error)?
            .and_then(|s| Device::from_entry(&s))
        {
            ops.device = Some(d.clone());
            return Ok(d);
        }
        self.replace_device(ops)
    }

    /// New key pair and `installation_id`; the session keeps nothing bound to the old key.
    pub(super) fn replace_device(&self, ops: &mut Ops) -> Result<Device, Error> {
        let device = Device::generate()?;
        let mut s = self.read_session_disk(ops).unwrap_or_default();
        self.store
            .set(DEVICE_ENTRY, &device.to_entry())
            .map_err(store_error)?;
        ops.device = Some(device.clone());
        if !s.device_ids.is_empty() {
            s.device_ids.clear();
            s.last_refresh_ts.clear();
            self.remove_lease()?;
        }
        self.write_session(ops, &mut s, Floor::Max)?;
        Ok(device)
    }

    /// Deletes the family's lease, which every app of it shares.
    pub(super) fn remove_lease(&self) -> Result<(), Error> {
        storage::remove(&self.paths.lease(self.cfg.profile.pi_product))?;
        self.view_mut().lease = None;
        Ok(())
    }

    /// Deletes the per-app lease and catalog files of 0.4.x, named by app id. UbotCAD's app id is
    /// its PI product code, so its files are kept.
    pub(super) fn remove_legacy_files(&self) -> Result<(), Error> {
        let own = self.cfg.profile.pi_product;
        for p in self.cfg.profile.products.iter().filter(|p| p.id() != own) {
            storage::remove(&self.paths.lease(p.id()))?;
            storage::remove(&self.paths.catalog(p.id()))?;
        }
        Ok(())
    }

    pub(super) fn write_lease(
        &self,
        device: &Device,
        jws: &str,
        warnings_shown: Vec<u32>,
    ) -> Result<(), Error> {
        let file = LeaseFile {
            lease: jws.to_owned(),
            warnings_shown,
        };
        let body = serde_json::to_vec(&file).map_err(|e| Error::Internal(e.to_string()))?;
        storage::write_atomic(
            &self.paths.lease(self.cfg.profile.pi_product),
            &storage::seal(&body, device.signing_key()),
        )
    }

    fn read_lease(
        &self,
        ops: &Ops,
        s: &SessionFile,
    ) -> Result<Option<Result<LeaseSlot, ()>>, Error> {
        let p = self.cfg.profile.pi_product;
        let Some(bytes) = storage::read(&self.paths.lease(p))? else {
            return Ok(None);
        };
        let (Some(device), Some(sub)) = (ops.device.as_ref(), s.user_id.as_deref()) else {
            return Ok(None);
        };
        // No device id for the product: the lease names a device this session does not know.
        let Some(device_id) = s.device_ids.get(p) else {
            log::warn!("lease for {p} has no device id in the session");
            return Ok(Some(Err(())));
        };
        let jkt = device.thumbprint();
        let expect = Expect {
            issuer: &self.cfg.issuer,
            audience: &self.cfg.client_id,
            product: p,
            sub,
            org: s.org_context.as_deref(),
            jkt: &jkt,
            device_id,
            nonce: None,
        };
        let slot = storage::unseal(&bytes, &device.verifying_key())
            .and_then(|body| serde_json::from_slice::<LeaseFile>(body).ok())
            .ok_or(())
            .and_then(|f| {
                lease::verify(&f.lease, &self.cfg.platform_keys, &expect)
                    .map(|lease| LeaseSlot {
                        lease,
                        warnings_shown: f.warnings_shown,
                    })
                    .map_err(|e| log::warn!("lease for {p} rejected on load: {e:?}"))
            });
        Ok(Some(slot))
    }

    /// Loads the family's lease file (lease.md §9 on load) and deletes it when invalid.
    pub(super) fn load_lease(&self, ops: &mut Ops) -> Result<(), Error> {
        let session = self.view().session.clone();
        let (slot, invalid) = match self.read_lease(ops, &session)? {
            Some(Ok(slot)) => (Some(slot), false),
            Some(Err(())) => (None, true),
            None => (None, false),
        };
        self.view_mut().lease = slot;
        if invalid {
            self.locked(ops, |ops| {
                // Another app may have written a valid lease, and its device id, since the
                // first read; judge it against the session on disk.
                let current = self.read_session_disk(ops).unwrap_or(session);
                if let Some(Err(())) = self.read_lease(ops, &current)? {
                    storage::remove(&self.paths.lease(self.cfg.profile.pi_product))?;
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Re-verifies `catalog-<pi_product>.jws` with the platform key (products.md §3).
    pub(super) fn load_catalog_file(&self) {
        let product = self.cfg.profile.pi_product;
        let Ok(Some(bytes)) = storage::read(&self.paths.catalog(product)) else {
            return;
        };
        let Ok(jws) = String::from_utf8(bytes) else {
            return;
        };
        let current = self.view().catalog.as_ref().map_or(0, |c| c.version);
        match catalog::verify(
            jws.trim(),
            &self.cfg.platform_keys,
            &self.cfg.issuer,
            product,
            current,
        ) {
            Ok(c) => self.view_mut().catalog = Some(c),
            Err(crate::VerifyError::Downgrade) => {}
            Err(e) => log::warn!("cached feature catalog rejected: {e:?}"),
        }
    }

    /// Local sign-out of all four apps; `revoke` (user sign-out) also calls the revocation
    /// endpoint (RFC 7009) and makes the next sign-in send `prompt=login`.
    pub(super) fn wipe(&self, ops: &mut Ops, revoke: bool) -> Result<(), Error> {
        ops.access = None;
        ops.login_prompt |= revoke;
        let result = if self.persistent {
            self.locked(ops, |ops| {
                let token = self.refresh_token().ok().flatten();
                if revoke && let Some(t) = token {
                    self.try_revoke(ops, &t);
                }
                self.store
                    .delete(REFRESH_TOKEN_ENTRY)
                    .map_err(store_error)?;
                self.remove_lease()?;
                ops.device = self
                    .store
                    .get(DEVICE_ENTRY)
                    .ok()
                    .flatten()
                    .and_then(|s| Device::from_entry(&s));
                if ops.device.is_some() {
                    let mut s = self.read_session_disk(ops).unwrap_or_default();
                    s.clear_identity();
                    s.login_prompt |= revoke;
                    self.write_session(ops, &mut s, Floor::Max)?;
                }
                Ok(())
            })
        } else {
            if let Some(t) = ops.memory_refresh.take()
                && revoke
            {
                self.try_revoke(ops, &t);
            }
            Ok(())
        };
        let mut view = self.view_mut();
        view.signed_in = false;
        view.lease = None;
        view.entitlements = None;
        view.reauth = false;
        view.session.clear_identity();
        result
    }

    pub(super) fn try_revoke(&self, ops: &mut Ops, token: &str) {
        let outcome = self
            .discovery(ops)
            .and_then(|d| crate::oidc::revoke(&self.http, &d, &self.cfg.client_id, token));
        if let Err(e) = outcome {
            log::warn!("refresh token revocation failed; local session cleared anyway: {e}");
        }
    }

    /// Persists `trusted_floor` at most every 10 min, or now with `force` (lease.md §7).
    pub(super) fn persist_floor(&self, ops: &mut Ops, force: bool) -> Result<(), Error> {
        if !self.persistent || ops.device.is_none() {
            return Ok(());
        }
        self.effective_now();
        if !force && !lock(&self.time).persist_due(self.mono()) {
            return Ok(());
        }
        self.locked(ops, |ops| {
            let Some(mut s) = self.read_session_disk(ops) else {
                return Ok(());
            };
            let changed = {
                let v = self.view();
                v.session.user_id != s.user_id || v.session.org_context != s.org_context
            };
            self.write_session(ops, &mut s, Floor::Max)?;
            if changed && !force {
                self.load_lease(ops)?;
            }
            Ok(())
        })
    }

    pub(super) fn record_warning(&self, ops: &mut Ops, stage: WarningStage) -> Result<(), Error> {
        if !self.persistent {
            return Ok(());
        }
        self.locked(ops, |ops| {
            self.reload_with(ops)?;
            let Some(mut slot) = self.view().lease.clone() else {
                return Ok(());
            };
            let device = ops
                .device
                .clone()
                .ok_or(Error::CredentialStoreUnavailable)?;
            if !slot.warnings_shown.contains(&stage.days()) {
                slot.warnings_shown.push(stage.days());
            }
            self.write_lease(&device, &slot.lease.jws, slot.warnings_shown)?;
            self.load_lease(ops)
        })
    }
}

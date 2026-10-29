//! Shared desktop session: credential entries, `session.json`, lease files, the lock
//! (lease.md §11, ADR 0010).
use serde::{Deserialize, Serialize};

use super::{Account, Ops, lock};
use crate::{
    Error, Product, StoreError, WarningStage,
    catalog::{self},
    device::Device,
    lease::{self, Expect, Lease},
    secrets::{DEVICE_ENTRY, REFRESH_TOKEN_ENTRY},
    status::Membership,
    storage,
};

/// `session.json`. `profile` caches PI's `/me` so an offline start can show the user.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SessionFile {
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub org_context: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
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
        self.device_id = None;
        self.device_revoked = false;
        self.device_cap_reached = false;
        self.profile = None;
    }
}

/// `lease-<product_id>.json`.
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
        self.load_leases(ops)
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
        if s.device_id.take().is_some() {
            self.remove_leases(None)?;
        }
        self.write_session(ops, &mut s, Floor::Max)?;
        Ok(device)
    }

    /// Deletes every lease file except `keep`'s.
    pub(super) fn remove_leases(&self, keep: Option<Product>) -> Result<(), Error> {
        for &p in self
            .cfg
            .profile
            .products
            .iter()
            .filter(|p| Some(**p) != keep)
        {
            storage::remove(&self.paths.lease(p))?;
        }
        let mut view = self.view_mut();
        view.leases.retain(|p, _| Some(*p) == keep);
        Ok(())
    }

    pub(super) fn write_lease(
        &self,
        device: &Device,
        product: Product,
        jws: &str,
        warnings_shown: Vec<u32>,
    ) -> Result<(), Error> {
        let file = LeaseFile {
            lease: jws.to_owned(),
            warnings_shown,
        };
        let body = serde_json::to_vec(&file).map_err(|e| Error::Internal(e.to_string()))?;
        storage::write_atomic(
            &self.paths.lease(product),
            &storage::seal(&body, device.signing_key()),
        )
    }

    fn read_lease(&self, ops: &Ops, p: Product) -> Result<Option<Result<LeaseSlot, ()>>, Error> {
        let Some(bytes) = storage::read(&self.paths.lease(p))? else {
            return Ok(None);
        };
        let view = self.view();
        let s = &view.session;
        let (Some(device), Some(sub), Some(device_id)) = (
            ops.device.as_ref(),
            s.user_id.as_deref(),
            s.device_id.as_deref(),
        ) else {
            return Ok(None);
        };
        let jkt = device.thumbprint();
        let expect = Expect {
            issuer: &self.cfg.issuer,
            audience: &self.cfg.client_id,
            product: p,
            sub,
            org: s.org_context.as_deref(),
            installation_id: &device.installation_id,
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
                    .map_err(|e| log::warn!("lease for {} rejected on load: {e:?}", p.id()))
            });
        Ok(Some(slot))
    }

    /// Loads the lease file of every product of this client family (lease.md §9 on load). Only this app's invalid lease is deleted.
    pub(super) fn load_leases(&self, ops: &mut Ops) -> Result<(), Error> {
        let mut leases = std::collections::BTreeMap::new();
        let mut invalid_own = false;
        for &p in self.cfg.profile.products {
            match self.read_lease(ops, p)? {
                Some(Ok(slot)) => {
                    leases.insert(p, slot);
                }
                Some(Err(())) => invalid_own |= p == self.cfg.product,
                None => {}
            }
        }
        self.view_mut().leases = leases;
        if invalid_own {
            let own = self.cfg.product;
            self.locked(ops, |ops| {
                // Another app may have written a valid lease since the first read.
                if let Some(Err(())) = self.read_lease(ops, own)? {
                    storage::remove(&self.paths.lease(own))?;
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Re-verifies `catalog-<product>.jws` with the platform key (products.md §3).
    pub(super) fn load_catalog_file(&self) {
        let Ok(Some(bytes)) = storage::read(&self.paths.catalog(self.cfg.product)) else {
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
            self.cfg.product,
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
                self.remove_leases(None)?;
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
        view.leases.clear();
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
                self.load_leases(ops)?;
            }
            Ok(())
        })
    }

    pub(super) fn record_warning(&self, ops: &mut Ops, stage: WarningStage) -> Result<(), Error> {
        if !self.persistent {
            return Ok(());
        }
        let product = self.cfg.product;
        self.locked(ops, |ops| {
            self.reload_with(ops)?;
            let Some(mut slot) = self.view().leases.get(&product).cloned() else {
                return Ok(());
            };
            let device = ops
                .device
                .clone()
                .ok_or(Error::CredentialStoreUnavailable)?;
            if !slot.warnings_shown.contains(&stage.days()) {
                slot.warnings_shown.push(stage.days());
            }
            self.write_lease(&device, product, &slot.lease.jws, slot.warnings_shown)?;
            self.load_leases(ops)
        })
    }
}

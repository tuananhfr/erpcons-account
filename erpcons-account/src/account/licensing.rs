//! Device activation, lease refresh and revocation (lease.md §3, §6, §8, §9).
use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::json;

use super::{Account, Ops, lock, shared::Floor};
use crate::{
    ApiCode, Error, RevocationReason,
    device::{Device, ProofClaims},
    jose::MAX_JWS,
    lease::{self, Copies, Expect},
};

const LEASE_REFRESH_EVERY: i64 = 12 * 3600;

#[derive(Deserialize)]
struct LeaseResponse {
    device_id: String,
    entitlement_ids: Vec<String>,
    rights: Vec<String>,
    offline_valid_until: String,
    policy_version: String,
    lease: String,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RefreshResponse {
    Active(LeaseResponse),
    Revoked { reason: String },
}

#[derive(Deserialize)]
struct Challenge {
    nonce: String,
}

impl Account {
    /// Activates or refreshes this app's lease when lease.md §6 says so.
    pub(super) fn sync_licence(&self, ops: &mut Ops) -> Result<(), Error> {
        if !self.persistent {
            return Ok(());
        }
        let now = self.effective_now();
        let (ready, activated, due) = {
            let view = self.view();
            let s = &view.session;
            let ready =
                view.signed_in && s.user_id.is_some() && !s.device_revoked && !s.device_cap_reached;
            let due = view.leases.get(&self.cfg.product).map(|slot| {
                now - slot.lease.iat >= LEASE_REFRESH_EVERY
                    || slot.lease.window(now).is_err()
                    || view.entitlements.as_ref().is_some_and(|(list, _)| {
                        let granted: BTreeSet<&str> = list
                            .iter()
                            .filter(|e| e.offline_allowed)
                            .map(|e| e.feature.as_str())
                            .collect();
                        granted != slot.lease.features.iter().map(String::as_str).collect()
                    })
            });
            (ready, s.device_id.is_some(), due)
        };
        match (ready, activated, due) {
            (false, _, _) => Ok(()),
            (true, true, Some(false)) => Ok(()),
            (true, true, Some(true)) => self.refresh_lease(ops),
            _ => self.activate(ops),
        }
    }

    /// `POST /v1/devices/activate` for this product, under the shared lock.
    pub(super) fn activate(&self, ops: &mut Ops) -> Result<(), Error> {
        if !self.persistent {
            return Err(Error::CredentialStoreUnavailable);
        }
        self.locked(ops, |ops| {
            self.reload_with(ops)?;
            {
                let view = self.view();
                let s = &view.session;
                if !view.signed_in || s.user_id.is_none() {
                    return Err(Error::NotSignedIn);
                }
                if s.device_revoked || s.device_cap_reached {
                    return Err(Error::ActivationBlocked);
                }
                let now = self.effective_now();
                // Another app may have activated this product while we waited for the lock.
                if view
                    .leases
                    .get(&self.cfg.product)
                    .is_some_and(|l| l.lease.window(now).is_ok())
                {
                    return Ok(());
                }
            }
            let (mut new_challenge, mut new_key) = (true, true);
            loop {
                let error = match self.activate_once(ops) {
                    Ok(()) => return Ok(()),
                    Err(e) => e,
                };
                match error.api_code() {
                    Some(ApiCode::ChallengeInvalid) if std::mem::take(&mut new_challenge) => {}
                    Some(ApiCode::InstallationKeyMismatch) if std::mem::take(&mut new_key) => {
                        self.replace_device(ops)?;
                    }
                    _ => {
                        self.on_device_error(ops, &error)?;
                        return Err(error);
                    }
                }
            }
        })
    }

    fn activate_once(&self, ops: &mut Ops) -> Result<(), Error> {
        let device = self.ensure_device(ops)?;
        let nonce = self.challenge(ops, "activate", &device)?;
        let proof = self.proof(&device, &nonce, "activate", None)?;
        let reply = self.api_post(
            ops,
            "/v1/devices/activate",
            &json!({
                "installation_id": device.installation_id,
                "product_id": self.cfg.product.id(),
                "platform": self.cfg.platform.id(),
                "client_version": self.cfg.client_version,
                "signed_challenge": proof,
            }),
        )?;
        let response: LeaseResponse = reply.json()?;
        self.accept_lease(ops, &device, &response, &nonce)
    }

    /// `POST /v1/licenses/refresh` for this product, under the shared lock.
    pub(super) fn refresh_lease(&self, ops: &mut Ops) -> Result<(), Error> {
        self.locked(ops, |ops| {
            self.reload_with(ops)?;
            if self.view().session.device_id.is_none() {
                return self.activate(ops);
            }
            let (mut new_challenge, mut reactivate) = (true, true);
            loop {
                let error = match self.refresh_once(ops) {
                    Ok(()) => return Ok(()),
                    Err(e) => e,
                };
                match error.api_code() {
                    Some(ApiCode::ChallengeInvalid) if std::mem::take(&mut new_challenge) => {}
                    Some(ApiCode::DeviceUnknown) if std::mem::take(&mut reactivate) => {
                        self.on_device_error(ops, &error)?;
                        return self.activate(ops);
                    }
                    _ => {
                        self.on_device_error(ops, &error)?;
                        return Err(error);
                    }
                }
            }
        })
    }

    fn refresh_once(&self, ops: &mut Ops) -> Result<(), Error> {
        let device = self.ensure_device(ops)?;
        let device_id = self
            .view()
            .session
            .device_id
            .clone()
            .ok_or(Error::ActivationBlocked)?;
        let nonce = self.challenge(ops, "refresh", &device)?;
        let proof = self.proof(&device, &nonce, "refresh", Some(&device_id))?;
        let reply = self.api_post(
            ops,
            "/v1/licenses/refresh",
            &json!({
                "device_id": device_id,
                "installation_id": device.installation_id,
                "product_id": self.cfg.product.id(),
                "platform": self.cfg.platform.id(),
                "client_version": self.cfg.client_version,
                "signed_challenge": proof,
            }),
        )?;
        match reply.json::<RefreshResponse>()? {
            RefreshResponse::Active(response) => self.accept_lease(ops, &device, &response, &nonce),
            RefreshResponse::Revoked { reason } => self.revoked(ops, &reason),
        }
    }

    fn challenge(&self, ops: &mut Ops, purpose: &str, device: &Device) -> Result<String, Error> {
        let reply = self.api_post(
            ops,
            "/v1/devices/challenges",
            &json!({
                "purpose": purpose,
                "installation_id": device.installation_id,
                "product_id": self.cfg.product.id(),
            }),
        )?;
        let c: Challenge = reply.json()?;
        let well_formed = c.nonce.len() == 43
            && c.nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !well_formed {
            return Err(Error::BadResponse("challenge nonce".into()));
        }
        Ok(c.nonce)
    }

    fn proof(
        &self,
        device: &Device,
        nonce: &str,
        purpose: &str,
        device_id: Option<&str>,
    ) -> Result<String, Error> {
        device.proof(&ProofClaims {
            nonce,
            purpose,
            device_id,
            installation_id: &device.installation_id,
            product_id: self.cfg.product.id(),
            platform: self.cfg.platform.id(),
            client_version: &self.cfg.client_version,
            iat: self.cfg.clock.unix_now(),
        })
    }

    /// lease.md §9 on receipt; any failure leaves the previous lease in place.
    fn accept_lease(
        &self,
        ops: &mut Ops,
        device: &Device,
        r: &LeaseResponse,
        nonce: &str,
    ) -> Result<(), Error> {
        if r.lease.len() > MAX_JWS {
            return Err(Error::Lease(crate::VerifyError::Format));
        }
        let session = self.view().session.clone();
        let sub = session.user_id.as_deref().ok_or(Error::NotSignedIn)?;
        let jkt = device.thumbprint();
        let expect = Expect {
            issuer: &self.cfg.issuer,
            audience: &self.cfg.client_id,
            product: self.cfg.product,
            sub,
            org: session.org_context.as_deref(),
            installation_id: &device.installation_id,
            jkt: &jkt,
            device_id: &r.device_id,
            nonce: Some(nonce),
        };
        let lease = lease::verify(&r.lease, &self.cfg.platform_keys, &expect)
            .map_err(|e| self.rejected(e))?;
        let (corrected, now) = {
            let mono = self.mono();
            let mut time = lock(&self.time);
            let corrected = time.correct(lease.iat, mono);
            (corrected, time.now(self.cfg.clock.unix_now(), mono))
        };
        lease.window(now).map_err(|e| self.rejected(e))?;
        lease
            .check_copies(&Copies {
                entitlement_ids: &r.entitlement_ids,
                rights: &r.rights,
                offline_valid_until: &r.offline_valid_until,
                policy_version: &r.policy_version,
            })
            .map_err(|e| self.rejected(e))?;
        let mut s = self.read_session_disk(ops).unwrap_or(session);
        if s.device_id.as_deref() != Some(r.device_id.as_str()) {
            if s.device_id.is_some() {
                // Step 9: the stored device id is stale, and so are leases naming it.
                self.remove_leases(Some(self.cfg.product))?;
            }
            s.device_id = Some(r.device_id.clone());
        }
        s.device_cap_reached = false;
        self.write_lease(device, self.cfg.product, &r.lease, Vec::new())?;
        let floor = if corrected { Floor::Exact } else { Floor::Max };
        self.write_session(ops, &mut s, floor)?;
        self.load_leases(ops)
    }

    fn rejected(&self, e: crate::VerifyError) -> Error {
        log::warn!("lease rejected on receipt: {e:?}; previous lease kept");
        Error::Lease(e)
    }

    /// `status: revoked` concerns the device: every lease goes, then per reason (lease.md §8).
    fn revoked(&self, ops: &mut Ops, reason: &str) -> Result<(), Error> {
        let reason = match reason {
            "membership_revoked" => RevocationReason::MembershipRevoked,
            "user_suspended" => RevocationReason::UserSuspended,
            _ => RevocationReason::DeviceRevoked,
        };
        log::warn!("lease refresh reported revocation: {reason:?}");
        self.remove_leases(None)?;
        match reason {
            RevocationReason::DeviceRevoked => self.update_session(ops, |s| {
                s.device_id = None;
                s.device_revoked = true;
            })?,
            RevocationReason::MembershipRevoked => {
                self.rotate(ops, Some("personal"), true)?;
                self.fetch_me(ops)?;
                if let Err(e) = self.activate(ops) {
                    log::warn!("activation in the personal context failed: {e}");
                }
            }
            RevocationReason::UserSuspended => self.wipe(ops, false)?,
        }
        Err(Error::Revoked(reason))
    }

    /// Device-specific actions of the contract error table.
    fn on_device_error(&self, ops: &mut Ops, error: &Error) -> Result<(), Error> {
        match error.api_code() {
            Some(ApiCode::DeviceCapReached) => {
                self.update_session(ops, |s| s.device_cap_reached = true)
            }
            Some(ApiCode::DeviceRevoked) => {
                self.remove_leases(None)?;
                self.update_session(ops, |s| {
                    s.device_id = None;
                    s.device_revoked = true;
                })
            }
            Some(ApiCode::DeviceUnknown) => {
                self.remove_leases(None)?;
                self.update_session(ops, |s| s.device_id = None)
            }
            _ => Ok(()),
        }
    }
}

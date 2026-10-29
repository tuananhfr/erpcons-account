//! Device activation, lease refresh and revocation (lease.md §3, §6, §8, §9) in PI's device
//! protocol (ADR 0012), all behind `Config::offline_licensing`.
use std::{collections::BTreeSet, sync::atomic::Ordering};

use serde::Deserialize;
use serde_json::json;

use super::{Account, Ops, lock, shared::Floor};
use crate::{
    ApiCode, Error, VerifyError,
    device::Device,
    http::{Body, Retry, query_escape},
    jose::MAX_JWS,
    lease::{self, Copies, Expect},
    pi_device::{activate_message, is_nonce, refresh_message},
    random,
};

const LEASE_REFRESH_EVERY: i64 = 12 * 3600;

/// Activation (201) and refresh (200) answer; only activation carries `entitlementId`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LeaseResponse {
    device_id: String,
    #[serde(default)]
    entitlement_id: Option<String>,
    rights: Vec<String>,
    offline_valid_until: String,
    policy_version: String,
    lease_id: String,
    lease: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Challenge {
    challenge_id: String,
    nonce: String,
}

impl Account {
    /// Activates or refreshes this app's lease when lease.md §6 says so.
    pub(super) fn sync_licence(&self, ops: &mut Ops) -> Result<(), Error> {
        if !self.persistent || !self.cfg.offline_licensing {
            return Ok(());
        }
        let product = self.cfg.product.id();
        let now = self.effective_now();
        let (ready, activated, due, lift) = {
            let view = self.view();
            let s = &view.session;
            // An ALLOW row with a seat means PI would now answer an activation.
            let granted = view
                .entitlements
                .as_ref()
                .is_some_and(|(list, _)| !list.is_empty());
            let refused = s.not_entitled.contains(product);
            let ready = view.signed_in
                && s.user_id.is_some()
                && s.org_context.is_some()
                && !s.device_revoked
                && !s.device_cap_reached
                && (!refused || granted);
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
            (
                ready,
                s.device_ids.contains_key(product),
                due,
                ready && refused,
            )
        };
        if lift {
            self.update_session(ops, |s| {
                s.not_entitled.remove(product);
            })?;
        }
        match (ready, activated, due) {
            (false, _, _) => Ok(()),
            (true, true, Some(false)) => Ok(()),
            (true, true, Some(true)) => self.refresh_lease(ops),
            _ => self.activate(ops),
        }
    }

    /// Challenge, then `POST /devices/activate` for this product, under the shared lock.
    pub(super) fn activate(&self, ops: &mut Ops) -> Result<(), Error> {
        if !self.cfg.offline_licensing {
            return Ok(());
        }
        if !self.persistent {
            return Err(Error::CredentialStoreUnavailable);
        }
        let product = self.cfg.product;
        self.locked(ops, |ops| {
            self.reload_with(ops)?;
            {
                let view = self.view();
                let s = &view.session;
                if !view.signed_in || s.user_id.is_none() {
                    return Err(Error::NotSignedIn);
                }
                // PI leases a product to an organization only (`ORG_CONTEXT_REQUIRED`).
                if s.org_context.is_none()
                    || s.device_revoked
                    || s.device_cap_reached
                    || s.not_entitled.contains(product.id())
                {
                    return Err(Error::ActivationBlocked);
                }
                let now = self.effective_now();
                // Another app may have activated this product while we waited for the lock.
                if view
                    .leases
                    .get(&product)
                    .is_some_and(|l| l.lease.window(now).is_ok())
                {
                    return Ok(());
                }
            }
            let mut new_challenge = true;
            loop {
                let error = match self.activate_once(ops) {
                    Ok(()) => return Ok(()),
                    Err(e) => e,
                };
                if error.api_code() == Some(&ApiCode::ChallengeInvalid)
                    && std::mem::take(&mut new_challenge)
                {
                    continue;
                }
                self.on_device_error(ops, &error)?;
                return Err(error);
            }
        })
    }

    fn activate_once(&self, ops: &mut Ops) -> Result<(), Error> {
        let device = self.ensure_device(ops)?;
        let product = self.cfg.product.id();
        let url = self.cfg.pi_url(&format!(
            "/devices/challenge?product_id={}",
            query_escape(product)
        ));
        let challenge: Challenge = self.api_get(ops, &url)?.json()?;
        if !is_nonce(&challenge.nonce) {
            return Err(Error::BadResponse("challenge nonce".into()));
        }
        let message = activate_message(
            &challenge.challenge_id,
            &challenge.nonce,
            &device.installation_id,
            product,
        );
        let url = self.cfg.pi_url("/devices/activate");
        let reply = self.api_post(
            ops,
            &url,
            &json!({
                "installationId": device.installation_id,
                "productId": product,
                "platform": self.cfg.platform.id(),
                "clientVersion": self.cfg.client_version,
                "devicePublicKey": device.x(),
                "challengeId": challenge.challenge_id,
                "signedChallenge": device.sign(&message),
            }),
        )?;
        let response: LeaseResponse = reply.json()?;
        self.accept_lease(ops, &device, &response, &challenge.nonce)
    }

    /// `POST /licenses/refresh` for this product, under the shared lock.
    pub(super) fn refresh_lease(&self, ops: &mut Ops) -> Result<(), Error> {
        let product = self.cfg.product;
        self.locked(ops, |ops| {
            self.reload_with(ops)?;
            let device_id = self.view().session.device_ids.get(product.id()).cloned();
            let Some(device_id) = device_id else {
                return self.activate(ops);
            };
            let mut retimed = true;
            loop {
                let mut before_send = None;
                let error = match self.refresh_once(ops, &device_id, &mut before_send) {
                    Ok(()) => return Ok(()),
                    Err(e) => e,
                };
                match &error {
                    // PI stores a timestamp only on success, so the rejected one is undone; the
                    // reply's `Date` has corrected the offset for one more try.
                    Error::Api(e)
                        if e.status == 422
                            && e.errors.iter().any(|f| f == "timestamp")
                            && std::mem::take(&mut retimed) =>
                    {
                        let product = product.id();
                        self.update_session(ops, |s| match before_send {
                            Some(t) => {
                                s.last_refresh_ts.insert(product.to_owned(), t);
                            }
                            None => {
                                s.last_refresh_ts.remove(product);
                            }
                        })?;
                    }
                    // PI answers a device it does not know with a bare 404.
                    Error::Api(e) if e.status == 404 => {
                        log::warn!("PI does not know this device; activating again");
                        self.forget_device(ops)?;
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

    /// `before_send` gets this product's `last_refresh_ts` as it was before the last send.
    fn refresh_once(
        &self,
        ops: &mut Ops,
        device_id: &str,
        before_send: &mut Option<i64>,
    ) -> Result<(), Error> {
        let device = self.ensure_device(ops)?;
        let url = self.cfg.pi_url("/licenses/refresh");
        let mut nonce = String::new();
        let reply = self.authorized(ops, |ops, token| {
            self.http.retrying(Retry::Idempotent, || {
                // Each send gets its own timestamp and nonce: PI may have stored the timestamp
                // of a send whose reply never arrived.
                let (body, sent, previous) = self.refresh_body(ops, &device, device_id)?;
                nonce = sent;
                *before_send = previous;
                let key = random::uuid_v4()?;
                self.http.post(&url, Some(token), &Body::Json(&body), &key)
            })
        })?;
        let response: LeaseResponse = reply.json()?;
        self.accept_lease(ops, &device, &response, &nonce)
    }

    /// Signed refresh body, its nonce and the previous `last_refresh_ts`. The timestamp follows
    /// PI's clock, stays above the last one sent, and is in `session.json` before the body leaves.
    fn refresh_body(
        &self,
        ops: &mut Ops,
        device: &Device,
        device_id: &str,
    ) -> Result<(Vec<u8>, String, Option<i64>), Error> {
        let product = self.cfg.product.id();
        let mut s = self
            .read_session_disk(ops)
            .unwrap_or_else(|| self.view().session.clone());
        let server_now = self.cfg.clock.unix_now() + self.server_offset.load(Ordering::SeqCst);
        let previous = s.last_refresh_ts.get(product).copied();
        let above_last = previous.map_or(i64::MIN, |t| t.saturating_add(1));
        let timestamp = server_now.max(above_last);
        s.last_refresh_ts.insert(product.to_owned(), timestamp);
        self.write_session(ops, &mut s, Floor::Max)?;
        let nonce = random::token()?;
        let body = json!({
            "deviceId": device_id,
            "timestamp": timestamp,
            "signature": device.sign(&refresh_message(device_id, timestamp, &nonce)),
            "nonce": nonce,
        });
        let bytes = serde_json::to_vec(&body).map_err(|e| Error::Internal(e.to_string()))?;
        Ok((bytes, nonce, previous))
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
            return Err(Error::Lease(VerifyError::Format));
        }
        let product = self.cfg.product;
        let session = self.view().session.clone();
        let sub = session.user_id.as_deref().ok_or(Error::NotSignedIn)?;
        let jkt = device.thumbprint();
        let expect = Expect {
            issuer: &self.cfg.issuer,
            audience: &self.cfg.client_id,
            product,
            sub,
            org: session.org_context.as_deref(),
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
                entitlement_id: r.entitlement_id.as_deref(),
                rights: &r.rights,
                offline_valid_until: &r.offline_valid_until,
                policy_version: &r.policy_version,
                lease_id: &r.lease_id,
            })
            .map_err(|e| self.rejected(e))?;
        let mut s = self.read_session_disk(ops).unwrap_or(session);
        s.device_ids
            .insert(product.id().to_owned(), r.device_id.clone());
        s.not_entitled.remove(product.id());
        s.device_cap_reached = false;
        let floor = if corrected { Floor::Exact } else { Floor::Max };
        // The device id is stored first: on load, a lease without one is deleted as stale.
        self.write_session(ops, &mut s, floor)?;
        self.write_lease(device, product, &r.lease, Vec::new())?;
        self.load_leases(ops)
    }

    fn rejected(&self, e: VerifyError) -> Error {
        log::warn!("lease rejected on receipt: {e:?}; previous lease kept");
        Error::Lease(e)
    }

    /// Device-specific actions for PI's activation and refresh errors.
    fn on_device_error(&self, ops: &mut Ops, error: &Error) -> Result<(), Error> {
        let product = self.cfg.product;
        match error.api_code() {
            Some(ApiCode::DeviceCapReached) => {
                self.update_session(ops, |s| s.device_cap_reached = true)
            }
            Some(ApiCode::DeviceRevoked) => {
                self.remove_leases(None)?;
                self.update_session(ops, |s| {
                    s.device_ids.clear();
                    s.device_revoked = true;
                })
            }
            Some(ApiCode::NoEntitlement | ApiCode::NoSeat | ApiCode::OrgContextRequired) => {
                log::warn!("PI holds no plan or seat for {}", product.id());
                self.remove_lease(product)?;
                self.update_session(ops, |s| {
                    s.not_entitled.insert(product.id().to_owned());
                })
            }
            _ => Ok(()),
        }
    }

    /// PI no longer knows this product's device: its id and lease go.
    fn forget_device(&self, ops: &mut Ops) -> Result<(), Error> {
        let product = self.cfg.product;
        self.remove_lease(product)?;
        self.update_session(ops, |s| {
            s.device_ids.remove(product.id());
        })
    }
}

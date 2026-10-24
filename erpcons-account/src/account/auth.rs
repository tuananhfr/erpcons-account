//! Sign-in, token rotation, authorized API calls, identity, entitlements and catalog
//! (contract §1 to §3, products.md §3 and §4).
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use serde::Deserialize;

use super::{
    Access, Account, Ops,
    shared::{Floor, Profile, SessionFile, store_error},
};
use crate::{
    ApiCode, DESKTOP_SCOPES, Error, Product, catalog,
    entitlements::{self, Me},
    http::{Body, Reply, Retry},
    loopback::{Loopback, Pages},
    oidc::{self, AuthorizeRequest, Discovery, Tokens},
    random,
    secrets::REFRESH_TOKEN_ENTRY,
    storage,
};

const CATALOG_EVERY: Duration = Duration::from_secs(86_400);
const ACCESS_MARGIN: Duration = Duration::from_secs(30);

struct ClearOnDrop<'a>(&'a AtomicBool);

impl Drop for ClearOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Account {
    /// Signs in through the system browser. `open_browser` receives the authorization URL; the
    /// call returns on the loopback callback, an error, a timeout or [`Account::cancel_sign_in`].
    pub fn sign_in<F>(&self, open_browser: F) -> Result<(), Error>
    where
        F: FnOnce(&str) -> Result<(), String>,
    {
        if self.signing_in.swap(true, Ordering::SeqCst) {
            return Err(Error::SignInInProgress);
        }
        let _reset = ClearOnDrop(&self.signing_in);
        self.cancel.store(false, Ordering::SeqCst);
        let discovery = self.discovery(&mut super::lock(&self.ops))?;
        let loopback = Loopback::bind()?;
        let redirect_uri = loopback.redirect_uri();
        let verifier = random::token()?;
        let state = random::token()?;
        let nonce = random::token()?;
        let url = oidc::authorize_url(
            &discovery,
            &AuthorizeRequest {
                client_id: &self.cfg.client_id,
                redirect_uri: &redirect_uri,
                scope: DESKTOP_SCOPES,
                state: &state,
                nonce: &nonce,
                code_challenge: &oidc::pkce_challenge(&verifier),
                org_context: None,
                ui_locale: self.cfg.ui_locale.as_deref(),
            },
        );
        open_browser(&url).map_err(Error::Browser)?;
        let callback = loopback.wait(
            &self.cancel,
            Instant::now() + self.cfg.sign_in_timeout,
            &state,
            &Pages {
                success: &self.cfg.callback_success_html,
                failure: &self.cfg.callback_failure_html,
            },
        )?;
        if callback
            .iss
            .as_ref()
            .is_some_and(|iss| *iss != self.cfg.issuer)
        {
            return Err(Error::IssuerMismatch);
        }
        let mut ops = super::lock(&self.ops);
        let tokens = oidc::exchange_code(
            &self.http,
            &discovery,
            &self.cfg.client_id,
            &callback.code,
            &verifier,
            &redirect_uri,
        )?;
        let id_token = tokens
            .id_token
            .as_deref()
            .ok_or(Error::InvalidIdToken("missing"))?;
        let sub = oidc::check_id_token(
            id_token,
            &self.cfg.issuer,
            &self.cfg.client_id,
            &nonce,
            self.effective_now(),
        )?;
        let refresh = tokens
            .refresh_token
            .clone()
            .ok_or_else(|| Error::BadResponse("no refresh token".into()))?;
        let access = Access::new(&tokens, self.mono());
        let reply = self.http.retrying(Retry::Idempotent, || {
            self.http
                .get(&format!("{}/v1/me", self.cfg.api()), Some(&access.token))
        })?;
        if !reply.ok() {
            return Err(reply.error());
        }
        let me: Me = reply.json()?;
        if me.user_id != sub {
            return Err(Error::BadResponse(
                "user_id differs from the ID token sub".into(),
            ));
        }
        self.establish(&mut ops, refresh, &me)?;
        ops.access = Some(access);
        {
            let mut view = self.view_mut();
            view.online = true;
            view.reauth = false;
        }
        if let Err(e) = self.sync_after_sign_in(&mut ops) {
            log::warn!("post sign-in sync incomplete: {e}");
        }
        Ok(())
    }

    /// Stops a pending [`Account::sign_in`], which then returns [`Error::Cancelled`].
    pub fn cancel_sign_in(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    fn sync_after_sign_in(&self, ops: &mut Ops) -> Result<(), Error> {
        if let Err(e) = self.sync_catalog(ops) {
            log::warn!("feature catalog not updated: {e}");
        }
        self.fetch_entitlements(ops)?;
        self.sync_licence(ops)
    }

    /// Stores the new session for all four apps (ADR 0010).
    fn establish(&self, ops: &mut Ops, refresh: String, me: &Me) -> Result<(), Error> {
        let profile = profile(me);
        if !self.persistent {
            ops.memory_refresh = Some(refresh);
            let mut view = self.view_mut();
            view.signed_in = true;
            view.entitlements = None;
            view.session = SessionFile {
                user_id: Some(me.user_id.clone()),
                org_context: me.org_context.clone(),
                profile: Some(profile),
                ..SessionFile::default()
            };
            return Ok(());
        }
        self.locked(ops, |ops| {
            self.ensure_device(ops)?;
            let previous = self.read_session_disk(ops).unwrap_or_default();
            self.store
                .set(REFRESH_TOKEN_ENTRY, &refresh)
                .map_err(store_error)?;
            let same = previous.user_id.as_deref() == Some(me.user_id.as_str())
                && previous.org_context == me.org_context;
            if !same {
                self.remove_leases(None)?;
            }
            let mut s = SessionFile {
                user_id: Some(me.user_id.clone()),
                org_context: me.org_context.clone(),
                device_id: previous.device_id.filter(|_| same),
                trusted_floor: previous.trusted_floor,
                profile: Some(profile),
                ..SessionFile::default()
            };
            self.write_session(ops, &mut s, Floor::Max)?;
            self.reload_with(ops)
        })
    }

    pub(super) fn discovery(&self, ops: &mut Ops) -> Result<Discovery, Error> {
        if let Some(d) = &ops.discovery {
            return Ok(d.clone());
        }
        let d = oidc::discover(&self.http, &self.cfg.issuer).inspect_err(|e| self.note(e))?;
        ops.discovery = Some(d.clone());
        Ok(d)
    }

    /// Refresh grant with rotation, under the lock after re-reading the stored token
    /// (ADR 0010). `org` switches the context; `invalid_grant` signs out when `wipe_on_invalid`.
    pub(super) fn rotate(
        &self,
        ops: &mut Ops,
        org: Option<&str>,
        wipe_on_invalid: bool,
    ) -> Result<(), Error> {
        let discovery = self.discovery(ops)?;
        let grant =
            |token: &str| oidc::refresh(&self.http, &discovery, &self.cfg.client_id, token, org);
        let result: Result<Tokens, Error> = if self.persistent {
            self.locked(ops, |ops| {
                self.reload_with(ops)?;
                let token = self.refresh_token()?.ok_or(Error::NotSignedIn)?;
                match grant(&token) {
                    Ok(tokens) => {
                        if let Some(next) = &tokens.refresh_token {
                            self.store
                                .set(REFRESH_TOKEN_ENTRY, next)
                                .map_err(store_error)?;
                        }
                        if let Some(org) = org {
                            self.switch_context(ops, org)?;
                        }
                        Ok(tokens)
                    }
                    Err(Error::InvalidGrant) if wipe_on_invalid => {
                        log::warn!("refresh token rejected; signing out locally");
                        self.wipe(ops, false)?;
                        Err(Error::InvalidGrant)
                    }
                    Err(e) => Err(e),
                }
            })
        } else {
            let token = ops.memory_refresh.clone().ok_or(Error::NotSignedIn)?;
            match grant(&token) {
                Ok(tokens) => {
                    if let Some(next) = &tokens.refresh_token {
                        ops.memory_refresh = Some(next.clone());
                    }
                    if let Some(org) = org {
                        self.switch_context(ops, org)?;
                    }
                    Ok(tokens)
                }
                Err(Error::InvalidGrant) if wipe_on_invalid => {
                    self.wipe(ops, false)?;
                    Err(Error::InvalidGrant)
                }
                Err(e) => Err(e),
            }
        };
        match result {
            Ok(tokens) => {
                ops.access = Some(Access::new(&tokens, self.mono()));
                self.view_mut().online = true;
                Ok(())
            }
            Err(e) => {
                self.note(&e);
                Err(e)
            }
        }
    }

    /// New context for all four apps: every lease and the context's device id are dropped.
    fn switch_context(&self, ops: &mut Ops, org: &str) -> Result<(), Error> {
        let org = (org != "personal").then(|| org.to_owned());
        self.view_mut().entitlements = None;
        if !self.persistent {
            self.view_mut().session.org_context = org;
            return Ok(());
        }
        self.remove_leases(None)?;
        self.update_session(ops, |s| {
            s.org_context = org;
            s.device_id = None;
            s.device_revoked = false;
            s.device_cap_reached = false;
        })
    }

    pub(super) fn access_token(&self, ops: &mut Ops) -> Result<String, Error> {
        if let Some(a) = &ops.access
            && self.mono() + ACCESS_MARGIN < a.expires
        {
            return Ok(a.token.clone());
        }
        self.rotate(ops, None, true)?;
        ops.access
            .as_ref()
            .map(|a| a.token.clone())
            .ok_or(Error::NotSignedIn)
    }

    /// Bearer call: refresh once on 401 and retry (contract §3), then the generic error actions.
    fn authorized(
        &self,
        ops: &mut Ops,
        mut call: impl FnMut(&str) -> Result<Reply, Error>,
    ) -> Result<Reply, Error> {
        let token = self.access_token(ops)?;
        let mut reply = call(&token).inspect_err(|e| self.note(e))?;
        if reply.status == 401 {
            ops.access = None;
            let token = self.access_token(ops)?;
            reply = call(&token).inspect_err(|e| self.note(e))?;
        }
        self.view_mut().online = true;
        if reply.ok() {
            return Ok(reply);
        }
        let error = reply.error();
        self.on_api_error(ops, &error)?;
        Err(error)
    }

    pub(super) fn api_get(&self, ops: &mut Ops, path: &str) -> Result<Reply, Error> {
        let url = format!("{}{path}", self.cfg.api());
        self.authorized(ops, |token| {
            self.http
                .retrying(Retry::Idempotent, || self.http.get(&url, Some(token)))
        })
    }

    /// POST with one `Idempotency-Key` for the logical operation, reused on every retry.
    pub(super) fn api_post(
        &self,
        ops: &mut Ops,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<Reply, Error> {
        let url = format!("{}{path}", self.cfg.api());
        let bytes = serde_json::to_vec(body).map_err(|e| Error::Internal(e.to_string()))?;
        let key = random::uuid_v4()?;
        self.authorized(ops, |token| {
            self.http.retrying(Retry::Idempotent, || {
                self.http.post(&url, Some(token), &Body::Json(&bytes), &key)
            })
        })
    }

    /// Error-table actions that do not depend on the operation (contract §3).
    fn on_api_error(&self, ops: &mut Ops, error: &Error) -> Result<(), Error> {
        match error.api_code() {
            Some(ApiCode::Unauthenticated | ApiCode::InsufficientScope) => {
                self.view_mut().reauth = true;
            }
            Some(ApiCode::UserSuspended) => self.wipe(ops, false)?,
            Some(ApiCode::MembershipInactive) => {
                let personal = self.view().session.org_context.is_none();
                if !personal {
                    self.rotate(ops, Some("personal"), true)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn fetch_me(&self, ops: &mut Ops) -> Result<(), Error> {
        let me: Me = self.api_get(ops, "/v1/me")?.json()?;
        if !self.persistent {
            let mut view = self.view_mut();
            if view.session.org_context != me.org_context {
                view.entitlements = None;
            }
            view.session.user_id = Some(me.user_id.clone());
            view.session.org_context = me.org_context.clone();
            view.session.profile = Some(profile(&me));
            return Ok(());
        }
        self.locked(ops, |ops| {
            self.ensure_device(ops)?;
            let mut s = self.read_session_disk(ops).unwrap_or_default();
            if s.user_id.as_deref() != Some(me.user_id.as_str()) || s.org_context != me.org_context
            {
                // A different sub or context makes every lease and the device id stale (§8).
                self.remove_leases(None)?;
                s.device_id = None;
                s.device_revoked = false;
                s.device_cap_reached = false;
                self.view_mut().entitlements = None;
            }
            s.user_id = Some(me.user_id.clone());
            s.org_context = me.org_context.clone();
            s.profile = Some(profile(&me));
            self.write_session(ops, &mut s, Floor::Max)?;
            self.load_leases(ops)
        })
    }

    pub(super) fn fetch_entitlements(&self, ops: &mut Ops) -> Result<(), Error> {
        let product = self.cfg.product;
        let reply = self.api_get(
            ops,
            &format!("/v1/me/entitlements?product_id={}", product.id()),
        )?;
        let org = self.view().session.org_context.clone();
        let list = entitlements::parse(&reply.body, product, org.as_deref())?;
        self.view_mut().entitlements = Some((list, self.mono()));
        Ok(())
    }

    /// Fetches the signed catalog at most once a day, guests included (products.md §3).
    pub(super) fn sync_catalog(&self, ops: &mut Ops) -> Result<(), Error> {
        #[derive(Deserialize)]
        struct Response {
            catalog: String,
        }
        let now = self.mono();
        if ops
            .catalog_fetched
            .is_some_and(|t| now.saturating_sub(t) < CATALOG_EVERY)
        {
            return Ok(());
        }
        let product: Product = self.cfg.product;
        let url = format!(
            "{}/v1/products/{}/feature-catalog",
            self.cfg.api(),
            product.id()
        );
        let reply = self
            .http
            .retrying(Retry::Idempotent, || self.http.get(&url, None))
            .inspect_err(|e| self.note(e))?;
        self.view_mut().online = true;
        if !reply.ok() {
            return Err(reply.error());
        }
        ops.catalog_fetched = Some(now);
        let response: Response = reply.json()?;
        let cached = self.view().catalog.as_ref().map_or(0, |c| c.version);
        let fetched = catalog::verify(
            &response.catalog,
            &self.cfg.platform_keys,
            &self.cfg.issuer,
            product,
            cached,
        )
        .map_err(Error::Catalog)?;
        if self.view().catalog.is_some() && fetched.version == cached {
            return Ok(());
        }
        self.locked(ops, |_| {
            storage::write_atomic(&self.paths.catalog(product), fetched.jws.as_bytes())
        })?;
        self.view_mut().catalog = Some(fetched);
        Ok(())
    }

    pub(super) fn sync_signed_in(&self, ops: &mut Ops) -> Result<(), Error> {
        if !self.view().signed_in {
            return Ok(());
        }
        self.access_token(ops)?;
        self.fetch_me(ops)?;
        self.fetch_entitlements(ops)?;
        self.sync_licence(ops)
    }
}

impl Access {
    fn new(tokens: &Tokens, mono: Duration) -> Self {
        Self {
            token: tokens.access_token.clone(),
            expires: mono + Duration::from_secs(tokens.expires_in),
        }
    }
}

fn profile(me: &Me) -> Profile {
    Profile {
        display_name: me.display_name.clone(),
        email: me.email.clone(),
        memberships: me.memberships.clone(),
    }
}

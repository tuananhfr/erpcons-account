//! Sign-in and organization switch through the browser, token rotation, authorized API calls,
//! identity from PI's `/me` (ADR 0011), and the Office-contract entitlements and catalog
//! (products.md §3 and §4) used only with `offline_licensing`.
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
    ApiCode, ApiError, Error, MembershipStatus, Product, catalog, entitlements,
    http::{Body, Reply, Retry},
    loopback::{Loopback, Pages},
    me::{self, Me},
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

/// What a browser authorization asks PI for, beyond the standard parameters.
struct Ask<'a> {
    org_hint: Option<&'a str>,
    prompt: Option<&'a str>,
    /// The session must stay this user's (organization switch).
    same_user: Option<&'a str>,
}

impl Account {
    /// Signs in through the system browser. `open_browser` receives the authorization URL; the
    /// call returns on the loopback callback, an error, a timeout or [`Account::cancel_sign_in`].
    /// After a [`Account::sign_out`] it asks PI for `prompt=login`.
    pub fn sign_in<F>(&self, open_browser: F) -> Result<(), Error>
    where
        F: FnOnce(&str) -> Result<(), String>,
    {
        let prompt = {
            let mut ops = super::lock(&self.ops);
            self.reload_with(&mut ops)?;
            (ops.login_prompt || self.view().session.login_prompt).then_some("login")
        };
        self.browser_session(
            open_browser,
            &Ask {
                org_hint: None,
                prompt,
                same_user: None,
            },
        )
    }

    /// Switches all four apps to `org_id`, or to the personal context with `None`, by running the
    /// authorization again: PI binds the organization to the token family and its refresh grant
    /// cannot change it (ADR 0011). `org_id` goes as `org_hint`; `None` sends
    /// `prompt=select_account`, where the user picks "personal" on PI's page.
    ///
    /// Returns [`Error::OrgUnavailable`] when PI granted another context; the session then holds
    /// the context PI granted. Blocks like [`Account::sign_in`] and is cancelled the same way.
    pub fn select_org<F>(&self, org_id: Option<&str>, open_browser: F) -> Result<(), Error>
    where
        F: FnOnce(&str) -> Result<(), String>,
    {
        let user = {
            let mut ops = super::lock(&self.ops);
            self.reload_with(&mut ops)?;
            let view = self.view();
            if !view.signed_in {
                return Err(Error::NotSignedIn);
            }
            if let Some(id) = org_id {
                let member = view.session.profile.as_ref().is_some_and(|p| {
                    p.memberships
                        .iter()
                        .any(|m| m.org_id == id && m.status == MembershipStatus::Active)
                });
                if !member {
                    return Err(Error::UnknownOrg);
                }
            }
            view.session.user_id.clone()
        };
        let (org_hint, prompt) = match org_id {
            Some(id) => (Some(id), None),
            None => (None, Some("select_account")),
        };
        self.browser_session(
            open_browser,
            &Ask {
                org_hint,
                prompt,
                same_user: user.as_deref(),
            },
        )?;
        if self.view().session.org_context.as_deref() != org_id {
            log::warn!("PI granted another organization context than the one requested");
            return Err(Error::OrgUnavailable);
        }
        Ok(())
    }

    /// Stops a pending [`Account::sign_in`] or [`Account::select_org`], which then returns
    /// [`Error::Cancelled`].
    pub fn cancel_sign_in(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    /// Authorization code flow with PKCE through the loopback redirect, then the new session.
    fn browser_session<F>(&self, open_browser: F, ask: &Ask) -> Result<(), Error>
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
                scope: self.cfg.profile.scopes,
                state: &state,
                nonce: &nonce,
                code_challenge: &oidc::pkce_challenge(&verifier),
                org_hint: ask.org_hint,
                prompt: ask.prompt,
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
        let refresh = tokens
            .refresh_token
            .clone()
            .ok_or_else(|| Error::BadResponse("no refresh token".into()))?;
        let access = Access::new(&tokens, self.mono());
        let me = match self.identity(&tokens, &access, &nonce, ask) {
            Ok(me) => me,
            Err(e) => {
                // The new token family is not kept, so it must not stay valid at PI either.
                self.try_revoke(&mut ops, &refresh);
                return Err(e);
            }
        };
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

    /// ID token checks, then PI's `/me` for the same subject.
    fn identity(
        &self,
        tokens: &Tokens,
        access: &Access,
        nonce: &str,
        ask: &Ask,
    ) -> Result<Me, Error> {
        let id_token = tokens
            .id_token
            .as_deref()
            .ok_or(Error::InvalidIdToken("missing"))?;
        let sub = oidc::check_id_token(
            id_token,
            &self.cfg.issuer,
            &self.cfg.client_id,
            nonce,
            self.effective_now(),
        )?;
        let url = self.cfg.pi_url("/me");
        let reply = self.http.retrying(Retry::Idempotent, || {
            self.http.get(&url, Some(&access.token))
        })?;
        if !reply.ok() {
            return Err(reply.error());
        }
        let me = me::parse(&reply.body)?;
        if me.user_id != sub {
            return Err(Error::BadResponse(
                "user id differs from the ID token sub".into(),
            ));
        }
        if me.locked {
            return Err(account_locked());
        }
        if ask.same_user.is_some_and(|u| u != me.user_id) {
            log::warn!("PI signed in another account during an organization switch; ignored");
            return Err(Error::OrgUnavailable);
        }
        Ok(me)
    }

    fn sync_after_sign_in(&self, ops: &mut Ops) -> Result<(), Error> {
        if !self.cfg.offline_licensing {
            return Ok(());
        }
        if let Err(e) = self.sync_catalog(ops) {
            log::warn!("feature catalog not updated: {e}");
        }
        self.fetch_entitlements(ops)?;
        self.sync_licence(ops)
    }

    /// Stores the new session for all four apps (ADR 0010) and revokes the one it replaces.
    fn establish(&self, ops: &mut Ops, refresh: String, me: &Me) -> Result<(), Error> {
        let profile = profile(me);
        ops.login_prompt = false;
        if !self.persistent {
            if let Some(old) = ops.memory_refresh.replace(refresh) {
                self.try_revoke(ops, &old);
            }
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
            let replaced = self.refresh_token().ok().flatten();
            self.store
                .set(REFRESH_TOKEN_ENTRY, &refresh)
                .map_err(store_error)?;
            if let Some(old) = replaced.filter(|old| *old != refresh) {
                self.try_revoke(ops, &old);
            }
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
    /// (ADR 0010); `invalid_grant` signs out when `wipe_on_invalid`.
    pub(super) fn rotate(&self, ops: &mut Ops, wipe_on_invalid: bool) -> Result<(), Error> {
        let discovery = self.discovery(ops)?;
        let grant = |token: &str| oidc::refresh(&self.http, &discovery, &self.cfg.client_id, token);
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

    pub(super) fn access_token(&self, ops: &mut Ops) -> Result<String, Error> {
        if let Some(a) = &ops.access
            && self.mono() + ACCESS_MARGIN < a.expires
        {
            return Ok(a.token.clone());
        }
        self.rotate(ops, true)?;
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

    pub(super) fn api_get(&self, ops: &mut Ops, url: &str) -> Result<Reply, Error> {
        self.authorized(ops, |token| {
            self.http
                .retrying(Retry::Idempotent, || self.http.get(url, Some(token)))
        })
    }

    /// POST with one `Idempotency-Key` for the logical operation, reused on every retry.
    pub(super) fn api_post(
        &self,
        ops: &mut Ops,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<Reply, Error> {
        let bytes = serde_json::to_vec(body).map_err(|e| Error::Internal(e.to_string()))?;
        let key = random::uuid_v4()?;
        self.authorized(ops, |token| {
            self.http.retrying(Retry::Idempotent, || {
                self.http.post(url, Some(token), &Body::Json(&bytes), &key)
            })
        })
    }

    /// Error actions that do not depend on the operation (ADR 0011, contract §3).
    fn on_api_error(&self, ops: &mut Ops, error: &Error) -> Result<(), Error> {
        match error.api_code() {
            Some(ApiCode::Unauthenticated | ApiCode::InsufficientScope) => {
                self.view_mut().reauth = true;
            }
            Some(ApiCode::UserSuspended) => self.wipe(ops, false)?,
            Some(ApiCode::MembershipInactive) => {
                // PI refuses this token family's organization from now on, refresh included;
                // only a new sign-in (another organization or personal) gives a usable session.
                self.remove_leases(None)?;
                self.view_mut().reauth = true;
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn fetch_me(&self, ops: &mut Ops) -> Result<(), Error> {
        let url = self.cfg.pi_url("/me");
        let me = me::parse(&self.api_get(ops, &url)?.body)?;
        if me.locked {
            self.wipe(ops, false)?;
            return Err(account_locked());
        }
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
        let url = self
            .cfg
            .contract_url(&format!("/v1/me/entitlements?product_id={}", product.id()));
        let reply = self.api_get(ops, &url)?;
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
        let url = self
            .cfg
            .contract_url(&format!("/v1/products/{}/feature-catalog", product.id()));
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
        if !self.cfg.offline_licensing {
            return Ok(());
        }
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

/// `/me` reporting a `LOCKED` account answers like PI's `403 ACCOUNT_LOCKED`.
fn account_locked() -> Error {
    Error::Api(ApiError {
        status: 403,
        code: ApiCode::UserSuspended,
        correlation_id: None,
        retry_after: None,
        max_devices: None,
        active_devices: None,
        errors: Box::default(),
    })
}

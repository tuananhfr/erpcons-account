use std::{path::PathBuf, sync::Arc, time::Duration};

use crate::{
    catalog::BuiltinFeature,
    clock::{Clock, SystemClock},
};

/// OIDC client id shared by the four desktop apps (contract §1).
pub const DESKTOP_CLIENT_ID: &str = "erpcons-office-desktop";
/// Scopes requested by the desktop client (contract §1).
pub const DESKTOP_SCOPES: &str = "openid profile email offline_access pi.entitlements pi.devices";
/// Platform licence-signing keys pinned in release builds, as `(kid, Ed25519 public key)`.
///
/// Empty until the PI Platform issues its keys (lease.md §10). Development keys, such as the
/// pi-mock key, are passed through [`Config::platform_keys`] and never listed here.
pub const PLATFORM_KEYS: &[(&str, [u8; 32])] = &[];

/// Office product, also the `product_id` of the PI product registry (ADR 0007).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Product {
    VanBan,
    BangTinh,
    TrinhChieu,
    Pdf,
}

impl Product {
    /// Every product, in registry order.
    pub const ALL: [Product; 4] = [
        Product::VanBan,
        Product::BangTinh,
        Product::TrinhChieu,
        Product::Pdf,
    ];

    /// Registry id (`vanban`, `bangtinh`, `trinhchieu`, `pdf`).
    pub fn id(self) -> &'static str {
        match self {
            Self::VanBan => "vanban",
            Self::BangTinh => "bangtinh",
            Self::TrinhChieu => "trinhchieu",
            Self::Pdf => "pdf",
        }
    }

    /// Product for a registry id.
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.id() == id)
    }

    /// Name used in `User-Agent: ERPCons-<name>/<version>` (contract §2).
    pub fn agent_name(self) -> &'static str {
        match self {
            Self::VanBan => "VanBan",
            Self::BangTinh => "BangTinh",
            Self::TrinhChieu => "TrinhChieu",
            Self::Pdf => "PDF",
        }
    }
}

/// Desktop operating system reported to the platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Macos,
    Linux,
}

impl Platform {
    /// Platform of this build.
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else {
            Self::Linux
        }
    }

    /// Contract value (`windows`, `macos`, `linux`).
    pub fn id(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Linux => "linux",
        }
    }
}

/// Platform licence-signing public key, pinned by `kid` (lease.md §10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedKey {
    pub kid: String,
    pub key: [u8; 32],
}

/// Account client configuration; [`Config::new`] gives the release defaults.
#[derive(Clone)]
pub struct Config {
    /// OIDC issuer; discovery must return exactly this value. Also the lease and catalog `iss`.
    pub issuer: String,
    /// Base URL of the `/v1` API. `None` uses the issuer.
    pub api_base: Option<String>,
    pub client_id: String,
    pub product: Product,
    /// App version `major.minor.patch`, sent as `client_version`.
    pub client_version: String,
    pub user_agent: String,
    pub platform: Platform,
    /// `ui_locales` sent on the authorization request (`vi` or `en`).
    pub ui_locale: Option<String>,
    /// Keys that verify leases and feature catalogs.
    pub platform_keys: Vec<PinnedKey>,
    /// Built-in catalog (version 0): every feature this release gates, with its tier.
    pub builtin_features: Vec<BuiltinFeature>,
    /// Overrides the shared PI directory (tests).
    pub state_dir: Option<PathBuf>,
    /// Per-request network timeout.
    pub timeout: Duration,
    /// Longest wait a call spends on its own retries before returning the error.
    pub max_retry_wait: Duration,
    /// How long `sign_in` waits for the browser callback.
    pub sign_in_timeout: Duration,
    /// Page served to the browser after a successful callback; the app supplies the text.
    pub callback_success_html: String,
    /// Page served to the browser after a failed callback.
    pub callback_failure_html: String,
    pub clock: Arc<dyn Clock>,
}

impl Config {
    /// Release defaults for `product`: pinned platform keys, built-in catalog, 15 s timeouts.
    pub fn new(
        issuer: impl Into<String>,
        product: Product,
        client_version: impl Into<String>,
    ) -> Self {
        let client_version = client_version.into();
        Self {
            issuer: issuer.into(),
            api_base: None,
            client_id: DESKTOP_CLIENT_ID.into(),
            product,
            user_agent: format!("ERPCons-{}/{client_version}", product.agent_name()),
            client_version,
            platform: Platform::current(),
            ui_locale: None,
            platform_keys: PLATFORM_KEYS
                .iter()
                .map(|(kid, key)| PinnedKey {
                    kid: (*kid).into(),
                    key: *key,
                })
                .collect(),
            builtin_features: BuiltinFeature::defaults(product),
            state_dir: None,
            timeout: Duration::from_secs(15),
            max_retry_wait: Duration::from_secs(10),
            sign_in_timeout: Duration::from_secs(600),
            callback_success_html: "<!doctype html><meta charset=\"utf-8\"><title>ERPCons</title>"
                .into(),
            callback_failure_html: "<!doctype html><meta charset=\"utf-8\"><title>ERPCons</title>"
                .into(),
            clock: Arc::new(SystemClock::new()),
        }
    }

    pub(crate) fn api(&self) -> &str {
        self.api_base
            .as_deref()
            .unwrap_or(&self.issuer)
            .trim_end_matches('/')
    }

    pub(crate) fn validate(&self) -> Result<(), crate::Error> {
        let bad = |s: &str| Err(crate::Error::Config(s.into()));
        if !crate::oidc::allowed_url(&self.issuer, &self.issuer) {
            return bad("issuer must be https, or http on a loopback address");
        }
        if let Some(api) = &self.api_base
            && !crate::oidc::allowed_url(api, &self.issuer)
        {
            return bad("api_base must be https, or http on a loopback address");
        }
        if !valid_version(&self.client_version) {
            return bad("client_version must be major.minor.patch");
        }
        if self
            .builtin_features
            .iter()
            .any(|f| !crate::catalog::is_valid_feature_id(&f.feature))
        {
            return bad("invalid built-in feature id");
        }
        Ok(())
    }
}

fn valid_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    v.len() <= 32
        && parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 9
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
}

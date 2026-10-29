use std::{path::PathBuf, sync::Arc, time::Duration};

use crate::{
    catalog::BuiltinFeature,
    clock::{Clock, SystemClock},
};

/// OIDC client id shared by the four desktop apps (contract §1).
pub const DESKTOP_CLIENT_ID: &str = "erpcons-office-desktop";
/// Scopes requested by the desktop client (contract §1).
pub const DESKTOP_SCOPES: &str = "openid profile email offline_access pi.entitlements pi.devices";
/// Path of PI's end-user API on the issuer's host (ADR 0011).
pub const PI_API_PATH: &str = "/api/v1/id";
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
    /// UbotCAD, the UbotBuild desktop app.
    UbotBuild,
}

impl Product {
    /// Every product, in registry order.
    pub const ALL: [Product; 5] = [
        Product::VanBan,
        Product::BangTinh,
        Product::TrinhChieu,
        Product::Pdf,
        Product::UbotBuild,
    ];

    /// The four Office products.
    pub const OFFICE: [Product; 4] = [
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
            Self::UbotBuild => "ubotbuild",
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
            Self::UbotBuild => "UbotCAD",
        }
    }

    /// Client family this product signs in as.
    pub fn profile(self) -> ClientProfile {
        match self {
            Self::UbotBuild => ClientProfile::UBOTCAD,
            _ => ClientProfile::OFFICE,
        }
    }

    /// Feature names (after `<product>.`) that stay free whatever a catalog says.
    pub fn pinned_free_suffixes(self) -> &'static [&'static str] {
        match self {
            Self::UbotBuild => &["cad-view", "cad-export"],
            _ => &["view", "export"],
        }
    }
}

/// Identity and storage names of one desktop app family sharing this library.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientProfile {
    pub client_id: &'static str,
    pub scopes: &'static str,
    pub keyring_service: &'static str,
    pub dir_windows: &'static str,
    pub dir_macos: &'static str,
    pub dir_linux: &'static str,
    /// Prefix of the `User-Agent` product token, before [`Product::agent_name`].
    pub agent_prefix: &'static str,
    pub app_title: &'static str,
    pub products: &'static [Product],
}

impl ClientProfile {
    pub const OFFICE: Self = Self {
        client_id: DESKTOP_CLIENT_ID,
        scopes: DESKTOP_SCOPES,
        keyring_service: "ERPCons Office PI",
        dir_windows: "ERPCons\\PI",
        dir_macos: "ERPCons/PI",
        dir_linux: "erpcons/pi",
        agent_prefix: "ERPCons-",
        app_title: "ERPCons",
        products: &Product::OFFICE,
    };

    pub const UBOTCAD: Self = Self {
        client_id: "ubotcad-desktop",
        scopes: DESKTOP_SCOPES,
        keyring_service: "UbotCAD PI",
        dir_windows: "UbotCAD\\PI",
        dir_macos: "UbotCAD/PI",
        dir_linux: "ubotcad/pi",
        agent_prefix: "",
        app_title: "UbotCAD",
        products: &[Product::UbotBuild],
    };
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
    /// Base URL of PI's end-user API (`/me` below it). `None`: `{issuer}/api/v1/id` (ADR 0011).
    pub api_base: Option<String>,
    pub client_id: String,
    pub profile: ClientProfile,
    pub product: Product,
    /// App version `major.minor.patch`, sent as `clientVersion` at activation.
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
    /// Device activation, offline leases and online entitlements through PI's device protocol
    /// (ADR 0012). Off by default: none of their endpoints is called. UbotCAD turns it on; PI has
    /// no Office product, so Office keeps it off.
    pub offline_licensing: bool,
    /// How long `sign_in` and `select_org` wait for the browser callback.
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
        let profile = product.profile();
        Self {
            issuer: issuer.into(),
            api_base: None,
            client_id: profile.client_id.into(),
            profile,
            product,
            user_agent: format!(
                "{}{}/{client_version}",
                profile.agent_prefix,
                product.agent_name()
            ),
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
            offline_licensing: false,
            sign_in_timeout: Duration::from_secs(600),
            callback_success_html: callback_page(profile.app_title),
            callback_failure_html: callback_page(profile.app_title),
            clock: Arc::new(SystemClock::new()),
        }
    }

    /// URL of a PI end-user API `path` (`/me`).
    pub(crate) fn pi_url(&self, path: &str) -> String {
        match &self.api_base {
            Some(base) => format!("{}{path}", base.trim_end_matches('/')),
            None => format!("{}{PI_API_PATH}{path}", self.issuer.trim_end_matches('/')),
        }
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
        if !self.profile.products.contains(&self.product) {
            return bad("product is not served by the client profile");
        }
        if self.client_id != self.profile.client_id {
            return bad("client_id differs from the client profile");
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

fn callback_page(title: &str) -> String {
    format!("<!doctype html><meta charset=\"utf-8\"><title>{title}</title>")
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

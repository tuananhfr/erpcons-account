//! Feature ids, tiers and the signed feature catalog (products.md §2, §3).
use std::collections::HashMap;

use serde_json::Value;

use crate::{ClientProfile, PinnedKey, Product, VerifyError, jose};

pub(crate) const CATALOG_TYP: &str = "pi-feature-catalog+jwt";

/// Feature tier: `pro` needs an entitlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Free,
    Pro,
}

/// Entry of the built-in catalog (version 0) compiled into a release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltinFeature {
    pub feature: String,
    pub tier: Tier,
}

impl BuiltinFeature {
    pub fn new(feature: impl Into<String>, tier: Tier) -> Self {
        Self {
            feature: feature.into(),
            tier,
        }
    }

    /// Office: `erpconsoffice.view` and `.export` free, `.use` pro (ADR 0013).
    /// UbotCAD: `cad-view` and `cad-export` free, `cad-use` pro (PI's plan codes).
    pub fn defaults(product: Product) -> Vec<Self> {
        let names: [(&str, Tier); 3] = match product {
            Product::UbotBuild => [
                ("cad-view", Tier::Free),
                ("cad-export", Tier::Free),
                ("cad-use", Tier::Pro),
            ],
            _ => [
                ("view", Tier::Free),
                ("export", Tier::Free),
                ("use", Tier::Pro),
            ],
        };
        names
            .into_iter()
            .map(|(name, tier)| Self::new(format!("{}.{name}", product.pi_product()), tier))
            .collect()
    }
}

/// `<pi_product>.<name>` as products.md §2 defines it.
pub fn is_valid_feature_id(feature: &str) -> bool {
    let Some((product, name)) = feature.split_once('.') else {
        return false;
    };
    feature.len() <= 64
        && ClientProfile::for_pi_product(product).is_some()
        && name.split('.').all(|seg| {
            !seg.is_empty()
                && seg.bytes().enumerate().all(|(i, b)| {
                    b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || b == b'_'
                        || (i > 0 && b == b'-')
                })
        })
}

/// A product's view and export features are free whatever a catalog says (HS02).
pub fn is_pinned_free(feature: &str) -> bool {
    is_valid_feature_id(feature)
        && feature
            .split_once('.')
            .and_then(|(product, name)| Some((ClientProfile::for_pi_product(product)?, name)))
            .is_some_and(|(profile, name)| profile.pinned_free.contains(&name))
}

#[derive(Clone, Debug)]
pub(crate) struct Catalog {
    pub version: u64,
    pub tiers: HashMap<String, Tier>,
}

/// Accepts a catalog of PI product `product` per products.md §3; `cached` is the version already
/// held.
pub(crate) fn verify(
    jws: &str,
    keys: &[PinnedKey],
    issuer: &str,
    product: &str,
    cached: u64,
) -> Result<Catalog, VerifyError> {
    let payload = jose::verify_platform(jws, CATALOG_TYP, keys)?;
    let version = payload
        .get("catalog_version")
        .and_then(Value::as_u64)
        .filter(|v| *v >= 1)
        .ok_or(VerifyError::Claims)?;
    payload
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(VerifyError::Claims)?;
    let features = payload
        .get("features")
        .and_then(Value::as_array)
        .filter(|f| f.len() <= 500)
        .ok_or(VerifyError::Claims)?;
    if payload.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(VerifyError::Issuer);
    }
    if payload.get("product").and_then(Value::as_str) != Some(product) {
        return Err(VerifyError::Product);
    }
    let mut tiers = HashMap::new();
    for entry in features {
        let feature = entry
            .get("feature")
            .and_then(Value::as_str)
            .ok_or(VerifyError::Claims)?;
        let tier = match entry.get("tier").and_then(Value::as_str) {
            Some("free") => Tier::Free,
            Some("pro") => Tier::Pro,
            _ => return Err(VerifyError::Claims),
        };
        if !is_valid_feature_id(feature) {
            return Err(VerifyError::Feature);
        }
        if tier == Tier::Pro && is_pinned_free(feature) {
            log::warn!("feature catalog marks pinned-free {feature} as pro; ignored");
        }
        if tiers.insert(feature.to_owned(), tier).is_some() {
            return Err(VerifyError::Claims);
        }
    }
    if version < cached {
        return Err(VerifyError::Downgrade);
    }
    Ok(Catalog { version, tiers })
}

/// `tier(f)` of products.md §3; `None` for a feature this release does not gate.
pub(crate) fn tier(builtin: &[BuiltinFeature], catalog: Option<&Catalog>, f: &str) -> Option<Tier> {
    let entry = builtin.iter().find(|b| b.feature == f)?;
    if is_pinned_free(f) {
        return Some(Tier::Free);
    }
    Some(
        catalog
            .and_then(|c| c.tiers.get(f).copied())
            .unwrap_or(entry.tier),
    )
}

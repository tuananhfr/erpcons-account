//! Online entitlement list of the Office contract and its tenant-isolation sanity check
//! (products.md §4). PI's `/me/entitlements` has another shape; not called (ADR 0011).
use serde::Deserialize;

use crate::{Error, Product};

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Entitlement {
    pub product_id: String,
    pub feature: String,
    pub org_id: Option<String>,
    pub offline_allowed: bool,
}

#[derive(Deserialize)]
struct EntitlementList {
    product_id: String,
    org_context: Option<String>,
    entitlements: Vec<Entitlement>,
}

/// Parses an entitlement list; another product's or tenant's data discards the whole response.
pub(crate) fn parse(
    body: &[u8],
    product: Product,
    org_context: Option<&str>,
) -> Result<Vec<Entitlement>, Error> {
    let list: EntitlementList =
        serde_json::from_slice(body).map_err(|e| Error::BadResponse(e.to_string()))?;
    let foreign = list.product_id != product.id()
        || list.org_context.as_deref() != org_context
        || list.entitlements.iter().any(|e| {
            e.product_id != product.id()
                || e.org_id.as_deref().is_some_and(|o| Some(o) != org_context)
        });
    if foreign {
        log::error!(
            "tenant isolation incident: entitlements for another product or tenant discarded"
        );
        return Err(Error::TenantIsolation);
    }
    Ok(list.entitlements)
}

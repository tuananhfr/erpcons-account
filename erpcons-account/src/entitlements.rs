//! PI's `/me/entitlements` rows for the token's organization and their tenant-isolation sanity
//! check (products.md §4).
use serde::Deserialize;

use crate::{Error, pi_device::compose_features};

#[derive(Clone, Debug)]
pub(crate) struct Entitlement {
    /// `<product>.<code>`.
    pub feature: String,
    pub offline_allowed: bool,
}

#[derive(Deserialize)]
struct List {
    items: Vec<Row>,
}

#[derive(Deserialize)]
struct Row {
    organization: Id,
    tenant: TenantRef,
    decision: String,
    #[serde(default)]
    seat: bool,
    #[serde(default)]
    features: Vec<Code>,
    offline: Option<Offline>,
}

#[derive(Deserialize)]
struct Id {
    id: String,
}

#[derive(Deserialize)]
struct TenantRef {
    product: String,
}

#[derive(Deserialize)]
struct Code {
    code: String,
}

#[derive(Deserialize)]
struct Offline {
    allowed: bool,
}

/// Features of the rows that grant PI product `product` in `org` (`ALLOW` with a seat); a row of
/// another product or organization discards the whole response; a row with an invalid feature
/// code is skipped.
pub(crate) fn parse(body: &[u8], product: &str, org: &str) -> Result<Vec<Entitlement>, Error> {
    let list: List = serde_json::from_slice(body).map_err(|e| Error::BadResponse(e.to_string()))?;
    let foreign = list
        .items
        .iter()
        .any(|r| r.organization.id != org || r.tenant.product != product);
    if foreign {
        log::error!(
            "tenant isolation incident: entitlements for another product or tenant discarded"
        );
        return Err(Error::TenantIsolation);
    }
    let mut granted = Vec::new();
    for row in list
        .items
        .iter()
        .filter(|r| r.decision == "ALLOW" && r.seat)
    {
        let codes: Vec<String> = row.features.iter().map(|f| f.code.clone()).collect();
        let offline_allowed = row.offline.as_ref().is_some_and(|o| o.allowed);
        // One malformed row must not stop the lease sync that follows the fetch.
        let Ok(features) = compose_features(product, &codes) else {
            log::warn!("entitlement row with an invalid feature code skipped");
            continue;
        };
        granted.extend(features.into_iter().map(|feature| Entitlement {
            feature,
            offline_allowed,
        }));
    }
    Ok(granted)
}

//! Offline lease verification (lease.md §4, §9).
use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::{PinnedKey, Product, VerifyError, catalog, jose, time};

pub(crate) const LEASE_TYP: &str = "pi-lease+jwt";
const MAX_WINDOW: i64 = 7_776_000;
const CLAIMS: [&str; 16] = [
    "iss",
    "aud",
    "lease_id",
    "sub",
    "org",
    "device_id",
    "installation_id",
    "cnf",
    "product",
    "features",
    "entitlement_ids",
    "nbf",
    "iat",
    "exp",
    "nonce",
    "policy_version",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Lease {
    pub lease_id: String,
    pub sub: String,
    pub org: Option<String>,
    pub device_id: String,
    pub product: Product,
    pub features: Vec<String>,
    pub entitlement_ids: Vec<String>,
    pub nbf: i64,
    pub iat: i64,
    pub exp: i64,
    pub policy_version: String,
    pub jws: String,
}

/// Values a lease must match; `nonce` only on receipt.
pub(crate) struct Expect<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub product: Product,
    pub sub: &'a str,
    pub org: Option<&'a str>,
    pub installation_id: &'a str,
    pub jkt: &'a str,
    pub device_id: &'a str,
    pub nonce: Option<&'a str>,
}

/// Unsigned copies in an activation or refresh response (§9 step 12).
pub(crate) struct Copies<'a> {
    pub entitlement_ids: &'a [String],
    pub rights: &'a [String],
    pub offline_valid_until: &'a str,
    pub policy_version: &'a str,
}

fn string<'a>(p: &'a Map<String, Value>, k: &str) -> Result<&'a str, VerifyError> {
    p.get(k).and_then(Value::as_str).ok_or(VerifyError::Claims)
}

fn int(p: &Map<String, Value>, k: &str) -> Result<i64, VerifyError> {
    p.get(k).and_then(Value::as_i64).ok_or(VerifyError::Claims)
}

fn strings(p: &Map<String, Value>, k: &str) -> Result<Vec<String>, VerifyError> {
    let items = p
        .get(k)
        .and_then(Value::as_array)
        .filter(|a| a.len() <= 200)
        .ok_or(VerifyError::Claims)?;
    items
        .iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or(VerifyError::Claims))
        .collect()
}

/// Steps 1 to 10 and the static part of step 11; the caller applies the time window.
pub(crate) fn verify(jws: &str, keys: &[PinnedKey], e: &Expect) -> Result<Lease, VerifyError> {
    let p = jose::verify_platform(jws, LEASE_TYP, keys)?;
    if CLAIMS.iter().any(|c| !p.contains_key(*c)) {
        return Err(VerifyError::Claims);
    }
    let org = match p.get("org") {
        Some(Value::Null) => None,
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => return Err(VerifyError::Claims),
    };
    let jkt = p
        .get("cnf")
        .and_then(|c| c.get("jkt"))
        .and_then(Value::as_str)
        .ok_or(VerifyError::Claims)?;
    let lease = Lease {
        lease_id: string(&p, "lease_id")?.to_owned(),
        sub: string(&p, "sub")?.to_owned(),
        org,
        device_id: string(&p, "device_id")?.to_owned(),
        product: Product::from_id(string(&p, "product")?).ok_or(VerifyError::Product)?,
        features: strings(&p, "features")?,
        entitlement_ids: strings(&p, "entitlement_ids")?,
        nbf: int(&p, "nbf")?,
        iat: int(&p, "iat")?,
        exp: int(&p, "exp")?,
        policy_version: string(&p, "policy_version")?.to_owned(),
        jws: jws.to_owned(),
    };
    let installation_id = string(&p, "installation_id")?;
    let nonce = string(&p, "nonce")?;
    if lease.lease_id.is_empty() || lease.policy_version.is_empty() {
        return Err(VerifyError::Claims);
    }
    if string(&p, "iss")? != e.issuer {
        return Err(VerifyError::Issuer);
    }
    if string(&p, "aud")? != e.audience {
        return Err(VerifyError::Audience);
    }
    if lease.product != e.product {
        return Err(VerifyError::Product);
    }
    if !lease
        .features
        .iter()
        .all(|f| catalog::belongs_to(f, e.product))
    {
        return Err(VerifyError::Feature);
    }
    if lease.sub != e.sub {
        return Err(VerifyError::Subject);
    }
    if lease.org.as_deref() != e.org {
        return Err(VerifyError::Org);
    }
    if installation_id != e.installation_id {
        return Err(VerifyError::Installation);
    }
    if jkt != e.jkt {
        return Err(VerifyError::KeyBinding);
    }
    if lease.device_id != e.device_id {
        return Err(VerifyError::Device);
    }
    if e.nonce.is_some_and(|n| n != nonce) {
        return Err(VerifyError::Nonce);
    }
    if !(lease.iat <= lease.nbf && lease.nbf < lease.exp && lease.exp - lease.iat <= MAX_WINDOW) {
        return Err(VerifyError::Validity);
    }
    log::info!("lease {} verified", lease.lease_id);
    Ok(lease)
}

impl Lease {
    /// `nbf - 300 s <= now < exp` (§8, §9 step 11).
    pub(crate) fn window(&self, now: i64) -> Result<(), VerifyError> {
        if now < self.nbf - time::SKEW {
            Err(VerifyError::NotYetValid)
        } else if now >= self.exp {
            Err(VerifyError::Expired)
        } else {
            Ok(())
        }
    }

    /// Step 12: the response copies equal the signed claims.
    pub(crate) fn check_copies(&self, c: &Copies) -> Result<(), VerifyError> {
        let set = |v: &[String]| v.iter().cloned().collect::<BTreeSet<_>>();
        if set(c.entitlement_ids) != set(&self.entitlement_ids)
            || set(c.rights) != set(&self.features)
            || time::parse_rfc3339(c.offline_valid_until) != Some(self.exp)
            || c.policy_version != self.policy_version
        {
            return Err(VerifyError::CopyMismatch);
        }
        Ok(())
    }
}

//! Offline verification of PI's device lease (lease.md §4, §9; ADR 0012).
use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::{PinnedKey, Product, VerifyError, jose, pi_device::compose_features, time};

pub(crate) const LEASE_TYP: &str = "pi-lease+jwt";
const MAX_WINDOW: i64 = 7_776_000;
const CLAIMS: [&str; 15] = [
    "iss",
    "jti",
    "sub",
    "org",
    "tenant",
    "product",
    "device",
    "cnf",
    "features",
    "policy_version",
    "nonce",
    "iat",
    "nbf",
    "exp",
    "aud",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Lease {
    /// `jti`.
    pub lease_id: String,
    pub sub: String,
    pub org: String,
    /// `device`.
    pub device_id: String,
    pub tenant: String,
    pub product: Product,
    /// `<product>.<code>`, without PI's internal codes.
    pub features: Vec<String>,
    pub nbf: i64,
    pub iat: i64,
    pub exp: i64,
    /// `<planCode>@<planVersion>`, or empty.
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
    pub jkt: &'a str,
    pub device_id: &'a str,
    pub nonce: Option<&'a str>,
}

/// Unsigned copies in an activation or refresh response (§9 step 12).
pub(crate) struct Copies<'a> {
    /// Absent from a refresh response.
    pub entitlement_id: Option<&'a str>,
    /// Bare PI codes, composed like `features` before comparing.
    pub rights: &'a [String],
    pub offline_valid_until: &'a str,
    pub policy_version: &'a str,
    pub lease_id: &'a str,
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
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => return Err(VerifyError::Claims),
    };
    let jkt = p
        .get("cnf")
        .and_then(|c| c.get("jkt"))
        .and_then(Value::as_str)
        .ok_or(VerifyError::Claims)?;
    let codes = strings(&p, "features")?;
    let mut lease = Lease {
        lease_id: string(&p, "jti")?.to_owned(),
        sub: string(&p, "sub")?.to_owned(),
        org,
        device_id: string(&p, "device")?.to_owned(),
        tenant: string(&p, "tenant")?.to_owned(),
        product: Product::from_id(string(&p, "product")?).ok_or(VerifyError::Product)?,
        features: Vec::new(),
        nbf: int(&p, "nbf")?,
        iat: int(&p, "iat")?,
        exp: int(&p, "exp")?,
        policy_version: string(&p, "policy_version")?.to_owned(),
        jws: jws.to_owned(),
    };
    let nonce = string(&p, "nonce")?;
    if lease.lease_id.is_empty() {
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
    lease.features = compose_features(e.product, &codes)?;
    if lease.sub != e.sub {
        return Err(VerifyError::Subject);
    }
    if Some(lease.org.as_str()) != e.org {
        return Err(VerifyError::Org);
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
        let rights =
            compose_features(self.product, c.rights).map_err(|_| VerifyError::CopyMismatch)?;
        if set(&rights) != set(&self.features)
            || c.entitlement_id.is_some_and(|t| t != self.tenant)
            || time::parse_rfc3339(c.offline_valid_until) != Some(self.exp)
            || c.policy_version != self.policy_version
            || c.lease_id != self.lease_id
        {
            return Err(VerifyError::CopyMismatch);
        }
        Ok(())
    }
}

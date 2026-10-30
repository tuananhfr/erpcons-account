//! Messages the device signs for PI's activate and refresh, and the feature-code rules
//! around them.
use crate::VerifyError;

/// Codes PI uses for its own bookkeeping; they never become client features.
pub(crate) const INTERNAL_CODES: [&str; 2] = ["offline", "offline-extended"];

pub(crate) fn activate_message(
    challenge_id: &str,
    nonce: &str,
    installation_id: &str,
    product_id: &str,
) -> String {
    format!("pi-device-activate\n{challenge_id}\n{nonce}\n{installation_id}\n{product_id}")
}

pub(crate) fn refresh_message(device_id: &str, timestamp: i64, nonce: &str) -> String {
    format!("pi-license-refresh\n{device_id}\n{timestamp}\n{nonce}")
}

/// `^[A-Za-z0-9_-]{16,128}$`
pub(crate) fn is_nonce(s: &str) -> bool {
    (16..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `^[a-z0-9][a-z0-9_-]{1,63}$`
pub(crate) fn is_feature_code(s: &str) -> bool {
    let b = s.as_bytes();
    (2..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// PI feature codes to `<pi_product>.<code>`, keeping the input order.
pub(crate) fn compose_features(
    pi_product: &str,
    codes: &[String],
) -> Result<Vec<String>, VerifyError> {
    let mut features = Vec::with_capacity(codes.len());
    for code in codes {
        if !is_feature_code(code) {
            return Err(VerifyError::Feature);
        }
        if !INTERNAL_CODES.contains(&code.as_str()) {
            features.push(format!("{pi_product}.{code}"));
        }
    }
    Ok(features)
}

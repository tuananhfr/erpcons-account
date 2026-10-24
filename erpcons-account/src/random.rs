use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::Error;

pub(crate) fn bytes<const N: usize>() -> Result<[u8; N], Error> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| Error::Internal(e.to_string()))?;
    Ok(b)
}

/// 32 random bytes, base64url: PKCE verifier, `state`, `nonce`.
pub(crate) fn token() -> Result<String, Error> {
    Ok(URL_SAFE_NO_PAD.encode(bytes::<32>()?))
}

pub(crate) fn uuid_v4() -> Result<String, Error> {
    let mut b = bytes::<16>()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
}

/// Uniform in `0..=max_ms`, for full-jitter backoff.
pub(crate) fn below(max_ms: u64) -> u64 {
    let r = bytes::<8>().map(u64::from_le_bytes).unwrap_or(0);
    r % max_ms.saturating_add(1)
}

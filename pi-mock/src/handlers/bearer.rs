//! Access-token check of PI's `BearerAccessCheck`: a valid PI ID JWT with `pi-platform` in
//! `aud`, then account status, route scope and the token's organization, in that order.
use serde_json::Value;

use crate::{
    http::{Req, Resp},
    jwt,
    state::{Auth, State},
};

/// PI's audience for its own API (`IdMeta::AUDIENCE`).
pub(crate) const AUDIENCE: &str = "pi-platform";

pub(crate) enum Denied {
    Unauthenticated,
    Locked,
    Scope(String),
    Membership,
}

impl Denied {
    /// PI's envelope; a missing or bad token is a bare 401 without `code`.
    pub(crate) fn pi(&self) -> Resp {
        match self {
            Self::Unauthenticated => Resp::pi_status(401),
            Self::Locked => {
                Resp::pi_error(403, "Tài khoản PI ID đã bị khoá.", Some("ACCOUNT_LOCKED"))
            }
            Self::Scope(scope) => Resp::pi_error(
                403,
                &format!("Access token không có phạm vi {scope}."),
                Some("INSUFFICIENT_SCOPE"),
            ),
            Self::Membership => Resp::pi_error(
                403,
                "Bạn không còn là thành viên hoạt động của tổ chức trong token.",
                Some("MEMBERSHIP_INACTIVE"),
            ),
        }
    }
}

pub(crate) fn check(st: &State, req: &Req, scope: &str) -> Result<Auth, Denied> {
    let token = req
        .header("Authorization")
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(Denied::Unauthenticated)?;
    let claims = jwt::verify(token.trim(), st.now(), "JWT", &st.scenario.signing_keys)
        .ok_or(Denied::Unauthenticated)?;
    let audience_ok = match &claims["aud"] {
        Value::String(a) => a == AUDIENCE,
        Value::Array(list) => list.iter().any(|a| a == AUDIENCE),
        _ => false,
    };
    let user_id = claims["sub"]
        .as_str()
        .filter(|_| audience_ok)
        .ok_or(Denied::Unauthenticated)?;
    let user = st.user(user_id).ok_or(Denied::Unauthenticated)?;
    if user.suspended {
        return Err(Denied::Locked);
    }
    let granted = claims["scope"].as_str().unwrap_or_default();
    if !granted.split(' ').any(|s| s == scope) {
        return Err(Denied::Scope(scope.to_owned()));
    }
    let org = claims["org_context"].as_str().map(str::to_owned);
    if org
        .as_deref()
        .is_some_and(|o| !st.membership_active(user_id, o))
    {
        return Err(Denied::Membership);
    }
    Ok(Auth {
        user_id: user_id.to_owned(),
        org,
        scope: granted.to_owned(),
        client_id: claims["azp"].as_str().unwrap_or_default().to_owned(),
    })
}

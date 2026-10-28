//! `GET /api/v1/id/me` of PI ID mapped to Office's identity model (ADR 0011).
use serde::Deserialize;

use crate::{
    Error,
    status::{Membership, MembershipStatus},
};

/// Identity, memberships and organization context of the access token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Me {
    pub user_id: String,
    pub display_name: String,
    pub email: Option<String>,
    /// PI account status `LOCKED`.
    pub locked: bool,
    /// `orgContext` of the access token; `None` is the personal context.
    pub org_context: Option<String>,
    pub memberships: Vec<Membership>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Body {
    ok: Option<bool>,
    user: User,
    #[serde(default)]
    organizations: Vec<Organization>,
    org_context: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    id: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    status: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Organization {
    id: String,
    #[serde(default)]
    name: String,
    my_role: Option<String>,
    my_status: Option<String>,
}

/// Parses PI's `{ok, user, organizations, orgContext, scopes, meta}`.
pub(crate) fn parse(body: &[u8]) -> Result<Me, Error> {
    let b: Body = serde_json::from_slice(body).map_err(|e| Error::BadResponse(e.to_string()))?;
    if b.ok == Some(false) || b.user.id.is_empty() {
        return Err(Error::BadResponse("/me without a user".into()));
    }
    let memberships = b
        .organizations
        .into_iter()
        .filter(|o| !o.id.is_empty())
        .filter_map(|o| {
            // PI lists ACTIVE and SUSPENDED memberships only; anything else is not usable.
            let status = match o.my_status.as_deref() {
                Some("ACTIVE") => MembershipStatus::Active,
                Some("SUSPENDED") => MembershipStatus::Suspended,
                _ => return None,
            };
            Some(Membership {
                org_id: o.id,
                name: o.name,
                role: o.my_role.unwrap_or_default(),
                status,
            })
        })
        .collect();
    Ok(Me {
        locked: b.user.status == "LOCKED",
        user_id: b.user.id,
        display_name: b.user.display_name,
        email: Some(b.user.email).filter(|e| !e.is_empty()),
        org_context: b.org_context.filter(|o| !o.is_empty()),
        memberships,
    })
}

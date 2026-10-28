//! PI's end-user API under `/api/v1/id/` (`IdApiController`); only `/me` is served.
use serde_json::{Value, json};

use super::bearer;
use crate::{
    crypto,
    http::{Req, Resp},
    state::State,
};

/// Fixed creation time of the mock's accounts and organizations (2026-01-01).
const CREATED: i64 = 1_767_225_600;

/// `GET /api/v1/id/me` (scope `openid`): `email` comes whatever the scopes, as in PI.
pub(super) fn me(st: &State, req: &Req) -> Resp {
    let auth = match bearer::check(st, req, "openid", false) {
        Ok(a) => a,
        Err(denied) => return denied.pi(),
    };
    let Some(user) = st.user(&auth.user_id) else {
        return Resp::pi_status(401);
    };
    let created = crypto::rfc3339(CREATED);
    let mut orgs: Vec<_> = user
        .memberships
        .iter()
        .filter(|m| {
            m.status.eq_ignore_ascii_case("ACTIVE") || m.status.eq_ignore_ascii_case("SUSPENDED")
        })
        .collect();
    orgs.sort_by(|a, b| a.name.cmp(&b.name));
    let organizations: Vec<Value> = orgs
        .iter()
        .map(|m| {
            json!({
                "id": m.org_id,
                "name": m.name,
                "type": "company",
                "country": "VN",
                "domain": "",
                "taxCode": "",
                "verification": "UNVERIFIED",
                "verifyMethod": "",
                "verifiedAt": null,
                "verifiedByName": "",
                "verifyNote": "",
                "requireMfa": false,
                "customer": { "id": "", "code": "" },
                "memberCount": 1,
                "myRole": m.role,
                "myStatus": m.status.to_ascii_uppercase(),
                "createdAt": created,
            })
        })
        .collect();
    let scopes: Vec<&str> = auth.scope.split(' ').collect();
    Resp::pi_ok(
        200,
        json!({
            "user": {
                "id": user.user_id,
                "email": user.email.clone().unwrap_or_default(),
                "displayName": user.display_name,
                "country": "VN",
                "profession": "",
                "status": if user.suspended { "LOCKED" } else { "ACTIVE" },
                "lockReason": "",
                "emailVerifiedAt": user.email.as_ref().map(|_| created.clone()),
                "phoneMasked": "",
                "phoneVerifiedAt": null,
                "lastLoginAt": null,
                "createdAt": created,
                "hasPassword": false,
                "passwordChangedAt": null,
            },
            "organizations": organizations,
            "orgContext": auth.org,
            "scopes": scopes,
            // PI sends its label dictionaries (`IdMeta::toApi`); no client reads them.
            "meta": {},
        }),
    )
}

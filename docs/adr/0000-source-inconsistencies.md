# ADR 0000: Inconsistencies in the PI spec package

Status: Proposed (resolutions for the PI Platform team to confirm)

## Context

The PI Holding spec package V3 (HS01 to HS07; base text, "Phụ lục V2" and "Phụ lục V3") states
the same contract in several places with different names, fields and numbers. The consumer
contract must pick one reading and say so. This list covers what affects the contract or the
Office client; other items are flagged for their owning team.

## Resolutions

| # | Sources | Conflict | Resolution |
|---|---|---|---|
| 1 | HS02 "API & kiểm thử" vs HS02 V2 "Hợp đồng kích hoạt" | Two `POST /v1/devices/activate` contracts. V1: `installation_id, product_id, app_version, device_public_key -> device_id, offline_lease`. V2: `installation_id, product_id, platform, client_version, signed_challenge -> entitlement_id, rights, offline_valid_until, policy_version, signature` | V2 (ADR 0003). `app_version` becomes `client_version`; the device public key travels in the `jwk` header of `signed_challenge`; `device_id` is added to the V2 response because refresh needs it; a challenge endpoint `POST /v1/devices/challenges` is added because V2 needs a server nonce |
| 2 | HS02 V2 | `signature` is listed without saying what it signs | `lease`: a compact JWS whose signature covers every lease claim (`lease.md` §4). `entitlement_id`, `rights`, `offline_valid_until`, `policy_version` remain as unsigned copies that must equal the claims |
| 3 | HS02 V2 vs HS02 "Thiết bị" and HS02-V3-01 | V2 returns one `entitlement_id` with plural `rights`; the entitlement model has one `feature` per entitlement | `entitlement_ids` (array) in the response and the lease |
| 4 | HS02 V2 vs HS02 "Offline license" | `rights` vs `features` | HTTP response copy keeps `rights`; the lease claim is `features`; same set, checked by the client (`lease.md` §9 step 12) |
| 5 | HS02 "Thiết bị" vs HS02-V3-01 vs HS02 API | Entitlement fields: `product, feature, scope, quota, seats, valid_from/to, offline_allowed, policy_version` vs `subject, product, feature, limit, expiry` vs response `features, quotas, policy_version` | The first list. `subject` is `scope` + `org_id` (and the token `sub`), `limit` is `quota`, `expiry` is `valid_to`. Added `entitlement_id`, `product_id`, `org_id`, `offline_days`. The response is a list of entitlements |
| 6 | HS02 API vs HS02-V3-03 | `GET /v1/entitlements?product_id=` vs `GET /v1/me/entitlements` | `GET /v1/me/entitlements?product_id=` |
| 7 | HS02 "Offline license" vs HS02-V3-04 vs HS02 V2 | Lease fields `subject, device binding, features, nonce, issued_at, expires_at` vs `device key, product, feature, nbf/exp` vs `offline_valid_until` | JWT claims `sub`, `cnf.jkt`, `features`, `nonce`, `iat`, `exp`, plus `nbf`, `product`; `offline_valid_until` = `exp` |
| 8 | HS02 "Thiết bị" vs HS02-V3-04 | Offline window "30 days default, 90 for construction sites by plan" vs "7/30/90 configurable" | 7, 30 or 90 days, default 30, per entitlement `offline_days` (`lease.md` §5) |
| 9 | HS05 "Hợp đồng chung" vs HS05 V2 vs HS02 V2 vs HS02-V3-03 | Error sets 400/401/403/409/412/422/429/503 vs 401/403/409/429 vs 401/403/409/429 vs 401/403/409/422/429 | The HS05 set, no other status. RFC 9457 bodies with `code` |
| 10 | HS05 vs HS02 V2 | 429 means "quota" vs "overload" | Two codes on 429: `rate_limited`, `quota_exceeded` |
| 11 | HS02 V2 | 403 = "no right" on activation | 403 = not allowed to activate (`membership_inactive`, `user_suspended`, `device_revoked`). A user without entitlements activates and gets empty `rights` (ADR 0004) |
| 12 | HS05 | `412 version_mismatch` undefined | `client_version_unsupported`: `client_version` below the platform minimum |
| 13 | HS05 "Hợp đồng chung" vs HS02-V3-03, HS05-V3-01 | API tracing id `trace_id` vs `correlation_id` | HTTP uses `X-Correlation-Id` and `correlation_id`; the platform may log it as `trace_id` |
| 14 | HS05 vs RFC 9068 | Token claim `scopes` vs standard `scope` | `scope` (space-delimited). Office never reads access tokens |
| 15 | HS05 | `org_context` claim exists but how it is chosen is not stated | Chosen with an `org_context` parameter on the authorization request and the refresh grant (ADR 0008) |
| 16 | HS05 V2 IDs | Both `org_id` and `tenant_id`, relation undefined | The contract uses `org_id` only |
| 17 | HS02 "Thiết bị" vs HS02-V3-01 | Device `device_id, installation_id, user_id, org_id, product_id, version, last_seen, status` vs `Device(id, user_id, public_key)` | One device record per (`installation_id`, `sub`, `org_context`) holding the key thumbprint, shared by the four desktop apps (ADR 0010); one lease per `product_id` on it; `platform` and `client_version` reported at each activation and refresh |
| 18 | HS02 "Thiết bị" vs HS02 V2 | "No signing key in the application" vs a device that signs a challenge | "Signing key" means the platform licence-signing key, which the client never holds. The device key is the device's own and lives in the OS credential store, as HS02 V2 "Bảo vệ dữ liệu" requires |
| 19 | HS02 "Đăng ký" and HS02-V3-02 vs owner decision | "First run activates PI ID" and a flow where install leads to OIDC sign-in | Owner decision: sign-in is optional; first run does not ask for it (ADR 0001) |
| 20 | HS01 "Phạm vi" | Rights axis Guest / PI ID / Pro / Enterprise vs catalog tiers | Guest and PI ID are sign-in states; Pro and Enterprise are entitlements (`personal` or `organization` scope); tier `pro` means "requires an entitlement" |
| 21 | HS02 V2 "Bảo vệ dữ liệu" | Requires the OS credential store; web has none | Web storage per ADR 0006 |
| 22 | HS03 base vs HS03-V3-03 | Tenant leakage is SEV1 vs SEV0 | SEV0 (later and stricter). Office discards and logs responses that carry another tenant's data (`products.md` §4) |
| 23 | HS03 base vs HS03 V2 vs HS03-V3-02 | Three `sync success` formulas: successful completed / completed, completed / eligible, ok / completed | Not used by Office (no sync). Flagged to Team D (Quality) |
| 24 | HS05 base vs HS05-V3-05 vs HS07 | Gates G0 to G7 (G2 parallel build with mocks, G7 production) vs G0 to G6 (G2 unit, G6 controlled release) vs G0 to G6 (certification) | Gates are cited with their document, e.g. "HS05-V3 G1". This deliverable is G1 (contracts and ADRs) in both HS05 numberings; HS07 gates are certification steps and unrelated |
| 25 | HS03 "Hợp đồng sự kiện" vs HS05-V3-01 | Event envelope `event_type, tenant_ref, device_ref, trace_id, release_id, ...` vs `type, tenant, correlation_id, ...` | Office emits no events in this phase. Flagged to Team A and Team D |

## Consequences

The contract deviates from the letter of HS02 V2 in items 1 to 4 and 11; each deviation keeps the
V2 field names where a value has the same meaning. The PI Platform team must confirm or reject
each row before G3 (integration).

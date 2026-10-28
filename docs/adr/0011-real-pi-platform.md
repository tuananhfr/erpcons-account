# ADR 0011: Connecting to the real PI Platform

Status: Accepted (owner decisions of 28/10/2026). Supersedes, where they differ, the OIDC and
identity parts of `contract.openapi.yaml`, ADR 0008, and the "every signed-in desktop app
activates" rule of ADR 0004. Leaves `lease.md` and the licensing parts of the contract as they are,
but turned off.

## Context

The contract in `docs/` was written before PI Platform existed. PI is now built (`pi_id`,
`pi_api`, `pi_device`, read at `main` b574e80) and differs from it in paths, bodies, error
format, organization switching and the whole device protocol. Office adapts to PI; PI is not
changed for Office. What PI must still do is listed in the workspace note
`tmp/briefs/pi-connect/de-nghi-pi-platform.md` (evidence with file:line in `gap-desktop.md` and
`gap-web.md` next to it).

## Decision

### What PI does and how the library maps it

| Topic | Contract (before) | Real PI | Library |
|---|---|---|---|
| OIDC endpoints | `/authorize`, `/token`, `/revoke`, `/jwks` | `/id/authorize`, `/id/token`, `/id/revoke`, `/id/userinfo`, `/id/logout`, `/id/jwks.json` | Unchanged: taken from discovery (`/.well-known/openid-configuration`). Discovery has no CORS at PI; only the web client cares |
| PKCE, loopback | S256, `http://127.0.0.1:{port}/callback` | S256 mandatory, challenge `^[A-Za-z0-9_-]{43}$`; registered `http://127.0.0.1/callback` matches any port | Unchanged |
| Access token | opaque | EdDSA JWT, header `{alg, typ, kid}`, `aud ["pi-platform"(, product)]`, `azp`, `scope`, `org_context`, 10 min | Still opaque to the library: it reads identity and context from `/me`, never from the token |
| ID token | `iss`, `aud`, `exp`, `nonce`, `sub` | Same claims plus `auth_time`, `amr`, profile claims; no `org_context` | Unchanged check |
| Refresh | rotation; `org_context` parameter switches organization | rotation, reuse revokes the family; no `org_context`, the organization is fixed per family; refresh token only with `offline_access` | The refresh grant sends no organization |
| Identity | `GET /v1/me`, snake_case | `GET /api/v1/id/me` (scope `openid`): `{ok, user{id, displayName, email, status ACTIVE/LOCKED}, organizations[{id, name, myRole, myStatus ACTIVE/SUSPENDED}], orgContext, scopes, meta}` | `me.rs` maps it; `LOCKED` signs out like `user_suspended`; `orgContext` is the active organization |
| Errors | RFC 9457, lowercase `code` | `{ok:false, message, code?}`, UPPERCASE codes; 401 has no code; unexpected failures are a bare 500 with `correlationId` | `ApiCode::from_parts`: `ACCOUNT_LOCKED` → `UserSuspended`, `MEMBERSHIP_INACTIVE` → `MembershipInactive`, `INSUFFICIENT_SCOPE` → `InsufficientScope`, `DEVICE_CAP` → `DeviceCapReached`, `DEVICE_REVOKED` → `DeviceRevoked`, `CHALLENGE_INVALID` → `ChallengeInvalid`, `IDEMPOTENCY_MISMATCH` → `IdempotencyKeyReused`; 500 and 502–504 → `DependencyUnavailable` (transient). Lowercase contract codes still map |
| Switch organization | refresh grant with `org_context` | `org_hint` (org UUID) on `/id/authorize` only | `select_org(Some(id), open_browser)` runs the authorization again with `org_hint` |
| Back to personal | `org_context=personal` | PI shows its organization page (with a "personal" choice) when the user has ≥ 2 active organizations, or ≥ 1 and `prompt=select_account` (`OidcController::afterLogin`) | `select_org(None, open_browser)` sends `prompt=select_account`; the user picks "personal" |
| Sign-out | revoke | revoke; PI's browser session lives 12 h | The next sign-in after a sign-out sends `prompt=login` (flag kept in `session.json`) |
| Entitlements, catalog | `/v1/me/entitlements`, signed `/v1/products/{p}/feature-catalog` | entitlements of every organization in personal context; no catalog endpoint | Not called; the built-in catalog decides `allowed()` |

`Config::api_base` is now the base of PI's end-user API (`/me` below it), default
`{issuer}/api/v1/id`. When `select_org` ends in another context than the one asked for, the session
keeps the context PI granted and the call returns `OrgUnavailable`; when another PI user signed in
on the browser page, the new tokens are revoked and the session is unchanged. Tokens replaced by a
new authorization are revoked.

### Offline licensing is turned off (deviation from ADR 0004)

Desktop apps no longer activate after sign-in. PI has no Office product (its activation answers
422), its lease `nonce` is random rather than the request's, so a lease cannot be bound to the
activation that asked for it (`lease.md` §9 step 10), and its key rotation signs with a new key at
once. Removing those checks would weaken the lease, so the activation, lease, revocation and
catalog code stays as it is, in the Office contract's wire format at `{issuer}/v1/...`, behind
`Config::offline_licensing` (default `false`). While it is off no device or licence endpoint is
called, `retry_activation()` does nothing, the licence is `NotActivated`, and `pro` features are
denied (every Office feature is `free` today). Turning it on against the real PI does not work: PI's
device protocol (challenge, raw-signature proof, camelCase bodies, per-product devices, lease
claims; `gap-desktop.md` #21–#44) must be implemented first, after PI items 4–6.

### pi-mock follows PI

pi-mock reproduces PI's code: the paths and bodies above, PI's envelope and messages, EdDSA access
and ID tokens with PI's header and claim order, `/id/jwks.json`, discovery without CORS, CORS on
`/id/token`, `/id/revoke`, `/id/userinfo` and `/api/v1/id/*` for registered redirect origins only,
`X-Correlation-Id` echoed on `/api/` when it is 8–64 letters, digits or dashes, `org_hint` and the
organization page (`Scenario::org_choice`), authorization codes of 60 s that a PKCE mismatch does
not burn, code and refresh reuse revoking the family, and refresh tokens only with
`offline_access`. Its user and organization ids are UUIDs. The Office contract's licensing
endpoints stay under `/v1/`, in RFC 9457 format, marked as not PI, so the code behind
`offline_licensing` remains tested. Not modelled: PI's login, consent, MFA, invitation pages and
the D511 product gate.

## Consequences

- Breaking API change: `Account::select_org(org, open_browser)` opens the browser and blocks like
  `sign_in`. Crate version 0.2.0.
- Switching organization needs the browser (PI may skip its page when its own session is alive).
- A membership turned inactive makes the whole token family unusable; the library asks for a new
  sign-in instead of moving to personal.
- The web client cannot read discovery from the browser; it configures PI's endpoints.

## Waiting for PI (`de-nghi-pi-platform.md`)

1. Register the two Office clients (no `product`), give the production issuer and a staging PI.
2. Answer whether Office Online goes through the D511/D525 product tick; then clients may gain a
   product and `aud` its code.
3. Add the Office product(s) to `ProductRegistry` (activation answers 422 today).
4. Bind the lease `nonce` to the request; agree a key-rotation procedure that publishes a key
   before it signs.
5. For paid plans: personal entitlements, personal context without every organization's rights, a
   signed feature catalog.

Items 3–5 are needed before `offline_licensing` and the entitlement list are used again.

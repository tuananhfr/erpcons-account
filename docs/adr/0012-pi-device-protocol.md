# ADR 0012: PI's device protocol and lease claims

Status: Accepted (owner decisions of 29/10/2026). Supersedes ADR 0011's "Offline licensing is
turned off" reasoning for the wire: the client now speaks PI's real device protocol. Office is
unchanged because `Config::offline_licensing` stays off for it.

## Context

ADR 0011 left the Office-contract licensing code (`/v1/...`) in place because PI's device protocol
differed. PI has since shipped a product (`ubotbuild`) with seats, devices and leases, so UbotCAD
needs the real wire. Only checks that PI cannot reasonably satisfy changed; every security check
stayed.

## Decision

### Wire (all under `{api_base}`, scope `pi.devices`)

- `GET /devices/challenge?product_id=` returns 201 `{challengeId, nonce, expiresAt}`; any 2xx is
  accepted and the nonce must match `^[A-Za-z0-9_-]{16,128}$`.
- `POST /devices/activate` takes 7 camelCase keys (`installationId`, `productId`, `platform`,
  `clientVersion`, `devicePublicKey`, `challengeId`, `signedChallenge`), never `label`. The signature is a raw
  Ed25519 signature over `pi-device-activate\n{challengeId}\n{nonce}\n{installationId}\n{productId}`
  (UTF-8, no trailing newline). The reply is 201 with `deviceId`, `entitlementId`, `rights`,
  `offlineValidUntil`, `policyVersion`, `leaseId` and `lease`.
- `POST /licenses/refresh` takes `{deviceId, timestamp, signature, nonce}` with no challenge. The
  client always sends a nonce, so the signed message is
  `pi-license-refresh\n{deviceId}\n{timestamp}\n{nonce}`. The reply has no `entitlementId`.
- `GET /me/entitlements?product_id=` is called only in an organization context. A row counts when it
  is ALLOW with a seat for this product and organization.

### Lease claims and checks

The 15 PI claims replace the contract's: `lease_id` is `jti`, `device_id` is `device`, `cnf.jkt` is
`b64url(SHA-256(raw 32-byte key))`, and `org` is a non-empty string.

- Kept: pinned-kid signature with strict 3-member header and `typ pi-lease+jwt`; `iss`; `aud` ==
  client id; `product`; `sub`; `org`; `cnf.jkt` binding; `device`; `nonce` at activation and
  refresh; `iat <= nbf < exp` within 90 days; trusted-time window; response copies; sealed files.
- Replaced: the `installation_id` claim (the key is bound by `cnf.jkt`); `entitlement_ids` (PI has
  `tenant`, compared with `entitlementId` only when present); `<product>.<name>` features (bare PI
  codes are validated, then composed); non-empty `policy_version` (may be `""`); RFC 7638 thumbprint.
- PI-internal codes `offline` and `offline-extended` are dropped from features.
- Features are `ubotbuild.cad-view`, `ubotbuild.cad-export` and `ubotbuild.cad-use`.

### Behaviour

- Refresh timestamp comes from server time (client clock plus an in-memory offset from the `Date`
  header), at least one past the last sent. It is persisted before every send, and undone on a 422
  `errors.timestamp` so the retry recomputes it. Body, nonce and idempotency key are rebuilt per send.
- A 409 `DEVICE_REVOKED` at refresh wipes every lease and sets the session-wide revoked flag. The
  client does not reactivate: a machine that was deactivated stays off until the user signs in again.
- `device_revoked` and `device_cap_reached` stay session-wide flags. A 404 at refresh forgets this
  product's device and activates once.
- 403 `NO_ENTITLEMENT` / `NO_SEAT` / `ORG_CONTEXT_REQUIRED` give `LicenceState::NotEntitled`; the
  client never activates in a personal context.
- One device id per product (`device_ids` in `session.json`); a lease without its id is deleted.
- The feature catalog is not fetched; built-in tiers decide `allowed()`. Loading a cached signed
  catalog from disk is kept for a future PI signed catalog.
- All public `ApiCode` variants stay, including ones PI no longer produces.
- State written by 0.3.0 (old lease, `device_id`) is discarded on upgrade; users activate again.

## Consequences

- Breaking: `LicenceState::NotEntitled`; `ApiError.errors` is `Box<[String]>`; UbotBuild feature ids;
  pi-mock `Scenario` uses `Tenant`. Crate version 0.4.0.
- Office keeps `offline_licensing` off; PI has no Office product, so nothing there changes.
- Revocation is observed only at refresh (at least every 12 h online); there is no push.

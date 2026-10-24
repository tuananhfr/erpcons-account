# Lease, device proof and trusted time

Scope: the desktop apps. Web never activates and never holds a lease (ADR 0004). Field names
match `contract.openapi.yaml` exactly. MUST/SHOULD/MAY as in RFC 2119.

A lease is a platform-signed statement: user `sub`, in context `org`, may use `features` of
`product` on the device that holds the key `cnf.jkt`, until `exp`. It is what lets a `pro`
feature work offline (HS02). Free features never need a lease (ADR 0005).

## 1. Objects

| Object | Signed by | `typ` | Where |
|---|---|---|---|
| Device proof | device key | `pi-device-proof+jwt` | `signed_challenge` in activate and refresh requests |
| Lease | platform licence-signing key | `pi-lease+jwt` | `lease` in activate and refresh responses |
| Feature catalog | platform licence-signing key | `pi-feature-catalog+jwt` | `catalog` in the feature catalog response (`products.md` §3) |

## 2. JOSE profile

Applies to all three objects.

- Compact serialization (RFC 7515 §7.1), at most 8 KiB.
- `alg` is exactly `EdDSA` with an Ed25519 key (RFC 8037). Every other value, including `none`,
  is rejected. RFC 9864 registers the fully specified `Ed25519`; switching to it is a one-constant
  change on both sides (open question for the platform).
- `typ` is exactly the value in §1 (explicit typing, RFC 8725 §3.11), so a catalog can never be
  accepted as a lease or a proof as either.
- Platform-signed headers contain exactly `alg`, `kid`, `typ`. `jku`, `x5u`, `jwk`, `x5c`, `crit` and
  unknown members are rejected: the verification key comes only from the pinned set (§10).
- Signatures are verified strictly (RFC 8032 §5.1.7: reject non-canonical `S` and small-order
  keys; `ed25519-dalek` `verify_strict`, as `erpcons-update` does).
- The payload is one JSON object in UTF-8; duplicate member names are rejected. Times are
  NumericDate integer seconds.

## 3. Device proof (`signed_challenge`)

The device key is an Ed25519 key pair created, together with a random UUIDv4 `installation_id`, at
the first sign-in on a machine with an OS credential store. There is one pair per OS user and
machine, shared by the four desktop apps (ADR 0010): the device is registered once and each app
gets its own lease for its `product_id`. The private key stays in the OS credential store (§11); it
is never sent, exported or logged, and it survives sign-out so that signing in again reuses the
device.

Header: `alg` `EdDSA`, `typ` `pi-device-proof+jwt`, `jwk` with exactly `kty` `OKP`, `crv`
`Ed25519`, `x` (public key; never `d`). The platform takes the device public key from this header;
there is no separate `device_public_key` field.

| Claim | Value |
|---|---|
| `nonce` | The `nonce` from `POST /v1/devices/challenges` |
| `purpose` | `activate` or `refresh`, as in the challenge request |
| `device_id` | Only with `purpose` `refresh`: the stored `device_id` |
| `installation_id`, `product_id`, `platform`, `client_version` | Same values as the request body |
| `iat` | Client clock. Informational: the server MUST NOT reject a proof because of it |

Freshness comes from the nonce: single use, 120 s, bound by the server to (`sub`, `org_context`,
`installation_id`, `product_id`, `purpose`). The server's checks are listed in the contract
(`activateDevice`, `refreshLease`).

The key thumbprint is the RFC 7638 SHA-256 thumbprint of `{"crv":"Ed25519","kty":"OKP","x":"..."}`,
base64url without padding. The server stores it and puts it in the lease as `cnf.jkt` (RFC 7800
confirmation; `jkt` member from RFC 9449 §6.1).

```
desktop app                                         PI Platform
  POST /v1/devices/challenges {purpose, installation_id, product_id}
                                                    -> 201 {nonce, expires_at}
  sign proof {nonce, purpose, ...} with device key
  POST /v1/devices/activate | /v1/licenses/refresh {..., signed_challenge}
                                                    -> 200 {device_id, ..., lease}
  verify lease (§9), store (§11)
```

## 4. Lease

Header: `alg` `EdDSA`, `kid`, `typ` `pi-lease+jwt`.

| Claim | Type | Meaning | Client check (§9) |
|---|---|---|---|
| `iss` | string | Platform issuer URL (the OIDC issuer) | Equals the pinned issuer |
| `aud` | string | `erpcons-office-desktop` | Equals |
| `lease_id` | string | Unique id of this lease | Present; logged |
| `sub` | string | `user_id` | Equals the signed-in user's `user_id` |
| `org` | string or `null` | `org_context` at issue; `null` = personal | Equals the current `org_context` |
| `device_id` | string | Device record, shared by the four apps | Equals the returned and the stored `device_id` |
| `installation_id` | UUID | Installation | Equals the local one |
| `cnf.jkt` | string | Thumbprint of the device public key (§3) | Equals the local key's thumbprint |
| `product` | product id | `vanban`, `bangtinh`, `trinhchieu` or `pdf` | Equals the app's product id |
| `features` | array of feature ids | Features usable offline; may be empty | Each matches `<product>.<name>` (`products.md` §2) |
| `entitlement_ids` | array of strings | Entitlements that contributed `features` | Informational |
| `nbf`, `iat`, `exp` | NumericDate | Validity; `exp` is the V2 `offline_valid_until` | §7, §9 |
| `nonce` | string | The challenge nonce the client signed | Equals, on receipt only |
| `policy_version` | string | Licensing policy revision that produced the lease | Present; informational |

Constraints: `iat <= nbf < exp` and `exp - iat <= 7776000` (90 days).

## 5. Offline window

The offline window is `exp - iat`: 7, 30 (default) or 90 days (HS02; 90 for construction sites,
by plan). The platform computes a lease as follows.

1. Contributing entitlements: those returned by `GET /v1/me/entitlements` for the product and the
   token's `org_context` that have `offline_allowed: true`.
2. `features` = their `feature` values; `entitlement_ids` = their `entitlement_id` values.
3. Window = the smallest `offline_days` among them; 30 days if there are none (a lease with empty
   `features` still records the activation).
4. `exp` = min(`iat` + window, earliest `valid_to` among them).

Entitlements with `offline_allowed: false` never contribute to a lease; they work through the
online path only (`products.md` §4). The client never extends a lease and rejects windows above 90
days. A single `exp` per lease is a simplification: an entitlement ending soon shortens the whole
lease, which is conservative.

## 6. Activation and refresh schedule

Activation (`POST /v1/devices/activate`) runs per app when all hold: signed in, desktop, OS
credential store available, no lease for this app's `product_id` in the current `sub` and
`org_context`. The first app to activate registers the device; the others reuse the stored
`device_id` (the server returns the same one and counts no new device). It does not run for
guests, on web, after `device_revoked` until the next sign-in, or after `device_cap_reached` until
the user retries or signs in again; both conditions are recorded in the shared session so that
the other three apps respect them too.

Refresh (`POST /v1/licenses/refresh`) runs when signed in, activated and online:

- at start-up after the access token is refreshed, then every 12 h while running;
- when `GET /v1/me/entitlements` disagrees with the lease `features`.

An organization switch, made in any app, applies to the shared session: every lease is deleted
and each app activates in the new context. Network errors, 429 and 503 keep the current lease and
retry with backoff (1 min doubling to 1 h, or `Retry-After`). Activation and refresh run under the
shared lock (§11); several processes of the same app may still refresh one after the other, and
each successful refresh yields a valid lease.

## 7. Trusted time and clock rollback

The client never trusts the wall clock alone. It keeps `trusted_floor`, the latest time any of
the four apps has observed on this installation, in the signed session file (§11). Writers take the
shared lock and store the maximum of the stored value and their own.

- At start: `floor0` = stored `trusted_floor` (0 if none); `mono0` = monotonic clock.
- `effective_now` = max(`system_now`, `floor0` + (`monotonic_now` - `mono0`), `trusted_floor`).
- After each evaluation `trusted_floor` = `effective_now`; it is persisted at most every 10 min and
  on clean exit.
- Rollback: if `system_now < effective_now - 300 s`, the clock moved backwards. The client keeps
  using `effective_now`, so a rollback never extends a lease, and records `clock_rolled_back` for
  diagnostics. Nothing else changes: free features, documents and the lease are untouched.
- Frozen clock: the monotonic term makes running time consume the lease even if the wall clock is
  frozen. Time while the app is closed is not counted in that case; this is accepted, as offline
  revocation is impossible anyway (HS02).
- Server correction: after a lease passes §9 on receipt, if `trusted_floor < iat` or
  `trusted_floor > iat + 300 s`, set `trusted_floor = iat`. This is the only way the floor goes
  down; it repairs a clock that was once set far in the future.
- A forward jump only pushes the floor forward and expires the lease early; it never grants
  anything. The next online refresh repairs it.
- Skew tolerance everywhere: 300 s.

## 8. Expiry, revocation and warnings

A lease is usable when it passed §9, its file signature is valid, the shared session holds a
refresh token for the same `sub` (not signed out), and `nbf - 300 s <= effective_now < exp`.

- Expired: the next `allowed()` call denies the `pro` features it granted. Free features and
  pinned-free view and export keep working (`products.md` §2). An action already started finishes;
  no document is closed, locked or made read-only. The expired lease stays on disk only to be
  replaced by a refresh.
- Revoked (refresh returns `status: revoked`, which concerns the device): delete every lease of
  the device, then by `reason`: `device_revoked`: also delete `device_id`, no automatic activation
  in any app until the next sign-in; `membership_revoked`: refresh tokens with
  `org_context=personal`, then activate in the personal context; `user_suspended`: sign out.
- Every lease is also deleted on sign-out, refresh-token `invalid_grant`, a different `sub`, an
  organization switch, 403 `device_unknown` (also deletes `device_id`) and 403
  `membership_inactive`. Sign-out in one app signs out all four (§11).
- A single lease is deleted when its file signature fails or it fails §9 on load.
- HS02: an offline device cannot be revoked; revocation applies at its next refresh.
- Warnings at 7, 3 and 1 days before `exp` (`exp - effective_now` at or below the threshold), only
  when the lease grants at least one feature whose current tier is `pro`; at most once per threshold
  per `lease_id`; non-modal; they ask the user to connect to renew. While every feature is free,
  no warning is ever shown.

## 9. Client verification order

On receipt (200 from activate, or 200 `status: active` from refresh):

1. The response matches its schema; `lease` is at most 8 KiB with three base64url segments.
2. Header: exactly `alg`, `kid`, `typ`; `alg` = `EdDSA`; `typ` = `pi-lease+jwt`; `kid` is pinned.
3. Strict signature check with the pinned key over the ASCII bytes `header_b64 "." payload_b64`.
   Nothing from the payload is used before this step.
4. Payload: one JSON object, no duplicate members, every claim of §4 present with its type.
5. `iss` = pinned issuer; `aud` = `erpcons-office-desktop`.
6. `product` = the app's product id; every `features` entry matches `<product>.<name>`.
7. `sub` = signed-in `user_id`; `org` = current `org_context`.
8. `installation_id` = local value; `cnf.jkt` = thumbprint of the local device public key.
9. `device_id` = the response `device_id` (on load: the stored `device_id`). On receipt, if the
   session stores a different `device_id`, the stored one is stale: replace it and delete the other
   products' leases, which name the old device.
10. `nonce` = the nonce signed in this request's proof.
11. `iat <= nbf < exp`, `exp - iat <= 7776000`; apply the §7 server correction; then
    `nbf - 300 s <= effective_now < exp`.
12. Copies agree: `entitlement_ids` and `rights` equal the claims `entitlement_ids` and `features` as
    sets, `offline_valid_until` equals `exp`, `policy_version` equals the claim.
13. Write the product's lease file atomically under the shared lock (§11), then switch the
    in-memory lease.

On load at start-up: lease file signature (§11), then steps 1 to 9 and 11 (without the §7
correction). Any failure on receipt leaves the previous lease in place and logs the
`X-Correlation-Id`; any failure on load deletes the lease (free features only until the next
refresh).

## 10. Platform keys

- Each client release embeds the platform licence-signing public keys as `kid` to 32-byte Ed25519
  constants, as `erpcons-update` embeds `ERPCONS_PUBLIC_KEY`. Leases and catalogs are never
  verified with a fetched key (JWKS), which an attacker on the network or the local machine could
  substitute.
- These keys are distinct from the OIDC ID token keys (`jwks_uri`) and from the erpcons-update
  release key.
- Rotation: the platform hands Office the next public key; Office ships it (pinned set = current +
  next); the platform signs with the next key only after at least 90 days plus release adoption, so
  every lease in circulation still verifies; a later Office release drops the old key once the
  last lease it signed has expired.
- Compromise: the platform stops using the `kid` and Office ships a release without it. Leases
  signed with it fail on load, so `pro` features stop until the next refresh; free features are
  unaffected.
- The mock's key is pinned only in development builds; release builds MUST NOT contain it (to be
  enforced by a test in the crate).

## 11. Desktop storage

The four desktop apps share one PI session per OS user (ADR 0010): signing in from any app signs
in all four, and signing out from any app signs out all four.

| Item | Location |
|---|---|
| Refresh token | OS credential store (Windows Credential Manager, macOS Keychain, Linux Secret Service), service `ERPCons Office PI`, one entry |
| Device private key and `installation_id` | Same service, one entry |
| Access token, ID token | Memory of each process only, never persisted |
| `session.json`: `user_id`, `org_context`, `device_id`, `installation_id`, `trusted_floor`, activation blocks (`device_revoked`, `device_cap_reached`) | Shared PI directory, signed with the device key |
| `lease-<product_id>.json`: `lease`, warnings shown | Shared PI directory, one file per product, signed with the device key |
| `catalog-<product_id>.jws`: verified feature catalog | Shared PI directory; re-verified with the platform key on load (also used by guests) |
| `pi.lock` | Shared PI directory: exclusive lock file |

Shared PI directory: Windows `%APPDATA%\ERPCons\PI\`, macOS
`~/Library/Application Support/ERPCons/PI/`, Linux `$XDG_CONFIG_HOME/erpcons/pi/` (default
`~/.config/erpcons/pi/`). Signed files carry a detached Ed25519 signature over their exact bytes.

- Every token refresh, activation, lease refresh, sign-in, sign-out and write to the shared
  directory or the credential entries happens under an exclusive lock on `pi.lock`, held for one
  exchange only (network timeouts 15 s, as in `erpcons-update`). After acquiring the lock a process
  re-reads the stored refresh token and `session.json` before acting, because another app may have
  rotated the token or changed the session. Only `pdfcraft` enforces a single instance today, so
  the lock also serializes several processes of one app.
- Other running apps notice changes by re-reading the credential entry and `session.json` when
  their window gains focus and before each refresh. A missing refresh token means signed out: the
  process drops its access token. A changed `user_id` or `org_context` reloads identity and leases.
- Sign-out deletes the refresh token, every lease file and the identity fields of `session.json`
  (`user_id`, `org_context`, `device_id`, activation blocks). The device key, `installation_id` and
  `trusted_floor` stay, so signing in again reuses the device.
- Without a credential store (for example no Secret Service on Linux), sign-in is still allowed
  but session-only: the refresh token lives in the memory of the app that signed in, is not shared
  with the other apps, and is lost on exit. No device key is created and no activation happens: an
  ephemeral key would register a new device at every start and exhaust the device cap. `pro`
  features use the online path only.
- Writes are atomic (temporary file, fsync, rename; as `write_json` in `erpcons-update`).

## 12. Test vectors

Generated with throwaway keys whose private halves were discarded. They are not platform keys
and MUST NOT be pinned in a release build. The JWS strings are the examples `ActivateRequest`,
`ActivationResponse`, `RefreshRequest`, `RefreshActive` and `FeatureCatalogVanban` in
`contract.openapi.yaml`; all verify with the keys below and pass §9 with issuer
`https://id.pi.invalid` at `effective_now` 2026-10-24T08:00:00Z (activation) and
2026-10-25T08:00:00Z (refresh).

- Platform key `kid` `pi-lease-example-1`: `x` `9NYv3EVAYbyMCnyywdUpJU99yTSSE44tQ_XASMni0gA`
  (hex `f4d62fdc454061bc8c0a7cb2c1d529254f7dc93492138e2d43f5c048c9e2d200`).
- Device key: `x` `l6OK4YIRw2jcSo2qqLHguJVk3hK-ESiS5OFGX5SAYsA`, thumbprint
  `n5qSxkI9wZW-xoKQMjjpdmktYTcLmdyB_lG9XaQhqLM`.

Activation proof:

```json
{"alg":"EdDSA","typ":"pi-device-proof+jwt","jwk":{"kty":"OKP","crv":"Ed25519","x":"l6OK4YIRw2jcSo2qqLHguJVk3hK-ESiS5OFGX5SAYsA"}}
{"nonce":"RFIe5GcljuC_NMfuhA0MLgYEOTcDhpKb2aN03xTxK0A","purpose":"activate","installation_id":"6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f","product_id":"vanban","platform":"windows","client_version":"0.6.5","iat":1792828798}
```

Lease from that activation (`iat` 2026-10-24T08:00:00Z, `exp` 2026-11-23T08:00:00Z):

```json
{"alg":"EdDSA","kid":"pi-lease-example-1","typ":"pi-lease+jwt"}
{"iss":"https://id.pi.invalid","aud":"erpcons-office-desktop","lease_id":"lse_01JB7A2F4H6K8M0P2R4T6V8X0Z","sub":"usr_01JB6Z2K8Q4XN3T5V7W9Y1A2C3","org":"org_01JB6Z3M5R7T9V1X3Z5B7D9F1H","device_id":"dev_01JB7A0C2E4G6J8L0N2Q4S6U8W","installation_id":"6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f","cnf":{"jkt":"n5qSxkI9wZW-xoKQMjjpdmktYTcLmdyB_lG9XaQhqLM"},"product":"vanban","features":["vanban.use"],"entitlement_ids":["ent_01JB7A1D3F5H7K9M1P3R5T7V9X"],"nbf":1792828800,"iat":1792828800,"exp":1795420800,"nonce":"RFIe5GcljuC_NMfuhA0MLgYEOTcDhpKb2aN03xTxK0A","policy_version":"2026-10-01.1"}
```

Refresh proof and renewed lease, one day later: the proof adds `"device_id":"dev_01JB7A0C2E4G6J8L0N2Q4S6U8W"`,
has `"purpose":"refresh"`, `"nonce":"69kBNOzEoxD6att1omKEeRkHNBgs9uVXYSqVN_bqg_E"`, `"iat":1792915198`;
the lease has `"lease_id":"lse_01JB9C4H6K8M0P2R4T6V8X0Z2B"`, `"nbf":1792915200`, `"iat":1792915200`,
`"exp":1795507200`, the new nonce, and otherwise the claims above.

Feature catalog:

```json
{"alg":"EdDSA","kid":"pi-lease-example-1","typ":"pi-feature-catalog+jwt"}
{"iss":"https://id.pi.invalid","product":"vanban","catalog_version":1,"iat":1792828800,"features":[{"feature":"vanban.view","tier":"free"},{"feature":"vanban.export","tier":"free"},{"feature":"vanban.use","tier":"free"}]}
```

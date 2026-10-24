# ADR 0009: Leases and catalogs are compact JWS signed with EdDSA, keys pinned

Status: Proposed

## Context

HS02 asks for an asymmetrically signed offline licence that the client verifies with a public key
only. Office already verifies Ed25519 signatures with a pinned key in `erpcons-update`.

## Decision

- Lease, feature catalog and device proof are compact JWS (RFC 7515), `alg` `EdDSA` with Ed25519
  (RFC 8037), an explicit `typ` per object (RFC 8725) and `kid` for rotation (`lease.md` §2).
- The lease binds the device key through `cnf.jkt`, an RFC 7638 thumbprint (RFC 7800, RFC 9449).
- The client pins the platform licence-signing public keys in each release and never fetches them
  (`lease.md` §10).

## Consequences

- Standard JOSE libraries exist on the platform side; the client needs only Ed25519, base64url and
  JSON, as `erpcons-update` does.
- Key rotation needs a client release at least 90 days before the platform switches keys.
- One key set signs both leases and catalogs; this is safe because `typ` is checked, and separate
  keys stay possible later through `kid`.

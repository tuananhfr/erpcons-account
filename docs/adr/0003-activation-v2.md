# ADR 0003: Device activation uses the HS02 V2 contract

Status: Accepted (owner decision)

## Context

HS02 gives two activation contracts (ADR 0000 item 1). V1 sends `device_public_key` and receives
`device_id` and `offline_lease`. V2 sends `signed_challenge` and receives `entitlement_id`,
`rights`, `offline_valid_until`, `policy_version`, `signature`.

## Decision

Use V2: the device signs a server-issued, single-use nonce with its Ed25519 key, and the server
returns a lease signed by the platform and bound to that key (`lease.md` §3, §4). A challenge
endpoint is added, and the V2 response gains `device_id` and carries the signed lease as `lease`.

Why not V1:

- V1 proves nothing about the key: anyone holding an access token can register any public key,
  for example one copied from another machine, and receive a lease for it. V2 proves possession of
  the private key at activation and at every refresh.
- V1 has no freshness, so a captured request can be replayed. The V2 nonce is single use, short
  lived and bound to user, context, installation, product and purpose.
- V2 is in the HS02 appendix marked mandatory ("Phụ lục triển khai V2 – yêu cầu bắt buộc").
- V2 already carries `policy_version` and the entitlement link that refresh and audit need.

## Consequences

- Two round trips per activation or refresh (challenge, then activate or refresh); both are rare
  (start-up and every 12 h).
- The device must keep a private key: OS credential store, or no activation (ADR 0004, ADR 0006).
- The platform implements nonce storage, JWS verification and RFC 7638 thumbprints.

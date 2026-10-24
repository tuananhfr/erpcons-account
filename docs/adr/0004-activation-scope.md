# ADR 0004: Who activates a device

Status: Accepted (owner decisions)

## Context

Activation registers a device, counts against a device cap and yields an offline lease. Guests
have no identity to bind a device to. Web runs in a browser profile that users clear at will, and a
browser has no OS credential store.

## Decision

- Guests never call any device endpoint.
- Only signed-in desktop apps activate. The device is registered once per machine, OS user and
  organization context, shared by the four apps; each app then activates its own `product_id` and
  holds one lease for it (ADR 0010).
- Web never activates and never holds a lease; it uses the online entitlement list only, and the
  web client is not granted the `pi.devices` scope.
- A desktop app without an OS credential store does not activate (an ephemeral key would register
  a new device at every start and exhaust the device cap). Session-only sign-in is still allowed,
  and `pro` features use the online path.
- A signed-in user without any entitlement still activates and receives a lease with empty
  `features`, so the Device Registry and the HS03 activation KPI see every signed-in install. 403 on
  activation means "not allowed to activate", not "no entitlement" (ADR 0000 item 11).

## Consequences

- `pro` features on web work only online (entitlements at most 10 min old).
- A stolen web refresh token cannot activate devices or mint leases.
- Every signed-in desktop machine appears in the Device Registry once per OS user and context, so
  the platform's device cap must be sized with free users in mind (open question).

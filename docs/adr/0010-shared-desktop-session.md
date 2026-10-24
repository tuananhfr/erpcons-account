# ADR 0010: One PI session per OS user for the four desktop apps

Status: Accepted (owner decision). Supersedes the per-app desktop storage of ADR 0006 and the
per-app sign-in noted in ADR 0002.

## Context

The four Office desktop apps are separate executables installed side by side. A first draft gave
each app its own session, refresh token and device key, which avoided refresh-token rotation races
between apps but made the user sign in four times and registered up to four devices per machine
against the device cap.

## Decision

- One PI session per OS user and machine, shared by `vanban`, `bangtinh`, `trinhchieu` and `pdf`:
  signing in from any app signs in all four; signing out from any app signs out all four. The
  organization context is part of the session, so switching it in one app switches all four.
- One refresh token, one device key pair and one `installation_id`, stored once in the OS credential
  store under the service `ERPCons Office PI`. Non-secret state lives in a common directory:
  Windows `%APPDATA%\ERPCons\PI\`, macOS `~/Library/Application Support/ERPCons/PI/`, Linux
  `$XDG_CONFIG_HOME/erpcons/pi/` (`lease.md` §11).
- One device registration per machine and OS user (per organization context): the device cap counts
  machines, not apps. Leases stay per product: one lease per `product_id`, all bound to the same
  device key.
- Refresh-token rotation is serialized across processes with an exclusive file lock (`pi.lock`) in
  the common directory. After acquiring the lock a process re-reads the stored refresh token before
  refreshing, since another app may already have rotated it. Other apps notice changes by
  re-reading the shared state when their window gains focus and before each refresh.
- Without a credential store, sign-in is session-only and limited to the app that signed in
  (ADR 0004 still applies: no activation).

## Consequences

- The user signs in once per machine; the device cap is not consumed four times.
- Every account operation of every app goes through one lock; it is held for a single network
  exchange (15 s timeouts), so contention is short.
- A running app keeps its in-memory access token after another app signed out until its window
  regains focus or it next refreshes. Revoking the refresh token does not revoke access tokens
  already issued, so such a token stays usable server-side until it expires (at most 60 min).
- macOS: Keychain items are bound to the creating app's code signature by default, and the four
  apps are separate, currently unsigned bundles; sharing one item without prompts needs a common
  signing identity and keychain access group (open item, tied to the missing macOS signing).
- A revoked device loses the leases of all four products at once (`lease.md` §8).
- The platform sees one `device_id` per machine and OS user and activations for several
  `product_id` values on it (contract `activateDevice`).

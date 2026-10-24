# ADR 0006: Where tokens and the device key live

Status: Accepted (owner decision). The desktop layout (one entry per app) is superseded by
ADR 0010: one shared entry for the four apps.

## Context

HS02 V2 asks for the OS credential store. Desktop apps usually have one; browsers do not. Web
editors open in new tabs and `sessionStorage` is per tab, so a session-only store would ask for
sign-in in every tab. The site is static with no backend (`erpcons-office` CLAUDE.md), so a
backend-for-frontend with an HttpOnly cookie is not available.

## Decision

Desktop:

- The refresh token and the device private key (with `installation_id`) live in the OS credential
  store: Windows Credential Manager, macOS Keychain, Linux Secret Service, shared by the four apps
  (ADR 0010).
- Access and ID tokens stay in memory.
- Without a credential store, the refresh token is kept in memory for the session only, no device
  key is created, and the app does not activate (ADR 0004).

Web:

- The access token stays in memory, per tab, with a 5 min lifetime.
- The refresh token is stored in `localStorage` (shared by the editor tabs), with mandatory
  rotation and reuse detection on the platform (contract §1). Tabs serialize refreshes with the Web
  Locks API, re-read the token inside the lock, and announce sign-in and sign-out on a
  `BroadcastChannel`.

## Consequences

- XSS trade-off: any script running in the `office.erpcons.ai` origin can read the refresh token
  and use it elsewhere until rotation or expiry catches it. Mitigations: 5 min access tokens;
  rotation with family revocation on reuse (the legitimate tab's next refresh fails, which signs
  the user out and exposes the theft); 7-day idle and 30-day absolute refresh lifetimes; no
  `pi.devices` scope on web, so a stolen token cannot activate devices or mint leases; no
  third-party script is loaded (none found in `erpcons-office` source). No Content-Security-Policy
  is defined in the `erpcons-office` repo (the Apache vhost include is outside the repo, so
  production is unverified); a strict CSP should ship before web sign-in does.
- Rejected: `sessionStorage` (sign-in per tab); memory only (sign-in lost on every reload); a BFF
  cookie (needs a backend); a DPoP-bound refresh token with a non-extractable WebCrypto key (the
  strongest option, but it needs DPoP on the platform; kept as a future step).
- The four desktop apps, and several processes of one app, share the credential entry, so token
  refresh takes an exclusive file lock (`lease.md` §11, ADR 0010). The platform should keep refresh tokens at most 1024 bytes
  (Windows credential blobs are limited to 2560 bytes).

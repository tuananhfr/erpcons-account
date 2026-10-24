# ADR 0002: OIDC sign-in on desktop and web

Status: Accepted (owner decisions: both builds get sign-in; no sign-in in embed mode); flow
details Proposed

## Context

Each editor ships a native desktop app and a wasm web app. HS02 requires OIDC Authorization Code
+ PKCE through the system browser. Web editors open in new tabs and hold unsaved documents in the
tab, so an editor tab must never navigate away to sign in.

## Decision

- Two public OIDC clients: `erpcons-office-desktop` (loopback redirect
  `http://127.0.0.1:{port}/callback`, any port, RFC 8252) and `erpcons-office-web` (redirect
  `https://office.erpcons.ai/dang-nhap/callback/`). One desktop client serves all four apps.
- Authorization Code + PKCE `S256` only; `state` and `nonce` always; refresh-token rotation
  mandatory (contract §1).
- Desktop opens the system browser, never an embedded web view, and listens once on an ephemeral
  `127.0.0.1` port.
- Web opens `/dang-nhap/` in a popup. The callback page exchanges the code, stores the refresh
  token (ADR 0006), tells the other tabs through `BroadcastChannel` and closes. The PKCE verifier
  and `state` live in the popup's `sessionStorage`.
- Sign-out revokes the refresh token (RFC 7009) and clears local state even if revocation fails.
- The four desktop apps share one session per OS user: signing in or out in one app does it for
  all four (ADR 0010).
- Embed mode (`?embed=erpcons` or `?host=parent`, where the editor runs inside another site's
  iframe) has no sign-in in this phase: the shell hides the sign-in entry and the editor behaves as
  a guest. Taking the identity from the ERP host is future work.

## Consequences

- `erpcons-office` needs static `/dang-nhap/` and `/dang-nhap/callback/` pages. Its service worker
  must not cache the callback; the callback strips `code` from the URL and is served with
  `Referrer-Policy: no-referrer`.
- Popup blockers: the sign-in button opens the popup from a user gesture.
- Embed mode needs no storage in a possibly partitioned iframe; `pro` features are unavailable
  there until host identity exists (open item: identity handed over by the ERP host, protocol in
  `docs/erp-embed.md` of erpcons-office).
- One desktop sign-in covers the four apps (ADR 0010).

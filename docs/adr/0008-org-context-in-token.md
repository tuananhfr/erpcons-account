# ADR 0008: Organization context is a token claim, not a header

Status: Proposed

## Context

A PI ID can belong to several organizations (HS02). Entitlements and devices depend on which
organization the user acts for. HS05 lists `org_context` among the token claims and requires the
server to check membership before any tenant resource. The alternative is a request header (for
example `X-PI-Org-Id`) next to a token valid for every organization of the user.

## Decision

The context is the access token claim `org_context` (`org_id`, or `null` for personal). The client
selects it with the parameter `org_context` (an `org_id` or `personal`) on the authorization
request and on the refresh-token grant; switching organization is one refresh grant. `GET /v1/me`
returns the current `org_context`, so the client never parses the access token.

Why not a header:

- It is what HS05 already defines.
- Least privilege: a leaked access token reaches one tenant, not every tenant of the user.
- One source of truth on the server: no rule is needed for a header that disagrees with the token,
  and no endpoint can forget to read the header.
- Leases record the context (`org`), so it has to be stable for a token's lifetime anyway.

## Consequences

- The platform supports a non-standard `org_context` parameter on two OIDC requests and checks the
  membership when issuing tokens as well as on every request.
- Switching organization costs one token request and a new activation in the new context.
- A membership revoked during a token's lifetime is caught by the per-request check (403
  `membership_inactive`) and by lease refresh (`status: revoked`, `reason: membership_revoked`).

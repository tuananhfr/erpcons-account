# ADR 0001: Sign-in is optional; tiers are server data

Status: Accepted (owner decision)

## Context

HS02 describes a first run that activates PI ID. ERPCons Office today needs no account (the site
says "không cần tài khoản") and every feature is free. The owner wants sign-in available but
optional, and a complete entitlement mechanism so that a feature can later move to a Pro tier by
changing server data or configuration only.

## Decision

- A guest (not signed in) can use every `free` feature, on desktop and web. Today every feature
  is `free`. First run never asks for sign-in.
- Each feature has a tier, `free` or `pro`. The tier comes from a platform-signed feature catalog
  (`GET /v1/products/{product_id}/feature-catalog`, public), with a built-in catalog compiled into
  each release as the fallback (`products.md` §3).
- A `pro` feature needs an entitlement, through an offline lease on desktop or the online
  entitlement list (`products.md` §4).
- `<product>.view` and `<product>.export` are pinned `free` in the client.

## Consequences

- Moving a feature to `pro` needs no client release once its gate has shipped; a feature without a
  gate needs one release first.
- The catalog endpoint must be public and CORS-enabled. It is signed so that a local edit cannot
  turn `pro` into `free`. Client-side gating can still be bypassed by patching the binary; that is
  accepted for local features, and cloud features are enforced server-side (HS02).
- An offline guest with no cached catalog uses the built-in tiers; while everything is free that
  makes no difference.

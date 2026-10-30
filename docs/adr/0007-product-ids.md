# ADR 0007: Product ids reuse the Office app ids

Status: Accepted (owner decision). Amended by ADR 0013: the ids stay the app identity, but PI
licenses the four apps as one product, `erpconsoffice`, and feature ids use that prefix.

## Context

HS01 asks for a product registry keyed by `product_id`. The four Office apps already have stable
ids: `erpcons-update` accepts only `vanban`/`wordcraft`, `bangtinh`/`gridcraft`,
`trinhchieu`/`deckcraft` and `pdf`/`pdfcraft`, and each fork passes its id in
`apps/<fork>/src/updates.rs`.

## Decision

`product_id` is `vanban`, `bangtinh`, `trinhchieu` or `pdf`. Feature ids are prefixed with it
(`products.md` §2).

## Consequences

- One id per app across updates, licensing and telemetry; no mapping table.
- The ids are lowercase ASCII without separators, which suits feature id prefixes.
- `pdf` is generic; the platform must not give that id to another product.

# ADR 0013: Office licensing on, one PI product for the four apps

Status: Accepted (owner decisions of 30/10/2026). Supersedes, for Office, the suspension of offline
licensing in ADR 0011 and the "Office keeps `offline_licensing` off" consequence of ADR 0012. Amends
ADR 0007 (feature id prefix), ADR 0010 (one lease per product) and `products.md` §2.

## Context

ADR 0011 turned offline licensing off because PI had no Office product. The owner has now decided
(workspace plan `tmp/briefs/office-licensing/plan.md`):

- PI registers one product for the four Office apps, code `erpconsoffice` (PI codes match
  `^[a-z0-9][a-z0-9_-]{1,63}$`, so no dot or app suffix), with bare feature codes `view`, `export`
  and `use`, and a free plan `office-mien-phi` (one person, 2 devices, 7-day leases).
- The Office desktop apps lock editing, as UbotCAD does: open, view, save, export and print always
  work; creating and editing need a valid licence. The web app is not gated by this library.
- Signing up through Office, or signing in to an Office client for the first time, gives the
  account Office and a one-person free organization (PI decision D578).

PI keys a device by installation, product and account, and issues one lease per device. With one
product per app, a machine running the four apps would hold four PI devices against a 2-device cap.

## Decision

- `ClientProfile` gains `pi_product` (`erpconsoffice` for Office, `ubotbuild` for UbotCAD) and
  `pinned_free`. Everything licensing sends to or reads from PI uses the family's `pi_product`:
  the challenge and activation `productId`, the entitlements query and tenant check, the lease
  `product` claim, the signed catalog `product`, and the keys of `device_ids`, `last_refresh_ts` and
  `not_entitled` in `session.json`.
- `Product` stays the app identity: `User-Agent`, `erpcons-update` id, `Config::product`.
- Feature ids are `<pi_product>.<code>`: Office uses `erpconsoffice.view`, `erpconsoffice.export`
  (pinned free) and `erpconsoffice.use`, exported as `OFFICE_VIEW`, `OFFICE_EXPORT`, `OFFICE_USE`.
  App ids (`vanban.use`, ...) are no longer valid feature ids.
- `erpconsoffice.use` is `pro` in the built-in catalog: it needs a lease on this device (or fresh
  online entitlements, except in `DeviceRevoked`, `DeviceCapReached` and `SessionOnly`).
- One device registration and one lease, `lease-<pi_product>.json`, per machine, OS user and
  organization context, shared by the four apps (ADR 0010). Any app may activate or renew it. Both
  run under `pi.lock` and re-check after taking it, so concurrent apps make one call: a waiting app
  that finds a lease activated or renewed by another returns without calling PI.
- `Status::licence` is the family's licence; `Status::licences` keeps one entry per app of the
  family, all with that value.
- Office may turn `Config::offline_licensing` on. It stays off by default; each app opts in.
- Upgrade from 0.4.x: `Account::new` deletes `lease-<app id>.json` and `catalog-<app id>.jws` of
  every app whose id differs from the family's `pi_product` (so UbotCAD keeps its files), and every
  `session.json` write drops map keys other than `pi_product`. 0.4.x Office never activated, so no
  user loses a lease; the next sync activates under `erpconsoffice`.
- pi-mock: `erpconsoffice` is in the product registry, both Office clients carry it (access token
  `aud` `["pi-platform", "erpconsoffice"]`), `Tenant::office_free`, `FREE_OFFICE`,
  `Scenario::office_free()` and the binary flag `--office-free` (a user whose only organization is
  the one-person free one). PI's auto-provisioning at the first Office sign-in is not modelled.

## Consequences

- Breaking for the four forks: Office feature ids, the `pro` tier of `use` (denied while licensing
  is off), `is_valid_feature_id`/`is_pinned_free` take PI codes, and `ClientProfile` has two new
  fields. Crate version 0.5.0. UbotCAD's ids, files and behaviour are unchanged.
- The device cap counts machines, not apps: two machines exhaust the free plan, whatever the number
  of Office apps on each.
- One revoked device, lost plan or expired lease removes editing from all four apps at once.
- The free plan has unlimited seats, and PI reports no seat before the first activation. A plan
  added after a refused activation (`NotEntitled`) is therefore not seen by a plain sync; the user's
  Retry (`retry_activation`), a sign-in or an organization switch activates. When PI provisions
  the free plan before it issues the first tokens (D578), a new Office user activates at sign-in.
- Personal context never activates (PI leases to organizations only): an Office user in the personal
  context must pick the free organization.

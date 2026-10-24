# Products and features

Registry entries for the four ERPCons Office products, their feature catalog, and how a client
decides `allowed(feature)`. Field names match `contract.openapi.yaml` and `lease.md`.

## 1. Product registry entries

`product_id` reuses the app ids already used by `erpcons-update` and the forks (ADR 0007).

| Field (HS01 V2) | `vanban` | `bangtinh` | `trinhchieu` | `pdf` |
|---|---|---|---|---|
| Display name, vi | Văn bản | Bảng tính | Trình chiếu | PDF |
| Display name, en (proposed) | Documents | Spreadsheets | Presentations | PDF |
| Desktop product name (in code) | Văn bản – ERPCons | Bảng tính – ERPCons | Trình chiếu – ERPCons | PDF – ERPCons |
| Repo (`github.com/tuananhfr/`) | `wordcraft` | `gridcraft` | `deckcraft` | `pdfcraft` |
| Web path on `office.erpcons.ai` | `/van-ban/` | `/bang-tinh/` | `/trinh-chieu/` | `/pdf/` |

The code has no English product names (each `PRODUCT_NAME` is Vietnamese); the `en` row is a
proposal for the registry only.

Common to all four:

| Field | Value |
|---|---|
| Distribution class (HS01) | Local-first |
| Channels | PC: Windows x64, macOS universal, Linux x86_64 (the erpcons-update asset keys). Web: `https://office.erpcons.ai` |
| Processing | Local (native Rust app; Rust compiled to wasm in the browser) |
| Storage | Local. Files stay on the device or in the browser; nothing is uploaded |
| Server database | None |
| API consumed | This contract (PI Platform). No Office backend |
| Auth policy | PI ID optional; guests use every free feature (ADR 0001). Desktop: one shared session for the four apps (ADR 0010). No sign-in in embed mode (`?embed=erpcons`, `?host=parent`) in this phase (ADR 0002) |
| Offline | Desktop: full. Web: assets cached by the site's service worker (offline behaviour not audited here) |
| Device activation | Desktop only, signed-in users only (ADR 0004); one device per machine and OS user, one lease per product (ADR 0010) |
| Release | Desktop: GitHub release `erpcons-v<version>` per fork with signed `update.json` (erpcons-update). Web: deploy of `office.erpcons.ai` |
| Owner, audit evidence | To be filled by the owner (HS01 requires them; not produced here) |

HS01 and HS02 require an open-source licence and trademark review before distribution; it also
gates any move of a feature to `pro` (§3).

## 2. Feature ids and catalog

A feature id is `<product_id>.<name>`, matching
`^(vanban|bangtinh|trinhchieu|pdf)\.[a-z0-9_]+(\.[a-z0-9_]+)*$`, at most 64 characters.

| Feature | Scope | Tier today | Pinned free |
|---|---|---|---|
| `<product>.view` | Open and display files | `free` | yes |
| `<product>.export` | Save, save as, export to every supported format, print | `free` | yes |
| `<product>.use` | Create and edit | `free` | no |

That gives `vanban.view`, `vanban.export`, `vanban.use`, `bangtinh.view`, `bangtinh.export`,
`bangtinh.use`, `trinhchieu.view`, `trinhchieu.export`, `trinhchieu.use`, `pdf.view`, `pdf.export`,
`pdf.use`.

Pinned free: HS02 requires that an expired or offline user can still view and export everything.
The client therefore treats `.view` and `.export` as `free` whatever a catalog says, and logs a
catalog that marks them `pro`.

## 3. Feature catalog and future `pro` features

Tiers are server data, so a feature can move to `pro` without a client release (ADR 0001).

- Each client release compiles in a built-in catalog (version 0) listing every feature it gates,
  with its tier. Today every tier is `free`.
- `GET /v1/products/{product_id}/feature-catalog` (public, no token) returns the signed catalog:
  JWS `typ` `pi-feature-catalog+jwt`, same JOSE profile and pinned keys as the lease
  (`lease.md` §2, §10). Payload: `iss`, `product`, `catalog_version`, `iat`, `features` (list of
  `feature` and `tier`, `free` or `pro`).
- The client accepts a catalog when the signature, `typ` and `iss` are valid, `product` equals its
  product, every `feature` matches §2, and `catalog_version` is not lower than the cached one (a
  higher version replaces it). It stores the verified JWS (desktop: the shared PI directory,
  `lease.md` §11; web: `localStorage`) and re-verifies it on load.
- Fetched at start-up and every 24 h when online, for guests too. Failures keep the cached or
  built-in catalog.
- `tier(f)`: pinned free if `f` is pinned; else its tier in the newest verified catalog; else its
  built-in tier. Catalog entries the client does not know are ignored: there is no code path to
  gate.

Declaring a future `pro` feature:

1. Office ships a release whose code calls `allowed("<product>.<name>")` before the feature and
   lists it in the built-in catalog (tier `free` until the switch).
2. If the feature comes from the upstream open-source editor, a licence and trademark review is
   recorded as an ADR first (HS02: do not assume the right to lock original open-source
   components).
3. The platform registers the feature, creates the plans that grant it as entitlements (with
   `offline_allowed` and `offline_days`), and publishes catalog version N+1 with tier `pro`.
4. Moving it back to `free` is version N+2. A feature whose gate has not shipped cannot be made
   `pro` by the server; pinned-free features can never be.

## 4. `allowed(feature)`

`allowed` never blocks on the network. It answers from cached state and, when that state is stale,
schedules a background fetch; the UI re-evaluates when the account state changes.

```
allowed(f):
    if f not in builtin_catalog: return false        # programming error, logged
    if tier(f) == free: return true                  # includes pinned free
    if not signed_in: return false                   # guest
    if desktop and lease_usable() and f in lease.features: return true      # lease.md §8
    if entitlements_fresh() and f in {e.feature for e in entitlements}: return true
    return false
```

- `signed_in`: a refresh token is stored (desktop: the shared credential entry, or session memory
  without a credential store; web: `localStorage`), whether or not the network is reachable.
- Online path: `entitlements` is the last `GET /v1/me/entitlements` result for this product, `sub`
  and `org_context`. `entitlements_fresh()` holds when it completed at most 10 min ago on the
  monotonic clock. It is refetched at sign-in, start-up, after each organization switch and
  whenever it is stale and a `pro` feature is queried.
- Sanity check: a response whose `product_id` differs from the request, or with an entitlement
  whose `product_id` differs or whose `org_id` is not `null` and differs from `org_context`, is
  discarded as a whole and logged as a tenant-isolation incident (HS03 SEV0).

| State | `free` and pinned free | `pro` granted by the lease | `pro` online only (`offline_allowed: false`) |
|---|---|---|---|
| Guest, desktop or web | allowed | denied | denied |
| Desktop, signed in, lease usable | allowed | allowed | allowed while entitlements are fresh |
| Desktop, signed in, lease expired, offline | allowed | denied | denied |
| Desktop, signed in, lease expired, online | allowed | allowed while entitlements are fresh (refresh renews the lease) | allowed while fresh |
| Desktop, signed in, lease revoked | allowed | denied unless fresh entitlements still list it | same |
| Desktop, signed in, no credential store | allowed | online path only | allowed while fresh |
| Web, signed in, online | allowed | n/a (no lease on web) | allowed while fresh |
| Web, signed in, offline for more than 10 min | allowed | n/a | denied |

A denied `pro` feature shows its entry point disabled with the reason (sign in, reconnect to renew,
or upgrade). Opening, saving and exporting are never blocked.

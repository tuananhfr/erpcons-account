# erpcons-account

Client side of PI account integration for ERPCons Office: sign-in with PI ID,
entitlements, device activation and offline leases for the four editors
(`vanban`, `bangtinh`, `trinhchieu`, `pdf`) in both their native desktop apps and
their wasm web apps on `office.erpcons.ai`. On desktop the four apps share one PI session per OS
user: one sign-in, one registered device per machine, one lease per product (ADR 0010).

ERPCons Office is a consumer of the PI Platform (HS05: product teams do not build
IAM). The platform is built by another team and does not exist yet; Office is
developed against a mock of the contract below and connected to the real platform
later.

Status: design phase. This repository holds only the consumer contract and its
decisions. The Rust crate arrives in the next phase and will follow the style of
`../erpcons-update`: a blocking library, `ureq`, Ed25519 verification with pinned
keys, typed errors, no UI text. Forks will pin it by git tag.

## Documents

| Document | Content |
|---|---|
| [docs/contract.openapi.yaml](docs/contract.openapi.yaml) | OpenAPI 3.1: OIDC usage and every PI Platform endpoint Office calls, with examples |
| [docs/lease.md](docs/lease.md) | Offline lease and device proof format, offline policy, trusted time, client verification order |
| [docs/products.md](docs/products.md) | Product registry entries, feature catalog, `allowed(feature)` |
| [docs/adr/](docs/adr/) | Decisions; [0000](docs/adr/0000-source-inconsistencies.md) lists contradictions in the PI spec package and their resolution |

Sources: PI Holding spec package V3, mainly HS02 (PI ID, organization, offline
licence) and HS05 (contracts and acceptance); HS01 for the product registry.

## Licence

MIT OR Apache-2.0 ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).

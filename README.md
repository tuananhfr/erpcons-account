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

The crate follows the style of `../erpcons-update`: a blocking library, `ureq`,
Ed25519 verification with pinned keys, typed errors, no UI text. Forks pin it by git tag.

## Layout

| Path | Content |
|---|---|
| `erpcons-account/` | The client library (native only; `compile_error!` on wasm32) |
| `pi-mock/` | Mock PI Platform: library `pi_mock::Server` for tests, binary `pi-mock` for manual and E2E runs |
| `docs/` | The contract; it is the specification for both crates |

## Using the library

```rust
use std::sync::Arc;
use erpcons_account::{Account, Config, Product, Status};

let config = Config::new("https://id.pi.example", Product::VanBan, env!("CARGO_PKG_VERSION"));
let account = Arc::new(Account::with_os_store(config)?);
// On a worker thread; blocks until the browser callback, an error, a timeout or cancel_sign_in.
account.sign_in(|url| open::that(url).map_err(|e| e.to_string()))?;
if let Status::SignedIn(s) = account.status() { /* show s.user, s.licence, s.warning */ }
let can_edit = account.allowed("vanban.use"); // cached state only, never blocks
if account.take_refresh_request() { /* run account.refresh() on a worker */ }
```

`Account` is `Send + Sync` and keeps no global state. Calls that touch the network block; run
them off the UI thread. `reload()` re-reads the session shared by the four apps (window focus),
`select_org(Some(id))` / `select_org(None)` switches organization context, `sign_out()` revokes
and clears the shared session. The secret store is the OS keyring (service `ERPCons Office PI`);
when it is unavailable the session lives in memory only and `Status` reports `session_only`.

Release builds pin `PLATFORM_KEYS` in `src/config.rs`; it is empty until PI publishes its
signing keys. Tests and E2E runs set `Config::platform_keys` to the mock's key.

Building on Linux needs `libdbus-1-dev` (Secret Service backend of `keyring`).

## pi-mock

In tests:

```rust
let server = pi_mock::Server::start(pi_mock::Scenario::default());
let mut config = Config::new(server.issuer(), Product::VanBan, "1.0.0");
config.platform_keys = vec![PinnedKey { kid: server.lease_key_id(), key: server.lease_public_key() }];
server.update_scenario(|s| s.entitlements.clear()); // or set_scenario, add_fault, revoke_device...
```

As a process: `cargo run -p pi-mock -- --port 8787 [--host 0.0.0.0] [--issuer URL]
[--web-redirect URI]...`. It prints one JSON line with the base URL, issuer, lease `kid` and lease
public key (hex). The lease key is a fixed development key derived from a public label; release
builds never pin it.

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo xwin clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings
```

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

# erpcons-account

Client side of PI account integration for ERPCons Office: sign-in with PI ID,
entitlements, device activation and offline leases for the four editors
(`vanban`, `bangtinh`, `trinhchieu`, `pdf`) in both their native desktop apps and
their wasm web apps on `office.erpcons.ai`. On desktop the four apps share one PI session per OS
user: one sign-in, one registered device per machine, one lease per product (ADR 0010).

ERPCons Office is a consumer of the PI Platform (HS05: product teams do not build
IAM). The library was first written against the contract in `docs/`, before PI existed. It now
talks to the real PI Platform (PI ID): PI's paths, `/api/v1/id/me`, its error envelope,
organization switching with `org_hint`; offline licensing (device activation and leases) speaks PI's
device protocol (ADR 0012) and is turned off for Office by `Config::offline_licensing`.
**Where this README, the contract or ADRs 0004/0008 differ from
[ADR 0011](docs/adr/0011-real-pi-platform.md) or [ADR 0012](docs/adr/0012-pi-device-protocol.md),
those ADRs win.**

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

With `Config::offline_licensing` on, `allowed()` also denies `pro` features while the licence state is
`DeviceRevoked`, `DeviceCapReached` or `SessionOnly`, even if PI's online entitlements say ALLOW:
a `pro` feature then needs a lease on this device.

`Account` is `Send + Sync` and keeps no global state. Calls that touch the network block; run
them off the UI thread. `reload()` re-reads the session shared by the four apps (window focus),
`select_org(Some(id), open_browser)` / `select_org(None, open_browser)` switches organization
context by running PI's authorization again (`org_hint`, or `prompt=select_account` to pick
personal; ADR 0011), `sign_out()` revokes
and clears the shared session. The secret store is the OS keyring (service `ERPCons Office PI`, or the profile's);
when it is unavailable the session lives in memory only and `Status` reports `session_only`.

`Config::api_base` is the base of PI's end-user API (default `{issuer}/api/v1/id`). With
`Config::offline_licensing` off (the default) no device, lease or entitlement endpoint is called and
`pro` features are denied. Turned on, the client uses PI's device protocol (`/devices/challenge`,
`/devices/activate`, `/licenses/refresh`, `/me/entitlements`; ADR 0012) and only in an organization
context; PI has no Office product, so this is for UbotCAD (`ubotbuild`). The feature catalog is not
fetched.

Release builds pin `PLATFORM_KEYS` in `src/config.rs`; it is empty until PI publishes its
signing keys. Tests and E2E runs set `Config::platform_keys` to the mock's key.

### Client families

`Config::new(issuer, product, version)` picks a `ClientProfile` from the product. `ClientProfile::OFFICE`
(the four Office apps) keeps client `erpcons-office-desktop`, keyring service `ERPCons Office PI`
and state directory `ERPCons\PI` (macOS `ERPCons/PI`, Linux `erpcons/pi`). `ClientProfile::UBOTCAD`
(`Product::UbotBuild`, feature ids `ubotbuild.cad-view|cad-export|cad-use`) uses client `ubotcad-desktop`, service
`UbotCAD PI` and `UbotCAD\PI` (`UbotCAD/PI`, `ubotcad/pi`), so the two families never share a
session, device key or lease. `Account::with_os_store` takes the service and directory from the profile.

On Linux the credential store is the Secret Service, reached through zbus (pure Rust): builds need no libdbus.

## pi-mock

In tests:

```rust
let server = pi_mock::Server::start(pi_mock::Scenario::default());
let mut config = Config::new(server.issuer(), Product::VanBan, "1.0.0");
config.platform_keys = vec![PinnedKey { kid: server.lease_key_id(), key: server.lease_public_key() }];
config.offline_licensing = true; // exercises PI's device protocol served by pi-mock
server.update_scenario(|s| s.tenants.clear()); // or set_scenario, add_fault, revoke_device...
```

As a process: `cargo run -p pi-mock -- --port 8787 [--host 0.0.0.0] [--issuer URL]
[--web-redirect URI]...`. It prints one JSON line with the base URL, issuer, lease `kid`, lease
public key (hex), signing `kid` and JWKS URI. pi-mock behaves like PI's code (ADR 0011): `/id/*`
OIDC endpoints, EdDSA access and ID tokens published at `/id/jwks.json`, `org_hint` and the
organization page (`Scenario::org_choice`), `/api/v1/id/me`, PI's envelope and CORS rules. Its
device endpoints follow PI's device protocol (`Scenario::tenants`). The signing and lease keys are fixed
development keys derived from public labels; release builds never pin them.

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
| [docs/contract.openapi.yaml](docs/contract.openapi.yaml) | OpenAPI 3.1: the original Office contract; superseded in part by ADR 0011 (operations marked `x-superseded-by`) |
| [docs/lease.md](docs/lease.md) | Offline lease and device proof format, offline policy, trusted time, client verification order |
| [docs/products.md](docs/products.md) | Product registry entries, feature catalog, `allowed(feature)` |
| [docs/adr/](docs/adr/) | Decisions; [0000](docs/adr/0000-source-inconsistencies.md) lists contradictions in the PI spec package and their resolution |

Sources: PI Holding spec package V3, mainly HS02 (PI ID, organization, offline
licence) and HS05 (contracts and acceptance); HS01 for the product registry.

## Licence

MIT OR Apache-2.0 ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).

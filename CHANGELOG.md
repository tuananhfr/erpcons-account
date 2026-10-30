# Changelog

## 0.5.0

Office licensing is on again, as one PI product for the four apps (ADR 0013). UbotCAD is unchanged.

### Breaking

- Office feature ids are `erpconsoffice.view`, `erpconsoffice.export` and `erpconsoffice.use`
  (constants `OFFICE_VIEW`, `OFFICE_EXPORT`, `OFFICE_USE`); the per-app ids (`vanban.use`, ...) are
  no longer valid. `is_valid_feature_id` and `is_pinned_free` take a PI product code as prefix.
- `erpconsoffice.use` is `pro` in the built-in catalog: it needs a lease (or fresh online
  entitlements), so it is denied to guests and while `Config::offline_licensing` is off.
- `ClientProfile` has new fields `pi_product` and `pinned_free`; struct literals must provide them.
- One device registration and one lease, `lease-erpconsoffice.json`, for the four Office apps instead
  of one per app. `Status::licence` is that lease's state; `Status::licences` repeats it per app.
- pi-mock: both Office clients carry product `erpconsoffice`, so their access tokens have `aud`
  `["pi-platform", "erpconsoffice"]`.

### Added

- `OFFICE_PI_PRODUCT`, `Product::pi_product`, `ClientProfile::ALL` and
  `ClientProfile::for_pi_product`.
- pi-mock: `erpconsoffice` in the product registry, `FREE_OFFICE`, `OFFICE_PRODUCT`, `ORG_OFFICE`,
  `Tenant::office_free`, `Scenario::office_free` and the binary flag `--office-free`.

### Changed

- A lease renewal re-checks under `pi.lock`, so concurrent apps of one family renew the shared lease
  once.
- State of 0.4.x is discarded on upgrade: `Account::new` deletes `lease-<app id>.json` and
  `catalog-<app id>.jws` of the Office apps, and session maps keep only the family's PI product.
  0.4.x Office never activated, so nothing usable is lost.

## 0.4.2

### Added

- `PLATFORM_KEYS` pins production PI's lease-signing key `lease-2026-10`, so release builds can
  verify leases without a development key.

## 0.4.1

### Breaking

- With `Config::offline_licensing` on, `allowed()` denies `pro` features in `DeviceRevoked`,
  `DeviceCapReached` and `SessionOnly` even while online entitlements say ALLOW, and requests no
  refresh there (ADR 0012, amendment). Office is unchanged.
- `Config::validate` rejects a `product` outside `profile.products` and a `client_id` that differs
  from `profile.client_id`.
- pi-mock: `Tenant.seats` is a `Vec` plus `unlimited_seats`; an unlimited plan reports `seat: false`
  until activation grants the seat, as PI's `Seats::hasSeat` does.

### Fixed

- Sign-in checks the ID token `exp` against system time, not `effective_now`. A `trusted_floor`
  left ahead by a clock that once ran fast blocked sign-in (`InvalidIdToken("exp")`) until real
  time caught up, and only a lease received after sign-in can lower it.
- A 404 at refresh re-activates only when it is PI's JSON envelope (`ApiCode::DeviceUnknown`); the
  old lease and device id stay until the new activation succeeds. Other 404s keep the lease.
- Every 422 `errors.timestamp` at refresh undoes the persisted `last_refresh_ts`, and a timestamp
  is never taken more than 300 s past PI's clock.
- An entitlement row with an invalid feature code is skipped with a warning instead of failing the
  fetch, so the lease sync still runs.
- `LicenceState::DeviceRevoked` documents that a staff- or organization-revoked device stays
  revoked; only a device the user retired recovers at sign-in.
- pi-mock gains `Fault::invalid` and `Fault::raw`.

## 0.4.0

Licensing now speaks PI Platform's device protocol (ADR 0012). Office is unchanged:
`Config::offline_licensing` stays off for it.

### Breaking

- Wire: the Office-contract `/v1/...` licensing calls are replaced by PI's
  `GET /devices/challenge`, `POST /devices/activate`, `POST /licenses/refresh` and
  `GET /me/entitlements` under `Config::api_base`. `Config::contract_url` is removed. Device proofs
  are raw Ed25519 signatures; leases carry PI's claims (`jti`, `device`, `tenant`, raw-key `cnf.jkt`).
- `LicenceState::NotEntitled` is a new variant (PI answered `NO_ENTITLEMENT`, `NO_SEAT` or `ORG_CONTEXT_REQUIRED`). A personal context yields `NotActivated`.
- `ApiError.errors` is a new `Box<[String]>` field naming the rejected request fields.
- UbotBuild feature ids are `ubotbuild.cad-view`, `ubotbuild.cad-export` and `ubotbuild.cad-use`
  (were `ubotbuild.cad.*`). PI's `offline` and `offline-extended` codes are not exposed as features.
- pi-mock scenarios use `Tenant`; `Entitlement`, `Catalog`, `max_devices`, `min_client_version` and
  `policy_version` are removed from `Scenario`, along with the `/v1` endpoints.
- Device ids are kept per product; the feature catalog is no longer fetched (a cached signed catalog
  on disk still applies).
- State written by 0.3.0 (leases, session `device_id`) is discarded on upgrade; the next `refresh()` activates again
  without a new sign-in.

### Changed

- Refresh timestamps use server time from the `Date` header, are persisted before each send, and are
  recomputed once after a 422 `errors.timestamp`.
- A 409 `DEVICE_REVOKED` at refresh wipes every lease and does not reactivate until the next sign-in.
- pi-mock gains `Fault::skew_date`.

## 0.3.0

### Breaking

- `Product::UbotBuild` is a new variant: exhaustive matches on `Product` must handle it.
- `Config.profile` (`ClientProfile`) is a new public field, set by `Config::new` from the product;
  struct literals of `Config` must provide it. `ClientProfile::OFFICE` and `ClientProfile::UBOTCAD`
  carry the client id, scopes, keyring service, state directories and `User-Agent` prefix.

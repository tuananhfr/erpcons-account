# Changelog

## 0.4.0

Licensing now speaks PI Platform's device protocol (ADR 0012). Office is unchanged:
`Config::offline_licensing` stays off for it.

### Breaking

- Wire: the Office-contract `/v1/...` licensing calls are replaced by PI's
  `GET /devices/challenge`, `POST /devices/activate`, `POST /licenses/refresh` and
  `GET /me/entitlements` under `Config::api_base`. `Config::contract_url` is removed. Device proofs
  are raw Ed25519 signatures; leases carry PI's claims (`jti`, `device`, `tenant`, raw-key `cnf.jkt`).
- `LicenceState::NotEntitled` is a new variant (no plan, no seat, or personal context).
- `ApiError.errors` is a new `Box<[String]>` field naming the rejected request fields.
- UbotBuild feature ids are `ubotbuild.cad-view`, `ubotbuild.cad-export` and `ubotbuild.cad-use`
  (were `ubotbuild.cad.*`). PI's `offline` and `offline-extended` codes are not exposed as features.
- pi-mock scenarios use `Tenant`; `Entitlement`, `Catalog`, `max_devices`, `min_client_version` and
  `policy_version` are removed from `Scenario`, along with the `/v1` endpoints.
- Device ids are kept per product; the feature catalog is no longer fetched (a cached signed catalog
  on disk still applies).
- State written by 0.3.0 (leases, session `device_id`) is discarded on upgrade; users sign in and
  activate again.

### Changed

- Refresh timestamps use server time from the `Date` header, are persisted before each send, and are
  recomputed once after a 422 `errors.timestamp`.
- A 409 `DEVICE_REVOKED` at refresh wipes every lease and does not reactivate until the next sign-in.
- pi-mock gains `Fault::skew_date`.

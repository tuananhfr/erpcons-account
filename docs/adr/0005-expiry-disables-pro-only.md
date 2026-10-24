# ADR 0005: Lease expiry or revocation only disables pro features

Status: Accepted (owner decision)

## Context

HS02: an expired or offline device can still view and export all local data, and an offline
device cannot be revoked until it reconnects. The owner adds that losing a lease must never affect
free features.

## Decision

- An expired, revoked, missing or invalid lease removes only the `pro` features that lease granted.
  `free` features keep working; `<product>.view` and `<product>.export` are pinned free and cannot
  be made `pro` by a catalog (`products.md` §2).
- No document is closed, locked or made read-only; an action already started finishes.
- A platform error deletes the lease only when the error says the lease is no longer valid
  (`lease.md` §8).

## Consequences

- The worst case of any account failure (platform down, clock problems, revoked device, tampered
  state file) is "free features only", never data loss.
- A revoked user keeps `pro` features offline until the lease expires (at most 90 days), as HS02
  accepts.

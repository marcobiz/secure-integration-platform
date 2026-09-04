# ADR-0014: Local recovery

**Status:** Accepted

## Decision

MVP: metadata/blob backup and recovery only with a profile/system state capable of using DPAPI. Complete machine loss requires re-enrollment and may make encrypted data unrecoverable.

Enterprise: per-Installation recovery copy, wrapped by a central recovery key, dual control, revocation and audit. No universal master key.

## Consequences

The MVP does not weaken isolation to offer universal recovery. The operational risk must be communicated and tested.

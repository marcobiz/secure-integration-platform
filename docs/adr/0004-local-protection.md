# ADR-0004: DPAPI CurrentUser and local encryption

**Status:** Accepted

## Context

Local data must resist offline copying, stolen backups and unprivileged processes without introducing a complex local PKI.

## Decision

- DPAPI CurrentUser under the virtual service identity for small secrets and data-key wrapping.
- AES-256-GCM for data, with per-Installation key versions and scoped AAD.
- Non-exportable ECDSA P-256 in Windows CNG for Installation identity.
- No `CRYPTPROTECT_LOCAL_MACHINE` as the default root.

## Consequences

Keys are isolated from the legacy process and differ per Installation. SYSTEM/local Administrator can still compromise the service. Complete loss of the service profile limits MVP recovery.

## Rejected alternatives

A mandatory TPM would reduce compatibility; a central universal key would introduce systemic risk; custom cryptography is prohibited.

# ADR-0004: DPAPI CurrentUser and local encryption

**Status:** Accepted

## Context

Local data must resist offline copying, stolen backups and unprivileged processes without introducing a complex local PKI.

## Decision

- DPAPI CurrentUser under the virtual service identity for small secrets and data-key wrapping.
- AES-256-GCM for data, with per-Installation key versions and scoped AAD.
- Non-exportable ECDSA P-256 in Windows CNG for Installation identity.
- No `CRYPTPROTECT_LOCAL_MACHINE` as the default root.

Local data-key initialization is explicit, not a side effect of ordinary protection
or key lookup. The installer requests it only for first use, under the virtual
service identity. A create-new claim and create-new wrapped-key/active files prevent
partial initialization or concurrent initialization from replacing existing keys.
Normal startup fails closed on missing metadata/key or unusable DPAPI state. Existing
key versions remain readable without conversion. Repair, restart and update do not
authorize new keys; no automatic rotation/recovery mechanism is introduced.

Application policy grants exact purpose/content-type pairs before decoding input
or using a data key. AEAD continues to bind Installation/application/purpose/content
type, with CR/LF rejected to keep the existing AAD delimiters unambiguous.

## Consequences

Keys are isolated from the legacy process and differ per Installation. SYSTEM/local Administrator can still compromise the service. Complete loss of the service profile limits MVP recovery.

## Rejected alternatives

A mandatory TPM would reduce compatibility; a central universal key would introduce systemic risk; custom cryptography is prohibited.

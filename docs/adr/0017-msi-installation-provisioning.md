# ADR-0017: MSI provisioning of Installation identity

**Status:** Accepted
**Date:** 2026-08-03

## Context

An Installation identity must be unique per host and survive repair and upgrade without being shared between installations. The MSI package, in contrast, is a reproducible, distributable artifact: embedding a final Installation ID, private key, activation code or other secret material in the package would clone the identity across machines and turn the supply chain into a credential distribution channel.

Installation runs with administrative privileges, whereas the cryptographic root must belong to the Broker running as a virtual service identity. Install, repair, upgrade, uninstall and reinstall semantics must therefore distinguish product artifacts from per-host state.

## Decision

### MSI artifacts and product manifest

- The release MSI is Authenticode-signed and contains a **signed product manifest** with a detached CMS signature that the Broker can also verify after installation.
- The manifest contains only product data: product identifier, version, compatibility range, schema version, allowed publisher identities and hashes of distributed artifacts. Its hash and signature are recorded in the release manifest.
- The signature is verified during install/upgrade and again before the Broker accepts the manifest. Production accepts only chains/publishers allowed by release policy; test builds use an explicit test trust root that cannot be promoted.
- MSI, transforms, response files and manifests contain no secrets, activation codes, private keys, credentials or final Installation ID. These values must not be passed as MSI properties or appear in Windows Installer logs.
- The MSI installs binaries, nonsensitive configuration, product manifest, service and ACLs. It does not generate the Installation identity in a privileged custom action.

### First startup under the service identity

On its first valid startup, the Broker running as the virtual service identity:

1. verifies the product manifest signature, schema and compatibility;
2. verifies that storage and key containers have the expected ACLs;
3. generates a unique random Installation ID using a CSPRNG;
4. generates an ECDSA P-256 key pair in the Windows CNG provider;
5. marks the private key as non-exportable and restricts access to the service identity, subject to the residual capabilities of SYSTEM/Local Administrator;
6. atomically persists the local record associating Installation ID, CNG key name, public key, schema version and enrollment state.

Installation ID and public key are not secrets, but are integrity-sensitive data and remain in protected Broker storage. The private key is not exported, serialized to the application filesystem or returned through IPC.

Initialization is idempotent. A crash before commit leaves recognizable, retryable state; an incomplete or inconsistent record is not interpreted as a new Installation. After enrollment starts, loss of the ID or key produces a fail-closed error and requires the recovery/reinstall path, without silent regeneration.

VM images must be sealed before the Broker's first startup. Cloning an already initialized machine is not a supported provisioning method.

### Future enrollment

Enrollment specified by ADR-0008 uses a random single-use activation code and proof-of-possession of the CNG key. The activation code is supplied at runtime through a dedicated administrative flow, never through MSI, a public command line, a transform or an unprotected persistent file.

Successful enrollment binds the Installation ID to the proven public key on the Gateway. Reinstallation and key loss generate a new identity and require a new activation code. Revoking the previous Installation is an explicit control-plane operation and is not implied by local uninstall.

### MSI lifecycle semantics

| Operation | Identity and state | Required behavior |
|---|---|---|
| **Install** | No identity in the package. | Installs signed artifacts, service and ACLs. The first Broker startup creates the Installation ID and CNG key once under the service identity. An MSI rollback removes artifacts created by the failed installation without leaving a partially usable identity. |
| **Repair** | Preserves Installation ID, CNG key, DPAPI state and enrollment. | Restores/verifies binaries, manifest and ACLs. Does not generate a new identity or attempt enrollment. Missing or inconsistent identity state causes an explicit health failure and requires recovery or reinstallation. |
| **Upgrade** | Preserves Installation ID, CNG key, protected data and enrollment. | Accepts only signed, compatible MSI/manifests. State migrations are versioned, atomic and rollback-aware. A major upgrade must not trigger the identity cleanup intended for a standalone uninstall. Incompatible downgrades are rejected. |
| **Uninstall** | Revokes only local state; does not imply central revocation. | Stops and removes the service, then deletes Installation ID, CNG private key, DPAPI material, local secrets and enrollment state. Any redacted audit follows the defined operational retention policy. Secure physical erasure on SSDs is not guaranteed; protection relies on encryption and key destruction. Cleanup failure is reported and is not reported as complete success. |
| **Reinstall** | Creates a new Installation. | After a complete uninstall, first startup generates a new Installation ID and CNG pair and requires a new activation code. It does not automatically recover the previous identity. Inconsistent remnants block provisioning until explicit recovery/cleanup is performed. |

Repair and upgrade are the only paths that automatically preserve identity. Backup/restore and recovery follow ADR-0014 and cannot make the private key exportable.

## Verifiable invariants

- Two installations of the same MSI produce different Installation IDs and public keys.
- MSI package, manifest and logs contain no final Installation ID, activation code or private material.
- The CNG private key is non-exportable and is created by the Broker process under the virtual service identity.
- Repair and upgrade do not change the Installation ID or public key.
- Reinstall after uninstall produces different values and returns to the unenrolled state.
- Invalid manifest signature or compatibility, overly permissive ACLs and corrupted identity state cause explicit failure.
- No IPC operation returns private keys, KEKs, DEKs, DPAPI material or activation codes.

These invariants must be covered by the installer/live Windows matrix before production release. This ADR defines the contract required by identity integration; it does not implement M2 or bring forward M9 installer hardening.

## Consequences

- A single MSI can be distributed to multiple hosts without cloning credentials.
- The key originates in the correct security context and does not pass through the MSI process or business application.
- Repair and upgrade are transparent to identity; uninstall/reinstall require a new enrollment ceremony.
- The signed manifest protects the origin and integrity of product configuration, not its confidentiality.
- Loss of the service identity profile or CNG key can make local data unrecoverable and requires re-enrollment, consistently with ADR-0004 and ADR-0014.
- Local Administrator and SYSTEM can still compromise the service, ACLs or key store; they are not considered threats fully mitigated by the package.

## Milestones

- **Before M2 identity integration:** the data model and enrollment protocol must follow this contract.
- **M2:** enrollment with single-use activation code and proof-of-possession, without implementing MSI shortcuts.
- **M9:** full implementation and validation of install, repair, upgrade, rollback, uninstall/reinstall, production signing and installer matrix.

## Rejected alternatives

- Pre-generated or final Installation ID in the MSI: would clone identity across hosts.
- Activation code or secret as an MSI/transform property: would expose the value to logs, process inspection and software distribution systems.
- A package-imported, shared or exportable private key: would eliminate per-host proof-of-possession.
- Key generation in an administrative custom action: would place the key in the wrong security context and broaden access.
- Automatic regeneration during repair or upgrade: would break enrollment, decryptability and audit correlation.
- Automatic identity reuse after reinstall: would make revocation ambiguous and encourage unauthorized restoration of copied state.

## Relationships

- ADR-0004 defines DPAPI CurrentUser, non-exportable CNG and local protection.
- ADR-0008 defines identity, proof-of-possession, mTLS and renewal.
- ADR-0014 defines service-identity recovery limits.
- ADR-0016 defines application-process identification and use of local manifests.

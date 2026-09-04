# ADR-0029: Local PKCS#12 provider for offline laboratories

**Status:** Accepted

## Context

The open-source quickstart must qualify the Gateway and Connector Runtime without a
cloud account. The synthetic provider covers functional flows but does not prove loading
server-owned X.509 identities with private keys, RS256 signing with S1 or mTLS use of A1.
Putting real PEM, P12, passwords, locators or fingerprints in the repository would violate the
secret boundary; making Azure mandatory would remove the quickstart's local-only property.

## Decision

- `packs/deployment/local-pkcs12` is an optional deployment pack and depends only on
  provider-neutral contracts. Core, the default Gateway image and the default quickstart do not depend on
  the pack.
- The pack accepts a server-owned closed-schema manifest and a material directory mounted
  read-only. Runtime references are exact-match logical URIs; the caller does not select paths,
  files, passwords, certificates or keys.
- Leaf, chain, fingerprint, SPKI and version are bound in the manifest. P12 files are loaded
  with `EphemeralKeySet`; the pack exposes only the client certificate, public metadata/material and
  bounded signing operations. Before every signature and every client-certificate return,
  it rereads the manifest, P12, leaf and chain, exact-matching version/role/fingerprint/SPKI/chain
  bytes; it verifies leaf-first order and signatures with `CustomRootTrust`, the exact pinned root,
  AIA downloads disabled and no fallback to the ambient trust store. The operation uses only objects
  already loaded and verified in memory. There is no private-key export.
- The pack offers no generic secret retrieval and declares `SecretValues=false`. The
  `ISecretValueProvider` slot required by the factory contract is deny-only, resolves no paths and does not access the
  filesystem; the provider-neutral Gateway does not require the secret capability from a pack exposing
  the required client certificate.
- A1 and S1 are distinct resources. The A1 role requires `clientAuth` and `DigitalSignature`; S1 is an
  RSA signing resource and the Published FSE2 policy continues to enforce
  `ContentCommitment` separately in both slots.
- The importer is offline and fail-closed. Its default mode verifies both CSR signatures and the
  exact-SPKI triple binding `key ↔ CSR ↔ leaf`, plus fingerprint, trust, roles and A1/S1
  separation, before creating output. Sources, output and temporary locations must be absolute local paths outside
  the repository, without UNC/device/ADS/reparse points in any ancestor; targets and parent identity
  are rechecked before reads, writes, ACL changes and cleanup. Creation requires `-Execute`,
  expected out-of-band fingerprints, a resolvable runtime principal and a new directory. It produces
  independent random passwords and exact ACLs: inheritance disabled, SYSTEM/Administrators FullControl and
  minimal runtime-identity read/execute, without unnecessary residual interactive FullControl.
- The FSE2 Compose overlay is opt-in. It does not publish a profile, invoke FSE2 endpoints or change the
  ordinary quickstart. The container remains non-root/read-only and receives material exclusively
  through read-only bind mounts.
- The profile is intended for development, demos and controlled test qualification. It does not replace HSM/KMS,
  revocation monitoring, rotation, backups or production custody.

## Consequences

The local technical demo can exercise the same provider surface used by the real Gateway
without Azure or reusable material in Git. The new Dockerfile enters
the supply-chain inventory, exact-head builds, secret scanning and SBOM. Import and live calls
remain separate operational gates and require explicit authorization after review.

Administrator/SYSTEM and an operator who regains privileged access to the external directory
remain in the TCB. A bind
mount is not an HSM: during signing the key exists in process memory and a privileged
host can observe it. Substitution defenses use ACLs, link-free paths, fingerprints and
SPKI. Private operations reduce the window by rereading and validating the complete snapshot at
the point of use, but privileged process/host compromise remains a residual laboratory risk.

## Rejected alternatives

- Committing PEM/P12/passwords or operational fingerprints to the repository.
- Using the synthetic provider as proof of real import/custody.
- Mandatory Azure dependency for the open-source quickstart.
- File or key selection by the Published Connector or caller-owned request.
- Globally relaxing the signer or inferring FSE2 behavior in Core.
- Claiming the local profile is equivalent to a production HSM/KMS provider.

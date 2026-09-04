# FSE2 local PKCS#12 provider runbook

## Scope and limits

This runbook enables a local laboratory with PostgreSQL, Gateway/Admin UI, Connector Runtime,
Synthetic Provider and the FSE2 pack. It adds a file-mounted provider for A1 mTLS and S1 signing
without requiring Azure. It does not accredit the installation, automatically publish an FSE2
Connector or make live calls.

Certificates, keys, CSRs, P12, passwords, runtime manifests and evidence must remain outside the
repository. Sensitive extensions are already excluded by `.gitignore`, but this does not replace
ACLs and operator checks.

## Prerequisites

- Docker Desktop with Compose;
- Windows PowerShell 5.1;
- OpenSSL 1.1.1 or later;
- A1, A1 CSR, A1 key, S1, S1 CSR, S1 key and official trust anchor in a protected directory
  outside Git, only when a separate operational mandate exists;
- expected A1, S1 and trust-anchor SHA-256 fingerprints obtained through an authorized channel;
- a new output directory outside the repository.

The process does not support interactively encrypted source keys: it avoids prompts and fails.
Received source keys remain temporary and must be deleted or archived according to custody
policy only after import, backup and rollback have been verified.

## 1. Read-only preflight

The default mode creates no output. It cryptographically verifies CSR signatures, exact SPKI
`key ↔ CSR ↔ certificate`, fingerprints, A1/S1 separation, a direct chain to the supplied root,
validity periods and Key Usage/EKU. All paths must be absolute, local, outside the repository and
without UNC, device paths, ADS, junctions/symlinks/reparse points in the leaf or ancestors.

```powershell
$arguments = @{
  AuthCertificatePath = 'C:\SecureInput\A1.pem'
  AuthPrivateKeyPath = 'C:\SecureInput\AUTH.key'
  AuthCsrPath = 'C:\SecureInput\AUTH.csr'
  SignCertificatePath = 'C:\SecureInput\S1.pem'
  SignPrivateKeyPath = 'C:\SecureInput\SIGN.key'
  SignCsrPath = 'C:\SecureInput\SIGN.csr'
  TrustAnchorPath = 'C:\SecureInput\ministero-test-root.pem'
  ExpectedAuthFingerprintSha256 = '<64 hex characters obtained out of band>'
  ExpectedSignFingerprintSha256 = '<64 hex characters obtained out of band>'
  ExpectedTrustAnchorFingerprintSha256 = '<64 hex characters obtained out of band>'
  OutputDirectory = 'C:\SecureRuntime\fse2-local'
  RuntimePrincipal = 'NT SERVICE\SecureIntegrationGateway'
}
./tools/fse2/New-Fse2LocalPkcs12Material.ps1 @arguments
```

The required result is `PASS_READ_ONLY_PREFLIGHT` and `outputCreated=false`. Do not correct a
mismatch by weakening the check: verify the provenance of the material.

## 2. Creating runtime material

Only after reviewing preflight:

```powershell
./tools/fse2/New-Fse2LocalPkcs12Material.ps1 @arguments -Execute -Confirm:$false
```

The importer creates a directory with restrictive ACLs, a manifest with SHA-256 sidecar, two P12
files with independent random passwords, A1/S1 leaves and the public trust anchor. It does not
print passwords or keys. Verify `status=PASS_CREATED`, `privateKeysExportedByProvider=false`
and `liveFse2Calls=0`.

On Windows, `RuntimePrincipal` must resolve to a specific user account or service SID; Everyone,
Anonymous, Authenticated Users, Users, Administrators and groups not explicitly authorized are
denied. Final ACLs are protected and exact: SYSTEM/Administrators FullControl and the runtime
identity only Read/Execute on directories and Read on files. Linux uses a non-root user/`uid:N`,
runtime ownership, `0550` directories and `0440` files. For Docker Desktop, the synthetic lab maps
the container UID declared by `FSE2_CONTAINER_RUNTIME_UID`; this demonstrates only bounded
readability of the local bind mount, not HSM, Key Vault or production-grade storage.

The manifest and `material` directory are sensitive operational material even if some files are
public. Do not copy them into the repository, CI artifacts or logs.

## 3. Validation and startup

```powershell
$manifest = 'C:\SecureRuntime\fse2-local\manifest.json'
$material = 'C:\SecureRuntime\fse2-local\material'
$labArtifacts = 'C:\SecureEvidence\fse2-lab-per-run'

./tools/fse2/Invoke-Fse2LocalProviderLab.ps1 `
  -Phase Validate -ProviderManifestPath $manifest -MaterialDirectory $material

./tools/fse2/Invoke-Fse2LocalProviderLab.ps1 `
  -Phase Start -ProviderManifestPath $manifest -MaterialDirectory $material `
  -QuickstartArtifactRoot $labArtifacts
```

If the pinned SDK is neither under `.dotnet` in the worktree nor the system `dotnet`, explicitly
specify its executable with `-DotNetPath`.

`Validate` repeats the pack build/tests and invokes the single canonical Compose validator,
using unprinted process-local synthetic values and no `--no-interpolate`. `Start` uses the
opt-in `deploy/fse2/docker-compose.fse2-local.yml` overlay and verifies non-root user, read-only
filesystem, read-only mounts, both packs and live/ready health over TLS with a synthetic CA.
The ordinary quickstart remains unchanged. The canonical per-run fixture is:

```powershell
./tools/fse2/Test-Fse2PathPolicy.ps1
./tools/fse2/Test-Fse2LocalPkcs12Material.ps1 -ValidateCompose -StartLab
```

It generates only per-run synthetic keys/CSRs/certificates/P12, tests signing and client
certificates, tampering with `live=200`/`ready=503`, degraded stop and cleanup, and removes
fixtures and temporary artifacts.

The presence of packs and identities does not authorize real outbound traffic. Profile
publication, official endpoint, grants and FSE2 invocation require a separate plan and mandate
with redacted evidence.

## 4. Shutdown and cleanup

```powershell
./tools/fse2/Invoke-Fse2LocalProviderLab.ps1 -Phase Stop
```

`Stop` neither reads nor requires manifests, P12, chains, passwords, env files or readiness.
It enumerates only containers, networks and volumes with exact-match project labels, rechecks
ownership of each target, removes them and must return `FSE2_LOCAL_PROVIDER_STOP_PASS` with
zero containers/networks/volumes/helpers. A similarly named resource with a different project
label must be preserved. Retain only redacted evidence manifests outside Git; do not include
P12, passwords, keys, tokens, headers or payloads.

## Criteria before a live call

- Independent review of the exact-head candidate.
- Fingerprints and chains rechecked before import.
- Server-owned bindings: A1 for mTLS only, the same S1 for authorization and integrity.
- Published endpoint/profile approved four-eyes with the exact checksum.
- Revocation/rotation plan, redacted logging and cleanup.
- Explicit call authorization and accreditation scope.

The local profile remains unsuitable for production custody: Administrator/SYSTEM and anyone
controlling the host directory can read or replace material, and the key is in memory during use.
The remediation and its tests use exclusively synthetic fixtures: no real certificate/CSR/key
was accessed, no real P12 was created or imported, and no FSE2 endpoint was called. Operational
custody, revocation/rotation, accreditation and live qualification remain external blockers.

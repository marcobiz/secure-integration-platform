# Standalone Windows Local Broker

**Status: standalone and continuity software integrated through PR #68; Windows delivery
candidate `5ad048f169b5ba19d8d058d240a2c5029cce9703` passed the bounded real-service
checks [recorded below](#windows-delivery-observed-on-september-5-2026).**
The candidate is not yet integrated. Its non-elevated account is a member of
Administrators, not a qualified standard non-admin account. The earlier elevated-only
service result remains attached to `3955fd0c3a5eccf816d44b0faba9a704227baa3d`.
Neither result establishes a Windows compatibility matrix or disaster recovery.

This path uses local `ProtectData`/`UnprotectData`, not the Direct Gateway pilot.
It needs no Gateway, PostgreSQL, cloud account, external certificate or enrollment.
Only synthetic data is used by the sample. The key stays in the Broker process and
is DPAPI-wrapped on disk, not returned by the SDK. This is software key custody,
not hardware non-exportability, EDR or protection against Administrator/SYSTEM or
code injected into an authorized application.

## Prepare once

The Windows delivery candidate adds a self-contained archive built by
`eng/Build-LocalBrokerPackage.ps1`, with a closed file/hash inventory, runtime dependency
manifests and the [short package guide](../../deploy/windows/README.md). Extract outside
the repository; the adopter does not need Git, an SDK, Node or Docker. SHA-256 is an
integrity checksum, not publisher authentication. Target-specific non-elevated and
two-build operational evidence is recorded below with the actual account/build limits.

An administrator installs published binaries on a Windows x64 machine. The source
developer needs the pinned .NET SDK; a self-contained runtime installation does not.
The current project target is `net10.0-windows10.0.17763.0`; this is not a tested
compatibility matrix. Use Windows PowerShell 5.1 for service lifecycle commands.
Unsigned development artifacts are for evaluation, not a signed MSI release.

From a source checkout, publish these two artifacts (or obtain these directories
from your authorized build). No database or operating credentials are involved:

```powershell
dotnet publish src/Broker/Broker.Service/Broker.Service.csproj -c Release -r win-x64 --self-contained true -p:NuGetLockFilePath=obj/standalone-win-x64.lock.json -o .artifacts/local-broker/broker
dotnet publish samples/LocalBroker/LocalBroker.csproj -c Release -r win-x64 --self-contained true -p:NuGetLockFilePath=obj/standalone-win-x64.lock.json -o .artifacts/local-broker/sample
```

The runtime-specific lock is generated outside tracked lock files; existing package
versions are centrally pinned. Keep the published directories and the shipped
[`Invoke-LocalBroker.ps1`](../../deploy/windows/Invoke-LocalBroker.ps1) together when
copying them to the runtime host. No repository/test knowledge is required there.

Obtain the application user's SID in that user's ordinary console with
`[Security.Principal.WindowsIdentity]::GetCurrent().User.Value`. Pass that observed
value as `$applicationSid` in the administrator's elevated Windows PowerShell:

```powershell
.\Invoke-LocalBroker.ps1 -Command Install -Instance sample -BrokerPublishDirectory .\broker -SamplePublishDirectory .\sample -ApplicationUserSid $applicationSid
.\Invoke-LocalBroker.ps1 -Command Start -Instance sample
```

Install claims a fresh, named directory under Program Files and ProgramData,
registers an own-process service `SecureIntegrationBroker.Local.sample` as
`NT SERVICE\SecureIntegrationBroker.Local.sample`, writes a unique Installation ID,
grants the explicitly selected application user's SID and the installed sample's exact path/hash, and
allows only status and protection for `sample` / `text/plain`.
Start creates the local data key once under that service identity, then disables
initialization in the persistent configuration. It reports `START=RUNNING` for SCM
readiness; run the sample's `status` under the registered user to verify application
readiness. The setup administrator is not implicitly authorized to use the application.

Install repeated on a complete instance preserves configuration. A partial install
without protected data can be resumed with the same command. Partial state with
existing data fails closed; it is not silently treated as a new installation.

## Protect and recover

Close the elevated console. In an ordinary console under the registered account:

```powershell
$sample = "$env:ProgramFiles\SecureIntegration\LocalBroker\sample\sample\SecureIntegration.Samples.LocalBroker.exe"
& $sample protect SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample local-sample .\sample.envelope
& $sample verify SecureIntegrationBroker.Local.sample SecureIntegrationBroker.Local.sample local-sample .\sample.envelope
```

`protect` creates a new ciphertext file and refuses to overwrite one. `verify`
recovers the synthetic value in memory and checks wrong-purpose/content-type and
tampered-envelope denial. Output contains only pass/fail, elapsed time and bounded
error codes, never plaintext or keys. Application plaintext is naturally available
to an authorized `UnprotectData` caller; this is not protection from that caller.

For your own .NET application, use `BrokerClient` from `SecureIntegration.Broker.Sdk`
and the same `ProtectDataRequest`/`UnprotectDataRequest` calls shown in the
[small sample](../../samples/LocalBroker/Program.cs). Pin `ServiceName`, `PipeName`
and your application registration in trusted application configuration. The SDK
queries SCM, retains a live process handle, checks the connected pipe's kernel PID
and virtual-service owner SID **before writing the handshake or request**. There is
no public verification bypass, network transport or automatic invocation retry.
Each call makes a newly authenticated connection, including after restart.

An administrator registers your application in the protected service configuration:
`AllowedUserSids`, exact installed `ExecutablePaths`, optional pinned hash/trusted
publisher, `AllowedOperations`, and exact `AllowedDataProtectionContexts` pairs.
An empty context list denies protection. Keep the executable and its managed DLLs
in administrator-writable-only directories. Do not authorize `dotnet.exe`, a shell
or a general-purpose interpreter as the application. Path/publisher-controlled
upgrades and optional hash updates are explicit administrator decisions.

The Broker derives the application from its OS-verified caller. Tenant/Gateway
identities are not involved. AEAD binds Installation, application, purpose and
content type; context identifiers must not contain CR/LF. A context grant is not
permission to decrypt another application's or Installation's envelope.

## Stop, restart and update

Run these lifecycle commands elevated. Stop never removes protected data, binaries,
configuration, profile or service registration; it is safe to repeat. Foreign or
uncertain ownership and reparse paths are denied without touching the resource.

```powershell
.\Invoke-LocalBroker.ps1 -Command Stop -Instance sample
.\Invoke-LocalBroker.ps1 -Command Start -Instance sample
.\Invoke-LocalBroker.ps1 -Command Update -Instance sample -BrokerPublishDirectory .\broker -SamplePublishDirectory .\sample
```

Update stops the owned service, copies authorized published binaries, preserves the
Installation/configuration/data/ACLs, updates the sample hash and starts normally
with initialization disabled before the first copy. On copy/start failure it reports failure, not a
successful upgrade; correct the cause and rerun Update. It is not a transactional
MSI updater or compatibility guarantee. Re-run `verify` against the **same** envelope.

## Key lifecycle and recovery limits

Normal startup and `GetActiveAsync` never create replacement keys. Explicit
first-use initialization accepts a genuinely empty key directory; a persistent
claim marker and create-new writes prevent concurrent or interrupted attempts from
overwriting material. Existing initialized stores remain readable without format
conversion. Key versions in envelopes are exact; an unknown version is not tried
against a different key. No automatic rotation or retirement is implemented.

Back up protected data, the complete Broker data directory, installation metadata
and application policy **while the service is stopped**, with access controls and
the same operational protection as the originals. Retain the Windows/service-user
profile and system state needed by DPAPI. Restore only into that same machine,
service identity/profile and Installation context, preserving ACLs, then start
normally and verify an existing envelope. Never enable initialization to repair
loss and never edit `active.txt` or key files to make startup pass.

The automated restore test replaces a synthetic wrapped blob from its saved copy
while the same CurrentUser profile remains available. Wrong-profile behavior is a
simulated DPAPI unwrap failure plus real DPAPI corruption tests, **not** a proved
machine/profile disaster restore. Machine/profile loss may make the data permanently
unrecoverable. Re-enrollment, a new key or copied DPAPI blobs cannot recover it.
Deletion/destruction of a key also destroys decryptability of dependent envelopes;
Stop is deliberately not a destructive uninstall or key-retirement command.

| Error | Meaning and safe action |
|---|---|
| `broker_server_not_authenticated` | Expected own-process service/pipe authority is absent or mismatched. Verify the installed service/configuration; never bypass authentication. |
| `data_context_not_granted` | Administrator policy does not allow that exact context. Correct the request or explicitly authorize the intended pair. |
| `data_key_store_not_initialized` / `key_metadata_corrupt` | Missing/inconsistent active metadata. Preserve state; restore the complete known-good same-profile backup. |
| `data_key_initialization_incomplete` / `data_key_initialization_failed` | Explicit provisioning was interrupted or could not claim/write the store. Preserve partial material; do not delete it as a retry strategy. |
| `data_key_storage_unavailable` / `data_key_unwrap_failed` | Missing, unreadable or unusable wrapped key/profile. Restore access or the supported backup; do not regenerate. |
| `LOCAL_BROKER_OWNERSHIP_UNCERTAIN` / `LOCAL_BROKER_FOREIGN_SERVICE` | Marker/path/service identity mismatch. Preserve the resource and resolve ownership administratively. |

## One real-service verification entrypoint

The following elevated entrypoint was executed once on the exact candidate:

```powershell
.\Invoke-LocalBroker.ps1 -Command Verify -Instance qualification-20260904 -BrokerPublishDirectory .\broker -SamplePublishDirectory .\sample
```

Choose a fresh instance name. This uses the same installer, actual SCM service and
SDK sample: fresh install → Protect → repeated Stop → Start → verify old ciphertext
→ unregistered/unstaged process denial → Update → verify again. It checks wrapped
key hashes, Installation metadata and data ACL preservation, and reports time to
first Protect. Update here reapplies the supplied candidate; it is not evidence of
cross-version compatibility. Invocations in this historical entrypoint run under the
invoking elevated account; the separate delivery observation below is the evidence
for the non-elevated walkthrough.

Finally it removes only the exact owned service registration; binaries, DPAPI state,
profile, Event Log source and synthetic envelope remain intentionally preserved.
It does not purge event logs or remove foreign resources. A retired qualification
instance is not an invitation to reinitialize its retained data. This cleanup stops
the service and removes its task-owned registration, but deliberately preserves the
fresh installation/state; it is not an uninstall.

Observed once: install/start/status with Gateway disabled; Protect in 139 ms;
`FIRST_PROTECT_MS=12532`; repeated Stop preserving data; restart/status; old-ciphertext
verify; two unauthorized-client denials; Stop/update/start; second old-ciphertext
verify; owned cleanup with persistent state preserved. The elapsed values are
observations, not performance thresholds or guarantees. The update reapplied the same
candidate, so it does not prove cross-version compatibility or ordinary-account use.
Machine/profile restore remains unqualified. Focused in-process/simulated-SCM tests
remain supporting evidence only; they are not the basis for this real-service result.

## Broker to Gateway continuity candidate

The existing remote operation uses the same `BrokerClient` and authenticated pipe. An
ordinary application calls `InvokeGatewayAsync` with only its registered application,
Connector/operation and payload; it cannot select Tenant, Installation, endpoint,
credential or provider resource. An administrator must already have created and
activated a Broker Installation, granted the operation, and Published the Connector
through the supported Gateway/Admin interfaces. The activation code is supplied only
for first enrollment and is cleared from the Broker process environment after the
Gateway accepts the credential.

The Broker persists `gateway-installation-state.json` beside the existing certificate
thumbprint marker. It contains only Installation/credential identifiers, certificate
thumbprints, owned CNG key names and expiry/renewal timestamps. It contains no activation
code, private key, vendor credential, endpoint, request or response body. The current and
replacement keys are non-exportable CurrentUser CNG P-256 keys. At the server-owned
renewal boundary, concurrent application calls serialize into one renewal.

If a renewal response is lost, the pending state remains. A restarted Broker first asks
the Gateway to authenticate that pending certificate; an accepted credential is promoted
without another renewal request. If it is not accepted, the still-authoritative current
credential is checked before a single renewal submission. This is recovery on a later
explicit application call, not an automatic retry loop. A lost application response,
timeout/body interruption, or 5xx after dispatch is returned as non-retryable
`gateway_outcome_ambiguous`; the Broker never resends that invocation. `ConnectionError`
also remains ambiguous because it does not establish whether dispatch occurred. DNS
resolution and TLS-handshake failures are `gateway_transport_failed` and can be attempted
only by a new explicit application call. Read-only policy probes retain their retryable
transport-failure result.

| Error | Meaning and safe action |
|---|---|
| `gateway_credential_state_invalid` | Lifecycle metadata does not match the closed schema/owned markers. Preserve state and repair from an authoritative backup; do not re-enroll. |
| `gateway_credential_state_unavailable` | An owned certificate/key or required marker cannot be recovered. Preserve remaining material; do not generate a replacement identity. |
| `gateway_renewal_outcome_ambiguous` | Renewal may have committed. Do not resend manually; a later explicit call probes the pending credential. |
| `gateway_renewal_state_unresolved` | Neither pending nor current authority can safely establish the next transition. Restore Gateway availability/state before another explicit call. |
| `gateway_outcome_ambiguous` | The remote application effect may have occurred. Reconcile by the Connector's business protocol; do not replay automatically. |
| `gateway_transport_failed` | DNS resolution/TLS-handshake failure, or failure of a read-only policy probe. A later explicit caller invocation may reconnect. |

Targeted evidence covers the public SDK/pipe and real Core authorization, enrollment,
Published Connector and Synthetic Provider through an in-process fault-injection HTTP
handler. It does not itself constitute actual-service, TLS, PostgreSQL, external-provider,
ordinary-user or cross-release qualification. The separate observations below add only
their stated real-service scope, not live renewal qualification.

## Windows delivery observed on September 5, 2026

Software/package commit: `5ad048f169b5ba19d8d058d240a2c5029cce9703` (PR #69).
Host: Windows 10 Pro 22H2 x64, build 19045.6466. The application used the installed
self-contained sample/public SDK outside the repository with a **non-elevated token**;
its account is a direct member of Administrators. Administrative lifecycle actions
were performed separately by the operator through the existing delivered script.

| Observed path | Result and boundary |
|---|---|
| Package | 433 inventory entries verified after independent extraction; sample boots without dotnet on PATH or DOTNET_ROOT, with no IPC in that boot check. Included runtime: Microsoft.NETCore.App 10.0.10. |
| Non-elevated local use | Status, Protect, Unprotect, wrong-purpose/content-type/tamper denial and unregistered-application denial passed on the actual service. New Protect: 137 ms; verify: 112 ms. |
| Distinct-build update | Integrated build `56b6d9a7dd07bdfbcff3ea74e7b9f95b18a59929` prepared one synthetic envelope under an elevated application token solely for compatibility. Update to `5ad048f...` retained the same Installation/keys; the non-elevated candidate decrypted that envelope. This proves this exact build pair, not arbitrary release compatibility. |
| Restart and rejected update | Repeated Stop/Start and a missing-source Update failure preserved the two envelopes, Installation/keys/data ACLs and disabled initialization. Non-elevated status and both envelope verifies passed after each checkpoint. |
| Actual remote path | Sample → authenticated pipe → Windows Service → TLS/mTLS/BGW1 → Gateway/PostgreSQL → Published `sample-secure-service` → Synthetic Provider/vendor passed. After Broker restart, the activation environment was absent and the same Installation retained one active credential, with no replacement. |
| Gateway outage/recovery | Only the owned Gateway container was stopped. One call failed in 4201 ms with `gateway_outcome_ambiguous`, `Retryable=false`; it did not reach the Gateway. After restoring the same container to healthy, a new explicit call succeeded in 2656 ms. No automatic replay occurred. |

The remote ledger contains **four application attempts: three successes and one bounded
failure**, three vendor accepts, zero vendor denials, and three distinct success audits
with `callerKind=Broker`. The unavailable-Gateway attempt added no invocation audit;
absence is not an invented failure or success record. Audit inspection retained only
bounded metadata, not identities, credentials, payloads or raw response/log bodies.

The original baseline non-elevated status attempt **failed** before pipe connection:
SCM lookup passed, but limited OpenProcess access returned ACCESS_DENIED (5). The
candidate fixes the earliest cause by adding only limited-query/synchronize rights
for configured account SIDs on its own process before IPC. SDK peer authentication
remains unchanged. The baseline failure is not reclassified by the elevated envelope
preparation or by the candidate's success.

The operator's final gate verified unchanged local/remote state, stopped the owned
service, restored standalone configuration and removed the temporary CA/environment.
Installation, protected local/remote identity and both synthetic envelopes are retained;
this is not uninstall or backup/restore qualification. The six task containers, network,
synthetic PostgreSQL volume and five task images were removed. Host policy denied
deletion of 12 synthetic bootstrap files under ignored `.artifacts/windows-delivery/raw`:
filesystem cleanup is therefore incomplete. Their initially broad inherited ACL was
replaced by protected owner/SYSTEM/Administrators-only access, with no parent ACL change.
They are not in Git, the package or retained evidence; their recipient database is gone
and their synthetic CA is not trusted by the host/current user. No claim is made about
unobserved access before that ACL correction. No production, external vendor,
FSE2/OfficialTest, live renewal, account outside Administrators, other Windows target,
machine/profile recovery, signed installer or public-release readiness is claimed.

Archive SHA-256: `CA10E0E5A430DE8640F2D6AD39654A2A6D6D47AB48190B5C52D7AFFD9EA11073`.
The checksum is not a signature. Exact software-head CI passed
[General 7/7](https://github.com/marcobiz/secure-integration-platform/actions/runs/33959817220)
and [M5/Admin 15/15](https://github.com/marcobiz/secure-integration-platform/actions/runs/33959817820).

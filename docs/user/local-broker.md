# Standalone Windows Local Broker

**Status: local candidate; real Windows Service qualification pending.**
The SDK, local crypto/storage and transport tests were run on Windows with .NET SDK
10.0.302. They do not attest a Windows Service installation, a standard-user service
invocation, upgrade compatibility across releases, or disaster recovery. The current
host denied SCM create access (Win32 5); no service was installed for this candidate.

This path uses local `ProtectData`/`UnprotectData`, not the Direct Gateway pilot.
It needs no Gateway, PostgreSQL, cloud account, external certificate or enrollment.
Only synthetic data is used by the sample. The key stays in the Broker process and
is DPAPI-wrapped on disk, not returned by the SDK. This is software key custody,
not hardware non-exportability, EDR or protection against Administrator/SYSTEM or
code injected into an authorized application.

## Prepare once

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

In an elevated Windows PowerShell under the account which will run the sample:

```powershell
.\Invoke-LocalBroker.ps1 -Command Install -Instance sample -BrokerPublishDirectory .\broker -SamplePublishDirectory .\sample
.\Invoke-LocalBroker.ps1 -Command Start -Instance sample
```

Install claims a fresh, named directory under Program Files and ProgramData,
registers an own-process service `SecureIntegrationBroker.Local.sample` as
`NT SERVICE\SecureIntegrationBroker.Local.sample`, writes a unique Installation ID,
grants the current user's SID and the installed sample's exact path/hash, and
allows only status and protection for `sample` / `text/plain`.
Start creates the local data key once under that service identity, then disables
initialization in the persistent configuration. It reports `START=READY` only after
an authenticated SDK status confirms `GatewayConfigured=false`.

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
with initialization disabled. On copy/start failure it reports failure, not a
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

Prepared for subsequent authorized execution in an elevated Windows PowerShell:

```powershell
.\Invoke-LocalBroker.ps1 -Command Verify -Instance qualification-20260904 -BrokerPublishDirectory .\broker -SamplePublishDirectory .\sample
```

Choose a fresh instance name. This uses the same installer, actual SCM service and
SDK sample: fresh install → Protect → repeated Stop → Start → verify old ciphertext
→ unregistered/unstaged process denial → Update → verify again. It checks wrapped
key hashes, Installation metadata and data ACL preservation, and reports time to
first Protect. Update here reapplies the supplied candidate; it is not evidence of
cross-version compatibility. Invocations run under the invoking elevated account;
the ordinary-account walkthrough above must also be exercised before that claim.

Finally it removes only the exact owned service registration; binaries, DPAPI state,
profile, Event Log source and synthetic envelope remain intentionally preserved.
It does not purge event logs or remove foreign resources. A retired qualification
instance is not an invitation to reinitialize its retained data.

This entrypoint has **not run** on the candidate. Focused tests use an in-process
transport fixture and simulated SCM only for lifecycle control-flow checks. No new
Windows/live claim follows from those results.

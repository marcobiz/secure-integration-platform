# Runbook: M0/M1 live matrix on a clean Windows VM

## Scope and expected result

This runbook installs Broker through SCM as a real Windows Service, uses `NT SERVICE\SecureIntegrationBroker`, creates two standard local accounts, runs matrix A-F, restarts the VM and produces a redacted, hashed evidence bundle. It neither starts nor implements M2.

A run is valid only if it ends with `post-reboot-summary.json` containing `passed: true` and all of matrix A-F marked `PASS`. Automatic output created without reboot or with a failure is not acceptance evidence.

## 1. Preparing the VM

Use a new x64 VM not joined to a domain, with Windows 11 Pro/Enterprise or a supported Windows Server, NTFS and at least 10 GB free. Take a snapshot before execution. Do not use a VM cloned after a previous first Broker startup.

Install:

1. Windows PowerShell 5.1, normally included.
2. Git for Windows, if cloning the repository.
3. The .NET SDK specified by `global.json` (`10.0.302` for this revision).
4. Windows updates required by laboratory policy.

Copy or clone the repository into the VM. Do not transfer `.artifacts`, `.dotnet`, previous `%ProgramData%\SecureIntegration` directories or output from other runs.

## 2. Initial verification

Open **Windows PowerShell as administrator** and move to the repository root:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
$runId = 'm0-m1-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
.\tools\live-matrix\Test-Prerequisites.ps1 -RunId $runId
```

The command must fail if the session is not elevated, the host is not recognized as a VM, the filesystem is not NTFS, the SDK does not match `global.json` or a same-named service exists that is not owned by the harness.

Keep the snapshot identifier and commit hash separately:

```powershell
git rev-parse HEAD
git status --short
```

The worktree must be clean before testing; the prerequisite check fails otherwise. The automatic documentation matrix update will modify the worktree only at final PASS.

## 3. Complete automatic execution

Start the run, including a real reboot:

```powershell
.\tools\live-matrix\Invoke-LiveMatrix.ps1 -Phase All -RunId $runId -Reboot
```

The initial phase:

1. Publishes Broker and the probe from the current commit.
2. Creates `SibLiveAuthorized` and `SibLiveDenied` as standard users with random passwords protected by DPAPI LocalMachine and administrative ACLs.
3. Registers `SecureIntegrationBroker` with `StartName = NT SERVICE\SecureIntegrationBroker` and an unrestricted service SID.
4. Configures the application manifest with the authorized apphost SID, path and SHA-256.
5. Verifies the service process token, pipe DACL and recursive storage ACLs.
6. Runs A-D, SCM stop/start and DPAPI key tampering/restoration.
7. Registers `SecureIntegration-LiveMatrix-PostReboot-<RunId>` as a `SYSTEM` AtStartup task.
8. Reboots the VM.

After reboot, the task verifies the boot-session change, waits for the automatic service, reuses secret references and envelopes created before reboot, repeats critical denials, analyzes the Event Log and creates the bundle.

## 4. Checking the result

After reconnecting to the VM, open elevated PowerShell:

```powershell
$runId = Get-Content "$env:ProgramData\SecureIntegration\LiveMatrix\last-run-id.txt"
$runRoot = "$env:ProgramData\SecureIntegration\LiveMatrix\$runId"
Get-Content "$runRoot\raw\post-reboot-summary.json" | ConvertFrom-Json | Format-List
Get-ChildItem "$runRoot\evidence"
Get-FileHash "$runRoot\evidence\M0-M1-live-matrix-$runId.zip" -Algorithm SHA256
Get-Content "$runRoot\evidence\M0-M1-live-matrix-$runId.zip.sha256"
git diff -- docs/reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md
```

The two ZIP hashes must match. Open `bundle/manifest.json` and verify per-file hashes. The bundle includes SCM configuration, SID/token, pipe SDDL, storage ACLs, process reports, redacted Event Logs and pre/post-reboot summaries; it excludes passwords, canary inputs, plaintext, secrets, key blobs, DPAPI copies and persistent envelopes.

## 5. Fail-closed criteria

The run terminates with a nonzero exit code and does not update the documentation matrix if any of the following occurs:

- PowerShell is not elevated or the host is not qualified as a VM.
- `StartName` or service token SID differs from the expected virtual identity.
- Pipe DACL differs from service SID plus authorized SID.
- Storage is accessible to a SID other than service, SYSTEM or Administrators.
- Policy accepts a process with an unregistered path.
- A second user can open the pipe or storage.
- DPAPI CurrentUser can unwrap under a different identity.
- An ungranted operation or key/secret extraction API is available.
- Tampered envelopes or key blobs are accepted.
- HMAC or Unprotect is unusable after stop/start or reboot.
- Event Log lacks the normal path, authentication denied, invalid payload, cryptographic failure or key unwrap failure.
- A canary/secret pattern appears in logs.

A failure is a review result; do not manually convert it to PASS. Preserve `failure-<Phase>.json`, diagnose and repeat from the same snapshot or on a new VM.

## 6. Resuming and diagnostics

If reboot occurred but the task did not start, do not simulate the phase. Start it manually, still elevated and in the same post-reboot boot session:

```powershell
.\tools\live-matrix\Invoke-LiveMatrix.ps1 -Phase PostReboot -RunId $runId
```

To inspect a failure:

```powershell
Get-ScheduledTask -TaskName "SecureIntegration-LiveMatrix-PostReboot-$runId" -ErrorAction SilentlyContinue
Get-ScheduledTaskInfo -TaskName "SecureIntegration-LiveMatrix-PostReboot-$runId" -ErrorAction SilentlyContinue
Get-ChildItem "$runRoot\raw"
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='SecureIntegrationBroker' } -MaxEvents 50
sc.exe qc SecureIntegrationBroker
```

The post-reboot phase explicitly refuses to proceed unless it observes a new `LastBootUpTime`.

## 7. Cleanup

After copying the bundle and its hash outside the VM:

```powershell
.\tools\live-matrix\Remove-LiveMatrix.ps1 -RunId $runId -Confirm:$false
```

This removes the service, tasks, synthetic accounts, binaries, Broker storage, credentials and exchange data, preserving the run's evidence/raw. On a VM intended for revert, local evidence may also be deleted:

```powershell
.\tools\live-matrix\Remove-LiveMatrix.ps1 -RunId $runId -PurgeEvidence -Confirm:$false
```

Finally restore or delete the snapshot/VM according to laboratory policy.

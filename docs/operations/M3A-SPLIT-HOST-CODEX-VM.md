# M3A split-host — manual execution in the VM

## Mandate

This procedure does not require elevated Codex in the VM. An operator opens a
**Windows PowerShell 5.1 console as administrator** and runs a single reviewed script,
generated and transferred from the candidate repository. SYSTEM is not used to orchestrate
the VM phase: the privileged identity is needed only to install the real Windows Service
and create the standard test user.

Do not start M3B/M4, modify or merge PR #3, or declare PASS without a PASS
`RESULT.json` and actual traversal through Broker.

## Expected handoff

`Prepare` creates and verifies this directory in the VM:

```text
C:\Lab\M3A\<RUN-ID>\
  input.zip
  input.zip.sha256
  Invoke-M3ASplitVmOperator.ps1
  Invoke-M3ASplitVmOperator.ps1.sha256
  RUNID.txt
```

`input.zip` contains per-run raw synthetic material and must not be opened, printed,
committed or transferred elsewhere. The operator script contains no secrets. Its SHA-256
hash is returned by `Prepare` and must be used in the command, so modifying the script
or sidecar causes a fail-closed stop.

## Single command

From the administrative console in the VM, run exactly the `operatorCommand` value
returned by `Prepare`. Its form is:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File "C:\Lab\M3A\<RUN-ID>\Invoke-M3ASplitVmOperator.ps1" `
  -RunId <RUN-ID> `
  -ExpectedScriptSha256 <SHA-256-SCRIPT>
```

Do not add activation codes, passwords or bootstrap contents to the command line.

## Script contract

The script:

1. Requires an administrative console and verifies the RunId, its own hash, ZIP hash and sidecar.
2. Extracts the handoff without printing or serializing `bootstrap.json`.
3. Rejects loopback Gateway endpoints and a remaining window shorter than 45 minutes.
4. Requires a clean VM worktree, runs `fetch` and switches to the candidate commit in detached HEAD.
5. Starts `ValidateVm` in a separate PowerShell 5.1 process.
6. Only after `ValidateVm` passes, starts `Run` with the same RunId, input, commit and output.
7. Leaves installation of Broker as a real service with StartName
   `NT SERVICE\SecureIntegrationBroker` and execution of the Legacy Simulator as a standard
   user with a `RunLevel Limited` task to the runner.
8. Always produces the canonical result
   `C:\SecureEvidence\<RUN-ID>\RESULT.json`, containing only redacted codes.
9. Returns exit code zero only when the runner's `RESULT.json` and `vm-manifest.json`
   also attest PASS on the candidate commit.

A `BLOCKED`, nonzero exit code or missing manifest prevents PASS.

## Result handoff

On PASS, transfer only these files to the HOST:

- `<RunId>-vm-redacted.zip`;
- `<RunId>-vm-redacted.zip.sha256`;
- the canonical `RESULT.json`.

Do not transfer input, bootstrap, PFX, raw Event Logs, canaries, DPAPI/CNG or build
directories. The HOST verifies sidecars and manifests, runs `Finalize`, correlates
Gateway scenarios and completes cleanup.

## VM cleanup

The runner removes the service, user, `SeBatchLogonRight` privilege, synthetic certificate,
tasks and protected directories owned by the RunId. After the HOST has retrieved the
result, the operator removes only the handoff directory:

```powershell
$runId = '<RUN-ID>'
Set-Location C:\Lab\broker-gateway
.\tools\m3\split-host\Invoke-M3ASplitVm.ps1 -Phase Cleanup -RunId $runId
Remove-Item -LiteralPath ("C:\Lab\M3A\" + $runId) -Recurse -Force
```

If cleanup fails, restore the pre-run Hyper-V checkpoint. The checkpoint is the
laboratory's primary recovery mechanism; existing automatic cleanup is an operational
defense, not a product security property or an independent M3 blocking criterion.

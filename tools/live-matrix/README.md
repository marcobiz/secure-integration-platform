# M0/M1 live matrix harness

This package runs live matrix A-F on a **clean Windows x64 VM**, with elevated Windows PowerShell. It contains no simulated fallbacks: if it cannot create real accounts, service, tokens, ACLs, reboot or Event Log, it exits with a nonzero code.

Entry point:

```powershell
.\tools\live-matrix\Invoke-LiveMatrix.ps1 -Phase All -RunId 'm0-m1-YYYYMMDD-01' -Reboot
```

The pre-reboot phase registers a `SYSTEM` task, then reboots the VM. The task runs the post-reboot phase, creates the redacted bundle under `%ProgramData%\SecureIntegration\LiveMatrix\<RunId>\evidence` and updates the generated section of `docs/reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md` only after a complete PASS.

## Components

| File | Responsibility |
|---|---|
| `Invoke-LiveMatrix.ps1` | idempotent orchestration and post-reboot resumption |
| `Test-Prerequisites.ps1` | elevation, VM, OS/NTFS, SDK and SCM collisions |
| `Install-LiveBroker.ps1` | build/publish, local accounts, policy, service and virtual identity |
| `Invoke-PreReboot.ps1` | matrices A-D, restart, tamper, ACL and cross-identity DPAPI |
| `Invoke-PostReboot.ps1` | persistence E, Event Log/redaction F and A-F closure |
| `New-EvidenceBundle.ps1` | artifact allowlist, per-file manifest, ZIP and SHA-256 |
| `Update-RequirementEvidence.ps1` | documentation update only from a post-reboot PASS summary |
| `Remove-LiveMatrix.ps1` | explicit cleanup of harness-owned objects |
| `probe/` | real client copied to authorized/unauthorized paths and started with distinct tokens |

Synthetic credentials and canaries remain in the ACL-protected state directory; they are excluded from the bundle. Probes are started through Task Scheduler using real logons for the two local accounts. The authorized account represents the installed business application/legacy simulator; a copy of the same apphost in a different path represents the unauthorized process under the same SID.

The complete operational runbook is in `docs/operations/M0-M1-LIVE-MATRIX-RUNBOOK.md`.

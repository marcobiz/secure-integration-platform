# M0/M1 live matrix evidence

**Date:** 2026-08-03

**RunId:** `m0-m1-20260803-232955`

**SUT baseline:** `39ac4eae23d6a4c43729863ca345fdbf10af0ee6`

**Harness baseline:** `f33bf910b9f7c1f5b8a4ea47476c26f7c49c2170`

**Tested commit:** `24288dbe065ecedc21c0018e8ed37ca844bc8caf`

**Technical result:** **PASS LIVE A-F**

**M2 decision:** **NO-GO until the tested commit is integrated into `origin/main`**

## Observed qualification

| Evidence ID | Check | Result |
|---|---|---|
| ENV-001 | `WindowsPrincipal.IsInRole(Administrator)` in the runner | `True` |
| ENV-002 | VM | `DESKTOP-5T30P6J`, Microsoft Virtual Machine, UUID `864384BD-9128-4F51-A741-001485E7DF72` |
| ENV-003 | OS | Windows 11 Pro 10.0.26200, build 26200 |
| ENV-004 | PowerShell | Windows PowerShell 5.1.26100.7920, clean `-NoProfile` process |
| ENV-005 | Repository | commit `24288dbe065ecedc21c0018e8ed37ca844bc8caf` |
| ENV-006 | Service identity | `NT SERVICE\SecureIntegrationBroker` |
| ENV-007 | Qualifying reboot | boot UTC `2026-08-03T21:38:33.1818970Z` |

Preflight produced `preflightPassed: true` and `overallStatus: InProgress`; it was not interpreted as an overall result. `ValidateHarness` produced `HarnessValidated` before system changes.

## A-F: live result

| ID | Status | Observed evidence |
|---|---|---|
| LIVE-A | PASS | Authorized application with pipe, limited grants, HMAC, Protect/Unprotect and persistence |
| LIVE-B | PASS | Distinct process under the same SID reaches the pipe but is denied by policy; storage denied |
| LIVE-C | PASS | Another Windows user denied on pipe, storage and DPAPI |
| LIVE-D | PASS | Encrypted legacy database readable; secret/key-material APIs unavailable |
| LIVE-E | PASS | Envelope and key tamper rejected, restore verified, HMAC and protected data persistent after restart/reboot |
| LIVE-F | PASS | Real Windows Event Log with normal/denied/invalid/crypto/key-failure paths and verified redaction |

## ACLs and service

- Named Pipe protected with only authorized application and service SIDs.
- Windows normalizes the application ACE to `ReadWrite, Synchronize`; the service has `FullControl`.
- Pre/post-reboot storage ACLs protected and exact for SYSTEM, Administrators and service SID.
- SCM configured with `StartName = NT SERVICE\SecureIntegrationBroker`, automatic startup and `UNRESTRICTED` service SID.
- After a second Windows servicing reboot, following matrix completion, the service was still `Running` and no LiveMatrix tasks remained.

## Event Log and redaction

The bundle contains 73 provider events; 41 belong to the current run window. Events are present for success, `application_not_authorized`, `invalid_base64`, `authentication_failed` and `data_key_unwrap_failed`. The SYSTEM report checked 11 protected canaries with no matches; an independent check of values readable from the unelevated session found neither leakage nor generic secret patterns.

## Verified bundle

| Field | Value |
|---|---|
| Run directory | `C:\ProgramData\SecureIntegration\LiveMatrix\m0-m1-20260803-232955` |
| ZIP | `evidence\M0-M1-live-matrix-m0-m1-20260803-232955.zip` |
| ZIP SHA-256 | `5B6E9997EF0C5C482B27B7DB63323BA54C96D5C2B083DAAEB4A47255D156C52C` |
| Manifest schema | `secureintegration.live-matrix.evidence/v1` |
| Declared files | 24 plus `manifest.json` |
| Verification | No missing/extra files; all sizes and SHA-256 hashes match |
| Completion UTC | `2026-08-03T21:40:05.9525444+00:00` |

The bundle is not simulated, is not tracked by Git and remains in ProgramData. The SHA-256 sidecar matches the recomputed digest.

## Preserved blocked runs

Previous runs remain preserved as failure evidence and were not converted into PASS:

- `m0-m1-20260803-183430`: BLOCKED - HARNESS RUNTIME ERROR;
- `m0-m1-20260803-212513`: BLOCKED - account-description provisioning;
- `m0-m1-20260803-215029`: BLOCKED - RID restore;
- `m0-m1-20260803-220555`: BLOCKED - batch logon;
- `m0-m1-20260803-222713`: BLOCKED - probe output ACL;
- `m0-m1-20260803-223835`: BLOCKED - process identity API;
- `m0-m1-20260803-225019`: BLOCKED - virtual service caller identity/Event Log source;
- `m0-m1-20260803-231445`: BLOCKED - process open/impersonation order;
- `m0-m1-20260803-232142`: BLOCKED - pipe ACE normalization in verifier.

Each run was preserved and cleaned through `Remove-LiveMatrix.ps1` without `PurgeEvidence` before starting the next run from a clean state.

## Reboot note

Windows servicing (`TrustedInstaller.exe` as SYSTEM) requested two planned reboots. The matrix post-reboot task ran after the first boot and completed the PASS bundle before the second reboot. The second reboot is external to the matrix and follows completion; subsequent operational state was verified read-only.

## Decision

AC-002 and AC-004 are **PASS-LIVE for the tested commit**. The Gate Review remains **NO-GO for M2** because `origin/main` is still `f33bf910b9f7c1f5b8a4ea47476c26f7c49c2170`. The lineage must be reviewed and integrated while preserving the tested SHA; if rewritten through rebase or squash, a new complete matrix on the new commit is required.

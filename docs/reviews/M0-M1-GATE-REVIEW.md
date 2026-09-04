# Final Gate Review for M0/M1 and the first vertical slice

**Date:** 2026-08-03
**Frozen baseline:** commit `7f68442ceb9adcc47bb1b1a534ad64e23bd26bac`
**Annotated tag:** `baseline-m0-m1-vslice-2026-08-03`
**M0/M1 SUT baseline:** `39ac4eae23d6a4c43729863ca345fdbf10af0ee6`

**Harness baseline:** `f33bf910b9f7c1f5b8a4ea47476c26f7c49c2170`

**Live-tested commit:** `24288dbe065ecedc21c0018e8ed37ca844bc8caf`

**Gate result:** **NO-GO for M2: live matrix PASS, canonical integration pending**

**IPC:** **provisional**, not frozen for COM/C ABI/CLI

This review uses `IMPLEMENTATION_STATUS.md` and the vertical-slice report as its baseline, but records only additional evidence, findings and gate decisions.

## 1. What was actually executed

### Baseline and clean checkout

- repository initialized and baseline committed/tagged before review changes;
- separate clone of the tag in `.artifacts/gate-clean-clone`, detached at `7f68442`;
- in the clone: Release restore/build with SDK 10.0.302, zero warnings/errors;
- in the clone: 6 unit, 9 integration and 1 E2E passed;
- document validation and content-based secret scan passed;
- an M0 defect was found: `scan-secrets.ps1` could leave exit code 1 after an `rg` with no matches despite printing success. Corrected during review, along with explicit exit in the document validator.

The clean checkout ran on the same host using an SDK installed outside the clone: it proves independence from the working tree, not that the OS is a clean machine.

### Hardening added during review

The review added tests/controls for:

- frame network layout, magic/version/type/flags, EOF/truncation and exact/oversize bounds;
- handshake sequence and malformed nonce;
- AES-GCM nonce, complete AAD, malformed envelope and unknown key version;
- idempotent delete, cross-Application and HMAC grants;
- explicit pipe and storage ACLs;
- persistence after repository reopen;
- wire/error/audit redaction for normal paths, denied authentication, invalid payload and cryptographic failure;
- process creation time, process-handle and file-handle closure;
- image/path race protection by retaining a read-only executable file handle for the entire connection;
- deterministic classification between deadline, client cancellation and shutdown;
- redacted mapping of storage records with corrupt Base64.

The four critical IPC/identity/cancel/redaction tests passed in **20/20 iterations**, 80 total executions without failure.

On the final live state: Release build of the entire solution with **0 warnings/0 errors**; **26 unit + 22 integration + 1 E2E = 49/49 tests passed**; PowerShell 5.1 parsing, `ValidateHarness`, documentation gate and secret scan passed.

## 2. Live environment qualification

The qualified environment for the live run is:

| Property | Observed value |
|---|---|
| OS | Windows 11 Pro 10.0.26200, build 26200 |
| Type | Microsoft Virtual Machine, UUID `864384BD-9128-4F51-A741-001485E7DF72` |
| Elevated runner | Yes, verified with `WindowsPrincipal.IsInRole(Administrator)` |
| PowerShell | Windows PowerShell 5.1.26100.7920, `-NoProfile` process |
| Repository commit | `24288dbe065ecedc21c0018e8ed37ca844bc8caf` |
| RunId | `m0-m1-20260803-232955` |
| Observed reboot | boot UTC `2026-08-03T21:38:33.1818970Z` |

The elevated runner created distinct local accounts, installed the service with a virtual account, applied real ACLs and configured a post-reboot task executed as SYSTEM. No simulated evidence was used.

### Live matrix A–F

| Matrix | Live evidence | Gate result |
|---|---|---|
| A — authorized application | pipe, grants, HMAC, Protect/Unprotect and persistence | PASS-LIVE |
| B — unauthorized process, same user | distinct process/path denied by policy; storage denied | PASS-LIVE |
| C — different Windows user | pipe, storage and DPAPI denied | PASS-LIVE |
| D — business application account | encrypted legacy DB readable; no API for secrets or key material | PASS-LIVE |
| E — restart and reboot | envelope/key tamper rejected, restore successful, HMAC and protected data persistent | PASS-LIVE |
| F — Windows Service logging | real Event Log present and scan of 11 canaries without leakage | PASS-LIVE |

The service remained installed and `Running` as the final observable SUT state. The post-reboot task was removed automatically; the bundle and blocked runs are retained in `C:\ProgramData\SecureIntegration\LiveMatrix`.

The qualified transcript and evidence-pack checklist are in `docs/reviews/evidence/M0-M1-LIVE-MATRIX-EVIDENCE.md`.

### Evidence acquired

Bundle `M0-M1-live-matrix-m0-m1-20260803-232955.zip` contains 24 files declared in the manifest plus the manifest itself. All sizes and SHA-256 hashes were verified; the ZIP SHA-256 is `5B6E9997EF0C5C482B27B7DB63323BA54C96D5C2B083DAAEB4A47255D156C52C` and matches the sidecar.

## 3. Targeted re-examination of critical surfaces

### IPC framing and bounds

The 36-byte frame, byte order, GUID, sequence, 1 MiB control hard limit and 64 KiB data frame are boundary-tested. Magic, major, type, flags, truncation and unknown JSON fail closed. Handshake requires a control frame, zero sequence, non-empty correlation and 16–64-byte Base64 nonce.

Residual finding: the declared 16/64 MiB aggregate limits are not implemented end-to-end; current SDK requests use Base64 in the control frame and therefore have an effective capacity below 1 MiB. This blocks IPC freeze, not the start of central M2 components with small payloads.

### Multiplexing and cancellation

Multiple requests on the same connection, potentially out-of-order responses, a limit of 16, deadlines and Cancel frames are implemented. The review explicitly separated client cancellation, deadline and shutdown, eliminating a flaky timing classification. The SDK still opens one connection per call.

### PID reuse, handles and authorization races

PID comes from `GetNamedPipeClientProcessId`; SID from the process primary token. Creation time, canonical path, SHA-256 and trusted publisher are captured. The process handle and executable file handle remain open until the connection closes; creation time is rechecked. The test verifies that `Dispose` closes both handles.

This reduces PID reuse and path/image replacement, but does not eliminate code injection into an authorized process or administrator compromise. A deterministic test forcing PID reuse or replacement during the capture/authorize window is missing.

### Pipe/storage ACLs and DPAPI

Security descriptors are protected from inheritance and have no World grants. The pipe includes the service SID plus configured application SIDs; storage includes the current service identity, SYSTEM and Administrators. Automated tests verify construction, not enforcement between real identities.

DPAPI uses `CurrentUser`, never `LocalMachine`. The effective root of the virtual service identity and its profile behavior have not been observed live: AC-002/004 remain open.

### AES-GCM, metadata and key versioning

- 256-bit key per Installation, random 96-bit nonce and 128-bit tag;
- AAD includes protocol marker, Installation, Application, purpose and content type;
- envelope contains key version; unknown version does not attempt fallback;
- tag/ciphertext tamper, malformed envelope, corrupt DPAPI key and corrupt secret record are rejected;
- 512 repeated protection operations produced no duplicate nonces.

Writing `active.txt` remains non-atomic, and the operational rotation workflow is missing.

### Logging and exceptions

IPC responses expose only code/category/retryable. Normal/denied/error audits use operation/application/correlation and sanitized codes; paths, payloads, Base64, stacks and exception types are not emitted. Denied authentication now produces a metadata-only audit.

The live run covers the Windows Event Log provider on normal, denied, invalid-payload, authentication-failure and key-unwrap-failure paths. Unhandled crashes and future telemetry remain non-blocking debt.

## 4. AC-002 and AC-004 criteria

- **AC-002 — PASS-LIVE on the tested commit:** real `SecureIntegrationBroker` instance observed with `StartName = NT SERVICE\SecureIntegrationBroker`, service SID, SCM restart and post-reboot persistence.
- **AC-004 — PASS-LIVE on the tested commit:** pipe/storage denied to the other user and DPAPI `CurrentUser` could not be unlocked by authorized, same-user untrusted or other-user accounts.

The result is attributable exclusively to commit `24288dbe065ecedc21c0018e8ed37ca844bc8caf` recorded in the manifest.

## 5. Open decisions evaluated, not implemented

| Topic | Recommended decision | Rationale | Milestone/ADR | Blocks M2? |
|---|---|---|---|---|
| Application policy upgrade | Default `SID + canonical path + trusted publisher`; optional hash for high-assurance/emergency pinning. Prohibit publisher-only without file handle/chain policy. | Publisher allows controlled upgrades; hash-only is fragile; path/SID bound scope. | Clarify ADR-0016 by M6, validate signed positive path in M9. | No for starting M2. |
| Virtual service identity profile recovery | MVP: reinstall/re-enroll and declared loss of unrecoverable local data only; no universal DPAPI-root escrow. Define supported backup only if it protects the entire profile/host. | Avoids a global KEK and unsustainable recovery promises. | Update ADR-0014 and ADR-0004 by M9, before the pilot. | No for M2 development; blocks pilot/production. |
| Installation ID/manifest provisioning through MSI | Unique random Installation ID generated once; atomic configuration under ACL; validated manifest signed or sourced from the control plane; repair does not regenerate ID. | AC-005 and M2 identity depend on a stable, non-cloned identity. | ADR-0017 Accepted; MSI implementation M9. | Documentation blocker closed; compliance remains mandatory for M2 identity integration. |
| Legacy adapter streaming API | Keep Data/End frames experimental; define backpressure, cancellation, buffer ownership and x86 limits only after M2/M3. | Avoids freezing an ABI around assumptions not validated end-to-end. | Update ADR-0003 during M3, freeze in M6. | No. |
| Operational key rotation | Atomic active version, retention of readable versions, audited administrative rotation and lazy migration; never silent fallback on unknown versions. | Maintains decryptability and makes rollback/recovery verifiable. | Extend ADR-0004 before M7/M9. | No for M2. |

ADR-0017 was subsequently accepted and formalizes MSI/Installation identity provisioning without implementing M2. Other recommendations remain planned for the indicated milestones.

## 6. IPC status

The current protocol is **provisional/stable only for internal M1 use**. It is not “experimental throwaway”, because framing and basic semantics have regression tests; however, it is not “frozen”, because it lacks:

- 16/64 MiB aggregate streaming and backpressure;
- validation with M2 Installation identity/revocation;
- production-like M3 vertical slice;
- .NET Framework, x86, COM and C ABI compatibility;
- stateful fuzzing and long-running connection tests.

No M6 adapter should assume a final ABI before these gates.

## 7. M2 blocker

1. **Canonical integration pending:** the PASS run is on local commit `24288dbe065ecedc21c0018e8ed37ca844bc8caf`; `origin/main` still points to `f33bf910b9f7c1f5b8a4ea47476c26f7c49c2170`.

The corrective lineage must be reviewed and integrated while preserving the exact tested SHA. If integration uses squash, rebase or any rewrite, the complete matrix must be rerun on the new commit from a clean state. Previous live A-F, AC-002, AC-004 and Event Log blockers are closed for the tested commit.

## 8. Non-blockers

1. SDK without a shared persistent connection.
2. Authenticode positive test with a controlled synthetic chain.
3. Dedicated PID reuse/replacement fault injection.
4. Remote CI not executed, provided it becomes mandatory before M2 merge/release.
5. Service identity profile recovery, provided it is closed before the pilot.

## 9. Deferred debt

1. aggregate streaming and backpressure;
2. operational key rotation and `active.txt` atomicity;
3. MSI install/repair/upgrade/uninstall and artifact signing;
4. .NET Framework, COM, C ABI and CLI;
5. stateful fuzzing, EventLog/telemetry corpus and performance soak;
6. production Gateway/Vault/Installation identity, intentionally M2+.

## 10. Administrator/SYSTEM residual risk

Local Administrator and SYSTEM can read memory, impersonate the service, change ACLs/policy, replace binaries or acquire the DPAPI profile. M0/M1 do not consider these fully mitigable threats. ACLs, DPAPI and process authorization protect against unprivileged users/processes and offline copies; they are not a barrier against administrative control of the host. No drivers, mandatory TPM, anti-debug or other disproportionate mechanisms are proposed.

## 11. Final decision

The M0/M1 technical matrix is **PASS** and AC-002/AC-004 are satisfied for the tested commit. The operational decision remains **NO-GO for M2** until the same lineage is reviewed and integrated into the canonical branch; if the SHA changes, a new complete run is needed. This review neither implements nor starts any M2 functionality.

The complete requirement/test/evidence matrix is in `docs/reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md`.

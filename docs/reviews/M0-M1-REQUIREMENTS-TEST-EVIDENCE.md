# M0/M1 matrix: requirement → test → evidence

Review date: 2026-08-03. Examined baseline: commit `7f68442ceb9adcc47bb1b1a534ad64e23bd26bac`, tag `baseline-m0-m1-vslice-2026-08-03`. The live run uses SUT baseline `39ac4eae23d6a4c43729863ca345fdbf10af0ee6`, harness baseline `f33bf910b9f7c1f5b8a4ea47476c26f7c49c2170` and tested commit `24288dbe065ecedc21c0018e8ed37ca844bc8caf`.

## Legend

- **PASS-A**: automated test executed in this review.
- **PASS-C**: evidence obtained from a clean checkout of the baseline tag.
- **PASS-S**: static verification or repository gate; does not replace live evidence.
- **PASS-LIVE**: test completed on a real Windows Service with distinct identities and reboot.
- **PARTIAL**: partly automated, but required evidence is missing.
- **OPEN-LIVE**: still requires complete live testing.
- **OUT**: explicitly belongs to later milestones.

The names below are actual test names, not planned IDs.

## M0 — Foundations

| M0 gate | Precise evidence | Status | Limitation |
|---|---|---|---|
| Git and identifiable baseline | commit `7f68442`; annotated tag `baseline-m0-m1-vslice-2026-08-03` | PASS-S | Local tag; no remote configured/verified. |
| Pinned toolchain | `global.json` = SDK 10.0.302; clean checkout built with SDK 10.0.302 outside the clone | PASS-C | The script does not install the SDK itself. |
| Reproducible restore/build | `eng/build.ps1`; clean tag checkout: Release build, 0 warnings/0 errors | PASS-C | Executed on the same host, not a clean OS. |
| Test runner and solution | `eng/test.ps1`; clean tag checkout: 6 unit + 9 integration + 1 E2E | PASS-C | The tag predates hardening tests added by the review. |
| Analyzer/warnings | Release build with `TreatWarningsAsErrors` | PASS-A | Does not replace dedicated SAST. |
| Schema/documentation | `eng/validate-docs.ps1` | PASS-A | Validator targets JSON and expected links, not full Markdown lint. |
| Secret scan | `eng/scan-secrets.ps1`; pattern scan + Gitleaks defined in CI | PASS-A/PASS-S | Gitleaks CI not run in this session. The PowerShell wrapper's spurious exit code was corrected during review. |
| Dependency vulnerability | `dotnet list BrokerGateway.slnx package --vulnerable --include-transitive` | PASS-A | Feed snapshot at the review date. |
| SBOM | `eng/generate-sbom.ps1`, SPDX 2.2 generated | PASS-A | Artifact in `.artifacts`, unsigned. |
| CI | `.github/workflows/ci.yml` inspected | PASS-S | No GitHub Actions run available: requirement not yet automated remotely. |
| Skeleton package | `deploy/windows`, `deploy/docker`, release manifest | PASS-S | Real MSI/containers belong to later milestones. |

## M1 — Functional requirements

| Requirement | Executed test/evidence | Status | Not yet demonstrated |
|---|---|---|---|
| FR-003 — Application/operation authorization | Automated tests plus live A-C matrix with unauthorized same-user process and another user | PASS-A/PASS-LIVE | Authenticode publisher has only a negative path on an unsigned binary. |
| FR-004 — Put/Delete without GetSecret | Automated tests plus live lifecycle through the installed service, restart and reboot | PASS-A/PASS-LIVE | No residual M1 gap. |
| FR-005 — AEAD/key versioning | `UT_CRYPTO_AeadRoundTripTamperRotation`; `AES_GCM_nonce_is_unique_across_repeated_protection`; `AEAD_authenticates_application_purpose_and_content_type`; `AEAD_rejects_unknown_key_version_without_trying_another_key`; `AEAD_rejects_malformed_envelope`; `AC005_Installation_key_and_ciphertext_differentiation` | PASS-A | Operational/atomic rotation not implemented. |
| FR-006 — M1 HMAC | `UT_BRK_LocalSecretLifecycle`; `HMAC_requires_an_explicit_secret_operation_grant`; `Repository_reopen_recovers_keys_secrets_and_protected_data_under_same_identity` | PASS-A | Local signing and certificate: OUT (M7). |
| FR-015 — .NET SDK, M1 portion | SDK used by `IT_BRK_*`, concurrency and vertical-slice E2E; `netstandard2.0`/`net10.0` builds | PASS-A | .NET Framework/COM/C ABI/CLI: OUT (M6); IPC not frozen. |
| FR-018 — Offline local operations | Automated tests plus DPAPI under virtual service account, SCM restart and real reboot | PASS-A/PASS-LIVE | Operational profile recovery remains pre-pilot debt. |

## M1 — Non-functional requirements and targeted surfaces

| Requirement/surface | Executed test/evidence | Status | Explicit gap |
|---|---|---|---|
| NFR-001 — Secret/log redaction | Automated tests, real Event Log and live scan of 11 canaries | PASS-A/PASS-LIVE | Unhandled crashes and future telemetry remain debt. |
| NFR-002 — Deny-by-default | Automated negative paths plus real same-user process and different SID | PASS-A/PASS-LIVE | No residual M1 gap. |
| NFR-004 — IPC bounds | `IPC_frame_accepts_exact_hard_limit`; `IPC_frame_rejects_body_above_hard_limit`; malformed/truncated/header tests | PARTIAL | 16 MiB aggregate and 64 MiB stream not assembled by SDK/server. |
| NFR-005 — Timeout/cancel/idempotency | `Pipe_supports_concurrent_clients_and_deadline_cancellation`; `Same_connection_multiplexes_requests_and_honors_cancel_frame`; idempotent delete; 20× stress on critical IPC tests | PASS-A for M1 | Retry/circuit breaker belong to M2+. |
| NFR-006 — Correlation | E2E verifies `X-Correlation-Id` Broker→Gateway | PARTIAL | Complete W3C trace context not implemented. |
| NFR-008 — Build/SBOM | Clean checkout, warning-free build, vulnerability scan, SPDX | PASS-A/PASS-C | Artifact signing not planned in M0/M1. |
| NFR-010 — No central payload persistence | E2E harness keeps payloads only in memory; local storage inspection | PASS-A in the vertical slice | No production Gateway/DB present. |
| Framing/version/handshake | `IPC_frame_round_trip_preserves_network_header_and_payload`; hard-limit/malformed/EOF/unknown JSON tests; `Handshake_rejects_nonzero_sequence_and_malformed_nonce` | PASS-A | Stateful fuzzing not executed. |
| Multiplexing/cancellation | `Same_connection_multiplexes_requests_and_honors_cancel_frame`; `Pipe_supports_concurrent_clients_and_deadline_cancellation`; stress 20/20 | PASS-A | Shared persistent SDK connection not implemented. |
| PID reuse/creation time/handles | `Named_pipe_caller_identity_is_captured_from_the_kernel` verifies PID, path, creation time and process/file handle closure | PARTIAL | Forced PID reuse is not automated; requires a dedicated harness/VM. |
| Identity→authorization race | Code review: process handle and read-only executable handle remain open for the connection; start time rechecked; hash/publisher snapshot used by authorizer | PASS-S + handle test | No fault-injection test replaces the image between capture and authorize. |
| Storage ACLs | Automated test plus exact pre/post-reboot ACLs with service SID and distinct users | PASS-A/PASS-LIVE | No residual M1 gap. |
| Pipe ACLs | Automated test plus SDDL and real access-denied for a different SID | PASS-A/PASS-LIVE | No residual M1 gap. |
| DPAPI CurrentUser | Automated round-trip plus cross-identity denial on service blob | PASS-A/PASS-LIVE | Service identity profile recovery remains pre-pilot debt. |
| AES-GCM nonce | 512 envelopes with the same key/plaintext, all 96-bit nonces distinct | PASS-A | Statistical test, not mathematical proof of the CSPRNG; uses `RandomNumberGenerator`. |
| AAD metadata | Tests with wrong Application, Installation, purpose and content type | PASS-A | No unexpected client metadata accepted by JSON. |
| Key versioning/corruption | Rotation/tamper, unknown version, corrupt DPAPI key, corrupt secret JSON/Base64 | PASS-A | Atomic writing of `active.txt` and rotation command remain debt. |
| Error redaction | Automated wire/audit plus live Event Log for normal/denied/invalid/crypto/key failure | PASS-A/PASS-LIVE | Crashes/unhandled exceptions and future telemetry remain debt. |

## M0/M1 acceptance criteria

| AC | Gate status | Evidence/note |
|---|---|---|
| AC-001 | PASS-A for vertical slice | Vendor API key only in Gateway harness; absent from client/Broker/audit. |
| AC-002 | **PASS-LIVE on tested commit** | Real service on virtual account, restart and post-reboot persistence verified. |
| AC-003 | PASS-A/PASS-LIVE | Policy/hash/publisher/grants and a genuinely distinct same-user process verified. |
| AC-004 | **PASS-LIVE on tested commit** | Pipe/storage ACLs and cross-identity DPAPI verified between service identity, business application and another user. |
| AC-005 | PASS-A | Two repositories/Installations produce different keys and ciphertext. |
| AC-006 | PASS-A/PASS-LIVE | Wire/audit and real Windows Event Log verified without canary leakage. |
| AC-007 | PASS-A in harness | No secrets in Gateway harness responses. |
| AC-008 | PASS-S/PASS-A | Broker depends only on `IGatewayInvoker`; no Vault provider. |
| AC-009 | PASS-A within scope | Request without URL, fixed HTTPS base address, negative TLS. |
| AC-010 | PASS-A within scope | No Gateway secret references; fixed Connector/operation grant. |
| AC-020 | PASS-C | Clean checkout of tag builds and tests with required SDK installed. |
| AC-021 | PASS-A | Repeatable synthetic vertical slice. |
| AC-023 | PASS-A | Secure Layer E2E. |
| AC-027 | PASS-A | SPDX generated. |

Unlisted ACs depend on M2 or later milestones and are not brought forward.

## Live automation executed

The `tools/live-matrix` package ran successfully on an elevated VM and after a real reboot. The result is attributable to commit `24288dbe065ecedc21c0018e8ed37ca844bc8caf`.

| Matrix/requirement | Real command/probe | Evidence produced after PASS |
|---|---|---|
| A / FR-003, FR-004, FR-005, FR-006 | `authorized-pre`, `authorized-post` under `SibLiveAuthorized` | Status/operation grant, HMAC, Protect/Unprotect and persistence report |
| B / NFR-002 | `unauthorized-same-user`, `storage-denied` from the apphost copy in an unregistered path | DACL connection succeeds but policy handshake rejected; storage denied |
| C / AC-004 | `unauthorized-other-user`, `storage-denied`, `dpapi-denied` under `SibLiveDenied` | Pipe/storage denied and CryptUnprotectData failed |
| D / secret boundary | `read-encrypted-database`, unknown `GetSecret`/`GetDataKey`, HMAC-only secret | Encrypted DB readable, no API key/secret material |
| E / AC-002, AC-004 | SCM stop/start, `expected-key-failure`, AtStartup task and `authorized-post` | Service SID token, tamper rejection, valid HMAC/envelope after reboot |
| F / NFR-001, AC-006 | Real Event Log provider and `Invoke-PostReboot.ps1` | Normal/denied/invalid/crypto/key failure present and canary scan PASS |

<!-- LIVE-MATRIX-AUTOMATION:BEGIN -->
## Latest automated live matrix

| Field | Evidence |
|---|---|
| Run ID | `m0-m1-20260803-232955` |
| Result | **PASS live A-F** |
| Tested commit | `24288dbe065ecedc21c0018e8ed37ca844bc8caf` |
| Machine/boot | `DESKTOP-5T30P6J` / `2026-08-03T21:38:33.1818970Z` |
| Service identity | `NT SERVICE\SecureIntegrationBroker`; SID `S-1-5-80-375269102-3931153373-1436009693-879735287-3770408939` |
| Local bundle | `C:\ProgramData\SecureIntegration\LiveMatrix\m0-m1-20260803-232955\evidence\M0-M1-live-matrix-m0-m1-20260803-232955.zip` |
| Bundle SHA-256 | `5B6E9997EF0C5C482B27B7DB63323BA54C96D5C2B083DAAEB4A47255D156C52C` |
| Completion UTC | `2026-08-03T21:40:05.9525444+00:00` |

This section is generated only after an elevated run, an observed reboot and all fail-closed checks passing. The bundle is not simulated and is not versioned in the repository.
<!-- LIVE-MATRIX-AUTOMATION:END -->

## Residual coverage that does not block the live gate

1. Deterministic PID reuse and image replacement during capture/authorize.
2. Authenticode positive path with a signed test executable and controlled chain policy.
3. Aggregate payload 16 MiB, streaming 64 MiB and backpressure.
4. GitHub Actions on a remote Windows runner and artifact signing.

The M2 decision remains NO-GO until the tested commit is integrated into `origin/main`. If integration rewrites the SHA, the complete matrix must be repeated.

# Matrice di tracciabilità requisiti-test

Questa matrice è la baseline. Durante l'implementazione gli ID di test logici vengono sostituiti/affiancati dai nomi reali delle suite e dai link ai report CI.

## Requisiti funzionali

| Req | Milestone | Test/evidence prevista |
|---|---|---|
| FR-001 | M2 | `IT-DAT-RegistryCrud`, RLS integration report |
| FR-002 | M2 | `E2E-IDN-EnrollmentRenewRevoke` |
| FR-003 | M1 | `IT_BRK_Authorized_application_uses_pipe_and_unauthorized_hash_is_denied`, pipe ACL, HMAC/grant negative; live identities aperte |
| FR-004 | M1 | `UT_BRK_LocalSecretLifecycle`, idempotent/cross-Application test, forbidden classes, API surface |
| FR-005 | M1 | AEAD roundtrip/tamper/rotation + nonce/AAD/unknown-version/malformed suite + Installation differentiation |
| FR-006 | M1/M7 | M1 HMAC lifecycle/grant/reopen; firma/certificato: M7 |
| FR-007 | M2 | `SEC-TENANT-ClientTenantIgnored`, `SEC-TENANT-CrossTenantDenied` |
| FR-008 | M3 | `E2E_CON_SecureLayer_success_boundaries_failures_timeout_and_replay` |
| FR-009 | M8 | `E2E-CON-ManagedConnector` |
| FR-010 | M7/M8 | local/gateway/hybrid sequence suites |
| FR-011 | M4 | `IT-CON-BindingScope`, secret absence scan |
| FR-012 | M4 | `UT-CON-LifecycleStateMachine` |
| FR-013 | M4 | `IT-CON-AtomicPublishRollback` |
| FR-014 | M5 | Playwright RBAC/four-eyes suite |
| FR-015 | M1/M6 | M1 SDK: Windows pipe/E2E suite; COM/C ABI/CLI: M6 |
| FR-016 | M2/M5 | audit append/redaction/role tests |
| FR-017 | M5/M9 | health/metrics/tracing/diagnostics tests |
| FR-018 | M1 | DPAPI roundtrip, offline corruption e repository reopen; service identity live aperta |

## Requisiti non funzionali

| Req | Test/evidence prevista |
|---|---|
| NFR-001 | secret scan + wire/audit four-path redaction; EventLog live aperto |
| NFR-002 | deny-by-default authorization/egress/binding/plugin tests |
| NFR-003 | TLS invalid cert/hostname/version tests |
| NFR-004 | IPC exact boundary/oversize pass; aggregate stream/backpressure aperti |
| NFR-005 | M1 deadline/cancel/idempotent delete; retry/circuit isolation da M2+ |
| NFR-006 | correlation Broker-Gateway E2E; W3C distributed trace aperto |
| NFR-007 | canonical checksum/immutability/tamper tests |
| NFR-008 | clean build, SBOM, signature verification report |
| NFR-009 | Windows and adapter compatibility matrix |
| NFR-010 | persistence inspection and payload deletion assertion |

## Acceptance criteria

| AC | Test/evidence |
|---|---|
| AC-001 | `E2E_CON_SecureLayer_success_boundaries_failures_timeout_and_replay` + secret scan |
| AC-002 | **OPEN/BLOCKER:** static service contract passa; vera Windows Service matrix non eseguita |
| AC-003 | automatic policy/grant suite passa; processo/utente distinti live aperti |
| AC-004 | **OPEN/BLOCKER:** DPAPI/ACL descriptor passano; identity separation live non eseguita |
| AC-005 | `AC005_Installation_key_and_ciphertext_differentiation` |
| AC-006 | wire/audit four-path redaction + vertical slice; Windows EventLog live aperto |
| AC-007 | Vertical slice response/secret-absence assertion; Gateway production aperto |
| AC-008 | M1 project dependency boundary + vertical slice through `IGatewayInvoker` |
| AC-009 | `InvokeGatewayRequest` API-surface assertion + fixed HTTPS BaseAddress/TLS negative test |
| AC-010 | fixed Gateway grant negative path nel vertical slice |
| AC-011 | server-side identity binding assertion |
| AC-012 | RLS/composite FK/cross-Tenant suite |
| AC-013 | revocation propagation E2E |
| AC-014 | ConnectorVersion persistence/API test |
| AC-015 | atomic rollback and cache invalidation E2E |
| AC-016 | JSON Schema/semantic/security validation corpus |
| AC-017 | Draft/Validated/Retired runtime denial tests |
| AC-018 | container smoke/health suite |
| AC-019 | MSI install/upgrade/repair/uninstall matrix |
| AC-020 | `eng/build.ps1`, pinned toolchain e istruzioni root |
| AC-021 | `docs/testing/first-vertical-slice-report.md` |
| AC-022 | SDK plus native/COM compatibility report |
| AC-023 | `E2E_CON_SecureLayer_success_boundaries_failures_timeout_and_replay` |
| AC-024 | Managed Connector example execution |
| AC-025 | runbook exercise and diagnostics evidence |
| AC-026 | threat-model review checklist |
| AC-027 | `eng/generate-sbom.ps1` — SPDX generato e validato |
| AC-028 | signature/tamper verification suite |
| AC-029 | pilot rotation/revocation evidence |
| AC-030 | pilot code/package/network bypass evidence |

## Security threats

La fotografia conclusiva M0/M1, inclusi gli elementi non automatizzati, è in `docs/reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md`.

Ogni `TM-*` in `security/threat-model.md` deve essere collegata a uno o più test `SEC-*` prima della milestone che introduce la relativa superficie. Un nuovo adapter/auth method non può essere Published senza aggiornare questa matrice.

# Matrice di tracciabilità requisiti-test

Questa matrice è la baseline. Durante l'implementazione gli ID di test logici vengono sostituiti/affiancati dai nomi reali delle suite e dai link ai report CI.

## Requisiti funzionali

| Req | Milestone | Test/evidence prevista |
|---|---|---|
| FR-001 | M2 | `IT_DAT_PostgreSQL18_migration_and_RLS_isolate_tenants_when_configured`, provisioning exercised by all `GatewaySecurityTests` |
| FR-002 | M2 | `UT_GTW_Enrollment_PoP_derives_tenant_and_replay_is_rejected`, `UT_GTW_Renewal_allows_seven_day_overlap_then_expires_old_credential`, `UT_GTW_Revocation_is_immediate_for_runtime_and_grants` |
| FR-003 | M1 | `IT_BRK_Authorized_application_uses_pipe_and_unauthorized_hash_is_denied`, pipe ACL, HMAC/grant negative; live identities aperte |
| FR-004 | M1 | `UT_BRK_LocalSecretLifecycle`, idempotent/cross-Application test, forbidden classes, API surface |
| FR-005 | M1 | AEAD roundtrip/tamper/rotation + nonce/AAD/unknown-version/malformed suite + Installation differentiation |
| FR-006 | M1/M7 | M1 HMAC lifecycle/grant/reopen; firma/certificato: M7 |
| FR-007 | M2 | `UT_GTW_Enrollment_PoP_derives_tenant_and_replay_is_rejected`, `UT_GTW_Invoke_contract_has_no_client_controlled_endpoint_or_secret_reference`, `UT_GTW_Cross_tenant_grant_is_rejected` |
| FR-008 | M3 | `E2E_CON_SecureLayer_success_boundaries_failures_timeout_and_replay`; CI `m3-deterministic-container-slice` M3-P01/P03-P07 e M3-N01..N15 PASS; run `m3a-live-20260805-091023` dimostra P02/Windows Service ma resta BLOCKED prima della matrice HOST completa e non chiude M3A |
| FR-009 | M8 | `E2E-CON-ManagedConnector` |
| FR-010 | M7/M8 | local/gateway/hybrid sequence suites |
| FR-011 | M4 | `IT-CON-BindingScope`, secret absence scan |
| FR-012 | M4 | `UT-CON-LifecycleStateMachine` |
| FR-013 | M4 | `IT-CON-AtomicPublishRollback` |
| FR-014 | M5 | Playwright RBAC/four-eyes suite |
| FR-015 | M1/M6 | M1 SDK: Windows pipe/E2E suite; COM/C ABI/CLI: M6 |
| FR-016 | M2/M5 | M2: `UT_SEC_Audit_is_metadata_only_and_excludes_payload_and_credentials`, API Problem redaction tests; admin audit/RBAC: M5 |
| FR-017 | M5/M9 | health/metrics/tracing/diagnostics tests |
| FR-018 | M1 | DPAPI roundtrip, offline corruption e repository reopen; service identity live aperta |

## Requisiti non funzionali

| Req | Test/evidence prevista |
|---|---|
| NFR-001 | `UT_SEC_Audit_is_metadata_only_and_excludes_payload_and_credentials`, `IT_GTW_Invalid_JSON_does_not_echo_canary_or_exception_details`, repository secret scan; M0/M1 Event Log 11-canary PASS-LIVE; M3-N15 canary scan container PASS |
| NFR-002 | `UT_EGR_Ungranted_operation_is_denied_before_DNS_vault_or_transport`, `UT_EGR_Private_or_loopback_destination_is_rejected_before_transport`, cross-Tenant grant test |
| NFR-003 | M2 transport TLS 1.2/1.3, hostname validation e DNS pinning; M3 synthetic CA/HTTPS/mTLS e certificato errato PASS in container; Key Vault/Managed Identity live PENDING |
| NFR-004 | IPC exact boundary/oversize pass; aggregate stream/backpressure aperti |
| NFR-005 | M1 deadline/cancel/idempotent delete; M2 `UT_EGR_Transient_retry_occurs_only_for_idempotent_operation`; circuit breaker resta M7 |
| NFR-006 | M2 correlation ID firmato/auditato e `traceparent` obbligatorio; propagazione Gateway→vendor PASS M3A container, Broker→Gateway live PENDING |
| NFR-007 | canonical checksum/immutability/tamper tests |
| NFR-008 | clean build, SBOM, signature verification report |
| NFR-009 | Windows and adapter compatibility matrix |
| NFR-010 | schema M2 contiene solo metadata redatti e nessun response body/secret value; test `IT_DAT_Migration_forces_RLS_and_contains_no_secret_value_columns` |

## Acceptance criteria

| AC | Test/evidence |
|---|---|
| AC-001 | E2E storico + M3A container P03-P07/N15 PASS; vero Broker Service M3-P02 e Azure M3B PENDING |
| AC-002 | **PASS-LIVE:** run `m0-m1-20260803-232955`, tag `m0-m1-live-pass-20260803-232955` |
| AC-003 | **PASS-LIVE:** processo autorizzato/non autorizzato sotto identità distinte nella stessa run |
| AC-004 | **PASS-LIVE:** ACL pipe/storage e DPAPI cross-identity nella stessa run |
| AC-005 | `AC005_Installation_key_and_ciphertext_differentiation` |
| AC-006 | **PASS-LIVE M0/M1** Event Log/11 canary; M2 audit metadata-only; M3-N15 container log/canary scan PASS |
| AC-007 | unit auth server-side + M3-P05/P06/P07 e M3-N12/N15 PASS container; Azure Key Vault smoke PENDING |
| AC-008 | M1 project dependency boundary + vertical slice through `IGatewayInvoker` |
| AC-009 | API-surface/fixed-endpoint/SSRF unit + M3-N07/N08/N09/N11 PASS container |
| AC-010 | API-surface/deny-before-side-effect unit + M3-N05/N06/N10 PASS container |
| AC-011 | enrollment/PoP unit + M3-P01, N02 e N03 PASS container |
| AC-012 | cross-Tenant/RLS unit e PostgreSQL 18 + M3-P03/N04 PASS container |
| AC-013 | revoca unit + M3-N01 PASS container; percorso completo via Broker Service PENDING |
| AC-014 | ConnectorVersion persistence/API test |
| AC-015 | atomic rollback and cache invalidation E2E |
| AC-016 | JSON Schema/semantic/security validation corpus |
| AC-017 | Draft/Validated/Retired runtime denial tests |
| AC-018 | PASS `gateway-container` run `30896803567`: build/esecuzione, non-root, read-only, live/ready, fail-closed, secret scan, SBOM e shutdown |
| AC-019 | ADR-0017 Accepted; MSI install/upgrade/repair/uninstall/reinstall matrix prevista in M9 |
| AC-020 | `eng/build.ps1`, pinned toolchain e istruzioni root |
| AC-021 | primo slice storico; M3A container PASS con evidence redatta, M3A Windows Service e M3B PENDING |
| AC-022 | SDK plus native/COM compatibility report |
| AC-023 | E2E storico + M3 synthetic vendor API key/mTLS container PASS; smoke Azure PENDING |
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

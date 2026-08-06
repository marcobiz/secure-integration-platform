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
| FR-008 | M3 | CI `m3-deterministic-container-slice` PASS; **M3A PASS-LIVE** run `m3a-live-20260805-094131`: P02/Windows Service, Legacy standard user, P01/P03–P07 e N01–N14; M3B PENDING |
| FR-009 | M8 | `E2E-CON-ManagedConnector` |
| FR-010 | M7/M8 | local/gateway/hybrid sequence suites |
| FR-011 | M4 | `M4_UT_Published_runtime_resolves_only_server_side_bindings_and_rejects_stale_cache`, `M4_E2E_sample_secure_service_uses_Published_definition_and_server_side_bindings`, secret scan |
| FR-012 | M4 | `M4_UT_Lifecycle_is_immutable_concurrent_and_rollback_reactivates_prior_publication`, `M4_UT_Runtime_denies_Draft_Validated_Retired_missing_and_missing_bindings` |
| FR-013 | M4 | `M4_IT_DAT_PostgreSQL18_connector_publication_binding_and_rollback_when_configured`, `M4_IT_Admin_API_requires_key_and_supports_import_validate_publish_export_and_test` |
| FR-014 | M5 | `M5_UT_Editor_or_requester_cannot_approve_own_checksum`, `M5_UT_Distinct_approval_is_checksum_specific_and_enables_policy`, `AdminApiSecurityTests`, Playwright E2E-04/05/06/07 |
| FR-015 | M1/M6 | M1 SDK: Windows pipe/E2E suite; COM/C ABI/CLI: M6 |
| FR-016 | M2/M5 | M2 metadata-only audit; M5 `M5_IT_Viewer_cannot_mutate_but_can_read`, activation one-time, Audit UI E2E-16 and canary/secret scan |
| FR-017 | M5/M9 | provider-neutral Dashboard/Health UI, E2E-17; metrics/tracing/advanced diagnostics remain M9 |
| FR-018 | M1 | DPAPI roundtrip, offline corruption e repository reopen; service identity live aperta |

## Requisiti non funzionali

| Req | Test/evidence prevista |
|---|---|
| NFR-001 | `UT_SEC_Audit_is_metadata_only_and_excludes_payload_and_credentials`, `IT_GTW_Invalid_JSON_does_not_echo_canary_or_exception_details`, repository secret scan; M0/M1 Event Log 11-canary PASS-LIVE; M3-N15 canary scan container PASS |
| NFR-002 | `UT_EGR_Ungranted_operation_is_denied_before_DNS_vault_or_transport`, `UT_EGR_Private_or_loopback_destination_is_rejected_before_transport`, cross-Tenant grant test |
| NFR-003 | M2 transport TLS 1.2/1.3, hostname validation e DNS pinning; M3 synthetic CA/HTTPS/mTLS e certificato errato PASS in container; Key Vault/Managed Identity live PENDING |
| NFR-004 | IPC exact boundary/oversize pass; aggregate stream/backpressure aperti |
| NFR-005 | M1 deadline/cancel/idempotent delete; M2 `UT_EGR_Transient_retry_occurs_only_for_idempotent_operation`; circuit breaker resta M7 |
| NFR-006 | M2 correlation ID firmato/auditato e `traceparent` obbligatorio; propagazione Gateway→vendor PASS M3A container e Broker→Gateway PASS-LIVE run `m3a-live-20260805-094131` |
| NFR-007 | `M4_CT_Sample_conforms_to_Draft_2020_12_and_is_canonical`, `M4_CT_Checksum_mismatch_is_rejected`, migration trigger + PG tamper test |
| NFR-008 | clean build, SBOM, signature verification report |
| NFR-009 | Windows and adapter compatibility matrix |
| NFR-010 | schema M2 contiene solo metadata redatti e nessun response body/secret value; test `IT_DAT_Migration_forces_RLS_and_contains_no_secret_value_columns` |

## Acceptance criteria

| AC | Test/evidence |
|---|---|
| AC-001 | E2E storico + M3A container P03-P07/N15 PASS; M3A P02 vero Broker Service PASS-LIVE; Azure M3B PENDING |
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
| AC-013 | revoca unit + M3-N01 PASS nella run split-host; percorso completo via Broker Service PASS-LIVE M3A |
| AC-014 | `M4_IT_DAT_PostgreSQL18_connector_publication_binding_and_rollback_when_configured`, Admin API integration test |
| AC-015 | `M4_UT_Lifecycle_is_immutable_concurrent_and_rollback_reactivates_prior_publication`, PostgreSQL rollback test |
| AC-016 | `M4_CT_Sample_conforms_to_Draft_2020_12_and_is_canonical`, invalid schema/version/binding/header/retry/checksum corpus |
| AC-017 | `M4_UT_Runtime_denies_Draft_Validated_Retired_missing_and_missing_bindings`, stale cache and corrupted store tests |
| AC-018 | PASS `gateway-container` run `30896803567`: build/esecuzione, non-root, read-only, live/ready, fail-closed, secret scan, SBOM e shutdown |
| AC-019 | ADR-0017 Accepted; MSI install/upgrade/repair/uninstall/reinstall matrix prevista in M9 |
| AC-020 | `eng/build.ps1`, pinned toolchain e istruzioni root |
| AC-021 | primo slice storico; M3A container e Windows Service PASS con evidence redatta correlata; M3B PENDING |
| AC-022 | SDK plus native/COM compatibility report |
| AC-023 | E2E storico + M3 synthetic vendor API key/mTLS container PASS; smoke Azure PENDING |
| AC-024 | Managed Connector example execution |
| AC-025 | runbook exercise and diagnostics evidence |
| AC-026 | threat-model review checklist |
| AC-027 | `eng/generate-sbom.ps1` — SPDX generato e validato |
| AC-028 | signature/tamper verification suite |
| AC-029 | pilot rotation/revocation evidence |
| AC-030 | pilot code/package/network bypass evidence |

## M5 Admin plane

| Requirement | Automated evidence | Status |
|---|---|---|
| OIDC/session/CSRF/logout | `M5_IT_Anonymous_is_denied_and_security_headers_are_present`, `M5_IT_Mutation_without_CSRF_is_denied`, `M5_IT_Logout_invalidates_cookie_session`, Production startup negative | PASS |
| RBAC and tenant scope | `M5_UT_RBAC_honors_global_and_tenant_scoped_roles`, `M5_UT_Disabled_principal_is_rejected_before_role_resolution`, Viewer integration negative, E2E-24 privileged-action hiding | PASS |
| Four-eyes/semantic approval | `ConnectorApprovalArtifacts` unit coverage, `AdminSecurityTests`, Admin API approval-review integration, `UI-MOCK-29/33`, `FULLSTACK-01` self-denial/distinct approval/digest equality/non-secret effective destination | PASS local + CI `31088473433`/`31088472335`/`31088472535` |
| Installation/activation/revoke | Admin API integration plus E2E-12/13; activation absent from list | PASS |
| Connector lifecycle/concurrency | M4 unit tests; PG18 `M5_IT_DAT_Approved_binding_digest_and_publication_are_atomic_under_concurrent_mutation_when_configured`; stale endpoint/secret/certificate/scope approval denial; FULLSTACK-01 import/approve/publish/retire | PASS local + CI |
| Tenant FORCE RLS mutations | PG18 `M5_IT_DAT_Tenant_mutations_are_FORCE_RLS_correct_atomic_and_concurrent_when_configured`: create/update/disable, atomic audit rollback, wrong/absent/cross-tenant context denial, pooled-context isolation, non-superuser and FORCE RLS assertions | PASS 9/9 PG18 + CI |
| Tenant/Application optimistic concurrency | `AdminConcurrencyTests`, Admin API ETag/428/400/409 tests, PostgreSQL barrier concurrency, `UI-MOCK-34/35` compare and reload | PASS local + CI |
| Binding immutability and atomic audit | migration `0007`; PG18 direct tamper/non-superuser/fault-injection tests; middleware denial fail-closed integration | PASS local + CI |
| Binding/grant/runtime invoke | exact Environment binding, grant, enrolled Installation BGW1+mTLS invoke, server-side API key/certificate, correlated audit and post-retire deny in `FULLSTACK-01` | PASS local + CI |
| Pagination/selectors | unit and PG18 stable totals/order with 101 records; `UI-MOCK-31` selects records 51/101 by keyboard | PASS local + CI |
| i18n/theme/a11y | 25 Vitest with exact IT/EN key parity and hardcoded-copy scan; `UI-MOCK-20/25/28/30/31/32/33`; axe critical/serious = 0; IT/EN without fallback | PASS local + CI |
| OpenAPI operational client | `AdminOpenApiParityTests`, generated `paths` client and `npm run check:api` | PASS local + CI |
| Packaging/open-source boundary | production Gateway/full-stack, Core export build/test/license/secret gates; candidate export 286 files, manifest `40E17FC7...55AED240` | PASS local + CI |
| Secret scanner negative control | hidden/untracked synthetic `client_secret` fixture must fail; fixture removal followed by clean scan must pass | PASS local + CI |

## Security threats

La fotografia conclusiva M0/M1, inclusi gli elementi non automatizzati, è in `docs/reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md`.

Ogni `TM-*` in `security/threat-model.md` deve essere collegata a uno o più test `SEC-*` prima della milestone che introduce la relativa superficie. Un nuovo adapter/auth method non può essere Published senza aggiornare questa matrice.

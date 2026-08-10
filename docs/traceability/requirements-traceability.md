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
| FR-006 | M1/M6/M7 | M1 HMAC lifecycle/grant/reopen; M6 Wave 2 `M6_RS256_positive_resolves_server_owned_policy_and_remote_signs`, same-ID policy substitution, SPKI substitution, replay/rotation matrix e one-shot purpose-bound mTLS; lifecycle service-specific resta M7/Connector Pack |
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
| NFR-001 | `UT_SEC_Audit_is_metadata_only_and_excludes_payload_and_credentials`, `IT_GTW_Invalid_JSON_does_not_echo_canary_or_exception_details`, M6 unexpected metadata/sign/certificate exception canary tests, repository secret scan; M0/M1 Event Log 11-canary PASS-LIVE; M3-N15 canary scan container PASS |
| NFR-002 | `UT_EGR_Ungranted_operation_is_denied_before_DNS_vault_or_transport`, `UT_EGR_Private_or_loopback_destination_is_rejected_before_transport`, cross-Tenant grant test |
| NFR-003 | M2 transport TLS 1.2/1.3, hostname validation e DNS pinning; M3 synthetic CA/HTTPS/mTLS e certificato errato PASS in container; M6 purpose-bound mTLS server locale, hostname/cert rejection, expiry/purpose/rotation PASS; Key Vault/Managed Identity live PENDING |
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
| Four-eyes/semantic approval | `M5_UT_Approval_review_is_semantic_canonical_and_contains_no_credential_value`, `M5_UT_Approval_digest_covers_every_catalog_and_certificate_revision_dimension`, PG18 transactional race, real Admin API→PostgreSQL approval/publication→provider→TLS/mTLS anti-exfiltration test with distinct attacker listener at zero requests, `UI-MOCK-29/33`, `FULLSTACK-01`; exact catalog/metadata/resource/certificate/binding revisions and digest equality | PASS local; exact-head CI pending |
| Provider resource reference safety | Canonical `OperationBindingDependencies`; operation-specific runtime/cache context; structured `ProviderResourceReference`; `M5_UT_Runtime_resolves_only_bindings_required_by_invoked_operation`; `M5_IT_DAT_PostgreSQL18_runtime_locator_is_exactly_granted_and_not_enumerable_when_configured`; migration `0010` controlled function; direct/enumerated and A-to-B binding denial even with wildcard scope; wrong lifecycle/environment/revision denial | PASS 10/10 PG18; exact-head CI pending |
| Published resource cache invalidation | Per-invocation publication/binding/resource stamps; `M5_UT_Runtime_cache_revalidates_catalog_revision_and_disable_on_every_invocation`; rotate/metadata/status failures deny without stale provider use | PASS local; exact-head CI pending |
| Installation/activation/revoke | Admin API integration plus E2E-12/13; activation absent from list | PASS |
| Connector lifecycle/concurrency | M4 unit tests; PG18 `M5_IT_DAT_Approved_binding_digest_and_publication_are_atomic_under_concurrent_mutation_when_configured`; stale endpoint/secret/certificate/scope approval denial; FULLSTACK-01 import/approve/publish/retire | PASS local + CI |
| Tenant FORCE RLS mutations | PG18 `M5_IT_DAT_Tenant_mutations_are_FORCE_RLS_correct_atomic_and_concurrent_when_configured`: create/update/disable, atomic audit rollback, wrong/absent/cross-tenant context denial, pooled-context isolation, non-superuser and FORCE RLS assertions | PASS 9/9 PG18 + CI |
| Tenant/Application optimistic concurrency | `AdminConcurrencyTests`, Admin API ETag/428/400/409 tests, PostgreSQL barrier concurrency, `UI-MOCK-34/35/36`; Application compares display name, min/max Broker versions, status, action and both ETags for update/disable | PASS local; exact-head CI pending |
| Binding immutability and atomic audit | migration `0007`; PG18 direct tamper/non-superuser/fault-injection tests; middleware denial fail-closed integration | PASS local + CI |
| Binding/grant/runtime invoke | exact Environment binding, grant, enrolled Installation BGW1+mTLS invoke, server-side API key/certificate, correlated audit and post-retire deny in `FULLSTACK-01` | PASS local + CI |
| Pagination/selectors | unit and PG18 stable totals/order with 101 records; `UI-MOCK-31` selects records 51/101 by keyboard | PASS local + CI |
| i18n/theme/a11y | Recursive backend emission inventory generates `runtime-wire-codes.json` and the typed frontend contract; exact backend/published/typed/IT/EN parity and known-code coverage; 28 Vitest; `UI-MOCK-16/17/18/20/22/25/28/30/31/32/33`; axe critical/serious = 0 | PASS local; exact-head CI pending |
| OpenAPI operational client | `AdminOpenApiParityTests`, generated `paths` client and `npm run check:api` | PASS local + CI |
| Packaging/open-source boundary | production Gateway/full-stack, Core export build/test/license/secret gates; candidate export 295 files, manifest `59379E70...32AAE6C4` | PASS local + CI |
| Secret scanner negative control | hidden/untracked synthetic `client_secret` fixture must fail; fixture removal followed by clean scan must pass | PASS local + CI |

## M5.5 Direct Gateway Access

| Requirement | Automated evidence | Status |
|---|---|---|
| Principal unificato e Tenant/Application server-side | `M55_UT_Broker_and_Direct_principals_converge_on_the_same_runtime_pipeline`; `UT_GTW_Invoke_contract_has_no_client_controlled_endpoint_or_secret_reference` | PASS local |
| Broker compatibility e Direct enrollment | `UT_GTW_Enrollment_PoP_derives_tenant_and_replay_is_rejected`; `M55_UT_Direct_installation_rejects_Broker_version_field_signature_replay_revocation_and_missing_grant`; PostgreSQL `IT_DAT_PostgreSQL18_registry_enrollment_grant_replay_and_revocation_when_configured` | PASS local + PG18 |
| Shared grant/runtime/binding/egress | `M55_UT_Broker_and_Direct_principals_converge_on_the_same_runtime_pipeline`; M4/M5 publication, operation dependency, locator e anti-exfiltration regressions | PASS local |
| Direct negative authentication | `M55_UT_Direct_installation_rejects_Broker_version_field_signature_replay_revocation_and_missing_grant`; `UT_GTW_Runtime_rejects_tampered_body_ambiguous_target_and_unknown_certificate`; `UT_GTW_Revocation_is_immediate_for_runtime_and_grants` | PASS local |
| Client non puo falsificare authority o binding | `UT_GTW_Invoke_contract_has_no_client_controlled_endpoint_or_secret_reference`; `UT_EGR_Ungranted_operation_is_denied_before_DNS_vault_or_transport`; `M5_UT_Instrumented_actual_canary_provider_is_called_only_for_published_approved_destination` | PASS local |
| Migration fresh/upgrade/no-op/RLS | migration runner fresh+no-op; M5 data upgrade backfill `broker:NULL:1.0.0`; `IT_DAT_PostgreSQL18_migration_and_RLS_isolate_tenants_when_configured`; static least-privilege assertions | PASS PostgreSQL 18 |
| Admin API/UI public metadata only | `M5_IT_Installation_activation_is_returned_once_and_never_listed` con Broker/Direct; `M55-UI-MOCK Direct installation selection is authoritative and public metadata only` | PASS local |
| OpenAPI e runtime wire contract | `M5_UT_Runtime_wire_contract_exports_all_stable_admin_audit_values`; `npm run check:api`; `npm run check:runtime` | PASS local; final gate pending |
| M6 auth contract freeze | `docs/architecture/connector-runtime-auth-contract.md`; architecture tests | Documented; independent review pending |

## M6 HTTP/OAuth outbound primitives

| Requirement | Automated evidence | Status |
|---|---|---|
| AP-02 challenge transport-neutral | existing challenge lifecycle tests plus `M6_UT_Challenge_completion_requires_original_correlation_and_diagnostics_are_redacted` | PASS local; session acquisition deferred to SOAP writer |
| AP-03 server-owned Authorization Code authority | real HTTPS lifecycle; `M6_IT_OAuth_Published_authority_rejects_profile_endpoint_secret_and_scope_substitution_before_provider_use`; `M6_IT_OAuth_completion_and_poll_require_original_correlation_but_session_cache_does_not` | PASS local |
| AP-04 destination-bound token/cache/bearer/refresh | `M6_IT_OAuth_cache_is_bounded_and_refresh_is_single_flight`; `M6_IT_OAuth_bearer_is_destination_bound_and_attacker_server_receives_zero_requests`; `M6_IT_OAuth_refresh_result_is_tombstoned_when_snapshot_rotates_during_await` | PASS local |
| Restricted egress and authorization presentation boundary | SSRF/redirect tests; `M6_UT_OAuth_authorization_endpoint_rejects_reserved_parameter_smuggling`; `M6_IT_OAuth_authorization_endpoint_is_user_agent_navigation_not_server_side_fetch` | PASS local |
| Redaction | `M6_IT_OAuth_diagnostics_ToString_JSON_exceptions_and_assertion_rendering_are_redacted`; AP-02 diagnostics; sanitized provider failures | PASS local |
| TM-046/TM-047 | All named M6 unit/integration tests above | PASS local + PR #9 CI 21/21; independent review pending |

The M6 foundation branch did not claim PKCE or `client_credentials`. Auth Phase 2 / Wave 1 adds those two generic profiles on its dedicated branch; production connector profiles remain excluded.

## Auth Phase 2 / Wave 1 — OAuth PKCE S256 and Client Credentials

| Requirement | Automated evidence | Status |
|---|---|---|
| PKCE S256-only, server-generated verifier and omitted-policy compatibility | `W1_IT_PKCE_S256_is_server_generated_bound_single_use_and_NONE_remains_compatible`; PKCE negative theory | PASS local |
| Client Credentials Published authority and restricted egress | `W1_IT_Client_credentials_cache_is_shared_revision_bound_and_single_flight`; substitution, malformed-response and SSRF tests | PASS local |
| Cache isolation and key-scoped single-flight | `W1_IT_Client_credentials_single_flight_is_per_security_key_without_cross_tenant_head_of_line_blocking`; `W1_SEC_Client_credentials_reacquisition_failure_invalidates_only_its_security_key` | PASS local |
| Authority endpoints covered by semantic four-eyes approval | `W1_UT_OAuth_authority_endpoints_are_complete_in_approval_dependencies_digest_and_risks` | PASS local |
| Raw response zeroization on stale post-transport state | `W1_SEC_Token_response_is_zeroed_when_snapshot_revalidation_fails_after_transport_returns` | PASS local |
| Validation → approval → publication → operation-scoped locator | `W1_IT_DAT_PostgreSQL18_OAuth_validation_approval_publication_and_operation_locator_resolution_when_configured` | PASS PostgreSQL 18 local |
| Provider-neutral boundaries | `W1_ARCH_PKCE_and_client_credentials_are_server_owned_S256_only_and_share_restricted_token_acquisition`; Core export gate | PASS local + product-candidate CI |

Detailed mapping: `docs/traceability/auth-phase2-wave1-oauth.md`. PR #17 product candidate `857810a04d1be86905bda26156e9660cf82f8bab` completed exact-head CI 21/21 (run `31262148895` and `31262148897`) and repeated independent review with GO. This is a PR product gate, not evidence of merge, public release or production connector qualification.

## M6 SOAP/Basic/Session primitives

| Requirement | Automated evidence | Status |
|---|---|---|
| AP-01 Basic server-side e redaction | `M6_UT_Basic_is_resolved_only_at_use_applied_once_and_redacted`; real HTTPS integration | PASS local |
| AP-02 opaque session e interactive completion | `M6_SEC_Interactive_challenge_is_opaque_single_use_cross_context_bound_and_fixation_safe`; `M6_IT_SOAP_real_HTTPS_interactive_challenge_completion_is_transport_neutral` | PASS local |
| Session cache, expiry, rotate/disable e logout | `M6_UT_Session_cache_expiry_rotation_disable_logout_and_controlled_reacquisition`; real HTTPS expiry/reacquisition/logout matrix | PASS local |
| Cache bounded, completion atomica e current generation only | `M6_SEC_Pending_interactions_are_bounded_per_key_and_globally_with_lazy_expiry_eviction`; `M6_SEC_Concurrent_completion_promotes_one_generation_and_denies_the_old_digest` | PASS local |
| Credential/binding/endpoint stamp corrente | `M6_SEC_Current_resource_stamp_denies_real_disable_rotate_binding_and_endpoint_changes_before_provider_or_transport_use` | PASS local |
| AP-07 SOAP 1.1/1.2 deterministic boundary | `M6_UT_SOAP_11_12_serialization_and_HTTP_policy_are_deterministic`; real HTTPS SOAP 1.1/1.2 theory | PASS local |
| XML security e namespace policy | `M6_SEC_XML_boundary_rejects_DTD_XXE_external_entity_complexity_malformed_oversize_namespace_and_content_type`; real malformed/oversize test | PASS local |
| Fault, timeout e cancellation | real HTTPS Fault/malformed/oversize/timeout/cancellation integration; `M6_SEC_Timeout_and_cancellation_are_distinct_and_sanitized` | PASS local |
| Deadline sul response body | `M6_IT_SOAP_real_HTTPS_timeout_covers_headers_flushed_then_stalled_response_body` | PASS local, 5 repetition run PASS |
| Fault cardinality e ambiguity denial | `M6_SEC_Ambiguous_duplicate_mixed_and_unexpected_SOAP_Fault_structures_are_sanitized_and_never_classified_for_relogin` SOAP 1.1/1.2 | PASS local |
| Endpoint, SOAPAction, Content-Type e SSRF | `M6_SEC_Binding_mismatch_and_SSRF_fail_before_transport_and_caller_has_no_endpoint_override`; real HTTPS action/content-type negatives | PASS local |
| Core/auth-writer boundary e deferred scope | `M6_CT_SOAP_writer_depends_only_on_public_Core_runtime_and_provider_abstractions`; `M6_CT_SOAP_writer_exposes_no_raw_session_resolver_generic_scripting_or_deferred_auth_framework` | PASS local |
| TM-048 session fixation/stale/replay | AP-02 negative suite, rotation/disable/logout and challenge replay tests | PASS local |
| TM-049 SOAP/XML parser and fault confusion | XML security corpus and real HTTP fault/malformed/oversize tests | PASS local |

## Wave 1 generic opaque-session HTTP projection

| Requirement | Automated evidence | Status |
|---|---|---|
| Non-forgeable Published authority and generic API ownership | `Wave1_CT_authorized_handoff_and_generic_dispatch_cannot_be_forged_by_public_callers`; Published resolver substitution matrix; architecture dependency direction | PASS local |
| Header token validation and tracing/forwarding denylist | `Wave1_UT_header_name_normalization_cannot_bypass_infrastructure_denylist` casing, whitespace, control, `traceparent`/`tracestate`/`baggage` and `X-Forwarded-*` matrix | PASS local |
| One-shot restricted dispatch | `Wave1_UT_published_authority_projects_once_only_during_restricted_dispatch`; `Wave1_IT_published_authority_projects_exactly_one_header_over_real_restricted_HTTPS` | PASS local |
| Final authority/session TOCTOU | `Wave1_SEC_deterministic_final_dispatch_race_revalidates_after_materialization_and_sends_zero`; real-HTTPS rotate/disable zero-network theory | PASS local |
| SOAP cache backward compatibility | `M6_REG_Session_cache_remains_shared_across_compatible_operations_without_reacquisition`; complete M6 SOAP regression | PASS local |
| Stale authority, SSRF, timeout and redaction | stale ConnectorVersion, same-revision endpoint substitution, attacker destination and generation/expiry unit matrix; real HTTPS timeout and attacker zero-network tests | PASS local |
| Vertical-neutral Core boundary | `Wave1_CT_Core_session_projection_is_vertical_neutral_and_has_no_healthcare_pack_dependency` | PASS local |
| TM-054 | All named Wave 1 tests above | PASS local; independent review pending |

## Wave 1 typed composed SOAP authenticated dispatch

| Requirement | Automated evidence | Status |
|---|---|---|
| Production runtime strategy selected only after installation/grant/Published resolution | `Wave1_UT_runtime_selects_the_exact_qualified_strategy_only_after_principal_grant_and_operation_resolution`; missing/duplicate/wrong-strategy zero-network theories; `ProductionComposedSoapRuntimeIntegrationTests` | PASS local |
| Single Published authority for Basic + SOAP + opaque session | `Wave1_UT_composed_authority_applies_Basic_typed_SOAP_and_opaque_session_once`; `Wave1_IT_composed_Basic_session_SOAPAction_and_body_use_one_real_restricted_HTTPS_dispatch` | PASS local |
| Typed SOAP 1.1/1.2 metadata and operation-owned action | positive version theory; schema action checksum test; wrong version/content type/action/policy negatives | PASS local |
| Authorization/custom-header ownership and no header bag | `Wave1_SEC_composed_session_header_cannot_collide_or_inject`; `Wave1_CT_composed_public_surface_has_no_authority_or_header_override`; composed architecture boundary | PASS local |
| Existing Basic and opaque-session handoff reuse | Basic header cardinality/provider resolution assertions; `OpaqueSessionLeaseProvider` architecture assertion; complete M6/opaque regression gates | PASS local |
| No supported public Basic apply or caller-constructible credential binding | reflection assertions in `Wave1_CT_composed_public_surface_has_no_authority_or_header_override`; `Wave1_CT_composed_SOAP_dispatch_is_closed_typed_Published_and_fault_preserving` | PASS local |
| Final Published/resource/session TOCTOU | unit and real-HTTPS Basic/session/endpoint/revision/action/disable race theories with zero transport/server requests | PASS local |
| SOAP-aware one-shot transport and strict Fault preservation | `Wave1_UT_SendSoapAsync_preserves_HTTP500_for_strict_Fault_parser`; `Wave1_IT_HTTP500_SOAP_Fault_reaches_hardened_parser_and_malformed_Fault_is_denied` | PASS local |
| Connector schema/catalog/four-eyes checksum publishability | `Wave1_CT_opaque_and_composed_SOAP_profiles_are_schema_catalog_and_checksum_publishable`; `opaqueSessionHttp` and `soapBasicOpaqueSession` production parser enums | PASS local |
| Real store → validation → distinct approval → atomic publication → runtime → pinned TLS dispatch | 11/11 `ProductionComposedSoapRuntimeIntegrationTests`; real PostgreSQL roles/store/catalog/runtime, no `MutableSnapshots` | PASS local |
| Required production denial matrix produces zero SOAP and generic network calls | invalid grant, disabled/rotated Basic, stale session, policy update, endpoint substitution, wrong action/mode, SSRF and final-window rotation cases in `ProductionComposedSoapRuntimeIntegrationTests` | PASS local |
| Connector Definition v1 legacy compatibility | `Wave1_UT_previously_valid_v1_allowed_client_header_still_loads_and_executes_while_new_auth_placement_denies_it` | PASS local |
| SSRF, timeout, cancellation and redaction | unit closed-failure test; real HTTPS timeout/cancellation test; intended-destination wrong-Basic counter | PASS local |
| TM-063/TM-064 | all named composed unit, real-HTTPS and architecture tests above | PASS local; independent review pending |

## M6 Certificate, Signing and mTLS primitives - Wave 2 synthetic

| Requirement | Automated evidence | Status |
|---|---|---|
| RS256 server-owned policy and claim authority | `M6_RS256_positive_resolves_server_owned_policy_and_remote_signs`; same-ID issuer/audience/subject/lifetime/allowlist substitution; reserved claim theory; duplicate/unapproved claims; excessive lifetime | PASS local, provider sign count zero on substitution |
| Wrong key, SPKI identity, metadata and replay denial | `M6_JWT_wrong_key_result_and_HS_RS_confusion_are_rejected`; `M6_JWT_approved_scalar_fingerprint_with_substituted_SPKI_is_denied_before_sign`; stale metadata; replayed jti; binding purpose/scope denial | PASS local |
| Provider-side custody/non-exportability | public signer API reflection; `IKeyOperationProvider` architecture check; unexpected metadata/sign exception sanitization | PASS local; real provider qualification PENDING |
| Purpose-bound one-shot mTLS | positive, expired, wrong-purpose, near-expiry, disabled and exact ConnectorVersion/operation/profile/Environment/endpoint/revision tests; no certificate-returning public API | PASS local |
| Rotation/disable fail-closed | signing and mTLS revision 1 -> revision 2 tests; retained rev1 provider result, mid-flight disable and endpoint substitution assert zero DNS/dispatch/connection | PASS local |
| Synthetic HTTPS/mTLS | real local TLS 1.2/1.3 handshake with required expected client certificate; wrong hostname and wrong certificate rejected through pinned restricted transport | PASS local |
| Redaction and repository material | unexpected exception canaries at metadata/sign/certificate boundaries; runtime-generated certificates only; repository secret scan | Tests PASS; scan pending final gate |
| Production FVG/Umbria lifecycle | Explicitly excluded pending authoritative characterization and custody approval | NO-GO |

## Wave 1 generic JWT/X.509 extensions

| Requirement | Automated evidence | Status |
|---|---|---|
| Safe immutable/bounded public leaf DER, optional chain and metadata | public API boundary; input/getter/backing-memory/metadata mutation tests; exact/oversize leaf, chain entry/count/total tests; provider capability architecture checks | PASS local |
| Typed server-owned `x5c`, standard Base64 and leaf-first order | `Wave1_x5c_leaf_and_chain_are_verified_leaf_first_and_standard_base64`; caller `x5c` reserved-claim denial | PASS local |
| DER fingerprint/SPKI identity and same-key signature verification | `Wave1_substituted_certificate_identity_is_denied_before_sign`; existing wrong-signing-result and SPKI tests | PASS local |
| Exact temporal inclusion with M6 default compatibility | `Wave1_temporal_mode_omits_nbf_and_trusted_sources_derive_only_authenticated_identity`; existing default positive test; invalid temporal policy denial | PASS local |
| Typed trusted runtime subject and claim sources | `Wave1_generic_Published_policy_resolves_typed_runtime_subject_without_caller_override`; built-in identity positive; invalid/reserved/duplicate/overlap policy matrix | PASS local |
| Runtime source authority, provenance and exact invocation binding | business-to-`sub` promotion denial with zero provider calls; source substitution; invocation A to B; wrong provenance and stale policy/catalog/resource/ConnectorVersion/operation/Tenant/Application/Installation matrix | PASS local |
| TrustedClaims immutable checksum/payload snapshot | `Wave1_trusted_claim_snapshot_cannot_flip_during_provider_await_or_after_checksum`; non-array/read-only collection assertions and deterministic flip/restore | PASS local |
| Rotation/disable and no stale `x5c` | `Wave1_retained_revision_one_public_material_cannot_authenticate_revision_two`; disable before/final materialization; current revision x5c rotation | PASS local |
| Provider exception sanitization | public-material canary and cancellation test plus existing metadata/sign boundaries | PASS local |
| Generic Core boundary | `Generic_certificate_signing_extensions_have_no_vertical_content_or_arbitrary_header_bag` | PASS local |

Dual-JWT orchestration, service-specific issuer/CN composition, CX/XON/IHE identifiers
and document hash remain Connector responsibilities. Lifetime/skew already exists and
was reused without a new subsystem.

## Wave 1 typed session handshake and authorized external admission

| Requirement | Automated evidence | Status |
|---|---|---|
| One Published request+response profile and exact registered adapter authority | `Wave1_UT_Published_profile_selects_exact_compiled_adapters_and_nested_request`; `Wave1_SEC_Published_adapter_ID_and_type_mismatch_fail_before_transport`; four-eyes digest test | PASS local |
| Core-owned typed request writer and immutable resolved value authority | nested request assertions; `Wave1_SEC_Core_stops_typed_request_adapter_at_the_Published_byte_bound_before_transport`; public API/architecture boundary | PASS local |
| Core-owned external validation transport and server-owned endpoint/credential policy | production restricted-HTTPS validation E2E; exact validation-adapter mismatch zero-network assertions; architecture assertions excluding transport/credential/endpoint members from the adapter | PASS local |
| Hardened outer XML boundary and individual values before typed adapter | `Wave1_SEC_Typed_response_keeps_hardened_outer_XML_boundary` DTD/QName/two-payload/Body-attribute matrix; `Wave1_SEC_Per_value_XML_bound_fails_before_the_typed_adapter_is_invoked`; below-boundary and aggregate-bound named cases | PASS local |
| Strict nested response order/cardinality/domain/duplicate/unexpected/mixed denial | `Wave1_SEC_Typed_response_adapter_denies_order_cardinality_domains_nested_unexpected_and_mixed_content` | PASS local |
| Closed Issued/ExternalAdmissionRequired/Rejected outcomes | direct nested issuance, external handoff and closed public result assertions | PASS local |
| Authenticated presentation boundary, internal sensitive candidate and closed provenance | `Wave1_UT_External_handoff_validates_and_atomically_promotes_into_existing_cache`; `Wave1_CT_Public_API_exposes_only_authenticated_presentation_and_keeps_legacy_scalar_path_optional`; `Wave1_SEC_Unknown_or_future_external_provenance_is_rejected_at_the_adapter_boundary`; production wrong-principal zero-validation-network matrix; API authentication/candidate-redaction test | PASS local |
| Intent single-use/TTL/exact profile and authenticated context binding | wrong/reused/expired/profile test plus `Wave1_SEC_Admission_intent_is_bound_to_exact_tenant_application_installation_and_lifecycle_key` | PASS local |
| Typed validation outcome, remote expiry and proof binding | validation status matrix; `Wave1_SEC_Remote_expiry_is_mandatory_future_and_capped_by_server_policy`; `Wave1_SEC_Validation_proof_is_bound_to_candidate_intent_profile_context_and_generation_and_is_single_use` | PASS local |
| Linearizable final promotion against publish/binding/resource/session mutation | store mutation generations; `Wave1_SEC_Promotion_is_rejected_for_the_entire_in_progress_mutation_window_even_when_captured_after_begin`; `Wave1_SEC_Final_window_mutation_after_every_async_check_fails_the_generation_CAS`; `Wave1_IT_PRODUCTION_STORE_final_race_uses_same_PostgreSQL_authority_and_denies_promotion` for real Published revision and resource-disable variants; architecture CAS/no-await assertions | PASS local including PostgreSQL 18 |
| Rotate/disable and concurrent completion denial | `Wave1_SEC_Rotate_or_disable_during_remote_validation_prevents_promotion`; `Wave1_SEC_Concurrent_same_intent_completion_has_exactly_one_success_without_timing_assumptions` | PASS local |
| Real vs fake extension cancellation and diagnostic sanitization | `Wave1_SEC_Adapter_cancellation_is_preserved_only_for_the_actual_token_and_otherwise_sanitized` request/response/validation matrix | PASS local |
| Existing 256-key cache/lazy sweep/current generation reuse | `Wave1_SEC_Admission_state_reuses_256_cap_and_lazy_TTL_sweep`; `Wave1_CT_Gateway_composition_aliases_business_leases_to_the_singleton_SOAP_session_lifecycle`; hosted acquire→completion→business generation/count assertions; legacy cache regression | PASS local |
| Redaction of candidate/session/raw XML/remote diagnostics | `Wave1_SEC_Candidate_session_raw_XML_and_validator_diagnostics_are_redacted` | PASS local |
| Neutral real HTTPS typed handshake and external admission | `Wave1_IT_Real_HTTPS_typed_handshake_direct_or_external_admission_promotes_and_supports_session_use` direct/external theory | PASS local |
| Production composition, real authorization/store/four-eyes and server-side completion resolution | `Wave1_IT_PRODUCTION_HOST_authenticated_routes_store_registry_admission_replay_and_session_use` traverses `Program`, real HTTP/BGW1, grant, PostgreSQL Published store, acquire/completion and the hosted `session-business:invoke` route; Published `soapBasicOpaqueSession` selects `ComposedSoapExecutionStrategy`, resolves Basic plus the same promoted lease and sends one validated SOAP request with unchanged acquisition/validation/generation; unknown adapter and exact-context replay are zero-validator-network; `Wave1_IT_DAT_PostgreSQL18_typed_session_four_eyes_publication_and_runtime_locator_resolution_when_configured`; older manually composed tests are classified internal | PASS local and PostgreSQL 18 |
| Backward-compatible scalar M6 path | existing `AcquireSessionAsync` public API assertion; 34 targeted legacy/configuration unit and 5 legacy HTTPS SOAP integration PASS | PASS local |
| Provider-neutral Core, one authoritative lifecycle and no generic XML/session-insertion framework | `Wave1_CT_Typed_handshake_and_external_admission_are_Published_compiled_vertical_neutral_and_reuse_the_single_cache`; `Wave1_CT_Gateway_composition_aliases_business_leases_to_the_singleton_SOAP_session_lifecycle`; hosted DI identity assertion | PASS local |
| TM-065/TM-066/TM-067 | `SEC-W1-HS-001/002/003` named matrices above | PASS local; independent review pending |

## Wave 1 provider-neutral Connector execution seam

| Requirement | Automated evidence | Status |
|---|---|---|
| Strong Published execution key distinct from authentication kind | `Wave1_CT_execution_strategy_key_is_schema_validated_canonical_and_checksum_bound`; `Wave1_UT_explicit_execution_key_is_independent_from_authentication_kind`; approval artifact assertion in the production-host test | PASS local |
| Legacy default, opaque-session and composed SOAP mapping without rewrite | `M5_UT_Approval_review_is_semantic_canonical_and_contains_no_credential_value`; `Wave1_CT_opaque_and_composed_SOAP_profiles_are_schema_catalog_and_checksum_publishable`; existing ordinary/opaque/composed regression suites | PASS local |
| Grant and Published authority before exact-one lookup | `Wave1_UT_runtime_selects_the_exact_qualified_strategy_only_after_principal_grant_and_operation_resolution`; `Wave1_CT_runtime_grants_and_resolves_Published_authority_before_exact_key_selection` | PASS local |
| Missing/unknown key denied without default/network; duplicate key fails startup | `Wave1_SEC_invalid_grant_and_missing_strategy_deny_before_strategy_or_network`; `Wave1_SEC_explicit_unknown_key_never_falls_back_to_default_HTTP`; `Wave1_SEC_duplicate_strategy_key_fails_during_composition`; hosted duplicate-module test | PASS local |
| Non-forgeable context and owned immutable payload | `Wave1_CT_qualified_execution_handoff_is_non_forgeable_and_hides_payload_and_operation_authority`; `Wave1_SEC_authorized_payload_is_an_owned_read_only_snapshot`; production-host server-derived context assertions | PASS local |
| External neutral assembly, no friend access, restricted registrar | `Wave1_CT_external_execution_module_uses_only_public_provider_neutral_contracts_without_friend_access`; `Wave1_CT_execution_contract_is_narrow_and_does_not_expose_DI_transport_or_provider_authority` | PASS local |
| Registrar constructor graph denies service locator, strategy collection and nested host reachability | `Wave1_SEC_external_module_constructor_graph_cannot_reach_host_DI_or_other_strategies` three-case hosted startup theory; `Wave1_CT_module_loading_is_explicit_exact_bounded_and_never_discovers_assemblies` | PASS local |
| Strategy/auth-kind compatibility is startup-validated, immutable and enforced before strategy/network | `Wave1_SEC_basic_strategy_cannot_execute_incompatible_session_or_composed_mode`; `Wave1_SEC_strategy_authentication_metadata_is_validated_and_snapshotted_at_startup`; hosted `auth-mismatch` denial | PASS local |
| Explicit local deployment allowlist, no discovery/framework and same-image load | `Wave1_CT_module_loading_is_explicit_exact_bounded_and_never_discovers_assemblies`; `Wave1_SEC_module_loader_denies_UNC_and_device_paths_before_file_access`; traversal denial; `Wave1_SEC_module_loader_verifies_and_loads_the_same_buffer_when_the_path_is_swapped_after_identity_acceptance`; `Wave1_SEC_execution_strategy_registry_is_bounded_and_not_runtime_growing` | PASS local |
| Caller cannot override selection | `Wave1_IT_PRODUCTION_HOST_external_module_crosses_real_BGW1_grant_Published_registry_and_result` sends conflicting payload, query, header and metadata values | PASS local |
| Production host and real Published lifecycle | `Wave1_IT_PRODUCTION_HOST_external_module_crosses_real_BGW1_grant_Published_registry_and_result`; PostgreSQL variant exercises store, editor/distinct approver, publish and invocation | PASS local and PostgreSQL 18 (148/148 integration) |
| External error forgery denied while built-in/capability host failures remain qualified | `Wave1_SEC_strategy_exception_and_fake_cancellation_are_sanitized_but_real_cancellation_is_preserved` asserts forged code/status/retryability; hosted `forged-error-execute`; `Wave1_REG_default_HTTP_preserves_sanitized_provider_unavailability`; bridge malformed-request qualified failure | PASS local |
| Narrow nonconstructible authority bridge and no-IVT typed handshake→admission→composed SOAP on the same lifecycle | `Wave1_CT_authorized_capability_bridge_is_closed_current_invocation_only_and_not_a_host_facade`; public reflection assertions; `Wave1_IT_PRODUCTION_HOST_external_no_IVT_module_uses_authorized_handshake_admission_and_composed_SOAP_on_one_session_lifecycle`; retained-bridge replay denial | PASS local |
| Generic Core starts without optional modules and has no reverse dependency | ordinary host/suite; `Wave1_CT_generic_seam_and_Core_solution_have_no_vertical_dependency_or_logic`; Core export gate | PASS local; exact-candidate export is a handoff gate |
| TM-068/TM-069/TM-070/TM-071/TM-072 | `SEC-W1-EXEC-001/002/003/004/005` named matrices above | PASS local; independent review pending |

## Healthcare Wave 1 — Regional ePrescription foundation

| Requirement | Automated evidence | Status |
|---|---|---|
| Healthcare-only regional domain and inbound-auth boundary | `HC_W1_ARCH_Core_does_not_reference_Healthcare_pack`, `HC_W1_ARCH_regional_domain_concepts_are_absent_from_Gateway_Core_source`, `HC_W1_ARCH_Healthcare_foundation_depends_only_on_public_Core_application_contract`, `HC_W1_ARCH_Healthcare_pack_does_not_reinterpret_inbound_identity` | PASS local |
| Minimal common model and bounded scalar extension input | `HC_W1_COMMON_model_contains_only_lookup_dispense_and_bounded_scalar_extensions` | PASS local |
| Caller cannot select region/profile/endpoint/auth/credential/route or extension schema | `HC_W1_SEC_caller_contract_has_no_profile_region_endpoint_auth_or_credential_selector`, `HC_W1_SEC_extension_schema_is_server_owned_and_revalidated_after_profile_resolution`, `HC_W1_SEC_tenant_cannot_select_another_profile_and_authority_mismatch_denies_before_dispatch` | PASS local |
| Credential-independent authenticated-principal active-state/exact-grant enforcement, cross-profile isolation and real Published lookup | `HC_W1_SEC_profile_A_cannot_use_endpoint_auth_or_credential_B_and_lookup_authority_is_server_derived`, `HC_W1_SEC_real_Published_adapter_and_credential_independent_authorization_fail_closed` | PASS local |
| Rotate/disable/stale complete binding denial | `HC_W1_SEC_rotation_disable_and_stale_complete_binding_stamp_fail_closed` | PASS local |
| Redaction, malformed nested values and regional safe-code allowlist | `HC_W1_SEC_normalized_error_preserves_only_allowlisted_safe_code_and_redacts_reference`, `HC_W1_SEC_unexpected_resolver_and_dispatcher_exceptions_are_redacted_without_inner_details`, `HC_W1_SEC_null_nested_command_and_response_values_fail_sanitized` | PASS local |
| Binding and compiled-profile collection immutability plus unambiguous fingerprint | `HC_W1_SEC_binding_and_compiled_profile_snapshot_mutable_collections` | PASS local |
| Profile response type/reference/enum-domain integrity | `HC_W1_SEC_profile_response_type_or_reference_mismatch_is_denied` | PASS local |
| Lombardia and Emilia-Romagna no-invention gate | `HC_W1_BLOCKED_regional_synthetic_HTTPS_sentinels_receive_zero_requests`; current source matrix in `docs/connectors/healthcare/regional-eprescription/README.md` | PASS local; both profiles `BLOCKED_BY_SPEC` |

OAuth/SOAP regional integration, callback/session correlation, actual operation/fault mapping,
accreditation and live conformance remain blocked until current official specifications are
available. Generic M6 auth tests are regression evidence only, not regional support evidence.

## Security threats

La fotografia conclusiva M0/M1, inclusi gli elementi non automatizzati, è in `docs/reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md`.

Ogni `TM-*` in `security/threat-model.md` deve essere collegata a uno o più test `SEC-*` prima della milestone che introduce la relativa superficie. Un nuovo adapter/auth method non può essere Published senza aggiornare questa matrice.

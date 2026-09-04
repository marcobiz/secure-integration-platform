# M2 — Implementation and verification report

**Date:** 2026-08-04
**Baseline:** `d1113d34a18e166c9eb0c14d8e11c3c1a1a20c12`

## Local result

The M2 Gateway implementation builds and the suites executable on the HOST are green.
The HOST has no Docker/Podman, but has PostgreSQL 18 binaries: an ephemeral,
unprivileged, isolated cluster was started under `.artifacts` without changing the
installed PostgreSQL service.

| Check | Local result |
|---|---|
| Build solution Release | PASS, 0 warnings, 0 errors |
| Gateway unit tests | PASS, 22 tests |
| Gateway API/integration | PASS, 6 ordinary tests |
| M0/M1 regression suites | PASS: 26 unit + 22 integration + 1 E2E |
| Real PostgreSQL 18 | PASS: 2 local tests and independent CI job `gateway-postgresql-18` |
| Migration runner | PASS on two executions; second a no-op; SHA-256 `182CC690E16BB986638A4B52EE1554A4B540A8E58FD673F2111A79D194C66A98` |
| Docker build/smoke | PASS CI `gateway-container`, run `30896803567` |
| document/secret scan | PASS |
| dependency vulnerability scan | PASS, no vulnerable packages detected |
| SBOM SPDX | PASS |

The overall ordinary regression contains 77 PASS tests: 26 Broker unit, 22 Broker
integration, 1 historical vertical slice, 22 Gateway unit and 6 Gateway integration. The two
named PostgreSQL tests were also rerun with the connection variable
set against real PostgreSQL 18.

## Named evidence

- enrollment/PoP/Tenant/replay:
  `UT_GTW_Enrollment_PoP_derives_tenant_and_replay_is_rejected`;
- tamper/target/unknown certificate:
  `UT_GTW_Runtime_rejects_tampered_body_ambiguous_target_and_unknown_certificate`;
- one-time activation and negative PoP:
  `UT_GTW_Activation_code_is_one_time_and_invalid_code_is_denied`,
  `UT_GTW_Enrollment_rejects_invalid_proof_of_possession`;
- renewal/overlap:
  `UT_GTW_Renewal_allows_seven_day_overlap_then_expires_old_credential`;
- revocation:
  `UT_GTW_Revocation_is_immediate_for_runtime_and_grants`;
- tenant isolation:
  `UT_GTW_Cross_tenant_grant_is_rejected`,
  `IT_DAT_PostgreSQL18_migration_and_RLS_isolate_tenants_when_configured`;
- server-side endpoint/secret references:
  `UT_GTW_Invoke_contract_has_no_client_controlled_endpoint_or_secret_reference`;
- SSRF and deny-before-side-effect:
  `UT_EGR_Private_or_loopback_destination_is_rejected_before_transport`,
  `UT_EGR_Ungranted_operation_is_denied_before_DNS_vault_or_transport`;
- Basic/API key/mTLS egress:
  `UT_EGR_Basic_credentials_are_injected_only_into_the_outbound_request`,
  `UT_EGR_Server_owned_endpoint_and_API_key_are_used_without_secret_disclosure`,
  `UT_EGR_mTLS_certificate_is_loaded_ephemerally_for_transport`;
- Vault/cache:
  `UT_VLT_Secret_cache_is_bounded_and_deduplicates_reads`,
  `UT_VLT_Reference_cannot_select_another_vault`;
- retry:
  `UT_EGR_Transient_retry_occurs_only_for_idempotent_operation`;
- audit/problem redaction:
  `UT_SEC_Audit_is_metadata_only_and_excludes_payload_and_credentials`,
  `IT_GTW_Invalid_JSON_does_not_echo_canary_or_exception_details`,
  `IT_GTW_Runtime_without_client_certificate_returns_sanitized_problem`;
- schema/RLS static:
  `IT_DAT_Migration_forces_RLS_and_contains_no_secret_value_columns`;
- real PostgreSQL repository:
  `IT_DAT_PostgreSQL18_registry_enrollment_grant_replay_and_revocation_when_configured`;
- container: CI job `gateway-container` with built-in health probe.

## Evidence limitations

- Azure Key Vault/Managed Identity is implemented but not tested live without a subscription;
- real PostgreSQL RLS and container hardening are PASS in the independent CI gate; M2 is Done;
- M3 has not started and no Broker→Gateway M2 E2E exists yet;
- Gateway HTTP v1 and IPC v1 remain provisional until M3 validation.

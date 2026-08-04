# M2 — Implementation e verification report

**Data:** 2026-08-04
**Baseline:** `d1113d34a18e166c9eb0c14d8e11c3c1a1a20c12`

## Risultato locale

L'implementazione Gateway M2 è compilabile e le suite eseguibili sull'HOST sono verdi.
L'HOST non dispone di Docker/Podman, ma contiene i binari PostgreSQL 18: è stato avviato
un cluster effimero non privilegiato e isolato sotto `.artifacts`, senza modificare il
servizio PostgreSQL installato.

| Controllo | Risultato locale |
|---|---|
| Build solution Release | PASS, 0 warning, 0 error |
| Gateway unit tests | PASS, 22 test |
| Gateway API/integration | PASS, 6 test ordinari |
| M0/M1 regression suites | PASS: 26 unit + 22 integration + 1 E2E |
| PostgreSQL 18 reale | PASS: 2 test locali e job CI indipendente `gateway-postgresql-18` |
| Migration runner | PASS due esecuzioni; seconda no-op; SHA-256 `182CC690E16BB986638A4B52EE1554A4B540A8E58FD673F2111A79D194C66A98` |
| Docker build/smoke | PASS CI `gateway-container`, run `30896803567` |
| document/secret scan | PASS |
| dependency vulnerability scan | PASS, nessun package vulnerabile rilevato |
| SBOM SPDX | PASS |

La regressione ordinaria complessiva contiene 77 test PASS: 26 Broker unit, 22 Broker
integration, 1 vertical slice storico, 22 Gateway unit e 6 Gateway integration. I due
test PostgreSQL nominati sono stati inoltre rieseguiti con la variabile di connessione
attiva contro PostgreSQL 18 reale.

## Evidenze nominate

- enrollment/PoP/Tenant/replay:
  `UT_GTW_Enrollment_PoP_derives_tenant_and_replay_is_rejected`;
- tamper/target/unknown certificate:
  `UT_GTW_Runtime_rejects_tampered_body_ambiguous_target_and_unknown_certificate`;
- activation one-time e PoP negativo:
  `UT_GTW_Activation_code_is_one_time_and_invalid_code_is_denied`,
  `UT_GTW_Enrollment_rejects_invalid_proof_of_possession`;
- renewal/overlap:
  `UT_GTW_Renewal_allows_seven_day_overlap_then_expires_old_credential`;
- revoca:
  `UT_GTW_Revocation_is_immediate_for_runtime_and_grants`;
- tenant isolation:
  `UT_GTW_Cross_tenant_grant_is_rejected`,
  `IT_DAT_PostgreSQL18_migration_and_RLS_isolate_tenants_when_configured`;
- endpoint/secret references server-side:
  `UT_GTW_Invoke_contract_has_no_client_controlled_endpoint_or_secret_reference`;
- SSRF e deny-before-side-effect:
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
- repository PostgreSQL reale:
  `IT_DAT_PostgreSQL18_registry_enrollment_grant_replay_and_revocation_when_configured`;
- container: job CI `gateway-container` con health probe incorporato.

## Limiti dell'evidenza

- Azure Key Vault/Managed Identity è implementato ma non provato live senza subscription;
- PostgreSQL RLS reale e container hardening sono PASS nel gate CI indipendente; M2 è Done;
- M3 non è stato avviato e non esiste ancora un E2E Broker→Gateway M2;
- Gateway HTTP v1 e IPC v1 restano provvisori fino alla validazione M3.

# M4 — Connector Configuration MVP Gate Review

Date: 2026-08-05

Baseline: `m3a-product-gate-pass-20260805` / `5301b61546f814fd32874570ff667218ffe002a2`

Implementation commit: `cf59a36e71ee899dfbbe4918345090a2cd4d402d`

Negative-test commit: `1485a0d`

Branch: `m4/connector-configuration`

## Result

**M4 Done.** The HOST gate is PASS and PR #4 CI run `30992487718` is PASS 6/6 on corrective candidate `cf3cf6c7d8fb7deddcaa6886c29bef8b329eae1b`. M3B was not executed and is correctly non-blocking because it belongs to the Azure Deployment Pack; M5 and further providers/packs have not started.

The first CI run `30992197169` was preserved as a failure: the new quick-start job did not make the bind-mounted fixture directory writable on Linux for the non-root Provisioner. Fix `cf3cf6c` applies permission only to the ephemeral raw directory on non-Windows hosts; it neither elevates containers nor broadens runtime permissions. The subsequent complete run demonstrates closure of the regression.

## Architectural boundaries

- Domain, Application, JSON Schema, runtime/Admin contracts and CLI expose no Azure types.
- Connector Definitions and exports contain only logical endpoint/secret names.
- URIs and provider references exist only in server-side Environment bindings.
- Provider-neutral capabilities are separated from M5 per ADR-0019; the synthetic provider enables local setup without Azure.
- The pre-M4 Azure adapter remains physically in Infrastructure/API for M3 compatibility. Its extraction into a Deployment Pack package is packaging debt and does not make Azure necessary for local Core runtime.

ADR-0010 already covered the declarative pipeline. ADR-0012 was made provider-neutral; ADR-0018 documents lifecycle, concurrency, bindings and cache because these were new decisions.

## Requirements and tests

| Property/scenario | Automated evidence |
|---|---|
| Draft 2020-12, sample and canonical checksum | `M4_CT_Sample_conforms_to_Draft_2020_12_and_is_canonical` |
| Invalid JSON/schemaVersion/header/binding/retry | `M4_CT_Invalid_schema_version_binding_header_and_retry_are_rejected` |
| Incompatible checksum | `M4_CT_Checksum_mismatch_is_rejected` |
| Lifecycle, immutable Published, rollback, concurrency | `M4_UT_Lifecycle_is_immutable_concurrent_and_rollback_reactivates_prior_publication` |
| Rollback target never Published | Same test, `BGW-CONNECTOR-ROLLBACK-TARGET` |
| Draft/Validated/Retired/missing | `M4_UT_Runtime_denies_Draft_Validated_Retired_missing_and_missing_bindings` |
| Missing endpoint, secret binding and operation | `M4_UT_Runtime_denies_missing_endpoint_secret_and_operation` |
| HTTPS endpoint binding without query/IP | `M4_UT_Endpoint_bindings_reject_query_IP_and_non_HTTPS_values` |
| Published-only, server-side bindings, stale cache | `M4_UT_Published_runtime_resolves_only_server_side_bindings_and_rejects_stale_cache` |
| Corrupted storage | `M4_UT_Corrupted_configuration_is_rejected_fail_closed` and PG tamper test |
| Request/response over bounds | `M4_UT_EGR_Request_and_response_bounds_fail_closed` |
| Missing operation grant | `UT_EGR_Ungranted_operation_is_denied_before_DNS_vault_or_transport` |
| No client-side URLs/secret references | `UT_GTW_Invoke_contract_has_no_client_controlled_endpoint_or_secret_reference` |
| Redacted canary/log and audit | `IT_GTW_Invalid_JSON_does_not_echo_canary_or_exception_details`, lifecycle audit assertion, secret scan |
| Admin API auth/import/export/publish/test | `M4_IT_Admin_API_requires_key_and_supports_import_validate_publish_export_and_test` |
| Real PG migration, publish/binding/rollback/immutability | `M4_IT_DAT_PostgreSQL18_connector_publication_binding_and_rollback_when_configured` |
| Complete sample Legacy→Broker→Gateway→Published→API key+mTLS | `M4_E2E_sample_secure_service_uses_Published_definition_and_server_side_bindings` |

No API exposes modification of Published configuration, and the `connector_version_immutable` trigger rejects even a direct UPDATE. The `ux_connector_one_published_version` index protects uniqueness at DB level.

## HOST gate

| Check | Result |
|---|---|
| Release build | PASS, zero warnings/errors |
| Ordinary suites | PASS, 99 tests |
| Real PostgreSQL 18 | PASS, apply 0001+0002, second apply no-op, lifecycle/tamper |
| M4 migration SHA-256 | `9D991B0E4E8268D47C32121DECE2D3593B183623059BB17F4A82A479DC8D322C` |
| M4 Compose quick start | PASS, Published list/test and zero-resource cleanup |
| PowerShell 5.1 parse | PASS |
| document validation | PASS |
| secret scan | PASS |
| vulnerable NuGet packages | zero detected |
| SBOM SPDX | PASS |
| `git diff --check` | PASS |
| PR #4 CI | PASS 6/6, run `30992487718` |

The quick start ran with Docker Engine 29.6.2 and Compose 5.3.1, including from a clean branch clone. The HOST had only .NET 8 globally, so the 10.0.302 SDK required by `global.json` was explicitly identified as an installed prerequisite; it is not an implicit repository dependency. The `m4-connector-quickstart` CI job repeats Start/Stop on a clean runner and verifies zero residual containers, volumes and networks.

## Open source readiness

Ready: pinned build, quick start without Azure, Compose/synthetic fixtures, sample, schema, API/CLI/SDK docs, threat model, CONTRIBUTING, SECURITY, scans and SBOM. No proprietary connectors or raw evidence are present.

Before general open-source publication, the following remain mandatory: final license decision/text, final security channel and physical separation of the Azure adapter into a Deployment Pack. These do not block the M4 functional gate or a private/synthetic pilot.

## Debt and open decisions

- extract provider-specific adapters from Infrastructure/API into separately installable packs;
- replace `DevelopmentApiKey` with OIDC/RBAC in production deployment; development mode is already rejected in Production;
- YAML is intentionally unimplemented;
- a Draft is changed by creating/importing a new version, not through in-place editing;
- cache uses a DB stamp on every invocation to guarantee immediate revocation: future optimization/scaling must preserve fail-closed behavior;
- API streaming, plugins and new auth/protocol adapters remain later milestones.

## Gate decision

**PASS — M4 Done. Technical GO for M5 and GO for a first synthetic/private pilot Connector Pack; no automatic start.** General public distribution remains NO-GO until the license is chosen and the other preview items above are completed.

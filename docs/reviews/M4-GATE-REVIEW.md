# M4 — Connector Configuration MVP Gate Review

Data: 2026-08-05

Baseline: `m3a-product-gate-pass-20260805` / `5301b61546f814fd32874570ff667218ffe002a2`

Commit implementativo: `cf59a36e71ee899dfbbe4918345090a2cd4d402d`

Commit test negativi: `1485a0d`

Branch: `m4/connector-configuration`

## Esito

**M4 Done.** Il gate HOST è PASS e la CI PR #4 run `30992487718` è PASS 6/6 sul candidate correttivo `cf3cf6c7d8fb7deddcaa6886c29bef8b329eae1b`. M3B non è stata eseguita ed è correttamente non bloccante perché appartiene al Deployment Pack Azure; M5 e provider/pack ulteriori non sono iniziati.

La prima run CI `30992197169` è stata conservata come failure: il nuovo job quick start non rendeva scrivibile su Linux la directory fixture bind-mounted per il Provisioner non-root. Il fix `cf3cf6c` applica soltanto il permesso alla directory raw effimera su host non-Windows; non eleva container né amplia permessi runtime. La run completa successiva dimostra la regressione chiusa.

## Confini architetturali

- Domain, Application, JSON Schema, runtime/Admin contract e CLI non espongono tipi Azure.
- Connector Definition ed export contengono solo logical endpoint/secret names.
- URI e provider reference esistono soltanto nei binding Environment server-side.
- `ISecretProvider` è il seam provider-neutral; Synthetic Vault abilita setup locale senza Azure.
- L'adapter Azure pre-M4 resta fisicamente in Infrastructure/API per compatibilità M3. La sua estrazione in un package Deployment Pack è debito di packaging e non rende Azure necessario al Core runtime locale.

ADR-0010 già copriva la pipeline dichiarativa. ADR-0012 è stato reso provider-neutral; ADR-0018 documenta lifecycle, concurrency, binding e cache perché erano decisioni nuove.

## Requisiti e test

| Proprietà/scenario | Evidenza automatica |
|---|---|
| Draft 2020-12, sample e checksum canonico | `M4_CT_Sample_conforms_to_Draft_2020_12_and_is_canonical` |
| JSON/schemaVersion/header/binding/retry invalidi | `M4_CT_Invalid_schema_version_binding_header_and_retry_are_rejected` |
| checksum incompatibile | `M4_CT_Checksum_mismatch_is_rejected` |
| lifecycle, Published immutabile, rollback, concorrenza | `M4_UT_Lifecycle_is_immutable_concurrent_and_rollback_reactivates_prior_publication` |
| rollback target mai Published | stesso test, `BGW-CONNECTOR-ROLLBACK-TARGET` |
| Draft/Validated/Retired/inesistente | `M4_UT_Runtime_denies_Draft_Validated_Retired_missing_and_missing_bindings` |
| endpoint, secret binding e operation mancanti | `M4_UT_Runtime_denies_missing_endpoint_secret_and_operation` |
| endpoint binding HTTPS senza query/IP | `M4_UT_Endpoint_bindings_reject_query_IP_and_non_HTTPS_values` |
| Published-only, binding server-side, stale cache | `M4_UT_Published_runtime_resolves_only_server_side_bindings_and_rejects_stale_cache` |
| storage corrotto | `M4_UT_Corrupted_configuration_is_rejected_fail_closed` e test PG tamper |
| request/response oltre limite | `M4_UT_EGR_Request_and_response_bounds_fail_closed` |
| operation grant mancante | `UT_EGR_Ungranted_operation_is_denied_before_DNS_vault_or_transport` |
| URL/secret reference client-side assenti | `UT_GTW_Invoke_contract_has_no_client_controlled_endpoint_or_secret_reference` |
| canary/log e audit redatti | `IT_GTW_Invalid_JSON_does_not_echo_canary_or_exception_details`, lifecycle audit assertion, secret scan |
| Admin API auth/import/export/publish/test | `M4_IT_Admin_API_requires_key_and_supports_import_validate_publish_export_and_test` |
| migration real PG, publish/binding/rollback/immutabilità | `M4_IT_DAT_PostgreSQL18_connector_publication_binding_and_rollback_when_configured` |
| sample completo Legacy→Broker→Gateway→Published→API key+mTLS | `M4_E2E_sample_secure_service_uses_Published_definition_and_server_side_bindings` |

La modifica di Published non è esposta da alcuna API e il trigger `connector_version_immutable` rifiuta anche un UPDATE diretto. L'indice `ux_connector_one_published_version` protegge l'unicità a livello DB.

## Gate HOST

| Controllo | Risultato |
|---|---|
| Release build | PASS, zero warning/error |
| suite ordinarie | PASS, 99 test |
| PostgreSQL 18 reale | PASS, apply 0001+0002, seconda apply no-op, lifecycle/tamper |
| migration M4 SHA-256 | `9D991B0E4E8268D47C32121DECE2D3593B183623059BB17F4A82A479DC8D322C` |
| M4 quick start Compose | PASS, Published list/test e cleanup zero risorse |
| PowerShell 5.1 parse | PASS |
| document validation | PASS |
| secret scan | PASS |
| vulnerable NuGet packages | zero rilevate |
| SBOM SPDX | PASS |
| `git diff --check` | PASS |
| CI PR #4 | PASS 6/6, run `30992487718` |

Il quick start è stato eseguito con Docker Engine 29.6.2 e Compose 5.3.1, anche da clone pulito del branch. L'HOST aveva globalmente solo .NET 8, quindi l'SDK 10.0.302 richiesto da `global.json` è stato esposto esplicitamente come prerequisito installato; non è una dipendenza implicita del repository. Il job CI `m4-connector-quickstart` ripete Start/Stop su un runner pulito e verifica zero container, volumi e network residui.

## Open source readiness

Pronti: build pinned, quick start senza Azure, compose/synthetic fixtures, sample, schema, API/CLI/SDK docs, threat model, CONTRIBUTING, SECURITY, scans e SBOM. Non sono presenti connector proprietari o evidence raw.

Prima di una pubblicazione open source generale restano obbligatori: decisione/licenza definitiva, canale security definitivo e separazione fisica dell'adapter Azure in un Deployment Pack. Questi non bloccano il gate funzionale M4 né un pilot privato/sintetico.

## Debito e decisioni aperte

- estrarre gli adapter provider-specific da Infrastructure/API in pack installabili separati;
- sostituire `DevelopmentApiKey` con OIDC/RBAC nel deployment production; la modalità development è già rifiutata in Production;
- YAML è intenzionalmente non implementato;
- modifica di Draft avviene creando/importando una nuova versione, non con editing in-place;
- cache usa uno stamp DB a ogni invoke per garantire revoca immediata: ottimizzazione/scaling futura deve preservare fail-closed;
- API streaming, plugin e nuovi auth/protocol adapter restano milestone successive.

## Decisione gate

**PASS — M4 Done. GO tecnico per M5 e GO per un primo Connector Pack pilota sintetico/privato; nessun avvio automatico.** La distribuzione pubblica generale resta NO-GO fino alla scelta della licenza e al completamento degli altri punti di preview indicati sopra.

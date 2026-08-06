# M5 final acceptance fixes

**Initial reviewed HEAD:** `835db2c5607f66c8a9888981f54f0dbde0f956f1`

**Product candidate:** `668e2266613ffa256a6759d5910520a5200e7cc1`

**Branch:** `m5/admin-ui-mvp`

**Decision:** local remediation gates PASS. One final read-only acceptance review, limited to the seven findings below, remains required. M5 is not declared Done, PR #5 remains open and unmerged, `main` is unchanged and M6 has not started.

## Seven acceptance findings

| Finding | Remediation | Named evidence |
|---|---|---|
| Complete approval artifact | The canonical server-built artifact separates catalog resource version, catalog revision, public-metadata revision and certificate version. It includes resource type, binding revision/checksum, definition checksum and public certificate metadata. The same canonical digest is rechecked in the SERIALIZABLE approval transaction and used by publication. | `M5_UT_Approval_review_is_semantic_canonical_and_contains_no_credential_value`, `M5_UT_Approval_digest_covers_every_catalog_and_certificate_revision_dimension`, PostgreSQL atomic approval test, `UI-MOCK-29` |
| Locator least privilege | Migration `0009` revokes direct runtime locator-table access and exposes one fixed-search-path `SECURITY DEFINER` function owned by a dedicated `NOLOGIN` role. PUBLIC/admin/readonly execution and owner schema-CREATE are revoked; runtime inputs must match an active grant and an exact Published binding/resource revision. | `M5_IT_DAT_PostgreSQL18_runtime_locator_is_exactly_granted_and_not_enumerable_when_configured`, architecture static assertions, PostgreSQL CI privilege assertions |
| Immediate cache invalidation | Every invocation verifies publication, binding and current resource stamps. Rotation, metadata revision or disable prevents stale snapshot reuse; stamp-verification failure is fail-closed. Runtime cache keys include the authenticated Installation context. | `M5_UT_Runtime_cache_revalidates_catalog_revision_and_disable_on_every_invocation`, locator PostgreSQL test |
| Integrated anti-exfiltration | One integrated test traverses Admin API, resource catalog, immutable bindings, review, approval, publish, runtime cache, instrumented provider and transport. It proves zero provider/transport use before publish, one approved use afterward, attacker-operation denial and immediate denial after rotation. | `M5_E2E_Admin_approval_publish_runtime_provider_transport_prevents_credential_exfiltration` |
| Complete Application conflict | Update and disable conflicts show display name, minimum/maximum Broker version, status, local/server ETags and the conflicting action. Save remains blocked until explicit reload; reload performs no mutation and clears stale error state. | `UI-MOCK-35`, `UI-MOCK-36`, existing API and PostgreSQL concurrency tests |
| Contract-driven runtime localization | `docs/api/runtime-wire-codes.json` is embedded and exposed by the authenticated Admin API. A generator produces the typed frontend contract; EN/IT key parity and backend-emitted code coverage fail closed in tests. Known codes cannot enter unknown fallback; roles are localized while sorting/filtering retain wire values. | `M5_UT_Runtime_wire_contract_exports_all_stable_admin_audit_values`, runtime i18n Vitest, `UI-MOCK-16/22/33`, OpenAPI parity/drift |
| Deterministic browser mocks | Approval submission synchronizes on `page.waitForRequest`; no asynchronous shared-variable read, sleep or retry was added. Application conflict teardown explicitly closes the dialog and resets mutation state. | `UI-MOCK-29` 20/20 isolated; `UI-MOCK-35` 30/30 isolated; complete 36-test suite repeated ten times, 360/360 PASS, retries 0 |

## Security properties

- The approver sees the effective non-secret destination, logical provider/resource identity, exact revision/checksum dimensions and public certificate metadata; credential values, locators, private keys, PFX and connection strings remain absent.
- Resource rotation, metadata change, status change, scope change and binding change alter or invalidate the approved semantic projection.
- `gateway_runtime` cannot enumerate `provider_resource_locator`; the controlled function rejects Draft, non-current, ungranted, cross-environment and cross-operation resolution.
- Runtime resolution derives tenant, application and Installation from authenticated state and checks the current grant before provider access.
- The anti-exfiltration test creates realistic synthetic credential and certificate material only in memory. It is not copied into Git or redacted evidence.

## Local gate on the product candidate

- Release build: PASS, zero warnings and errors.
- Ordinary .NET: 159 PASS; nine PostgreSQL-configured tests explicitly skipped in this run and executed separately.
- PostgreSQL 18: 10/10 PASS; empty apply, second apply no-op, non-superuser roles, FORCE RLS and locator least privilege PASS.
- Migration `0009` SHA-256: `92D2A5826CF348C676EB619C8A75F5F267C0C15E074617DDD700B885324A80F1`.
- Frontend: OpenAPI/runtime-contract drift PASS, lint PASS, 28 Vitest PASS, production build PASS and accessibility PASS.
- Browser: 360/360 repeated browser-mock executions PASS with retries 0; isolated determinism repetitions also PASS.
- Full stack: `FULLSTACK-01` PASS through production Admin build, PostgreSQL 18, synthetic Vault and BGW1+mTLS vendor mock; redaction and Docker cleanup PASS.
- M4 regression: quickstart connector test PASS with a distinct generated database credential and a non-superuser Admin pool; the runtime role remains unable to enumerate provider locators.
- Supply chain: conservative scanner negative/clean controls, Gitleaks history scan, NuGet/npm vulnerability, npm audit, frontend license, SPDX SBOM and documentation validation PASS.

Exact-head GitHub CI and the external redacted bundle are completion evidence for this remediation, not authorization to merge. Their identifiers are reported with the final handoff after verification. No acceptance criterion in this document declares M5 Done.

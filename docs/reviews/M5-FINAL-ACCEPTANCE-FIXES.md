# M5 final acceptance fixes

**Initial reviewed HEAD for the absolute final B/C/D cycle:** `4674033d2243d27f6d1cf46da438f7a2d26f495c`

**Product candidate:** `9f523e9c7efb07d81ca96032869e76c1e6ab07f1`

**Branch:** `m5/admin-ui-mvp`

**Decision:** criteria B, C and D pass the complete local gate. Exact-head CI and one final read-only acceptance review remain required. Criterion A was not modified. M5 is not declared Done, PR #5 remains open and unmerged, `main` is unchanged and M6 has not started.

## Final three-finding delta

This final cycle changes only locator least privilege, the real anti-exfiltration path and runtime localization. The other acceptance findings below remain regression evidence and were not redesigned.

| Finding | Remediation | Named evidence |
|---|---|---|
| Complete approval artifact | The canonical server-built artifact separates catalog resource version, catalog revision, public-metadata revision and certificate version. It includes resource type, binding revision/checksum, definition checksum and public certificate metadata. The same canonical digest is rechecked in the SERIALIZABLE approval transaction and used by publication. | `M5_UT_Approval_review_is_semantic_canonical_and_contains_no_credential_value`, `M5_UT_Approval_digest_covers_every_catalog_and_certificate_revision_dimension`, PostgreSQL atomic approval test, `UI-MOCK-29` |
| Locator least privilege | The canonical publication artifact now contains immutable `OperationBindingDependencies`. Runtime context and cache keys are operation-specific and resolve only the endpoint, secret and certificate bindings used by the invoked operation. Additive migration `0010` makes `logical_binding_id` an explicit controlled-function input and proves that the published operation authorization references that logical binding. The old broad overload is removed. | `M5_UT_Runtime_resolves_only_bindings_required_by_invoked_operation`; `M5_IT_DAT_PostgreSQL18_runtime_locator_is_exactly_granted_and_not_enumerable_when_configured`; architecture and privilege assertions |
| Immediate cache invalidation | Every invocation verifies publication, binding and current resource stamps. Rotation, metadata revision or disable prevents stale snapshot reuse; stamp-verification failure is fail-closed. Runtime cache keys include the authenticated Installation context. | `M5_UT_Runtime_cache_revalidates_catalog_revision_and_disable_on_every_invocation`, locator PostgreSQL test |
| Integrated anti-exfiltration | One deterministic PostgreSQL 18 test traverses the real Admin API, persisted resource catalog and bindings, review, production approval transaction, production publication transaction, operation-scoped runtime cache, instrumented provider and the production restricted HTTPS/mTLS transport. Separate approved and attacker TLS listeners are used. The attacker receives zero requests through every phase. | `M5_E2E_Admin_approval_publish_runtime_provider_transport_prevents_credential_exfiltration` |
| Complete Application conflict | Update and disable conflicts show display name, minimum/maximum Broker version, status, local/server ETags and the conflicting action. Save remains blocked until explicit reload; reload performs no mutation and clears stale error state. | `UI-MOCK-35`, `UI-MOCK-36`, existing API and PostgreSQL concurrency tests |
| Contract-driven runtime localization | `BackendRuntimeWireCodes` is the typed backend authority. The generator reads only its explicit published section; generic backend scanning is validation-only and cannot add codes. Generated JSON, TypeScript and EN/IT keys must be exactly equal. The public contract has 139 emitted reason codes and 25 audit actions; `BGW-GRANT-REVOKED` and `grant.revoke` are explicitly reserved because no emitting product path exists. | `M5_UT_Runtime_wire_contract_exports_all_stable_admin_audit_values`, exhaustive runtime i18n Vitest, `UI-MOCK-16/22/33`, `npm run check:runtime`, `test:runtime-negative` |
| Deterministic browser mocks | Browser synchronization uses observable requests, responses and locator state. No `waitForTimeout` remains in the browser test directory, and Playwright retries remain zero. | `UI-MOCK-29` 20/20 isolated; complete 36-test suite repeated ten times, 360/360 PASS, one worker, retries 0 |

## Security properties

- The approver sees the effective non-secret destination, logical provider/resource identity, exact revision/checksum dimensions and public certificate metadata; credential values, locators, private keys, PFX and connection strings remain absent.
- Resource rotation, metadata change, status change, scope change and binding change alter or invalidate the approved semantic projection.
- `gateway_runtime` cannot enumerate `provider_resource_locator`; the controlled function rejects Draft/Retired/Disabled, non-current, ungranted, cross-environment, cross-revision and cross-operation resolution. `operation_scope='*'` cannot authorize a logical binding absent from the invoked operation dependencies.
- Runtime resolution derives tenant, application and Installation from authenticated state and checks the current grant before provider access.
- The anti-exfiltration test creates realistic synthetic credential and certificate material only in memory. Only the approved vendor mock observes the API-key canary; it is not copied into Git, logs, browser artefacts or redacted evidence.

### Criterion B counter timeline

| Phase | Provider secret/certificate | Restricted transport | Approved vendor | Attacker |
|---|---:|---:|---:|---:|
| Before approval | 0/0 | 0 | 0 | 0 |
| Approved, before publication | 0/0 | 0 | 0 | 0 |
| First approved invocation | 1/1 | 1 | 1 | 0 |
| Unauthorized operation | unchanged | unchanged | unchanged | 0 |
| Rotated resource before new approval/publication | unchanged | unchanged | unchanged | 0 |
| Rotated resource after new review/approval/publication | 2/2 cumulative | 2 cumulative | 2 cumulative | 0 |
| Disabled resource | unchanged | unchanged | unchanged | 0 |

## Local gate on the product candidate

- Release build: PASS, zero warnings and errors.
- Ordinary .NET: 159 PASS and 10 PostgreSQL-gated SKIP, derived from the six assembly summaries; every skipped scenario is exercised by the dedicated database phase.
- PostgreSQL 18: `PostgresIsolationTests` 10/10 PASS plus the definitive anti-exfiltration E2E 1/1 PASS in a separate, ordered phase; empty apply, second apply no-op, non-superuser roles, FORCE RLS and locator least privilege PASS.
- Migration `0010` SHA-256: `8DEA12DF50270E871D717C101B422FAB9E66198E4AAD5D9C40997055BC56C3A2`; empty apply and second apply no-op PASS.
- Frontend: OpenAPI/runtime-contract drift PASS, lint PASS, 28 Vitest PASS, production build PASS and accessibility PASS.
- Browser: `UI-MOCK-29` 20/20 isolated and the complete browser-mock suite 360/360 PASS with one worker, retries 0 and no sleeps.
- Full stack: `FULLSTACK-01` PASS through production Admin build, PostgreSQL 18, synthetic Vault and BGW1+mTLS vendor mock; redaction and Docker cleanup PASS.
- M4 regression: quickstart connector test PASS with a distinct generated database credential and a non-superuser Admin pool; the runtime role remains unable to enumerate provider locators.
- Runtime contract: 201 published values total, including 139 reason codes and 25 audit actions; one additional reason and one audit action are reserved/non-emitted and excluded. Synthetic unmapped backend code negative control PASS.
- Supply chain local: conservative scanner negative/clean controls, NuGet/npm vulnerability, npm audit, frontend license, container-inclusive SPDX SBOM, Core export and documentation validation PASS. Gitleaks is executed by exact-head CI because its CLI is not installed on the HOST.

Exact-head GitHub CI and the external redacted bundle are completion evidence for this remediation, not authorization to merge. Their identifiers are reported with the final handoff after verification. No acceptance criterion in this document declares M5 Done.

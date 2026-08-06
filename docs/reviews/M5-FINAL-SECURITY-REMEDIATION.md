# M5 final security remediation

**Initial reviewed HEAD:** `644e45986086d92d3fba055b0aebf5ace52007da`  
**Product candidate:** `fc342b62d8e1165e643cbead898dec4f34188969`  
**Branch:** `m5/admin-ui-mvp`  
**Decision:** **GO for a concluding read-only review limited to the three residual technical findings.** M5 is not declared Done, PR #5 remains open and unmerged, `main` is unchanged and M6 has not started.

## Findings remediated

| Finding | Result | Named evidence |
|---|---|---|
| Arbitrary secret/certificate references | Admin binding requests accept structured `ProviderResourceReference` values only. Provider and resource IDs must resolve to a current server-owned catalog revision with matching type, Environment, Connector and operation scope. URI, PEM, encoded credential material, connection-string-like input and unknown resources fail closed before approval, publish or provider invocation. | `M5_UT_Actual_canary_and_opaque_credential_material_are_denied_by_catalog_before_binding`, `M5_UT_Instrumented_actual_canary_provider_is_called_only_for_published_approved_destination`, `M5_IT_DAT_Approved_binding_digest_and_publication_are_atomic_under_concurrent_mutation_when_configured`, `UI-MOCK-27/29`, `FULLSTACK-01` |
| Application conflict presentation | The dialog compares every editable value: display name, minimum Broker version and maximum Broker version. It shows local/server ETags and changed/unchanged text, blocks blind resubmission and reloads the current server snapshot. | `UI-MOCK-35`, Admin API concurrency integration and PostgreSQL barrier tests |
| Runtime values in Italian UI | A typed mapper translates known status, lifecycle, approval, health, audit, role and scope wire values. Sorting/filtering retain wire values; an unknown code is shown as a safely marked technical value rather than receiving an English fallback. | `runtimeValues.test.ts`, `UI-MOCK-16/17/18/32/33` |

Tenant FORCE RLS remains **RESOLVED** and was not redesigned. Its PostgreSQL regression remains green.

## Server-owned resource model

`ProviderResourceReference` contains `providerId`, `resourceId`, `resourceType`, optional `version` and optional `publicMetadataRevision`. The Admin UI lists catalog metadata and submits a selection; it cannot submit a provider locator or credential value. Logical IDs are bounded, syntax checked and then authoritatively resolved from the catalog.

PostgreSQL migration `0008_provider_resource_catalog_m5.sql` separates:

- reviewable metadata in `provider_resource_catalog_version`;
- protected physical locators in `provider_resource_locator`.

The metadata table has no secret-value or physical-reference column. `gateway_readonly` cannot select locators; `gateway_admin` can insert immutable revisions but cannot update them; `gateway_runtime` can read the locator required for Published execution. Exact grants are re-established idempotently after historical migration replay. Migration SHA-256: `9C3ED60348B6B161C271A63C306500EC5628E5F049238520B5639BB8DC387E6E`.

## Certificate metadata and transactional approval

`ICertificateMetadataProvider` returns only SHA-256 fingerprint, subject, issuer, validity, public-key algorithm/size and provider version. Synthetic tests use real X.509 certificates. A certificate binding without public metadata is rejected, and `CERTIFICATE_NEAR_EXPIRY` is derived from actual validity.

The authoritative approval transaction locks the approval request and ConnectorVersion, locks binding revisions, takes transaction-scoped advisory locks for each logical provider resource, rereads current immutable revisions, rebuilds the canonical review artifact, recalculates the digest, performs fixed-time comparison and four-eyes checks, and writes approval plus metadata-only audit before commit. Registration uses the same logical lock; a catalog rotation racing the review invalidates approval. Publish repeats current-resource and digest validation.

The instrumented provider contains an actual credential value during the test. It is not reproduced in this document or evidence. Tests demonstrate zero provider/transport calls before approved publication, exactly one provider read after publication, injection only into the approved destination, and absence from review artifact, response and audit.

## Gate results on the candidate

- Release build: PASS, zero warnings/errors.
- Ordinary .NET: 153 PASS; eight PostgreSQL-gated cases skipped only in this ordinary run.
- PostgreSQL 18: 9/9 PASS; empty apply, second apply no-op, non-superuser, forced RLS and catalog least privilege PASS.
- Frontend: OpenAPI drift PASS, lint PASS, 28 Vitest PASS, production build PASS, 35/35 Playwright browser-mock PASS, accessibility PASS.
- Full stack: `FULLSTACK-01` PASS through production Admin build, PostgreSQL 18, synthetic Vault and BGW1+mTLS vendor mock; redaction and Docker cleanup PASS.
- Supply chain: secret negative/clean scan, Gitleaks, NuGet/npm vulnerability, npm audit, license scan, SBOM and Core export PASS.
- Core export: 295 files; manifest SHA-256 `59379E707AD9500CA90325D835E98AFADF80E6E33ED9F61C342516F132AAE6C4`.
- Candidate CI: general PR run `31098662098` 6/6 PASS; M5 push run `31098659514` 15/15 PASS; M5 PR run `31098662290` 15/15 PASS. All use `GITHUB_SHA=fc342b62d8e1165e643cbead898dec4f34188969`.

## Evidence and limits

Redacted evidence is outside Git at `C:\SecureEvidence\m5-final-security-fix-20260806-134839`. ZIP SHA-256: `49B89C1D25AB72361A337F877A2724BA90C48FCEE5E0A071D9D8A8353FF94D43`. It contains summaries, manifest, file hashes and SPDX SBOMs; no raw logs, credential value, activation code, token, cookie, private key or certificate bundle is included.

This remediation does not merge PR #5, change `main`, create a tag, declare M5 Done or begin M6.

# M5 technical final remediation

> Superseded for the three last residual findings by `M5-FINAL-SECURITY-REMEDIATION.md` and candidate `fc342b62d8e1165e643cbead898dec4f34188969`. This report remains the evidence for the preceding four-finding cycle.

**Initial reviewed HEAD:** `7039fd5adfb200b3243eaef8eb3d89c866929e32`
**Implementation candidate:** `7ac956fe9d3fa641d420004c2f944c7a2f5a8210`
**Branch:** `m5/admin-ui-mvp`
**Decision:** **GO for a final read-only review limited to the four technical findings.** M5 is not declared Done, PR #5 remains open and unmerged, `main` is unchanged and M6 has not started.

## Findings closed

| Finding | Remediation | Evidence |
|---|---|---|
| Semantic approval | The backend builds `ApprovalReviewArtifact` from the same immutable connector and binding revisions used for publication/runtime. It exposes the effective non-secret destination, methods, logical provider/resource/certificate metadata, revisions, checksums, semantic diff, risk indicators, canonical JSON and digest. Approve accepts only request ID, expected digest and optional redacted comment; the digest is recomputed in the approval transaction. | `ConnectorConfigurationTests`, `AdminSecurityTests`, `AdminApiSecurityTests`, `UI-MOCK-29/33`, `FULLSTACK-01` |
| Tenant FORCE RLS | Tenant create/update/disable set transaction-local `app.tenant_id` through parameterized `set_config`, mutate and write audit in one transaction. Update/disable lock the row and compare row version before mutation. No global context, superuser or RLS bypass was added. | PostgreSQL 18 `M5_IT_DAT_Tenant_mutations_are_FORCE_RLS_correct_atomic_and_concurrent_when_configured` plus role/FORCE-RLS assertions |
| Tenant/Application concurrency | GET/create responses expose ETag; update/disable require If-Match. Missing precondition returns 428, malformed ETag is stable, stale state returns 409, and no success audit or overwrite occurs. Frontend preserves row versions and offers compare/reload for both resources. Existing additive `row_version` columns made a new migration unnecessary. | `AdminConcurrencyTests`, Admin API integration, PostgreSQL barrier test, `UI-MOCK-34/35`, OpenAPI drift |
| Italian completeness | English and Italian resources are independent and have exactly equal key sets. Missing keys fail closed, hardcoded JSX/accessibility copy is scanned, and browser coverage exercises the administrative surfaces in both languages without hidden English fallback. | 25 Vitest, `UI-MOCK-18/32/33`, hardcoded-copy scanner |

## Approval security properties

The review artifact includes connector/version/operation/environment, effective `scheme://hostname:port/path`, HTTP methods, redirect/TLS policy, destination classification, logical secret and certificate bindings, provider identity, public certificate metadata when available, immutable revision checksums and publication digest. Credential values, API keys, passwords, client secrets, private keys, PFX, tokens, connection strings and provider credentials are never part of the artifact.

Risk indicators are server-computed and text-labelled for new/changed host, public Internet destination, new/changed port, path/method/redirect/TLS change, provider/resource/certificate/scope/environment change, near-expiry certificate and previously unused bindings. The frontend neither constructs the digest nor chooses its fields. Any binding change invalidates the checksum-specific approval; runtime remains Published-only and resolves endpoint/provider/resource exclusively server-side.

## Gate evidence

- Release build: PASS, zero warnings/errors.
- Ordinary .NET: 149 PASS; eight environment-gated PostgreSQL tests skipped only in the ordinary run.
- PostgreSQL 18: 9 PASS, zero skipped, non-superuser role, FORCE RLS, apply/no-op and cleanup PASS.
- Migration `0007` checksum: `EC3B4E9A85FB050A1FDFC16E4E7B89042A7A6D93972CA46DF2BCEA2AE51FEE4A`; no migration was added or modified.
- Frontend: lint PASS, build PASS, 25 Vitest PASS, 35 Playwright browser-mock PASS, axe zero serious/critical.
- Full stack: `FULLSTACK-01` PASS through production Admin build, PostgreSQL 18, synthetic Vault and vendor BGW1+mTLS; redaction and Docker cleanup PASS.
- Security/release: secret negative fixture and clean scan PASS, Gitleaks PASS in CI, NuGet/npm vulnerability PASS, dependency scan PASS, SBOM PASS, document validation and `git diff --check` PASS.
- Exact-candidate CI: general PR run `31088473433` 6/6 PASS; M5 PR run `31088472335` 15/15 PASS; M5 push run `31088472535` 15/15 PASS. All use `GITHUB_SHA=7ac956fe9d3fa641d420004c2f944c7a2f5a8210`.

## Evidence and scope

The redacted technical bundle is stored outside Git at `C:\SecureEvidence\m5-technical-final-fixes-20260806-110934`. ZIP SHA-256 is `96FCC2FB9380AB82FBA2A96E3C7CABCFAC92F94A3EEA621EC29C2D3D54DB3A83`; its manifest and sidecar bind the candidate, CI runs, SBOM hashes and test results. Raw logs, dumps and reusable credentials are excluded.

This remediation changes only the four confirmed technical findings and their regression evidence. It does not change repository visibility, licensing, terminology, export policy or Git history, and it does not authorize merge or start M6.

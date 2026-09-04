# M2 Gateway baseline — Final Gate Review

**Date:** 2026-08-04

**Result:** M2 **Done**; no M3 activity started.

## Baseline and CI evidence

The code and gate candidate commit is `b6e1e46aebbd005d1bacf20943b358f6ccb6ea1a`.
GitHub Actions run `30896803567` ran all jobs on the same SHA through
explicit checkout. The final documentation commit is a docs-only descendant and must
repeat the same gate before the annotated tag is applied.

| Job | Result | Evidence |
|---|---|---|
| `build-test (windows-latest)` | PASS | Release, 77 tests, document validation, secret scan, vulnerability scan and SBOM |
| `gateway-postgresql-18` | PASS | Real PostgreSQL 18, migration apply/no-op, checksum, roles, FORCE RLS, tenant isolation and cleanup |
| `gateway-container` | PASS | Build/execution, non-root, read-only, live/ready, fail-closed, Trivy secret scan, SBOM and shutdown |
| `gitleaks` | PASS | PR history; a historical false positive is excluded only through its exact fingerprint |

Candidate commit container evidence:

- Gateway image content digest: `sha256:613507c2cc914cbe41fa0164cce6893d1fa92489bfcf4a473395d8d435c574d9`;
- migration image content digest: `sha256:d05ec2be0334a0105f31dae11c3df185f6f5bc962ca13f41cce240445bae6830`;
- migration SQL SHA-256: `182CC690E16BB986638A4B52EE1554A4B540A8E58FD673F2111A79D194C66A98`;
- image SBOM artifact SHA-256: `38ad96f4bc04fb9a515980277451d4a2b6deb484fdcfab283a7e72c2125960be`.

The annotated tag contains the digests produced by the repeated CI run on the final commit,
which is the normative evidence if revision labels make it differ from the candidate values above.

## Review of critical areas

| Area | Result and evidence |
|---|---|
| Authenticated Tenant | PASS. `RuntimeIdentityService` resolves the registered certificate's SHA-256 digest and returns server-side Tenant/Application/Installation. |
| Client-side `tenantId` | PASS. `GatewayInvokeRequest` exposes no Tenant, URL or secret reference; `UT_GTW_Invoke_contract_has_no_client_controlled_endpoint_or_secret_reference` prevents regressions. |
| PostgreSQL and RLS | PASS. Composite FKs, `ENABLE/FORCE ROW LEVEL SECURITY`, transactional tenant context and narrow locators; local and CI PostgreSQL 18 cross-Tenant tests. |
| Activation/enrollment | PASS. Random 256-bit activation code stored as HMAC, 24 hours, maximum five attempts and single-use consumption. |
| PoP | PASS. Expiring challenge and deterministic-format ECDSA P-256 signature verified before activation. |
| Replay | PASS. Bounded UTC timestamp, 16-byte nonce and persisted digest with TTL; reuse denied. |
| Renewal/overlap | PASS. Renewal in the final 30 days and maximum seven-day overlap; previous credential expiry tested. |
| Revocation | PASS. Installation/credential state checked before grants, Vault, DNS and transport; immediate revocation tested. |
| Grant | PASS. Immutable server-side catalog and deny-by-default; denial occurs before any side effect. |
| URI/DNS/IP | PASS. HTTPS only, filtered resolution, loopback/private/link-local/multicast/ULA denied and validated IP passed to transport. |
| SSRF/DNS rebinding | PASS. `ConnectCallback` opens the socket on the already validated address, preventing a second uncontrolled resolution. |
| Redirect/header | PASS. Redirects, proxies, cookies and implicit decompression disabled; API key header name and method are server-side catalog configuration. |
| Basic/API key/mTLS | PASS. Values are read from the server-side provider only after identity and grant checks and applied exclusively to the outbound request. |
| Arbitrary URLs/secrets | PASS. The client selects only Connector/operation; endpoints and Vault references are not part of the invoke contract. |
| Key Vault boundary | PASS for code. Azure SDK and Managed Identity belong to the Gateway; the Broker depends only on `IGatewayInvoker`. Live Azure evidence remains environmental debt. |
| Redaction | PASS. Metadata-only audit, sanitized Problem Details, negative log canary, source scan, Gitleaks and image secret scan green. |
| No GetSecret | PASS. No route or public contract returns secrets; `GetSecretAsync` is an internal infrastructure abstraction used only to compose egress. |

## M2 criteria

- FR-001, FR-002, FR-007 and the M2 portion of FR-016: satisfied.
- NFR-001, NFR-002, NFR-003, NFR-005, NFR-006 and NFR-010: satisfied within M2 scope.
- AC-007, AC-009, AC-010, AC-011, AC-012 and AC-018: PASS.
- AC-013: immediate M2 revocation PASS; production-like Broker→Gateway propagation intentionally remains in the M3 gate.
- AC-027: repository SBOM and image SBOM PASS.

## Preserved failed runs and corrections

| Run | Cause | Correction with regression coverage |
|---|---|---|
| `30895783874` | Unresolvable Trivy action, missing Gitleaks token, implicit `rg` on Windows runner | Correct action tag, explicit token/permissions, Git PCRE fallback tested in clean PowerShell |
| `30896092242` | Gitleaks PR permission and Docker label quoting | `pull-requests: read` and label lookup with `jq` |
| `30896294941` | Exact Gitleaks false positive and outdated Trivy installer | Fixture rename, precise historical fingerprint and updated official Trivy |
| `30896531326` | All jobs PASS, but artifacts labeled with synthetic merge SHA | Checkout and labels bound to the real PR HEAD |

No squash, rebase, amend or force push was used. No ADR was changed:
the review found no architectural deviations.

## Non-blocking residual risks

- Key Vault/Managed Identity was not tested live without an authorized subscription;
- challenge store still single-node/in-memory per ADR-0008;
- full operational idempotency deduplication deferred to M4;
- Gateway HTTP v1 and IPC v1 remain provisional until M3 validation;
- Local Administrator and privileged cloud identities remain operational residual risks.

# Test strategy

This strategy distinguishes automated tests, environment-specific gates, external
qualification and deferred work. In the full repository, the canonical requirement → test
→ evidence/state matrix is maintained in `requirements-traceability.md`, which is not part
of the Core export; an aggregate count alone is not evidence.

## Principles

- negative paths and fail-closed behavior are first-class tests;
- synthetic tests, controlled live labs, OfficialTest and production are distinct levels;
- no fixture contains reusable secrets, real certificates, healthcare data or raw
  external responses;
- a skip in a required gate is not a PASS;
- a failure remains visible and the gate is rerun only on the exact corrected commit;
- every claim is tied to named tests and environmental preconditions.

## Evidence states

| State | Meaning |
|---|---|
| `AUTOMATED` | Named test executed by a repeatable suite; PASS applies to the exact commit/run. |
| `EXTERNAL` | Requires an externally administered service or environment and separate attestation. |
| `MANUAL` | Documented operator procedure, not replaced by an automated test. |
| `DEFERRED` | Planned work not required for the current claim. |
| `BLOCKED` | A precondition or known defect prevents the claim. |
| `UNVERIFIED` | Code/design exists but no sufficient evidence is recorded. |

A requirement can have multiple rows/states: for example, `AUTOMATED` Core behavior and
`EXTERNAL/UNVERIFIED` cloud deployment.

## Current automated coverage

| Level | Main surfaces |
|---|---|
| Unit | DPAPI/AES-GCM, redaction, authorization/grants, canonicalization/checksum, Connector schema/validator, lifecycle, endpoint/header/path policy, SSRF, replay, OAuth/SOAP/session/JWT/signing foundation and XML hardening. |
| Integration | IPC and Windows identity, enrollment/renewal/revocation/BGW1, PostgreSQL 18 migration/RLS/privileges, publish/four-eyes/binding/cache/rollback, restricted egress/TLS/mTLS and synthetic providers. |
| Architecture | Core/pack dependencies, absence of prohibited capabilities, Core export, provider boundaries and runtime contracts. Some guards are source-text checks and do not replace assembly/IL audits. |
| Synthetic hosted/E2E | Broker/Direct to the same runtime, REST Connector, Admin import-to-invoke, SOAP/session/capability bridge and vertical packs against synthetic servers/certificates. |
| Admin Web | Lint, strict TypeScript, generated-contract checks, Vitest, Playwright mock UI, accessibility and full-stack with Gateway/PostgreSQL/provider/vendor mock. |
| Supply chain | Secret scan, dependency/npm audit in relevant jobs, container checks, base-image validation, Core export and SPDX SBOM. |

OAuth Authorization Code/PKCE and Client Credentials primitives have foundation
tests, but the current Gateway host does not register an E2E OAuth execution strategy.
They are therefore not a qualified external OAuth Connector.

## Gates with a dedicated environment

| Gate | Environment and permitted claim |
|---|---|
| Windows Broker | Windows host with real Service/virtual account, Named Pipe, ACLs, DPAPI and process identity; does not prove MSI or native adapters. |
| PostgreSQL 18 | Dedicated instance/container, separate migration/runtime/admin identities, fresh/upgrade/no-op, FORCE RLS and races; the test must execute, not be skipped. |
| Container/M3A | Linux Docker, non-root/read-only/tmpfs where configured, network split and TLS mocks; qualifies the synthetic lab, not a production cloud deployment. |
| Admin full-stack | Gateway/Admin, PostgreSQL 18, Synthetic Provider and vendor mock without intercepting Admin API/auth; rollback proofs remain separate named tests. |
| Local PKCS#12 lab | Opt-in pack, per-run synthetic material outside Git, non-root/read-only and tamper/readiness; no official import or live external call. |
| M3B Azure | Separate authorized workflow; not live-qualified on the current baseline. |
| FSE2 OfficialTest | Official environment with authorized access/material and its own runner prerequisites. The [current pilot](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md) records CDA and workflow live observations; the [capability summary](../../IMPLEMENTATION_STATUS.md) owns offline/live limits. This is not overall live or production qualification. |

## UI trust boundary

- `npm run test:ui-mock` intercepts calls with `page.route`: it is browser/component testing, not
  product E2E.
- `tools/m5/Invoke-M5FullStack.ps1` uses real APIs and processes in the full-stack lab;
  DevelopmentAuth is restricted to the loopback peer.
- synthetic OIDC integration uses the real ASP.NET Core handler and verifies code, PKCE,
  state, nonce, issuer/subject, cookie, session rotation, logout and negatives; it does not qualify
  an external identity provider.
- UI tests cover roles, CSRF/RBAC/tenant scope, four-eyes, EN/IT, keyboard and axe without
  critical/serious findings.

## Security test policy

Every security-sensitive change adds at least one positive and one negative case for the
relevant authorities: identity, grant, Published revision, binding/provider resource,
replay, endpoint/DNS, credential, signing scope, A→B race, redaction and cleanup.

Deterministic bounds and malformed inputs are automated for JSON/XML/IPC, traversal and
ambiguous encoding, SSRF IPv4/IPv6/DNS rebinding, header injection/hop-by-hop,
XXE/entity expansion, replay/PID reuse, provider failure and secret canaries. They are not
described as fuzzing until a dedicated fuzz harness exists with corpus, duration and
crash triage.

## PostgreSQL and audit

Named PostgreSQL tests prove migration checksum/fresh/no-op, roles, FORCE RLS,
tenant isolation, publication/binding/locator and transactions/races. Metadata-only tests
prove that payloads and credentials do not enter events.

Migration 0017 revokes `gateway_admin` UPDATE/DELETE/TRUNCATE on audit and all its
invocation-event privileges. The named test
`SEC_DAT_PostgreSQL18_event_table_privilege_matrix_is_minimal_and_append_only_when_configured`
checks the effective role matrix, including denied audit UPDATE. It requires configured
PostgreSQL; its existence alone is not a new exact-head PASS. Owner/migration and
privileged database administrators remain trusted.

## SBOM and export

`eng/generate-sbom.ps1` produces SPDX for application artifacts and an aggregate manifest
with SHA-256/exact commit. The Linux job adds the container document through Syft;
`eng/validate-sbom.ps1` and `eng/test-sbom-modes.ps1` verify completeness and fail-closed behavior.
CycloneDX, artifact signing and published provenance are not implemented.

The raw Core export manifest SHA includes run-specific metadata and is not used as a
deterministic cross-run digest. The exporter also writes `normalizedInventorySha256`
over source commit and canonical path/size/hash inventory, without the run timestamp.
`eng/Test-CoreExportInventoryDeterminism.ps1` checks same-commit stability and negative
content/path/size-hash changes. This qualifies source-inventory identity, not binary
reproducibility or signed provenance.

## Planned gaps

| Area | State and required gate |
|---|---|
| Fuzzing | `DEFERRED`: stateful harness, versioned corpus, budget and crash regression. |
| Performance/load | `UNVERIFIED`: repeatable throughput/latency/provider-cache/PostgreSQL baseline. |
| IPC large payload | `DEFERRED`: implement `Data`/`End` and backpressure or reduce declared bounds. |
| Coverage/SAST | `UNVERIFIED`: coverage threshold and dedicated CodeQL/SAST are not current gates. |
| Module provenance | `DEFERRED`: manifest/hash/CMS/publisher/tamper; the loader checks path/identity/MVID, not signatures. |
| Installer/legacy | `DEFERRED`: MSI, C ABI/COM, x86/x64 and compatibility matrix. |
| Enterprise resilience | `UNVERIFIED`: load/soak, backup/restore, failover, HA/DR, recovery and pentest. |
| External services | `EXTERNAL`: live Azure, real OIDC and FSE2 OfficialTest are not inferred from mocks. |

## Fixtures and evidence

- use reserved domains, synthetic identities and per-test generated certificates;
- do not save real responses, tokens, PFX/PEM/P12, activation codes or clinical data;
- run canary/secret scans on logs, browser output and package staging too;
- keep raw evidence outside the repository in a protected directory;
- only redacted manifests, test IDs, exact commits and hashes remain in the repository;
- before declaring an external gate PASS, record environment, preconditions, outcome and
  qualification limits without publishing confidential material.

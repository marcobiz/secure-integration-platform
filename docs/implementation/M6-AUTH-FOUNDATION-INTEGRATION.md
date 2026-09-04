# M6 Auth Foundation integration

Gate date: 2026-08-07
Verdict: **PASS — M6 Auth Foundation DONE**

This document attests only to the integration of the M6 authentication foundations. It does not attest to production-ready healthcare connectors and does not start SOGEI, Lombardia, FVG or Umbria.

## Baseline and lineage

- initial `main` baseline: `f34275096b4960bb5f31840553444935defc3d2d`;
- PR #12, PostgreSQL test isolation: approved HEAD and resulting SHA `5670b674612c13ce21cff2552329b0355e78bada`, integrated by fast-forward without rewriting;
- PR #9, HTTP/OAuth: reviewed HEAD `ed60cb3e41bde3ab0078e187593d162405b9bb80`, rebased on #12 and resulting/merge SHA `e852d4a2ca1e3dfd4060b278c96f214f8ce5b264`;
- PR #10, SOAP/Basic/session: reviewed HEAD `389ac772b3249210d69f546dd466a45357945f00`, rebased on #12+#9 and resulting/merge SHA `3c04424bba79ca55ddfdc3a5671d8e37ef1f173d`;
- PR #11, certificate/RS256/mTLS: reviewed HEAD `8e15bf26866e8f4a0dc7d0611220d78f14f30d81`, rebased on #12+#9+#10 and resulting/merge SHA `44be6583632cf3d07cdbf329ed7bfc9316c8313b`.

`44be6583632cf3d07cdbf329ed7bfc9316c8313b` is the combined product HEAD qualified by the gate. The subsequent commit containing only this report is the documentation HEAD and target of annotated tag `m6-auth-foundation-baseline-20260807`; the target's final Git identity is therefore recorded by the tag, without creating self-referential SHA references in this file.

All four PRs had a **FINAL GO** review verdict before integration. After each rebase, targeted tests, applicable PostgreSQL gates, Core export and exact-head CI were repeated before fast-forward.

## Overlap and conflicts

The preliminary analysis found no production files shared between OAuth, SOAP and certificate/signing. Overlaps involved solutions/projects, Core export, documentation/indexes and lock files:

- #9/#10: solution, status, auth contract, threat model, traceability, allowlist, test project references and locks;
- #9/#11: solution, status, auth contract, threat model, traceability and test locks;
- #10/#11: solution, status, auth contract, threat model, traceability and test locks.

PR #9 produced no conflicts. PR #10 required mechanical unions of `BrokerGateway*.slnx`, test project references, regenerated locks, Core allowlist and documentation sections. PR #11 required only composition of documentation sections; solution and locks aligned automatically. Threat IDs remained unique: OAuth `TM-046/047`, SOAP `TM-048/049`, certificate/signing `TM-050…053`. No semantic adaptations, bypasses, retries or weakened controls were introduced.

## OAuth

PASS on targeted tests and 21 synthetic HTTPS integrations, plus 4 architecture tests. They demonstrate:

- authority and profile derived from the server-owned Published snapshot;
- denial of profile, endpoint, secret reference and scope substitution;
- destination-bound bearer and zero requests to the attacker endpoint;
- correlation binding, state/code replay denial and one-time attempt;
- single-flight refresh, invalidation/tombstone after rotation and no stale fallback;
- fail-closed parameter-smuggling, SSRF, redirect and restricted token/resource transport controls;
- opaque challenge/session references and redacted diagnostics.

## SOAP, Basic and session

PASS on 14 targeted unit tests, 5 synthetic HTTPS integrations and 2 architecture tests. They demonstrate:

- Basic resolved and applied exclusively server-side;
- bounded interaction/session cache, revision-aware generation and security stamp;
- transport-neutral AP-02 and one-time challenge;
- acquisition, expiry, a single controlled reacquisition and logout;
- fail-closed `Active→Disabled` and `rev1→rev2` rotation;
- deadline extended to stalled response body and parsing;
- SOAP 1.1/1.2, DTD/XXE/external-entity denial and XML bounds;
- duplicate, mixed or ambiguous Faults denied without re-login classification;
- redacted faults, errors and diagnostics.

## Certificate, RS256 and mTLS

PASS on 49 dedicated tests and 4 provider/architecture boundary tests. They demonstrate:

- server-owned JWT policy and `ResolvedRs256SigningContext` that consumers cannot construct;
- denial of policy substitution, claim injection, HS/RS confusion and key substitution;
- approved fingerprint and SPKI digest, provider-side signing and verification against the same SPKI;
- sanitized provider exceptions and preserved real cancellation;
- one-shot transport-bound mTLS without a public reusable handle;
- purpose, endpoint and revision binding with immediate revalidation;
- fail-closed rotate/disable and retained revision 1 with zero connections;
- real local TLS handshake, hostname validation and wrong-certificate denial;
- no generic signing oracle, private-key/PFX export or Broker fallback.

## PostgreSQL 18 and shared isolation

The dedicated gate used PostgreSQL `18.4` in a temporary isolated container, subsequently removed:

- canonical suite: 3/3 consecutive runs PASS, 71 tests per run, 213 tests executed;
- fresh migration apply: 3/3 PASS;
- second no-op application: 3/3 PASS;
- seven critical tables with FORCE RLS: 3/3 PASS;
- pagination, atomic failure injection, Tenant/Application concurrency and binding/publication concurrency: 4/4 PASS;
- retry count 0, sleeps in tests 0, global parallelism not disabled;
- ignored local evidence: `.artifacts/m6-auth-foundation-gate/postgresql-qualification.json`, SHA-256 `0A1EA4152ECE3D52BA27741E90AEE17E4AE009DF3136318D301172EC766CEE0B`.

`gateway-postgresql-18` and `m5-postgresql-18` also PASS on each realigned candidate and the combined HEAD.

## Combined gate

### Build and tests

- Release build: PASS, 0 warnings, 0 errors;
- ordinary .NET suite: 271 total, 261 PASS, 10 PostgreSQL-conditional SKIP; those 10 were subsequently executed and passed in the dedicated PostgreSQL gate;
- breakdown: Architecture 16/16, Gateway Unit 80/80, Broker Core 26/26, Broker Integration 28/28, Vertical Slice 1/1, Gateway Integration 61 PASS + 10 conditional, Certificate Signing 49/49;
- frontend: 28/28 Vitest, 2/2 accessibility, 37/37 browser mock;
- OpenAPI drift and runtime wire contract: PASS;
- production build and `FULLSTACK-01`: PASS in exact-head CI.

### Architecture invariants

The 16 architecture tests, including `HttpOAuthBoundaryTests`, `SoapAuthBoundaryTests` and `ProviderBoundaryTests`, confirm:

1. inbound Broker/Direct separate from outbound auth;
2. no vendor-auth decision based on `InstallationKind`;
3. connector input limited to logical policy/profile IDs;
4. endpoint, resource and policy derived from server-owned Published state;
5. no exposure of passwords, tokens, private keys, PFX, reusable certificate handles or provider locators;
6. mandatory restricted transport;
7. rotation/disable invalidates stale material;
8. AP-02 remains transport-neutral;
9. no cyclic OAuth/SOAP/Crypto dependency;
10. future Healthcare Pack dependency allowed only through public Core APIs, not Infrastructure internals.

### Security and release

- conservative secret scan and negative CI check: PASS;
- Gitleaks: PASS;
- NuGet vulnerability scan: no vulnerable packages;
- npm audit: 0 vulnerabilities;
- frontend license scan: 407 locked packages qualified;
- SBOM: generation and validation PASS; aggregate manifest SHA-256 `A749E9BBFBA14175354746F1C09F9405E047512DE6E3C09B344BA5BE9668B74A`;
- Core export: PASS, 357 files, manifest SHA-256 `D385F7EDDBC5CF099E77D751F27F2393E922195C90316E8A9993CBA758299751`;
- documentation validation and `git diff --check`: PASS;
- cleanup: zero gate PostgreSQL containers and zero repository Node processes; the pre-existing dev container was not altered.

## Final CI on the combined HEAD

All jobs ran on SHA `44be6583632cf3d07cdbf329ed7bfc9316c8313b`:

- push `ci` run `31214475589`: 6/6 PASS (`build-test`, `gateway-postgresql-18`, `gateway-container`, M3 deterministic, M4 quick-start, Gitleaks);
- push `m5-admin-ui` run `31214474149`: 15/15 PASS, including `m5-postgresql-18`, frontend, browser mock, accessibility, OpenAPI/runtime checks, `FULLSTACK-01`, Core boundary, scans, SBOM and cleanup;
- corresponding PR exact-head runs `31214135710` and `31214135658`: PASS.

## Known deferred

- production PKCE primitive, if still needed beyond the implemented foundation;
- production healthcare connectors;
- real WSDL/OpenAPI;
- service-specific lifecycles;
- service-specific fault taxonomy;
- real providers and endpoints;
- real custody of FVG/Umbria keys;
- generic SAML;
- generic WS-Security;
- generic HMAC;
- XML-DSig;
- smart-card/VPN framework.

These items require their own characterization and gates. None is implicitly declared ready by the M6 Auth Foundation baseline.

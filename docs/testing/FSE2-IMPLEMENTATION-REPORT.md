# FSE2 National Connector Organization profile — implementation report

Date: 2026-08-12

Immutable Core/Auth/Runtime baseline: `a40765dfa30dce23c6ce266b18740c3c766c21e3`

Content-commitment remediation branch: `wave1/fse2-content-commitment-signing`

Lineage: historical PR #16; Organization replacement branch
`wave1/fse2-national-organization`; this branch is a new focused Core exception and does not
rewrite either lineage.

Official public freeze: guide 2.23 and OpenAPI 1.0.0 at
`430e6b5d9dde8a35b04ae635c11303db787a977e`.

## Implemented result

The Organization profile now runs as the external module `healthcare-fse2` and strategy
`healthcare-fse2-organization`. Its only declared outbound authentication kind is `mtls`.
The pack consumes the public `AuthorizedConnectorExecution` surface and has one project dependency:
`Gateway.Application`. It has no `InternalsVisibleTo`, store, provider, signing primitive,
certificate primitive, restricted-transport implementation, Gateway internal invocation object,
service locator or HTTP client.

The FSE2-specific profile is parsed and validated inside `Healthcare.FSE2` from the immutable
`AuthorizedPublishedExtensionConfiguration` copied from initially authorized Published A. The
strict extension supplies only common organization/locality/application values and a maximum
document bound. Operation, method, `pathTemplate`, parameter name, content type, multipart
boundary, signing slots and security policy cannot be selected there; the operation is the exact
already-authorized Core context and its semantics come from the frozen catalog. The profile does
not reread a generic store and is not a second authority model. Its approved P.IVA plus assigning authority produce canonical CX;
the two server-owned signing policies use that value as fixed `sub`. `person_id` remains a separate
validated business CX. DAP, purpose and action are derived from the frozen operation matrix and
`use_subject_as_author` is absent. Human Actor remains deferred.

The module registers `Fse2OrganizationPublishedOperationExpectationProvider`. Before strategy,
capability scope, signing, DNS or network, Core exact-matches mTLS, mandatory restricted transport,
the two-slot set, RS256, explicit `ContentCommitment` certificate Key Usage on both slots,
projection, environment-derived audience, canonical subject, issuer/CN
relation, 300-second `iat`/`exp` with no `nbf`, `jti`, `x5c`, claim sets, equal signing identities and
their distinction from mTLS. The strategy then requests exactly one fresh opaque token from
`authorization` and one from `integrity`. Core owns issuer, temporal values, signing binding, SPKI,
`x5c` and both projections. The vertical never reads either compact JWT and never creates an
Authorization or `FSE-JWT-Signature` header. Core projects the first as Bearer and the second as the
FSE header, then performs the existing Published-A freshness, restricted-egress and server-owned
mTLS flow.

ADR-0028 introduces the only new Core primitive required by the official S1 certificate profile:
`JwtSigningCertificateKeyUsageMode`, with closed `DigitalSignature` and `ContentCommitment` values.
The historical public policy factory and an absent Published `certificateKeyUsage` both map exactly
to `DigitalSignature`. A present value is canonical/checksum/four-eyes covered and the policy digest
always includes the effective mode. The signer uses separate branches, never a generic OR:
`DigitalSignature` preserves the old rule (missing Key Usage accepted; present Key Usage must contain
`DigitalSignature`), while `ContentCommitment` requires a present extension containing
`X509KeyUsageFlags.NonRepudiation`. No subject, issuer, OID, slot or connector inference exists.
Private-key handling, chain construction, leaf-first `x5c`, RS256, provider resolution, restricted
transport and the A1 mTLS validator are unchanged.

FSE2 claim composition remains connector-local. The integrity token receives only allowlisted
business/derived scalar claims. For document operations, the connector composes one immutable,
deterministic multipart body and computes lowercase SHA-256 over those exact final outbound bytes;
the same copied byte array is handed to restricted transport without later serialization. The
frozen eleven-operation inventory is unchanged: nine Production-available operations, two official
test-only operations, and no speculative FHIR create/replace, callback or consumer surface. All
eleven use Core `pathTemplate`; DELETE and both status GETs use `bodyMode: none`, producing no
`HttpContent`, body bytes or `Content-Type`. Payload operations use REQUIRED.

Responses are reduced to bounded technical identifiers and safe warnings. The module-owned workflow
store keeps technical workflow/trace correlations scoped by authenticated identities, Connector
version and `SharedOrganizationProfileChecksumSha256`; it never stores patient or document data.
The originating `OperationProfileChecksumSha256` is retained separately for validation/audit and is
not a correlation-key equality requirement between create and status. This correlation
store is process-local and is not represented as durable PostgreSQL workflow persistence.

## Production-path evidence

`Fse2OrganizationHostedIntegrationTests` crosses the real hosted path:

PostgreSQL 18 or in-memory Published store → Connector import/validation → editor → distinct
approver → publication → hosted Gateway → BGW1 request authentication → grant → dynamically loaded
FSE2 module/strategy → exact Published extension → both authorized signing slots → server-owned
mTLS/restricted HTTPS → synthetic FSE2 server → bounded response.

The all-operation server requires the exact trusted client certificate and checks the real request
method, projected path without query/fragment, body mode and content type for every one of the 11
operations. For every operation it verifies two distinct compact tokens and `jti` values, both RS256 signatures,
the full expected `x5c` chain, the same signing leaf, distinct `auth:`/`integrity:` issuers, fixed
organization subject, audience, `iat+exp` without `nbf`, exact Published lifetime,
DAP/purpose/action, the exact claim set, organization/locality/application and person claims, and
the SHA-256 of network-observed bytes where required. The matrix observes exactly 11 single
outbounds. The create operation correlates successfully to both workflow and trace status.

The runtime-only synthetic certificate fixture gives the shared S1 signing identity a critical
`contentCommitment`/`NonRepudiation` Key Usage and no `DigitalSignature`; the distinct A1 mTLS
identity retains `DigitalSignature` and no `NonRepudiation`. Both FSE2 slots publish and preflight
the explicit `contentCommitment` mode, use the same S1 SPKI, and remain distinct from A1.

Connector-specific real-Published negatives cover subject, audience, issuer/CN, projection,
missing/extra/unknown slots, temporal mode/`nbf`, lifetime, `x5c`, claim set and signing/mTLS
identity relations, including a Published `digitalSignature` substitution against the connector's
typed `ContentCommitment` expectation. A strategy sentinel plus counters prove zero signing, DNS,
HTTPS and generic transport/network effects.
Token-shape negatives reject missing/empty `jti` and any `nbf`. Dynamic-path negatives cover
missing and caller-named parameters, slash/backslash, percent form, query/fragment, dot segments,
non-NFC and over-limit values. Cross-scope workflow tests cover every authority dimension and
unknown workflow/trace values. The deterministic connector race completes mandatory policy
preflight, blocks public-material resolution immediately before the first signing operation,
publishes B, resumes and receives Core stale denial with zero signatures, FSE2 requests and generic
transport effects. Generic signing-slot, provider,
cancellation, timeout, restricted-egress and binding-substitution matrices remain regression evidence
from the qualified Core foundation; they are not reimplemented in the vertical.

## Current remediation qualification ledger

Preliminary failures remain visible and are not PASS evidence:

- the first host test command selected machine-wide SDK 8.0.418 and stopped before compilation
  because `global.json` requires 10.0.302;
- the first combined container invocation timed out before returning test evidence; its exact
  transient container was verified absent before the bounded reruns;
- the first hosted FSE2 compile used incompatible enum assertions (`CS0411`/`CS1503`); the assertions
  were corrected and the complete hosted class then passed;
- a later `--no-restore` rerun found an absent `Humanizer.Core` cache entry, and a full-solution
  Linux restore stopped on Windows targeting (`NETSDK1100`); locked project restores recovered the
  targeted gates, while an isolated Windows SDK 10.0.302 ran the canonical full build;
- the Linux architecture run was 39/40 because one pre-existing test treats Windows backslashes in
  `ProjectReference` paths as native separators; the native Windows rerun passed 40/40;
- the first PostgreSQL harness assertion expected the wrong `0014` filename after the migration had
  run. No FSE2 test was claimed, the ephemeral container was removed, and the corrected gate was
  restarted from a new empty PostgreSQL 18 database.

These are harness/implementation findings, not rerun PASS records. Final exact-head local gates and
new CI run/job identifiers are appended only after they complete.

The content-commitment remediation tree then passed the following local gates with SDK 10.0.302:

- full Release restore/build, container-base validation and compilation: zero warnings/errors;
- complete CertificateSigning suite 100/100, including `JwtX509ExtensionSecurityTests` 22/22;
  the new named matrix proves NonRepudiation-only PASS only under `ContentCommitment`, legacy denial,
  DigitalSignature-only denial under `ContentCommitment`, absent-extension denial, `x5c: none`
  validation, legacy missing-extension compatibility and distinct policy digests;
- focused Gateway Published/expectation contract classes 42/42, including unchanged legacy
  canonical checksum, explicit-value checksum binding, unknown-value denial and typed expectation
  compatibility;
- FSE2 unit 43/43; hosted non-PostgreSQL profile/policy/path/race matrix 5/5; all 11 wire
  operations in the matrix with 22 signatures and 11 single transports;
- fresh PostgreSQL 18 migrations `0001` through `0014`, second apply no-op, locked FSE2 restore,
  Release build and canonical FSE2 test 1 passed / 0 skipped / 0 failed with
  `REQUIRE_FSE2_POSTGRES_GATE=1`; the dedicated container was removed;
- full architecture 40/40 on Windows; the complete ordinary solution command has zero failures.
  Its environment-gated PostgreSQL skips remain explicit and are not used as PostgreSQL evidence
  (Gateway 167 passed / 31 skipped; FSE2 hosted 5 passed / 1 skipped in that ordinary run).

Documentation, conservative secret scan, Gitleaks, vulnerability inventory, SBOM, Core export,
final clean-tree checks and exact-head CI are recorded after the focused remediation commits;
pre-commit artefacts do not qualify the final head.

Candidate `02c59240e226da484c48cd5c322f67d2574cc115` passed the exact-head local release
controls: Gitleaks 8.28.0 scanned 328 commits with no leaks; the complete container SBOM manifest
names that exact SHA and indexes 165 container packages; and the verified Core export contains 430
allowlisted files with no Healthcare or ConnectorPacks path. PR #32 then passed exact-candidate
General run
[`31600436413`](https://github.com/marcobiz/secure-integration-platform/actions/runs/31600436413)
6/6 and M5/Admin run
[`31600436429`](https://github.com/marcobiz/secure-integration-platform/actions/runs/31600436429)
15/15. General includes the canonical PostgreSQL 18 FSE2 FQN with zero skip. This concluding report
update is documentation-only; PR checks must and do re-evaluate every subsequent head before
handoff. An independent Core certificate-signing security review, limited to the new Key Usage
criterion and explicitly excluding a general product/vertical review, is requested in the PR body.

## Historical local qualification before the temporal remediation

The following results belong to predecessor candidate `45548c13df5d46cdb5f9cba1d101ee08619ef15b`.
They remain visible as historical evidence but do not qualify the temporal-remediation exact HEAD.
The replacement PR and final writer handoff record the newly executed exact-head gates.

Two historical harness invocation failures remain recorded and are not PASS evidence: a bare
`npm run test:e2e` was started without the required Gateway full-stack service and failed with
`ECONNREFUSED ::1:8443`; an initial PostgreSQL gate command selected the machine-wide .NET 8 SDK
instead of repository-pinned SDK 10.0.302 and stopped before any product test ran. The later
canonical full-stack and pinned-SDK executions do not erase or reclassify those failures.

- FSE2 public-contract unit suite: 33/33 PASS;
- Healthcare architecture slice: 8/8 PASS, including one `Gateway.Application` reference and no IVT;
- hosted FSE2 in-memory success/negatives and A→B race: 2/2 PASS;
- hosted FSE2 PostgreSQL 18 canonical test: 1/1 PASS on an ephemeral `postgres:18` container;
- migration `0001` through `0013`, including authorized signing slots: PASS; container removed;
- pack and hosted integration build: zero warnings/errors.

- full `BrokerGateway.slnx` Release build and ordinary test gate: 599 PASS, 31 explicit
  environment-gated skips and zero failures, with zero build warnings/errors;
- authorized signing-slot focused regression: 8/8 PASS; complete certificate-signing suite:
  93/93 PASS; hosted capability/execution regression: 5/5 PASS with its PostgreSQL-only case
  explicitly skipped in the ordinary run;
- Admin Web lint, generated OpenAPI diff, 28/28 Vitest, production build and npm high-severity
  audit: PASS; `FULLSTACK-01` 1/1 PASS with production images, redaction and Docker cleanup;
- documentation validation, conservative secret scan, NuGet vulnerability scan and
  `git diff --check`: PASS;
- full SPDX generation, including the indexed Gateway container, validation and SBOM-mode
  regression: PASS;
- verified Core export: PASS for 418 allowlisted files, including its clean restore, Release build,
  Core tests, Admin build and frontend-license scan; an independent inventory check found no
  Healthcare or ConnectorPacks path;
- deterministic M3 split-network, split-firewall and operator-handoff regressions: PASS.

## Pre-remediation canonical PostgreSQL CI qualification

The predecessor connector/CI candidate exact head `c450d7133436a6f7a3a83dcb5c35f594dcadf7b6` qualified on
2026-08-11 without rerun. General run
[`31495813159`](https://github.com/marcobiz/secure-integration-platform/actions/runs/31495813159)
passed 6/6 and M5/Admin run
[`31495813186`](https://github.com/marcobiz/secure-integration-platform/actions/runs/31495813186)
passed 15/15. In General job
[`gateway-postgresql-18` (`93793113966`)](https://github.com/marcobiz/secure-integration-platform/actions/runs/31495813159/job/93793113966),
the log identifies that exact SHA, restores the FSE2 integration project in locked mode, builds it
in Release, and runs the exact PostgreSQL FSE2 FQN with `REQUIRE_FSE2_POSTGRES_GATE=1` before the
always-run cleanup. The explicit result is `Healthcare.FSE2.Integration.Tests.dll`: Failed 0,
Passed 1, Skipped 0, Total 1.

The historical harness invocation failures above remain failures and are not evidence for the new
remediation head. This older run does not qualify the current delta. This report does not claim an
official FSE endpoint call or accreditation.

## Readiness boundary

- `ORGANIZATION_PROFILE = SYNTHETIC_SOFTWARE_COMPATIBILITY_PASS_REVIEW_PENDING`;
- `HUMAN_ACTOR_PROFILE = DEFERRED`;
- `NEW_CORE_PRIMITIVE_REQUIRED = YES`;
- `OFFLINE_CERTIFICATE_CORRELATION_AND_TRUST = PREVIOUSLY_VERIFIED_OUTSIDE_REPOSITORY_NOT_REEXECUTED`;
- `OPERATIONAL_CERTIFICATE_IMPORT = NOT_PERFORMED`;
- `LIVE_FSE2_QUALIFICATION = BLOCKED_NOT_EXECUTED`;
- `ACCREDITED_PRODUCTION_READY = false`.

The PASS in this report is software compatibility using runtime-only synthetic material. The
previous offline certificate correlation/trust result remains external, redacted evidence and was
not opened or reproduced for this change. No real PEM, CSR, certificate, private key or P12 was
accessed or created; no certificate was imported; and no FSE2 endpoint was called. Official
provisioning, production certificate custody, approved policy values, conformance, accreditation,
monitoring and live evidence remain required before production readiness.

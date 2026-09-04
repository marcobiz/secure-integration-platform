# Implementation plan

Updated: 2026-08-24
Recorded planning baseline: `97daa565f582d575da5d61665126c50ea52be3ed`

The status tables and gate outcomes below are planning snapshots, not current
qualification claims. In particular, the earlier 11-operation/no-live FSE2 snapshot
is superseded by the integrated PR #65 status and
[current pilot](../user/fse2-validation-status.md). Gate criteria remain references;
this note does not attest new gate outcomes or authorize publication.

Current summary status is in
[`IMPLEMENTATION_STATUS.md`](../../IMPLEMENTATION_STATUS.md), gates in
[`0.1.0-alpha-scope.md`](0.1.0-alpha-scope.md) and ordered slices in the
[`backlog`](backlog.md). Detailed history remains in the existing tags and reports.

## Planning principles

- a capability is CURRENT only when integrated into `main`; a release or external
  qualification also requires its own exact-head gate;
- synthetic, live lab, official-test and production are distinct states;
- optional packs depend on Core contracts; Core does not depend on cloud or
  vertical packs;
- no generic capability enters this phase without a reproducible Core golden-path
  or FSE2 gate blocker;
- a maintainer statement does not become repository evidence;
- attested baselines are not rewritten;
- there are only two active tracks: Core alpha and FSE2 Organization OfficialTest.

## Recorded baseline

| Area | Status | Current limitation |
|---|---|---|
| M0-M2 | Done | Foundations, Broker and Gateway integrated; historical live gates are not an installer release. |
| M3A | PASS live lab | M3B Azure remains unqualified. |
| M4/M5/M5.5 | Done | Connector lifecycle, Admin and Direct Gateway integrated; Direct sample key storage remains non-production. |
| Authentication foundation / Wave 1 | Integrated | Provider-neutral primitives and external modules do not automatically qualify an external service. |
| FSE2 Organization | Synthetic-qualified | 11 operations, dual JWT, S1 `contentCommitment`, distinct A1 mTLS and canonical PostgreSQL; no live calls. |
| Local PKCS12 / FSE2 vertical image | Integrated by PR #33, synthetic lab qualified | Optional `SecretValues=false` provider, offline importer, overlay and vertical image; custody and OfficialTest open. |
| Productization alpha | Governance candidate | Version/artifacts and golden path are candidates; ALPHA-LIC/SEC/DOC-04 are implemented on the branch but await review/integration. ALPHA-REL is not closed. |
| Legacy/enterprise | Deferred | MSI, native/COM, live cloud, HA/DR and production are not active tracks. |

PR #33 was merged by fast-forward onto exact main. General 6/6, M5/Admin 15/15,
PostgreSQL FSE2 1/1 zero skips, provider 30/30, architecture 42/42, provider-active
synthetic lab and security micro-review are PASS/GO within the attested scope. These gates
do not include real material, operational import or FSE2 calls.

## Track A — Core `0.1.0-alpha`

### Outcome

A non-production, provider-neutral developer alpha with one golden path:

```text
Direct .NET
→ Gateway
→ Connector REST Published
→ Synthetic Provider
→ mock HTTPS/mTLS
→ sanitized response and metadata-only audit
```

### Dependencies and parallel work

DOC-01 is the only initial common prerequisite. After DOC-01, these proceed in parallel:

- **Core documentation:** DOC-02 for architecture/security/deployment and DOC-03 for
  OpenAPI/API/generated types;
- **Core consumption:** ALPHA-REST, ALPHA-DIRECT and ALPHA-CLEAN;
- **productization:** ALPHA-VER may start without waiting for DOC-02/03; ALPHA-ART follows
  ALPHA-VER;
- **governance:** human decisions ALPHA-LIC and ALPHA-SEC are implemented in the ALPHA-GOV-REL slice and remain pending independent review/integration;
- **FSE2 documentation:** DOC-04 aligns the optional pack with the state integrated by
  PR #33, without executing or requiring FSE2-T01..T06.

ALPHA-ADOPT starts when the golden path is documented and repeatable: it requires
ALPHA-REST, ALPHA-DIRECT, ALPHA-CLEAN and applicable Core documentation DOC-02/03.

ALPHA-REL is the final step and explicitly requires ALPHA-DOC-01, ALPHA-DOC-02,
ALPHA-DOC-03, ALPHA-DOC-04, ALPHA-REST, ALPHA-DIRECT, ALPHA-CLEAN, ALPHA-ADOPT,
ALPHA-VER, ALPHA-ART, ALPHA-LIC and ALPHA-SEC, plus green ALPHA-01..08 on the exact
release candidate. ALPHA-DOC-04 is a documentation-truth dependency only: it does not
require live `validate-cda` or FSE2-T01..T06. FSE2 OfficialTest qualification does not block
the Core alpha release.

### Constraints

- FSE2 and vendor-specific packs do not enter the Core golden path;
- MSI, COM/C ABI, Azure live, HA/DR and stable API compatibility remain excluded;
- the raw Core export SHA is evidence for a single run. `ALPHA-ART` adds a normalized
  inventory digest because `generatedAtUtc` makes the raw manifest run-specific;
- no publication precedes independent review, integration and the ALPHA-LIC and ALPHA-SEC publication gate.

## Track B — FSE2 Organization OfficialTest

### Outcome

The first outcome is `validate-cda` in the official test environment, with an authorized
synthetic dataset, exact configuration and redacted evidence. Attachment hash, create/replace and
status follow; they are not `validate-cda` prerequisites without new official evidence.

### Integrated CURRENT

- optional Local PKCS12 pack, without generic secret retrieval and with
  `SecretValues=false`/deny-only slot;
- offline importer and synthetic path/CSR/ACL/custody guards;
- vertical image including `Healthcare.FSE2`, while the default Gateway Core
  image continues to exclude it;
- Compose overlay and provider-active synthetic lab;
- S1 `contentCommitment`, distinct A1 mTLS, CI and review within the synthetic scope.

### TARGET still open

- operational access/import and verification of real custody;
- verified distinction between test access and software accreditation;
- any `ActivationHmacSecretReference` composed as a separate server-owned
  capability, never as generic secret retrieval by the certificate pack;
- bounded warning mapping for `validate-cda`;
- exact OfficialTest image/configuration and redacted operational driver;
- any live FSE2, `validate-cda`, create/replace or status call.

### Candidate operationalization slice

The `FSE2-OFFICIALTEST-OPERATIONALIZATION` slice, still subject to exact-head gate and review, fixes
the canonical source for `validate-cda` only, the closed external plan, A1 mTLS/S1 authorization+integrity,
the zero-effect dry run and the Admin configure/propose/approve/publish/read-back workflow. It does not
import operational material, add Core primitives or make a live call. Its
authority uses exact server-side A1/S1 lookups, an authenticated publisher identical to the exact approver and
URI composition that preserves the OfficialTest prefix without accepting caller overrides.
Integration closes only the software tooling in step 6; steps 1-5 and 7-8 remain separate
operational gates.

### Sequence

1. external intake: distinguish test access and software accreditation;
2. import/custody preflight outside Git;
3. composition of required server-owned capabilities;
4. public metadata, chain, S1 signing and A1 mTLS preflight without FSE2 network access;
5. bounded warning mapping required for `validate-cda`;
6. vertical image and exact OfficialTest configuration;
7. synthetic E2E from the same image/configuration;
8. `validate-cda` OfficialTest with an authorized synthetic dataset;
9. `attachment_hash` over exact file bytes;
10. authorized create/replace;
11. bounded/redacted status;
12. subsequent workflows only if included in the plan.

### Gates and claims

FSE2-T01..T04 and T06 enable only the `validate-cda` official-test claim on the exact
attested configuration. FSE2-T05 enables only subsequent workflows actually
executed. Synthetic tests of the 11 operations do not become an 11/11 live claim. No
gate in this track implies production.

## Relationship between tracks

```text
DOC-01
  ├─→ ALPHA-DOC-02 ───────────────────────────────────┐
  ├─→ ALPHA-DOC-03 ───────────────────────────────────┤
  ├─→ ALPHA-REST ─────────────────────────────────────┤
  ├─→ ALPHA-DIRECT ───────────────────────────────────┼─→ ALPHA-ADOPT ───────┐
  ├─→ ALPHA-CLEAN ────────────────────────────────────┘                       │
  ├─→ ALPHA-VER ─→ ALPHA-ART ────────────────────────────────────────────────┤
  ├─→ ALPHA-LIC + ALPHA-SEC ─────────────────────────────────────────────────┤
  └─→ ALPHA-DOC-04 (truth only; no validate-cda/FSE2 gates) ──────────────────┘
                                                                                └─→ ALPHA-REL + ALPHA-01..08

Independent Track B: intake/custody/composition → offline preflight → exact synthetic E2E
                                                → validate-cda → hash/create/status
```

The two tracks can advance independently. An FSE2 problem does not block Core alpha
unless it demonstrates a general security defect. A new Core abstraction requires
a concrete blocker and test. DOC-04 does not convert FSE2 gates into Core gates: it only
keeps the optional pack documentation truthful.

## HISTORICAL and deferred work

The original roadmap used M0-M9. The M6/M7 names are ambiguous because the authentication
foundation was brought forward ahead of legacy adapters. Historical tags and reports remain
immutable, but new work and statuses use ALPHA/FSE2 IDs.

Legacy beta, other providers, other verticals and enterprise/production remain deferred
backlog, not active tracks. This plan neither estimates nor starts them.

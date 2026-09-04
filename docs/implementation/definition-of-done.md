# Definition of Done

Updated: 2026-08-13

The DoD is proportional to scope and evidence class. A developer alpha or
synthetic gate cannot be presented as official-test or production.

## Change/Story DoD

A story is Done only when:

- the requested behavior and relevant negative cases are implemented;
- builds and named tests for the changed surface pass;
- authorization, provider and Core/pack boundaries remain fail-closed;
- when a change introduces or alters a durable architectural decision, the relevant
  ADR is added or updated; an ADR is not required for every change;
- when the threat surface, a trust boundary, a sensitive capability or a security
  mitigation changes, the threat model is updated and security-sensitive changes
  retain proportionate positive and negative tests;
- migrations, OpenAPI, generated clients, schemas and examples are synchronized where
  applicable;
- logs, Problem Details, audit and evidence are checked for the absence of secrets, tokens,
  cookies, authorization headers, sensitive payloads and stack traces;
- documentation and traceability distinguish CURRENT, TARGET and HISTORICAL and do not
  overstate live testing or conformance;
- affected requirements, named tests and evidence are linked in requirements
  traceability, distinguishing automated PASS, external evidence, manual verification,
  deferred, blocked and unverified;
- missing tests or evidence are not converted into PASS through documentation or
  aggregate counts;
- proportionate secret/dependency/artifact checks pass;
- fixtures and raw evidence remain synthetic and outside Git;
- residual risk, deferred work and compatibility impact are explicit;
- proportionate technical/security review is recorded when the risk or gate
  requires it.

An integrated story is not automatically a publishable product.
ADRs, threat model and traceability are updated where applicable; a decision not to
update them must be consistent with the actual changed surface. A documentation-only
change that does not alter decisions, threats or capabilities does not, by that fact
alone, require a full security review.

## Documentation DoD

- every claim can be classified as **CURRENT**, **TARGET** or **HISTORICAL**;
- every qualification is explicitly **synthetic**, **live lab**, **official-test** or
  **production**;
- dashboards and roadmaps do not duplicate complete branch or PR histories;
- relative links and gate references are valid;
- aggregate counts are not the only evidence;
- maintainer input is not transformed into repository evidence;
- machine-readable API documents, guides and parity tests evolve in the same change set
  when the API surface changes;
- `validate-docs`, secret scan and `git diff --check` pass;
- General and M5/Admin CI pass on the final exact HEAD before PR handoff.

## DOC-01 DoD

The ALPHA-DOC-01 slice is Done only if it:

- starts from exact main `eec2fa5556eccc7e8e3b47fc7d7b127bcac1ed9e`;
- preserves the local dirty truth source unchanged and semantically reconciles
  the pre-PR #33 baseline, dirty truth pass and integrated result;
- changes only the authorized dashboard, scope, plan, backlog and DoD;
- records PR #33 as integrated and synthetic-qualified without claiming custody or live
  calls;
- defines only Track A Core alpha and Track B FSE2 Organization OfficialTest;
- records `P3-CORE-EXPORT-DIGEST` as a future ALPHA-ART outcome, separating the raw
  run-specific manifest and normalized inventory digest;
- retains `SecretValues=false` and deny-only generic secret retrieval for Local PKCS12;
- leaves architecture/security/deployment, API/generated types and detailed FSE2
  documentation to DOC-02/03/04;
- passes documentation-only gates and exact-head CI without changing source code or Core
  export.

## `0.1.0-alpha` DoD

ALPHA-01..08 in
[`0.1.0-alpha-scope.md`](0.1.0-alpha-scope.md) apply. In summary:

- common version `0.1.0-alpha.1`, future exact-commit tag and consistent artifacts/checksums/SPDX;
- approved OSS license and operational minimum security/governance channels;
- reproducible clean clone and quickstart;
- one supported golden path: Direct .NET → Gateway → REST Connector Published →
  Synthetic Provider → mock HTTPS/mTLS → sanitized response and metadata-only audit;
- configuration/enrollment/publish/grant/invoke documented and tested by a second
  user;
- explicit non-production and sample key-storage limitations;
- Core, Admin, PostgreSQL 18, container/export, scan and cleanup gates green on the exact
  release commit;
- Core export with the raw run-specific manifest and reproducible normalized
  inventory digest as separate artifacts.

MSI, C ABI/COM, fuzzing, performance, Azure live, FSE2, HA/DR and API stability do not
block the alpha because they are out of scope; they cannot be claimed as included.

## FSE2 OfficialTest DoD

There are two claim levels, both configuration-specific.

### First outcome: `validate-cda`

Requires FSE2-T01..T04 and T06:

- test access, applicable software accreditation and the authorized plan are separate and
  verified outside Git;
- custody/import and server-owned composition prove S1 `contentCommitment`, public chain,
  distinct A1 mTLS and any separate activation HMAC;
- the exact vertical image/configuration completes synthetic E2E and zero-network negatives;
- warning mapping is bounded and retains no raw text;
- `validate-cda` OfficialTest completes on an authorized synthetic dataset;
- exact commit/image/Connector/binding/provider revision and redacted evidence are
  attested.

The permitted claim is: **qualified for `validate-cda` in the official FSE2 test environment
on the attested configuration**. It does not imply create/status, 11/11 live, production or
Human Actor.

### Subsequent outcome: create/status

Also requires FSE2-T05:

- `attachment_hash` is SHA-256 of the exact input-file bytes, not the HTTP multipart;
- create/replace are authorized by the plan;
- status exposes only bounded/redacted technical outcomes;
- process-local/cross-restart limitations are explicit;
- cleanup and evidence remain compliant with FSE2-T06.

Only the specific attested workflows may be claimed as official-test qualified.
Synthetic tests of the 11 operations do not authorize an 11/11 live claim.

## Legacy and production DoD

These tracks are deferred and not active. If authorized in future, they add
installer/native tests on real hosts, real providers/cloud, artifact signing/provenance,
backup/restore, HA/DR, rotation/recovery, load/soak, fuzzing, pentest, observability,
support ownership, pilot and acceptance/risk sign-off. None of these properties
can be inferred from the alpha or OfficialTest.

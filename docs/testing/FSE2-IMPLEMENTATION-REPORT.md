# FSE2 National Connector organization profile — implementation report

Date: 2026-08-09

Starting HEAD: `298e76163143f339d14b88308c3b4ca609036b2f`

Branch/PR: `wave1/fse2-national` / #16

Official public freeze: guide 2.23 and OpenAPI 1.0.0 at
`430e6b5d9dde8a35b04ae635c11303db787a977e`.

## Implemented result

The independent gate decision `RESUME_FSE2_WITH_EXISTING_CORE` is implemented only for the
server-owned organization profile. The profile's approved P.IVA is canonicalized into CX,
bound to the exact Published authority and checksum, and signed as fixed `sub`. Changing
the organization identity requires a different checksum/revision.

The pack implements the frozen eleven-operation inventory, while rejecting both official
test-only operations in Production and leaving direct FHIR create/replace plus inbound
callback surfaces unavailable. DAP/purpose/action combinations are explicit and fail
closed. `person_id` remains clinical/business identity; `use_subject_as_author` is omitted.

Two fresh RS256 JWTs are composed per call with leaf `x5c`, issuer prefix plus CN from the
verified exact signing DER, fixed audience and `iat+exp` without `nbf`. A distinct
purpose-bound client certificate is used for mTLS. The document hash is lowercase SHA-256
over the exact input bytes. Workflow/trace status uses only stored technical security
context; only those two operations are safe-retry. Responses and RFC7807 errors retain
bounded allowlisted technical fields and stable codes only.

## Synthetic evidence

The test server uses per-run CA, HTTPS server, signing and mTLS certificates. It requires
the expected client certificate and cryptographically verifies both JWT signatures,
standard-Base64 leaf x5c, issuer, organization subject, audience, temporal profile,
role/purpose/action, CX/XON and exact uploaded-file hash. CI performs no official FSE call.

Named negative coverage includes caller authority-surface inspection, wrong organization
profile/checksum, wrong grant, wrong role/purpose/action, missing JWT 1/2, wrong x5c,
substituted signing identity, signing/mTLS cross-use, wrong issuer/audience, unexpected
`nbf`, expired token, malformed CX, wrong hash, stale/rotated/disabled profile or resource,
wrong endpoint, bounded timeout and RFC7807 canary redaction. Early policy failures assert
zero resource/provider, DNS or network access at the applicable boundary.

## Readiness boundary

- `ORGANIZATION_PROFILE = IMPLEMENTATION_READY`, subject to exact-head CI and independent review;
- `HUMAN_ACTOR_PROFILE = DEFERRED_PENDING_TRUSTED_ACTOR_SOURCE`;
- `ACCREDITED_PRODUCTION_READY = false`.

Official provisioning, production certificate custody, approved deployment lifetime/skew,
official conformance/accreditation, operational monitoring and live evidence remain
required before any production-readiness claim.

## Local qualification candidate

The local product candidate completed:

- full Release restore/build: PASS, 38 projects, zero warnings/errors;
- FSE2 pack: 46/46 PASS, including real HTTPS/mTLS, dual JWT/x5c, negative matrix,
  workflow, timeout, rotation/disable and redaction;
- ordinary .NET solution: 442 PASS, 11 PostgreSQL-conditional SKIP, zero failures;
- architecture: 26/26 PASS, including seven Healthcare boundary tests;
- certificate-signing/X.509 regression: 91/91 PASS;
- documentation validation and conservative secret scan: PASS;
- Gitleaks 8.30.0 on the complete FSE2 commit range: PASS;
- transitive NuGet vulnerability audit: no vulnerable packages reported;
- Windows SBOM generation/validation with explicit `-SkipContainer` and the SBOM
  fail-closed mode regression: PASS;
- open-source Core export: PASS, 371 files, Healthcare excluded, internal secret scan,
  Release build/test and Admin frontend 28/28 PASS.

Docker Desktop was unavailable locally. Therefore the PostgreSQL 18 conditional tests and
container SBOM were not executed locally; the ordinary suite reported the 11 skips, and the
first full SBOM attempt failed visibly at Docker daemon connection before the explicit
Windows-mode rerun passed. No database, migration, Admin Web or container surface changed
in this PR. The exact-head CI PostgreSQL/Gitleaks/SBOM results remain mandatory and are
recorded after push; this report does not convert the local skips into PASS.

Exact-head CI, final SHA, PR check state and clean-worktree result are recorded in the
final PR handoff after push, so this committed report does not contain a self-referential SHA.

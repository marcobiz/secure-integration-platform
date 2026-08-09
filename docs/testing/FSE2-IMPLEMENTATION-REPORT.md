# FSE2 National Connector organization profile — implementation report

Date: 2026-08-09

Starting HEAD: `298e76163143f339d14b88308c3b4ca609036b2f`

Independent-review remediation baseline: `702642f8254f34a8e34879ba052689eb7c67e077`

Branch/PR: `wave1/fse2-national` / #16

Official public freeze: guide 2.23 and OpenAPI 1.0.0 at
`430e6b5d9dde8a35b04ae635c11303db787a977e`.

## Implemented result

The independent gate decision `RESUME_FSE2_WITH_EXISTING_CORE` is implemented only for the
server-owned organization profile. The profile's approved P.IVA is canonicalized into CX,
bound to the exact Published authority and checksum, and signed as fixed `sub`. Changing
the organization identity requires a different checksum/revision.

The targeted remediation replaces caller-constructible profile attestation with
`PublishedConnectorFse2ProfileResolver`: the production path reads the real Connector store with
the authenticated access context, validates the exact Published version/operation/canonical
checksum and active binding/resource stamps, and requires a current exact-checksum/exact-binding-
digest four-eyes record with distinct requester/approver principals. The resolved profile and
dispatch authority have no public construction path.

The pack implements the frozen eleven-operation inventory, while rejecting both official
test-only operations in Production and leaving direct FHIR create/replace plus inbound
callback surfaces unavailable. DAP/purpose/action combinations are explicit and fail
closed. `person_id` remains clinical/business identity; `use_subject_as_author` is omitted.

Two fresh RS256 JWTs are composed per call with leaf `x5c`, issuer prefix plus the exactly-one
OID `2.5.4.3` CN parsed from Subject DER, fixed audience and `iat+exp` without `nbf`. A distinct
purpose-bound client certificate is used for mTLS. Signing and mTLS bindings carry their actual
Published logical ID, protected provider reference, catalog and binding revisions/checksums,
fingerprint, SPKI and version. Both JWTs, both resources, organization subject and endpoint are
held by one `Fse2DispatchLease`; after mTLS material/DNS resolution the final transport re-reads
the complete authority, then projects the JWT headers synchronously and sends.

The document hash is lowercase SHA-256 over the same private invocation-entry byte snapshot sent
on wire. Workflow/trace persistence uses a full tenant/application/installation/environment/
ConnectorVersion/profile revision+checksum key and technical identifiers only; patient claims and
document bodies are not persisted. Only the two status operations are safe-retry. Responses and
RFC7807 errors retain bounded allowlisted technical fields and stable codes only.

## Synthetic evidence

The test server uses per-run CA, HTTPS server, signing and mTLS certificates. It requires
the expected client certificate and cryptographically verifies both JWT signatures,
standard-Base64 leaf x5c, issuer, organization subject, audience, temporal profile,
role/purpose/action, CX/XON and exact uploaded-file hash. CI performs no official FSE call.

`CONNECTOR_SECURITY_PATH` evidence crosses the production Published resolver, connector, generic
signing/mTLS and final restricted transport. It covers wrong grant, invalidated four-eyes approval,
business person/organization separation, stable signing and mTLS substitutions, purpose cross-use,
attacker endpoint, Production use of a test-only operation, four deterministic final races
(signing, mTLS, organization profile and endpoint), workflow cross-context reuse and payload
mutation during signing. Pre-dispatch denials assert network zero and pre-signing denials also
assert provider zero. `SERVER_VALIDATION_TEST` cases for malformed/missing JWT headers are kept
separate and are not counted as connector-authority evidence.

Unit evidence additionally covers truly frozen catalog collections, canonical ASN.1 OID arc rules,
and DER X.500 CN absence/duplicates/multi-valued RDN/empty/malformed/SAN-only behavior.

## Readiness boundary

- `ORGANIZATION_PROFILE = READY_FOR_TARGETED_REREVIEW`, subject to exact-head CI and that review;
- `HUMAN_ACTOR_PROFILE = DEFERRED_PENDING_TRUSTED_ACTOR_SOURCE`;
- `ACCREDITED_PRODUCTION_READY = false`.

Official provisioning, production certificate custody, approved deployment lifetime/skew,
official conformance/accreditation, operational monitoring and live evidence remain
required before any production-readiness claim.

## Local qualification candidate

The local product candidate completed:

- full Release restore/build: PASS, 38 projects, zero warnings/errors;
- FSE2 pack remediation candidate: 50/50 PASS, including real Published resolver, HTTPS/mTLS,
  production-path negatives, final TCS races, workflow authority, immutable payload/catalog,
  exact CN, semantic OID and separately labelled server validation;
- ordinary .NET solution: 446 PASS, 11 PostgreSQL-conditional SKIP, zero failures;
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

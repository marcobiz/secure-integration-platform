# FSE2 OfficialTest pilot — historical validate-only profile

For the new current-spec path limited to VERIFICA and lookup, see
[FSE2 Organization: validation and status](fse2-validation-status.md). This guide
preserves the context of the previous validate-cda 1.0.1 profile.

**Audience:** organizations authorized to use the OfficialTest environment.
**Status:** HISTORICAL for first adoption; reference only for
`fse2-officialtest-validate-cda@1.0.1` / `validate-cda` and the shared provisioner.
**Historical claim:** `validate-cda` LIVE_QUALIFIED on its own exact baseline.
The bootstrap/session/runner gaps below concern this earlier path, not the
[current pilot](fse2-validation-status.md). The
[capability status](../../IMPLEMENTATION_STATUS.md#product-status) distinguishes the profiles.

This guide puts steps in their actual order and identifies where the product stops.
It does not authorize new live calls, create accounts or A1/S1 material, or qualify
production or accreditation.

## CDA validation and publication eligibility

OfficialTest operations serve different purposes:

- `VERIFICA` checks the CDA but does not make it eligible for publication;
- `VALIDATION` is the validation required before publication and must return the
  `workflowInstanceId` to use in the next step;
- `validate-and-create` combines validation and publication in one operation.

The test certificates and accreditation used for validation do not automatically
guarantee admission to publication operations. Final production accreditation is
not necessarily required to try them in the test environment; however, specific
OfficialTest enablement may be needed for `VALIDATION`, `create` and
`validate-and-create`.

If `VERIFICA` returns HTTP 200 but both the separate publication path and
`validate-and-create`, built in conformance with the contract, receive HTTP 404,
classify the case as a possible admission/routing anomaly and request confirmation
from Sogei/the Ministry. If a `create` outcome is ambiguous, reconcile through
workflow, trace or status first: do not blindly repeat `create`.

Official references:

- [FSE 2.0 accreditation process](https://github.com/ministero-salute/it-fse-support/blob/main/doc/accreditamento/README.md)
- [FSE Gateway integration](https://github.com/ministero-salute/it-fse-support/blob/main/doc/integrazione-gateway/README.md)

## Before starting: outcome and hard stops

The available pilot checks CDA quality with one `validate-cda`. It does not publish
a document. `create + get-status-by-workflow` are offline-qualified on the product
path with durable PostgreSQL correlation, but are not included in the canonical
OfficialTest definition or in live qualification.

Stop if any of the following is missing:

- organization-authorized OfficialTest access and a one-call budget;
- a synthetic CDA dataset approved for use in the test;
- exact FSE2 vertical-image deployment, allowlisted module and current PostgreSQL 18 migrations;
- Tenant, Application, OfficialTest Environment and an active Direct Installation,
  derived and verified server-side;
- distinct active A1 and S1 resources scoped to the Connector/operation, with custody
  and public metadata managed by the authorized provider;
- three separate Admin sessions: Security Administrator, Connector Editor and a
  distinct Connector Approver;
- Gateway HTTPS and, if needed, only a pinned public DER CA;
- a protected operational plan outside Git, conforming to the
  [closed schema](../connectors/healthcare/fse2/fse2-officialtest-operational-plan.schema.json).

For this historical path, the repository did not yet offer a supported workflow to
create a real FSE2 deployment from scratch, import operational provider material,
create/assign principals or acquire the three sessions. These were explicit external
prerequisites. The Local PKCS#12 laboratory uses synthetic material and does not
replace OfficialTest custody or import.

## Plan boundary

The plan contains Tenant/Installation selectors, an Environment assertion,
organization/locality identity and public A1/S1 references with expected revisions.
It contains no P12 files or paths, passwords, private keys, tokens, Authorization
headers, cookies, principal identities or client-selected runtime authority.

Use a protected absolute path outside the repository:

```powershell
$protectedPlan = '<protected-absolute-path-outside-repository>'
```

## 1. Plan — no effects

From the exact product HEAD:

```powershell
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- plan $protectedPlan
```

`plan` runs before the Admin client is constructed and prints only fixed identities
and redacted digests. A plan result does not prove that declared IDs are authoritative:
`configure` must resolve the authenticated Installation and derive its Environment.
Any `FSE2_OFFICIALTEST_*` code is a hard stop.

## 2. Apply — Security Administrator

In a process dedicated to the Security Administrator session, set these without
using the command line or plan:

```powershell
$env:FSE2_GATEWAY_URL = 'https://<admin-gateway>'
$env:FSE2_ADMIN_SESSION_COOKIE = '<protected-session-cookie>'
$env:FSE2_GATEWAY_CA_FILE = '<optional-public-der-ca>'
```

The deployment's authentication mechanism must supply the session; this repository
does not document a generic way to extract or copy it. Run:

```powershell
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- configure $protectedPlan
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- grant $protectedPlan
```

`configure` validates/imports the canonical definition, validates persisted state
and applies the exact binding. `grant` creates or verifies the
Installation/Connector/`validate-cda` grant. Both reconstruct state through Admin
APIs and skip only phases already persisted with identical state.

## 3. Apply — Connector Editor

Remove the Security Administrator session from the process. In a separate Connector
Editor session:

```powershell
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- plan $protectedPlan
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- propose $protectedPlan
```

Retain only the approval request ID, approval digest and returned redacted
checksums/digests for the role handoff. Do not retain compiled definitions,
Admin responses, cookies or provider metadata.

## 4. Apply — distinct approver and publication

Remove the editor session. In a new process authenticated as a distinct Connector
Approver, repeat `plan`, compare the handoff digests, then use the redacted values
returned by `propose`:

```powershell
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- approve $protectedPlan <approval-request-id> <approval-digest-sha256>
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- publish $protectedPlan <expected-publication-revision>
```

Self-approval, checksum/revision drift, binding/provider drift or a publisher other
than the exact approver fail closed. Do not change the plan or version to bypass the error.

## 5. Verify

In the same approver session:

```powershell
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- verify $protectedPlan
```

Proceed only if read-back is `Published/Active`, version is `1.0.1`, there is exactly
one `validate-cda` operation, A1 is the mTLS certificate, S1 feeds both JWT slots,
there are no ordinary secret bindings and all digests/revisions match.

## 6. Invocation — historical self-service blocker

The baseline has redacted live qualification: one application `validate-cda` request
crossed the Gateway to OfficialTest and received Gateway 200, with one dispatch,
zero retries and zero redirects. This qualifies the capability on the attested
configuration; it does not make the pilot reproducible for a new adopter.

This historical path did not ship an adopter-facing runner that:

1. uses an already-enrolled Installation and the exact grant;
2. obtains authorized synthetic CDA input without depending on Git fixtures/tests;
3. constructs the expected public FSE2 payload;
4. checks clock, one-call budget and Published read-back;
5. performs one invocation and produces a redacted result/audit;
6. can safely resume after publication but before the call.

Consequently, the supported path ended at `verify` for an independent adopter.
Do not use integration tests, M3 fixtures, Git objects, hand-reconstructed payloads
or endpoints read from evidence as an operational runner. The next product slice
was required to deliver that runner/guided workflow and close the black-box
**time to first successful call** gate. Only an already-authorized owner of the
external runner used for qualification could make a new call, with new live authorization.
The [current pilot](fse2-validation-status.md) supersedes this adoption blocker.

## Resume, errors and cleanup

- A 429 does not trigger automatic retries. Respect any bounded `Retry-After`
  and repeat the same command with the same plan/session; the result reports
  `currentState`, `nextRequiredPhase` and `retrySafe`.
- Installation, Environment, binding, provider or approval drift requires
  reconciliation of server-side authority, not SQL, force flags or in-place edits.
- A Published version is immutable. Decommissioning uses retire; rollback reactivates
  only an already-published Superseded version.
- Do not delete volumes or provider material to “start again”. A configuration
  Published in the wrong Environment requires a new supported clean state and
  preserves the previous configuration as historical evidence.

The code → action table is in [troubleshooting.md](troubleshooting.md). The profile's
technical reference is the [FSE2 README](../connectors/healthcare/fse2/README.md).

## Future success criterion recorded for this path

With external prerequisites already available, a person without repository knowledge
must reach a sanitized, auditable `validate-cda` without SQL, store access, copied
cookies, invented sequences or routine support. Time, steps and recovery must be
measured black-box; the live qualification already obtained does not replace this
adoption test.

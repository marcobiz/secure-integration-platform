# FSE2 OfficialTest `validate-cda` operationalization

## Purpose and hard stop

This runbook configures and publishes only `fse2-officialtest-validate-cda@1.0.1` through the
existing authenticated Admin API. It does not invoke the Connector and does not authorize a live
FSE2 call. Production, accreditation, create/replace/status/delete and provider-material creation
are outside this procedure.

Version `1.0.1` is the immutable contract-parity successor to the historical Published `1.0.0`.
It must be imported, validated, approved and published as a new Connector Version through this
supported lifecycle; an existing Published version must never be edited in place. Both JWT slots
emit `x5c` with exactly the S1 leaf certificate, and the `VERIFICA` request body contains only
`healthDataFormat=CDA` and `activity=VERIFICA` (no `mode` and no `attachment_hash`). This offline
contract correction does not establish that an upstream HTTP 401 or 403 is resolved.

The parity behavior is selected only from the exact server-owned Published identity:
`fse2-officialtest-validate-cda@1.0.1`, Environment `OfficialTest`, operation `validate-cda`.
Published `1.0.0` remains historical compatibility, is not contract-parity qualified, and retains
`certificateHeader=chain` plus `mode=ATTACHMENT`. A differently named connector cannot inherit the
`1.0.1` behavior, and an unknown version of the canonical Connector ID fails before signing, DNS or
transport. The caller has no field that selects the Connector ID, version, environment or operation
authority used by this decision.

Stop unless three already-authorized role handoffs are available in separate authenticated Admin
sessions: Security Administrator for binding and grant, Connector Editor for proposal, and a
distinct Connector Approver for approval and publication. The same human must not perform both
proposal and approval. This runbook does not create principals, accounts or role assignments.

## Prerequisites

- the exact Healthcare/FSE2 execution module is deployed and allowlisted;
- the OfficialTest Environment already exists;
- the target Tenant and one active authenticated Installation already exist; the Installation is
  immutably bound server-side to that Tenant, Application and Environment;
- A1 and S1 are distinct active client-certificate catalog resources scoped to the exact Connector
  and `validate-cda` operation;
- A1 is authorized only for client-certificate use and S1 for signing/public-material use;
- both resources have current public metadata, catalog revisions and ContentCommitment semantics;
- the provider exposes public certificate material without exposing a password, private key or a
  generic secret-value capability;
- the Admin endpoint is HTTPS and the operator session cookie remains in a process-scoped protected
  environment variable;
- PostgreSQL 18 migrations are current and a second migration application is a no-op.

The provisioner consumes one protected operational plan outside Git, conforming to
`fse2-officialtest-operational-plan.schema.json`. Operational commands obtain exact public A1/S1
metadata only from the authenticated Admin API `/provider-resources` catalog. An external
`server-public-metadata.json` is not accepted and cannot authorize configuration.

The operational plan contains Tenant and Installation IDs only as lookup selectors. Its Environment
ID is a protected assertion, not authority. Before the first Admin mutation, the provisioner
authenticates the session, resolves exactly one Installation from `/installations` under the selected
Tenant, requires it to be Active, and compares the assertion with the server-owned
`InstallationRecord.EnvironmentId`. A mismatch is a hard stop with zero Admin mutations and zero
provider, signing, DNS, HTTPS, transport or network effects. The server-derived Environment then
selects the environment catalog, A1/S1 resources, binding and Installation grant.

The plan must not contain P12 bytes or paths, passwords, private keys, tokens, authorization
headers, session cookies, principal identities or client-selected runtime authority. Tenant,
Installation and Environment cannot be inferred from repository state or operator convention.

## Phase 0: local plan with zero side effects

Run from the product exact HEAD:

```text
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- plan <protected-plan>
```

This command is handled before Admin client construction. It has no store/provider dependency and
must report zero workflow-store, signing, DNS, HTTPS, transport and network counters. Its output
contains only the fixed Connector identity, the asserted Environment ID and digests; endpoint and
provider identifiers are represented by one-way digests. Plan output does not prove the assertion:
only authenticated Installation read-back does. Any stable `FSE2_OFFICIALTEST_*` error is a hard stop.

## Phase 1: Security Administrator configures and grants

Set `FSE2_GATEWAY_URL`, `FSE2_ADMIN_SESSION_COOKIE` and, only when required, the pinned public DER
CA certificate path `FSE2_GATEWAY_CA_FILE` in the Security Administrator's protected process environment.
The provisioner rejects a reparse point, oversized file, non-CA certificate or any certificate with
a private key. Never pass cookies on
the command line or write them into the plan.

Run `configure`. After authenticated Installation and Environment read-back, it compiles the repository source definition with the protected organization
profile, the source-owned application identity `secure-integration-platform` / `ApoCert S.r.l.` /
`0.1.0-alpha.1`, and exact server-catalog A1/S1 metadata, then uses only the existing Admin validate, import,
validate-stored and binding endpoints. Read-back must match:

- canonical Connector Definition checksum;
- operation-profile checksum;
- vertical binding-configuration digest;
- server binding checksum and exact provider revisions;
- one operation, `validate-cda`;
- A1 on mTLS and the same S1 on both signing slots;
- exactly the S1 leaf, and no issuer/intermediate/root certificate, in each JWT `x5c`;
- zero ordinary secret bindings.

After `GET /admin/auth/me`, every command first discovers the exact Connector/version/checksum,
server-owned Installation/Application/Environment, provider revisions, binding, grant, approval and
publication state through bounded Admin API pages and read-back. It then performs only the next
missing supported phase. From an empty state, `configure` uses `POST /connectors:validate`, `POST
/connectors:import`, stored validation and `PUT /connectors/{id}/bindings`, with full discovery after
each persistent transition. From Draft it resumes at stored validation; from Validated it resumes at
binding; with the exact binding already present it is verify-only. Identity drift or a non-monotonic
server state stops before the next mutation.

An Admin HTTP 429 is returned once as the bounded redacted code
`BGW-PROVISIONING-RATE-LIMITED`; the provisioner performs no retry loop. The result reports
`currentState`, `completedPhases`, `nextRequiredPhase`, `retrySafe`, an optional valid Retry-After
bounded to one hour, and the same supported command. It never preserves the response body, arbitrary
headers, endpoint, token, cookie, certificate, stack or exception message. After respecting the
operational rate limit, repeat the exact same command with the same plan. For the observed
post-validation case the result is `Validated`, retry-safe, with next phase
`BindingConfiguration`; re-entry does not import or validate again. Invalid or oversized
Retry-After is omitted and never causes a hidden retry.

Run `grant` in the same Security Administrator session. It re-resolves the Installation, then
lists grants for the server-owned Tenant. It verifies one exact enabled grant or creates one for the
selected Installation, Connector and `validate-cda`, followed by exact read-back. It never accepts
an Environment in the grant request; Environment authority remains the Installation record.

## Phase 2: Connector Editor proposes

Clear the Security Administrator session. In a Connector Editor session, run `plan`, compare the
digests, then run `propose` once with the same protected plan. The command rechecks Installation and
provider authority immediately before `POST /approval-requests`. Preserve only its redacted approval
request ID, approval digest and three exact checksums in the handoff. Do not preserve the compiled
definition or Admin responses in ordinary logs.

## Phase 3: distinct Connector Approver approves and publishes

Clear the editor session from the process. Start a separate process with the distinct approver's
authenticated session. Re-run `plan`, compare its digests with the handoff, then run `approve` with
the exact request ID and approval digest.

The server recomputes the approval artefact. Self-approval, a wrong request, a wrong/stale Connector
checksum, operation-profile drift, binding drift or provider revision drift fails closed. The second
operator then runs `publish` with the current expected publication revision. The vertical provisioner
additionally requires the current authenticated principal to be the distinct approver of the exact
checksum before it sends the publish request. A binding change atomically invalidates every requested
or approved prior digest in PostgreSQL; the provisioner consumes that server-owned status rather than
maintaining a second approval state machine.

Installation authority is re-read immediately before both the approval and publication mutations.
Environment or Installation drift stops before the next Admin write. Run `verify` in the approver
session. Success requires Published/Active read-back, exact canonical and
operation-profile checksums, exact logical resource revisions, no generic secret binding and only
the fixed OfficialTest endpoint component checksum. Every operational phase re-resolves the exact
unique active provider-catalog identities before mutation or read-back. The provisioner never prints
the endpoint.

Every phase has the same resume rule. An exact existing grant, request or approval is verified and
not recreated; exact Published/Active is a final verify-only no-op. RBAC and the distinct proposer /
approver handoff remain server-enforced on every real mutation. Never change role, plan, version,
binding or provider revision merely to continue after a 429, and never use a force/recovery flag.

## Handoff to the single-live runner

The handoff contains only Connector ID/version, operation ID, Environment ID, canonical definition
checksum, operation-profile checksum, binding-configuration digest, server approval/binding digests
and provider revisions. The live runner must independently verify Published read-back, its separate
clock gate and its one-request budget. This runbook does not run that handoff.

## Rollback and decommission

Do not edit a Published definition or binding. Before any live use, decommission by retiring the
exact version through the normal Security Administrator surface. After live use, follow the formal
release rollback decision; do not restore an older database or provider state manually. Provider
resource disablement/rotation is a separate privileged operation and intentionally makes the
Published resource stamp stale before signing, DNS and network.

An upgrade publishes immutable `1.0.1`; a supported lifecycle rollback reactivates immutable
`1.0.0`. Neither transition rewrites either version's effective wire contract: `1.0.1` remains
leaf-only/two-field parity and `1.0.0` remains chain/historical-body compatibility.

Evidence must be redacted and stored outside Git. Never retain raw Admin responses, provider
configuration, JWTs, payloads, certificate chains, P12 material or session cookies.

## Clean-state acceptance and recovery

The dedicated release gate is
`FSE2_OFFICIALTEST_clean_state_supported_provisioner_reaches_Published_for_authenticated_installation`.
It creates a unique labelled Docker network, container and named volume from the already-present
`postgres:18` image, publishing PostgreSQL only on a random loopback port. The empty-state proof is
an authenticated Admin API read-back showing zero Tenants, Applications, Environments and provider
resources; the test never reads PostgreSQL to establish or verify that inventory.

The supported bootstrap sequence used by the gate is:

1. `Gateway.Migrations apply`, with `GATEWAY_MIGRATION_CONNECTION`, applies the canonical migrations;
2. `tools/m3/FixtureGenerator` creates only task-owned synthetic material;
3. `tools/m3/Provisioner`, with the opt-in
   `M3_FSE2_OFFICIALTEST_SYNTHETIC_BOOTSTRAP=1`, creates the synthetic Tenant, Application,
   Environment, pending Installation and exact public A1/S1 catalog records through the existing
   stack bootstrap component;
4. the real Gateway host enrollment endpoints activate the Installation;
5. authenticated Admin API sessions run Installation read-back, server-side Environment derivation,
   exact provider-catalog resolution, configure, grant, propose, distinct approve, publish and
   Published/Active read-back.

The test project references the migration runner, fixture generator and M3 provisioner as build-only
components and launches their produced entrypoints; it does not register replacement stores, create
persisted records directly, or execute SQL. SQL used internally by the migration component and role
bootstrap remains encapsulated behind those supported deployment entrypoints. The opt-in M3 output
contains only public catalog identities needed to construct the protected synthetic plan.

The three direct preflight negatives are
`FSE2_OFFICIALTEST_preflight_rejects_missing_installation_before_any_Admin_mutation`,
`FSE2_OFFICIALTEST_preflight_rejects_ambiguous_installation_before_any_Admin_mutation` and
`FSE2_OFFICIALTEST_preflight_rejects_unauthorized_installation_before_any_Admin_mutation`.
Missing and unauthorized selections return the same non-enumerating unavailable result; ambiguity
never selects the first record. All three assert zero Admin mutation, provider access, signing, DNS,
HTTPS, transport and network effects.

The shared deterministic recovery qualification consists of the ten exact `PROVISIONER_*` named
tests in `Fse2ProvisionerResumabilityIntegrationTests`. They persist a synthetic Validated state,
inject one 429 before binding, prove one-attempt/no-loop behavior, same-plan resume through
Published/Active, Published re-entry no-op, exact identity drift denial, unchanged four-eyes/RBAC,
bounded redaction and connector-neutral operation. Every negative asserts zero signing, DNS, HTTPS,
transport and external network effects.

Record elapsed time from empty database to Published. The dedicated PostgreSQL job sets
`REQUIRE_FSE2_POSTGRES_GATE=1` and requires exactly one execution with zero failed and zero skipped;
skipping that dedicated gate is not a PASS. Cleanup removes only the exact labelled task-owned
container, network, volume and synthetic directory, then proves that none remains.

A Published configuration with the wrong Environment is immutable and must not be updated in place.
Preserve the historical bad volume/evidence, provision a new clean laboratory volume, bootstrap a new
valid Installation, and run the supported sequence once against that clean state. Do not edit the
Published row, restore the bad database into the active store or use direct SQL as recovery.

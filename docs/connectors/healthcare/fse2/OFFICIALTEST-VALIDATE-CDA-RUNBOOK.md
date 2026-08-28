# FSE2 OfficialTest `validate-cda` operationalization

## Purpose and hard stop

This runbook configures and publishes only `fse2-officialtest-validate-cda@1.0.0` through the
existing authenticated Admin API. It does not invoke the Connector and does not authorize a live
FSE2 call. Production, accreditation, create/replace/status/delete and provider-material creation
are outside this procedure.

Stop unless two already-authorized human operators are available in separate authenticated Admin
sessions. The first needs Connector Editor authority; the second needs Connector Approver authority.
This runbook does not create principals, accounts or role assignments.

## Prerequisites

- the exact Healthcare/FSE2 execution module is deployed and allowlisted;
- the OfficialTest Environment already exists;
- A1 and S1 are distinct active client-certificate catalog resources scoped to the exact Connector
  and `validate-cda` operation;
- A1 is authorized only for client-certificate use and S1 for signing/public-material use;
- both resources have current public metadata, catalog revisions and ContentCommitment semantics;
- the provider exposes public certificate material without exposing a password, private key or a
  generic secret-value capability;
- the Admin endpoint is HTTPS and the operator session cookie remains in a process-scoped protected
  environment variable;
- PostgreSQL 18 migrations are current and a second migration application is a no-op.

The provisioner consumes two files outside Git:

1. a protected operational plan conforming to
   `fse2-officialtest-operational-plan.schema.json`;
2. a protected server-public-metadata file containing only schema version plus, for A1 and S1,
   `subjectPublicKeyInfoSha256`, `subjectCommonName` and `catalogChecksumSha256`.

The second file must be produced from the deployed provider's public-material capability and the
current server catalog. It is not a substitute for provider resolution. Do not derive it by opening
a P12 with this provisioner. Keep both files outside the repository with operator-only ACLs and
delete them under the deployment evidence-retention policy.

The operational plan may contain only the exact Environment ID, the fixed OfficialTest endpoint,
organization/locality identity, logical A1/S1 provider resource references and expected
revisions. It must not contain P12 bytes or paths, passwords, private keys, tokens, authorization
headers, session cookies, principal identities or client-selected runtime authority.

## Phase 0: local plan with zero side effects

Run from the product exact HEAD:

```text
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- plan <protected-plan>
```

This command is handled before Admin client construction. It has no store/provider dependency and
must report zero workflow-store, signing, DNS, HTTPS, transport and network counters. Its output
contains only the fixed Connector identity, Environment ID and digests; endpoint and provider
identifiers are represented by one-way digests. Any stable `FSE2_OFFICIALTEST_*` error is a hard
stop.

## Phase 1: first operator configures and proposes

Set `FSE2_GATEWAY_URL`, `FSE2_ADMIN_SESSION_COOKIE` and, only when required, the pinned public DER
CA certificate path `FSE2_GATEWAY_CA_FILE` in the first operator's protected process environment.
The provisioner rejects a reparse point, oversized file, non-CA certificate or any certificate with
a private key. Never pass cookies on
the command line or write them into the plan.

Run `configure` once. It compiles the repository source definition with the protected organization
profile and exact public A1/S1 metadata, then uses only the existing Admin validate, import,
validate-stored and binding endpoints. Read-back must match:

- canonical Connector Definition checksum;
- operation-profile checksum;
- vertical binding-configuration digest;
- server binding checksum and exact provider revisions;
- one operation, `validate-cda`;
- A1 on mTLS and the same S1 on both signing slots;
- zero ordinary secret bindings.

Run `propose` once with the same two protected files. Preserve only its redacted approval request ID,
approval digest and three exact checksums in the handoff. Do not preserve the compiled definition or
Admin responses in ordinary logs.

## Phase 2: distinct operator approves and publishes

Clear the first session from the process. Start a separate process with the second operator's
authenticated session. Re-run `plan`, compare its digests with the handoff, then run `approve` with
the exact request ID and approval digest.

The server recomputes the approval artefact. Self-approval, a wrong request, a wrong/stale Connector
checksum, operation-profile drift, binding drift or provider revision drift fails closed. The second
operator then runs `publish` with the current expected publication revision. The vertical provisioner
additionally requires the current authenticated principal to be the distinct approver of the exact
checksum before it sends the publish request.

Run `verify` in the second session. Success requires Published/Active read-back, exact canonical and
operation-profile checksums, exact logical resource revisions, no generic secret binding and only
the fixed OfficialTest endpoint component checksum. The provisioner never prints the endpoint.

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

Evidence must be redacted and stored outside Git. Never retain raw Admin responses, provider
configuration, JWTs, payloads, certificate chains, P12 material or session cookies.

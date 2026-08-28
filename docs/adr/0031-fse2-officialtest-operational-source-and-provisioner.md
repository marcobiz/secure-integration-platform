# ADR 0031: FSE2 OfficialTest operational source and vertical provisioner

- Status: Accepted
- Date: 2026-08-28

## Context

The frozen FSE2 runtime already consumes an immutable Published operation, but an operational
OfficialTest profile contains deployment-owned organization/locality identity and exact public A1/S1
metadata. Committing those values would make the repository an operational authority. Adding an
FSE2 dependency to the provider-neutral Connector CLI or adding a generic Core certificate/secret
hydration API would reverse the dependency boundary.

## Decision

The Healthcare/FSE2 pack owns a public-safe canonical source definition containing only
`validate-cda`, logical binding names and non-operational placeholders. A vertical compiler overlays
only a strictly parsed protected plan and server-resolved public certificate metadata. It emits the
exact canonical definition checksum, operation-profile checksum and binding-configuration digest.

The supported edge is `tools/fse2/OfficialTestProvisioner`. It uses the existing authenticated Admin
API for validate/import/bind/request/approve/publish/read-back. Dry-run is completed before Admin
client construction. Operational commands use the server-derived Admin session principal; the plan
cannot declare principal, Tenant or Installation authority. Publication through this workflow is
sent only by the distinct approver of the exact request.

The runtime remains unchanged structurally: A1 is the existing Published mTLS certificate binding,
S1 is the existing key binding for both authorization and integrity signing slots, and restricted
transport remains the existing Core capability. There is no `GetSecret`, generic HTTP/crypto API,
signing oracle or Healthcare dependency in Core.

## Consequences

- real configuration and public provider metadata remain outside Git;
- four-eyes continues to bind the server-computed approval artefact, while the vertical handoff also
  exposes the operation-profile and binding-configuration digests;
- any definition, binding or provider-revision mutation makes the old handoff stale;
- PostgreSQL is required for atomic approved publication; the in-memory store intentionally refuses
  that production path;
- public metadata input is a trusted deployment artefact and must be generated from the deployed
  provider/catalog, ACL-protected and checksum-verified;
- no live network call is part of provisioning or qualification.

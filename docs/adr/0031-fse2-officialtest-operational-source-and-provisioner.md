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
only a strictly parsed protected plan and public certificate metadata resolved from the authenticated
Admin API provider catalog. It emits the
exact canonical definition checksum, operation-profile checksum and binding-configuration digest.
The source-owned application identity is `secure-integration-platform` / `ApoCert S.r.l.` /
`0.1.0-alpha.1`; no plan or caller field can override it.

The supported edge is `tools/fse2/OfficialTestProvisioner`. It uses the existing authenticated Admin
API for validate/import/bind/grant/request/approve/publish/read-back. Dry-run is completed before Admin
client construction. Operational commands use the server-derived Admin session principal. Tenant
and Installation IDs in the plan are selectors only, and the plan Environment ID is an assertion.
Before the first Admin mutation the provisioner resolves exactly one active Installation through the
authenticated Admin API and treats `InstallationRecord.EnvironmentId` as the sole Environment
authority. Mismatch fails before Admin writes or provider/signing/network effects. Publication through this workflow is
sent only by the distinct approver of the exact request. This is also an authoritative server-side
condition: both the approval precheck and the serializable PostgreSQL publication transaction bind
the authenticated session actor to the current approval's `approved_by`.

`server-public-metadata.json` is not an authority and is not accepted by operational commands.
The Installation identity is re-read before each mutation, including binding, proposal, approval and
publication; drift stops before the next mutation. The server-derived Environment selects the
environment catalog, exact A1/S1 resources, binding and Installation grant. Before compilation and again before every mutation/read-back, the provisioner requests exactly one
active `ClientCertificate` catalog revision for A1 and S1 through a bounded exact server lookup by Environment, provider/resource/version,
catalog/public-metadata revision, Connector/operation scope, catalog checksum, SPKI SHA-256 and
subject CN. The lookup neither scans offset pages nor depends on global catalog order; server-side
catalog checksum verification makes inconsistent public metadata fail closed. Missing, ambiguous,
inactive, cross-Environment or drifted selection fails closed.

The runtime composes the Published operation path structurally as a child of the server-owned base
endpoint path. A rooted operation path cannot replace the `/govway/rest/in/FSE/gateway/v1` prefix;
scheme, host and port remain unchanged, HTTPS is required, and userinfo/query/fragment, traversal
and encoded/double-normalized paths are denied. This behavior is selected by the immutable,
source-owned `pathResolution=appendToBasePath`; existing definitions retain `authorityRoot` semantics.

The runtime remains unchanged structurally: A1 is the existing Published mTLS certificate binding,
S1 is the existing key binding for both authorization and integrity signing slots, and restricted
transport remains the existing Core capability. There is no `GetSecret`, generic HTTP/crypto API,
signing oracle or Healthcare dependency in Core.

## Consequences

- real configuration remains outside Git; public provider metadata remains server-owned;
- an Environment in the protected plan cannot redirect provisioning away from the authenticated
  Installation; a historical Published row with the wrong Environment remains immutable and recovery
  requires a new clean deployment state;
- four-eyes continues to bind the server-computed approval artefact, while the vertical handoff also
  exposes the operation-profile and binding-configuration digests;
- any definition, binding or provider-revision mutation makes the old handoff stale;
- PostgreSQL is required for atomic approved publication; the in-memory store intentionally refuses
  that production path;
- administrative catalog pagination uses total deterministic ordering and one repeatable-read
  snapshot for count and page, while operational A1/S1 authority never uses pagination;
- the Admin API exposes only public certificate identity (including SPKI SHA-256 and subject CN),
  never a provider locator, private key, P12, password or generic secret value;
- no live network call is part of provisioning or qualification.

# Wave 1 bounded authorized signing slots

## Scope and baseline

- exact baseline: `b1810eda7e96fabfc6e15e608d48867e96cd5a80`;
- branch: `wave1/authorized-signing-slots`;
- worktree: `C:\Codice\broker-gateway-wave1-signing-slots`;
- one Core/Auth freeze exception only: bounded authorized signing slots;
- no connector-specific implementation, healthcare logic, provider, adapter family or merge.

This closes the demonstrated Core limitation where one already-authorized operation needs two fresh
opaque signed tokens while preserving server-owned signing and restricted transport.

## Published model

New definitions use `authorizedCapabilities.signingSlots`, with one to four entries. Each entry has:

- a canonical `slot` key;
- an explicit `required` transport-completeness decision;
- the unchanged qualified `invocationSigning` object;
- `authorizationBearer`, or `signedTokenHeader` with one Published field name.

The existing `restrictedTransport` profile continues to own mTLS SPKI, revision and near-expiry
policy. In the new form it does not contain an Authorization selector because projections belong to
the exact signing slots. The schema and semantic validator reject zero or more than four slots,
duplicate keys or policy IDs, invalid keys, unknown/missing certificate bindings, duplicate Bearer
or custom-header projections, unsafe headers and mixed legacy/new signing modes.

Canonical JSON already supplies checksum and four-eyes coverage. Changing any slot key, signing
policy, issuer, binding, required flag or projection creates a different definition checksum and
requires a new immutable revision and exact approval.

## Legacy compatibility

A stored historical definition remains byte-for-byte unchanged and keeps its historical checksum.
Core derives one internal required slot named `legacy`; the original signing policy is used once and
the original `signedTokenBearer` transport value becomes Authorization Bearer. The public historical
signing overload and transport request constructor remain source-compatible. They do not create a
fallback for an explicit new definition.

## Invocation and lifetime behavior

`CreateSignedTokenAsync(ConnectorSigningSlotKey, claims, cancellationToken)` is the only new signing
selector. The bridge registers the call in the exact ADR-0024 host lifetime scope before claims,
provider or signing work. It maintains a set capped at four and denies the second request for the
same slot before the dispatcher and private-key effect.

The runtime rereads only to compare the current snapshot with Published A, exact-matches the slot,
and builds the existing server-owned RS256 policy. Algorithm, key binding, provider reference,
certificate/x5c, issuer, audience, subject, lifetime and reserved claims remain Core-owned. Each slot
invokes the signer independently and receives its own `jti`, payload and signature.

`AuthorizedConnectorSignedToken` still exposes no public property or constructor. Internally it is
bound by reference to the exact bridge and carries the exact slot. The bridge retains an exact
slot-to-handle map. Restricted transport receives that map only across internal interfaces, checks
required completeness and slot identity, and installs the Published projections. External modules
never build a header collection and never receive compact token material.

Transport remains one-shot and continues through `PurposeBoundMutualTlsSender`, restricted DNS,
destination policy, TLS validation, response bounds and the exact Published mTLS identity. Its final
A comparison remains after DNS and before network. Scope close prevents later signing or transport,
cancels/drains in-flight work and rejects an early strategy result without success audit.

## PostgreSQL least privilege

Migration `0013_authorized_signing_slots.sql` replaces only the body of the existing
`SECURITY DEFINER` locator. A client-certificate locator is admitted when it is the exact operation's
mTLS binding, historical signing binding or one of the new operation's slot signing bindings. All
existing principal, grant, Published version, binding checksum/revision, resource scope/revision,
catalog-current and RLS predicates and runtime-role grants remain unchanged.

The migration SHA-256 is
`5AF2DF3FC69BB24D63BCAF1C17C30EDF4758DD8CAFC8EC18D7574B13C45D797C`.

## Public API delta

| Surface | Delta | Authority |
|---|---|---|
| Slot selector | `ConnectorSigningSlotKey` with `MaximumLength`, `Value`, `Parse`, `TryParse`, `ToString` | immutable identifier only; exact Published match creates authority |
| Signing | overload `CreateSignedTokenAsync(signingSlot, claims, cancellationToken)` | one token per authorized slot; no policy/key/provider selector |
| Transport | body-only `AuthorizedConnectorRestrictedTransportRequest` constructor | Core consumes its internal token map and Published projections |

No token getter, raw-signature API, certificate view, provider/key selector, generic header bag,
`HttpRequestMessage`, `HttpClient` or arbitrary authenticated transport surface was added.

## Automated evidence

- schema/checksum/dependency and negative matrix:
  `Wave1_CT_authorized_signing_slots_are_bounded_checksum_bound_and_dependency_complete` and
  `Wave1_SEC_authorized_signing_slot_schema_and_projection_matrix_fails_closed`;
- per-slot one-shot, independent slots, four-attempt cap, post-close and cross-invocation denial:
  `Wave1_SEC_signing_slots_are_one_shot_independent_and_attempts_are_bounded` and
  `Wave1_SEC_signed_token_is_denied_post_close_and_across_invocations_before_transport`;
- neutral external no-IVT HTTPS/mTLS proof, including distinct issuer, same signing identity, x5c,
  fresh/distinct tokens, Bearer plus custom header, unknown slot, repeat and missing required slot:
  `Wave1_IT_PRODUCTION_HOST_in_memory_Published_profile_signs_x5c_and_dispatches_real_mTLS`;
- the same canonical hosted proof through PostgreSQL 18, distinct editor/approver, publication, BGW1
  and grant: `Wave1_IT_PRODUCTION_HOST_PostgreSQL18_Published_profile_signs_x5c_and_dispatches_real_mTLS`;
- deterministic second-slot signing A-to-B and post-DNS transport A-to-B:
  `Wave1_SEC_Published_A_to_B_during_signing_public_material_returns_no_token_and_performs_no_transport`
  and `Wave1_SEC_Published_A_to_B_after_DNS_denies_before_restricted_transport`;
- public/API/architecture/no-vertical boundary:
  `Wave1_CT_authorized_signing_slots_are_bounded_opaque_slot_bound_and_server_projected` and the
  existing capability-completion architecture gates.

The local product gate records a zero-warning Release build; 560 ordinary .NET PASS plus 30 explicit
PostgreSQL-conditional skips; 34/34 architecture and 93/93 signing PASS; the complete Gateway
integration project PASS against a fresh PostgreSQL 18 database with the canonical non-superuser
admin role; 28/28 Vitest, 2/2 accessibility, 37/37 isolated browser tests and `FULLSTACK-01` 1/1 with
redaction and Docker cleanup PASS. Documentation, conservative secret scan, NuGet/npm vulnerability
checks, SBOM validation/generation and `git diff --check` also pass.

The Windows PowerShell split-network, split-firewall, operator-handoff and TLS-hardening M3
regressions pass. The local full M3 driver reached its fault-control phase but the non-interactive
Windows run could not install the per-run synthetic CA because the OS displayed a GUI trust prompt;
the prompt was terminated, no CA remained installed and the exact Compose project was removed.
Therefore the Linux exact-head `m3-deterministic-container-slice`, rather than that incomplete local
attempt, remains the required full M3 evidence. Final-HEAD Gitleaks, Core export, exact-head CI and
independent review also remain required before handoff. Merge is not authorized.

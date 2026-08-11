# Wave 1 authorized Published operation contract

## Scope and baseline

- exact baseline: `8e5a3cac41959b9ffd7c52dcf7576c309051f7f4`;
- branch: `wave1/authorized-operation-contract`;
- worktree: `C:\Codice\broker-gateway-wave1-authorized-operation-contract`;
- one Core security freeze exception only: mandatory Published-operation policy preflight, bounded
  Published path projection and explicit restricted-transport body mode;
- no healthcare/commercial connector, provider pack, System Test change, mass republish or merge.

## Mandatory preflight

An external/non-Core strategy is not entered merely because its key and authentication kind match.
After principal and grant checks, Core requires an authoritative catalog, a non-null exact current
Published operation A and authority stamp, exactly one module-owned expectation provider, and the
internal capability dispatcher. The provider is registered through the existing bounded module
registrar and constructor-graph controls. A non-authoritative catalog, missing authority/provider/
dispatcher, duplicate strategy coverage, invalid provider metadata, provider exceptions and null or
invalid expectations fail closed as sanitized `BGW-EGRESS-AUTHENTICATION` before capability-scope
entry, strategy, signing, DNS or network. The formerly accepted non-authoritative external dispatch
is intentionally denied. Built-in Core strategies marked by the internal Core contract keep their
qualified legacy behavior and do not require a module provider.

The provider receives a non-constructible `AuthorizedPublishedOperationExpectationContext`. Its
public state is limited to connector/version/operation/strategy identifiers and authentication kind;
it may open only a defensive copy of the existing open `extensionConfiguration`. Payload, endpoint,
authority stamp, effective policy, binding/resource, provider/store/DI, certificate, token and
capability bridge are absent.

The returned immutable expectation model contains only bounded generic semantics. Core resolves the
effective Published policies and exact-compares:

- authentication kind and restricted-transport presence;
- exact signing-slot set, required flags and RS256;
- Authorization Bearer or one exact bounded signed-token header;
- fixed subject, audience, business-claim allowlist, lifetime and temporal mode;
- mandatory Core-generated `jti` and exact x5c mode;
- exact issuer or fixed prefix plus the verified signing-certificate subject CN;
- cryptographic signing-identity equality across declared slots;
- cryptographic inequality between declared signing identities and the approved mTLS identity.

Presence is part of that exact comparison. `RestrictedTransportRequired=false` means the Published A
must not contain `restrictedTransport`; an empty expected slot set means A must contain neither
legacy `signing` nor `signingSlots`. `false/empty` is exact verified absence, never an opt-out. Core
returns without parsing a restricted profile only for the symmetric absent/absent and empty/empty
case. An actual policy with empty expectations, expected transport with actual absence, or either
direction of slot-set mismatch is denied before strategy and every privileged/network effect.

Core obtains approved public certificate material only when a certificate relation requires it,
checks DER/fingerprint/SPKI/provider metadata, extracts the subject CN internally and revalidates A
after every await. The module receives none of that material. The preflight operation exists only on
internal dispatcher/runtime contracts; `IAuthorizedConnectorCapabilityBridge` has no new method.

All preflight mismatch and exception paths return sanitized `BGW-EGRESS-AUTHENTICATION` before the
strategy, signing and network. A Published A-to-B change while public material is in flight returns
the existing stale classification with zero signing and zero network.

This is a breaking-security remediation for external modules: every external positive path must now
provide authoritative Published authority, an exact-key provider, a dispatcher and complete coherent
expectations for every signing/restricted-transport capability it actually uses. It adds no public
bridge method, generic HTTP surface, policy metadata view, schema member or migration.

## Published path projection

New definitions may select exactly one of static `path` and `pathTemplate`. A template is an absolute
path only; it has no authority, scheme, query, fragment, backslash or percent syntax. At most eight
unique canonical placeholders may occur, each occupying one complete segment. Static literal
segments use canonical URI-unreserved characters.

`AuthorizedConnectorRestrictedTransportRequest` may carry at most eight copied
`AuthorizedConnectorPathParameter` values. Names must exactly equal the template placeholders.
Values are non-empty NFC text bounded to 512 UTF-8 bytes and reject whitespace-only, controls,
slash, backslash, percent, query/fragment delimiters and `.`/`..`. Core performs one
`Uri.EscapeDataString` encoding and then asserts the final scheme, IDN host, port, user-info, query,
fragment and escaped path. A static Published path rejects every supplied parameter.

The final endpoint is re-rendered from Published A at every runtime authority check, including the
post-DNS check. Missing, extra, duplicate or unknown names and all injection/double-encoding forms are
denied before transport.

## Restricted transport body mode

`authorizedCapabilities.restrictedTransport.bodyMode` accepts only `required` and `none`.
Definitions without the member map to `required`, preserving the historical request constructor and
wire behavior. `none` is valid only for GET and DELETE. Runtime requires exact agreement between the
Published mode and the request representation:

- `required`: a non-empty bounded copied body is mandatory and Core applies the Published
  Content-Type;
- `none`: a body is forbidden, `HttpRequestMessage.Content` remains null, the wire length is zero and
  no Content-Type is sent.

The module cannot select method, Content-Type, endpoint, header or body mode.

## Compatibility and persistence

The schema additions are optional and canonical only when present. Historical static-path
definitions remain byte-for-byte unchanged, retain the fixed checksum regression and continue to
load as `required`. Published rows are immutable and need no rewrite or republish. Connector state is
stored as canonical JSONB, and neither the storage schema nor operation-scoped resource locator
changes; therefore no migration is necessary.

The original body-only and body-plus-token request constructors remain present. New constructors add
bodyless and bounded-path representations without exposing URI authority. The external synthetic
module compiles only against public Core contracts and has no friend access.

## Automated evidence

- public surface, bounds, exact encoding, injection denial and historical constructor inventory:
  `Wave1_CT_Published_path_projection_is_exact_single_encoded_and_origin_preserving`,
  `Wave1_SEC_Published_path_values_reject_empty_traversal_delimiters_percent_and_controls`,
  `Wave1_SEC_Published_path_template_rejects_authority_partial_duplicate_and_noncanonical_forms`,
  `Wave1_CT_restricted_transport_request_represents_REQUIRED_and_NONE_without_URI_authority` and
  `Wave1_CT_qualified_execution_handoff_is_non_forgeable_and_hides_payload_and_operation_authority`;
- schema/checksum/body semantics and historical checksum regression:
  `Wave1_CT_Published_path_template_and_NONE_body_mode_are_checksum_bound_and_method_bounded`,
  `Wave1_SEC_Published_path_template_schema_and_semantics_fail_closed` and
  `Wave1_CT_Published_capability_profile_is_strict_bounded_and_dependency_complete`;
- exact two-slot policy, certificate/CN relation, identity equality/separation, path/body wire proof
  through the production host:
  `Wave1_IT_PRODUCTION_HOST_in_memory_authorized_operation_projects_Published_paths_and_body_modes`;
- the same canonical editor/distinct-approver/Published/BGW1/grant path on PostgreSQL 18:
  `Wave1_IT_PRODUCTION_HOST_PostgreSQL18_authorized_operation_projects_Published_paths_and_body_modes`;
- full preflight mismatch matrix and missing-validator denial with zero signing/network:
  `Wave1_SEC_authorized_operation_policy_mismatches_deny_before_signing_and_network` and
  `Wave1_SEC_authorized_operation_missing_expectation_provider_denies_before_signing_and_network`;
- exact absence and authoritative-preflight remediation:
  `Wave1_SEC_false_empty_expectations_verify_exact_Published_absence_before_scope_signing_DNS_and_network`
  and
  `Wave1_SEC_external_strategy_requires_authoritative_Published_provider_and_dispatcher_before_scope_entry`;
- path/template and REQUIRED/NONE mismatch denial with zero network:
  `Wave1_SEC_authorized_operation_path_and_body_mismatches_deny_before_network`;
- deterministic exact-A races before signing and before network:
  `Wave1_SEC_Published_A_to_B_during_policy_preflight_denies_before_signing_and_network` and
  `Wave1_SEC_Published_A_to_B_after_DNS_denies_before_restricted_transport`.

The remediation product commit completed the repository suites, PostgreSQL 18.4 fresh apply/no-op
with 198/198 Gateway integration tests and no skip, Admin 29/29 unit plus 37/37 browser-mock and 2/2
accessibility tests, `FULLSTACK-01` with zero residual Compose resources, documentation and secret
validation, vulnerability inventory, and the complete container SBOM. Core export and the repeated
local gate on the final documentation commit precede the normal push. Exact-head CI and independent
micro-rereview remain separate post-push gates. Merge is not authorized by this exception.

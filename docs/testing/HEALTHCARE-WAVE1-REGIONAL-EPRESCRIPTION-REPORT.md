# Healthcare Wave 1 — Regional ePrescription report

Date: 2026-08-08

Baseline: `m6-auth-foundation-baseline-20260808` / `6e1a7c626e0e24d0a385c611fc03faef51598889`

Branch: `wave1/regional-eprescription`

## Product result

The Regional ePrescription foundation is implemented inside the Healthcare Pack. Lombardia and
Emilia-Romagna remain `BLOCKED_BY_SPEC`; no production endpoint, wire operation, OAuth/SOAP
mapping, credential, scope or accreditation claim exists in the product.

## Named Healthcare tests

| Test | Evidence |
|---|---|
| `HC_W1_COMMON_model_contains_only_lookup_dispense_and_bounded_scalar_extensions` | Small common API and bounded scalar input |
| `HC_W1_COMMON_dispense_uses_only_the_matching_published_operation` | Typed dispense routing |
| `HC_W1_SEC_caller_contract_has_no_profile_region_endpoint_auth_or_credential_selector` | Caller authority surface closed |
| `HC_W1_SEC_extension_schema_is_server_owned_and_revalidated_after_profile_resolution` | Caller cannot declare its own extension schema |
| `HC_W1_SEC_real_Published_adapter_and_credential_independent_authorization_fail_closed` | Opaque Core authorization, exact grant and Published projection for a no-credential operation; missing grant, cross-Tenant and suspended Installation denied before lookup |
| `HC_W1_SEC_null_nested_command_and_response_values_fail_sanitized` | Malformed nested input/output denial without raw runtime errors |
| `HC_W1_SEC_profile_A_cannot_use_endpoint_auth_or_credential_B_and_lookup_authority_is_server_derived` | Endpoint/auth/credential cross-profile isolation and server-derived Published lookup |
| `HC_W1_SEC_tenant_cannot_select_another_profile_and_authority_mismatch_denies_before_dispatch` | Cross-Tenant/profile spoof denial |
| `HC_W1_SEC_rotation_disable_and_stale_complete_binding_stamp_fail_closed` | Disable/rotation and complete binding fingerprint with zero dispatch |
| `HC_W1_SEC_normalized_error_preserves_only_allowlisted_safe_code_and_redacts_reference` | Safe-code separation and redaction |
| `HC_W1_SEC_profile_response_type_or_reference_mismatch_is_denied` | Response type, reference, extension-schema, safe-code allowlist and enum-domain confusion denial |
| `HC_W1_SEC_unexpected_resolver_and_dispatcher_exceptions_are_redacted_without_inner_details` | Resolver, stamp and dispatcher exception normalization plus regional-code allowlisting |
| `HC_W1_SEC_binding_and_compiled_profile_snapshot_mutable_collections` | Immutable binding/compiled-profile snapshots and length-prefixed fingerprint |
| `HC_W1_BLOCKED_regional_synthetic_HTTPS_sentinels_receive_zero_requests` | Pinned TLS health handshakes succeed, but blocked profiles produce zero business requests |
| `HC_W1_ARCH_Core_does_not_reference_Healthcare_pack` | Dependency direction |
| `HC_W1_ARCH_regional_domain_concepts_are_absent_from_Gateway_Core_source` | Vertical vocabulary remains out of Core |
| `HC_W1_ARCH_Healthcare_foundation_depends_only_on_public_Core_application_contract` | Pack dependency allowlist |
| `HC_W1_ARCH_Healthcare_pack_does_not_reinterpret_inbound_identity` | Pack cannot read certificate DER or perform registry identity derivation |

## Local gate

| Gate | Result |
|---|---|
| `./eng/build.ps1` | PASS, zero warnings/errors |
| Focused Healthcare Pack | PASS, 14/14 |
| Architecture suite | PASS, 20/20; 4 Healthcare boundary tests |
| `./eng/test.ps1` | PASS on the final candidate tree |
| Full solution total | 289 discovered: 279 passed, 10 PostgreSQL-configured tests skipped, 0 failed |
| `./eng/validate-docs.ps1` | PASS |
| `./eng/scan-secrets.ps1` | PASS |
| `./eng/generate-sbom.ps1` | PASS; ignored output under `.artifacts/sbom` |
| Vulnerable transitive packages | PASS, none reported |
| `git diff --check` | PASS |

The ten skipped PostgreSQL tests require the dedicated PostgreSQL gate and are unrelated to this
pack, which adds no migration or persistence. Their skip is not counted as healthcare evidence.

### Visible remediation

The first added TLS health-handshake assertion failed because Kestrel could not use an
`EphemeralKeySet` private key after fixture setup. The sentinel certificate was changed to a
runtime-only `UserKeySet | Exportable` instance retained and disposed by the server fixture. The
same named TLS/blocked-dispatch test then passed five consecutive repetitions. The complete build,
full solution test, documentation validation and secret scan were rerun successfully on the
remediated tree. No TLS validation callback was broadened: the client accepts only the exact
runtime certificate SHA-256 for that sentinel.

The first independent review returned NO-GO on the foundation because the caller could provide an
extension schema, cross-profile isolation was asserted only through a fake resolver, resolver and
dispatcher exceptions could escape with raw details, binding collections were shallowly mutable,
and the Core dependency scan covered only Gateway projects. The remediation removes schema from
the caller API, adds a concrete principal-derived Published resolver plus a compiled profile
catalog, compares exact endpoint/auth/credential resources, snapshots collections, revalidates a
complete binding fingerprint, normalizes resolver/stamp/dispatcher failures, and recursively scans
all projects reachable from `BrokerGateway.Core.slnx`. Named negative tests cover each finding.

The second independent review kept the candidate at NO-GO because the Published source was still
only an interface, nested command/response nulls could escape as runtime exceptions, the binding
fingerprint used ambiguous delimiters, and the foundation required at least one credential without
source support. The next remediation adds the public production adapter over
`IConnectorConfigurationStore`, the existing access/grant context and canonical operation
dependencies; validates nested request/response state; uses length-prefixed fingerprint hashing;
and accepts an exact empty credential set when the Published/compiled auth policy requires none.

The third independent review found that PostgreSQL locator authorization was conditional on at
least one provider resource, so `authentication.kind=none` could skip grant enforcement. It also
identified the remaining delimiter key in the compiled catalog and missing enum-domain checks.
The attempted remediation added a credential-independent registry authorizer inside Healthcare;
it exercised missing grant/cross-Tenant/suspended Installation negatives, used a composite catalog
key with explicit profile/operation equality, and rejected undefined response/error enum values.
Its identity re-resolution placement was not accepted and was replaced by the Core capability
described next; it is not part of the final product design.

The fourth independent review correctly rejected the first authorization placement because the
Healthcare Pack reinterpreted inbound certificate material and received broad registry access,
contrary to the frozen runtime-auth contract. The remediation moves active-state/grant enforcement
to provider-neutral Gateway Core, which produces an opaque `AuthorizedGatewayInvocation`; the pack
only consumes that capability. A named architecture test forbids certificate DER, registry identity
lookup and `IGatewayRegistry` access from Healthcare sources.

CI, independent review, exact final HEAD, PR URL and final worktree state are recorded at handoff;
this report does not pre-claim them.

## Deferred and blocked evidence

- no profile-specific OAuth or SOAP integration;
- no callback/session correlation test against a regional contract;
- no regional restricted-egress dispatch or safe fault mapping;
- no accreditation or current test endpoint;
- no live Lombardia or Emilia-Romagna evidence;
- no public/private preview GO for a regional connector.

The generic M6 OAuth and SOAP test suites remain regression coverage for their own primitives only.
They are not counted as regional profile conformance.

## Gate verdict

- **GO**: merge/review consideration for the Healthcare Pack foundation, subject to CI and
  independent review.
- **NO-GO**: any claim that Lombardia or Emilia-Romagna is supported.
- **NO-GO**: live regional use or private-preview pilot.

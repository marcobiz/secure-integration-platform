# Wave 1 authorized typed composed-SOAP request composition

## Scope and baseline

- immutable base: `feec547a3e0991171fca1f8b22b136d3dd4c4ee3`;
- branch: `wave1/authorized-typed-composed-soap`;
- worktree: `C:\Codice\broker-gateway-wave1-typed-composed-request`;
- one Core security freeze exception only;
- no merge and no production connector or commercial adapter.

This capability closes the gap between a caller-owned business payload and the already-qualified
Basic + opaque-session + SOAPAction transport. It does not add a response adapter: the existing
bounded response remains available to the connector strategy for protocol validation.

## Published model

An opt-in business operation adds:

```json
{
  "typedComposedSoapRequest": {
    "requestAdapter": {
      "id": "external-business-request",
      "type": "external-compiled-business-request"
    },
    "requestElement": {
      "localName": "BusinessOperation",
      "namespaceUri": "urn:synthetic:session"
    },
    "serverOwnedInputs": [
      {
        "name": "organization-code",
        "secretBinding": "organization"
      }
    ]
  }
}
```

The block is closed by schema, valid only on POST with `soapBasicOpaqueSession`, and maps at most 16
unique adapter names to logical bindings of kind `opaque`. Adapter identity, QName, mappings and the
operation request maximum participate in validation, canonical JSON and the checksum-specific
four-eyes artifact. Operation dependency extraction includes every mapped binding, so binding
revision/checksum, locator metadata and catalog revision also enter the resource stamp.

## Runtime composition

The unchanged authorized bridge call follows this sequence:

1. authorize the authenticated principal, grant and exact Published operation A;
2. resolve the exact module-owned adapter and its frozen required input names;
3. resolve only A's mapped provider references, revalidating A after every await;
4. give the synchronous adapter repeatable read-only streams over a Core-owned bounded copy of the
   caller business payload and the existing write-only binding input view;
5. accept adapter output only through the currently bound hardened Core `XmlWriter`;
6. validate the internal fragment, add the Published Envelope/Body/request QName and freeze bounded
   exact SOAP bytes;
7. reuse the existing composed authority for Basic, opaque session, Content-Type/SOAPAction, DNS and
   `IRestrictedTransport.SendSoapAsync`;
8. perform the existing complete final Published/session check immediately before the network effect.

The context cannot be constructed by a module. It contains safe authenticated identities, Connector
and operation identifiers, correlation ID, Published checksum, payload length, read-only streams and
write-only inputs. It has no final body, URI, method, endpoint, credential, provider, store, transport,
header collection, service locator, XML template or generic field map. Retained contexts reject new
streams; already-open retained streams observe cleared backing bytes after the callback. Binding
views reject alternate writers and post-callback writes.

Real caller cancellation is preserved with the actual caller token. Adapter-thrown fake cancellation
and other adapter exceptions are converted to sanitized protocol failure. There is no automatic retry.

## Exact A and compatibility

Adapter ID/type, QName, input mapping, provider locator/resource metadata and the existing endpoint,
Basic, SOAP action, strategy and opaque-session state are one fingerprinted authority. Every reread is
comparison-only. Deterministic races cover adapter, mapping, QName, binding revision, resource
rotation, action, endpoint and strategy mutation after composition and before dispatch; all produce
zero business network effects and never adopt B.

An operation without `typedComposedSoapRequest` bypasses the composer and sends
`AuthorizedConnectorExecution.Payload` unchanged. Historical composed-SOAP JSON and checksum do not
change, and no republish or rewrite is required.

## PostgreSQL least privilege

Migration `0014_typed_composed_soap_request_inputs.sql` replaces only the locator function body and
adds the exact `typedComposedSoapRequest.serverOwnedInputs[*].secretBinding` predicate. Runtime still
cannot enumerate locator rows or gain migration/admin privileges. Fresh apply and a second no-op
apply are part of the PostgreSQL 18 gate; the canonical hosted path exercises editor/distinct
approver, publication, grant, runtime locator, server-owned input resolution and real HTTPS.

## Automated evidence

- schema, canonical checksum, dependency and negative bounds:
  `Wave1_CT_typed_composed_SOAP_request_is_canonical_checksum_and_dependency_complete` and
  `Wave1_SEC_typed_composed_SOAP_schema_QName_bounds_auth_and_input_kinds_fail_closed`;
- public/architecture boundary:
  `Wave1_CT_typed_composed_request_has_no_new_bridge_or_arbitrary_body_binding_provider_or_transport_escape`;
- exact adapter/input registration and denial:
  `Wave1_SEC_typed_composed_request_adapter_and_inputs_match_exact_Published_operation_before_provider_or_transport`
  plus the duplicate/wrong-module startup matrix;
- canonical no-IVT hosted flow:
  `Wave1_IT_PRODUCTION_HOST_PostgreSQL_full_external_no_IVT_bridge_lifecycle_uses_real_Published_authority_and_HTTPS`;
- malformed, oversized, caller-envelope/spoof, retained-view, exception and cancellation negatives:
  the hosted lifecycle security assertions,
  `Wave1_SEC_typed_composed_adapter_exception_and_fake_cancellation_are_sanitized_with_zero_transport`
  and `Wave1_SEC_typed_composed_adapter_preserves_only_the_actually_cancelled_caller_token`;
- final freshness:
  `Wave1_SEC_external_bridge_typed_composed_SOAP_bound_to_A_denies_mutated_B_after_composition_before_dispatch`;
- legacy compatibility:
  `Wave1_E2E_PostgreSQL18_legacy_composed_profile_preserves_original_caller_envelope_without_republish_when_configured`.

Targeted worktree evidence is 31/31 composed/configuration unit tests, 41/41 ordinary hosted
execution-seam tests and 15/15 relevant architecture tests. The full local gate is also green:

- Release build with zero warnings/errors, `Gateway.Unit.Tests` 223/223 and the ordinary
  `Gateway.Integration.Tests` 158 PASS with 30 PostgreSQL-conditional skips;
- dedicated PostgreSQL 18.4 `Gateway.Integration.Tests` 188/188 with zero skips, migration `0014`
  fresh apply plus second no-op apply, explicit runtime least privilege and both canonical typed and
  historical legacy hosted paths;
- Admin 28/28 Vitest, API/runtime drift checks with the runtime negative control, production build,
  2/2 accessibility, 37/37 mock-browser and `FULLSTACK-01` 1/1 with redaction and cleanup;
- documentation and repository secret scans, full-history Gitleaks, vulnerable-package inventory,
  SPDX SBOM with 165 container packages, and the 423-file Core export clean-room
  build/test/frontend/license/boundary/secret gate.

Exact-head CI and the single independent Core security review remain handoff gates on the final PR;
merge is not authorized by this exception.

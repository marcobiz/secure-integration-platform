# Healthcare Wave 1 - Sistema TS connector implementation

Status: **CONNECTOR-LOCAL VALIDATION READY; BUSINESS DISPATCH BLOCKED BY CORE**

Baseline: `b1810eda7e96fabfc6e15e608d48867e96cd5a80`

## Placement

- Core-owned and reused unchanged: Basic authority, callback-only server-owned values, module
  loading/registration, typed session transport, authenticated admission, candidate handling,
  shared lifecycle, Published freshness and restricted transport.
- Sistema TS connector-owned: official XML names, namespaces, nesting, sequence, cardinality and
  facets; `RICETTA-DEM`/`EROGATORE`; create/checkToken result interpretation; SOAP actions; and
  operation-specific synthetic wire expectations.
- Healthcare shared: no new abstraction. There is not yet a second Healthcare connector with the
  same exact semantics.

The current composed SOAP capability dispatches the original authorized caller payload. It cannot
safely construct a body from caller-owned business fields plus Core-resolved server-owned bindings.
The pack does not work around this gap: it has no IVT, service locator, provider/store injection,
plaintext binding extraction, `HttpClient`, restricted-transport injection or Gateway.Api dependency.

`CORE_COMPOSITION_BLOCKER = STILL_OPEN`.

`NEW_CORE_PRIMITIVE_REQUIRED = YES`.

## Published operations

Only `session-create` is present in the immutable sample definition. It uses Core-owned Basic, the
typed create adapter, authenticated external admission and exact checkToken validation.

The four frozen business contracts remain represented by connector-local exact validators,
serializers and synthetic-server wire cases, but are not Published and cannot execute through the
module:

| Operation ID | Official action | Runtime status |
|---|---|---|
| `visualizza-erogato` | official `VisualizzaErogato` action | `BLOCKED_BY_CORE` |
| `invio-erogato` | official `InvioErogato` action | `BLOCKED_BY_CORE` |
| `sospendi-erogato` | official surprising `visualizzaerogato.../SospendiErogato` action | `BLOCKED_BY_CORE` |
| `annulla-erogato` | official `AnnullaErogato` action | `BLOCKED_BY_CORE` |

An invocation using any business operation ID fails before connector transport. Architecture and
hosted tests assert that the unsafe `ExecuteComposedSoapAsync`/raw-payload path is absent, session
generation is unchanged, and the synthetic business and generic counters remain zero.

## Executable evidence

- `SistemaTsPublicContractTests` validates all frozen request and response structures recursively,
  including exact QName, order, cardinality, simple/complex shape and frozen facets. Real XSD-derived
  negatives cover nested unexpected elements, children inside simple values, invalid sequence,
  missing required values and invalid lexical/value forms.
- checkToken uses XML Schema `dateTime` parsing and rejects culture-specific, slash-separated,
  RFC-1123 and space-separated non-XSD lexical forms.
- `HC_W1_SISTEMATS_IT_synthetic_server_asserts_exact_wire_and_negatives_for_every_business_operation`
  drives all four operation-specific requests over loopback HTTPS and asserts SOAP 1.1,
  `text/xml; charset=utf-8`, exact quoted SOAPAction, Basic, `Authorization2F`, nested XML,
  namespaces, values, counters and seven wire-policy negatives per operation. This is protocol-fixture
  evidence, not product business dispatch evidence.
- `HC_W1_SISTEMATS_IT_hosted_BGW1_create_admission_checkToken_and_business_operations_fail_closed`
  crosses hosted BGW1, grant and Published session-create, then proves all four unavailable business
  operation IDs cause zero business transport.
- `HC_W1_SISTEMATS_IT_PostgreSQL18_four_eyes_Published_admission_and_checkToken_execute_when_required`
  runs that admission-only path against PostgreSQL 18. The canonical PostgreSQL job restores,
  builds and runs the vertical project with `REQUIRE_SISTEMA_TS_POSTGRES_GATE=1`, so missing database
  configuration fails instead of skipping.

Existing named Wave 1 lifecycle, freshness, replay, redaction, timeout/cancellation and one-shot
suites remain prerequisite Core evidence; this connector consumes those boundaries without
duplicating them.

`SERVER_OWNED_BUSINESS_FIELDS = BLOCKED_BY_CORE`.

`BUSINESS_SOAP = BLOCKED_BY_CORE`.

`POSTGRESQL_FULL_BUSINESS_E2E = BLOCKED_BY_CORE`.

The deterministic synthetic evidence is not accreditation, production provisioning or live
Sistema TS conformance.

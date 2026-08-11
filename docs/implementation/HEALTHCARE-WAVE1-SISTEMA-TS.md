# Healthcare Wave 1 - Sistema TS connector implementation

Status: **IMPLEMENTATION_READY; exact-head CI and independent connector review pending**

Baseline: `b1810eda7e96fabfc6e15e608d48867e96cd5a80`

## Placement

- Core-owned and reused unchanged: Basic authority, callback-only server-owned values, module
  loading/registration, typed session transport, authenticated admission, candidate handling,
  shared lifecycle, freshness and composed restricted SOAP.
- Sistema TS connector-owned: official XML names and nesting, `RICETTA-DEM`/`EROGATORE`, create and
  checkToken result interpretation, business QName/cardinality catalog, SOAP actions and no-retry
  classification.
- Healthcare shared: no new abstraction. There is not yet a second Healthcare connector with the
  same exact semantics.

`NEW_CORE_PRIMITIVE_REQUIRED = NO`. The pack has no IVT, service locator, provider/store injection,
`HttpClient` or Gateway.Api dependency.

## Published operations

| Operation ID | Official action | Authentication | Retry |
|---|---|---|---|
| `session-create` | `.../create` | Core-owned Basic + typed handshake | none |
| `visualizza-erogato` | official `VisualizzaErogato` action | Basic + `Authorization2F: Bearer` | none |
| `invio-erogato` | official `InvioErogato` action | same composed authority | none |
| `sospendi-erogato` | official surprising `visualizzaerogato.../SospendiErogato` action | same | none |
| `annulla-erogato` | official `AnnullaErogato` action | same | none |

The immutable sample definition binds endpoints, credentials, adapter IDs/types, input names,
SOAP metadata and exact extension configuration. Callers supply only the bounded SOAP business
body; endpoint, header, action, credential and session selectors have no authority.

## Executable evidence

- `SistemaTsPublicContractTests`: module/metadata, canonical definition and exact nested
  create/checkToken response semantics. The hosted authority independently rejects any create or
  checkToken request whose QName, order or server-owned value differs.
- `HC_W1_SISTEMATS_IT_hosted_BGW1_create_admission_checkToken_and_business_use_one_shared_session`:
  hosted BGW1 and real HTTPS path, caller spoof attempts, exact wire counters, generation reuse and
  redaction.
- `HC_W1_SISTEMATS_IT_PostgreSQL18_four_eyes_Published_hosted_full_lifecycle`: same path with editor,
  distinct approver, real PostgreSQL 18 Published store and least-privilege runtime lease.
- Existing named Wave 1 handshake, admission, composed SOAP and execution-seam race suites qualify
  cross-context replay, expiry/rotate/disable, A-to-B stale zero-effect, provider failures and
  caller-cancellation versus product timeout on the reused Core boundary.

This is deterministic product evidence against a synthetic authority. It is not accreditation,
production provisioning or live Sistema TS conformance.

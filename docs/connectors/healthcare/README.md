# Healthcare connector characterization

This directory contains public-safe characterization, official-source freezes, synthetic test guidance,
the Wave 1 Regional ePrescription foundation and the connector-local Sistema TS contract
implementation. Sistema TS business dispatch remains blocked by the Core composed-body gap.

## Package contents

- [Complete integration inventory](integration-inventory.md)
- [Protocol matrix](protocol-matrix.md)
- [Execution-location matrix](execution-location-matrix.md)
- [Minimal authentication primitives](auth-primitives-required.md)
- [Clean-implementation provenance](provenance.md)
- [Implementation waves and GO/NO-GO](M6-IMPLEMENTATION-PLAN.md)
- [Regional ePrescription Wave 1 foundation](regional-eprescription/README.md)
- [Sistema TS ePrescription Wave 1 official registry](sistema-ts-eprescription/official-source-registry.md)
- [Sistema TS ePrescription Wave 1 specification freeze](sistema-ts-eprescription/spec.md)
- [Sistema TS immutable Published definition](sistema-ts-eprescription/sistema-ts.connector.json)
- Connector specifications:
  - [SOGEI Basic + session](sogei-basic-session/spec.md)
  - [Lombardia OAuth helper](lombardia-oauth-helper/spec.md)
  - [FVG PKCE + JWT](fvg-pkce-jwt/spec.md)
  - [Umbria mTLS + dual JWT](umbria-mtls-jwt/spec.md)
- Synthetic vectors: `tests/characterization/healthcare`

`KNOWN` is a historical characterization label, not current official or live-verified evidence. The
Sistema TS Wave 1 source questions are resolved from current public material. Qualified baseline
`b1810ed` supplies module-owned adapter registration and exact callback-only server-owned inputs for
create/checkToken, plus admission and the shared lifecycle. The current composed SOAP primitive does
not safely combine caller business data with Core-resolved server-owned fields, so business
publication and execution fail closed and require a new Core typed composed-body capability. The
vertical does not duplicate provider, secret, transport or session authority. Other production
profiles remain `NEEDS_PUBLIC_SOURCE` and NO-GO until their own unresolved questions are closed.

# Healthcare connector characterization

This directory contains public-safe characterization, official-source freezes, synthetic test guidance
and the Wave 1 Regional ePrescription foundation. No production healthcare connector is implemented.

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
- Connector specifications:
  - [SOGEI Basic + session](sogei-basic-session/spec.md)
  - [Lombardia OAuth helper](lombardia-oauth-helper/spec.md)
  - [FVG PKCE + JWT](fvg-pkce-jwt/spec.md)
  - [Umbria mTLS + dual JWT](umbria-mtls-jwt/spec.md)
- Synthetic vectors: `tests/characterization/healthcare`

`KNOWN` is a historical characterization label, not current official or live-verified evidence. The Sistema TS Wave 1 source questions are resolved from current public material. Baseline `3f8667b` also provides external admission, shared lifecycle, composed SOAP and the provider-neutral execution seam. The connector is nevertheless `NOT_READY`: the production module seam does not register compiled handshake adapters and the typed request context has no provider-resolved source for the official STS identity fields. Supplying those values from the caller, hardcoding them or reading provider secrets directly in Healthcare would violate the qualified custody boundary. Other production profiles remain `NEEDS_PUBLIC_SOURCE` and NO-GO until their own unresolved questions are closed.

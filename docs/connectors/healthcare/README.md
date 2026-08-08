# Healthcare connector characterization

This directory contains public-safe characterization, synthetic guidance and the Wave 1 Regional
ePrescription foundation. No production regional connector is implemented.

## Package contents

- [Complete integration inventory](integration-inventory.md)
- [Protocol matrix](protocol-matrix.md)
- [Execution-location matrix](execution-location-matrix.md)
- [Minimal authentication primitives](auth-primitives-required.md)
- [Clean-implementation provenance](provenance.md)
- [Implementation waves and GO/NO-GO](M6-IMPLEMENTATION-PLAN.md)
- [Regional ePrescription Wave 1 foundation](regional-eprescription/README.md)
- Connector specifications:
  - [SOGEI Basic + session](sogei-basic-session/spec.md)
  - [Lombardia OAuth helper](lombardia-oauth-helper/spec.md)
  - [FVG PKCE + JWT](fvg-pkce-jwt/spec.md)
  - [Umbria mTLS + dual JWT](umbria-mtls-jwt/spec.md)
- Synthetic vectors: `tests/characterization/healthcare`

`KNOWN` is a historical characterization label, not current official or live-verified evidence. Each production profile remains `NEEDS_PUBLIC_SOURCE` and NO-GO until its unresolved questions are closed with current official provenance.

# Healthcare connector characterization

This directory is the decision package for the authorized M6 Healthcare Characterization workstream. It contains specifications and synthetic test guidance only; no production connector or authentication module is implemented.

## Package contents

- [Complete integration inventory](integration-inventory.md)
- [Protocol matrix](protocol-matrix.md)
- [Execution-location matrix](execution-location-matrix.md)
- [Minimal authentication primitives](auth-primitives-required.md)
- [Clean-implementation provenance](provenance.md)
- [Implementation waves and GO/NO-GO](M6-IMPLEMENTATION-PLAN.md)
- Connector specifications:
  - [SOGEI Basic + session](sogei-basic-session/spec.md)
  - [Lombardia OAuth helper](lombardia-oauth-helper/spec.md)
  - [FVG PKCE + JWT](fvg-pkce-jwt/spec.md)
  - [Umbria mTLS + dual JWT](umbria-mtls-jwt/spec.md)
- Synthetic vectors: `tests/characterization/healthcare`

`KNOWN` means explicitly present in supplied authorized material; it does not mean current official or live-verified. Each production profile remains NO-GO until its specification's unresolved questions are closed with provenance.

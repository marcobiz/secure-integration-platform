# Healthcare public-source and clean-room policy

## Publication boundary

This public repository may contain only:

- current or historical official specifications and public standards;
- provider-neutral product architecture;
- independently authored synthetic fixtures and negative tests;
- public-safe characterization hypotheses that are clearly marked as not implementation-ready.

Customer-specific reverse engineering, migration assessments, proprietary module inventories, restricted reports, recovered artifacts and customer prioritization are not valid public sources and must not be committed here.

## Public source register

| Source ID | Public source | Permitted use |
|---|---|---|
| PUB-FSE2 | [Ministero della Salute FSE 2.0 Gateway](https://github.com/ministero-salute/it-fse-support) | Current national FSE producer lifecycle, subject to version review |
| PUB-RX-MFA | [Decreto 27 febbraio 2025, GU n. 57/2025](https://www.gazzettaufficiale.it/atto/vediMenuHTML?atto.codiceRedazionale=25A01494&atto.dataPubblicazioneGazzetta=2025-03-10&tipoSerie=serie_generale&tipoVigenza=originario) | SAC/SAR architecture and multi-factor requirement |
| PUB-VETINFO | [VetInfo public help](https://www.vetinfo.it/help/farmaco/help/fornitura) | Public veterinary supply workflow only; not credential onboarding |
| PUB-ADR | Repository ADRs | Product boundaries, execution location and provider separation |
| PUB-SYNTH | `tests/characterization/healthcare/**` | Synthetic boundary tests only; never evidence of external conformance |

The regional profile candidates in this directory do not currently have a complete public official source pack. They remain `NEEDS_PUBLIC_SOURCE` and `NO-GO` for production implementation until the applicable authority specification, onboarding policy and conformance material are reviewed and recorded.

## Evidence labels

| Label | Meaning |
|---|---|
| `OFFICIAL_CURRENT` | Supported by a current authoritative public source |
| `OFFICIAL_HISTORICAL` | Supported by an authoritative historical source but not assumed current |
| `SYNTHETIC` | Independently authored fixture or policy used to test a product boundary |
| `INFERRED` | Provider-neutral design conclusion derived from public evidence and repository ADRs |
| `NEEDS_PUBLIC_SOURCE` | Characterization hypothesis that cannot support production work or a conformance claim |
| `UNKNOWN` | Not established by allowed public evidence |

`KNOWN` in older characterization tables means only that a hypothesis was recorded at the time. It must not be interpreted as official, current or implementation-authorizing evidence.

## Clean-room rule

Implementation writers must use public official specifications, public standards and independent synthetic vectors. They must not use proprietary source, decompiled behavior, customer topology, private endpoints, credentials, private certificate material, captured clinical traffic or customer-specific migration analysis.

No caller may supply tenant authority, endpoint, credential reference, certificate reference, issuer, audience, scope, header or algorithm as an authorization decision. All such bindings remain server-owned and policy-controlled.

## Writer handoff gate

A healthcare connector may start only when:

1. its current official WSDL/OpenAPI/schema and version are recorded;
2. auth, certificate/key ownership and onboarding are established;
3. test and production environments are classified;
4. fault, retry, idempotency and reconciliation behavior is known;
5. public conformance examples or independent synthetic vectors exist;
6. threat-model and traceability changes are approved.

Until then, only provider-neutral authentication primitives and synthetic boundary tests are allowed.

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
| PUB-LOM-RX | [SISS Ricetta Elettronica](https://www.siss.regione.lombardia.it/wps/portal/site/siss/il-sistema-informativo-socio-sanitario/principali-servizi-offerti/ricetta-elettronica) and [SISS A2A](https://siss.regione.lombardia.it/wps/portal/site/siss/il-sistema-informativo-socio-sanitario/piattaforma-siss/integrazione-application-to-application) | Current public process/A2A characterization only; insufficient for a production profile |
| PUB-ER-RX | [Regione Emilia-Romagna Rete SOLE](https://salute.regione.emilia-romagna.it/ssr/organizzazione/aziende-sanitarie-irccs/rete-sole), [Lepida white prescriptions](https://www.lepida.net/news/2022-03/anche-ricette-bianche-disponibili-online-fse) and [historical DGR 930/2013](https://salute.regione.emilia-romagna.it/normativa-e-documentazione/leggi-atti/regionali/delibere/specialistica-ambulatoriale/dgr-930-2013) | Current process plus historical lifecycle characterization; insufficient for a production profile |

The regional profile candidates in this directory do not currently have a complete public official source pack. Lombardia and Emilia-Romagna were re-reviewed on 2026-08-08 and remain `BLOCKED_BY_SPEC` and `NO-GO` for production implementation. The applicable current authority specification, onboarding policy and conformance material must be reviewed and recorded before either profile can move to implementation.

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

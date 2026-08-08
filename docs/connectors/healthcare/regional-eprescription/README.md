# Regional ePrescription foundation — Wave 1

## Result

The public Healthcare Pack now contains a compiled regional ePrescription foundation. It does not
contain a supported Lombardia or Emilia-Romagna production profile.

| Deliverable | Status |
|---|---|
| Common business API | Implemented for `prescription.lookup` and `prescription.dispense` only |
| Server-owned profile routing | Implemented, fail-closed |
| Controlled profile-specific fields | Implemented as an exact compiled server-owned scalar schema allowlist |
| Normalized errors | Implemented with a compiled server-owned regional safe-code allowlist |
| Lombardia profile | `BLOCKED_BY_SPEC` |
| Emilia-Romagna profile | `BLOCKED_BY_SPEC` |
| Live regional conformance | Not performed and not claimed |

Implementation details are in the [implementation plan](../../../implementation/HEALTHCARE-WAVE1-REGIONAL-EPRESCRIPTION.md)
and local evidence is in the [test report](../../../testing/HEALTHCARE-WAVE1-REGIONAL-EPRESCRIPTION-REPORT.md).

## Official sources reviewed

Reviewed on 2026-08-08. `OFFICIAL_CURRENT` means the page was current and authority-owned when
reviewed; it does not mean the page contains a complete connector contract.

| ID | Status | Source | What it supports | What it does not support |
|---|---|---|---|---|
| RX-LOM-01 | `OFFICIAL_CURRENT` | [SISS — Ricetta Elettronica](https://www.siss.regione.lombardia.it/wps/portal/site/siss/il-sistema-informativo-socio-sanitario/principali-servizi-offerti/ricetta-elettronica) | Regional prescription and dispensing process; identification by NRE; communication of dispensing to SISS/SAC | Current pharmacy API, auth, endpoints, payloads, faults, token/scopes or accreditation |
| RX-LOM-02 | `OFFICIAL_CURRENT` | [SISS — Application-to-Application integration](https://siss.regione.lombardia.it/wps/portal/site/siss/il-sistema-informativo-socio-sanitario/piattaforma-siss/integrazione-application-to-application) | General SISS API Manager/A2A and server-side process-token model | A prescription-specific OAuth/helper profile or operation mapping |
| RX-LOM-03 | `OFFICIAL_CURRENT` | [SISS — Architectural model](https://siss.regione.lombardia.it/wps/portal/site/siss/il-sistema-informativo-socio-sanitario/piattaforma-siss/Modello-architetturale) | General web-service and workstation/application topology | Current ePrescription wire and accreditation contract |
| RX-LOM-04 | `OFFICIAL_HISTORICAL` | [SISS public document catalogue](https://www.siss.regione.lombardia.it/EdmaSissPortaleSitoWebPublic/documentoDiProgetto.jsp) | Public catalogue contains historical prescription material | No reviewed document closes the current-profile gaps |
| RX-ER-01 | `OFFICIAL_CURRENT` | [Regione Emilia-Romagna — Rete SOLE](https://salute.regione.emilia-romagna.it/ssr/organizzazione/aziende-sanitarie-irccs/rete-sole) | SOLE exchanges pharmaceutical and specialist prescriptions | Current A2A protocol, auth, endpoints, operations, faults or onboarding |
| RX-ER-02 | `OFFICIAL_CURRENT` | [Lepida — electronic white prescriptions](https://www.lepida.net/news/2022-03/anche-ricette-bianche-disponibili-online-fse) | SAR/SAC relation and pharmacy viewing/dispensing at process level | General SSN pharmacy wire profile, Basic/session placement or current endpoint |
| RX-ER-03 | `OFFICIAL_HISTORICAL` | [Regione Emilia-Romagna DGR 930/2013](https://salute.regione.emilia-romagna.it/normativa-e-documentazione/leggi-atti/regionali/delibere/specialistica-ambulatoriale/dgr-930-2013) | Historical SAR/SOLE prescription lifecycle and NRE context | Current 2026 application contract or authentication profile |
| RX-MFA-01 | `OFFICIAL_CURRENT` | [Decreto MEF 27 February 2025](https://www.gazzettaufficiale.it/atto/vediMenuHTML?atto.codiceRedazionale=25A01494&atto.dataPubblicazioneGazzetta=2025-03-10&tipoSerie=serie_generale&tipoVigenza=originario) | Current national multi-factor requirement and SAR/SAC context | Either region's exact connector integration profile |

No customer research, private endpoint, legacy scope, credential, captured payload or restricted
document was read or committed.

## Commonality analysis

| Candidate concept | Lombardia | Emilia-Romagna | Foundation decision |
|---|---|---|---|
| Prescription reference | NRE identification is stated | NRE/SAR lifecycle is stated in official regional material | Common opaque `PrescriptionReference`; no region-specific format validation |
| Lookup/view | Prescription identification is stated | Pharmacy viewing is stated | Common `PrescriptionLookupRequest/Result` |
| Dispensing | Communication of dispensing is stated | Pharmacy dispensing/processing is stated | Common `DispenseRequest/Outcome` |
| Take-in-charge | Not sufficiently characterized for the pharmacy profile | Not sufficiently characterized as the same semantic transition | Excluded |
| Cancellation | Current operation contract absent | Current operation contract absent | Excluded |
| Reconciliation | Current contract absent | Current contract absent | Excluded |
| Workflow/correlation | Profile topology absent | Profile topology absent | Profile-specific and blocked |
| Server-owned routing | Required by repository security architecture | Required by repository security architecture | Common resolver over authenticated principal and Published configuration |

## Common API

The caller supplies only a business command containing an opaque prescription reference and
bounded scalar extension values that are later validated against an exact server-owned schema. It
cannot supply Tenant, profile, region, endpoint, route, auth policy, credential or secret
reference.

Before Published resolution, the provider-neutral Core authorizer consumes the already-authenticated
principal, checks active state and the exact operation grant independently of whether the operation
uses credentials, and produces an opaque `AuthorizedGatewayInvocation`. The Healthcare Pack never
reads certificate material or accesses `IGatewayRegistry`. The production adapter then resolves a
validated Published snapshot from the real `IConnectorConfigurationStore` using the authenticated
Installation/Tenant/Application/operation
access context and canonical `OperationBindingDependencies`. The runtime builds a logical
`RegionalEPrescriptionProfileBinding` from that snapshot and verifies exact
Tenant/Application/operation authority, profile availability, compiled endpoint/auth/credential
authority, the extension schema, the safe-code allowlist, and the current length-prefixed complete
binding fingerprint/resource stamp,
then creates a non-caller-constructible `RegionalEPrescriptionExecution` for a compiled profile
dispatcher. The execution contains only the exact logical endpoint, auth-policy and credential
binding IDs selected by the Published profile; it contains no secret value or provider locator.

## Operation mapping

| Common operation | Lombardia wire mapping | Emilia-Romagna wire mapping |
|---|---|---|
| `prescription.lookup` | `BLOCKED_BY_SPEC` — API/schema/action not current and complete | `BLOCKED_BY_SPEC` — A2A operation/schema/action not current and complete |
| `prescription.dispense` | `BLOCKED_BY_SPEC` — request/outcome/fault/idempotency contract missing | `BLOCKED_BY_SPEC` — request/outcome/fault/idempotency contract missing |

No take-in-charge, cancellation or reconciliation operation exists in the common API.

## Authentication composition

| Profile | Status | Decision |
|---|---|---|
| Lombardia | `BLOCKED_BY_SPEC` | General SISS A2A/API Manager material is not enough to bind the M6 OAuth writer. No helper/callback, grant, client auth, scope, PKCE, token lifecycle or accreditation policy is implemented. |
| Emilia-Romagna | `BLOCKED_BY_SPEC` | No current official A2A contract confirms the historical SOAP/Basic/session hypothesis. No SPID/CIE/CNS login is added to Gateway; an external interaction reference may be composed only after the official session contract is available. |

## Synthetic servers and security evidence

`SyntheticLombardiaEPrescriptionServer` and
`SyntheticEmiliaRomagnaEPrescriptionServer` are test-only loopback HTTPS sentinels using
runtime-generated, short-lived certificates. Because both profiles are blocked, they expose no
invented regional operation contract. The test pins each runtime certificate for a real loopback
TLS health handshake, then proves profile resolution fails before business dispatch and both
servers receive zero business requests.

Named tests cover:

- common-model, bounded-input and server-owned extension-schema validation;
- opaque Core state/grant authorization and Published-store adapter authority derivation,
  including grant-missing, cross-Tenant, suspended Installation and an exact
  no-credential operation;
- absence of caller-selectable profile/region/endpoint/auth/credential/route/Tenant fields;
- profile A endpoint/auth isolation from profile B;
- cross-Tenant authority mismatch denial before dispatch;
- disabled and stale/rotated complete binding denial;
- immutable credential/schema snapshots;
- normalized resolver/stamp/dispatcher error and reference redaction;
- malformed nested command/response null denial and regional-code allowlisting;
- profile response type/reference/extension-schema/safe-code/enum-domain mismatch denial;
- Core-to-Healthcare dependency denial and absence of regional domain identifiers in Gateway
  Core;
- denial of certificate/registry identity reinterpretation inside the Healthcare Pack;
- both blocked regional HTTPS sentinels at zero requests.

OAuth/SOAP integration, callback/session correlation, profile-specific restricted egress and
regional response/fault mapping are `BLOCKED_BY_SPEC`; the already-qualified M6 generic auth
regressions remain applicable but are not presented as regional conformance.

## GO / NO-GO

- **GO** for the provider-neutral Regional ePrescription foundation inside the Healthcare Pack.
- **GO** to request and review current official technical/onboarding packages independently for
  each region.
- **NO-GO** to publish Lombardia or Emilia-Romagna as supported.
- **NO-GO** for live use, accreditation, a regional endpoint binding, or a private-preview pilot.

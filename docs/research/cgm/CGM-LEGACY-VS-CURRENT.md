# CGM legacy versus current official target

## Regole

- `CURRENT_AND_REQUIRED`: capability ancora necessaria; il protocollo va comunque riaccreditato.
- `CURRENT_BUT_SHOULD_USE_NEW_OFFICIAL_API`: funzione valida, seam legacy da sostituire con il target nazionale corrente.
- `LEGACY_TRANSITIONAL`: percorso alternativo/fallback da ritirare dopo migrazione.
- `OBSOLETE`: solo con prove di non-reachability o sostituzione; il nome non basta.
- `UNKNOWN`: manca evidenza sul contratto corrente.

## Matrice

| Seam group | Legacy observed implementation | Current official target | Classificazione | Effetto sul catalogo SIP | Provenance |
|---|---|---|---|---|---|
| W-01, D-01 | SOAP SAC, Basic, sessione/OTP | SAC/SAR restano l'architettura ricetta SSN; decreto 2025 richiede due o più fattori | `CURRENT_AND_REQUIRED` | Costruire connector Sistema TS, non assorbire la ricetta nel FSE2 | `LEGACY_CODE_*`, `OFFICIAL_CURRENT` |
| W-02..W-08, D-02..D-05 | Adapter SAR specifici | SAR regionali/provinciali restano parte dell'architettura ufficiale | `CURRENT_AND_REQUIRED` | Shared prescription core + profili solo dove i contract coincidono | `LEGACY_CODE_*`, `OFFICIAL_CURRENT` |
| W-09..W-14, D-06, D-08, D-10 | REST o XDS regionali per search/retrieve | Nessuna API GTW producer equivalente | `CURRENT_AND_REQUIRED`, D-10 `UNKNOWN` sul target esatto | Regional FSE consumer resta separato | `LEGACY_CODE_*`, `OFFICIAL_CURRENT` |
| D-07, D-09 | Publication e metadata update regionali | GTW 2.23: validate/create/replace/delete/metadata/status | `CURRENT_BUT_SHOULD_USE_NEW_OFFICIAL_API` | Eliminare due seam producer regionali in favore di FSE2 | `LEGACY_CODE_DRCLOUD`, `OFFICIAL_CURRENT` |
| D-11 | Validazione FSE2 mediata CGM | GTW 2.23 diretto | `CURRENT_AND_REQUIRED` | Estendere da validate all'intero lifecycle ufficiale | `LEGACY_CODE_DRCLOUD`, `OFFICIAL_CURRENT` |
| W-15 | VetInfo REST con OAuth password grant | VetInfo corrente espone workflow di fornitura/web services; auth va riaccreditata | `CURRENT_BUT_SHOULD_USE_NEW_OFFICIAL_API` | Conservare capability, scartare il grant legacy | `LEGACY_CODE_WINGESFAR`, `OFFICIAL_CURRENT` |
| W-16 | Alternativa veterinaria Sogei SOAP | API VetInfo diretta | `LEGACY_TRANSITIONAL` | Ritirare dopo cutover W-15 | `LEGACY_CODE_WINGESFAR`, `INFERRED` |
| W-17, W-18 | TS 730 diretto e mediazione Promofarma | Servizio nazionale separato dal FSE2 | `CURRENT_AND_REQUIRED`; mediazione W-18 da confermare | Un connector TS con eventuale compatibility profile | `LEGACY_CODE_WINGESFAR`, `NEEDS_CHARACTERIZATION` |
| W-19 | WebDPC REST | DPC resta regionale/vendor-specific | `CURRENT_AND_REQUIRED` | `DpcAdapter`, non FSE2 | `LEGACY_CODE_WINGESFAR` |
| W-20, W-21 | WebCare/GOpenCare/GPack | Assistenza integrativa resta regionale/vendor-specific | `CURRENT_AND_REQUIRED` | Shared core solo per contratti realmente comuni | `LEGACY_CODE_WINGESFAR` |
| W-22 | Enerj/CGM mediator NSO | NSO nazionale, ma accesso diretto non provato | `CURRENT_AND_REQUIRED` come funzione; target `UNKNOWN` | Mantenere mediatore inizialmente; non inventare direct connector | `LEGACY_CODE_WINGESFAR`, `NEEDS_CHARACTERIZATION` |
| D-12 | Abruzzo vaccination set/delete | API regionale | `CURRENT_AND_REQUIRED` | Profilo Abruzzo; ONIT altri profili non ancora attivi | `LEGACY_CODE_DRCLOUD` |
| D-13 | Sistema TS malattia | Servizio nazionale separato | `CURRENT_AND_REQUIRED`, contract corrente `UNKNOWN` | `Other` on demand dopo specifiche | `LEGACY_CODE_DRCLOUD`, `NEEDS_CHARACTERIZATION` |
| D-14 | Lombardia assistiti/esenzioni | Servizio regionale | `CURRENT_AND_REQUIRED` | `Other` on demand | `LEGACY_CODE_DRCLOUD` |
| W-23, D-15 | Backend/trace/cataloghi CGM | Nessun replacement ufficiale | `CURRENT_AND_REQUIRED` per il prodotto, `DO_NOT_MIGRATE` in SIP | Restano CGM | `LEGACY_CODE_*` |

## Cosa FSE 2.0 rende superfluo

**Due seam su 38:** D-07 e D-09. Sono producer regionali che il lifecycle nazionale GTW può sostituire, previa verifica dei document type e dell'accreditamento CGM.

Non diventano superflui:

- ricerca e recupero FSE regionale;
- ricetta/dispensazione SAC/SAR;
- VetInfo;
- Sistema TS spese sanitarie;
- DPC, WebCare, vaccinazioni, certificati malattia;
- consensi regionali non esposti dal GTW.

## Consolidamento connector

| Pattern | Evidenza di comunanza | Decisione |
|---|---|---|
| Sistema TS/Sogei prescription | Operation family e fault model condivisi tra Wingesfar e drCLOUD | `SistemaTSEPrescriptionConnector` con ruoli prescriber/dispenser |
| Regional ePrescription | Modello ricetta comune ma auth, MFA, DCR e operazioni divergono | `RegionalEPrescriptionCore` minimo + profili Lombardia, Emilia-Romagna, Veneto, Bolzano, Trento, Puglia, Piemonte, Liguria |
| Regional FSE consumer | Search/retrieve comune; REST, XDS, consensi e security divergono | `RegionalFseConsumerCore` + profili, senza un mega-contract |
| XDS Sardegna/Bolzano | Primitive XDS/SAML/WS-Security condivise, semantica diversa | Riutilizzare transport/security, non forzare lo stesso connector |
| DPC/WebCare | Workflow di erogazione correlati ma sistemi e stati diversi | Due adapter separati |
| GOpenCare/GPack/celiachia | Login/sessione/reporting comuni in parte | Shared client core solo dopo contract diff e vector |
| ONIT vaccination | Client multi-regione compilato suggerisce riuso vendor | Un `VaccinationAdapter` con profili solo dopo prova di registration/tenant |
| SISS/SOLE/SORESA/DOGE/SIRPED/SIAVr | Nomi/piattaforme ricorrenti nel corpus | Nessun connector autonomo senza call chain e specifica corrente |

## Dead code e confidence

Nessun componente healthcare è dichiarato `DEAD` con confidence alta. I casi più vicini sono:

- configurazioni mock/local/test: `OBSOLETE` per produzione, confidence alta;
- duplicato runtime `eprescriptionNoDotNet452`: compatibility-only, confidence alta;
- Umbria FSE v1 STS/SAML: probabile fallback superseded, confidence media;
- client drCLOUD compilati ma non registrati: `UNKNOWN/NEEDS_CHARACTERIZATION`, non dead;
- Fido Sogei: transitional, ma ancora presente come route alternativa.

Per dichiarare dead i candidati servono feature registration/tenant manifest, factory selection e trace sanitizzate sul processo AOT.

## Official-current guardrail

La baseline FSE è il README ufficiale Gateway 2.23. Le fonti regionali dettagliate non sono uniformemente pubbliche: prima di implementare un profilo regionale occorrono specifica corrente, onboarding/accreditamento e test environment autorizzato. Il PDF fornito descrive i profili osservati ma non sostituisce una fonte ufficiale.

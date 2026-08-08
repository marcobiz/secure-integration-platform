# CGM integration seam map

Questa è la mappa decisionale canonica. Conta confini migrabili, non endpoint né operazioni: **38 seam confermate**. Gli artefatti compilati senza registration/call reference sono esclusi e restano `NEEDS_CHARACTERIZATION` nell'inventario.

## Legenda

- Stato: `S` stateless per richiesta; `T` token/sessione; `W` workflow persistente; `U` interazione utente.
- Locale: `-` nessun requisito intrinseco; `cert` store/key locale osservato ma potenzialmente migrabile; `card/VPN` requisito locale provato; `file` scambio file legacy sostituibile.
- Difficulty: `L`, `M`, `H`, `VH`.
- La colonna “drCLOUD” indica coinvolgimento nel percorso corrente, non mera presenza della stessa capability nel prodotto.

## Seam Wingesfar

| ID | Legacy module | Business capability | Current caller | drCLOUD | External system | Auth | State | Local dependency | Official current replacement | SIP target | Difficulty | Priority | Provenance |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| W-01 | ePrescription Sogei | Ricetta SSN/RBE: lookup, carico, erogazione, sospensione, annullo, report | Wingesfar | No | Sistema TS SAC | Basic + sessione/MFA | T,U,W | - | SAC/SAR con MFA | `SistemaTSEPrescriptionConnector` | H | P0 | `LEGACY_CODE_WINGESFAR`, `OFFICIAL_CURRENT` |
| W-02 | ePrescription Lombardia | Ricetta regionale e token helper | Wingesfar | No | Lombardia SAR | OAuth authorization code, bearer | T,U,W | browser callback | SAR Lombardia corrente da accreditare | `RegionalEPrescriptionAdapter` | H | P0 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-03 | ePrescription Veneto | Ricetta, OTP, DCR/archive | Wingesfar | No | Veneto SAR | mTLS, SAML/WS-Security, OTP | T,U,W | cert | SAR Veneto corrente da accreditare | `RegionalEPrescriptionAdapter` | VH | P1 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-04 | ePrescription SOLE | Ricetta/lista/consenso | Wingesfar | No | Emilia-Romagna SOLE/SAR | Basic + sessione da SPID/CIE/CNS | T,U,W | - | SAR Emilia-Romagna corrente da accreditare | `RegionalEPrescriptionAdapter` | H | P0 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-05 | ePrescription Bolzano | Ricetta e batch | Wingesfar | No | Alto Adige SAR | OAuth client credentials, bearer, mTLS | T,W | cert | SAR provinciale corrente da accreditare | `RegionalEPrescriptionAdapter` | H | P1 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-06 | ePrescription Trento | Ricetta, consenso, distinta/report | Wingesfar | No | Trentino SAR | Basic, HMAC, sessione | T,U,W | - | SAR provinciale corrente da accreditare | `RegionalEPrescriptionAdapter` | H | P1 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-07 | ePrescription Puglia | Ricetta, DCR, RBE, consenso | Wingesfar | No | Puglia SIST | VPN, smartcard/PIN, XML-DSig/WS-Security | T,U,W | card/VPN | SIST/SAR corrente; caratterizzazione produzione obbligatoria | `RegionalEPrescriptionAdapter` | VH | P1 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-08 | ePrescription Piemonte | Liste/deleghe farmacia e supporto ricetta | Wingesfar | No | Piemonte SAR | Credenziali/sessione regionali | T,U | - | SAR Piemonte corrente da accreditare | `RegionalEPrescriptionAdapter` | H | P1 | `LEGACY_CODE_WINGESFAR` |
| W-09 | WgFse Lombardia | Ricerca/recupero FSE | Wingesfar | No | Lombardia FSE | OAuth authorization code, bearer | T,U | browser callback | FSE consumer regionale | `RegionalFseConsumerAdapter` | H | P0 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-10 | WgFse Bolzano | Identità/attributi, consensi, ricerca/recupero | Wingesfar | No | Alto Adige FSE | STS/SAML, WS-Security, mTLS | T,U | cert | FSE consumer provinciale | `RegionalFseConsumerAdapter` | VH | P1 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-11 | WgFse FVG | Login e ricerca/recupero | Wingesfar | No | FVG FSE | OAuth authorization code + PKCE, JWT RS256 | T,U | browser callback, cert | FSE consumer regionale | `RegionalFseConsumerAdapter` | H | P1 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-12 | WgFse Liguria | Consensi, ricerca/recupero, prescrizione | Wingesfar | No | Liguria FSE | Bearer fisso legacy, mTLS, cifratura identificativo | T | cert | FSE consumer regionale; auth corrente da confermare | `RegionalFseConsumerAdapter` | VH | P1 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-13 | WgFse Umbria | Ricerca/recupero, consenso/disclosure | Wingesfar | No | Umbria FSE | mTLS + dual JWT RS256 | T | cert | FSE consumer regionale | `RegionalFseConsumerAdapter` | H | P1 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-14 | WgFse Sardegna | Query/recupero XDS | Wingesfar | No | Sardegna FSE | SAML/WS-Security, mTLS | T | cert | FSE consumer regionale | `RegionalFseConsumerAdapter` | VH | P2 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-15 | Fido MdS | Ricerca e fornitura veterinaria, rettifica, annullo, PDF | Wingesfar | No | VetInfo | OAuth password grant legacy, bearer | T,W | - | API VetInfo corrente e nuovo profilo di accreditamento | `VetInfoConnector` | H | P1 | `LEGACY_CODE_WINGESFAR`, `OFFICIAL_CURRENT` |
| W-16 | Fido Sogei | Alternativa veterinaria SOAP | Wingesfar | No | Sogei/VetInfo | SOAP Basic | S,W | - | API VetInfo corrente | `VetInfoConnector` | M | P2 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-17 | ServiziSS730P | Invio/modifica/stato/ricevuta spese | Wingesfar | No | Sistema TS spese sanitarie | Basic oppure mTLS/CNS | S,W | cert opzionale, file | API Sistema TS corrente da accreditare | `SistemaTSHealthExpensesConnector` | H | P1 | `LEGACY_CODE_WINGESFAR` |
| W-18 | PromofarmaService | Spese sanitarie e flussi DCR mediati | Wingesfar | No | Promofarma/Federfarma | Credenziali + token/sessione | T,W | file | Confermare mediazione corrente vs accesso TS diretto | `SistemaTSHealthExpensesConnector` | H | P2 | `LEGACY_CODE_WINGESFAR` |
| W-19 | WgDPC WebDPC | Verifica/conferma, dettaglio, erogazione, riapertura, AIFA | Wingesfar | No | WebDPC | Username/password → token | T,W | - | Piattaforma DPC regionale corrente | `DpcAdapter` | M | P0 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-20 | WGWebcare/GOpenCare | Piano/movimenti, erogazione, residui, precontabilità | Wingesfar | No | WebCare/GOpenCare | Username/password o token/sessione | T,W | file; card solo helper | Piattaforma WebCare corrente | `WebCareAdapter` | H | P1 | `LEGACY_CODE_WINGESFAR` |
| W-21 | WGGPack/celiachia | Contabilizzazioni, listini, allowance/celiachia | Wingesfar | No | GPack/GOpenCare profiles | Username/password o token | T,W | file | Profilo WebCare/assistenza integrativa da caratterizzare | `WebCareAdapter` | H | P2 | `LEGACY_CODE_WINGESFAR` |
| W-22 | Enerj | Creazione/lettura/stato ordine NSO | Wingesfar | No | Enerj/CGM mediator | OAuth client credentials + bearer | T,W | file XML | Interfaccia corrente del mediatore; accesso diretto NSO non provato | `Other` | M | P2 | `LEGACY_CODE_WINGESFAR`, `LEGACY_CONFIG` |
| W-23 | RicetteInCloud | Busta/stato workflow CGM | Wingesfar | No | CGM cloud | Proprietaria | T,W | file | Nessun replacement pubblico: funzione prodotto CGM | `DO_NOT_MIGRATE` | M | P3 | `LEGACY_CODE_WINGESFAR` |

## Seam drCLOUD

| ID | Legacy module | Business capability | Current caller | drCLOUD | External system | Auth | State | Local dependency | Official current replacement | SIP target | Difficulty | Priority | Provenance |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| D-01 | SogeiPrescriptionClient | Creazione/lettura/annullo ricetta SSN/RBE, lotto NRE, OTP | drCLOUD+ | Sì | Sistema TS SAC | Basic + MFA/sessione | T,U,W | - | SAC/SAR con MFA | `SistemaTSEPrescriptionConnector` | H | P0 | `LEGACY_CODE_DRCLOUD`, `OFFICIAL_CURRENT` |
| D-02 | LombardiaPrescriptionClient | Prescrizione regionale | drCLOUD+ | Sì | Lombardia SAR | OAuth authorization code, bearer | T,U,W | callback app | SAR Lombardia corrente | `RegionalEPrescriptionAdapter` | H | P0 | `LEGACY_CODE_DRCLOUD` |
| D-03 | PiemontePrescriptionClient | Prescrizione regionale | drCLOUD+ | Sì | Piemonte SAR | MFA/sessione regionale | T,U,W | - | SAR Piemonte corrente | `RegionalEPrescriptionAdapter` | H | P1 | `LEGACY_CODE_DRCLOUD` |
| D-04 | BolzanoPrescriptionClient | Prescrizione regionale | drCLOUD+ | Sì | Alto Adige SAR | OAuth client credentials, mTLS | T,W | cert app | SAR provinciale corrente | `RegionalEPrescriptionAdapter` | H | P1 | `LEGACY_CODE_DRCLOUD` |
| D-05 | LiguriaPrescriptionClient | Prescrizione regionale | drCLOUD+ | Sì | Liguria SAR | OAuth authorization code + PKCE | T,U,W | callback app | SAR Liguria corrente | `RegionalEPrescriptionAdapter` | H | P1 | `LEGACY_CODE_DRCLOUD` |
| D-06 | LombardiaFascicoloClient | Ricerca/recupero FSE | drCLOUD+ | Sì | Lombardia FSE | OAuth/bearer, firma dove richiesta | T,U | - | FSE consumer regionale | `RegionalFseConsumerAdapter` | H | P1 | `LEGACY_CODE_DRCLOUD` |
| D-07 | LombardiaFascicoloClient | Invio documento FSE | drCLOUD+ | Sì | Lombardia FSE | OAuth/bearer, firma | T,W | cert app | Gateway FSE 2.0 producer | `FSE2NationalConnector` | H | P0 | `LEGACY_CODE_DRCLOUD`, `OFFICIAL_CURRENT` |
| D-08 | SardegnaFascicoloClient | Stato, query e recupero XDS | drCLOUD+ | Sì | Sardegna FSE | XDS, SAML/WS-Security, mTLS | T | cert app | FSE consumer regionale | `RegionalFseConsumerAdapter` | VH | P2 | `LEGACY_CODE_DRCLOUD` |
| D-09 | SardegnaFascicoloClient | Provide/register, update/remove metadata | drCLOUD+ | Sì | Sardegna FSE | XDS, SAML/WS-Security, mTLS | T,W | cert app | Gateway FSE 2.0 producer | `FSE2NationalConnector` | VH | P0 | `LEGACY_CODE_DRCLOUD`, `OFFICIAL_CURRENT` |
| D-10 | SogeiFascicoloClient | Ricerca documenti FSE | drCLOUD+ | Sì | Sistema TS/Sogei FSE search | Credenziali/sessione | T | - | Consumer non coperto da GTW; target corrente da confermare | `RegionalFseConsumerAdapter` | H | P2 | `LEGACY_CODE_DRCLOUD`, `NEEDS_CHARACTERIZATION` |
| D-11 | CGM ValidationClient | Validazione documento FSE 2.0 | drCLOUD+ | Sì | Gateway FSE 2.0 via CGM | mTLS + dual JWT RS256 | T,W | cert app | Gateway FSE 2.0 v2.23 | `FSE2NationalConnector` | H | P0 | `LEGACY_CODE_DRCLOUD`, `OFFICIAL_CURRENT` |
| D-12 | AbruzzoVaccinazioniClient | Registrazione/cancellazione vaccinazione | drCLOUD+ | Sì | Abruzzo vaccinazioni | Credenziali/token regionali | T,W | - | API regionale corrente da accreditare | `VaccinationAdapter` | H | P2 | `LEGACY_CODE_DRCLOUD` |
| D-13 | SogeiMalattiaClient | Invio/ricerca/annullo/rettifica certificato malattia | drCLOUD+ | Sì | Sistema TS malattia | Credenziali, PIN/MFA profile | T,U,W | - | Servizio nazionale corrente da verificare | `Other` | H | P2 | `LEGACY_CODE_DRCLOUD`, `NEEDS_CHARACTERIZATION` |
| D-14 | LombardiaPatientClient | Identificazione assistito e consultazione esenzioni | drCLOUD+ | Sì | Lombardia assistiti/esenzioni | Profilo regionale | T,U | - | Servizio regionale corrente da accreditare | `Other` | H | P3 | `LEGACY_CODE_DRCLOUD` |
| D-15 | DocumentTrace/VieSomministrazione | Trace/dashboard e catalogo AIC→via | drCLOUD+ | Sì | CGM NAIS/Helios/cataloghi | Credenziali CGM | T,W | - | Funzione prodotto CGM | `DO_NOT_MIGRATE` | M | P3 | `LEGACY_CODE_DRCLOUD` |

## Riconciliazione numerica

| Dimensione | Conteggio |
|---|---:|
| Totale confermato | 38 |
| Wingesfar | 23 |
| drCLOUD | 15 |
| Regionale/provinciale o piattaforma regionale | 26 |
| Nazionale, inclusi percorsi mediati nazionali | 10 |
| CGM privato, fuori dal catalogo SIP pubblico | 2 |
| `CURRENT_AND_REQUIRED` | 32 |
| `CURRENT_BUT_SHOULD_USE_NEW_OFFICIAL_API` | 3 |
| `LEGACY_TRANSITIONAL` | 1 |
| `DO_NOT_MIGRATE`/privato | 2 |

Le tre seam “current ma nuovo target” sono W-15 (VetInfo con autenticazione moderna), D-07 e D-09 (producer regionali da portare sul Gateway FSE 2.0). Le ultime due sono le sole seam rese superflue dal FSE 2.0: il GTW non sostituisce ricerca/recupero FSE né la dispensazione. Le 32 + 3 seam target-relevant e le due funzioni CGM private sono correnti; W-16 è la sola route transitional.

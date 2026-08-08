# CGM healthcare connector roadmap

## Final verdict: GO

L'evidenza è sufficiente per ridefinire la Healthcare Connector Roadmap: le 38 seam sono collegate a caller, auth, stato, dipendenza locale e target. Il GO autorizza una roadmap e la successiva acquisizione delle specifiche/accreditamenti; **non** autorizza implementazione, test verso produzione o public-release claim.

## Primi connector

| Ordine | Connector | Decisione | Seam coperte | Perché ora | Condizione |
|---:|---|---|---:|---|---|
| 1 | `SistemaTSEPrescriptionConnector` | `BUILD_NOW` | 2 | Nazionale, critico, comune a Wingesfar/drCLOUD; SAC/SAR resta ufficiale | MFA corrente, ruoli prescriber/dispenser, accreditamento |
| 2 | `RegionalEPrescriptionAdapter` | `BUILD_NOW` | 11 | Maggiore consolidamento reale; iniziare Lombardia ed Emilia-Romagna, poi profili | Contract pack per profilo, nessuna mega-abstraction |
| 3 | `RegionalFseConsumerAdapter` | `BUILD_NOW` | 9 | FSE2 non sostituisce search/retrieve; forte rimozione di moduli/cert locali | Lombardia per prima; XDS/SAML profiles separati |
| 4 | `FSE2NationalConnector` | `BUILD_NOW` | 3 | Target ufficiale 2.23, sostituisce due producer regionali e la mediazione validate | Lifecycle completo, dual-JWT/mTLS, document type scope |
| 5 | `DpcAdapter` | `BUILD_NOW` | 1 | Uso operativo farmacia e seam tecnicamente circoscritta | Stato/idempotency WebDPC caratterizzati |
| 6 | `SistemaTSHealthExpensesConnector` | `BUILD_NEXT` | 2 | Adempimento nazionale; riduce file/credential locali | Specifica e onboarding correnti |
| 7 | `VetInfoConnector` | `BUILD_NEXT` | 2 | Nazionale e riusabile; rimuove password grant e route alternativa | Profilo OAuth/accreditamento corrente |
| 8 | `WebCareAdapter` | `BUILD_NEXT` | 2 | Alta utilità farmacia, ma contract vendor/profile-specific | Characterization allowance/residui |
| 9 | `VaccinationAdapter` | `BUILD_ON_DEMAND` | 1 | drCLOUD prova Abruzzo; catalogo ONIT più ampio non è attivo | Cliente/tenant e specifica regionale |
| 10 | `Other/NSO-MediatorProfile` | `BUILD_ON_DEMAND` | 1 | Funzione reale ma mediata Enerj/CGM | Non costruire direct NSO senza evidenza |
| 11 | `Other/DiseaseCertificate` | `NEEDS_EVIDENCE` | 1 | Client reale, target/current contract non acquisito | Specifica Sistema TS corrente |
| 12 | `Other/LombardiaPatientServices` | `BUILD_ON_DEMAND` | 1 | Regionale e drCLOUD-only | Sponsor cliente e accreditamento |
| — | CGM trace/catalog/RicetteInCloud | `DO_NOT_BUILD` | 2 | Funzioni prodotto CGM, non connector pubblico | Restano esterne |

“11 seam regional ePrescription” significa un core minimo più profili accreditati, non un unico rilascio che dichiara tutte le regioni supportate.

## Migration coverage

| Pacchetto | Connector inclusi | Seam coperte | Coverage numerica | Coverage business qualitativa |
|---|---|---:|---:|---|
| Top 3 | Sistema TS Prescription, Regional ePrescription, Regional FSE Consumer | 22/38 | 58% | **Molto alta (circa 70–80%)**: prescrizione/dispensazione e consultazione FSE dominano la criticità, non è una metrica di volume |
| Top 5 | Top 3 + FSE2 National + DPC | 26/38 | 68% | **Molto alta (circa 80–88%)**: aggiunge producer nazionale e un workflow farmacia frequente |
| Top 10 | Top 5 + Health Expenses, VetInfo, WebCare, Vaccination, NSO mediator | 34/38 | 89% | **Quasi completa (circa 93–97%)**: restano malattia, assistiti/esenzioni e due funzioni CGM private |

Gli intervalli qualitativi sono giudizi espliciti basati su criticità/frequenza del workflow, riuso e dismissione di codice; non sono transaction share.

## Executive output

1. **Quante integrazioni sanitarie reali?** 38 seam confermate: 23 Wingesfar e 15 drCLOUD. Otto famiglie compilate/configurate soltanto restano escluse e `NEEDS_CHARACTERIZATION`.
2. **Quante sono ancora current?** 35 seam pubbliche target-relevant: 32 `CURRENT_AND_REQUIRED` e 3 da portare alla nuova API ufficiale. Altre 2 funzioni CGM private restano correnti per il prodotto ma non appartengono a SIP; una route è transitional.
3. **Quante diventano superflue usando FSE2?** 2: producer Lombardia e Sardegna drCLOUD. Nessuna seam FSE consumer o ricetta/dispensazione.
4. **Quante restano regionali?** 26, incluse le piattaforme regionali DPC/WebCare e i profili FSE/SAR.
5. **Quante sono servizi nazionali separati?** 10 seam in 6 famiglie: Sistema TS prescription, FSE2, VetInfo, health expenses, certificati malattia e NSO mediato.
6. **Quali dipendono realmente dal Broker?** Una seam nelle 38: Puglia SIST. Fuori dal conteggio, il sync desktop drCLOUD richiede accesso EMR locale. Altri store/callback sono centralizzabili o condizionali.
7. **Quante auth primitive mancano davvero?** 7: PKCE, client credentials, SAML, WS-Security, HMAC, XML-DSig/PKCS#7 e smartcard/CNS+PIN. La VPN è un gap locale separato; dual-JWT è una piccola estensione; OAuth password grant va rimosso.
8. **Primi 5 connector?** Sistema TS Prescription, Regional ePrescription, Regional FSE Consumer, FSE2 National, DPC.
9. **Quanto drCLOUD può essere sostituito?** 14/15 seam healthcare, 93% per superficie. Non è una stima di volume/effort.
10. **Cosa deve restare?** UI/logica prodotto, EMR extractor/sync se ancora necessario, NAIS/Helios/cataloghi CGM, telemetria/update/email; local key operation solo se non esportabile.
11. **Coverage Top 3/5/10?** 58% / 68% / 89% per seam; circa 70–80% / 80–88% / 93–97% qualitativo.
12. **Percorso meno rischioso?** Strangler sulle facciate esistenti, read-only/shadow, canary per regione, migrazione secret, write con reconciliation, fallback time-boxed e retirement verificato.

## Cosa non costruire ora

- Un connector FSE per ogni regione senza shared-contract evidence.
- Un unico connector che mescoli FSE producer, consumer e prescrizione.
- OAuth password grant, bearer fissi, token file cache o secret export.
- Un Broker obbligatorio per tutte le farmacie.
- Direct NSO, ONIT multi-regione, SORESA, DOGE/Molise o altri client compilati senza caller/tenant evidence.
- Funzioni CGM private come connector open-source Core.

## Gate prima dell'implementazione

Per ogni connector: fonte ufficiale corrente, scope operativo, ownership credential/cert, accreditamento e test environment autorizzato, clean-room vector, positive/negative auth tests, idempotency/reconciliation, data minimization, traceability e threat-model delta. Nessuna chiamata a produzione sanitaria è parte di questa ricerca.

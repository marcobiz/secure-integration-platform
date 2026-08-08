# drCLOUD responsibility and replacement map

## Conclusione

SIP può sostituire **14 delle 15 seam healthcare drCLOUD (93% per conteggio di superficie)**. D-15 è una funzione CGM privata e non deve diventare un connector SIP. La percentuale non è un volume transazionale né una stima di effort.

drCLOUD Desktop non è il bridge generale delle chiamate sanitarie osservate: il processo locale su loopback estrae dati dai database EMR e li sincronizza con CGM cloud. Le chiamate nazionali/regionali di drCLOUD+ transitano invece dalla libreria mobile `ConnectedServices`. Il componente desktop può quindi rimanere per l'accesso ai DB locali senza rimanere nel percorso dei connector SIP.

## Responsibility matrix corrente

| Capability | Wingesfar | drCLOUD | CGM cloud | External service | Provenance |
|---|---|---|---|---|---|
| Selezione prescrizione/erogazione farmacia | UI, stato locale, local service, adapter | Non coinvolto nel percorso Wingesfar osservato | Nessuna prova nel percorso principale | SAC/SAR mantiene stato autorevole | `LEGACY_CODE_WINGESFAR` |
| Prescrizione medico drCLOUD | Non coinvolto | UI, mapping, routing, auth, token, client | Servizi di supporto e configurazione | SAC/SAR valida e persiste | `LEGACY_CODE_DRCLOUD` |
| FSE consumer Wingesfar | UI, adapter, cert/token, chiamata diretta | Non coinvolto | Nessuna prova | Regione/provincia cerca e restituisce | `LEGACY_CODE_WINGESFAR` |
| FSE consumer/producer drCLOUD | Non coinvolto | Mapping, XDS/REST, auth, cache token | Validazione/trace in alcune route | Regione o GTW | `LEGACY_CODE_DRCLOUD` |
| FSE 2.0 | Nessuna seam producer provata | Client di validazione | Mediazione CGM osservata | GTW è autorevole per lifecycle producer | `LEGACY_CODE_DRCLOUD`, `OFFICIAL_CURRENT` |
| Certificati e firma | Store Windows/PFX/smartcard per profilo | Risorse certificate e handler nell'app | Sign service disponibile | Il servizio verifica mTLS/firma | `LEGACY_CODE_WINGESFAR`, `LEGACY_CODE_DRCLOUD` |
| Credenziali vendor/farmacia/operatore | Config e input operatore | Config/risorse e input utente | Possibile catalogo/config remoto | Identity provider nazionale/regionale | `LEGACY_CONFIG`, `INFERRED` |
| OAuth e token cache | Helper/browser o memoria/disk cache locale | Handler e cache app | Alcuni token/helper possono essere mediati | Authorization server | `LEGACY_CODE_WINGESFAR`, `LEGACY_CODE_DRCLOUD` |
| DPC/WebCare/VetInfo/730 | Moduli diretti e stato workflow | Non provato | Mediatori solo nelle seam esplicite | Piattaforma sanitaria/associativa | `LEGACY_CODE_WINGESFAR` |
| Vaccinazioni/malattia/assistiti | Non provato | Client diretto | Config/supporto | Regione o Sistema TS | `LEGACY_CODE_DRCLOUD` |
| Routing endpoint | Factory/config locali | `Subsystem` + environment + bootstrapper | Live-update/config distribution | Nessuna autorità client-side | `LEGACY_CODE_DRCLOUD` |
| Telemetria/email/live update | Funzioni prodotto separate | Client registrati, non connector sanitario | CGM cloud | Servizi CGM | `LEGACY_CODE_DRCLOUD` |
| EMR locale | Gestionale Wingesfar stesso | Desktop legge DB IGEA/Phronesis/Studio/Venere/FPF | Riceve sincronizzazione | Non coinvolto | `REVERSE_ENGINEERING_REPORT`, `LEGACY_CODE_DRCLOUD` |

## Disposizione per responsabilità drCLOUD

| Responsabilità | Decisione | SIP destination | Motivazione |
|---|---|---|---|
| Certificate custody esportabile | `MOVE_TO_SIP_GATEWAY` | `ICertificateProvider` + `IKeyOperationProvider` | Elimina materiale condiviso e logica dall'app; binding server-owned |
| Chiave/certificato non esportabile | `MOVE_TO_SIP_BROKER` | Broker locale con operazione di firma, mai export | Solo quando l'accreditamento impone realmente la custodia locale |
| Credenziali vendor/farmacia | `MOVE_TO_SIP_GATEWAY` | `ISecretProvider`, scope per installation/pharmacy | Il client non deve scegliere reference o endpoint |
| OAuth authorization code/PKCE | `MOVE_TO_SIP_GATEWAY` | Challenge opaca + callback controllato; token cache effimera | Il browser è user interaction, non prova di necessità del Broker |
| OAuth client credentials | `MOVE_TO_SIP_GATEWAY` | Secret provider + token cache effimera | Flusso machine-to-machine naturale per Gateway |
| Session/MFA | `MOVE_TO_SIP_GATEWAY` | Stato runtime opaco; prompt al client solo per il fattore umano | Evita token/sessione su disco o nei log |
| JWT, SAML, HMAC, XML signing | `MOVE_TO_SIP_GATEWAY` o `MOVE_TO_SIP_BROKER` | Key operation provider; Broker solo per key locale | Mai esporre chiave privata al connector o al caller |
| Routing regionale/nazionale | `MOVE_TO_SIP_GATEWAY` | Definizioni immutabili, binding server-owned | Sostituisce `Subsystem`/config distribuita con policy pubblicata |
| FSE2 validation/lifecycle | `REPLACE_WITH_DIRECT` | `FSE2NationalConnector` verso GTW | Rimuove la mediazione CGM quando accreditamento e tenancy lo consentono |
| FSE consumer regionale | `MOVE_TO_SIP_GATEWAY` | `RegionalFseConsumerAdapter` + profili | Rimane regionale; non è coperto dal GTW producer |
| ePrescription regionale/nazionale | `MOVE_TO_SIP_GATEWAY` | connector nazionale + profili regionali | SAC/SAR restano sistemi esterni autorevoli |
| Config/update distribution sanitario | `MOVE_TO_SIP_GATEWAY` | Publication e cache fail-closed | Gli update applicativi CGM possono rimanere separati |
| Sign service CGM | `UNKNOWN` per uso non sanitario; `REMOVE` dal percorso SIP | Provider crittografico SIP | Mantenere solo se richiesto da funzioni CGM fuori perimetro |
| DocumentTrace/NAIS/Helios e vie di somministrazione | `KEEP_EXTERNAL` | Nessun connector pubblico | Funzioni prodotto CGM, seam D-15 |
| Telemetria, CRM, email e live update | `KEEP_EXTERNAL` | Fuori perimetro | Non sono capability gateway sanitarie |
| drCLOUD Desktop EMR sync | `KEEP_EXTERNAL`, oppure `REMOVE` dopo integrazione diretta | Eventuale adapter locale CGM, non healthcare connector | Accesso ai DB locali è una responsabilità di prodotto/data sync |

## Stato e retry

- Lo stato clinico/autorevole resta sempre presso SAC/SAR/FSE/VetInfo/piattaforma regionale (`OFFICIAL_CURRENT` o `LEGACY_CODE_*`).
- SIP conserva solo correlazione, idempotency key, challenge, token/sessione opaca e stato tecnico necessario al retry (`INFERRED`).
- Un retry automatico è sicuro solo per letture o con idempotency ufficiale. Invio, erogazione, annullo, rettifica e pubblicazione richiedono query di stato/reconciliation prima di ripetere (`INFERRED`).
- Le code file-based Wingesfar e la persistenza token su disco sono comportamenti legacy da sostituire, non contratti da copiare (`LEGACY_CODE_WINGESFAR`).

## Cosa deve eventualmente restare di drCLOUD

1. UI e logica clinica/prodotto drCLOUD+.
2. Extractor/sync desktop finché deve leggere database EMR locali non esposti da API.
3. NAIS/Helios, cataloghi e altre funzioni CGM private non standardizzate.
4. Telemetria, email e aggiornamento applicativo, fuori dal gateway sanitario.
5. Una capability locale di firma solo se una chiave accreditata è non esportabile; dovrebbe diventare Broker SIP, non rimanere un protocollo drCLOUD proprietario.

## Limiti della conclusione

Il 93% è affidabile come mappa statica delle registration del bootstrapper, ma non prova il numero di tenant abilitati o i volumi. Le famiglie compilate ma non registrate vanno caratterizzate con manifest di feature/tenant o trace sanitizzate prima di aumentare il catalogo.

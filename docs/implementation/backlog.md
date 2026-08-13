# Backlog attivo ordinato per dipendenze

Aggiornato: 2026-08-13
Baseline CURRENT: `eec2fa5556eccc7e8e3b47fc7d7b127bcac1ed9e`

Questo backlog contiene soltanto le due track attive. `Todo` non autorizza lavoro fuori
scope; `BLOCKED_EXTERNAL` non autorizza workaround insicuri. Gate e claim sono definiti
in [`0.1.0-alpha-scope.md`](0.1.0-alpha-scope.md).

## P0 — Core `0.1.0-alpha`

| ID | Outcome | Stato | Dipendenza | Gate | Non prova |
|---|---|---|---|---|---|
| ALPHA-DOC-01 | Riconciliare governance, scope, backlog e DoD con PR #33 sull'exact main. | In progress | Exact main e dirty truth source preservato | ALPHA-05 | Architettura/security complete, API parity o FSE2 runbook. |
| ALPHA-DOC-02 | Allineare architecture, security e deployment boundaries, inclusi claim PostgreSQL/audit e traceability pertinenti. | Todo | ALPHA-DOC-01 | ALPHA-04/05 | Modifiche di codice, threat remediation o qualifica production. |
| ALPHA-DOC-03 | Rendere coerenti OpenAPI, API docs e generated types con le route effettive e i parity test. | Todo | ALPHA-DOC-01 | ALPHA-05 | API stabile o backward compatibility futura. |
| ALPHA-DOC-04 | Allineare la documentazione FSE2 all'exact main e separare synthetic, OfficialTest e production. | Todo | ALPHA-DOC-01 | FSE2-T01..T06 / ALPHA-05 | Custody reale, import o call OfficialTest. |
| ALPHA-VER | Derivare una sola versione `0.1.0-alpha` per assembly, package, Admin, immagini e manifest; nessun default `1.0.0`. | Todo | ALPHA-DOC-01 | ALPHA-06/08 | Pubblicazione o stabilità API. |
| ALPHA-REST | Consolidare un solo `sample-secure-service` Published con Synthetic Provider, API key+mTLS, mock e tutorial coerente. | Todo | ALPHA-DOC-03 | ALPHA-02/03 | Supporto ad altri Connector o provider reali. |
| ALPHA-CLEAN | Provare clean clone e quickstart unico con cleanup/canary su macchina non preparata. | Todo | ALPHA-DOC-02/03, ALPHA-REST | ALPHA-01/02 | Installer, Azure live o production operations. |
| ALPHA-DIRECT | Documentare e provare Direct .NET come evaluation integration, con limite del key storage esplicito. | Todo | ALPHA-REST, ALPHA-CLEAN | ALPHA-03/08 | SDK production-grade o supporto native/COM. |
| ALPHA-ADOPT | Far completare enrollment→publish→grant→invoke a un secondo utilizzatore usando soltanto documentazione pubblica. | Todo | ALPHA-CLEAN, ALPHA-DIRECT | ALPHA-03 | Market fit, support SLA o production adoption. |
| ALPHA-ART | Produrre archive/checksum/SBOM/vulnerability inventory e aggiungere un normalized Core export inventory digest separato dal raw manifest run-specific. | Todo | ALPHA-VER, ALPHA-CLEAN | Riproducibilità binaria assoluta, firma release o production provenance. |
| ALPHA-LIC | Ottenere decisione umana sulla licenza e aggiornare metadata di distribuzione autorizzati. | BLOCKED_EXTERNAL | Decisione legal/business | ALPHA-07 | Che oggi il progetto sia legalmente distribuibile come OSS. |
| ALPHA-SEC | Decidere security contact privato e regola DCO/CLA, con contatti CoC autorizzati. | BLOCKED_EXTERNAL | Decisione maintainer/legal | ALPHA-07 | Certificazione o security support enterprise. |
| ALPHA-REL | Preparare release notes/known limits, rieseguire ALPHA-01..08 sull'exact candidate e applicare il tag; è l'ultimo step. | Todo | Tutte le slice ALPHA precedenti | ALPHA-01..08 | Production readiness, FSE2 qualification o merge automatico. |

`P3-CORE-EXPORT-DIGEST` è l'outcome interno di ALPHA-ART: il raw SHA del manifest
attuale è evidence della run perché include `generatedAtUtc`; il digest normalizzato
futuro deve coprire l'inventario in modo riproducibile. Il finding non è una failure di
PR #33 né del Core export corrente.

## P0 parallelo — FSE2 Organization OfficialTest

FSE2-PROV e FSE2-PACK non sono più candidate fuori main: PR #33 ha integrato provider
Local PKCS12, importer, overlay e vertical image e li ha qualificati sinteticamente. Le
slice sotto coprono solo il percorso ancora aperto verso OfficialTest. Il pack resta
`SecretValues=false`; generic secret retrieval resta deny-only.

| ID | Outcome | Stato | Dipendenza | Gate | Non prova |
|---|---|---|---|---|---|
| FSE2-INTAKE | Distinguere e verificare fuori Git accesso test, software accreditation applicabile, piano autorizzato e inventory pubblica/redatta. | BLOCKED_EXTERNAL | Input dell'organizzazione | FSE2-T01 | Accreditamento production o validità/custody del materiale. |
| FSE2-CUSTODY | Eseguire preflight e import operativo fuori Git con path, ACL, principal, chain, fingerprint e separazione A1/S1 verificati. | BLOCKED_EXTERNAL | FSE2-INTAKE, materiale autorizzato | FSE2-T02 | HSM/KMS equivalence, rotation/revocation production o call FSE2. |
| FSE2-ACTIVATION-COMPOSITION | Comporre l'eventuale activation HMAC come capability server-owned separata e verificare startup fail-closed senza ampliare il pack certificati. | Todo | FSE2-INTAKE, exact environment requirements | FSE2-T02 | Generic secret retrieval, `GetSecret` o accesso del Connector al secret. |
| FSE2-WARN | Mappare i warning necessari a `validate-cda` in codici tecnici bounded/allowlisted e scartare testo raw. | Todo | Fonte/piano ufficiale congelato | FSE2-T03/06 | Completezza di tutte le risposte o status workflow. |
| FSE2-DRIVER | Fissare vertical image, Connector/binding/config exact OfficialTest e driver Direct con soli path fuori Git e output redatto. | Todo | FSE2-CUSTODY, FSE2-ACTIVATION-COMPOSITION | FSE2-T03 | Connettività o qualifica OfficialTest. |
| FSE2-OFFLINE | Eseguire E2E sintetico dalla stessa immagine/configurazione destinata a OfficialTest, inclusi negativi zero-network. | Todo | FSE2-WARN, FSE2-DRIVER | FSE2-T03 | Chiamata live, accreditamento o risposta ufficiale. |
| FSE2-LIVE-VAL | Eseguire `validate-cda` OfficialTest con dataset sintetico autorizzato ed evidence redatta. | BLOCKED_EXTERNAL | FSE2-T01/T02/T03 e autorizzazione operativa | FSE2-T04/06 | Create/status, 11/11 live o production. |
| FSE2-HASH | Calcolare `attachment_hash` sugli exact input-file bytes per create/replace e coprire file ≠ multipart con regression. | Todo | FSE2-LIVE-VAL, autorizzazione workflow | FSE2-T05 | Prerequisito tecnico di `validate-cda` o create live già eseguita. |
| FSE2-STATUS | Mappare soltanto outcome status tecnici bounded/redatti e dichiarare i limiti di persistenza. | Todo | FSE2-LIVE-VAL, piano workflow | FSE2-T05/06 | Status live o durata cross-process. |
| FSE2-LIVE-WF | Eseguire create/replace e status soltanto se autorizzati, con hash e outcome verificati. | Todo | FSE2-HASH, FSE2-STATUS | FSE2-T05/06 | Tutte le 11 operation live-qualified o production. |
| FSE2-DUR | Aggiungere persistenza workflow cross-process/cross-node solo su requisito dimostrato. | Deferred | Evidenza operativa successiva | Gate futuro | Non blocca il primo `validate-cda`; nessuna durata è oggi promessa. |
| FSE2-HUMAN | Implementare Human Actor solo con requisito e piano ufficiale autorizzati. | Deferred | Specifica e autorizzazione future | Gate futuro | Organization profile o Human Actor production. |

`FSE2-HASH` e `FSE2-STATUS` non sono prerequisiti di `validate-cda`. Diventano necessari
per le sole claim create/status autorizzate.

## Stop list della fase

Fino alla chiusura dell'alpha e del primo `validate-cda` non si avviano o autorizzano:

- nuove capability Core generiche senza un blocker riproducibile;
- nuovi Connector verticali;
- altri provider cloud;
- MSI;
- COM/C ABI;
- refactor generici non richiesti da un difetto osservabile;
- fuzzing o performance come claim della fase;
- HA/DR;
- marketplace;
- claim production;
- merge automatici.

I claim esplicitamente non autorizzati sono elencati nello
[`scope`](0.1.0-alpha-scope.md#claim-non-autorizzati).

## Deferred fuori dalle track attive

Legacy distribution, altri provider/verticali, supply-chain production, operabilità
enterprise e pilot restano deferred. Non diventano P0 per effetto di questa truth pass.

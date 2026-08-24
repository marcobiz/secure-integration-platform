# Backlog attivo ordinato per dipendenze

Aggiornato: 2026-08-24
Baseline CURRENT: `ee3072be5e34a7b0477907a2580dcf454b8a4aba`

Questo backlog conserva l'esito chiuso della Core alpha e mantiene una sola track
corrente: FSE2 Organization OfficialTest. `Todo` non autorizza lavoro fuori scope;
`BLOCKED_EXTERNAL` non autorizza workaround insicuri. La release pubblicata e i suoi
limiti sono descritti nelle [release notes](../releases/0.1.0-alpha.1.md) e nella
[publication attestation](../releases/0.1.0-alpha.1-publication-attestation.json).

## Esito chiuso — Core `0.1.0-alpha.1`

| ID | Outcome | Stato | Dipendenza | Gate | Non prova |
|---|---|---|---|---|---|
| ALPHA-DOC-01 | Riconciliare governance, scope, backlog e DoD con PR #33 sull'exact main. | PASS | Exact main e dirty truth source preservato | ALPHA-05 | Architettura/security complete, API parity o FSE2 runbook. |
| ALPHA-DOC-02 | Allineare architecture, security e deployment boundaries, inclusi claim PostgreSQL/audit e traceability pertinenti. | PASS | ALPHA-DOC-01 | ALPHA-04/05 | Modifiche di codice, threat remediation o qualifica production. |
| ALPHA-DOC-03 | Rendere coerenti OpenAPI, API docs e generated types con le route effettive e i parity test. | PASS per la release; follow-up registrato | ALPHA-DOC-01 | ALPHA-05 | API stabile o backward compatibility futura. |
| ALPHA-DOC-04 | Allineare la documentazione FSE2 all'exact main e separare synthetic, OfficialTest e production. | PASS — truth-only | ALPHA-DOC-01 e stato PR #33 integrato | ALPHA-05; nessun gate FSE2 | Custody reale, import, call OfficialTest o FSE2-T01..T06 PASS. |
| ALPHA-VER | Derivare una sola versione `0.1.0-alpha.1` per assembly, package, Admin, OpenAPI, immagini e manifest; nessun default prodotto `1.0.0`. | PASS | ALPHA-DOC-01 | ALPHA-06/08 | Stabilità API. |
| ALPHA-REST | Consolidare un solo `sample-secure-service` Published con Synthetic Provider, API key+mTLS, mock e tutorial coerente. | PASS | ALPHA-DOC-01 | ALPHA-02/03 | Supporto ad altri Connector o provider reali. |
| ALPHA-CLEAN | Provare clean clone e quickstart unico con cleanup/canary su macchina non preparata. | PASS | ALPHA-DOC-01 | ALPHA-01/02 | Installer, Azure live o production operations. |
| ALPHA-DIRECT | Documentare e provare Direct .NET come evaluation integration, con limite del key storage esplicito. | PASS | ALPHA-DOC-01 | ALPHA-03/08 | SDK production-grade o supporto native/COM. |
| ALPHA-ADOPT | Far completare enrollment→publish→grant→invoke a un secondo utilizzatore usando soltanto documentazione pubblica. | PASS — independent adopter simulation | ALPHA-REST, ALPHA-DIRECT, ALPHA-CLEAN, ALPHA-DOC-02, ALPHA-DOC-03 | ALPHA-03 | Market fit, support SLA o production adoption. |
| ALPHA-ART | Produrre archive/checksum/SBOM/vulnerability inventory e aggiungere un normalized Core export inventory digest separato dal raw manifest run-specific. | PASS | ALPHA-VER | ALPHA-06 | Riproducibilità binaria assoluta, firma release o production provenance. |
| ALPHA-LIC | Applicare decisione path-based MPL-2.0/Apache-2.0, testi, metadata, artifact binding e validatore. | PASS | ALPHA-DOC-01; decisione legal/business ricevuta | ALPHA-07 | Trademark grant o licenza per repository esterni. |
| ALPHA-SEC | Applicare security contact, Contributor Covenant 3.0 e DCO 1.1 senza CLA. | PASS | ALPHA-DOC-01; decisione maintainer/legal ricevuta | ALPHA-07 | Certificazione, SLA o security support enterprise. |
| ALPHA-REL | Pubblicare tag annotato e GitHub public prerelease sull'exact source commit con release notes e inventario verificabili. | PASS | ALPHA-DOC-01..04, ALPHA-REST, ALPHA-DIRECT, ALPHA-CLEAN, ALPHA-ADOPT, ALPHA-VER, ALPHA-ART, ALPHA-LIC, ALPHA-SEC | ALPHA-01..08 | Production readiness, FSE2 qualification, NuGet/registry publication o merge automatico. |

`P3-CORE-EXPORT-DIGEST` è **PASS per la release**. Il raw SHA del manifest resta evidence
della singola run perché include `generatedAtUtc`; `normalizedInventorySha256` copre
separatamente source commit, file count e inventario path/byte/SHA-256 in ordine ordinal,
con payload canonico UTF-8 senza BOM. Il finding non reinterpreta i raw SHA storici.

`NONDETERMINISTIC_UI_MOCK_20_AXE_SNAPSHOT` è registrato come follow-up noto non
bloccante. Questa slice non modifica comportamento UI, CSS o soglie Axe; il solo fixture hostname pubblico è riallineato al dominio riservato `.test`.

La prerelease pubblica contiene nove asset: cinque artefatti prodotto, due SBOM container,
`release-manifest.json` e `SHA256SUMS`. Il manifest conserva nove record SBOM interni e
`claims.publicReleaseGo=false`; questo valore è un'errata storica di stato
pre-pubblicazione, non un finding di integrità. I gate FSE2 non erano dipendenze di
ALPHA-REL e restano aperti.

## Follow-up documentali — non implementati in questa PR

| ID | Outcome | Stato | Limite |
|---|---|---|---|
| DOC-CONTRACT-ROUTES | Verificare se session-handshake e session-admission siano route pubbliche; se sì, riallineare OpenAPI, runtime e generated types, altrimenti correggerne la classificazione. | Todo | Nessuna modifica OpenAPI/session in questa PR. |
| DOC-BROKER-CONTRACT | Rimuovere o implementare consapevolmente le quattro operazioni IPC, le extensions e lo streaming dichiarati ma non presenti. | Todo | Nessuna modifica Broker IPC in questa PR. |
| DOC-CONNECTOR-SPEC | Riallineare capability schema e retry rule all'implementazione. | Todo | Nessuna modifica alla Connector specification in questa PR. |

Il threat model contiene ID duplicati `TM-083`..`TM-086`; la rinumerazione resta un
follow-up e non viene applicata qui. La distinzione FSE2 tra hash degli exact file bytes e
hash del multipart è in gestione al writer FSE2; questa PR non modifica documentazione o
gate FSE2 dettagliati.

## Track corrente — FSE2 Organization OfficialTest

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

Fino alla chiusura del primo `validate-cda` OfficialTest non si avviano o autorizzano:

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

I claim non autorizzati restano quelli esclusi dalle release notes: production readiness,
FSE2 OfficialTest/production, cloud qualification, SLA, stabilità API, firma e provenance.

## Deferred fuori dalle track attive

Legacy distribution, altri provider/verticali, supply-chain production, operabilità
enterprise e pilot restano deferred. Non diventano P0 per effetto di questa truth pass.

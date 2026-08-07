# Implementation status

Aggiornato: 2026-08-07

## Stato sintetico

| Ambito richiesto | Stato | Evidenza principale |
|---|---|---|
| M0 — fondamenta repository | Implementato; baseline congelata | commit `7f68442`, tag `baseline-m0-m1-vslice-2026-08-03` |
| M1 — Local Broker minimo | Implementato; **gate live tecnico PASS** | run `m0-m1-20260803-232955`; AC-002/004 PASS-LIVE sul commit testato |
| Primo vertical slice E2E | Completato come harness ripetibile | `E2E_CON_SecureLayer_success_boundaries_failures_timeout_and_replay` |
| M2 — Gateway minimo | **Done** | gate CI `30896803567`: build/test, PostgreSQL 18, container hardening, Gitleaks e SBOM PASS |
| M3 — vertical slice production-like | **M3A product gate PASS** | tag `m3a-product-gate-pass-20260805`; M3B PENDING non bloccante per il Core |
| M4 — Connector Configuration MVP | **Done** | PR #4 CI `30992487718`: 6/6 job PASS; schema v1, lifecycle, PG18, Published runtime, CLI, sample E2E e quick start |
| M5 — Admin UI MVP | **Done** | baseline `8774c252b233456173c3ab31346fb21390fb8d7d`, tag `m5-admin-ui-baseline-20260807` |
| M5.5 — Direct Gateway Access | Implementato localmente; CI e review indipendente pending | product candidate `1b3a3b38fa7d01c8c5f96af0324d040e412ac0be`; branch `m55/direct-gateway-access` |
| M3B, M6 e milestone successive | Non iniziate | nessun cloud reale, connector sanitario o adapter commerciale |
| Harness matrice live M0/M1 | Implementato ed eseguito su VM | matrice A-F PASS, reboot reale, bundle con manifest e SHA-256 verificati |

## Gate Review prima di M2

Esito conclusivo: **GO per M2**. La lineage live è stata integrata linearmente: il commit realmente testato resta `24288dbe065ecedc21c0018e8ed37ca844bc8caf`, il tag `m0-m1-live-pass-20260803-232955` non è stato riscritto e il commit documentale successivo `d1113d34a18e166c9eb0c14d8e11c3c1a1a20c12` è la baseline M2.

- **AC-002:** PASS-LIVE sul commit testato; servizio reale osservato come `NT SERVICE\SecureIntegrationBroker`, con restart e persistenza dopo reboot.
- **AC-004:** PASS-LIVE sul commit testato; ACL pipe/storage e negazione DPAPI verificate tra identità Windows distinte.
- IPC v1 è **provvisorio**, non congelato per COM/C ABI/CLI prima di M2/M3.
- review completa: `docs/reviews/M0-M1-GATE-REVIEW.md`;
- matrice requirement/test/evidence: `docs/reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md`.
- pacchetto live automatizzato: `tools/live-matrix`; runbook: `docs/operations/M0-M1-LIVE-MATRIX-RUNBOOK.md`.

## Modifiche implementate

### M0

- solution `.slnx`, struttura monorepo e confini di packaging;
- SDK .NET 10 pinned, central package management, lock file, nullable/analyzer e warning-as-error;
- script riproducibili di restore/build, test, validazione documenti, secret scan e SBOM SPDX;
- GitHub Actions con job Windows, dependency check, gitleaks e SBOM;
- `.gitignore` che esclude toolchain/artifact locali, materiale sensibile `input-docs` e formati di chiavi/certificati;
- skeleton Docker/MSI e release manifest senza anticipare implementazioni successive.

### M1

- framing IPC v1 `BGR1`, network byte order, version negotiation, limiti, sequence, correlation ID, challenge, nonce, deadline, multiplexing e cancel;
- Named Pipe con ACL per service/application SID e più connessioni concorrenti;
- caller identity acquisita dal kernel: PID, handle mantenuto per la connessione, creation time, SID del process token, path canonico, SHA-256 e publisher Authenticode trusted quando richiesto;
- manifest Application deny-by-default per SID, path, publisher/hash opzionale, operazioni Broker e coppie Connector/operation;
- persistenza atomica sotto ACL protette, DPAPI `CurrentUser`, data key casuale per Installation e AES-256-GCM versionato con AAD Installation/Application/purpose/content type;
- `PutLocalSecret` e `DeleteLocalSecret` idempotente per classi Tenant/Session; Vendor/Operator rifiutate; nessuna `GetSecret`;
- `ProtectData`, `UnprotectData`, `ComputeHmac`, `InvokeGateway` vincolata e status redatto;
- SDK .NET sottile per `netstandard2.0` e `net10.0`;
- Windows Service host e script di registrazione con virtual account `NT SERVICE\SecureIntegrationBroker`.
- harness VM fail-closed con account/processi reali distinti, ACL exact, DPAPI cross-identity, restart/reboot, tamper, Event Log e evidence bundle SHA-256.

### Vertical slice

- legacy simulator -> Broker reale -> Gateway HTTPS/mTLS di test -> provider sintetico -> mock REST HTTPS/mTLS;
- endpoint, Connector/operation, API key vendor e certificato client esterno restano centrali;
- test di successo, grant invalido, assenza secret, TLS failure, timeout e replay;
- nessuna capacità M2 production introdotta. Dettagli in `docs/testing/first-vertical-slice-report.md`.

### M2 — Gateway minimo

- modular monolith `Gateway.Domain/Application/Infrastructure/Api` e migration runner separato;
- PostgreSQL 18 con schema additivo, composite FK, ruoli distinti, RLS forzata e locator di autenticazione a superficie stretta;
- Tenant/Application/Environment/Installation, activation HMAC, challenge e PoP ECDSA P-256;
- credential ClientAuth, renewal 30 giorni, overlap massimo 7 giorni, revoca e replay nonce;
- autenticazione BGW1 che copre method, target, timestamp, nonce e body digest e deriva il Tenant dal certificato registrato;
- operation catalog immutabile server-side e grant deny-by-default;
- Azure Key Vault tramite Managed Identity; provider in-memory confinato a Development/Testing;
- egress HTTPS con DNS/IP filtering, socket pinned anti-rebinding, proxy/redirect/cookie disabilitati, bounds, timeout e retry solo idempotente;
- Basic, API key e mTLS applicati esclusivamente dal Gateway senza esporre secret reference;
- API health/readiness, Problem Details redatti, Docker non-root/read-only-compatible, health probe e Bicep contract skeleton;
- architettura, runbook, piano e report in `docs/architecture/m2-gateway-architecture.md`, `docs/operations/M2-GATEWAY-RUNBOOK.md`, `docs/implementation/M2-IMPLEMENTATION-PLAN.md` e `docs/testing/M2-IMPLEMENTATION-REPORT.md`.

### M3 — vertical slice production-like

- Broker production invoker con enrollment Installation, PoP/firma BGW1 e chiave CNG ECDSA P-256 non esportabile sotto la service identity;
- stack deterministico con Gateway container reale, PostgreSQL 18, synthetic Vault HTTPS e vendor mock HTTPS/mTLS, tutti alimentati da certificati e canary per-run;
- matrice automatica M3-P01/P03-P07 e M3-N01..N15, inclusi revoca, firma invalida, replay, tenant/URL/secret reference client-side, grant, SSRF/DNS, redirect, certificato errato, Vault/PostgreSQL indisponibili e log redaction;
- runner VM e script operatore revisionato per installare il Broker come vero servizio ed eseguire il Legacy Simulator standard user senza vendor secret;
- workflow Azure manuale protetto, federato OIDC, con Managed Identity, Key Vault reale, PostgreSQL 18 e App Service mTLS;
- evidence CI redatta con manifest, digest immagini, versione PostgreSQL, scenari e sidecar SHA-256; raw evidence esclusa da Git.

M3A product gate è PASS con la run `m3a-live-20260805-094131`: P02 ha attraversato il
vero Windows Service e tutti gli scenari obbligatori HOST/VM sono PASS. Il finalizzatore
del laboratorio è separatamente BLOCKED e non viene presentato come PASS. Il tag
`m3a-product-gate-pass-20260805` è la baseline del Core. M3B non è stato eseguito ed è
rinviato al gate dell'Azure Deployment Pack; non blocca M4. Non è richiesto un runner
Codex elevato o un executor SYSTEM generico: queste automazioni sono rinviate alla
qualificazione di release.
Review: `docs/reviews/M3-GATE-REVIEW.md` e `docs/reviews/M3A-PRODUCT-GATE-20260805.md`.

### M4 — Connector Configuration MVP

- Connector Definition JSON v1 provider-neutral, Draft 2020-12, sample sintetico e SHA-256 del JSON canonico;
- lifecycle Draft/Validated/Published/Superseded/Retired, Published immutabile, rollback per riattivazione e optimistic concurrency;
- migration PostgreSQL additiva `0002_connector_configuration_m4.sql`, unique Published e trigger anti-tamper;
- endpoint/secret binding logici per Environment, assenti da definition/export/runtime request;
- runtime esclusivamente Published con cache TTL, invalidazione, stamp per-invocation e no stale-on-error;
- Admin REST API autenticata, audit redatto e CLI senza accesso DB;
- sample E2E Legacy → Broker → Gateway → Published Connector → Synthetic Secret Provider → API key+mTLS → mock;
- quick start Compose completabile senza Azure e cleanup deterministico;
- ADR-0018, API/CLI/SDK docs, CONTRIBUTING, SECURITY e placeholder licenza.

M3B, connector sanitari reali, provider cloud aggiuntivi e adapter COM/C/Java non sono iniziati. M5 introduce esclusivamente Admin UI/API e separazione fisica provider; non anticipa M6.

### M5 — Admin UI MVP

- Core provider-neutral compilabile tramite `BrokerGateway.Core.slnx`; Azure resta pack opzionale escluso dall'export.
- OIDC Authorization Code server-side con PKCE/state/nonce, cookie `__Host-` sicuro, CSRF, logout e DevelopmentAuth fail-closed in Production.
- RBAC globale/tenant-scoped e principal `(issuer, subject)`; five roles e bootstrap SecurityAdministrator controllato.
- Four-eyes checksum-specific fail-closed: Production e OIDC non possono disabilitarlo; soltanto DevelopmentAuth esplicito e loopback può usare la policy semplificata. Self/requester/creator denial, binding activation e publication sono verificati anche al confine PostgreSQL.
- Admin API paginata con ProblemDetails/correlation, ETag/If-Match, audit e DTO privi di secret.
- React/TypeScript strict same-origin con dashboard, risorse, connector lifecycle, binding, grant, approval, audit, health, IT/EN e light/dark/system.
- Migration additive fino a `0010_operation_scoped_locator_m5.sql` SHA-256 `8DEA12DF50270E871D717C101B422FAB9E66198E4AAD5D9C40997055BC56C3A2`; catalogo metadata e locator fisico sono separati. Il runtime non può enumerare la tabella locator e usa una funzione `SECURITY DEFINER` stretta, con owner `NOLOGIN`, `search_path` fisso e grant limitato. La risoluzione richiede il logical binding della specifica operation pubblicata; il runtime materializza e mette in cache soltanto le dipendenze dell'operation invocata. Trigger e privilegi colonnari continuano a impedire tamper delle revisioni binding Active/Approved. Pool amministrativo separato dal runtime.
- Container non-root include asset hashati/CSP nonce; quickstart locale usa PostgreSQL 18 e Synthetic Provider senza cloud.
- M5 è congelata sulla baseline `8774c252b233456173c3ab31346fb21390fb8d7d` e tag `m5-admin-ui-baseline-20260807`; M5.5 non riapre i suoi criteri.

### M5.5 — Direct Gateway Access

- `InstallationKind` additivo (`Broker`/`Direct`) con backfill M5 compatibile e nessuna modifica alle migration attestate.
- `GatewayClientPrincipal` unifica identità inbound, credential, metodo di autenticazione e correlation context prima di grant e Connector Runtime.
- Broker e Direct riusano mTLS, PoP ECDSA P-256, BGW1, replay protection, renewal, revoca, grant, publication, provider resolution, restricted egress e audit.
- migration `0011_direct_installation_m55.sql` checksum `62D79829F1B3DF072E563A415B9380053227C6BCCA774C70C113DA372BC977C1`; fresh apply, upgrade M5, seconda applicazione e PostgreSQL 18/RLS qualificati localmente.
- Admin API/UI espongono tipo, stato e soli metadata pubblici della credential; activation code resta one-time e nessuna chiave privata viene restituita.
- sample `samples/DirectGatewayClient` completa enrollment e invoke senza Broker, Named Pipe, DPAPI o vendor secret.
- candidate prodotto `1b3a3b38fa7d01c8c5f96af0324d040e412ac0be`: build Release PASS, 161 test .NET ordinari PASS, PostgreSQL 18 10/10 PASS, 28 Vitest PASS e nuovo browser test Direct PASS. Gate completo/CI e review indipendente restano pending; M5.5 non è ancora dichiarata Done.
- contratti: `docs/architecture/direct-gateway-access.md`, `docs/architecture/connector-runtime-auth-contract.md`, ADR-0020 e coupling audit M5.5.

La run split-host `m3a-live-20260804-131718` è stata classificata **BLOCKED — PRE-HANDOFF INFRASTRUCTURE VALIDATION**: live/readiness erano HTTP 200, ma Docker health falliva per SAN incompatibile e i profili Windows Firewall erano disabilitati. Il runner VM non è stato eseguito e P02 non è stato testato. Cleanup PASS ha lasciato zero risorse della run e ha rimosso l'handoff non utilizzato. I fix health/TLS e firewall reversibile sono implementati. Il runner predispone ora un secondo switch Hyper-V Internal e una NIC VM `M3A-Isolated`, senza NAT/gateway/DNS/forwarding, con rollback SYSTEM, isolamento del profilo Private e probe VM→HOST pre-handoff. La run è storica ed è superata dal PASS product gate `m3a-live-20260805-094131`. Dettagli: `docs/reviews/M3A-BLOCKED-RUN-20260804-131718.md`.

La successiva run `m3a-live-20260804-153103` è **BLOCKED — ROLLBACK WINDOW EXPIRED**:
il runner VM ha incontrato collisione col servizio M0/M1, diritto batch mancante, ACL
installazione insufficiente e versione Broker non parsabile; P02 non è accettato e
non esistono `RESULT.json` o archive completi. Cleanup HOST/VM e invalidazione del
materiale di attivazione sono PASS. L'harness ora risolve soltanto collisioni M0/M1
con ownership verificata, gestisce `SeBatchLogonRight`, concede `ReadAndExecute` al
Legacy SID, usa versione `3.0.0` e separa risultati `PASS` da failure `BLOCKED`.
Dettagli: `docs/reviews/M3A-SPLIT-HOST-BLOCKED-20260804.md`. Una nuova run resta
PENDING e deve usare materiale e RunId nuovi.

Il gate M3A è stato semplificato in HOST `Prepare` → `WAITING_FOR_OPERATOR` → singolo
script PowerShell 5.1 amministrativo nella VM → `RESULT.json` → HOST `Finalize` e cleanup.
Le proprietà bloccanti restano quelle del prodotto (vero service account, Legacy standard
user, P02 e controlli security); automazione Codex/SYSTEM, rollback perfetto, gestione
Tailscale e ricreazione dinamica del laboratorio non sono criteri M3. Il prototipo SYSTEM
interrotto è conservato solo nel branch `experimental/m3a-system-executor` al commit
`b081c527186d4b66b1c03511c0c17856b9ea217a`.

La run `m3a-live-20260805-091023` ha attraversato realmente il Broker Windows Service e
ha prodotto evidenze VM redatte PASS per P02, identità/ACL, applicazione non autorizzata,
grant negato, Event Log/canary e cleanup. La run resta **BLOCKED**, non PASS: durante il
`Finalize` il SecurityDriver HOST ha usato una chiave client effimera incompatibile con
Windows Schannel, quindi la matrice negativa HOST e il bundle finale non sono stati
completati. Il cleanup ha lasciato zero risorse Docker della run e ha ripristinato rete e
Firewall. Il fix harness/test è `678aa07`; serve una run interamente nuova dopo CI verde.
Dettagli: `docs/reviews/M3A-SPLIT-HOST-BLOCKED-20260805.md`.

## Test ed esiti

| Suite/comando | Esito atteso dell'ultima verifica | Copertura |
|---|---|---|
| `eng/build.ps1` | PASS, zero warning/error | intera solution Release |
| `eng/test.ps1` | PASS | unit, Windows integration, E2E |
| `eng/validate-docs.ps1` | PASS | link/struttura/schema documentali |
| `eng/scan-secrets.ps1` | PASS | repository escluso materiale sorgente riservato |
| `eng/generate-sbom.ps1` | PASS | SBOM SPDX degli artefatti |
| `Broker.Core.Tests` | 26 PASS | lifecycle/grant, AEAD/nonce/AAD/version, framing e hard limits |
| `Broker.Integration.Tests` | 28 PASS | DPAPI, pipe/storage ACL, persistence/corruption, identity/handle, IPC, redaction, CNG, handshake Schannel e regressioni harness M3 |
| `VerticalSlice.Tests` | 1 PASS | vertical slice e negative/security path |
| `Gateway.Unit.Tests` | 35 PASS | security M2/M3 e 10 contract/lifecycle/cache/bounds/corruption test M4 |
| `Gateway.Integration.Tests` | 9 PASS | API/Admin e schema; test real-PG condizionali eseguiti nel gate PG18 |
| Totale suite | 99 PASS | 26 Broker Core + 28 Broker integration + 35 Gateway unit + 9 Gateway integration + 1 E2E |
| CI `m3-deterministic-container-slice` | PASS, run `30903757495`, commit `91963ce` | Gateway/PostgreSQL 18/Vault/vendor reali, matrice positiva/negativa, non-root/read-only, redazione, cleanup ed evidence SHA-256 `A52CACB8…FCA30` |
| PostgreSQL 18 effimero locale | 2 PASS | migration, FORCE RLS, registry enrollment/grant/replay/revoca |
| CI `gateway-postgresql-18` | PASS | run `30896803567`: PostgreSQL 18, migration apply/no-op, checksum, ruoli, FORCE RLS, tenant isolation e cleanup |
| CI `gateway-container` | PASS | run `30896803567`: build/esecuzione, non-root/read-only, live/ready, fail-closed, secret scan, SBOM e shutdown |
| parsing `tools/live-matrix/*.ps1/*.psm1` | 9 PASS | sintassi PowerShell dell'intero harness |
| prerequisite check non elevato | expected FAIL con `LIVE_MATRIX_REQUIRES_ELEVATION` | fail-closed prima di qualsiasi modifica di sistema |
| probe command non valido | expected exit 1 con report redatto `unknown_probe_command` | contratto di errore machine-readable |

In aggiunta, quattro critical test IPC/identity/cancel/redaction sono passati per 20 iterazioni consecutive (80 esecuzioni).

I conteggi e gli esiti definitivi vanno aggiornati se una successiva esecuzione modifica le suite.

La matrice live A-F è PASS sulla VM `DESKTOP-5T30P6J` con RunId `m0-m1-20260803-232955`; il bundle locale e il relativo hash sono registrati nella documentazione di evidence.

## Criteri di accettazione soddisfatti nel perimetro

- **AC-001:** Vendor Secret assente da client e boundary Broker-Gateway, verificato E2E.
- **AC-002:** virtual service account, restart e persistenza post-reboot verificati live.
- **AC-003:** policy automatica e processo realmente distinto sotto lo stesso utente verificati live.
- **AC-004:** separazione service identity/gestionale/altro utente, ACL e DPAPI cross-user verificate live.
- **AC-005:** chiavi e ciphertext differenti tra due Installation.
- **AC-006:** audit strutturato senza payload/secret e verifica E2E sul secret sintetico.
- **AC-007:** il Gateway harness restituisce solo la risposta applicativa, mai il secret.
- **AC-008:** il Broker dipende da `IGatewayInvoker` e non possiede dipendenze o API Vault.
- **AC-009:** il client non espone URL; l'invoker usa esclusivamente la BaseAddress configurata.
- **AC-010:** il client non espone secret reference Gateway e può usare solo grant Connector/operation.
- **AC-011:** il Gateway M2 deriva Tenant/Application/Installation dal digest del certificato registrato.
- **AC-012:** grant cross-Tenant e input Tenant client-side sono negati; FORCE RLS PASS su PostgreSQL 18 reale locale.
- **AC-013:** revoca verificata prima di grant, Vault, DNS e dispatch; il gate E2E completo resta M3.
- **AC-014:** ConnectorVersion persistita e amministrata via API/CLI con checksum canonico.
- **AC-015:** publish/supersede/rollback atomici verificati in-memory e PostgreSQL 18.
- **AC-016:** JSON Schema Draft 2020-12 e semantic/security validation corpus PASS.
- **AC-017:** runtime Published-only, binding mancante, stale cache e storage corrotto fail-closed.
- **AC-018:** PASS CI; immagine eseguibile non-root/read-only, health/readiness, fail-closed, secret scan, SBOM e shutdown verificati.
- **AC-020:** sorgenti, toolchain pinned e istruzioni build/test presenti.
- **AC-021:** E2E ripetibile interamente con servizi e certificati sintetici.
- **AC-023:** esempio Secure Layer eseguito dalla suite E2E.
- **AC-027:** generazione SBOM SPDX verificata.

Per M3A, AC-001/006/007/009/010/011/012/013/021/023 hanno evidenza container deterministica e split-host PASS-LIVE. Lo smoke M3B resta PENDING come qualificazione separata dell'Azure Deployment Pack; la baseline Core è il tag M3A.

**AC-002 e AC-004 restano PASS-LIVE sul commit testato invariato. M2 è Done.** Il gate indipendente M2 è PASS sul commit candidato `b6e1e46aebbd005d1bacf20943b358f6ccb6ea1a`; il tag annotato di baseline viene applicato soltanto dopo la replica verde sul commit documentale conclusivo.

## Debito tecnico noto

- il server supporta multiplexing e `Cancel`, ma l'SDK sottile apre ancora una connessione per invocazione e non offre un client persistente condiviso;
- i frame Data/End sono codificati ma l'assembly streaming 16/64 MiB non è ancora esposto dall'SDK; gli input M1 usano control frame base64 e quindi un limite effettivo inferiore;
- key rotation è leggibile dal formato/repository e testata nel core, ma manca un comando operativo atomico di rotazione;
- installazione MSI, upgrade/repair/uninstall e signature appartengono alle milestone di packaging/hardening;
- nessuna compatibilità .NET Framework 4.7.2 o adapter COM/C ABI/CLI: sono esplicitamente M6;
- log/wire redaction copre normal, denied, invalid payload e crypto failure anche nel Windows Event Log live; crash non gestiti e telemetry futura restano aperti;
- il Gateway del vertical slice è un harness, non implementa identity Installation, revoca, replay distribuito, Vault reale o restricted egress production.
- il challenge store M2 è in-memory/single-node come consentito da ADR-0008; prima dello scale-out servirà storage TTL condiviso o challenge stateless firmata;
- i locator PostgreSQL e le funzioni RLS sono PASS sia sul cluster PostgreSQL 18 effimero locale sia nel service container CI indipendente;
- Key Vault/Managed Identity è implementato ma non provato live senza ambiente Azure;
- non esiste ancora idempotency record/runtime deduplication: l'envelope valida la key e il retry è limitato alle operation server-side idempotenti; la semantica completa resta nel runtime Connector M4;
- Gateway HTTP v1 e IPC v1 restano provvisori fino al gate M3.
- il workflow M3A container prova Gateway e servizi reali ma non sostituisce il P02 live;
  la fase VM richiede una console amministrativa dell'operatore, non Codex elevato;
- M3B è implementata ma non eseguita: mancano environment GitHub protetto, federazione OIDC e subscription Azure dev autorizzata;
- la rete Default Switch resta esclusa dal gate; la rete interna M3A dedicata è automatizzata ma deve ancora superare la prova live e il rollback reale sull'HOST/VM;
- le action `checkout@v4`/`upload-artifact@v4` producono un warning di runtime Node 20 deprecato sul runner corrente; non altera l'esito ma richiede upgrade quando disponibile.

## Decisioni ancora aperte

- policy di upgrade applicativo: publisher Authenticode, hash pinning o combinazione per ciascun prodotto;
- procedura di provisioning/backup/recovery del profilo della virtual service identity e delle data key;
- implementazione M9 dell'MSI conforme ad ADR-0017; il contratto architetturale di provisioning è ora accettato;
- semantica streaming e aggregate limits da validare in M2/M3 prima del freeze IPC per M6;
- policy CA/trust chain e certificate forwarding dell'hosting Azure da validare con l'ambiente DEP-02/M9;
- scelta scale-out del challenge store prima di eseguire più repliche Gateway;
- invalidazione proattiva della cache Key Vault e circuit breaker rinviati ai moduli operativi successivi sulla base di metriche reali; M2 usa cache in-process con TTL massimo 5 minuti.

## ADR

Nessun ADR è stato modificato da M2: l'implementazione segue ADR-0002/0005/0007/0008/0013/0015. ADR-0017 resta la decisione per il provisioning MSI futuro. Upgrade policy, recovery, streaming e key rotation restano decisioni operative future.

# Implementation status

Aggiornato: 2026-08-10

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
| M6 — auth HTTP/OAuth primitives | Remediation mirata dei 7 finding qualificata | PR #9 product commit `9a7db4b`: CI exact-head 21/21 PASS; authority capability da snapshot Published, bearer destination-bound, correlation, refresh tombstone, query hardening, user-agent boundary e diagnostic redaction; nessun connector sanitario production |
| Auth Phase 2 / Wave 1 — OAuth PKCE S256 + Client Credentials | **GO sul product candidate; merge non eseguito** | PR #17 product candidate `857810a04d1be86905bda26156e9660cf82f8bab`: CI exact-head 21/21 PASS e review indipendente GO; profili provider-neutral, authority endpoints nel four-eyes digest, cache/single-flight e invalidazione per security key |
| M6 — SOAP/Basic/Session primitives | Implementato sul branch; remediation PR #10 e CI/review pending | AP-01/AP-02/AP-07 sintetiche, cache/stamp/deadline/Fault hardened, server SOAP HTTPS reale e 21 casi mirati PASS locali |
| Wave 1 — Generic opaque-session HTTP projection | Remediation local product gate PASS; CI exact-head e targeted re-review pending | 312 suite ordinaria (302 PASS, 10 PG conditional); targeted 49 unit (34 generic + 15 SOAP), 10 integration (5 generic + 5 SOAP), 17 architecture e 11/11 PostgreSQL 18 PASS; handoff non-forgeable da Published state, cache SOAP M6 ripristinata, final race zero-network |
| Wave 1 — Typed composed SOAP authenticated dispatch | Remediation product gate locale PASS; CI exact-head e re-review pending | strategia runtime production exact-kind post grant/Published, Basic helper non esportato, compatibilità Connector v1 preservata; 433 ordinary PASS + 23 PG conditional, 124/124 Gateway integration con PostgreSQL, 99 unit mirati, 20 real-HTTPS regression, 11/11 store→publish→runtime→TLS, 24 architecture e `FULLSTACK-01` PASS; nessun connector production |
| Wave 1 — Typed SOAP session handshake + authorized external admission | Shared-lifecycle wiring remediation qualificata localmente; CI exact-head e targeted re-review pending | PR #23 commit `f08eb9762fcc21dc7d6d7ba236cf6a80840dfac9`: `OpaqueSessionLeaseProvider` è l'alias del lifecycle singleton posseduto da `SoapSessionClient`; vero host `Program`/HTTP/BGW1/Published/`ComposedSoapExecutionStrategy` riusa la sessione promossa senza reacquire; 120 unit session/composed, 38 integration mirati, 509 ordinary e 10×133 PostgreSQL integration PASS |
| Wave 1 — Provider-neutral Connector execution seam | Ultima remediation mirata implementata; full gate/CI exact-head e targeted re-review pending | bridge no-IVT vincolato allo snapshot Published iniziale con stale A→B zero-effect; full lifecycle PostgreSQL aggiunto; negativi cross-module/ciclo descriptor-atomic; loader invariato |
| Wave 1 — Connector capability completion | Implementata; qualificazione exact-head/CI e review indipendente pending | tre adapter esistenti registrabili da modulo esterno, input server-owned exact-Published, profilo verticale bounded, signing RS256/x5c opaco e restricted HTTPS/mTLS invocation-bound; E2E reali in-memory e PostgreSQL 18 PASS senza connector production |
| M6 — Certificate, Signing and outbound mTLS primitives | Wave 2 remediation dei quattro finding implementata; product-head CI PASS | PR #11; 49 test AP-05/AP-06 PASS locali; workflow `31201004049` e `31201004276` verdi su `1ae76f6` |
| Wave 1 - Generic JWT/X.509 extensions | Remediation mirata local gate PASS; CI exact-head e rereview pending | baseline `6e1a7c626e0e24d0a385c611fc03faef51598889`; 304 ordinary, 71 PostgreSQL relevant, scan/SBOM/vulnerability/Core export PASS |
| Healthcare Wave 1 — Regional ePrescription | Foundation compilata; profili regionali non pubblicabili | capability opaca Core post-auth con stato/grant verificati indipendentemente dalle credenziali, adapter al vero store Published, schema estensioni e safe-code allowlist server-owned, isolamento cross-profile; 14 test pack + 4 architecture PASS locali; Lombardia ed Emilia-Romagna `BLOCKED_BY_SPEC` |
| M3B e milestone/connector production successivi | Non iniziati | nessun cloud reale, connector sanitario production o adapter commerciale |
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
- candidate prodotto `1b3a3b38fa7d01c8c5f96af0324d040e412ac0be`: build Release PASS, 161 test .NET ordinari PASS, PostgreSQL 18 10/10 PASS, 28 Vitest, browser mock 37/37, `FULLSTACK-01`, scan, SBOM e cleanup Docker PASS. CI e review indipendente restano pending; M5.5 non è ancora dichiarata Done.
- contratti: `docs/architecture/direct-gateway-access.md`, `docs/architecture/connector-runtime-auth-contract.md`, ADR-0020 e coupling audit M5.5.

### Auth Phase 2 / Wave 1 — OAuth PKCE S256 e Client Credentials

- Authorization Code supporta profili Published legacy senza `pkcePolicy` (`NONE`) e profili `S256_REQUIRED`; non esiste fallback `plain` e verifier/challenge restano server-owned;
- Client Credentials usa soltanto endpoint, client identity, secret binding, scope, audience/resource e limiti dal Published snapshot, con `client_secret_basic` e restricted transport;
- authorization endpoint e token endpoint sono dipendenze semantiche esplicite, incluse nell'artefatto/digest four-eyes e nei risk indicator insieme alla destinazione protetta;
- cache condivisa e bounded per i due grant; acquisizione iniziale/esplicita e reacquisition su scadenza sono single-flight per security key, invalidazione e generation sono scoped alla security key/Connector, senza invalidazione cross-tenant;
- schema e runtime rifiutano control characters e redirect URI malformate, con user-info, query o fragment; ogni raw token response viene azzerata anche quando la revalidation post-transport fallisce;
- test mirati: 46 casi OAuth real HTTPS, 19 casi Connector Configuration nel gruppo interessato e percorso PostgreSQL 18 `W1_IT_DAT_PostgreSQL18_OAuth_validation_approval_publication_and_operation_locator_resolution_when_configured`;
- scope ancora escluso: inbound identity, connector production, cache distribuita, provider/cloud adapter e merge in `main`. Il product candidate `857810a04d1be86905bda26156e9660cf82f8bab` ha completato CI exact-head 21/21 (run `31262148895` e `31262148897`) e review indipendente con verdetto GO; un eventuale commit conclusivo solo documentale deve conservare verdi i check PR prima del merge.

### M6 — SOAP/Basic/Session Authentication Primitives

- assembly Core separato `Gateway.ConnectorRuntime.Auth.Soap`, dipendente soltanto dal runtime pubblico e dalle provider abstractions;
- AP-01 applica HTTP Basic esclusivamente da binding server-side e risolve username/password al momento dell'uso, senza cache plaintext o valori nelle eccezioni;
- AP-07 serializza deterministicamente SOAP 1.1/1.2, fissa Content-Type/SOAPAction e applica parser XML con DTD/entity/network resolution disabilitati e limiti di size, depth, node e attribute complexity;
- AP-02 mantiene sessione upstream e challenge nel Gateway, espone soltanto reference opache, usa chiavi cache scoped a Tenant/Installation/Application, Connector/version, Environment, binding/endpoint/credential revision e profile; la cache è limitata a 256 key, una interaction e una generation corrente per key, con completion atomica ed eviction lazy delle entry scadute;
- ogni riuso verifica obbligatoriamente lo stamp server-side corrente: credential resource `Active`, credential revision, binding revision ed endpoint revision; disable/rotate falliscono prima di secret, resolver o transport;
- login, challenge completion transport-neutral, expiry, una sola reacquisition controllata, retry business solo se dichiarato, logout/invalidation e SOAP Fault mapping tipizzato; la deadline copre request, header, body bounded e parsing, mentre Fault SOAP 1.1/1.2 ambigui o duplicati sono negati senza re-login;
- server sintetico Kestrel HTTPS reale con Login, challenge, BusinessOperation, Logout, expiry, invalid session, Fault, malformed XML, oversize, timeout e contatori;
- nessuna modifica all'autenticazione inbound, nessun OAuth, certificate/signing, healthcare production, SAML, WS-Security, XML-DSig o scripting XML generico;
- report: `docs/testing/M6-SOAP-AUTH-IMPLEMENTATION-REPORT.md`.

### Wave 1 — Typed composed SOAP authenticated dispatch

- `PublishedComposedSoapAuthorityResolver` compone principal/grant, snapshot Published, endpoint/operation, tre logical secret binding esistenti, placement session e metadata SOAP in una capability senza costruttore pubblico;
- `RestrictedEgressService` seleziona dopo grant e risoluzione Published una sola `IConnectorExecutionStrategy` tramite execution key server-owned; authentication kind resta indipendente e strategia mancante o duplicata è negata senza fallback e senza rete;
- `SoapHttpRequestMetadata` deriva `text/xml` + SOAPAction quoted per SOAP 1.1 oppure `application/soap+xml` con parametro action per SOAP 1.2; caller e runtime payload non possono fornire header/action/version;
- Basic viene risolto sul solo request interno tramite helper e binding internal non esportati; provider/resource/version/revision/checksum/stamp restano dipendenze esatte; la sessione production è presa dalla cache server-owned e usa lease/generation/expiry M6; Authorization, SOAPAction e Content-Type non sono placement custom valide;
- final revalidation Published/resource/session immediatamente prima di `SendSoapAsync`; rotate Basic/session, endpoint/revision e action policy producono zero rete nei test deterministici e real HTTPS;
- `SendSoapAsync` conserva HTTP 500 e il parser Fault hardened mantiene cardinalità/namespace strict; malformed/duplicate Fault è negato;
- Connector Definition v1 e catalogo riconoscono in modo opt-in `opaqueSessionHttp` e `soapBasicOpaqueSession`, senza header bag; checksum canonico/four-eyes copre l'action e le dipendenze; la denylist storica di `allowedClientHeaders` resta separata e una definizione v1 già valida con `SOAPAction` continua a load/publish/execute senza rewrite;
- E2E PostgreSQL reale con ruoli migration/admin/runtime separati, store, validate, editor/approver distinti, publish atomico, catalogo, runtime strategy e SOAP TLS pinned passa 11/11; tutte le negazioni richieste provano contatori SOAP e generic a zero senza `MutableSnapshots`;
- product gate locale PASS: build Release senza warning/errori, 433 test ordinari PASS e 23 PostgreSQL-condizionali SKIP, poi 124/124 Gateway integration con PostgreSQL 18 e zero skip; 28/28 Vitest, drift API/runtime, build Admin, `FULLSTACK-01`, redazione/cleanup, scan, SBOM, vulnerability e document validation PASS;
- report: `docs/implementation/WAVE1-TYPED-COMPOSED-SOAP-DISPATCH.md`; Core export, CI exact-head e review indipendente restano pending sul candidate commit.

### Wave 1 — Typed SOAP session handshake e authorized external admission

- profilo di handshake selezionato esclusivamente dal ConnectorVersion Published e incluso nel checksum four-eyes con SOAP version/action, QName esatti, adapter request/response/validation compilati, endpoint binding/path, limiti, deadline e lifetime;
- il validation adapter scrive/legge soltanto payload tipizzato e non possiede endpoint, DNS, credential locator, timeout o transport; il Core risolve binding e credenziali Basic server-side, applica restricted HTTPS con pinning/no proxy/no redirect/deadline/bounds e interpreta solo outcome chiusi;
- nessun dizionario libero, XPath, XSLT, reflection dinamica o template XML: il Core apre Envelope/Body e payload esatto; la boundary XML applica DTD/entity/network resolution disabilitati con limiti di byte, depth, node, attributi e text/CDATA/attribute individuali prima di `XDocument`;
- outcome chiusi `Issued`, `ExternalAdmissionRequired` e `Rejected`; il valore di sessione resta server-side e il chiamante riceve solo reference o intent opachi;
- gli intent di ammissione esterna vivono nella cache SOAP M6 esistente, sono bounded, scoped a Tenant/Installation/Application, Connector/version, Environment, binding/endpoint/profile e security fingerprint, con expiry, single-use e provenance `InteractiveHandoff`;
- la completion pubblica accetta soltanto principal autenticato, reference opaca e candidate bytes; risolve server-side intent, Connector/operation/profile/key/provenance/expiry/validator, reautorizza il grant e solo allora costruisce `ExternalSessionCandidate` internal owned/zeroed; provenance diversa da `InteractiveHandoff` è negata;
- Admin e runtime store condividono una authority process-local a 64 stripe: publish/binding/resource mutation aprono una lease attiva e avanzano generation a begin/end senza lock durante I/O; dopo tutti gli await la promozione sincrona richiede generation exact e zero mutation attive, verifica proof/candidate/intent/session generation e consuma/promuove nella stessa stripe senza gap;
- fake `OperationCanceledException` e altre eccezioni extension sono normalizzate senza inner/message; solo un token caller/deadline realmente cancellato conserva semantica OCE con il token effettivo;
- CreateSession/ValidateSession sintetiche sono provider-neutral e validate con ordine/nesting rigoroso su HTTPS reale; il business call successivo prova il riuso della sessione, mentre M6 legacy rimane compatibile;
- il composition root mantiene `SoapSessionClient` singleton e registra `OpaqueSessionLeaseProvider` come alias di `SoapSessionClient.OpaqueSessionLeases`: handshake, admission, AP-02, opaque HTTP e composed SOAP osservano la stessa cache/generation; non esiste una seconda registrazione `SoapSessionCache`;
- evidenza shared-lifecycle remediation: 120 unit session/composed/opaque/legacy e 38 integration mirati PASS, 3/3 guardie architecture mirate e 26/26 architecture complete, suite ordinaria 509 totali (482 PASS, 27 PostgreSQL conditional), PostgreSQL 18 canonico 10×133 PASS più 80/80 matrici concorrenti, Admin 28 unit + 37 UI mock + 2 a11y + full-stack 1/1 senza retry, build Release zero warning/errori; document/secret/vulnerability scan e SBOM completo con 165 pacchetti container PASS. Gitleaks e Core export exact-head sono eseguiti sul commit documentale e registrati nell'evidence esterna; CI e targeted re-review restano gate di handoff, merge non autorizzato;
- decisione e report: ADR-0022, `docs/implementation/WAVE1-TYPED-SESSION-HANDSHAKE.md` e `docs/testing/WAVE1-TYPED-SESSION-HANDSHAKE-REPORT.md`.

### Wave 1 — Provider-neutral Connector execution seam

- execution strategy key tipizzata, schema/canonical checksum/four-eyes bound e distinta da
  `GatewayAuthenticationKind`; definizioni legacy mappate server-side senza rewrite o republish;
- registry exact-one bounded: duplicate key fallisce startup, missing/unknown nega senza fallback;
  grant e risoluzione Published precedono selection/handoff;
- `AuthorizedConnectorExecution` public-read/internal-construct espone solo identity e operation
  server-derived, correlation, auth/key/content type e payload owned/read-only;
- modulo startup esplicito deployment-owned con path assoluto canonico, assembly full identity, type
  e module ID esatti; solo local fixed/direct path, nessun UNC/device/traversal/reparse; metadata e
  load dalla stessa immagine buffered; nessuno scanning/hotload/service locator;
- registrar buffered valida ricorsivamente un unico costruttore pubblico e consente soltanto
  dipendenze module-owned esplicitamente registrate (`SAFE_HOST_DEPENDENCIES=NONE`); provider DI,
  scope, collection di strategy, delegate/cross-module, cicli e varianti annidate falliscono startup;
  test comportamentali verificano che il modulo fallito non commetta descrittori parziali;
- ogni strategy dichiara auth-kind supportati, validati e snapshottati a startup; mismatch nega prima
  di strategy/rete. Solo marker Core internal preservano failure qualificate; un `GatewayException`
  external forgiato perde code/status/retryability e diventa `BGW-EGRESS-UPSTREAM-REJECTED`;
- bridge pubblico minimo/non costruibile, per-invocazione e one-shot espone soltanto typed session
  handshake e composed SOAP senza selector; uno stamp interno opaco catturato dalla stessa snapshot
  Published che produce operation/auth/key lega version/publication/canonical/binding/resource,
  operation e strategy key. Ogni rilettura valida A senza adottare B e il confronto finale avviene
  dopo la preparazione awaited, adiacente al primo effetto; retained replay negato;
- assembly sintetico separato usa solo contratti pubblici e nessun friend access; production-host E2E
  attraversa HTTP/BGW1, principal, grant, Published lifecycle, registry e risultato; il full path
  handshake→admission autenticata→sessione promossa→composed SOAP HTTPS gira anche sul vero store
  PostgreSQL con editor/approver distinti. Race deterministici A→B negano handshake con provider/
  rete/sessione a zero e business SOAP senza dispatch/reacquire, incluso cambio strategy key;
- remediation targeted gate corrente: 83/83 unit session/composed/opaque/configuration, 2/2 race
  A→B e 2/2 negative constructor graph PASS; hosted seam 18 totali (16 PASS, 2 PostgreSQL
  conditional), 32/32 architecture e build Release zero warning/errori. Suite ordinaria 551
  totali (522 PASS, 29 PostgreSQL conditional), gate PostgreSQL 18 153/153, Admin 28 unit +
  37 UI mock + 2 a11y e `FULLSTACK-01` PASS; M3 split-host regressions, docs, secret scan,
  vulnerability inventory, SBOM container da 165 pacchetti e Core export verificato PASS.
  Exact-head CI resta il gate di handoff sul commit candidato; merge non autorizzato;
- decisione: ADR-0023 e `docs/implementation/WAVE1-CONNECTOR-EXECUTION-SEAM.md`.

### Wave 1 — Connector capability completion

- `AuthorizedConnectorExecution` proietta una copia bounded dell'esatto
  `extensionConfiguration` Published senza esporre stamp, store o autorità di mutazione;
- il registrar ristretto ammette soltanto i tre contratti adapter già consumati dal runtime typed
  session (request, response, external validation); ownership del modulo, duplicati, limiti e grafo
  costruttori restano fail-closed prima del commit DI;
- request e validator dichiarano nomi statici bounded; il profilo Published li associa uno-a-uno a
  binding opachi approvati. Core risolve i locator e fornisce una view non costruibile con sola
  scrittura XML nominata, senza getter stringa/provider reference;
- il bridge privato aggiunge signing RS256 e restricted transport mTLS one-shot. Claim, policy,
  binding, SPKI, x5c, endpoint, metodo, header Authorization, certificato, timeout e response bound
  restano server-owned; il token compatto non è leggibile e vale solo sullo stesso bridge;
- la migration additiva `0012_connector_capability_locator_scope.sql` estende il locator PostgreSQL
  soltanto ai binding di signing e input dichiarati dalla stessa operation Published e conserva
  principal/grant/scope/revision/checksum e privilegi runtime least-privilege;
- i test sintetici neutrali provano il lifecycle external adapter→input server-owned→handshake→
  admission→shared session→composed SOAP e il flusso Published profile→RS256/x5c→mTLS→restricted
  HTTPS. Entrambi attraversano anche PostgreSQL 18, editor/approver distinti, publication, BGW1,
  grant e reale effetto esterno;
- negativi mirati coprono spoof caller, mapping missing/extra/duplicate, adapter duplicate/wrong
  module, provider/store/transport DI, claim non ammessa, endpoint/key/certificate/profile arbitrari,
  retained bridge e race A→B durante input, signing/public material e dopo DNS prima del transport;
- nessun connector sanitario/commerciale, provider, adapter family ipotetica, generic store/provider
  capability, signing oracle, arbitrary authenticated HTTP o public certificate view è stato aggiunto;
- decisione e inventory: ADR-0024 e
  `docs/implementation/WAVE1-CONNECTOR-CAPABILITY-COMPLETION.md`.

### M6 — Certificate, Signing and outbound mTLS primitives

- modulo Core provider-neutral `Authentication.CertificateSigning`, separato da inbound
  Broker/Direct e senza dipendenze cloud o Healthcare Pack;
- `IKeyOperationProvider` ristretto a signing digest e metadata pubblici: nessuna API di
  export private key, nessun KMS universale e nessun fallback automatico Broker;
- JWT RS256 con policy risolta server-side per Published ConnectorVersion/operation:
  revision/checksum, issuer/audience/subject/claim allowlist/lifetime/key/resource binding
  non sono input del Connector; `jti` è server-generated e la SPKI usata per verificare
  la firma deve corrispondere al digest SPKI approvato;
- mTLS outbound one-shot: policy/binding/status/revision/endpoint sono rivalidati subito
  prima di DNS/dispatch e il certificato resta interno al sender, senza handle riusabile;
- rotate/disable risolti per invocazione senza private-key/certificate cache: revision 1
  non viene riutilizzata dopo revision 2 e disable nega prima del provider/network;
- provider sintetico con chiavi/certificati per-run e server TLS locale che richiede il
  client certificate atteso; hostname e certificato errato sono negati;
- 49 test dedicati PASS locali, inclusi policy substitution, retained rev1, endpoint
  substitution, fingerprint/SPKI substitution ed exception provider inattese. Connector FVG/Umbria reali, lifecycle autoritativo,
  OAuth/PKCE e SOAP/session restano esclusi e **NO-GO**.

### Wave 1 - Generic JWT/X.509 extensions

- `ICertificatePublicMaterialProvider` espone soltanto leaf DER, chain pubblica opzionale,
  metadata e identita SPKI pubblica; nessun export private key/PFX/password/locator;
- `JwtCertificateHeaderMode` tipizzato (`None`, `Leaf`, `Chain`) e policy-bound; `x5c`
  usa Base64 standard, leaf-first, senza header bag o input DER dal caller;
- fingerprint e SPKI sono derivati dal DER reale e legati constant-time alla stessa
  identita approvata usata per verificare la firma RS256 provider-side;
- `JwtTemporalClaimMode` conserva per default `iat+nbf+exp` e abilita `iat+exp` senza
  `nbf`, riusando lifetime/skew M6;
- subject e trusted claim possono usare Tenant/Application/Installation autenticati o
  una runtime source tipizzata scelta dalla Published policy e risolta da un resolver
  registrato server-side; provenance e binding esatti invocation/policy/catalog/resource
  negano business promotion, source substitution e cross-context reuse senza introdurre
  principal globale, dictionary/espressioni/reflection o raw subject override;
- public material usa storage privato bounded (64 KiB per DER, sette issuer, 256 KiB
  totali), copy-on-read e metadata collection copy-safe; `TrustedClaims` e allowlist
  restano snapshot strutturalmente immutabili dopo il checksum;
- policy/binding/catalog/resource sono rivalidati prima della firma e prima del ritorno:
  rotate/disable negano token e `x5c` stale;
- 91 test certificate/signing e 17 architecture PASS locali; report:
  `docs/implementation/WAVE1-GENERIC-JWT-X509-EXTENSIONS.md`.
- build Release, ordinary suite 304 PASS, PostgreSQL 18.4 relevant 71 PASS, docs, secret scan,
  SBOM, vulnerability inventory e Core export verificato sono PASS locali.

Dual JWT, issuer/CN service-specific, CX/XON/IHE e document hash restano
`CONNECTOR_RESPONSIBILITY`. Il sistema lifetime/skew e `ALREADY_EXISTS`.

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
| `Gateway.Unit.Tests` | 80 PASS | security M2-M6, contract/lifecycle/cache/bounds/corruption, runtime principal, OAuth e SOAP/session |
| `Authentication.CertificateSigning.Tests` | 91 PASS | RS256/policy/claim/replay, generic trusted runtime subject, immutable/bounded public DER/x5c and policy snapshot, temporal, provider redaction, mTLS e rotate/disable |
| `Gateway.Integration.Tests` | 61 PASS, 10 conditional SKIP | API/Admin/OAuth/SOAP/schema; i 10 test PostgreSQL condizionali richiedono il gate dedicato |
| `Architecture.Tests` | 17 PASS | boundary Core/provider/auth writer, generic JWT/X.509, CI, provisioning e OpenAPI |
| Totale suite locale ordinaria | 304 PASS, 10 conditional SKIP | 26 Broker Core + 28 Broker integration + 80 Gateway unit + 61 Gateway integration + 91 certificate/signing + 17 architecture + 1 E2E |
| CI `m3-deterministic-container-slice` | PASS, run `30903757495`, commit `91963ce` | Gateway/PostgreSQL 18/Vault/vendor reali, matrice positiva/negativa, non-root/read-only, redazione, cleanup ed evidence SHA-256 `A52CACB8…FCA30` |
| PostgreSQL 18.4 effimero locale | 71 PASS | suite relevant completa; fresh apply/no-op; container rimosso |
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

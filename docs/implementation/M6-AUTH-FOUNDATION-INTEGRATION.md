# M6 Auth Foundation integration

Data del gate: 2026-08-07  
Verdetto: **PASS — M6 Auth Foundation DONE**

Questo documento attesta esclusivamente l'integrazione delle fondamenta di autenticazione M6. Non attesta connector sanitari production-ready e non avvia SOGEI, Lombardia, FVG o Umbria.

## Baseline e lineage

- baseline iniziale `main`: `f34275096b4960bb5f31840553444935defc3d2d`;
- PR #12, PostgreSQL test isolation: HEAD approvata e resulting SHA `5670b674612c13ce21cff2552329b0355e78bada`, integrata fast-forward senza riscrittura;
- PR #9, HTTP/OAuth: HEAD revisionata `ed60cb3e41bde3ab0078e187593d162405b9bb80`, rebase sopra #12 e resulting/merge SHA `e852d4a2ca1e3dfd4060b278c96f214f8ce5b264`;
- PR #10, SOAP/Basic/session: HEAD revisionata `389ac772b3249210d69f546dd466a45357945f00`, rebase sopra #12+#9 e resulting/merge SHA `3c04424bba79ca55ddfdc3a5671d8e37ef1f173d`;
- PR #11, certificate/RS256/mTLS: HEAD revisionata `8e15bf26866e8f4a0dc7d0611220d78f14f30d81`, rebase sopra #12+#9+#10 e resulting/merge SHA `44be6583632cf3d07cdbf329ed7bfc9316c8313b`.

`44be6583632cf3d07cdbf329ed7bfc9316c8313b` è la HEAD combinata del prodotto qualificata dal gate. Il commit successivo che contiene soltanto questo report è la HEAD documentale e il target del tag annotato `m6-auth-foundation-baseline-20260807`; l'identità Git definitiva del target è quindi registrata dal tag, senza creare riferimenti SHA autoreferenziali nel file.

Le quattro PR avevano verdetto di review **FINAL GO** prima dell'integrazione. Dopo ogni rebase sono stati ripetuti i test mirati, i gate PostgreSQL applicabili, l'export Core e la CI exact-head prima del fast-forward.

## Overlap e conflitti

L'analisi preventiva non ha rilevato file di produzione condivisi fra OAuth, SOAP e certificate/signing. Gli overlap erano di tipo soluzione/progetto, export Core, documentazione/indici e lock file:

- #9/#10: solution, status, contratto auth, threat model, tracciabilità, allowlist, project reference e lock dei test;
- #9/#11: solution, status, contratto auth, threat model, tracciabilità e lock dei test;
- #10/#11: solution, status, contratto auth, threat model, tracciabilità e lock dei test.

PR #9 non ha prodotto conflitti. PR #10 ha richiesto union meccaniche di `BrokerGateway*.slnx`, project reference dei test, lock rigenerati, allowlist Core e sezioni documentali. PR #11 ha richiesto soltanto la composizione delle sezioni documentali; solution e lock si sono auto-allineati. Gli ID di threat sono rimasti univoci: OAuth `TM-046/047`, SOAP `TM-048/049`, certificate/signing `TM-050…053`. Non sono stati introdotti adattamenti semantici, bypass, retry o indebolimenti dei controlli.

## OAuth

PASS sui test mirati e sulle 21 integrazioni HTTPS sintetiche, oltre a 4 architecture test. Sono dimostrati:

- authority e profilo derivati dallo snapshot Published server-owned;
- negazione di profile, endpoint, secret reference e scope substitution;
- bearer destination-bound e zero richieste all'endpoint attaccante;
- correlation binding, state/code replay denial e attempt one-time;
- refresh single-flight, invalidation/tombstone dopo rotation e nessuno stale fallback;
- parameter smuggling, SSRF, redirect e restricted token/resource transport fail-closed;
- challenge/session reference opache e diagnostica redatta.

## SOAP, Basic e sessione

PASS su 14 test unitari mirati, 5 integrazioni HTTPS sintetiche e 2 architecture test. Sono dimostrati:

- Basic risolto e applicato esclusivamente server-side;
- interaction/session cache bounded, generation e security stamp revision-aware;
- AP-02 transport-neutral e challenge one-time;
- acquisition, expiry, una sola reacquisition controllata e logout;
- `Active→Disabled` e rotation `rev1→rev2` fail-closed;
- deadline estesa al response body stalled e parsing;
- SOAP 1.1/1.2, DTD/XXE/external entity denial e limiti XML;
- Fault duplicati, mixed o ambigui negati senza classificazione per re-login;
- fault, errori e diagnostica redatti.

## Certificate, RS256 e mTLS

PASS su 49 test dedicati e 4 provider/architecture boundary test. Sono dimostrati:

- policy JWT server-owned e `ResolvedRs256SigningContext` non costruibile dal consumer;
- negazione di policy substitution, claim injection, HS/RS confusion e key substitution;
- fingerprint e digest SPKI approvati, firma provider-side e verifica della stessa SPKI;
- eccezioni provider sanificate e cancellazione reale preservata;
- mTLS one-shot transport-bound senza handle riutilizzabile pubblico;
- purpose, endpoint e revision binding con revalidation immediata;
- rotate/disable fail-closed e retained revision 1 con zero connessioni;
- handshake TLS locale reale, hostname validation e certificato errato negato;
- nessun generic signing oracle, export di private key/PFX o fallback al Broker.

## PostgreSQL 18 e isolamento condiviso

Il gate dedicato ha usato PostgreSQL `18.4` in un container temporaneo isolato e poi rimosso:

- canonical suite: 3/3 run consecutive PASS, 71 test per run, 213 test eseguiti;
- fresh migration apply: 3/3 PASS;
- seconda applicazione no-op: 3/3 PASS;
- sette tabelle critiche con FORCE RLS: 3/3 PASS;
- pagination, atomic failure injection, Tenant/Application concurrency e binding/publication concurrency: 4/4 PASS;
- retry count 0, sleep nei test 0, parallelismo globale non disabilitato;
- evidence locale ignorata: `.artifacts/m6-auth-foundation-gate/postgresql-qualification.json`, SHA-256 `0A1EA4152ECE3D52BA27741E90AEE17E4AE009DF3136318D301172EC766CEE0B`.

Sono inoltre PASS `gateway-postgresql-18` e `m5-postgresql-18` su ciascuna candidate riallineata e sulla HEAD combinata.

## Combined gate

### Build e test

- Release build: PASS, 0 warning, 0 error;
- suite .NET ordinaria: 271 totali, 261 PASS, 10 PostgreSQL-condizionali SKIP; i 10 sono stati successivamente eseguiti e superati nel gate PostgreSQL dedicato;
- breakdown: Architecture 16/16, Gateway Unit 80/80, Broker Core 26/26, Broker Integration 28/28, Vertical Slice 1/1, Gateway Integration 61 PASS + 10 conditional, Certificate Signing 49/49;
- frontend: 28/28 Vitest, 2/2 accessibility, 37/37 browser mock;
- OpenAPI drift e runtime wire contract: PASS;
- production build e `FULLSTACK-01`: PASS in CI exact-head.

### Architecture invariants

I 16 architecture test, inclusi `HttpOAuthBoundaryTests`, `SoapAuthBoundaryTests` e `ProviderBoundaryTests`, confermano:

1. inbound Broker/Direct separato dall'auth outbound;
2. nessuna decisione vendor auth basata su `InstallationKind`;
3. input connector limitato a logical policy/profile ID;
4. endpoint, resource e policy derivati da stato Published server-owned;
5. nessuna esposizione di password, token, private key, PFX, handle certificato riutilizzabile o provider locator;
6. restricted transport obbligatorio;
7. rotation/disable invalida il materiale stale;
8. AP-02 resta transport-neutral;
9. nessuna dipendenza ciclica OAuth/SOAP/Crypto;
10. dipendenza futura Healthcare Pack consentita solo dalle API pubbliche Core, non dagli internals Infrastructure.

### Security e release

- conservative secret scan e controllo negativo CI: PASS;
- Gitleaks: PASS;
- NuGet vulnerability scan: nessun pacchetto vulnerabile;
- npm audit: 0 vulnerabilità;
- frontend license scan: 407 package lock qualificati;
- SBOM: generazione e validazione PASS; aggregate manifest SHA-256 `A749E9BBFBA14175354746F1C09F9405E047512DE6E3C09B344BA5BE9668B74A`;
- Core export: PASS, 357 file, manifest SHA-256 `D385F7EDDBC5CF099E77D751F27F2393E922195C90316E8A9993CBA758299751`;
- documentation validation e `git diff --check`: PASS;
- cleanup: zero container PostgreSQL di gate e zero processi Node del repository; il container dev preesistente non è stato alterato.

## CI finale sulla HEAD combinata

Tutti i job sono stati eseguiti sullo SHA `44be6583632cf3d07cdbf329ed7bfc9316c8313b`:

- push `ci` run `31214475589`: 6/6 PASS (`build-test`, `gateway-postgresql-18`, `gateway-container`, M3 deterministic, M4 quick-start, Gitleaks);
- push `m5-admin-ui` run `31214474149`: 15/15 PASS, inclusi `m5-postgresql-18`, frontend, browser mock, accessibility, OpenAPI/runtime checks, `FULLSTACK-01`, Core boundary, scans, SBOM e cleanup;
- le corrispondenti PR exact-head run `31214135710` e `31214135658`: PASS.

## Known deferred

- primitive PKCE production, se ancora necessaria oltre la foundation implementata;
- connector healthcare production;
- WSDL/OpenAPI reali;
- lifecycle specifici dei servizi;
- fault taxonomy specifica dei servizi;
- provider ed endpoint reali;
- custody reale delle chiavi FVG/Umbria;
- generic SAML;
- generic WS-Security;
- generic HMAC;
- XML-DSig;
- framework smart-card/VPN.

Questi elementi richiedono characterization e gate propri. Nessuno è implicitamente dichiarato pronto dalla baseline M6 Auth Foundation.

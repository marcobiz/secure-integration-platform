# Piano di implementazione corrente

Aggiornato: 2026-08-24
Baseline CURRENT: `ee3072be5e34a7b0477907a2580dcf454b8a4aba`

Questa è la roadmap attiva. Lo stato sintetico è in
[`IMPLEMENTATION_STATUS.md`](../../IMPLEMENTATION_STATUS.md), la release pubblicata nelle
[release notes](../releases/0.1.0-alpha.1.md) e le slice ordinate nel
[`backlog`](backlog.md). La cronologia dettagliata resta nei tag e nei report esistenti.

## Principi di pianificazione

- una capability è CURRENT solo se integrata in `main`; una release o qualifica esterna
  richiede inoltre il proprio gate exact-head;
- synthetic, live lab, official-test e production sono stati distinti;
- i pack opzionali dipendono dai contratti Core; il Core non dipende da cloud o
  verticali;
- nessuna capability generica entra nella fase senza un blocker riproducibile del golden
  path Core o del gate FSE2;
- una dichiarazione del maintainer non diventa evidence repository;
- le baseline attestate non vengono riscritte;
- la Core alpha è una prerelease pubblicata; l'unica track corrente è FSE2 Organization
  OfficialTest.

## Baseline CURRENT

| Area | Stato | Limite corrente |
|---|---|---|
| M0-M2 | Done | Fondamenta, Broker e Gateway integrati; i gate live storici non sono un installer release. |
| M3A | PASS live lab | M3B Azure resta non qualificato. |
| M4/M5/M5.5 | Done | Connector lifecycle, Admin e Direct Gateway integrati; Direct sample key storage resta non-production. |
| Authentication foundation / Wave 1 | Integrata | Primitive provider-neutral e moduli esterni non qualificano automaticamente un servizio esterno. |
| FSE2 Organization | Synthetic-qualified | 11 operation, dual JWT, S1 `contentCommitment`, A1 mTLS distinta e PostgreSQL canonico; nessuna call live. |
| Local PKCS12 / FSE2 vertical image | Integrati da PR #33, synthetic lab qualified | Provider opzionale `SecretValues=false`, importer offline, overlay e vertical image; custody e OfficialTest aperti. |
| Productization alpha | GitHub public prerelease pubblicata | `v0.1.0-alpha.1` è una Public Technical Preview pubblicata dall'exact source commit `ee3072be5e34a7b0477907a2580dcf454b8a4aba`; ALPHA-LIC/SEC/DOC-04/REL sono PASS senza claim production o FSE2 OfficialTest. |
| Legacy/enterprise | Deferred | MSI, native/COM, cloud live, HA/DR e production non sono track attive. |

PR #33 è merged tramite fast-forward sull'exact main. General 6/6, M5/Admin 15/15,
PostgreSQL FSE2 1/1 zero skip, provider 30/30, architecture 42/42, provider-active
synthetic lab e security micro-review sono PASS/GO nel perimetro attestato. Questi gate
non includono materiale reale, import operativo o chiamate FSE2.

## Esito pubblicato — Core `0.1.0-alpha.1`

### Outcome

Una developer alpha non-production e provider-neutral con un solo golden path:

```text
Direct .NET
→ Gateway
→ Connector REST Published
→ Synthetic Provider
→ mock HTTPS/mTLS
→ risposta sanificata e audit metadata-only
```

### Dipendenze chiuse

DOC-01 è stato il prerequisito comune iniziale. Dopo DOC-01 sono stati chiusi:

- **documentazione Core:** DOC-02 per architecture/security/deployment e DOC-03 per
  OpenAPI/API/generated types;
- **consumption Core:** ALPHA-REST, ALPHA-DIRECT e ALPHA-CLEAN;
- **productization:** ALPHA-VER può iniziare senza attendere DOC-02/03; ALPHA-ART segue
  ALPHA-VER;
- **governance:** ALPHA-LIC e ALPHA-SEC, inclusi i gate di licenza e DCO applicabili;
- **documentazione FSE2:** DOC-04 riallinea il pack opzionale allo stato integrato da
  PR #33, senza eseguire o richiedere FSE2-T01..T06.

ALPHA-ADOPT è PASS sulla simulazione indipendente autorizzata; non prova adoption
production o market fit.

ALPHA-REL è stato l'ultimo step e ha richiesto ALPHA-DOC-01, ALPHA-DOC-02,
ALPHA-DOC-03, ALPHA-DOC-04, ALPHA-REST, ALPHA-DIRECT, ALPHA-CLEAN, ALPHA-ADOPT,
ALPHA-VER, ALPHA-ART, ALPHA-LIC e ALPHA-SEC, oltre ad ALPHA-01..08 verdi sull'exact
release commit. ALPHA-DOC-04 è una dipendenza di verità documentale soltanto: non
richiede `validate-cda` live né FSE2-T01..T06. La qualifica FSE2 OfficialTest non blocca
la release Core alpha.

### Vincoli

- FSE2 e pack vendor-specific non entrano nel golden path Core;
- MSI, COM/C ABI, Azure live, HA/DR e API compatibility stabile restano esclusi;
- il raw SHA del Core export è evidence della singola run. `ALPHA-ART` aggiunge un digest
  normalizzato dell'inventario perché `generatedAtUtc` rende il raw manifest run-specific;
- la pubblicazione non implica production readiness, stabilità API, firma/provenance o
  qualifica di servizi esterni.

## Track corrente — FSE2 Organization OfficialTest

### Outcome

Il primo outcome è `validate-cda` nell'ambiente ufficiale di test, con dataset sintetico
autorizzato, exact configuration ed evidence redatta. Attachment hash, create/replace e
status seguono; non sono prerequisiti di `validate-cda` senza nuova evidenza ufficiale.

### CURRENT integrato

- pack Local PKCS12 opzionale, senza generic secret retrieval e con
  `SecretValues=false`/deny-only slot;
- importer offline e path/CSR/ACL/custody guard sintetiche;
- vertical image che include `Healthcare.FSE2`, mentre l'immagine Gateway Core
  predefinita continua a escluderlo;
- overlay Compose e provider-active synthetic lab;
- S1 `contentCommitment`, A1 mTLS distinta, CI e review sul perimetro sintetico.

### TARGET ancora aperto

- accesso/import operativo e verifica della custody reale;
- distinzione verificata tra accesso test e software accreditation;
- eventuale `ActivationHmacSecretReference` composta come capability server-owned
  separata, mai come generic secret retrieval del pack certificati;
- warning mapping bounded per `validate-cda`;
- exact OfficialTest image/configuration e driver operativo redatto;
- qualunque chiamata FSE2, `validate-cda`, create/replace o status live.

### Sequenza

1. intake esterno: distinguere accesso test e accreditamento software;
2. import/custody preflight fuori Git;
3. composition delle capability server-owned richieste;
4. public metadata, chain, signing S1 e mTLS A1 preflight senza rete FSE2;
5. warning mapping bounded necessario a `validate-cda`;
6. vertical image e configurazione exact OfficialTest;
7. E2E sintetico dalla medesima immagine/configurazione;
8. `validate-cda` OfficialTest con dataset sintetico autorizzato;
9. `attachment_hash` sugli exact file bytes;
10. create/replace autorizzati;
11. status bounded/redatto;
12. workflow successivi soltanto se previsti dal piano.

### Gate e claim

FSE2-T01..T04 e T06 abilitano soltanto la claim `validate-cda` official-test sull'exact
configurazione attestata. FSE2-T05 abilita soltanto i successivi workflow effettivamente
eseguiti. I test sintetici delle 11 operation non diventano una claim 11/11 live. Nessun
gate di questa track implica production.

## Relazione storica di chiusura e track corrente

```text
DOC-01
  ├─→ ALPHA-DOC-02 ───────────────────────────────────┐
  ├─→ ALPHA-DOC-03 ───────────────────────────────────┤
  ├─→ ALPHA-REST ─────────────────────────────────────┤
  ├─→ ALPHA-DIRECT ───────────────────────────────────┼─→ ALPHA-ADOPT ───────┐
  ├─→ ALPHA-CLEAN ────────────────────────────────────┘                       │
  ├─→ ALPHA-VER ─→ ALPHA-ART ────────────────────────────────────────────────┤
  ├─→ ALPHA-LIC + ALPHA-SEC ─────────────────────────────────────────────────┤
  └─→ ALPHA-DOC-04 (truth only; no validate-cda/FSE2 gates) ──────────────────┘
                                                                                └─→ ALPHA-REL + ALPHA-01..08

Track B indipendente: intake/custody/composition → offline preflight → exact synthetic E2E
                                                → validate-cda → hash/create/status
```

La Core alpha è pubblicata e non è più una release-candidate track attiva. Un problema
FSE2 non reinterpreta la release Core, salvo che dimostri un difetto di sicurezza generale.
Una nuova astrazione Core richiede un blocker e un test concreti. DOC-04 non converte i
gate FSE2 in gate Core: mantiene soltanto veritiera la documentazione del pack opzionale.

## HISTORICAL e lavoro deferred

La roadmap originaria usava M0-M9. I nomi M6/M7 sono ambigui perché l'authentication
foundation è stata anticipata rispetto agli adapter legacy. Tag e report storici restano
immutabili, ma nuovo lavoro e nuovi status usano gli ID ALPHA/FSE2.

Legacy beta, altri provider, altri verticali ed enterprise/production restano backlog
deferred, non track attive. Non vengono stimati né avviati da questo piano.

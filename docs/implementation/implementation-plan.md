# Piano di implementazione corrente

Aggiornato: 2026-08-13
Baseline CURRENT: `eec2fa5556eccc7e8e3b47fc7d7b127bcac1ed9e`

Questa è la roadmap attiva. Lo stato sintetico è in
[`IMPLEMENTATION_STATUS.md`](../../IMPLEMENTATION_STATUS.md), i gate in
[`0.1.0-alpha-scope.md`](0.1.0-alpha-scope.md) e le slice ordinate nel
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
- esistono due sole track attive: Core alpha e FSE2 Organization OfficialTest.

## Baseline CURRENT

| Area | Stato | Limite corrente |
|---|---|---|
| M0-M2 | Done | Fondamenta, Broker e Gateway integrati; i gate live storici non sono un installer release. |
| M3A | PASS live lab | M3B Azure resta non qualificato. |
| M4/M5/M5.5 | Done | Connector lifecycle, Admin e Direct Gateway integrati; Direct sample key storage resta non-production. |
| Authentication foundation / Wave 1 | Integrata | Primitive provider-neutral e moduli esterni non qualificano automaticamente un servizio esterno. |
| FSE2 Organization | Synthetic-qualified | 11 operation, dual JWT, S1 `contentCommitment`, A1 mTLS distinta e PostgreSQL canonico; nessuna call live. |
| Local PKCS12 / FSE2 vertical image | Integrati da PR #33, synthetic lab qualified | Provider opzionale `SecretValues=false`, importer offline, overlay e vertical image; custody e OfficialTest aperti. |
| Productization alpha | Non pronta | Governance, versione, artefatti, clean-clone e prova esterna aperti. |
| Legacy/enterprise | Deferred | MSI, native/COM, cloud live, HA/DR e production non sono track attive. |

PR #33 è merged tramite fast-forward sull'exact main. General 6/6, M5/Admin 15/15,
PostgreSQL FSE2 1/1 zero skip, provider 30/30, architecture 42/42, provider-active
synthetic lab e security micro-review sono PASS/GO nel perimetro attestato. Questi gate
non includono materiale reale, import operativo o chiamate FSE2.

## Track A — Core `0.1.0-alpha`

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

### Sequenza

1. **Truth e confini documentali** — DOC-01 governance/scope/backlog; DOC-02
   architecture/security/deployment; DOC-03 OpenAPI/API/generated types; DOC-04 FSE2
   exact-main.
2. **Version freeze** — una sorgente `0.1.0-alpha` per assembly, package, Admin, immagini
   e manifest.
3. **Consumption** — un solo sample REST, clean clone/quickstart e integrazione Direct
   descritta come evaluation.
4. **External proof** — un secondo utilizzatore completa il golden path usando soltanto
   la documentazione pubblica.
5. **Artifact readiness** — archive/checksum/SBOM/vulnerability inventory, Core export e
   digest normalizzato riproducibile distinto dal manifest run-specific.
6. **Human governance** — licenza, security contact e DCO/CLA decisi.
7. **Release candidate** — release notes/known limits e gate ALPHA-01..08 sull'exact HEAD.
8. **Tag** — `v0.1.0-alpha` è l'ultimo step; nessun merge automatico.

### Vincoli

- FSE2 e pack vendor-specific non entrano nel golden path Core;
- MSI, COM/C ABI, Azure live, HA/DR e API compatibility stabile restano esclusi;
- il raw SHA del Core export è evidence della singola run. `ALPHA-ART` aggiunge un digest
  normalizzato dell'inventario perché `generatedAtUtc` rende il raw manifest run-specific;
- nessuna pubblicazione precede le decisioni umane ALPHA-LIC e ALPHA-SEC.

## Track B — FSE2 Organization OfficialTest

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

## Relazione tra le track

```text
DOC-01
  ├─→ Track A: DOC-02/03/04 → version/sample/clean clone → adopter → artifacts/governance → release
  └─→ Track B: intake/custody/composition → offline preflight → exact synthetic E2E
                                                → validate-cda → hash/create/status
```

Le due track possono avanzare separatamente. Un problema FSE2 non blocca il Core alpha,
salvo che dimostri un difetto di sicurezza generale. Una nuova astrazione Core richiede
un blocker e un test concreti.

## HISTORICAL e lavoro deferred

La roadmap originaria usava M0-M9. I nomi M6/M7 sono ambigui perché l'authentication
foundation è stata anticipata rispetto agli adapter legacy. Tag e report storici restano
immutabili, ma nuovo lavoro e nuovi status usano gli ID ALPHA/FSE2.

Legacy beta, altri provider, altri verticali ed enterprise/production restano backlog
deferred, non track attive. Non vengono stimati né avviati da questo piano.

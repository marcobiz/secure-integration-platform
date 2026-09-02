# Implementation dashboard

Aggiornato: 2026-09-02
Baseline CURRENT: `main` / `origin/main` =
`313fa5aa8e6efa4dba7d123d87802705cf45ae81`

Questa pagina è l’autorità sintetica sullo stato integrato. Le guide CURRENT spiegano
come usare ciò che esiste; piani, review e report precedenti sono HISTORICAL e non
prevalgono su questa dashboard. `Synthetic`, `live lab`, `OfficialTest qualified` e
`production qualified` sono livelli distinti.

## Stato prodotto

| Superficie | Stato CURRENT | Limite della claim |
|---|---|---|
| Core M0–M5.5 | Integrato | Local Broker, Gateway, PostgreSQL, Connector lifecycle/runtime, Admin e Direct Gateway; non equivale a installer o produzione enterprise. |
| Pilot locale | **Disponibile — Docker-first synthetic live lab** | Un percorso canonico Direct .NET → Gateway → Connector REST Published → mock HTTPS/mTLS; l'host richiede soltanto Git, PowerShell e Docker Linux/Compose, non SDK applicativi o database. Nessun servizio esterno o cloud. |
| Admin UI/API | **Integrata — onboarding Connector guidato** | Cinque azioni su tre ruoli coprono Installation/enrollment, file validate/import, binding server-owned e grant autorizzati dall’esatta versione canonica; retry sequenziali o concorrenti convergono su una riga/un audit. `FULLSTACK-02` prova reload/resume e prima invocation su PostgreSQL 18. Il quickstart locale usa identità sintetiche, non una configurazione production. |
| Authentication foundation | **Integrata** | Le primitive SOAP/session, JWT/X.509, signing e mTLS non qualificano automaticamente un servizio esterno. |
| FSE2 `validate-cda` | **LIVE_QUALIFIED — OfficialTest** | Una chiamata applicativa bounded sulla baseline exact ha restituito Gateway 200 con A1 mTLS, dual JWT S1 e contratto CDA/`VERIFICA`; non è accreditamento né qualifica production. |
| FSE2 `delete` | **PRODUCT_PATH_OFFLINE_QUALIFIED** | Metodo/path/no-body/claim e risposta bounded attraversano il product path verso mock; nessuna qualifica live o operationalization distribuita. |
| Altre nove operazioni FSE2 | **IMPLEMENTED_PARTIAL** | Runtime foundation sintetica; mancano a seconda dell’operazione definition/provisioning canonici, DTO/response completi, persistence o qualifica live. |
| Copertura completa Gateway FSE 2.0 | **NO** | Solo 1/11 live-qualified; Human Actor, callback inbound, correlation durevole, accreditamento e produzione non sono coperti. |
| Private preview | **Limitata** | Il Core e il pilot qualità CDA sono valutabili nei limiti dichiarati; non esiste una release pubblica o un impegno di stabilità API. |
| Produzione/accreditamento | **NON QUALIFICATI** | Cloud live, MSI, HA/DR, restore/load/soak, pentest, firma artefatti, custody production e accreditamento restano fuori dal CURRENT. |

## Percorsi CURRENT

- prodotto locale: [docs/user/local-pilot.md](docs/user/local-pilot.md);
- FSE2 OfficialTest: [docs/user/fse2-officialtest.md](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-officialtest.md);
- amministrazione: [docs/user/administration.md](docs/user/administration.md);
- sviluppo Connector: [docs/connector-development/README.md](docs/connector-development/README.md);
- regole interne: [docs/internal/README.md](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/internal/README.md).

La configurazione FSE2 dispone di un provisioner Admin resumable, ma bootstrap/provider
operativo, acquisizione delle sessioni di ruolo e runner live adopter-facing non sono un
flusso self-service documentabile dalla repository. Per questo
`FSE2_PILOT_REPRODUCIBLE_FROM_DOCS = NO`, pur restando vera la qualifica live di
`validate-cda` sulla baseline.

## Capacità FSE2 e prossimo gate

Il pilot di qualità CDA è già disponibile con `validate-cda`. Un pilot minimo di
pubblicazione richiede la slice coerente:

```text
validate-cda → create → get-status-by-workflow
```

`create` e `get-status-by-workflow` sono ancora parziali; un `202` di `create` senza
riconciliazione non dimostra il completamento verso INI/EDS. `replace`, `delete`,
`update-metadata` e `get-status-by-trace` sono successivi ad alto valore; le altre
operazioni non entrano automaticamente in roadmap.

Il gate prodotto **time to first successful call** resta black-box e da stato pulito.
Deve misurare separatamente:

- pilot locale: prerequisiti → singolo workflow → prima risposta sanificata → cleanup;
- FSE2: prerequisiti esterni già presenti → bootstrap supportato → plan/apply/four-eyes
  → verify → una `validate-cda` → audit/evidence redatti → resume terminale.

Il gate fallisce se l’operatore deve conoscere la struttura della repository, usare SQL
o store diretti, copiare cookie come procedura ordinaria, inventare una sequenza o
richiedere intervento specialistico per onboarding, recovery o test normali.

## Regole di aggiornamento

- Aggiornare questa dashboard solo quando cambia lo stato integrato o viene attestato un
  gate esterno exact-head.
- Non trasformare test sintetici, una risposta `202`, una dichiarazione del maintainer o
  un conteggio aggregato in una claim più ampia.
- Conservare dettagli di run, SHA storici e remediation nei report HISTORICAL; non
  ricopiarli nelle guide utente.
- Non versionare endpoint operativi riservati, certificati, chiavi, P12, password, token,
  cookie, payload sanitari o risposte raw.

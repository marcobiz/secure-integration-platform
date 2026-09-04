# Implementation dashboard

Aggiornato: 2026-09-04
Baseline integrata fino alla PR #65:
`18df69d6eaa34ed636b101bce1d188cd65226e1a`.

Questa pagina è l’autorità sintetica sulle capability integrate e sui limiti delle
claim. Le guide CURRENT possiedono le procedure; i riferimenti tecnici dettagliano i
contratti; piani, review e report precedenti sono HISTORICAL per lo stato qui riassunto.
`Synthetic`, `live lab`, `OfficialTest qualified` e `production qualified` sono livelli
distinti. La baseline integrata non sostituisce l'exact commit di una prova live.

## Stato prodotto

| Superficie | Stato CURRENT | Limite della claim |
|---|---|---|
| Core M0–M5.5 | Integrato | Local Broker, Gateway, PostgreSQL, Connector lifecycle/runtime, Admin e Direct Gateway; non equivale a installer o produzione enterprise. |
| A. Pilot Core locale | **Disponibile — Docker-first synthetic live lab** | Percorso principale Direct .NET → Gateway → Connector REST Published → mock HTTPS/mTLS. Host con Git, PowerShell e Docker Linux/Compose; niente .NET SDK, Node, npm, curl o PostgreSQL host. Nessun servizio esterno, cloud o pack healthcare. |
| B. Windows / Local Broker | **Integrato — evidenze live lab storiche M0/M1 e M3A** | Windows Service, identità/processi e isolamento locale; M3A include Gateway e upstream sintetico. Non è il pilot Direct, un installer o una nuova qualifica exact-head: vedi i [riferimenti storici](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/history/README.md#prove-windows--local-broker). |
| Admin UI/API | **Integrata — onboarding Connector guidato** | Cinque azioni su tre ruoli per Installation/enrollment, definition, binding/grant, four-eyes e prima invocation. `FULLSTACK-02` prova reload/resume e prima invocation su PostgreSQL 18. Il pilot usa identità sintetiche, non autenticazione production. |
| Authentication foundation | **Integrata** | Primitive SOAP/session, JWT/X.509, signing e mTLS provider-neutral; non qualificano automaticamente un servizio esterno. |
| C. FSE2 Organization current-spec | **PRODUCT_PATH_OFFLINE_COMPLETE — 14 route** | Profilo opt-in `fse2-organization-current-spec@1.0.0`: contratti, provisioning e risposte bounded completi nei limiti della [specifica congelata](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/connectors/healthcare/fse2/current-spec.md). Non significa 14 route qualificate live. |
| FSE2 CDA `VERIFICA` | **LIVE_QUALIFIED — OfficialTest** | Sul profilo current-spec: upstream/Gateway 200, `VALIDATED`, workflow e trace, A1 mTLS e dual JWT S1; non abilita o prova pubblicazione documentale. |
| FSE2 `get-status-by-workflow` | **LIVE_QUALIFIED — OfficialTest, caso CDA osservato** | Dopo riavvio reale Gateway: upstream/Gateway 200, `FOUND`, un evento bounded sul workflow restituito da CDA. Prova consultazione e correlazione PostgreSQL durevole, non completamento clinico o pubblicazione. |
| FSE2 FHIR `VERIFICA` | **NON QUALIFICATO LIVE** | Due richieste intenzionali con configurazione corretta: upstream 500 / Gateway 502, `generic-error`. Causa non determinata; non attribuibile da questo codice a formato, accreditamento o autorizzazione. |
| FSE2 pubblicazione documentale live | **NON QUALIFICATA** | Il runner corrente consente soltanto VERIFICA e consultazione. Pubblicare la configurazione Connector non pubblica documenti; un `202` non prova completamento verso INI/EDS. |
| Copertura/qualifica complessiva Gateway FSE 2.0 | **NO** | Offline limitato alle 14 route congelate; live limitato ai casi sopra. Human Actor, callback inbound e pubblicazione nativa FHIR confermata restano esclusi. |
| Private preview | **Limitata** | Core e pilot opzionale valutabili nei rispettivi prerequisiti; nessuna release pubblica o stabilità API garantita. |
| Produzione/accreditamento | **NON QUALIFICATI** | Cloud live, MSI, adapter C ABI/COM, HA/DR, restore/load/soak, pentest, firma artefatti e custody production non sono qualificati. |

## Percorsi CURRENT e provenienza

- Core: [quickstart](docs/user/quickstart.md) → [pilot locale](docs/user/local-pilot.md).
- FSE2: [validazione e consultazione OfficialTest](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md).
  È l'ingresso operativo corrente: runner distribuito, bootstrap locale, enrollment
  Direct, sessioni di ruolo in memoria e provisioner Admin resumable, senza SQL/store
  diretti o cookie copiati. Richiede SDK .NET host e materiale A1/S1 già predisposto e
  autorizzato, accesso OfficialTest e configurazione organizzativa esterna. Non crea
  account esterni o certificati e non fornisce custody production.
- La [qualifica osservata il 4 settembre](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md#qualifica-osservata-il-4-settembre-2026)
  identifica codice eseguito, esiti e limiti delle prove live. I gate offline sono nel
  riferimento current-spec; le qualifiche dei vecchi profili non si trasferiscono al nuovo.
- Il [precedente percorso validate-only](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-officialtest.md)
  è HISTORICAL per la prima adozione. Conserva la provenienza di
  `fse2-officialtest-validate-cda@1.0.1` e il riferimento al provisioner condiviso;
  `1.0.0` rimane compatibilità Published immutabile.
- [Amministrazione](docs/user/administration.md),
  [sviluppo Connector](docs/connector-development/README.md) e
  [regole interne](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/internal/README.md).

Il percorso FSE2 è ora documentato ed eseguibile con i suoi prerequisiti esterni:
il vecchio blocco «runner/sessioni/bootstrap locale non distribuiti» non è più CURRENT.
Questo non rende FHIR live riuscito né il pilot riproducibile senza accesso e materiale
autorizzati. Il Core resta indipendente dall'esito e dalla presenza del pack FSE2.

## Regole di aggiornamento

- Aggiornare questa sintesi solo quando cambia lo stato integrato o viene attestato un
  gate esterno exact-head; README e guide la riassumono con collegamenti.
- Non trasformare test sintetici, una risposta `202`, `FOUND` o un conteggio aggregato
  in una claim più ampia.
- Conservare percorsi e profili storici, identificandoli senza riscrivere le evidenze
  attestate; non ricopiare matrici di capability nelle guide.
- Non versionare endpoint operativi riservati, certificati, chiavi, P12, password, token,
  cookie, payload sanitari o risposte raw.

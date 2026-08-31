# Connector CLI

Il progetto `tools/connector-cli` usa esclusivamente l'Admin API; non apre connessioni PostgreSQL.

```text
connector validate <definition.json>
connector import <definition.json> [expected-sha256]
connector list
connector show <connector-id> <version>
connector export <connector-id> <version> <output.json>
connector versions <connector-id>
connector publish <connector-id> <version> <row-version> <publication-revision>
connector rollback <connector-id> <target-version> <active-row-version>
connector retire <connector-id> <version> <row-version>
connector test <connector-id> <operation-id> <environment-id>
```

Configurazione:

- `CONNECTOR_GATEWAY_URL`: base HTTPS Admin API;
- `GATEWAY_ADMIN_API_KEY`: solo modalità di sviluppo; mai argomento CLI;
- `CONNECTOR_ADMIN_ACTOR`: identificatore audit redatto;
- `CONNECTOR_GATEWAY_CA_FILE`: CA sintetica opzionale per il quick start.

La CLI richiede HTTPS salvo loopback, disabilita proxy/cookie/redirect e non implementa trust-all. Il file CA aggiunge soltanto una trust root esplicita e mantiene la verifica hostname.

## Provisioning resumable condiviso

I provisioner verticali possono usare `tools/connector-provisioning`, una state machine soltanto
operativa e connector-neutral. Prima di ogni mutazione il verticale deve ricostruire lo stato dalle
Admin API supportate e confrontare in modo ordinale l'identità completa: Connector/version/checksum,
Environment e Application server-owned, binding e operation-profile digest, provider reference e
revisioni, grant e approval correnti. Le sole fasi ammesse sono un prefisso monotono da import a
Published/Active; una combinazione incompleta o un drift produce un arresto prima della mutazione.

Un HTTP 429 non viene ritentato automaticamente. Il risultato `BGW-PROVISIONING-RATE-LIMITED`
contiene soltanto stato corrente, fasi completate, prossima fase, `retrySafe`, un `Retry-After`
opzionale e bounded, e il comando supportato da ripetere. Non contiene response body/header,
endpoint, credenziali o exception text. Dopo l'attesa operativa l'operatore ripete esattamente lo
stesso comando e piano: le fasi persistite vengono verificate e saltate. Uno stato già Published e
identico è verify-only/no-op. Non esistono flag force/recovery né bypass del rate limiter, di RBAC o
del four-eyes.

## Confine rate-limit Admin

Il Gateway mantiene due classi di partizione non sovrapponibili. `AUTH` usa il remote IP elaborato
soltanto dal middleware forwarded-header e solo per proxy configurati esplicitamente; `API` usa il
subject della sessione autenticata e ricade sul remote IP solo se quel claim non è disponibile. La
classe e il tipo di identità fanno parte della chiave tipizzata: una prima richiesta AUTH non può
creare il limiter API e l'ordine inverso non può ampliare il bucket AUTH. Non esiste un bucket API
globale fra principal o fra workflow tenant/Installation distinti.

I default restano AUTH 20/minuto e API 240/minuto, finestra un minuto, coda zero e replenishment
automatico. Un 429 Gateway contiene soltanto il codice `BGW-RATE-LIMITED`, un Problem redatto e,
quando disponibile dal lease, `Retry-After` bounded fra 0 e 3600 secondi. Il Gateway non attende e
non ritenta. Il provisioner interpreta il rifiuto usando lo stato server-side e permette di ripetere
lo stesso comando/piano; non sono richiesti cleanup, SQL, accesso store o un comando recovery.

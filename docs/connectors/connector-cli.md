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

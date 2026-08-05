# Gateway API

La specifica machine-readable è [gateway-openapi.yaml](gateway-openapi.yaml).

## Runtime

`POST /v1/connectors/{connectorId}/operations/{operationId}:invoke` mantiene il contratto M2/M3. Certificato Installation, firma ECDSA P-256, timestamp, nonce, content hash e `traceparent` sono obbligatori. Tenant ed Environment derivano dall'Installation autenticata; non sono autorevoli se presenti nel body.

Il client sceglie soltanto Connector e operation già autorizzati. URL, method, endpoint binding, secret reference, algoritmo e credenziali non fanno parte della request. Il runtime accetta esclusivamente una versione Published e applica i grant deny-by-default prima di risolvere secret o invocare la rete.

## Admin Connector API

| Metodo e path | Funzione |
|---|---|
| `POST /admin/v1/connectors:validate` | valida una definizione senza persisterla |
| `POST /admin/v1/connectors:import` | importa una nuova versione Draft |
| `GET /admin/v1/connectors` | elenco redatto |
| `GET /admin/v1/connectors/{id}/versions` | versioni e lifecycle |
| `GET /admin/v1/connectors/{id}/versions/{version}` | metadata versione |
| `GET /admin/v1/connectors/{id}/versions/{version}:export` | JSON canonico, senza binding |
| `POST .../{version}:validate` | Draft → Validated con `expectedRowVersion` |
| `POST .../{version}:publish` | Validated → Published con row/publication revision |
| `POST /admin/v1/connectors/{id}:rollback` | riattiva una Superseded già pubblicata |
| `POST .../{version}:retire` | revoca una versione |
| `PUT /admin/v1/connectors/{id}/bindings` | configura binding Environment server-side |
| `POST /admin/v1/connectors/{id}:test` | verifica non distruttiva Published + binding |

Import/export usa JSON soltanto. Un expected checksum opzionale protegge l'import; export restituisce la forma canonica. Concurrency mismatch restituisce un errore stabile e non applica transizioni parziali.

## Autenticazione Admin

La modalità predefinita è `Disabled`. `DevelopmentApiKey` è consentita soltanto negli environment non-production previsti da ADR-0012 e legge la chiave dalla variabile configurata. La CLI non accetta la chiave come argomento. Un deployment di produzione deve collegare il confine Admin a OIDC/policy senza cambiare il formato Connector.

## Errori e redazione

Gli errori usano codici stabili `BGW-*`. Response e audit non includono payload, URI risolti, provider reference, header di autenticazione o secret value. Corruzione checksum/storage, stato non Published, binding assente, store indisponibile e precondition concurrency falliscono chiusi.

## Health

`GET /health/live` verifica il processo. `GET /health/ready` verifica registry e Secret Provider. La disponibilità del runtime Connector viene inoltre verificata durante la risoluzione dello stamp Published: non è consentito stale-on-error.

# Anatomia minima di un Connector

**Pubblico:** sviluppatori di Connector.
**Stato:** CURRENT per Connector Definition JSON v1.

La sorgente machine-readable è
[connector-definition.schema.json](../connectors/connector-definition.schema.json). Il
[sample REST](../connectors/examples/sample-secure-service.connector.json) è il punto di
partenza eseguibile.

## Contenuto necessario

| Parte | Contiene | Non contiene |
|---|---|---|
| Identità | `schemaVersion`, Connector ID, versione semantica, nome. | Tenant, Environment o identità runtime. |
| Binding logici | Nomi di endpoint, secret e certificati richiesti. | URI, secret value, P12, path o provider locator. |
| Operation | ID, metodo/path/template autorizzati, content type, timeout e limiti bounded. | URL scelto dal caller, header arbitrari o workflow. |
| Autenticazione | Uno dei profili supportati e riferimenti logici alle capability. | Algoritmi, chiavi o certificati selezionabili a runtime. |
| Affidabilità | Idempotenza/retry coerenti e redirect deny. | Retry illimitato o fallback stale. |
| Estensione | Solo configurazione chiusa coperta dal checksum, se serve una strategy tipizzata. | Script, reflection, codice dinamico o service locator. |

## Binding server-owned

Per ogni Environment l’amministratore associa i nomi logici a endpoint HTTPS e risorse
provider revisionate. Secret retrieval, certificato client, signing/MAC, health e
capability discovery restano contratti separati. La definition esportata e la request
runtime non contengono i valori concreti.

## Quando serve codice compilato

Usare prima le operation REST e i profili già supportati. Una strategy/modulo compilato
è giustificato soltanto da un requisito corrente che non può essere espresso in modo
sicuro e tipizzato. Deve ricevere una invocation già autenticata, granted e Published,
senza accesso generico a store, provider, segreti, HTTP o firma.

Non introdurre un framework/plugin generico per un possibile Connector futuro. Se
un’astrazione non rimuove duplicazione misurata in almeno due casi correnti, mantenerla
locale alla capability che la richiede.

## Checklist minima prima dell’import

- JSON conforme allo schema, campi sconosciuti negati e checksum canonico stabile;
- logical binding dichiarati una sola volta e usati da operation note;
- nessun header sensibile/hop-by-hop controllabile dal client;
- request/response/timeouts bounded;
- retry consentito solo con semantica idempotente o idempotency key obbligatoria;
- destination, auth e provider non presenti nel payload caller-owned;
- test negativi per grant assente, binding assente/drifted, operation sconosciuta e input
  oltre i limiti;
- percorso di [prima chiamata](golden-path.md) definito prima di ampliare la superficie.

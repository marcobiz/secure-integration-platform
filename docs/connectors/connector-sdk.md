# Connector SDK v1

M4 non introduce un SDK binario o un plugin ABI: l'SDK è il contratto portabile composto da JSON Schema, sample, Admin REST API e contract test.

## Flusso per uno sviluppatore

1. Copiare [sample-secure-service.connector.json](examples/sample-secure-service.connector.json).
2. Dichiarare operation e logical binding senza URI o riferimenti provider.
3. Eseguire `connector validate`.
4. Importare, osservare `rowVersion`, validare e pubblicare con optimistic concurrency.
5. Far configurare i binding Environment tramite Admin API.
6. Eseguire `connector test`, poi invocare attraverso il normale SDK Legacy/Broker.

## Contract suite minima

Una definizione è accettabile quando passa Draft 2020-12 e le regole semantiche documentate, il checksum canonico è stabile, ogni binding è dichiarato, nessun header protetto è client-controlled e retry/idempotenza sono coerenti. I test in `ConnectorConfigurationTests` costituiscono la suite di riferimento.

## Compatibilità

M4 supporta soltanto `schemaVersion: "1.0"`. Evoluzioni additive compatibili rimangono nella major 1; una semantica incompatibile richiede una nuova schema major e un aggiornamento esplicito del Core. Nessun campo sconosciuto viene accettato.

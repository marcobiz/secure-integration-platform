# ADR-0010: Definizione Connector

**Stato:** Accepted

## Decisione

Modello dichiarativo ristretto con pipeline fissa: resolve, grant, validate, bind, authenticate, invoke, normalize, redact. Configurazione JSON canonica; trasformazioni complesse esclusivamente in plugin compilati.

Da M5 i valori server-side sono revisioni immutabili di un binding bundle scoped a ConnectorVersion ed Environment. Endpoint, secret reference e certificate reference restano distinti; il loro checksum entra in un digest con il checksum canonico del Connector. Una revisione diventa runtime `Active` solo nella stessa transazione PostgreSQL che verifica una approval four-eyes sul digest esatto e pubblica la ConnectorVersion. Una modifica crea una nuova revisione e non cambia mai il comportamento gia Published.

## Conseguenze

Endpoint, autenticazione e retry sono reviewabili e validabili. Non si possono modellare flussi arbitrari; nuovi pattern richiedono un adapter tipizzato o un plugin.

## Alternative escluse

Workflow engine, PowerShell, JavaScript, C# dinamico, loop ed espressioni generiche.

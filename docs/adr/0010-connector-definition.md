# ADR-0010: Definizione Connector

**Stato:** Accepted

## Decisione

Modello dichiarativo ristretto con pipeline fissa: resolve, grant, validate, bind, authenticate, invoke, normalize, redact. Configurazione JSON canonica; trasformazioni complesse esclusivamente in plugin compilati.

## Conseguenze

Endpoint, autenticazione e retry sono reviewabili e validabili. Non si possono modellare flussi arbitrari; nuovi pattern richiedono un adapter tipizzato o un plugin.

## Alternative escluse

Workflow engine, PowerShell, JavaScript, C# dinamico, loop ed espressioni generiche.


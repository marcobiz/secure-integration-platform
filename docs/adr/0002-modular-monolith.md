# ADR-0002: Gateway modular monolith

**Stato:** Accepted

## Contesto

La piattaforma richiede runtime, enrollment, configurazione, admin e audit, ma non esistono ancora volumi o team che giustifichino microservizi.

## Decisione

Un solo processo e una sola immagine Gateway, con moduli Domain/Application/Infrastructure separati e dipendenze controllate. Un solo PostgreSQL operativo.

## Conseguenze

Deployment, transazioni e sviluppo restano semplici. I confini modulari permettono estrazione futura basata su evidenze. Un guasto del processo impatta tutti i moduli e richiede buoni health check.

## Alternative escluse

Microservizi, service mesh e broker di messaggi non sono giustificati nell'MVP.


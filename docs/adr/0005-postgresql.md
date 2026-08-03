# ADR-0005: PostgreSQL e multi-tenancy

**Stato:** Accepted

## Decisione

PostgreSQL 18, schema condiviso, UUID, `tenant_id`, composite foreign key e Row Level Security. EF Core/Npgsql per accesso; migrazioni esplicite e reviewate. JSONB contiene la configurazione Connector canonica.

## Conseguenze

Portabilità e self-hosting restano possibili. RLS richiede il contesto Tenant transaction-local e test obbligatori. Il database non contiene secret value.

## Alternative escluse

Database per Tenant moltiplica operations; SQL Server riduce portabilità; NoSQL non offre vantaggi per lifecycle transazionale e grants.


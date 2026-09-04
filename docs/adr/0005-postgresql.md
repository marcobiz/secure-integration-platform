# ADR-0005: PostgreSQL and multi-tenancy

**Status:** Accepted

## Decision

PostgreSQL 18, shared schema, UUIDs, `tenant_id`, composite foreign keys and Row Level Security. EF Core/Npgsql for access; explicit, reviewed migrations. JSONB holds canonical Connector configuration.

## Consequences

Portability and self-hosting remain possible. RLS requires transaction-local Tenant context and mandatory tests. The database contains no secret values.

## Rejected alternatives

A database per Tenant multiplies operational work; SQL Server reduces portability; NoSQL offers no advantage for transactional lifecycle and grants.

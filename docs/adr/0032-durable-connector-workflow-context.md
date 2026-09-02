# ADR 0032: Durable authorized Connector workflow context

- Status: Accepted
- Date: 2026-09-02

## Context

The FSE2 `create` operation returns a workflow instance ID and a trace ID that later status
operations must bind to the exact authenticated and Published authority that created them. The
previous FSE2-owned in-memory correlation survived neither a Gateway restart nor a second replica.
Accepting Tenant, Installation, Connector or Published selectors from the pack would let the
vertical choose Core authority. Persisting request or response objects would also introduce
clinical-data retention without a product requirement.

## Decision

The existing invocation-bound authorized capability bridge gains exactly two operations: record one
closed technical workflow context, and resolve one exact workflow or trace identifier. Neither
operation accepts an authority selector. Core derives Tenant, Application, Installation,
Environment, Connector ID/version and a deterministic checksum of the exact Published version,
binding and resource configuration from `AuthorizedConnectorExecution`.

Core owns the provider-neutral PostgreSQL store and migration `0018`. The
`gateway.connector_workflow_context` table persists the server-derived authority plus only:

- originating operation ID;
- action code;
- purpose-of-use code;
- originating operation-profile SHA-256;
- workflow instance ID;
- trace ID;
- server-owned technical timestamp.

There is no JSON or metadata bag. Person or patient identifiers, document bytes, CDA/PDF, request or
response bodies, JWTs, certificates, endpoints and headers have no field or bridge parameter.
Healthcare.FSE2 serializes and validates the closed record; Core bounds the technical representation
without interpreting FSE2 semantics.

PostgreSQL enforces forced RLS on the exact Tenant and Installation session scope. The runtime role
has only `SELECT` and `INSERT`; `UPDATE`, `DELETE` and `TRUNCATE` are absent. `gateway_admin`,
`gateway_readonly` and `PUBLIC` have no table privileges, so there is no Admin read-back path.
Separate partial unique indexes bind workflow and trace IDs to the complete authoritative scope.

Recording uses `INSERT ... ON CONFLICT DO NOTHING` followed in the same transaction by exact
read-back. An identical record is an idempotent no-op. If either identifier already denotes a
different closed context, the operation fails closed and no row is mutated. Resolution exact-matches
the entire authority and one closed identifier kind before the FSE2 strategy can sign, resolve DNS
or dispatch transport.

## Consequences

- `create` correlation survives process restart and is shared by Gateway replicas using the same
  authoritative PostgreSQL database;
- configuration, version, Connector, Environment, Application, Installation and Tenant changes do
  not inherit an old workflow context;
- the process-local FSE2 correlation service and its vertical authority-scope types are removed;
- no second bridge, microservice, cache, worker, retention subsystem or application-level encryption
  mechanism is introduced;
- migration owners, the PostgreSQL superuser, host Administrator/SYSTEM and privileged memory or
  database dumps remain trusted residual threats.

## Alternatives rejected

A second capability bridge, an FSE2-owned database repository, caller-selected scope, distributed
cache, generic metadata persistence, Admin API/read-back, background cleanup and premature retention
configuration were rejected because they add authority or machinery not required by the demonstrated
workflow.

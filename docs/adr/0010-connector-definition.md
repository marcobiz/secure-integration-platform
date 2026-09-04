# ADR-0010: Connector definition

**Status:** Accepted

## Decision

A restricted declarative model with a fixed pipeline: resolve, grant, validate, bind, authenticate, invoke, normalize, redact. Canonical JSON configuration; complex transformations exclusively in compiled plugins.

Since M5, server-side values are immutable revisions of a binding bundle scoped to ConnectorVersion and Environment. Endpoints, secret references and certificate references remain distinct; their checksum is included in a digest with the canonical Connector checksum. A revision becomes runtime `Active` only in the same PostgreSQL transaction that verifies a four-eyes approval for the exact digest and publishes the ConnectorVersion. A change creates a new revision and never changes already Published behavior.

## Consequences

Endpoints, authentication and retries can be reviewed and validated. Arbitrary flows cannot be modeled; new patterns require a typed adapter or a plugin.

## Rejected alternatives

Workflow engines, PowerShell, JavaScript, dynamic C#, loops and generic expressions.

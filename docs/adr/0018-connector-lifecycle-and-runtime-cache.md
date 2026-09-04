# ADR-0018: Connector lifecycle, publication and cache

**Status:** Accepted

## Context

ADR-0010 defines the declarative pipeline, but does not specify the lifecycle, concurrency, rollback, binding and cache behavior needed by the Connector Configuration MVP.

## Decision

- A Connector Definition v1 is Draft 2020-12-compliant JSON and contains only logical endpoint and secret references.
- The lifecycle is `Draft → Validated → Published → Superseded → Retired`. There is no implicit state or validation bypass.
- A version that has been Published can no longer change its definition, checksum, version or schema. The database also enforces an immutability trigger.
- Publishing a new version makes the previous one `Superseded`. Rollback reactivates only a previously published `Superseded` version; it does not copy or change JSON.
- The SHA-256 checksum is computed over canonical UTF-8 JSON. The v1 numeric domain allows only integers, keeping canonicalization deterministic and free of floating-point ambiguity.
- `row_version` protects every transition and `publication_revision` serializes concurrent publications for the Connector.
- Endpoint URIs and provider references are per-Environment bindings, managed server-side and absent from the definition, runtime request, export and audit.
- The runtime resolves only the `Published` version. A TTL cache retains the complete snapshot, but checks a lightweight publication stamp on every invocation. State/revision changes, local invalidation, corruption or store unavailability prevent snapshot use: no stale fallback.
- The Admin API is the only supported boundary for CLI and tools; direct database access is not allowed.

## Consequences

Revocation/retirement is effective even within the TTL, rollback preserves provenance and checksum, and two publishers cannot silently succeed. Temporary PostgreSQL unavailability interrupts new invocations instead of using potentially revoked configuration.

## Rejected alternatives

Stale-on-error cache, in-place modification of Published versions, rollback through a new copy, URLs/secret references in client payloads, arbitrary workflows/scripts and direct CLI database access.

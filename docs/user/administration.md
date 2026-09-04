# Administration

**Audience:** authorized administrators and operators.
**Status:** CURRENT for the integrated Admin UI/API; DevelopmentAuth mode is local
and synthetic only.

The Admin UI communicates exclusively with authenticated same-origin Admin APIs.
It does not access PostgreSQL, providers or the filesystem. Tenant, Installation and
Environment are server-side authorities; runtime callers cannot select endpoints
or provider references.

## Roles and separation of responsibilities

| Role | Normal task |
|---|---|
| Viewer | Read non-sensitive state. |
| Connector Editor | Import/validate a definition and propose approval. |
| Connector Approver | Approve the exact checksum; must be distinct from the proposer. |
| Security Administrator | Manage Installations, server-owned bindings, grants, authorized diagnostic audit and health. |
| Operator | Run controlled tests on permitted surfaces. |

The UI may hide unauthorized actions, but the server always enforces RBAC, tenant
scope, CSRF, concurrency and four-eyes checks.

## Canonical onboarding order

For a new Connector, use the **Guided onboarding** page and the five-action procedure
in [Guided Connector onboarding](guided-connector-onboarding.md). The page selects
server-owned authorities, shows the next role and resumes from persisted state
without asking for UUIDs, checksums or binding JSON.

```text
deployment/provider bootstrap
→ Environment and Installation enrollment
→ definition validate/import
→ stored validation
→ server-owned binding
→ Installation/Connector/operation grant
→ editor proposal
→ distinct approval
→ publish
→ verify Published/Active
→ one bounded invocation
→ metadata-only audit
```

The normal path uses Admin UI/API or a supported, idempotent
`plan → apply → verify` provisioner. Do not use SQL, direct store access, edits to
Published rows or values recovered from logs.

## Connector lifecycle

`Draft → Validated → Published → Superseded → Retired`.

- A Published version is immutable.
- Publishing a new version makes the previous one Superseded.
- Rollback reactivates an already-published Superseded version; it does not copy or edit JSON.
- Each mutation uses the observed row/publication revision. A conflict requires
  a new read-back, not force.
- A binding change creates a new revision and invalidates previous approvals.

## Bindings, providers and grants

A definition contains only logical names. For each Environment, the administrator
selects HTTPS endpoints and provider resources from server-owned catalogs. The browser
sends only identifiers, revisions and checksums as assertions; the server resolves
the actual authority. Secret retrieval, client certificates, signing and health are
separate capabilities. Neither browser nor runtime client receives secret values,
private keys, P12 files, provider locators or arbitrary URLs.

A grant is deny-by-default and binds an Installation to a Connector/operation.
The request also specifies the exact `connectorVersion`, which the server rereads
from the configuration store: only a `Validated` or `Published` version and a
canonical operation from its definition can authorize creation. Neither the grant
nor the client chooses the Environment: it derives from the authenticated Installation.
Retrying an identical enabled tuple with the same expiry is a 200 no-op; first creation
returns 201. A retry needs no preliminary GET and produces no duplicate rows or audit,
including when two requests arrive concurrently.

## Audit, health and recovery

- `/health/live` checks the process; `/health/ready` includes required dependencies.
- Audit retains bounded metadata, not payloads, credentials, cookies, headers or raw responses.
- Locally, the **Audit** page is `/admin/audit`.
- On 429 or an expired session, read server-side state and repeat only the action
  declared retry-safe. Do not wait in a loop or restart the whole onboarding process.
- Provider/binding drift makes Published authority stale before signing/network use;
  correct the authoritative cause first, then republish through the lifecycle.

To explore the UI after the [local pilot](local-pilot.md), start the Admin laboratory
with `./tools/m5/Invoke-M5Quickstart.ps1 -Phase Start` and stop it with `-Phase Stop`.
This is a synthetic inspection environment, not a second canonical pilot or a production
configuration. For FSE2-specific actions, use the
[current validation/status guide](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md).

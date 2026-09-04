# Connector CLI

The `tools/connector-cli` project uses only the Admin API; it opens no PostgreSQL connections.

```text
connector validate <definition.json>
connector import <definition.json> [expected-sha256]
connector list
connector show <connector-id> <version>
connector export <connector-id> <version> <output.json>
connector versions <connector-id>
connector publish <connector-id> <version> <row-version> <publication-revision>
connector rollback <connector-id> <target-version> <active-row-version>
connector retire <connector-id> <version> <row-version>
connector test <connector-id> <operation-id> <environment-id>
```

Configuration:

- `CONNECTOR_GATEWAY_URL`: Admin API HTTPS base;
- `GATEWAY_ADMIN_API_KEY`: development mode only; never a CLI argument;
- `CONNECTOR_ADMIN_ACTOR`: redacted audit identifier;
- `CONNECTOR_GATEWAY_CA_FILE`: optional synthetic CA for the quick start.

The CLI requires HTTPS except on loopback, disables proxies/cookies/redirects and implements no trust-all mode. The CA file adds only an explicit trust root and preserves hostname verification.

## Shared resumable provisioning

Vertical provisioners can use `tools/connector-provisioning`, an operational-only,
connector-neutral state machine. Before every mutation, the vertical must reconstruct state from
supported Admin APIs and compare the complete identity ordinally: Connector/version/checksum,
server-owned Environment and Application, binding and operation-profile digests, provider references and
revisions, and current grants and approvals. Allowed phases are only a monotonic prefix from import to
Published/Active; an incomplete combination or drift stops execution before mutation.

An HTTP 429 is not retried automatically. The `BGW-PROVISIONING-RATE-LIMITED` result
contains only current state, completed phases, next phase, `retrySafe`, an optional bounded
`Retry-After`, and the supported command to repeat. It contains no response body/headers,
endpoints, credentials or exception text. After the operational wait, the operator repeats exactly the
same command and plan: persisted phases are verified and skipped. An already Published,
identical state is verify-only/no-op. There are no force/recovery flags or bypasses of rate limiting, RBAC or
four-eyes controls.

## Admin rate-limit boundary

The Gateway maintains two non-overlapping partition classes. `AUTH` uses the remote IP processed
only by forwarded-header middleware and only for explicitly configured proxies; `API` uses
only the `sub` validated by server-side authentication. Class, type and identity are part
of the typed key: a first request cannot poison the other class's policy. Untrusted
headers, parameters, bodies, tenants, Installations and unvalidated cookies cannot choose the partition.

AUTH covers: `GET /admin/auth/login`, `POST /admin/auth/development/login`, the configured OIDC
callback, `GET /admin/auth/csrf` before login and unknown `/admin/auth/*` endpoints.
API covers, after server-side authentication: post-login CSRF, `me`, logout and ordinary Admin APIs.
DevelopmentAuth uses a separate cookie jar per role and independent workflow; two concurrent
workflows do not share the three technical sessions. DevelopmentApiKey is validated before the
limiter and uses a constant server-owned subject without consuming AUTH; OIDC keeps login and callback
in AUTH and moves subsequent session requests to API. No claims are made about rate limits
of the external IdP.

Defaults are AUTH 60 requests per 60 seconds per trusted remote IP and API 600 requests per 60
seconds per authenticated subject, with no queue and automatic replenishment. Each workflow reuses
its own session per role and renews CSRF only when necessary: it does not wait for the window, repeat login
or require technical support on the golden path. A Gateway 429 contains only the
`BGW-RATE-LIMITED` code, a redacted Problem and, when available from the lease, `Retry-After` bounded between 0 and
3600 seconds. The Gateway does not wait or retry. The provisioner interprets the refusal using
server-side state and allows the same command/plan to be repeated; no cleanup, SQL,
store access or recovery command is required.

This limiter concerns only the Admin plane. It does not govern tenant/data-plane traffic and
the same thresholds must not be applied to the data plane without dedicated capacity tests.

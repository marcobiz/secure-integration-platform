# Requirements, non-goals and acceptance criteria

> **Classification:** this is the normative catalog of targets and acceptance criteria,
> not an implementation dashboard. In the full repository, current status and
> verifiable coverage are maintained respectively in `IMPLEMENTATION_STATUS.md` and
> `requirements-traceability.md`; these documents are not part of Core export.
> A requirement listed here may be deferred or outside alpha scope.

## Product objective

Remove hardcoded secrets and distributed credentials from legacy software with as few changes to existing code as possible, preserving working flows and preventing the Gateway from becoming an arbitrary proxy.

## Normative terminology

- **Local Broker:** local Windows service that protects secrets/keys, exposes controlled IPC and communicates with the Gateway.
- **Local Proxy:** commercial synonym for Local Broker; not a transparent HTTP proxy or MITM.
- **Gateway:** central service that authenticates, authorizes, uses centralized credentials and invokes external services.
- **Vault:** storage for secrets, certificates and keys; initial provider Azure Key Vault.
- **Secure Layer:** the legacy application keeps logic and payloads; the platform performs only sensitive operations.
- **Managed Connector:** the platform manages a substantial part or all of the integration.
- **Connector Pack:** reusable definitions, plugins, tests and documentation for a service or vertical.
- **Installation:** a single authorized installation at a customer.
- **Application:** product or component authorized to use the Local Broker.
- **Tenant:** organization to which the Installation belongs.
- **Operator:** end user performing the operation.
- **Vendor/Tenant/Operator/Session Secret:** secret classes defined by their owner and lifecycle.

## Functional requirements

| ID | Requirement |
|---|---|
| FR-001 | Register Tenant, Application, Installation and Environment. |
| FR-002 | Enrollment, renewal, revocation and reinstallation with a distinct identity per Installation. |
| FR-003 | Local Broker authorization per Application and operation. |
| FR-004 | Put/Delete local secrets without a default GetSecret API. |
| FR-005 | Protect/Unprotect data with key versioning and AEAD. |
| FR-006 | HMAC, signing and certificate use bound to Connector/operation. |
| FR-007 | Gateway invocation with Tenant derived from authenticated identity. |
| FR-008 | Secure Layer with prebuilt JSON, XML or binary payloads. |
| FR-009 | Managed Connector with domain or protocol request. |
| FR-010 | `gateway`, `broker` and `hybrid` execution strategies. |
| FR-011 | Logical secret bindings with values exclusively in Vault/Broker. |
| FR-012 | Connector lifecycle Draft/Validated/Published/Superseded/Retired. |
| FR-013 | Atomic publication, promotion and rollback. |
| FR-014 | Admin UI/API with OIDC and RBAC. |
| FR-015 | Thin .NET, COM, C ABI SDKs and CLI. |
| FR-016 | Redacted administrative and operational audit. |
| FR-017 | Health, metrics, tracing and offline diagnostics. |
| FR-018 | Offline operation for exclusively local operations. |

## Nonfunctional requirements

| ID | Requirement |
|---|---|
| NFR-001 | No secrets in repository, database, logs, errors or telemetry. |
| NFR-002 | Deny-by-default IPC, grants, egress, bindings and plugins. |
| NFR-003 | Modern TLS with hostname validation always enabled. |
| NFR-004 | Standard payload 16 MiB, controlled streaming 64 MiB. |
| NFR-005 | Explicit timeout, idempotent retries and circuit breakers. |
| NFR-006 | End-to-end correlation ID and W3C trace context. |
| NFR-007 | Immutable Published configurations and canonical checksum. |
| NFR-008 | Reasonably reproducible builds, SBOM and signable artifacts. |
| NFR-009 | x86/x64 and .NET Framework 4.7.2+ compatibility for initial adapters. |
| NFR-010 | Application payloads not persisted centrally by default. |

## Non-goals

- Generic forward proxy, MITM, ESB, BPM or scripting engine.
- General-purpose IAM, EDR, PKI or zero-trust platform.
- Complete protection against local Administrator/SYSTEM.
- Safe execution of untrusted plugins in the same process.
- Automatic remediation of SQLi, XXE, backdoors, IDOR or CVEs.
- Mandatory active multi-cloud, AKS, Redis, service mesh or HSM in the MVP.

## Global acceptance criteria

| ID | Criterion |
|---|---|
| AC-001 | No Vendor Secret is present in the client. |
| AC-002 | The Local Broker uses a separate Windows service identity. |
| AC-003 | An unauthorized process cannot use the Local Broker. |
| AC-004 | The business application cannot read service DPAPI blobs. |
| AC-005 | Local keys differ per Installation. |
| AC-006 | Secrets do not appear in logs. |
| AC-007 | The Gateway returns no secrets. |
| AC-008 | The Local Broker does not access the Vault directly. |
| AC-009 | The client cannot choose arbitrary URLs. |
| AC-010 | The client cannot choose arbitrary secret references. |
| AC-011 | Tenant derives from the authenticated Installation. |
| AC-012 | An Installation cannot impersonate another Tenant. |
| AC-013 | Installation revocation verified end-to-end. |
| AC-014 | Versioned Connectors. |
| AC-015 | Atomic rollback verified. |
| AC-016 | Configurations validated against schema and policy. |
| AC-017 | Runtime limited to Published versions. |
| AC-018 | Gateway deployable as a container. |
| AC-019 | Local Broker installable and upgradable through MSI. |
| AC-020 | Complete sources and build instructions. |
| AC-021 | Repeatable end-to-end tests with mocks. |
| AC-022 | .NET SDK and at least one additional legacy adapter. |
| AC-023 | Secure Layer example. |
| AC-024 | Managed Connector example. |
| AC-025 | Operational runbook and diagnostics. |
| AC-026 | Updated threat model. |
| AC-027 | SBOM for all artifacts. |
| AC-028 | Signable artifacts and tested signature verification. |
| AC-029 | In the pilot, old credentials removed or revoked. |
| AC-030 | In the pilot, old bypass and direct egress disabled. |

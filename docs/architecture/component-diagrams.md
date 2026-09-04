# Container and component diagrams

**CURRENT** views represent existing components. **TARGET** views describe
packaging or qualifications that remain open.

## CURRENT — Local Broker

```mermaid
flowchart TB
  subgraph Host[Windows Host]
    Apps[Legacy Applications]
    SDK[Thin .NET SDK]
    Pipe[Versioned Named Pipe Host]
    Identity[Caller Identity and Application Policy]
    Core[Broker Use Cases]
    LocalCrypto[DPAPI and AES-GCM]
    Hmac[Bounded HMAC]
    CNG[Installation CNG Key and BGW1 Signing]
    Store[(Protected Local Metadata and Blobs)]
    GatewayClient[Fixed-Origin Gateway Client]
    Audit[Redacted Local Audit]
  end
  Apps --> SDK --> Pipe --> Identity --> Core
  Core --> LocalCrypto
  Core --> Hmac
  Core --> CNG
  Core --> Store
  Core --> GatewayClient
  Core --> Audit
```

Current IPC operations include storage/deletion of permitted local secrets,
protect/unprotect, HMAC, Gateway invocation and status. There is no Broker interface for
reading a secret. The current SDK is .NET; native/COM and smart-card signing belong to
the legacy target.

## CURRENT — Gateway modular monolith

```mermaid
flowchart TB
  RuntimeAPI[Runtime and Enrollment APIs] --> Inbound[Installation Authentication and Replay Protection]
  Inbound --> Principal[GatewayClientPrincipal]
  Principal --> Grants[Server-Side Grants]
  Grants --> Catalog[Published Connector Catalog]
  Catalog --> Strategies[Bounded Execution Strategy Registry]
  Strategies --> Auth[Typed Auth and Capability Modules]
  Strategies --> Egress[Restricted Egress]

  AdminWeb[Admin Web Static Assets] --> AdminAPI[Same-Origin Admin API]
  AdminAPI --> AdminAuth[OIDC Session, CSRF and RBAC]
  AdminAuth --> Config[Four-Eyes Connector and Registry Administration]

  Inbound --> Persistence[Provider-Neutral Persistence]
  Catalog --> Persistence
  Config --> Persistence
  Persistence --> PG[(PostgreSQL 18)]

  Auth --> Ports[Provider Capability Ports]
  Egress --> Ports
  Ports --> Synthetic[Synthetic Provider]
  Ports -. explicit deployment composition .-> OptionalPack[Optional Provider Pack]
  Egress --> External[Configured External Service]

  RuntimeAPI --> Audit[Metadata-Only Audit]
  AdminAPI --> Audit
  Audit --> Persistence
```

Domain and Application remain provider-neutral. `Gateway.Api` composes Infrastructure,
Synthetic Provider, authentication runtime and explicitly configured modules. Azure, local
PKCS#12 and vertical packs are optional consumers and do not enter the Core graph. The
local PKCS#12 pack declares `SecretValues=false`; the generic secret provider supplied to the factory
is deny-only.

## CURRENT — Connector runtime and Published cache

```mermaid
flowchart LR
  Input[Authenticated Invocation] --> Principal[GatewayClientPrincipal]
  Principal --> Grant[Check Exact Connector and Operation Grant]
  Grant --> Stamp[Read Current Published Stamp]
  Stamp --> Cache{Matching Unexpired Cache Entry}
  Cache -->|No| Snapshot[Load Published Snapshot and Active Bindings]
  Cache -->|Yes| Operation[Authorized Published Operation]
  Snapshot --> Verify[Verify Snapshot Equals Stamp]
  Verify --> Operation
  Operation --> Strategy[Resolve Exact Installed Strategy]
  Strategy --> Capability[Resolve Bounded Provider Capabilities]
  Capability --> HTTP[Restricted Outbound Transport]
  HTTP --> Normalize[Bound, Sanitize and Audit Result]
```

The stamp covers Published authority and relevant binding/resource revisions. It is
checked on every invocation; a TTL cache does not become a stale fallback when the store is
unavailable or changes. The module receives no generic proxy, client-controlled
endpoint, locator or provider facade. An in-process .NET module nevertheless remains
full-trust.

## CURRENT — Admin plane and publication

```mermaid
flowchart LR
  Editor[Connector Editor] --> Web[Admin Web]
  Approver[Distinct Connector Approver] --> Web
  Web --> API[Same-Origin Admin API]
  API --> Draft[Draft Version and Binding]
  Draft --> Validate[Validate Canonical Definition]
  Validate --> Request[Request Exact Approval]
  Request --> Approval[Distinct Actor Approval]
  Approval --> Publish[Serializable Publish Transaction]
  Publish --> DB[(Published/Superseded State and Active Pointer)]
  DB --> Revision[Increment publication_revision and Append Audit]
  Publish --> LocalInvalidate[Invalidate Local Runtime Cache]
  Invoke[Next Runtime Invocation] --> Stamp[Read Current PostgreSQL Stamp]
  Stamp --> RuntimeCache[Reuse or Reload]
```

Approval is separate from version state and binds the canonical checksum and binding
digest. Publication makes the new version `Published`, the previous one
`Superseded` and updates the active pointer. Rollback reactivates a previously
published `Superseded` version without copying or modifying its bytes.

The runtime and Admin plane produce metadata-only records. Migration 0017 revokes
application-role modification of existing event records: runtime retains only INSERT on
audit/invocation and Admin only SELECT/INSERT on audit. Owner/migration and
host/DB administrators remain in the TCB; no signing or notarization is introduced.

## CURRENT — local no-cloud laboratory

```mermaid
flowchart LR
  Client[Local Broker or Direct Client] -->|mTLS and BGW1| Gateway[Gateway and Admin UI]
  Admin[Admin Browser] -->|same-origin HTTPS| Gateway
  Gateway --> PG[(PostgreSQL 18)]
  Gateway --> Synthetic[Synthetic Provider]
  Gateway --> Mock[HTTPS and mTLS Mock]
  Migrations[Separate Migration Container] --> PG
```

M2–M5 Compose profiles combine these components for tests and quickstart. They are synthetic
environments, not a qualified production topology. PostgreSQL uses separate roles, but
local Compose is not evidence of database TLS or production HA.

## CURRENT, opt-in — local PKCS#12 laboratory

The FSE2 overlay replaces only the Gateway image with a composition including the
local PKCS#12 provider and vertical module. The manifest and per-run synthetic material are
mounted read-only; the container remains non-root/read-only. The gate tests provider
certificate/signing, readiness and tamper response without executing live FSE2 calls.

## TARGET — optional Azure qualification

```mermaid
flowchart TB
  Traffic[Broker, Direct and Admin Traffic] --> App[Linux App Service Container]
  OIDC[OIDC Provider] --> App
  App --> AzurePack[Optional Azure Provider Pack]
  AzurePack -->|Managed Identity| KV[Azure Key Vault]
  App --> PG[(PostgreSQL Flexible Server 18)]
  ACR[Azure Container Registry] --> App
  Pipeline[Protected OIDC Pipeline] --> ACR
  Pipeline --> Bicep[m3-dev Bicep Smoke]
```

The pack and Bicep skeleton exist, but M3B has no attested live gate. Private
networking, HA/DR, backup/restore, release signing, operational monitoring and
production-qualified providers are targets, not baseline claims.

## TARGET — distribution

- Core alpha: publication and adoption gates; existing licensing and security-reporting
  policies are in [LICENSING.md](../../LICENSING.md) and [SECURITY.md](../../SECURITY.md);
- legacy: MSI, additional adapters and compatibility matrix;
- FSE2 OfficialTest: the [current optional pilot](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md)
  covers validation and lookup; remaining qualification targets are in the
  [capability summary](../../IMPLEMENTATION_STATUS.md);
- enterprise: qualified providers/cloud, provenance, backup/restore, HA/DR, load/soak
  and pentest.

Historical adopter-simulation evidence applies to its recorded baseline; it does not
by itself establish release readiness or production adoption.

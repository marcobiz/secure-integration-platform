# M5 — Admin UI and provider boundaries

## Purpose

M5 adds a production-grade administrative console without changing the Broker data plane. The console and Admin API cannot read secret values, contact providers directly or choose arbitrary runtime endpoints.

## Component view

```mermaid
flowchart LR
  B[Browser] -->|same-origin HTTPS + cookie| H[Gateway/Admin host]
  H -->|OIDC code + PKCE| I[OIDC provider]
  H --> A[Admin API v1]
  A --> P[RBAC policy + four-eyes]
  P --> C[Connector administration]
  P --> R[Registry administration]
  C --> DB[(PostgreSQL 18 + RLS)]
  R --> DB
  H --> UI[React static assets]
  RT[Gateway runtime] --> PA[Provider abstractions]
  PA --> SYN[Synthetic provider]
  AZ[Azure deployment pack] -. optional assembly .-> PA
  RT --> EXT[Restricted HTTPS egress]
```

Allowed dependencies:

```mermaid
flowchart BT
  D[Domain] --> X[no provider dependency]
  APP[Application] --> D
  ABS[Providers.Abstractions] --> X
  INF[Gateway.Infrastructure] --> APP
  INF --> ABS
  SYN[Providers.Synthetic] --> ABS
  HOST[Gateway.Api] --> INF
  HOST --> SYN
  AZ[Azure deployment pack] --> ABS
  AZ -. never a Core dependency .-> HOST
```

Core comprises Domain, Application, provider-neutral Infrastructure, API, Broker, SDK, contracts and synthetic provider. The Azure pack is an optional consumer of the abstractions alone.

This direction remains unchanged after M5: the local PKCS#12 pack is a second optional
consumer, and the default Gateway image includes neither that pack nor healthcare modules.
The local pack declares `SecretValues=false`; its generic secret provider is
deny-only, while certificate, public material and signing remain separate capabilities.

## Admin authentication flow

```mermaid
sequenceDiagram
  actor U as Operator
  participant B as Browser
  participant H as Admin host
  participant O as OIDC provider
  participant A as Admin API
  participant D as PostgreSQL
  U->>B: Open /admin
  B->>H: GET /admin/auth/login
  H->>H: state, nonce, PKCE, correlation cookie
  H->>O: authorization request
  O-->>H: authorization code
  H->>O: code + verifier
  O-->>H: validated ID token
  H->>D: resolve issuer + subject and roles
  H-->>B: HttpOnly Secure SameSite cookie + redirect
  B->>H: GET /admin/auth/csrf
  H-->>B: session-bound CSRF token
  B->>A: mutation + cookie + X-CSRF-TOKEN
  A->>A: session, CSRF, role, tenant scope, ETag
  A->>D: transaction and metadata-only audit
  A-->>B: DTO or ProblemDetails + correlationId
```

The persisted identity is `(issuer, subject)`. Email and display name are visual attributes, never authorization keys.

## Four-eyes lifecycle

```mermaid
stateDiagram-v2
  [*] --> Draft
  Draft --> Validated: validation
  Validated --> ApprovalRequested: request approval
  ApprovalRequested --> Approved: distinct approver + current checksum
  ApprovalRequested --> Draft: change invalidates request
  Approved --> Draft: change invalidates approval
  Approved --> Published: publish with ETag and valid approval
  Published --> Superseded: new version published
  Published --> Retired: retire
  Superseded --> Published: authorized rollback
```

An approval is a separate immutable record bound to version ID, checksum and approver. Creator, requester and last editor cannot approve. Any change to content or approval-controlled bindings invalidates prior approvals.

## Data flow and prohibitions

- The browser talks only to the same-origin Admin API.
- Admin UI/API persist logical references and metadata; they do not return secret values or key material.
- The runtime resolves endpoints and credentials exclusively server-side after grants and tenant binding.
- Broker and legacy applications receive no vendor secrets.
- No browser access to PostgreSQL, filesystem, synthetic vault or provider packs.
- The administrative API has no direct or indirect `GetSecret`.

## Local deployment

The frontend uses React 19, strict TypeScript, Vite, React Router, TanStack Query, React Hook Form, AJV 2020-12, CodeMirror 6, MUI Community, Lucide, i18next, Vitest, Testing Library, Playwright and axe. Client-side navigation preserves dirty state in complex forms and requires an explicit choice before discarding changes; no form content is persisted in localStorage. No CDNs, remote fonts, analytics, PWA or production source maps.

```mermaid
flowchart TB
  subgraph Browser
    WEB[Admin UI]
  end
  subgraph GatewayContainer[Non-root Gateway container]
    ASP[ASP.NET Core]
    STATIC[Hashed React assets]
    DEV[Development OIDC fixture]
  end
  subgraph PrivateNetwork[Private Compose network]
    PG[(PostgreSQL 18)]
    VAULT[Synthetic provider]
    MOCK[HTTPS/mTLS mock]
  end
  WEB --> ASP
  ASP --> STATIC
  ASP --> PG
  ASP --> VAULT
  ASP --> MOCK
  ASP --> DEV
```

Only the Gateway HTTPS port is published. PostgreSQL, synthetic provider and mock remain on the private Compose network.

## Open-source boundaries

The OSS export uses a versioned allowlist, creates a temporary directory, recomputes a SHA-256 manifest, performs license/secret scans and builds/tests the exported Core solution. Azure packs, healthcare packs, commercial adapters, raw evidence and internal reports are excluded. The export does not publish remote repositories.

The raw manifest digest depends on export content and run metadata and is not a
cross-run deterministic value. The exporter also writes a normalized inventory digest
over source commit and sorted paths, sizes and file hashes, without a run timestamp.
This is source-inventory identity, not binary reproducibility or release signing;
see [CoreExportInventory.psm1](../../eng/CoreExportInventory.psm1).

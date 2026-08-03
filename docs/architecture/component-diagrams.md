# Diagrammi di container e componenti

## Local Broker

```mermaid
flowchart TB
  subgraph Host[Windows Host]
    Apps[Legacy Applications]
    SDK[SDK / COM / C ABI / CLI]
    Pipe[Named Pipe Host]
    Identity[Caller Identity and Policy]
    Core[Broker Use Cases]
    Crypto[DPAPI / AES-GCM / HMAC / Signing]
    CNG[Windows CNG Identity Key]
    Store[(Local Metadata and Blobs)]
    Sessions[Session Store]
    GatewayClient[Gateway Client]
    Audit[Redacted Local Audit]
  end
  Apps --> SDK --> Pipe --> Identity --> Core
  Core --> Crypto
  Core --> CNG
  Core --> Store
  Core --> Sessions
  Core --> GatewayClient
  Core --> Audit
```

## Gateway modular monolith

```mermaid
flowchart TB
  RuntimeAPI[Runtime API] --> InstallAuth[Installation Authentication]
  EnrollmentAPI[Enrollment API] --> Enrollment[Enrollment Module]
  AdminAPI[Admin API] --> AdminAuth[OIDC and RBAC]
  InstallAuth --> Runtime[Connector Runtime]
  AdminAuth --> Config[Configuration Module]
  Enrollment --> Registry[Installation Registry]
  Runtime --> Registry
  Runtime --> Grant[Grant Policy]
  Runtime --> Connector[Connector Engine]
  Connector --> VaultPort[Secret Provider Port]
  Connector --> Outbound[Restricted Outbound Client]
  Config --> Persistence[Persistence]
  Registry --> Persistence
  Runtime --> Audit[Audit and Telemetry]
  Persistence --> PG[(PostgreSQL)]
  VaultPort --> AKV[Azure Key Vault]
  Outbound --> External[External Service]
```

## Connector runtime

```mermaid
flowchart LR
  Input[Authenticated Invocation] --> Resolve[Resolve Published Version]
  Resolve --> Grant[Check Installation Grant]
  Grant --> Validate[Validate Payload and Context]
  Validate --> Secrets[Resolve Logical Bindings]
  Secrets --> Auth[Typed Authentication Handler]
  Auth --> Mode{Mode}
  Mode -->|Secure Layer| Pass[Validated Pass-through]
  Mode -->|Managed| Plugin[Built-in Adapter or Signed Plugin]
  Pass --> HTTP[Restricted Outbound Client]
  Plugin --> HTTP
  HTTP --> Normalize[Validate / Normalize / Redact]
```

Il plugin non riceve un generico proxy o un endpoint client-controlled. L'interfaccia ristretta non costituisce sandbox: un plugin .NET in-process resta full-trust.

## Admin plane

```mermaid
flowchart LR
  User[Administrator] --> Entra[Microsoft Entra ID]
  Entra --> Web[Admin Web]
  Web --> API[Admin API]
  API --> Draft[Draft]
  Draft --> Validate[Validated]
  Validate --> Approve[Approved by second actor]
  Approve --> Publish[Published immutable version]
  Publish --> Deploy[Environment Deployment]
  Deploy --> Notify[LISTEN/NOTIFY]
  Notify --> Runtime[Runtime Cache]
  API --> Audit[(Administrative Audit)]
```

## Azure deployment

```mermaid
flowchart TB
  Internet[Broker and Admin Traffic] --> App[Linux App Service for Containers]
  Entra[Microsoft Entra ID] --> App
  App -->|Managed Identity| KV[Azure Key Vault]
  App -->|Private network / TLS| PG[(PostgreSQL Flexible Server)]
  App --> AI[Application Insights]
  AI --> LA[Log Analytics]
  ACR[Azure Container Registry] --> App
  Pipeline[Release Pipeline] --> ACR
  Pipeline --> Bicep[Bicep Deployment]
  Bicep --> App
  Bicep --> KV
  Bicep --> PG
```

## Self-hosted deployment

```mermaid
flowchart LR
  Broker -->|mTLS listener| Gateway[Gateway Container]
  Admin -->|OIDC control listener| Gateway
  Gateway --> PG[(PostgreSQL 18)]
  Gateway --> Vault[Configured Vault Provider]
  Gateway --> External[External Services]
```

Il provider produttivo iniziale resta Azure Key Vault. `LocalDevelopmentSecretProvider` accetta solo fixture sintetiche e deve rifiutare l'ambiente Production.


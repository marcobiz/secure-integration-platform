# Diagrammi di container e componenti

Le viste **CURRENT** rappresentano componenti presenti. Le viste **TARGET** descrivono
packaging o qualifiche ancora aperte.

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

Le operation IPC correnti includono storage/delete di secret locali ammessi,
protect/unprotect, HMAC, invoke Gateway e status. Non esiste un'interfaccia Broker per
leggere un secret. Lo SDK corrente è .NET; native/COM e smart-card signing appartengono
al target legacy.

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

Domain e Application restano provider-neutral. `Gateway.Api` compone Infrastructure,
Synthetic Provider, auth runtime e moduli esplicitamente configurati. Azure, local
PKCS#12 e i pack verticali sono consumer opzionali e non entrano nel grafo Core. Il pack
local PKCS#12 dichiara `SecretValues=false`; il generic secret provider fornito al factory
è deny-only.

## CURRENT — Connector runtime e cache Published

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

Lo stamp copre la Published authority e le revisioni binding/resource pertinenti. Viene
verificato a ogni invocazione; una cache TTL non diventa fallback stale quando lo store è
indisponibile o cambia. Il modulo non riceve un proxy generico, un endpoint
client-controlled, un locator o un provider facade. Un modulo .NET in-process resta
comunque full-trust.

## CURRENT — Admin plane e pubblicazione

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

L'approvazione è separata dallo stato della versione e lega checksum canonico e digest
dei binding. La pubblicazione rende la nuova versione `Published`, la precedente
`Superseded` e aggiorna il puntatore attivo. Il rollback riattiva una versione
`Superseded` già pubblicata senza copiarne o modificarne i byte.

Il runtime e l'Admin plane producono record metadata-only. Il comportamento applicativo
è append-only, ma `gateway_admin` conserva una grant UPDATE storica sulle tabelle audit;
la claim di immutabilità DB completa resta deferred fino a migration e test di privilege.

## CURRENT — laboratorio locale no-cloud

```mermaid
flowchart LR
  Client[Local Broker or Direct Client] -->|mTLS and BGW1| Gateway[Gateway and Admin UI]
  Admin[Admin Browser] -->|same-origin HTTPS| Gateway
  Gateway --> PG[(PostgreSQL 18)]
  Gateway --> Synthetic[Synthetic Provider]
  Gateway --> Mock[HTTPS and mTLS Mock]
  Migrations[Separate Migration Container] --> PG
```

I profili Compose M2-M5 combinano questi componenti per test e quickstart. Sono ambienti
sintetici, non una topologia production qualificata. PostgreSQL usa ruoli distinti, ma
il Compose locale non è prova di TLS database o HA production.

## CURRENT, opt-in — laboratorio local PKCS#12

L'overlay FSE2 sostituisce solo l'immagine Gateway con una composizione che include il
provider local PKCS#12 e il modulo verticale. Manifest e materiale sintetico per-run sono
montati read-only; il container resta non-root/read-only. Il gate prova provider
certificate/signing, readiness e tamper response senza eseguire chiamate FSE2 live.

## TARGET — qualifica Azure opzionale

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

Il pack e lo skeleton Bicep esistono, ma M3B non ha un gate live attestato. Networking
privato, HA/DR, backup/restore, release signing, monitoring operativo e provider
production-qualified sono target, non claim della baseline.

## TARGET — distribuzione

- Core alpha: packaging, licenza, security channel e clean-clone del golden path REST;
- legacy: MSI, adapter aggiuntivi e compatibility matrix;
- FSE2 OfficialTest: composizione verticale, custody/import e driver redatto, con
  `validate-cda` come primo outcome futuro;
- enterprise: provider/cloud qualificati, provenance, backup/restore, HA/DR, load/soak
  e pentest.

Early-adopter completion non è dichiarata finché `ALPHA-ADOPT` resta aperto.

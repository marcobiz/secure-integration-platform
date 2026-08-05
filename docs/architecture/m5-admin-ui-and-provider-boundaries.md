# M5 — Admin UI e confini dei provider

## Scopo

M5 aggiunge una console amministrativa production-grade senza modificare il data plane del Broker. La console e l'Admin API non possono leggere valori segreti, contattare provider direttamente o scegliere endpoint runtime arbitrari.

## Vista dei componenti

```mermaid
flowchart LR
  B[Browser] -->|same-origin HTTPS + cookie| H[Gateway/Admin host]
  H -->|OIDC code + PKCE| I[OIDC provider]
  H --> A[Admin API v1]
  A --> P[Policy RBAC + four-eyes]
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

Dipendenze consentite:

```mermaid
flowchart BT
  D[Domain] --> X[nessuna dipendenza provider]
  APP[Application] --> D
  ABS[Providers.Abstractions] --> X
  INF[Gateway.Infrastructure] --> APP
  INF --> ABS
  SYN[Providers.Synthetic] --> ABS
  HOST[Gateway.Api] --> INF
  HOST --> SYN
  AZ[Azure deployment pack] --> ABS
  AZ -. mai dipendenza Core .-> HOST
```

Il Core è l'insieme di Domain, Application, Infrastructure provider-neutral, API, Broker, SDK, contratti e provider sintetico. Il pack Azure è un consumer opzionale delle sole astrazioni.

## Flusso di autenticazione Admin

```mermaid
sequenceDiagram
  actor U as Operatore
  participant B as Browser
  participant H as Admin host
  participant O as OIDC provider
  participant A as Admin API
  participant D as PostgreSQL
  U->>B: Apri /admin
  B->>H: GET /admin/auth/login
  H->>H: state, nonce, PKCE, correlation cookie
  H->>O: authorization request
  O-->>H: authorization code
  H->>O: code + verifier
  O-->>H: ID token validato
  H->>D: resolve issuer + subject e ruoli
  H-->>B: cookie HttpOnly Secure SameSite + redirect
  B->>H: GET /admin/auth/csrf
  H-->>B: token CSRF associato alla sessione
  B->>A: mutation + cookie + X-CSRF-TOKEN
  A->>A: session, CSRF, ruolo, tenant scope, ETag
  A->>D: transazione e audit metadata-only
  A-->>B: DTO o ProblemDetails + correlationId
```

L'identità persistita è `(issuer, subject)`. Email e display name sono attributi visuali, mai chiavi di autorizzazione.

## Lifecycle four-eyes

```mermaid
stateDiagram-v2
  [*] --> Draft
  Draft --> Validated: validazione
  Validated --> ApprovalRequested: richiesta approvazione
  ApprovalRequested --> Approved: approvatore distinto + checksum corrente
  ApprovalRequested --> Draft: modifica invalida richiesta
  Approved --> Draft: modifica invalida approvazione
  Approved --> Published: publish con ETag e approvazione valida
  Published --> Superseded: nuova versione pubblicata
  Published --> Retired: retire
  Superseded --> Published: rollback autorizzato
```

Una approvazione è una registrazione separata e immutabile, legata a version id, checksum e approvatore. Creator, requester e ultimo editor non possono approvare. Ogni modifica del contenuto o dei binding soggetti ad approvazione invalida le approvazioni precedenti.

## Data flow e divieti

- Il browser parla soltanto con l'Admin API same-origin.
- Admin UI/API persistono riferimenti logici e metadata; non restituiscono secret value o materiale di chiave.
- Il runtime risolve endpoint e credenziali esclusivamente server-side dopo grant e tenant binding.
- Il Broker e il Legacy non ricevono vendor secret.
- Nessun accesso browser a PostgreSQL, filesystem, synthetic vault o pack provider.
- Non esiste `GetSecret`, diretto o indiretto, nell'API amministrativa.

## Deployment locale

Il frontend usa React 19, TypeScript strict, Vite, TanStack Query, React Hook Form, AJV 2020-12, CodeMirror 6, MUI Community, Lucide, i18next, Vitest, Testing Library, Playwright e axe. Il routing MVP usa collegamenti same-origin e un piccolo dispatcher di path: React Router è stato escluso perché la famiglia di versioni valutata introduceva advisory npm nel lockfile. La decisione è reversibile quando una versione compatibile e priva di advisory sarà disponibile. Nessun CDN, font remoto, analytics, PWA o source map di produzione.

```mermaid
flowchart TB
  subgraph Browser
    WEB[Admin UI]
  end
  subgraph GatewayContainer[Gateway container non-root]
    ASP[ASP.NET Core]
    STATIC[asset React hashati]
    DEV[Development OIDC fixture]
  end
  subgraph PrivateNetwork[rete Compose privata]
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

Solo la porta HTTPS del Gateway è pubblicata. PostgreSQL, provider sintetico e mock restano su rete privata Compose.

## Confini open source

L'export OSS usa una allowlist versionata, crea una directory temporanea, ricalcola un manifest SHA-256, esegue scansioni license/secret e compila/testa la soluzione Core esportata. Sono esclusi pack Azure, futuri pack sanitari, adapter commerciali, raw evidence e report interni. L'export non pubblica repository remoti.

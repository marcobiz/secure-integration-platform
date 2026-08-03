# Diagrammi di sequenza

## 1. Protezione di un segreto locale

```mermaid
sequenceDiagram
  participant L as Legacy
  participant B as Local Broker
  participant D as DPAPI
  participant S as Local Store
  L->>B: PutLocalSecret(logicalName, value)
  B->>B: Authorize Application and operation
  B->>D: Protect(CurrentUser, scoped entropy)
  D-->>B: Protected blob
  B->>S: Persist metadata and blob
  B-->>L: Opaque localSecretRef
```

## 2. Cifratura di un dato locale

```mermaid
sequenceDiagram
  participant L as Legacy
  participant B as Local Broker
  participant S as Key Store
  participant D as DPAPI
  L->>B: ProtectData(purpose, plaintext)
  B->>S: Load active key version
  B->>D: Unwrap data key
  B->>B: AES-256-GCM with scoped AAD
  B-->>L: Versioned authenticated envelope
```

## 3. HMAC tramite Local Broker

```mermaid
sequenceDiagram
  participant L as Legacy
  participant B as Local Broker
  participant D as DPAPI
  L->>B: ComputeHmac(operation, message)
  B->>B: Authorize operation and message constraints
  B->>D: Unprotect bound HMAC secret
  B->>B: HMAC-SHA256
  B-->>L: Digest only
```

## 4. Chiamata mTLS centralizzata

```mermaid
sequenceDiagram
  participant L as Legacy
  participant B as Local Broker
  participant G as Gateway
  participant V as Vault
  participant E as External Service
  L->>B: InvokeGateway(connector, operation, body)
  B->>G: mTLS + timestamp + nonce + signed body hash
  G->>G: Resolve Installation, grant and published version
  G->>V: Resolve vendor certificate
  G->>E: HTTPS mTLS to configured endpoint
  E-->>G: Response
  G-->>B: Validated response
  B-->>L: Response
```

## 5. OAuth browser locale e token exchange centrale

```mermaid
sequenceDiagram
  participant L as Legacy
  participant U as Browser
  participant B as Local Broker
  participant G as Gateway
  participant V as Vault
  participant I as Identity Provider
  L->>U: Open authorization URL with state/PKCE
  U-->>L: Authorization code
  L->>B: Exchange(code, verifier, stateRef)
  B->>G: Signed handoff
  G->>V: Resolve vendor client secret if required
  G->>I: Token exchange
  I-->>G: Access/refresh token
  G->>V: Store persistent session secrets
  G-->>B: Opaque sessionRef
  B-->>L: sessionRef
```

## 6. Smart card locale

```mermaid
sequenceDiagram
  participant L as Legacy
  participant B as Local Broker
  participant W as Windows Certificate Provider
  participant O as Operator
  L->>B: SignData(certificatePolicy, digest)
  B->>B: Authorize Application and claim constraints
  B->>W: Select allowed certificate and sign
  W->>O: Local PIN/provider interaction
  O-->>W: Consent/PIN
  W-->>B: Signature without private-key export
  B-->>L: Signature and public certificate metadata
```

## 7. Enrollment Installation

```mermaid
sequenceDiagram
  participant A as Administrator
  participant G as Gateway
  participant B as Local Broker
  participant C as Windows CNG
  A->>G: Create Installation and activation code
  B->>C: Generate non-exportable ECDSA P-256 key
  B->>G: Request short-lived challenge
  G-->>B: Challenge
  B->>C: Sign activation statement
  B->>G: Activation code + public certificate + proof
  G->>G: Verify code, proof and bind Tenant/Application
  G-->>B: Enrollment policy and certificate metadata
```

## 8. Revoca Installation

```mermaid
sequenceDiagram
  participant A as Administrator
  participant G as Gateway
  participant D as Database
  participant B as Local Broker
  A->>G: Revoke Installation(reason)
  G->>D: Revoke Installation and active credentials
  G->>D: Append audit event
  B->>G: Next runtime request
  G-->>B: 403 BGW-INSTALLATION-REVOKED
```

## 9. Pubblicazione Connector

```mermaid
sequenceDiagram
  participant E as ConnectorEditor
  participant A as ConnectorApprover
  participant G as Admin API
  participant D as Database
  participant R as Runtime Cache
  E->>G: Save draft
  G->>G: JSON Schema and security validation
  A->>G: Approve and publish
  G->>D: Immutable version + deployment revision
  G-->>R: Notify invalidation
```

## 10. Rollback Connector

```mermaid
sequenceDiagram
  participant A as ConnectorApprover
  participant G as Admin API
  participant D as Database
  participant R as Runtime Cache
  A->>G: Rollback(target published version, reason)
  G->>D: Create new deployment revision
  G->>D: Append audit event
  G-->>R: Invalidate active version
```

## 11. Managed Connector

```mermaid
sequenceDiagram
  participant L as Legacy
  participant B as Local Broker
  participant G as Gateway
  participant C as Managed Connector
  participant E as External Service
  L->>B: Domain operation and payload
  B->>G: Authorized invocation
  G->>C: Validated execution context
  C->>E: Protocol-specific request through restricted client
  E-->>C: Protocol response
  C-->>G: Normalized result
  G-->>B: Result
  B-->>L: Result
```

## 12. Secure Layer pass-through

```mermaid
sequenceDiagram
  participant L as Legacy
  participant B as Local Broker
  participant G as Gateway
  participant E as External Service
  L->>B: Pre-built SOAP/JSON/binary body
  B->>G: Body + fixed connector/operation
  G->>G: Validate content, size, grant and binding
  G->>E: Fixed method/path with injected authentication
  E-->>G: Response
  G-->>B: Validated pass-through response
  B-->>L: Response
```


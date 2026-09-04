# Sequence diagrams

Labels distinguish **CURRENT** sequences, current foundations not qualified
end-to-end, and targets. Numbering is retained for historical continuity.

## 1. CURRENT — Protecting a local secret

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

## 2. CURRENT — Encrypting local data

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

## 3. CURRENT — HMAC through Local Broker

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

## 4. CURRENT synthetic — Centralized mTLS call

```mermaid
sequenceDiagram
  participant L as Legacy
  participant B as Local Broker
  participant G as Gateway
  participant V as Server-Side Provider
  participant E as External Service
  L->>B: InvokeGateway(connector, operation, body)
  B->>G: mTLS + timestamp + nonce + signed body hash
  G->>G: Resolve Installation, grant and published version
  G->>V: Resolve purpose-bound client certificate
  G->>E: HTTPS mTLS to configured endpoint
  E-->>G: Response
  G-->>B: Validated response
  B-->>L: Response
```

## 5. FOUNDATION CURRENT — OAuth authorization code and central token exchange

```mermaid
sequenceDiagram
  participant L as Legacy
  participant U as Browser
  participant B as Local Broker
  participant G as Gateway
  participant V as Server-Side Provider
  participant I as Identity Provider
  L->>B: Begin authorization for logical profile
  B->>G: Signed handoff for authorized operation
  G->>G: Generate state and S256 verifier; retain bounded one-time attempt
  G-->>U: Approved authorization URL
  U-->>G: Authorization callback with code and state
  G->>V: Resolve vendor client secret if required
  G->>I: Token exchange
  I-->>G: Access/refresh token
  G->>G: Keep bounded process-local token session
  G-->>B: Opaque sessionRef
  B-->>L: sessionRef
```

The foundation is implemented and tested at module level. It is not an E2E hosted OAuth execution
strategy or qualification of an external identity provider.

## 6. TARGET — Local smart card

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

## 7. CURRENT — Installation enrollment

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

## 8. CURRENT — Installation revocation

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

## 9. CURRENT — Connector publication

```mermaid
sequenceDiagram
  participant E as ConnectorEditor
  participant A as ConnectorApprover
  participant G as Admin API
  participant D as Database
  participant R as Runtime Cache
  E->>G: Save draft
  G->>G: JSON Schema and security validation
  E->>G: Request approval for exact version and binding digest
  A->>G: Approve as distinct actor
  A->>G: Publish with expected revisions
  G->>D: Serializable transaction verifies approval, publishes and supersedes
  G-->>R: Invalidate local cache
  R->>D: Next invocation rechecks current Published stamp
```

## 10. CURRENT — Connector rollback

```mermaid
sequenceDiagram
  participant A as ConnectorApprover
  participant G as Admin API
  participant D as Database
  participant R as Runtime Cache
  A->>G: Rollback(target Superseded version, reason, expected revision)
  G->>D: Reactivate exact prior bytes and update active pointer/revision
  G->>D: Append metadata-only audit event
  G-->>R: Invalidate local cache; next invoke rechecks stamp
```

## 11. CURRENT seam / TARGET packaged example — Connector execution module

```mermaid
sequenceDiagram
  participant L as Legacy
  participant G as Gateway Core
  participant C as Installed Connector Module
  participant E as External Service
  L->>G: Authorized operation and bounded payload
  G->>G: Resolve principal, grant, Published authority and exact strategy
  G->>C: Read-only business input and bounded capability bridge
  C->>G: Request exact Published capability
  G->>E: One restricted protocol-specific request
  E-->>G: Bounded response
  G-->>C: Bounded capability result
  C-->>G: Normalized result
  G-->>L: Sanitized result
```

## 12. CURRENT — Secure Layer pass-through

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

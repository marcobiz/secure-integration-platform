# Work breakdown e backlog ordinato

Scala: 3 small, 5 medium, 8 large, 13 very large. Le stime sono relative e non temporali.

| ID | Epic / story | Task principali | Pri | SP | Dipendenze | Parallelo |
|---|---|---|---:|---:|---|---|
| FND-01 | Repository foundation | solution, layout, conventions, scripts, pinned SDK | P0 | 8 | — | No |
| FND-02 | CI quality gates | build/test/analyzers/schema/doc links | P0 | 8 | FND-01 | Sì |
| FND-03 | Supply-chain gates | secret/dependency/container scan, SBOM, manifest | P0 | 8 | FND-01 | Sì |
| BRK-01 | Windows service host | virtual account, service SID, lifecycle, recovery | P0 | 8 | FND-01 | Sì |
| BRK-02 | Local filesystem boundary | ProgramData layout, ACL, migration/version | P0 | 8 | BRK-01 | Sì |
| BRK-03 | IPC framing | pipe host, frames, handshake, limits, cancellation | P0 | 13 | BRK-01 | Sì |
| BRK-04 | Caller identity | SID, PID/handle/time, path, publisher/hash, manifest | P0 | 13 | BRK-03 | No |
| BRK-05 | Local secret storage | DPAPI entropy, metadata, deletion, zeroing | P0 | 8 | BRK-02 | Sì |
| BRK-06 | Local data protection | AES-GCM envelope, versions, lazy rotation | P0 | 13 | BRK-05 | Sì |
| BRK-07 | HMAC/signing operations | scoped use, constraints, audit | P0 | 8 | BRK-04/05 | Sì |
| SDK-01 | .NET SDK | netstandard/net10, async, timeout, errors, streaming | P0 | 8 | BRK-03 | Sì |
| SDK-02 | Legacy simulator | synthetic app and behavior fixtures | P0 | 5 | SDK-01 | Sì |
| GTW-01 | Gateway skeleton | host, modules, auth policies, health | P0 | 8 | FND-01 | Sì |
| DAT-01 | Domain and schema | entities, constraints, migrations, roles | P0 | 13 | GTW-01 | Sì |
| DAT-02 | Tenant isolation | RLS context, composite FK, negative tests | P0 | 8 | DAT-01 | No |
| IDN-01 | Enrollment | activation HMAC, challenge, CNG PoP, registry | P0 | 13 | BRK-07/DAT-01 | No |
| IDN-02 | Runtime identity | mTLS forwarding/direct, request signature, replay | P0 | 13 | IDN-01 | No |
| IDN-03 | Renewal/revocation | overlap, expiry, cache, re-enrollment | P0 | 8 | IDN-02 | Sì |
| VLT-01 | Secret provider | interface, Azure Key Vault, memory cache | P0 | 8 | GTW-01 | Sì |
| VLT-02 | Synthetic provider | test-only provider with production guard | P0 | 5 | VLT-01 | Sì |
| EGR-01 | Restricted outbound | URI/path/header builder, TLS, size/timeout | P0 | 13 | GTW-01 | Sì |
| EGR-02 | SSRF/DNS controls | resolve/filter/connect callback, redirect/proxy rules | P0 | 13 | EGR-01 | No |
| CON-01 | Connector schema | JSON Schema, canonicalization, CLI validation | P0 | 13 | FND-01 | Sì |
| CON-02 | Semantic/security validator | refs, auth/location, retry, endpoint policy | P0 | 13 | CON-01/EGR-02 | No |
| CON-03 | Runtime pipeline | resolve/grant/bind/auth/invoke/redact | P0 | 13 | CON-02/VLT-01 | No |
| CON-04 | Lifecycle | state machine, immutability, projection, audit | P0 | 13 | DAT-01/CON-01 | Sì |
| CON-05 | Deployment/cache | revisions, publish/rollback, notify/poll | P0 | 13 | CON-04 | Sì |
| VSL-01 | Secure Layer vertical slice | REST body, API key+mTLS, mock and E2E | P0 | 8 | M1/M2 core | No |
| ADM-01 | Admin OIDC/RBAC | Entra, app roles, antiforgery, bootstrap | P1 | 13 | GTW-01 | Sì |
| ADM-02 | Installation console | create code, status, revoke, health | P1 | 8 | ADM-01/IDN-03 | Sì |
| ADM-03 | Connector editor | JSON editor, validation, diff/import/export | P1 | 13 | ADM-01/CON-04 | Sì |
| ADM-04 | Approval/deployment UI | four-eyes, publish, rollback, audit | P1 | 13 | ADM-03/CON-05 | No |
| NAT-01 | Native IPC client | C++20 x86/x64, buffers, cancellation | P1 | 13 | IPC v1 | Sì |
| NAT-02 | C ABI | header, handles, error contract, samples | P1 | 8 | NAT-01 | Sì |
| NAT-03 | COM Automation | ATL, BSTR/SAFEARRAY/HRESULT, type library | P1 | 8 | NAT-01 | Sì |
| NAT-04 | Secure CLI | stdin/pipe, exit codes, no command-line secret | P1 | 5 | IPC v1 | Sì |
| AUT-01 | Basic/API key | typed injection and redaction | P0 | 5 | CON-03 | Sì |
| AUT-02 | OAuth client credentials | token cache/Vault/session reference | P1 | 8 | CON-03/VLT-01 | Sì |
| AUT-03 | Auth code/PKCE | state/verifier handoff, exchange, refresh | P1 | 13 | AUT-02/IDN-02 | Sì |
| AUT-04 | JWT RS256 | fixed issuer/audience/claims/lifetime | P1 | 8 | CON-03 | Sì |
| AUT-05 | SOAP/XML | secure parser, envelope and response handling | P1 | 13 | CON-03 | Sì |
| AUT-06 | Local certificate/smart card | store policy, CSP/KSP/PKCS#11 seam | P1 | 13 | BRK-07 | Sì |
| PLG-01 | Plugin verification | manifest, CMS, publisher and startup load | P1 | 13 | CON-03/FND-03 | Sì |
| HCP-01 | Synthetic Secure Layer | healthcare-shaped mTLS fixture | P1 | 8 | VSL-01/AUT | Sì |
| HCP-02 | Synthetic Managed Connector | SOAP Basic+session plugin and tests | P1 | 13 | AUT-05/PLG-01 | Sì |
| MIG-01 | Seam Map tooling/template | provenance, finding, tests, evidence | P1 | 5 | docs baseline | Sì |
| MIG-02 | Real pilot | seam, rotation, bypass removal, acceptance pack | P1 | 13 | HCP/M6 | No |
| PKG-01 | Broker MSI | WiX, ACL/service, upgrade/repair/uninstall | P1 | 13 | M1 stable | Sì |
| DEP-01 | Container hardening | non-root/read-only/health/signing hooks | P1 | 8 | M2 stable | Sì |
| DEP-02 | Azure Bicep | app, ACR, KV, PG, network, telemetry | P1 | 13 | DEP-01 | Sì |
| OPS-01 | OTel observability | traces, metrics, redaction, dashboards | P1 | 13 | M2/M4 | Sì |
| OPS-02 | Runbook/alerts | rotation, revoke, outage, rollback, restore | P1 | 8 | OPS-01 | Sì |
| ENT-01 | Secure updater | signed manifest/package and anti-rollback | P2 | 13 | PKG/signing | Sì |
| ENT-02 | Recovery enterprise | wrapped per-Installation recovery, dual control | P2 | 13 | stable key model | Sì |
| ENT-03 | HA/DR | zone redundancy, restore, failover, cross-region plan | P2 | 13 | DEP-02 | Sì |
| ENT-04 | Plugin isolation evaluation | worker/container based on real requirements | P2 | 8 | plugin evidence | Sì |
| SDK-03 | Java adapter | thin JAR/transport client | P2 | 8 | IPC v1 | Sì |

## Priorità

- P0: necessario al vertical slice e agli invarianti di sicurezza.
- P1: necessario alla prima release/pilot.
- P2: hardening o espansione successiva, attivata da requisito reale.


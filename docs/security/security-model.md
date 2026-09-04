# Security model

## Protection objectives

1. Prevent Vendor Secret extraction and distribution.
2. Limit a local compromise to one Installation and its authorized capabilities.
3. Prevent unauthorized Applications from using the Local Broker.
4. Prevent cross-Tenant/cross-Installation impersonation.
5. Prevent clients from turning the Gateway into a proxy, signer or secret oracle.
6. Protect local data/keys against offline copying and unprivileged processes.
7. Provide revocation, rotation, metadata-only audit and verifiable provenance.

## Authority and identity

Broker and Direct clients use ClientAuth mTLS, BGW1, timestamps and nonces. The Gateway
resolves the credential in the registry and derives Installation, Application, Tenant,
Environment and caller kind from authenticated state. Client fields with the same
semantics are not authoritative.

Connector/operation grants are server-side and deny-by-default. Published authority
defines the execution strategy, endpoint, method/path/body mode, bindings and auth profile.
A reread may confirm the same authority A but cannot adopt B during an invocation.

## Provider capability boundary

Providers expose separate capabilities:

- `ISecretValueProvider` for bounded server-side use;
- `IClientCertificateProvider` for one-shot mTLS attachment;
- public certificate metadata and material;
- `IKeyOperationProvider`/signing without private-key export;
- `IMacProvider`;
- health and capability discovery.

There is no generic `IKms`, nor a client/Broker/UI `GetSecret`. The runtime does not
return PFX, private keys, locators or authenticated request handles. Endpoints and locators
are resolved server-side from Published configuration and the provider catalog.
Missing capabilities are not inferred, combined or emulated.

The local PKCS#12 pack declares `SecretValues=false`. Its `ISecretValueProvider` slot is
deny-only: it neither resolves paths nor accesses the filesystem. A1 and S1 are distinct
resources; certificate use, public material and signing remain separate capabilities.
The repository qualifies the pack using only per-run synthetic material. The pack does
not replace HSM/KMS, custody, rotation/revocation, operational import or live qualification.

## Local Broker

- Dedicated virtual service account and service SID.
- Restrictive ACLs on the pipe, `ProgramData` and CNG key.
- Composite Application identity: SID, registration, path, publisher/hash and process
  handle/creation time.
- Frame/payload limits, timeouts, cancellation, nonces and sequences.
- Per-operation and Connector/operation authorization.
- Storage/deletion of permitted local secrets, AES-GCM protect/unprotect and bounded HMAC.
- No IPC operation for reading/revealing secrets or generic signing.
- Redacted local audit and health without sensitive values.

The Broker Installation key is a non-exportable ECDSA P-256 CNG key owned by the service
identity. Complete repair/upgrade/recovery remain installer targets, not claims made
by the laboratory script.

## Gateway and Connector Runtime

- Credentials/status/revocation checked fail-closed; nonces consumed atomically.
- Tenant/Application/Installation derived from the registry.
- Grants and Published ConnectorVersion only.
- Checksum/four-eyes and binding digest checked during publication.
- Published/binding/resource stamps rechecked per invocation; no stale-on-error.
- Logical secret/certificate/key bindings resolved server-side.
- Optional providers and modules depend on provider-neutral Core, never the reverse.
- The default Gateway image uses the Synthetic Provider and contains no vertical packs.

Execution modules receive bounded authority and invocation-bound capabilities, not
generic providers/stores/service locators/endpoints/credentials. They are nevertheless
full-trust in-process code: the boundary limits the supported surface; it is not a sandbox.

## Egress, TLS and SSRF

- HTTPS is mandatory on supported central paths.
- Scheme/host/port and path templates come from Published authority.
- DNS/IP validation blocks literals, loopback, private, link-local, multicast and metadata
  addresses, except exact-host/CIDR test allowances in dedicated environments.
- Sockets use validated addresses; the runtime rechecks authority and bindings after
  relevant awaits and before dispatch.
- Redirects, ambient proxies, cookies and hop-by-hop headers are denied.
- Method, Content-Type, auth headers, certificates, timeouts and response bounds are
  server-owned.
- Retries only for operations declared idempotent; no stale fallback.

Synthetic CAs and HTTPS/mTLS mocks prove the local pipeline. They do not attest the
trust, revocation, availability or conformance of a real external service.

## Admin plane and browser

- Server-side OIDC Authorization Code with PKCE, state and nonce.
- Browser uses `__Host-`, HttpOnly, Secure, SameSite cookies and a server-side session.
- CSRF on mutations, CSP/frame policy, no permissive CORS.
- Stable `(issuer, subject)` principal and server-side roles; email is not authority.
- Tenant scope, RBAC, optimistic concurrency and checksum-specific four-eyes.
- Same-origin UI without access to PostgreSQL, providers, Broker or the filesystem.
- No secret values, private keys, reusable activation codes or provider locators in
  the browser.

DevelopmentAuth is test-only, loopback-only and rejected in Production.

## PostgreSQL, RLS and audit

PostgreSQL stores metadata, canonical JSON, checksums, public certificate material and
server-side locators; it does not store secret values. Composite FKs and FORCE RLS defend
tenant scope. Migration, runtime, admin, readonly and locator-owner are distinct identities;
`SECURITY DEFINER` locator functions have a NOLOGIN owner and operation-scoped predicates.

Audit and invocation events are metadata-only: no bodies, Authorization/Cookie, tokens,
passwords, private keys or raw responses. Code and `gateway_runtime` emit INSERT only.
Additive migration 0017 corrects the broad grant in 0001: it revokes UPDATE/DELETE/
TRUNCATE on `audit_event` and all unnecessary Admin privileges on `invocation_event`.
Consequently:

- metadata-only audit is **CURRENT** and tested;
- application runtime/admin roles are **CURRENT** append-only;
- `gateway_admin` retains only SELECT/INSERT on `audit_event`; SecurityAdministrator
  read-back and Admin inserts remain unchanged;
- `gateway_runtime` retains INSERT on both tables and no implicit SELECT;
- `gateway_readonly` receives no new event privileges;
- owner/migration and privileged DBA/host identities remain in the TCB.

This control is the PostgreSQL privilege matrix, not an immutability trigger. It does
not introduce signing or notarization and is not absolute protection against a DBA.

The presence of the tables alone does not implement/qualify partitioning, retention jobs,
backup/PITR or restore.

## Parsing, bounds and redaction

- DTDs, external entities and XML resolvers are disabled.
- Input limits for bytes, depth, nodes, attributes and scalars.
- QName/cardinality, namespaces and Fault structure checked in implemented modules.
- JSON Schema 2020-12, additional-property denial in closed contracts and canonical
  checksums.
- Provider/module exceptions sanitized to stable codes; genuine cancellation preserved.
- Structural redaction before serialization, with canary/secret scans as additional
  protection.

Fields prohibited in logs/audit/redacted evidence include payloads, Authorization/Cookie,
tokens, passwords/PINs/OTPs, private keys/PFX, activation codes and unnecessary PII.

## Current and target supply chain

**CURRENT:** pinned lock files/toolchain/base images, fail-closed Dockerfile validator,
secret/dependency/container checks, SPDX SBOM, Core export and architecture boundary tests.
The module loader checks the exact local path, assembly identity/type/module ID and MVID
on the same bytes; ACLs/provenance remain deployment responsibilities.

**TARGET:** Authenticode/CMS/Cosign, module publisher allowlist/hash manifests, release
publishing, signed provenance and CycloneDX. These are not baseline guarantees.

The raw export SHA manifest contains run-specific metadata and is not a cross-run
deterministic digest. The exporter also produces a normalized inventory and digest
from the source commit and sorted file paths, byte counts and hashes, without a run
timestamp. This identifies the exported source inventory, not reproducible binaries
or signed provenance; see [CoreExportInventory.psm1](../../eng/CoreExportInventory.psm1).

## Evidence and claim boundary

- Synthetic-qualified tests do not mean OfficialTest.
- A live lab with real processes/containers and synthetic fixtures does not mean a live
  FSE2 call.
- OfficialTest does not mean production/accreditation.
- Received and correlated certificates do not mean operational import.
- The [capability summary](../../IMPLEMENTATION_STATUS.md) distinguishes FSE2 offline
  completeness from the observed CDA/workflow live qualification and remaining limits.
  The [current pilot](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md)
  owns the procedure and live evidence; neither implies overall live qualification.

## Declared risks

- Local Administrator and SYSTEM can replace binaries, read memory or abuse an authorized
  process.
- Necessary plaintext and key handles temporarily exist in the TCB.
- A malicious in-process module can cause compromise/DoS despite the restricted contract.
- Gateway/provider compromise requires incident response and external rotation.
- The Direct sample does not qualify production key custody.
- Process-local caches/sessions do not imply scale-out or durability.
- The platform limits the capabilities of compromised legacy software but does not
  guarantee its integrity.

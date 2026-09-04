# Secure Integration Platform

Secure Integration Platform (SIP) runs integrations with external services on behalf
of installed applications, including legacy software. The application sends data
and an operation name; a Gateway authenticates the caller, checks its permission
to perform the operation, and uses the external service's credentials on the server.
The client receives neither those credentials nor their private signing keys.

The integration unit is a **Connector**: a versioned JSON definition describing
operations, message formats, authentication, logical resource references and execution
limits. It can include a compiled module for protocols that the existing primitives
cannot express. It is not an open HTTP proxy: callers cannot arbitrarily select a
destination, HTTP method or key.

SIP provides a Direct path to the Gateway and a Local Broker for Windows.
The Core also includes PostgreSQL persistence, the Connector runtime, a synthetic
provider, the .NET SDK and the Admin UI/API. The software is a technical private
preview: having these components does not imply an installer, API stability or
production qualification.

[Running the Core locally](#running-the-core-locally) comes first, followed by
the [sample](#example-the-sample-secure-service-connector),
the [reasons for separating responsibilities](#why-separate-applications-operations-and-credentials),
the [request path](#how-a-request-moves-through-the-gateway) and
the [code map](#finding-your-way-around-the-code).

## Running the Core locally

The local path uses a Direct client and a synthetic HTTPS/mTLS upstream. It needs
no access to external services, cloud resources or healthcare packs.

Prerequisites:

- a repository checkout obtained with Git;
- Docker Engine/Desktop with Linux containers and Docker Compose;
- Windows PowerShell 5.1 or PowerShell 7;
- network access for build packages and images that are not already cached.

.NET SDK, Node, npm, curl and PostgreSQL **are not required on the host**:
application tools and builds run in containers. This applies to the default Core
path, not to the FSE2 pilot or Windows laboratories.

From the checkout root:

```powershell
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Validate
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Run
```

`Validate` checks Linux Docker/Compose and builds the sample in the pinned SDK image.
`Run` builds and starts PostgreSQL 18, migrations, Gateway/Admin UI, the synthetic
provider and an HTTPS/mTLS mock. It prepares the Published configuration and Direct
identity, makes one application call, and checks the response, outbound request,
audit and cleanup. The runner supplies the sample's temporary configuration: there
is no `.env` file to fill in, no credentials to copy and no database intervention.

Success markers include:

```text
ALPHA_GOLDEN_PATH_DIRECT_PASS
ALPHA_GOLDEN_PATH_OUTBOUND_PASS; POSITIVE_OUTBOUND_COUNT=1
ALPHA_GOLDEN_PATH_RESPONSE_PASS; SANITIZED=YES; AUDIT=METADATA_ONLY; LOGS=REDACTED
ALPHA_GOLDEN_PATH_CLEANUP_PASS; CONTAINERS=0; NETWORKS=0; VOLUMES=0; SYNTHETIC_MATERIAL=0
ALPHA_GOLDEN_PATH_PASS
```

The run removes its own containers, network, volume and synthetic material; it does
not leave a permanent service to administer. If interrupted:

```powershell
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Stop
```

After cleanup, repeat `Validate` and `Run`; intermediate resume is not supported.
The runner does not change the host trust store. The [local procedure](docs/user/local-pilot.md)
covers operational details; [troubleshooting](docs/user/troubleshooting.md)
maps error codes to supported actions.

## Example: the sample-secure-service Connector

The [sample client](samples/DirectGatewayClient/Program.cs) creates its own ECDSA
P-256 key and certificate, then enrolls through a challenge and proof of key
possession. These identify the client to SIP; they are not the upstream vendor's
API key or certificate.

The sample sends this application payload:

```json
{"message":"direct-gateway-sample"}
```

The client encodes it in the runtime `InvokeRequest` envelope, signs the BGW1
request and invokes
`POST /v1/connectors/sample-secure-service/operations/submit:invoke`.
It does not send that JSON directly to the vendor. The
[sample-secure-service 1.0.0 definition](docs/connectors/examples/sample-secure-service.connector.json)
specifies how to handle `submit`:

- `POST /vendor/orders` at the destination bound to `sample-vendor-endpoint`;
- a JSON body, with a 1 MiB limit for both request and response;
- `apiKeyAndMtls` authentication: the Gateway applies `X-Vendor-Api-Key` and uses
  a client certificate, resolved through two separate logical bindings;
- a 30-second timeout, redirects denied, no arbitrary client headers and
  zero automatic retries; the operation is declared non-idempotent.

The definition contains binding names, not the API key value, private certificate
material or deployment URL. The mock checks the expected API key and certificate.
The sample decodes the application result in the Gateway envelope and prints:

```json
{"accepted":true,"vendorReference":"synthetic-order"}
```

This is the sample's output, not the entire upstream HTTP response. The type and
decoding are in [GatewayApiContracts.cs](samples/DirectGatewayClient/GatewayApiContracts.cs).
The runner also checks that the call produced exactly one accepted outbound request.

This checks the authenticated path to the mock and server-side use of API key and
mTLS credentials. The name `orders` does not imply a business contract: the payload
is not a complete order and the mock does not run a business process. It does not
establish correctness against a real vendor, exercise the Windows Local Broker,
demonstrate external JWT signing or qualify production storage of the Direct key,
which is process-local in this sample.

## Why separate applications, operations and credentials

An external credential distributed with an application may authorize more functions
than that installation needs. Hiding it in a local file does not change the fact
that the process must be able to use it. A protocol or credential change may also
require updating many copies of the client.

SIP separates three decisions. Identity establishes **who is calling**; a grant
establishes **which operation is allowed**; server configuration establishes **how
to execute it and which external resources to use**. Knowing a Connector's name is
not sufficient to invoke it, and permission to invoke it does not provide access
to the underlying credential. The application remains responsible for the data and
intent of the operation; external authentication and destination are the Gateway's
responsibility.

This separation has a cost. Gateway, database, provider, network and SIP identity
management become dependencies in addition to the vendor. Bindings and grants must
be configured and configurations approved. A missing or stale configuration blocks
execution instead of selecting an implicit fallback. Calls pass through an additional
service, adding latency and operational costs that must be measured for the intended
workload. No particular performance or availability level is promised.

This moves the trust boundary; it does not remove trust. Gateway and provider can
use sensitive material and must be protected. A compromised application can still
attempt operations allowed to its identity with malicious input. SIP does not
replace endpoint security, business validation or the external service's controls.

## How a request moves through the Gateway

Direct and Broker Installations use the same runtime protocol. The following path
distinguishes controls from the components that perform the work.

1. **Client authentication.** The Gateway verifies the Installation certificate
   presented through mTLS and the BGW1 signature. Method, target, timestamp, nonce
   and body hash participate in the signature; timestamp and nonce limit replay.
   Prior enrollment binds the key to an Installation, the registered identity of
   a SIP client. Tenant, Application and Environment come from authenticated
   server-side state, not from a tenant asserted in the payload. The request also
   carries a `traceparent`.

2. **Operation authorization.** The Gateway checks Installation state and revocation
   and looks for an active Connector/operation grant in its scope. A missing grant
   is a denial, not implicit permission. These checks precede credential access
   and dispatch to the vendor.

3. **Published configuration resolution.** The catalog selects the published version
   and Environment bindings. The definition fixes the method, path, authentication
   and limits; bindings associate logical names with concrete server-side resources.
   A Published definition is immutable. Publication requires approval of the exact
   checksum/configuration by an authorized principal distinct from the proposal's
   author. Revisions and freshness checks prevent silently substituting an approved
   configuration during execution.

4. **Connector execution.** The runtime checks payload encoding and size and selects
   the operation's strategy. That strategy builds the protocol message. An external
   module receives an already-authorized context, not permission to select tenants,
   providers, credentials or a general-purpose HTTP client. Any transformations and
   response reductions belong to the operation contract; they are not code or
   scripts supplied by the caller.

5. **Provider capabilities.** The Core requests only the capabilities needed:
   secret retrieval for server-side use, client certificate use, digest signing,
   MAC, public metadata, health and discovery are separate contracts. A signature
   can therefore be requested from a provider without exporting its private key;
   an API key, by contrast, must be available to the server code that applies it.
   Applications, Broker and Admin UI have no `GetSecret` API. Custody guarantees
   depend on the actual provider, not merely the interface name.

6. **Restricted transport.** The Core enforces the authorized destination and policy,
   resolves addresses and checks DNS/egress, TLS, timeouts and response limits.
   The caller cannot use SIP as a proxy to an arbitrary address or metadata service.
   Redirects and retries depend on the permitted contract; the sample denies the
   former and disables the latter. Losing a response after remote acceptance does
   not make it safe to repeat a mutation.

7. **Result and audit.** The client receives an envelope with a correlation ID,
   Connector version and bounded application result, not credentials or upstream
   headers. The Connector must define what to return: sanitization is not a
   universal sensitive-data detector. Audit and errors retain metadata and bounded
   codes, not bodies, tokens or keys. This limits diagnostic data: a generic code
   is not enough to infer the remote cause.

PostgreSQL stores identities, grants, configurations and audit, and where required
durable technical correlations, not an archive of application payloads.
The Gateway processes payloads during execution: this is not end-to-end encryption
that excludes the server from reading them. Admin APIs manage control state with
roles and concurrency checks. The UI communicates only with those authenticated,
same-origin APIs, not with the database, providers or filesystem.

## Direct clients and the Windows Local Broker

A **Direct** client calls the Gateway over HTTPS and owns its Installation key.
It uses the common enrollment, mTLS, BGW1, grants and runtime. It avoids a local
service installation, but makes the application responsible for storing its client
key, renewing its identity and handling revocation. It provides no Windows
isolation between the application process and that key. The local sample uses this path.

The **Local Broker** is a Windows Service with a separate identity. The application
uses the SDK over a Named Pipe; the Broker checks pipe access and local process
identity/policy before forwarding authorized operations to the Gateway. The service
stores its local material using Windows protections, including DPAPI/CNG, and uses
its own Installation for remote access. It does not receive vendor credentials.

The Broker therefore adds a local application/service boundary to the Gateway's
controls. It also requires service management, process policies, ACLs and local
identity recovery. It is not a universal adapter for every language: MSI and C ABI/COM
adapters are not available as qualified adoption paths. The two client types do
not introduce two server authorization models; see
[ADR-0020](docs/adr/0020-direct-gateway-client-principal.md).

## Security model and residual threats

Separating external credentials does not make applications anonymous or free of
secrets. Each client retains its own identity, directly or through the Broker.
Theft of a Direct key or control of an authorized process can enable abuse of
existing grants; revocation and least privilege remain necessary. Absolute
protection against malware is not promised.

Administrator and SYSTEM can compromise the Windows service and its context:
they remain privileged residual threats. Gateway, provider and database
administrators also remain inside the trust boundary. Audit immutability against
a database administrator is not claimed.

The model requires deny-by-default, server-side tenant isolation, TLS and egress
checks, immutable Published configurations and four-eyes approval. Browser
administration also requires authentication, RBAC, CSRF, secure cookies and CSP.
DevelopmentAuth identities and local-path CAs are synthetic laboratory material,
not a production configuration.

See the [security model](docs/security/security-model.md) for details.
Report vulnerabilities according to [SECURITY.md](SECURITY.md), without publishing
credentials, tokens, sensitive payloads, dumps or raw responses.

## Available paths and verification coverage

The [capability summary](IMPLEMENTATION_STATUS.md) is authoritative for the state
integrated through PR #65 and the qualification of each surface. These paths are
not interchangeable:

- **Local synthetic Core.** The commands above check Direct → Gateway → Published
  Connector → HTTPS/mTLS mock, response, audit and cleanup. They use neither cloud
  nor healthcare and do not exercise the Windows Local Broker. Synthetic evidence
  does not qualify a real vendor's API or behavior.
- **Windows / Local Broker.** The [historical M0/M1 and M3A evidence and runbooks](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/history/README.md#windows--local-broker-evidence)
  cover a real Windows Service, identity/process controls, ACLs, persistence after
  restart and, for M3A, legacy simulator → Broker → Gateway → synthetic upstream.
  They apply to their attested baselines. They require a dedicated Windows laboratory
  and are not a new demo or an exact-head qualification of the current README.
- **Optional FSE2.** The pack for Italy's electronic health record system
  (Fascicolo Sanitario Elettronico 2.0) depends on Core contracts, never the reverse.
  The [current validation/status pilot](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md)
  has its own prerequisites, including a host .NET SDK, OfficialTest access and
  previously provisioned, authorized A1/S1 material. Its 14 routes are complete
  offline within the frozen specification's limits. CDA `VERIFICA` and workflow
  `FOUND` after restart are live-qualified for the observed cases. FHIR is not
  live-qualified: upstream HTTP 500, cause undetermined. Live document publication
  is not qualified; publishing a Connector configuration is not publishing a document.

No production readiness, overall certification or FSE2 accreditation is claimed.
Live cloud use, production custody, HA/DR, restore/load/soak, penetration testing
and artifact signing are not qualified. The [limitations summary](docs/user/known-limitations.md)
also links historical profiles; their qualification does not transfer to a new profile.

## Finding your way around the code

The server and Broker are implemented in .NET, the UI in React/TypeScript, and
persistence uses PostgreSQL. These entry points follow the request path above:

| Area | Responsibility and reading entry point |
|---|---|
| Gateway HTTP and identity | [Gateway.Api](src/Gateway/Gateway.Api) hosts APIs and composition; [RuntimeIdentityService.cs](src/Gateway/Gateway.Application/RuntimeIdentityService.cs) manages runtime identity. |
| Authorization and execution | [OperationServices.cs](src/Gateway/Gateway.Application/OperationServices.cs) coordinates grants, Published operations, strategy, result and audit; [ConnectorExecutionContracts.cs](src/Gateway/Gateway.Application/ConnectorExecutionContracts.cs) defines the authorized context and capabilities. |
| Infrastructure | [Gateway.Infrastructure](src/Gateway/Gateway.Infrastructure) contains persistence and restricted transport; [Gateway.Migrations](src/Gateway/Gateway.Migrations) applies migrations with privileges separate from the runtime. |
| Providers | [ProviderContracts.cs](src/Providers/Abstractions/ProviderContracts.cs) separates capabilities; [Synthetic](src/Providers/Synthetic) implements them for local tests. |
| Windows and clients | [Broker](src/Broker) contains the service, logic and Windows integration; [BrokerClient.cs](sdk/dotnet/Broker.Sdk/BrokerClient.cs) is the Named Pipe client. The [Direct sample](samples/DirectGatewayClient) shows the other entry path. |
| Administration | [Admin.Web](src/Admin/Admin.Web) uses Gateway Admin APIs; it does not resolve bindings or credentials in the browser. |

The [Gateway API specification](docs/api/gateway-api.md) and [OpenAPI](docs/api/gateway-openapi.yaml)
describe the actual envelopes. For a REST Connector, start with the sample definition:
declare logical bindings, operations and an authentication profile, then validate
against the [schema](docs/connectors/connector-definition.schema.json). Deployment
associates resources through Admin APIs, grants operations and follows validation,
proposal, distinct approval and publication. The
[onboarding guide](docs/user/guided-connector-onboarding.md) describes that workflow.

A compiled module is needed only when existing primitives cannot express the protocol.
It must use the authorized context and bounded Core capabilities without adding
general-purpose provider, store, signing or HTTP access. The [Connector guide](docs/connector-development/README.md)
and [SDK contract](docs/connectors/connector-sdk.md) cover extension and positive/negative
tests. The supported path from empty configuration to the first invocation is part
of a Connector, not a SQL sequence left to operators.

The exported Core excludes deployment providers and vertical packs.
[Export boundaries](OPEN_SOURCE_BOUNDARIES.md) and [architecture](ARCHITECTURE.md)
explain the separation. FSE2 and historical links point to the full repository:
those documents and packs do not need to be included in the Core.

## Licensing and contributions

The repository's [licensing policy](LICENSING.md) assigns licenses by path:
MPL-2.0 is the default; SDKs, samples, the synthetic provider and the contracts
listed in the policy use Apache-2.0. Generic examples under `docs/connectors/examples`
use `MPL-2.0 OR Apache-2.0`. The texts are in [LICENSE](LICENSE) and
[LICENSE-APACHE-2.0](LICENSE-APACHE-2.0); this summary does not replace the full mapping
or dependency licenses.

[CONTRIBUTING.md](CONTRIBUTING.md) and [DCO.md](DCO.md) describe contributions.
The [documentation index](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/README.md)
separates current procedures, technical references and history; milestone documents
do not override the integrated status.

# Core alpha golden path

Product candidate: `0.1.0-alpha.1`. This product version is distinct from the unchanged
BGW1/runtime protocol version `1.0` and the canonical Connector version `1.0.0`.

This is the single supported early-adopter path for the non-production Core alpha:

```text
Direct .NET sample
-> Gateway
-> Published sample-secure-service/submit
-> Synthetic Provider
-> restricted HTTPS/mTLS mock
-> sanitized response and metadata-only audit
```

It is a synthetic local evaluation, not a production deployment or an external-service
qualification. It uses no cloud account, FSE2 material or real credential.

## Prerequisites

- Docker Engine with Linux containers and Docker Compose;
- the .NET SDK selected by `global.json`: baseline `10.0.302` with
  `rollForward: latestPatch`;
- PowerShell 7 or Windows PowerShell 5.1;
- network access only when the pinned SDK, NuGet packages or container images are not
  already present in public caches.

Node is built inside the pinned Gateway image for this path. No host `.env`, trusted
development CA, cloud login or pre-existing project container is required.

From the repository root, verify the SDK resolver without changing the host:

```powershell
dotnet --version
```

The command is intentionally run under the directory that contains `global.json`; the
.NET CLI resolver is authoritative for `latestPatch`. Installing a compatible SDK is the
adopter's responsibility. The runner never downloads an SDK, changes `PATH`, falls back
to .NET 8 or turns a missing prerequisite into success.

Preflight reports only bounded stable diagnostics:

```text
ALPHA_GOLDEN_PATH_DOTNET_HOST_NOT_FOUND
ALPHA_GOLDEN_PATH_DOTNET_SDK_UNAVAILABLE;BASELINE=10.0.302;ROLL_FORWARD=latestPatch
ALPHA_GOLDEN_PATH_CHILD_EXIT_NONZERO;COMPONENT=DotNet;EXIT_CODE=<bounded>
```

The first means no `dotnet` host could be started; the second means the host ran but the
CLI could not resolve an SDK compatible with `global.json`. The third is reserved for a
later restore/build/run child failure. Raw CLI output, stack traces and local paths are
not printed.

## Run

From the repository root:

```powershell
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Validate
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Run
```

`Run` builds and starts PostgreSQL 18, migrations, Gateway/Admin UI, Synthetic Provider
and the HTTPS/mTLS mock. The quickstart creates a synthetic Direct Installation and grant
in its isolated database, but keeps the one-time activation only in the ignored per-run
directory and process environment. The sample compiles from source and uses only the
public enrollment and invoke HTTP contracts; it has no friend access, store/provider
access, endpoint override, credential selector or generic secret retrieval.

The runner verifies:

- positive health/readiness and the built Admin UI;
- Published `sample-secure-service` version `1.0.0` and operation `submit`;
- exactly one additional outbound `POST /vendor/orders` with `application/json`, the
  expected body SHA-256 and expected synthetic client-certificate SHA-256;
- Synthetic Provider reads for the server-owned API key and mTLS certificate;
- a usable sanitized response, one correlated successful `operation.invoke` audit event,
  and absence of per-run canaries, authorization/cookie values, private-key PEM and stack
  traces from sample output, audit and container logs;
- zero project containers, networks and volumes plus removal of activation material,
  private keys, PFX files and control output in a `finally` cleanup.

The Direct sample receives HTTP `200` with the public `InvokeResponse` envelope. For the
canonical operation the minimum observable result is:

```json
{
  "correlationId": "11111111-1111-1111-1111-111111111111",
  "connectorVersion": "1.0.0",
  "result": {
    "contentType": "application/json; charset=utf-8",
    "encoding": "base64",
    "data": "eyJhY2NlcHRlZCI6dHJ1ZSwidmVuZG9yUmVmZXJlbmNlIjoic3ludGhldGljLW9yZGVyIn0="
  }
}
```

After decoding `result.data`, the sample prints:

```json
{
  "accepted": true,
  "vendorReference": "synthetic-order"
}
```

`accepted: true` means only that the local synthetic HTTPS/mTLS mock accepted the one
canonical request. `synthetic-order` is the expected synthetic reference; neither value
is an external-service, business-outcome or production claim. During `Run`, the runner
uses the same correlation ID to verify exactly one `operation.invoke` success audit event
containing metadata only. In an interactive local Admin session the same redacted audit
surface is the **Audit** page at `/admin/audit`; the automated run verifies it before its
isolated database is removed.

Expected final markers are:

```text
ALPHA_GOLDEN_PATH_DIRECT_PASS
ALPHA_GOLDEN_PATH_OUTBOUND_PASS; POSITIVE_OUTBOUND_COUNT=1
ALPHA_GOLDEN_PATH_RESPONSE_PASS; SANITIZED=YES; AUDIT=METADATA_ONLY; LOGS=REDACTED
ALPHA_GOLDEN_PATH_CLEANUP_PASS; CONTAINERS=0; NETWORKS=0; VOLUMES=0; SYNTHETIC_MATERIAL=0
ALPHA_GOLDEN_PATH_PASS
```

If a run is interrupted, execute the idempotent, ownership-checked cleanup:

```powershell
./tools/alpha/Invoke-AlphaGoldenPath.ps1 -Phase Stop
```

The Direct sample keeps its private key only for the process lifetime. A production
consumer must use an appropriate protected or non-exportable client key store. The local
DevelopmentAuth mode and synthetic CA/material are never production controls. This path
is a synthetic public-technical-preview evaluation only: it is not an external-service
qualification, a stable API commitment or a production deployment.

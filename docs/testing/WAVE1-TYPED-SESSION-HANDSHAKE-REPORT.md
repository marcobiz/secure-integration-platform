# Wave 1 typed session handshake and external admission report

## Candidate scope

This report covers only the generic Core capability described by ADR-0022. It does not qualify a
production connector, a deployment environment, a distributed cache or generic XML scripting.

## Implemented controls

- Published/four-eyes profile authority and exact registered adapter ID/type selection;
- hardened, bounded Core-owned request writer and response reader boundary;
- closed handshake outcomes without raw XML or dynamic field bags;
- dedicated sensitive candidate presentation type and closed provenance;
- opaque TTL/single-use admission intent embedded in the existing bounded session cache;
- remote validation without cache authority;
- post-validation policy/resource revalidation and atomic generation promotion;
- remote expiry validation and server-owned cap;
- rotate/disable/current-generation race denial;
- neutral real-HTTPS nested handshake/validation protocol;
- unchanged scalar M6 session profile path.

## Local evidence on the candidate worktree

| Suite | Result | Coverage |
|---|---:|---|
| `TypedSessionHandshakeTests` | 27 PASS | typed adapters, admission, races, bounds, redaction, publication and API |
| `TypedSessionHandshakeRealHttpIntegrationTests` | 2 PASS | direct and external admission over pinned real HTTPS plus subsequent session use |
| legacy SOAP plus Connector configuration targeted unit tests | 34 PASS | backward compatibility and schema/lifecycle regression |
| legacy real-HTTPS SOAP integration | 5 PASS | existing Login/Challenge/Business/Logout and hardening regression |
| Architecture tests | 24 PASS | Core/provider/auth boundaries and vertical neutrality |
| ordinary solution suite | 434 total: 423 PASS, 11 PostgreSQL-conditional SKIP | all solution projects; zero failures |
| Gateway integration suite on PostgreSQL 18 | 105 PASS, 0 SKIP | fresh migration, idempotent second apply and non-superuser admin principal |
| Release restore/build | PASS, 0 warnings, 0 errors | pinned .NET SDK and locked dependency graph |
| documentation validation and conservative secret scan | PASS | repository documentation and tracked/untracked candidate content |
| SPDX SBOM generation/validation | PASS | .NET, Admin Web and Gateway container artefacts |
| vulnerable package scan | PASS | no vulnerable direct or transitive NuGet packages reported |

## Visible gate failures and remediation

- The first Core export on candidate `cac6bfe` failed in the exported Admin Web tests because the
  new `action` and `namespaceUri` fields used JSON Schema `format: uri`, while the pinned AJV
  composition intentionally has no format plugin. Exported .NET build and tests had passed before
  that failure. The schema now uses explicit bounded, scheme-prefixed, control/space-denying
  patterns instead of relying on an unregistered format.
- A direct `npm run test:e2e` invocation then reached zero product assertions because its required
  Gateway at `https://localhost:8443` was not running (`ECONNREFUSED`). The repository-owned
  `Invoke-M5FullStack.ps1` harness was used for the qualified rerun: `FULLSTACK-01`, redaction and
  cleanup all passed against the production build and real PostgreSQL/synthetic-service stack.
- Remediation evidence before the export rerun: AJV schema tests 2/2 PASS, typed unit tests 27/27
  PASS, Admin lint/API drift/unit 28/28/build PASS and owned full-stack 1/1 PASS.

The open-source Core export, exact candidate HEAD, pull request, exact-head CI and independent review
remain pending until the final commit and publication steps complete. No merge is authorized by this
report.

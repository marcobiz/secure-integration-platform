# FSE2 Organization: OfficialTest validation and lookup

**Audience:** organizations authorized to use OfficialTest.
**Status:** CURRENT, entry point to the optional FSE2 pilot at the PR #65 baseline.
**Outcome:** VERIFICA validation and bounded lookup, not document publication.
The [capability summary](../../IMPLEMENTATION_STATUS.md#product-status) distinguishes
offline coverage, live outcomes and limits; the
[current-spec contract](../connectors/healthcare/fse2/current-spec.md) details the routes.

This local path uses the normal Gateway, PostgreSQL and the Published
`fse2-organization-current-spec@1.0.0` profile. It does not enable document
publication: the runner allows only `VERIFICA` and lookup. The profile's 14
operations remain offline-qualified; this does not imply live availability.

## Prerequisites

- Repository distribution with Linux Docker Desktop and the .NET SDK specified by
  `global.json`; Windows PowerShell 5.1 or PowerShell 7.
- A LocalPkcs12 root already provisioned and authorized for OfficialTest, with
  `manifest.json`, `material`, and valid `fse2-auth` A1 and `fse2-sign` S1 resources.
  No operational material is created, copied or changed. The mount is read-only.
- HTTPS access to GitHub for frozen official examples and to the OfficialTest
  service. No TLS exceptions, redirects or automatic retries.
- No other active `secure-integration-m5-quickstart` stack. The command rejects
  resources from other checkouts; it does not attempt to free other owners' ports or containers.
- Organization/locality administrative configuration, stored outside the repository.
  The [officialtest-pilot.example.json](../../tools/fse2/officialtest-pilot.example.json)
  template contains only synthetic values: use values permitted by your test access.
  The domain is the official three-digit organization code and corresponding
  description (§16.3.7), **not** the local health authority/facility identifier.
  The template uses the already-qualified test profile (`190` / `Regione Sicilia`,
  `LABORATORIO DI PROVA`); it does not assign that domain to another organization.

No SQL, direct store access, copied cookies, reconstructed UUIDs/checksums or operational
certificates supplied to the caller are needed. Existing bootstrap creates synthetic
local identities; Direct enrollment uses a real challenge and proof of possession.

## Commands and roles

From a clean, committed distribution, set the three local paths:

```powershell
$runner = '.\tools\fse2\Invoke-Fse2ValidationStatus.ps1'
$provider = 'C:\SecureRuntime\fse2-officialtest-v1'
$settings = 'C:\SecureRuntime\fse2-pilot-settings.json'
$sdk = (Get-Command dotnet).Source

# Copy the template outside the repository once and check its organization/locality
# values against your test access before Configure.
Copy-Item '.\tools\fse2\officialtest-pilot.example.json' $settings
& $runner -Phase Start -ProviderRoot $provider -DotNetPath $sdk
& $runner -Phase Configure -SettingsPath $settings
& $runner -Phase Propose -SettingsPath $settings
& $runner -Phase Approve -SettingsPath $settings
& $runner -Phase Verify -SettingsPath $settings
```

`Configure` uses Security Administrator; `Propose` uses Connector Editor;
`Approve` uses a distinct Connector Approver and publishes **the configuration**,
not a healthcare document. The approved checksum and current revision are read from
the APIs. There are only four grants: FHIR/CDA validation and workflow/trace status.
Sessions are obtained normally in memory through the already-supported DevelopmentAuth
login, exclusively from the M5Testing stack's real loopback. This is not an
authentication method for production or a remote Gateway.

Administrative commands reuse the provisioner and its fail-closed resume:
correct existing configuration is not recreated; drift and insufficient permissions
require explicit correction and are not bypassed.
`Verify` also checks mTLS/BGW1 on the existing Broker read operation: for an
authenticated Direct client, role denial is expected and distinct from authentication
failure. This check sends no OfficialTest requests.

## Validation and a second instance

Each invocation command below sends **one invocation**, never an automatic loop:

```powershell
& $runner -Phase Validate-Fhir -SettingsPath $settings
& $runner -Phase Audit -SettingsPath $settings
& $runner -Phase Restart
& $runner -Phase Status-Workflow -SettingsPath $settings
& $runner -Phase Audit -SettingsPath $settings
```

The runner downloads the official `RAP.json` example into memory from commit
`4d2691dcdc051fa5a842e2cac074226bb50373d2`, checks SHA-256
`5FBEB57A5250FBFB3E6F028C834316CCA1546109CB5A2EE34A748E22C0F880DF` and the
explicitly test-only `PROVA…` patient. It sends the unchanged Bundle as a multipart
JSON file with `{"mode":"RESOURCE","activity":"VERIFICA"}`, according to the frozen
OpenAPI. It does not infer the format from the route name or save the document.

`Status-Workflow` takes the technical identifier returned by the last validation.
You can specify `-Identifier` with a previously observed workflow. The runtime
payload contains only the identifier; the Gateway resolves all other authority.
Each command starts in a new process; `Restart` also restarts the Gateway without
touching PostgreSQL. There is no in-memory fallback.

If FHIR validation returns no workflow, **do not invent one**. You can intentionally
run `-Phase Validate-Cda`, then Audit, Restart and Status-Workflow: it uses PDF
PSS476 and the corresponding XML from accreditation commit
`d937255fd7e9c079c5641c537da17fe98a2f2259`, both hash-checked, without rewriting
the PDF. This is a separate CDA test, not a FHIR PASS.
`Status-Trace` is reserved for a concrete diagnostic/regression need.

## Outcomes, resume and cleanup

- `VALIDATED`: upstream success and Gateway mapping; does not mean publication.
- `FOUND`: transaction found; `eventCount` reports the bounded events returned.
- `NOT_FOUND`: exclusively the allowlisted `record-not-found` recognized by
  the product. It does not prove a completed workflow.
- `FAILURE_CHECK_AUDIT`: query Audit. A generic 404 remains a failure; it does not
  by itself prove an accreditation problem. Audit shows one success/failure and,
  when available, phase, upstream HTTP and allowlisted code, never body or detail.
- `DISPATCH_PENDING`: outcome not yet known; read Audit, do not blindly resend.
- `WORKFLOW_MISSING…`: prerequisite missing; use an actually returned workflow
  or consider the permitted CDA validation. There is no manual store insertion.
- Local errors: check prerequisites, state/role and the reported stable code.
  If activation expires before enrollment, stop and restart your own stack; no
  OfficialTest request is needed to restore bootstrap. A test configuration already
  Published with incorrect organization values must also be recreated in a new
  temporary stack: the immutable definition is not overwritten.

Identifiers and the last reduced result are in
`.artifacts/m5/fse2-validation-status/fse2-last-call.json`; `fse2-build.json` binds
executed code, Gateway image and provisioner. Existing bootstrap `raw` files contain
only temporary local identities and are not evidence to publish.
Do not export them. Retain only the reduced ledger before Stop.

```powershell
& $runner -Phase Stop
```

Stop reuses M5 ownership and cleanup: it removes only the owned stack, temporary
database and temporary local material. The operational A1/S1 root remains unchanged.
The ignored provisioner build may remain as a non-sensitive local cache.

## Qualification observed on September 4, 2026

Code executed live: `ac115fef76344dc4857204830b6badbc154a03d4`, on a clean temporary
deployment with Published configuration and a normally enrolled Direct identity.
Subsequent documentation edits and a C# parameter rename for a Gitleaks false positive
do not change behavior and require no further live requests.

| Path with corrected configuration | Upstream / Gateway HTTP | Outcome | Audit per invocation |
| --- | --- | --- | --- |
| FHIR RAP JSON, VERIFICA | 500 / 502, in two intentional requests | `generic-error`; **not live-qualified** | 0 success, 1 failure |
| CDA PSS476, VERIFICA | 200 / 200 | `VALIDATED`, workflow and trace returned | 1 success, 0 failure |
| CDA workflow after real Gateway restart | 200 / 200 | `FOUND`, 1 bounded event | 1 success, 0 failure |

The second FHIR attempt, a few minutes later, tested whether the 500 was transient;
it was not an automatic retry. The frozen source documents this JSON format and
provides no ready-to-use alternative FHIR PDF. The allowlisted `generic-error`
code does not identify the cause: it does not establish an accreditation, format
or authorization problem. No FHIR PASS is claimed and no speculative changes are made.

The status workflow is the one actually returned by CDA validation. The new client
sends only `resourceIdentifier` and ordinary authentication; PostgreSQL retains
correlation authority during Gateway restart. `FOUND` proves lookup with events,
not publication or clinical completion.

Development-session total: 7 local HTTP invocations, 6 FSE2 upstream requests.
The first local invocation stopped with 401 before authentication and without
operation audit: the new client omitted `traceparent`, subsequently corrected and tested.
Two initial upstream requests (FHIR/CDA) returned 403 `jwt-validation` with the
incorrect local health authority domain in the template, subsequently corrected
using the already-qualified profile. Another CDA command stopped locally at the
dataset check, without invocation: the irrelevant assumption that the official CDA
case had the FHIR `PROVA` prefix was removed. The other four requests are in the table.
Admin, enrollment, health and local authentication checks are not FSE2 upstream requests.
Automatic retries, redirects, status-by-trace and document publications: **zero**.

Focused verification: 28 passing `Fse2PilotTests` /
`Fse2ProvisionerResumabilityIntegrationTests`; BGW1/traceparent signing, frozen
datasets, denied publication commands, reduction without raw data, four grants and
provisioner resume. Full CI runs are associated with the subsequent final PR HEAD,
without local duplication. The session ledger retains only metadata and hashes,
not JWTs, operational certificates, documents or response bodies. Stop removes the
temporary stack and bootstrap; the A1/S1 root does not change.

Offline qualification of the 14 routes remains distinct from this partial live
qualification of CDA validation/workflow lookup. This path establishes no
production, accreditation or publication qualification.

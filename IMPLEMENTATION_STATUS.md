# Implementation dashboard

Updated: 2026-09-05
Baseline integrated through PR #68:
`56b6d9a7dd07bdfbcff3ea74e7b9f95b18a59929`.
PR #67 integrated the standalone Local Broker protection and SDK peer-authentication
candidate. Its exact-main General and M5/Admin gates passed; the real Windows Service
qualification remains attached to software commit
`3955fd0c3a5eccf816d44b0faba9a704227baa3d` and its stated limits.

This page is the authoritative summary of integrated capabilities and claim limits.
CURRENT guides own procedures; technical references detail contracts; earlier plans,
reviews and reports are HISTORICAL for the state summarized here.
`Synthetic`, `live lab`, `OfficialTest qualified` and `production qualified` are
distinct levels. The integrated baseline does not replace the exact commit of a live test.

## Product status

| Surface | CURRENT status | Claim limit |
|---|---|---|
| Core M0–M5.5 | Integrated | Local Broker, Gateway, PostgreSQL, Connector lifecycle/runtime, Admin and Direct Gateway; not equivalent to an installer or enterprise production readiness. |
| A. Local Core pilot | **Available — Docker-first synthetic live lab** | Primary path: Direct .NET → Gateway → Published REST Connector → HTTPS/mTLS mock. Host needs Git, PowerShell and Linux Docker/Compose; no host .NET SDK, Node, npm, curl or PostgreSQL. No external service, cloud or healthcare pack. |
| B. Windows / Local Broker | **Integrated — standalone protection and authenticated SDK path** | Exact-main software includes mutual SCM/PID/pipe-owner authentication, explicit local-key lifecycle, application/operation/context policy and the bounded sample. The real-service result remains exact to `3955fd0c...`; ordinary-user, cross-release and machine/profile restore are not qualified. |
| Broker → Gateway continuity | **Integrated through PR #68 — targeted synthetic E2E PASS** | Existing Broker identity records authoritative renewal lifecycle, renews single-flight, resumes after restart or a lost renewal response and reports uncertain remote outcomes as non-retryable. Evidence is an in-process Windows transport fixture over the real enrollment, authorization, Published Connector and Synthetic Provider services; it is not a Windows Service or PostgreSQL/live qualification. |
| Windows x64 delivery | **ACTIVE CANDIDATE — package and focused checks** | Self-contained Broker/sample archive, explicit application-user SID independent of setup admin, state-preserving lifecycle and SHA-256 inventory. Windows 10 Pro 22H2 x64 build 19045.6466 is the selected test host. Ordinary-token, two-build and real-service → Gateway checks are pending elevated setup; no expanded Windows/production claim. |
| Admin UI/API | **Integrated — guided Connector onboarding** | Five actions across three roles for Installation/enrollment, definition, binding/grant, four-eyes and first invocation. `FULLSTACK-02` proves reload/resume and first invocation on PostgreSQL 18. The pilot uses synthetic identities, not production authentication. |
| Authentication foundation | **Integrated** | Provider-neutral SOAP/session, JWT/X.509, signing and mTLS primitives; they do not automatically qualify an external service. |
| C. FSE2 Organization current-spec | **PRODUCT_PATH_OFFLINE_COMPLETE — 14 routes** | Opt-in profile `fse2-organization-current-spec@1.0.0`: contracts, provisioning and bounded responses complete within the [frozen specification](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/connectors/healthcare/fse2/current-spec.md). This does not mean 14 live-qualified routes. |
| FSE2 CDA `VERIFICA` | **LIVE_QUALIFIED — OfficialTest** | On the current-spec profile: upstream/Gateway 200, `VALIDATED`, workflow and trace, A1 mTLS and dual S1 JWT; does not enable or prove document publication. |
| FSE2 `get-status-by-workflow` | **LIVE_QUALIFIED — OfficialTest, observed CDA case** | After a real Gateway restart: upstream/Gateway 200, `FOUND`, one bounded event for the workflow returned by CDA. Proves lookup and durable PostgreSQL correlation, not clinical completion or publication. |
| FSE2 FHIR `VERIFICA` | **NOT LIVE-QUALIFIED** | Two intentional requests with corrected configuration: upstream 500 / Gateway 502, `generic-error`. Cause undetermined; this code cannot establish a format, accreditation or authorization cause. |
| FSE2 live document publication | **NOT QUALIFIED** | The current runner permits only VERIFICA and lookup. Publishing a Connector configuration does not publish documents; a `202` does not prove completion towards INI/EDS. |
| Overall FSE 2.0 Gateway coverage/qualification | **NO** | Offline limited to the 14 frozen routes; live limited to the cases above. Human Actor, inbound callbacks and confirmed native FHIR publication remain excluded. |
| Private preview | **Limited** | Core and optional pilot can be evaluated with their respective prerequisites; no public release or guaranteed API stability. |
| Production/accreditation | **NOT QUALIFIED** | Live cloud use, MSI, C ABI/COM adapters, HA/DR, restore/load/soak, penetration testing, artifact signing and production custody are not qualified. |

## Local Broker path — standalone and continuity integrated, Windows delivery active

PR #67 integrated the independently usable Windows Local Broker software: an identified,
authorized .NET application uses an Installation-local key without receiving it or
requiring a Gateway. The result includes mutually authenticated IPC,
application/operation/context policy, state preservation across restart and supported
same-candidate service update, DPAPI-bounded lifecycle/backup/restore, and a small
executable SDK/sample and guide. It is not an installer or public release.

The integrated path contains SCM/pipe-owner peer authentication, explicit
non-replacing data-key initialization, exact protection-context grants, and the
[sample/lifecycle guide](docs/user/local-broker.md). Focused Windows transport,
DPAPI/storage and simulated-SCM lifecycle tests pass.
The single elevated gate subsequently passed on exact software candidate
`3955fd0c3a5eccf816d44b0faba9a704227baa3d`: actual service install/start, standalone
Protect, repeated Stop, restart, old-ciphertext verify, two unauthorized-client denials,
same-candidate update/restart/verify and owned cleanup. `FIRST_PROTECT_MS=12532` is an
observation without a performance threshold. Cleanup removed the exact service
registration but intentionally preserved installation/state; it was not an uninstall.
Ordinary-user service use, cross-release update and machine/profile restore remain
unqualified.

PR #68 completed the existing Broker → Gateway path without another
identity or runtime. The Broker persists only Installation/credential lifecycle metadata,
creates a non-exportable replacement key inside the server-owned renewal window, and
serializes renewal per process. A pending renewal is recorded before dispatch; a later
explicit application invocation probes the new credential through authenticated
`/v1/broker-policy` and either promotes it, safely sends the still-unaccepted renewal once,
or returns a bounded unresolved error. A lost invoke response and any post-dispatch 5xx
are `gateway_outcome_ambiguous` with `Retryable=false`; there is no automatic invocation
retry. Revocation, expiry and removed grants remain Gateway-side denials before the
synthetic upstream.

The integrated fixture proves enrollment, Published Connector invocation, restart with
the same Installation and no activation reuse, single-flight renewal, interruption
recovery, explicit reconnection and negative authority cases. It uses the real Core
services and filesystem/CNG state behind an in-process HTTP handler; it does not claim an
actual Windows Service, TLS socket, PostgreSQL or external-service qualification. The
historical M3A path remains the operational reference until a new bounded real-service
gate is authorized and available. Target-specific
distribution and operational qualification follow, without making universal MSI,
COM/native, all Windows versions, full M9 or enterprise HA/DR prerequisites for the
first local result. The full repository's implementation plan and backlog own this
sequence; they do not authorize a new Connector, customer pilot or FSE2 live call.

Local keys belong to the Installation; vendor credentials remain on the Gateway side.
The Broker is not EDR/HSM and cannot protect plaintext returned to a compromised
application. Administrator/SYSTEM remain residual threats. DPAPI blob backup is not
portable key recovery: machine/profile loss without the necessary recovery material
may make protected data unrecoverable. Status changes require actual evidence; local
candidate work is not integration, publication or production qualification.

## CURRENT paths and provenance

- Core: [quickstart](docs/user/quickstart.md) → [local pilot](docs/user/local-pilot.md).
- FSE2: [OfficialTest validation and lookup](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md).
  This is the current operational entry point: shipped runner, local bootstrap,
  Direct enrollment, in-memory role sessions and a resumable Admin provisioner,
  without direct SQL/store access or copied cookies. Requires a host .NET SDK,
  previously provisioned and authorized A1/S1 material, OfficialTest access and
  external organization configuration. It does not create external accounts or
  certificates and does not provide production custody.
- The [qualification observed on September 4](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md#qualification-observed-on-september-4-2026)
  identifies executed code, outcomes and limits of the live tests. Offline gates
  are in the current-spec reference; older profiles' qualifications do not transfer.
- The [previous validate-only path](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-officialtest.md)
  is HISTORICAL for first adoption. It preserves the provenance of
  `fse2-officialtest-validate-cda@1.0.1` and the shared provisioner reference;
  `1.0.0` remains immutable Published compatibility.
- [Administration](docs/user/administration.md),
  [Connector development](docs/connector-development/README.md) and
  [internal rules](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/internal/README.md).

The FSE2 path is now documented and executable with its external prerequisites:
the former “runner/sessions/local bootstrap not shipped” blocker is no longer CURRENT.
This does not make FHIR live-successful or make the pilot reproducible without
authorized access and material. The Core remains independent of the FSE2 pack's
presence and outcomes.

## Update rules

- Update this summary only when integrated status changes or an exact-head external
  gate is attested; README and guides summarize it with links.
- Keep authorized active objectives separate from integrated capabilities. Promote
  candidate evidence only within its proved scope; do not infer integration or release.
- Do not turn synthetic tests, a `202` response, `FOUND` or an aggregate count
  into a broader claim.
- Preserve and identify historical paths and profiles without rewriting attested
  evidence; do not copy capability matrices into guides.
- Do not version private operational endpoints, certificates, keys, P12 files,
  passwords, tokens, cookies, healthcare payloads or raw responses.

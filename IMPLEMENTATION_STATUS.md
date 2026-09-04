# Implementation dashboard

Updated: 2026-09-04
Baseline integrated through PR #66:
`8de271bfb3fa0f6953a0a8b6062245223713acf5`.
PR #66 changed documentation; the previously attested product/live qualifications
remain attached to their original baselines.

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
| B. Windows / Local Broker | **Integrated — historical M0/M1 and M3A live-lab evidence** | Windows Service, identity/process controls and local isolation; M3A includes Gateway and a synthetic upstream. Not the Direct pilot, an installer or a new exact-head qualification: see [historical references](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/history/README.md#windows--local-broker-evidence). |
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

## Active work — not yet qualified

The first active objective is an independently usable Windows Local Broker: an
identified, authorized .NET application uses an Installation-local key without
receiving it or requiring a Gateway. The target includes mutually authenticated IPC,
application/operation/context policy, state preservation across restart and supported
service update, DPAPI-bounded lifecycle/backup/restore, and a small executable SDK/sample
and guide. **This is implementation work, not a completed or newly qualified capability.**
Existing M0/M1 and M3A evidence does not close this new standalone acceptance path.

The local candidate now contains SCM/pipe-owner peer authentication, explicit
non-replacing data-key initialization, exact protection-context grants, and the
[sample/lifecycle guide](docs/user/local-broker.md). Focused Windows transport,
DPAPI/storage and simulated-SCM lifecycle tests pass; this is **not integrated**.
Real service installation/restart/update and ordinary-user service qualification
remain **PENDING**: the current host denied SCM creation access (Win32 5), and no
service was installed. The guide provides the single prepared elevated entrypoint.

Next comes the existing Broker → Gateway path: Installation identity renewal, revocation,
reconnection and interruption recovery using the synthetic service. Target-specific
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

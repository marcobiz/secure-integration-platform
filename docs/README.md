# Documentation

This index separates CURRENT procedures from technical references and history.
An adopter should not have to read the whole repository to find the supported path.

## CURRENT — entry points by responsibility

| Audience | Entry point | Authority |
|---|---|---|
| Adopter / operator | [User guide](user/README.md) | CURRENT procedures for quickstart, local pilot, FSE2, administration, troubleshooting and limits. |
| Connector developer | [Connector development](connector-development/README.md) | Minimum contract, server-owned bindings and first-call golden path. |
| Maintainer / internal agent | [Internal documentation](internal/README.md) | Status, scope, simplicity and review rules. |
| Architecture / security | [ARCHITECTURE.md](../ARCHITECTURE.md), [ADRs](adr/README.md), [security model](security/security-model.md), [threat model](security/threat-model.md) | Decisions and boundaries; not adoption runbooks. |
| APIs / contracts | [Gateway API](api/gateway-api.md), [OpenAPI](api/gateway-openapi.yaml), [Connector specification](connectors/connector-specification.md), [JSON schema](connectors/connector-definition.schema.json) | Executable contracts; not substitutes for missing operational sequences. |
| Status and traceability | [Capability summary](../IMPLEMENTATION_STATUS.md), [requirements-to-tests matrix](traceability/requirements-traceability.md) | One authoritative CURRENT summary; evidence mapping with the respective baselines. |

## Supported user paths

1. [Core quickstart](user/quickstart.md).
2. [Docker-first Core local pilot](user/local-pilot.md), without a host SDK or curl.
3. [Connector, binding, grant and audit administration](user/administration.md).
4. [Current optional FSE2 validation/status pilot](user/fse2-validation-status.md),
   with its own prerequisites, including a host .NET SDK.
5. [Troubleshooting without SQL or store access](user/troubleshooting.md).

[Historical Windows tests](history/README.md#windows--local-broker-evidence) cover the
installed-software → Local Broker boundary; they are not a second current quickstart.
The [old FSE2 validate-only pilot](user/fse2-officialtest.md) remains a historical
profile/provisioner reference, not the entry point for new adopters.

## CURRENT references

These are CURRENT references, not an adopter's reading order:

- `docs/adr/` for Accepted decisions;
- `docs/api/`, `docs/connectors/connector-specification.md` and
  `docs/connectors/connector-sdk.md` for public contracts;
- `docs/architecture/` except the explicitly historical M2 document;
- [FSE2 current-spec](connectors/healthcare/fse2/current-spec.md) for the technical
  matrix of 14 offline routes and frozen-specification limits, in the optional pack only;
- `docs/data/database-schema.md`, `docs/requirements/requirements.md` and
  `docs/testing/test-strategy.md` for maintainers and reviewers;
- `docs/implementation/0.1.0-alpha-scope.md`, `implementation-plan.md`, `backlog.md` and
  `definition-of-done.md` as internal planning, subordinate to the implementation dashboard.

Documents outside these groups are not CURRENT procedures. Before using them,
consult the [historical index](history/README.md); stale or target-state documents
remain non-authoritative until explicitly reclassified.

## HISTORICAL

The [historical index](history/README.md) preserves the initial classification of
53 milestone plans, reports, reviews and runbooks and identifies earlier FSE2 paths.
Paths remain stable but must not be used to reconstruct status or invent a procedure.

## Maintenance rules

- Each operational page declares its audience, status and supported outcome.
- One page owns each pilot's sequence; other pages link to it.
- [IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md) owns the capability summary:
  indices do not maintain parallel matrices.
- OpenAPI/schemas/migrations/tests remain executable authorities, but do not replace
  missing operational steps.
- Guides do not contain evidence SHAs, PR diaries, laboratory details, P12 files,
  tokens, real identifiers, private endpoints or raw responses.
- A problem repeated across two Connectors belongs to the shared workflow; it is
  not a reason to duplicate vertical runbooks.

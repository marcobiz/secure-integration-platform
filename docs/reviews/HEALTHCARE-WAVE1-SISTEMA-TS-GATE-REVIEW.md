# Healthcare Wave 1 - Sistema TS gate review

Review date: 2026-08-08

Baseline: `m6-auth-foundation-baseline-20260808` / `6e1a7c626e0e24d0a385c611fc03faef51598889`

Branch: `wave1/sistema-ts-eprescription`

## Verdict

**NO-GO for `SistemaTSEPrescriptionConnector` implementation.**

The official-current source freeze is complete and the national SAC business contracts
are identifiable. The hard stop is caused by a missing generic primitive, not by a missing
WSDL: the current SAC ID-session must be sent in a fixed HTTP `Authorization2F` bearer
header, while M6 supports only a session element in the SOAP Header.

## Requested output

| Output | Result |
|---|---|
| Official registry | Complete; public links, versions, dates and SHA-256 digests recorded |
| Confirmed operations | retrieve/take-in-charge, release, dispense/close, suspend/revoke suspension, cancel/correct dispensation |
| Unconfirmed/deferred operations | deferred/offline, reports, history, prescription-side and regional operations |
| SAC routing model | documented as `NationalSac` vs server-owned `RegionalReference(profileId)`; no code added |
| SOAP contracts | current official identities and digests frozen; no generated code or invented XML |
| MFA/session model | official `create`, `revoke`, `checkToken` and `Authorization2F` placement recorded |
| Business workflow | authoritative state retained upstream; only future correlation/idempotency/reconciliation metadata allowed |
| RBE | current official family confirmed separately; not implemented or semantically merged |
| Synthetic server | not implemented because the required auth primitive is absent |
| Security tests | zero connector-specific tests added; no connector execution surface was introduced |
| Product test total | 0 new product tests; existing M6 totals are not counted as Sistema TS evidence |
| Live/accreditation evidence | none; no external call or onboarding claim |
| Release decision | NO-GO until a separately authorized generic primitive and its security gate exist |

## Implemented confirmed scope

`IMPLEMENTED_CONFIRMED_SCOPE` for this branch means only:

- public official source registry and immutable digest freeze;
- confirmed/unconfirmed operation inventory;
- provider-neutral SAC/SAR routing decision;
- exact identification of the generic primitive gap;
- public-safe provisioning and accreditation blockers.

It does not mean a connector, DTO, serializer, synthetic server, Published definition or
external conformance implementation exists.

## Blockers

### BLOCKED_BY_GENERIC_PRIMITIVE

A narrow, server-owned opaque-session HTTP-header placement capability is required. It
must be implemented and qualified in Core under separate authorization before this wave
can resume. A connector-local raw header injection workaround is prohibited.

### BLOCKED_BY_ACCREDITATION

Test and production provisioning, authorized identities, grants and live conformance have
not been performed. These remain separate even after the product code can be implemented.

## Gate evidence

Documentation validation, secret scan and `git diff --check` are the applicable local
gate for this documentation-only hard-stop branch. On 2026-08-08:

- `./eng/validate-docs.ps1`: PASS;
- `./eng/scan-secrets.ps1`: PASS;
- `git diff --check` for the owned paths and the complete worktree: PASS;
- product/connector test total: 0, because no execution surface was introduced;
- SBOM/build/test: not rerun for a documentation-only hard stop and not claimed.

CI is reported in the PR/final handoff. None of these results can upgrade the product
verdict to GO.

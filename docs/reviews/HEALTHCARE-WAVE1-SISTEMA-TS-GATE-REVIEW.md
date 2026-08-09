# Healthcare Wave 1 - Sistema TS gate review

Review date: 2026-08-09

Resumed starting HEAD: `12d98d175d163bc4e73c9510b867b5c68af337c0`

Foundation merge-base: `705e9d4bd203ca7b902ad0aeedc9d4402f9f4452`

Branch: `wave1/sistema-ts-eprescription`

## Verdict

**NO-GO for `SistemaTSEPrescriptionConnector` implementation.**

The official-current source freeze remains complete and the national SAC business contracts
are identifiable. The Wave 1 Foundation closes the earlier fixed `Authorization2F` placement
gap, but the complete profile still cannot be composed through the qualified generic APIs.

Official SSN MFA requires server-owned `RICETTA-DEM` and `EROGATORE` values in `create`.
Production acknowledges the request and delivers the ID-session out of band. The M6 lifecycle
always sends an empty login value map, accepts only scalar login-response children and can cache
only a session returned by a SOAP completion response. It cannot check and promote an opaque
artifact supplied through the transport-neutral interaction. The final opaque-session dispatcher
also cannot add the fixed SOAP 1.1 `SOAPAction` required by the business WSDLs.

## Requested output

| Output | Result |
|---|---|
| Official registry | Complete; 2026-08-09 portal recheck and 7/7 fresh digest matches |
| Confirmed operations | retrieve/take-in-charge, release, dispense/close, suspend/revoke suspension, cancel/correct dispensation |
| Unconfirmed/deferred operations | deferred/offline, reports, history, prescription-side and regional operations |
| SAC routing model | documented as `NationalSac` vs server-owned `RegionalReference(profileId)`; no code added |
| SOAP contracts | current official identities and digests frozen; no generated code or invented XML |
| MFA/session model | official `create`, out-of-band delivery, `checkToken`, `revoke` and `Authorization2F` recorded; current Core composition gap demonstrated |
| Business workflow | authoritative state retained upstream; only future correlation/idempotency/reconciliation metadata allowed |
| RBE | current official family confirmed separately; not implemented or semantically merged |
| Synthetic server | not implemented because a runnable official session/SOAP composition is absent |
| Security tests | zero connector-specific tests added; no connector execution surface was introduced |
| Product test total | 0 new product tests; existing M6 totals are not counted as Sistema TS evidence |
| Live/accreditation evidence | none; no external call or onboarding claim |
| Release decision | BLOCKED_BY_GENERIC_PRIMITIVE until typed login/out-of-band promotion and SOAP 1.1 one-shot composition are separately authorized and qualified |

## Implemented confirmed scope

`IMPLEMENTED_CONFIRMED_SCOPE` for this branch means only:

- public official source registry and immutable digest freeze;
- lightweight current-source recheck with seven matching fresh artifact digests;
- confirmed/unconfirmed operation inventory;
- provider-neutral SAC/SAR routing decision;
- proof that the earlier HTTP placement gap is closed and exact identification of the remaining
  generic composition gaps;
- public-safe provisioning and accreditation blockers.

It does not mean a connector, DTO, serializer, synthetic server, Published definition or
external conformance implementation exists.

## Blockers

### BLOCKED_BY_GENERIC_PRIMITIVE

The required generic work is broader than the now-integrated fixed session-header placement:

- server-owned typed login values and bounded nested response handling;
- transport-neutral validation and promotion of an out-of-band opaque session into the existing
  generation/revision-bound cache;
- fixed SOAP 1.1 HTTP policy composed with opaque-session projection in the same one-shot
  restricted dispatch.

It must be implemented and qualified in Core under separate authorization before this wave can
resume. A Healthcare cache, raw-header transport wrapper or simplified synthetic contract is
prohibited.

### BLOCKED_BY_ACCREDITATION

Test and production provisioning, authorized identities, grants and live conformance have
not been performed. These remain separate even after the product code can be implemented.

## Gate evidence

Documentation validation, secret scan and `git diff --check` are the applicable local
gate for this documentation-only hard-stop update. On 2026-08-09:

- `./eng/validate-docs.ps1`: PASS;
- `./eng/scan-secrets.ps1`: PASS;
- `git diff --check` for the owned paths and the complete worktree: PASS;
- product/connector test total: 0, because no execution surface was introduced;
- SBOM/build/test: not rerun for a documentation-only hard stop and not claimed.

CI is reported in the PR/final handoff. None of these results can upgrade the product
verdict to GO.

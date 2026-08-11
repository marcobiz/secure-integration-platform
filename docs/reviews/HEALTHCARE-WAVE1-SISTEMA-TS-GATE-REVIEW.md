# Healthcare Wave 1 - Sistema TS gate review

Review date: 2026-08-10

Original PR #15 HEAD: `1e4d2dca93c2bfa926c68eaa4a55caf1252981f5`

Qualified baseline: `3f8667b7cb9678d6efb670f1c192cc227228ab1f`

Post-rebase documentation HEAD before this audit: `a89849a7a6f5c0f841382e8573d6513636bc519a`

Branch: `wave1/sistema-ts-eprescription`

## Verdict

**NO-GO for `SistemaTSEPrescriptionConnector` implementation.**

The official-current source freeze remains complete and the national SAC business contracts
are identifiable. Exact baseline `3f8667b` closes the previously recorded generic lifecycle and
dispatch gaps: compiled typed XML, authenticated external admission, atomic promotion into the
shared cache, composed SOAP and the exact-authority external strategy bridge are present.

The production vertical is still inexpressible through that frozen surface. The module loader
registers only execution strategies while the host constructs its adapter registry from
Gateway.Api synthetic instances. More importantly, the compiled request context has no
provider-resolved source for the mandatory STS `userId`, encrypted identifier, tax identifier
and organization codes. The official manual requires those values for the
`RICETTA-DEM`/`EROGATORE` create and checkToken messages. Caller input, hardcoding, direct provider
access or a test-host DI replacement would violate or misrepresent server-side custody.

## Requested output

| Output | Result |
|---|---|
| Official registry | Complete; 2026-08-09 portal recheck and 7/7 fresh digest matches |
| Confirmed operations | retrieve/take-in-charge, release, dispense/close, suspend/revoke suspension, cancel/correct dispensation |
| Unconfirmed/deferred operations | deferred/offline, reports, history, prescription-side and regional operations |
| SAC routing model | documented as `NationalSac` vs server-owned `RegionalReference(profileId)`; no code added |
| SOAP contracts | current official identities and digests frozen; no generated code or invented XML |
| MFA/session model | official `create`, out-of-band delivery, `checkToken`, `revoke` and `Authorization2F` recorded; generic lifecycle now available, vertical registration/provider-input hard stop demonstrated |
| Business workflow | authoritative state retained upstream; only future correlation/idempotency/reconciliation metadata allowed |
| RBE | current official family confirmed separately; not implemented or semantically merged |
| Synthetic server | not implemented because a runnable official session/SOAP composition is absent |
| Security tests | zero connector-specific tests added; no connector execution surface was introduced |
| Product test total | 0 new product tests; existing M6 totals are not counted as Sistema TS evidence |
| Live/accreditation evidence | none; no external call or onboarding claim |
| Release decision | NOT_READY; a separately authorized Core change is required under freeze-policy criterion C before a truthful production connector can be implemented |

## Implemented confirmed scope

`IMPLEMENTED_CONFIRMED_SCOPE` for this branch means only:

- public official source registry and immutable digest freeze;
- lightweight current-source recheck with seven matching fresh artifact digests;
- confirmed/unconfirmed operation inventory;
- provider-neutral SAC/SAR routing decision;
- proof that lifecycle/dispatch prerequisites are closed and exact identification of the remaining
  production module-registration and provider-resolved-input gaps;
- public-safe provisioning and accreditation blockers.

It does not mean a connector, DTO, serializer, synthetic server, Published definition or
external conformance implementation exists.

## Blockers

### FROZEN-SURFACE HARD STOP

The remaining problem is narrower than the remediated generic runtime:

- `ConnectorExecutionModuleLoader` registers an external type only as
  `IConnectorExecutionStrategy`; `Program` builds `TypedSessionHandshakeAdapterRegistry` from
  three synthetic Gateway.Api adapters and never consumes module-owned adapter implementations;
- `TypedSessionHandshakeRequestContext` and `ExternalSessionValidationRequestContext` provide
  authenticated Core identity, profile and checksum plus the opaque candidate, but no approved
  binding-scoped values for the required STS identity fields;
- Basic resolution is internal to the HTTP authenticator and cannot legitimately be repurposed
  by Healthcare as XML field access.

Continuing would require Gateway.Api-to-Healthcare coupling, test-only replacement, credential
hardcoding/caller trust or direct provider access. Each option bypasses an already-qualified Core
boundary, satisfying freeze-policy criterion C for a separately reviewed Core change. A Healthcare
cache, raw-header transport wrapper, generic request map or simplified synthetic contract remains
prohibited.

### BLOCKED_BY_ACCREDITATION

Test and production provisioning, authorized identities, grants and live conformance have
not been performed. These remain separate even after the product code can be implemented.

## Gate evidence

Documentation validation, secret scan and `git diff --check` are the applicable local
gate for this documentation-only hard-stop update. On 2026-08-10:

- `./eng/validate-docs.ps1`: PASS;
- `./eng/scan-secrets.ps1`: PASS;
- `git diff --check` for the owned paths and the complete worktree: PASS;
- product/connector test total: 0, because no execution surface was introduced;
- SBOM/build/test: not rerun for a documentation-only hard stop and not claimed.

CI is reported in the PR/final handoff. None of these results can upgrade the product
verdict to GO.

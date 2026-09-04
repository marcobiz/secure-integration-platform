# Historical index

**Audience:** maintainers, auditors and reviewers.
**Status:** HISTORICAL index.

This index preserves the initial classification of 53 completed plans, gates, reviews,
reports and milestone runbooks, and identifies subsequently superseded paths.
Files retain their original paths to preserve links and evidence provenance.
They are not authorities on current status and must not supply missing adopter steps.

The English translation changes presentation, not historical outcomes, dates or
attested baselines. Protocol values, identifiers, paths and recorded outputs retain
their original spelling; attested commits and tags remain unchanged.

## Initial classification of 53 documents

| Group | Count | Paths classified HISTORICAL |
|---|---:|---|
| Milestone architecture | 1 | `docs/architecture/m2-gateway-architecture.md` |
| Earlier Connector plan | 1 | `docs/connectors/healthcare/M6-IMPLEMENTATION-PLAN.md` |
| Completed implementation plans | 19 | All files in `docs/implementation/` except `0.1.0-alpha-scope.md`, `implementation-plan.md`, `backlog.md`, `definition-of-done.md`. |
| Milestone runbooks/laboratories | 5 | `M0-M1-LIVE-MATRIX-RUNBOOK.md`, `M2-GATEWAY-RUNBOOK.md`, `M3-E2E-RUNBOOK.md`, `M3A-SPLIT-HOST-CODEX-VM.md`, `M3A-SPLIT-HOST-RUNBOOK.md` under `docs/operations/`. |
| Reviews | 16 | All versioned files under `docs/reviews/` at the baseline. |
| Test/evidence reports | 9 | All files under `docs/testing/` except `test-strategy.md`; includes the pre-qualification FSE2 report, now superseded by the CURRENT dashboard. |
| Phase traceability | 1 | `docs/traceability/auth-phase2-wave1-oauth.md` |
| M0/M1 harness | 1 | `tools/live-matrix/README.md` |
| **Total** | **53** | No files moved in this tranche. |

`docs/operations/M4-QUICKSTART.md` is a duplicated, non-canonical path: retain it as
a milestone reference, but use only [docs/user/local-pilot.md](../user/local-pilot.md)
for adoption. Stale/target-state documents not included in the historical count
do not become CURRENT by exclusion: the CURRENT list is explicitly defined in
[docs/README.md](../README.md).

## Windows / Local Broker evidence

- [M0/M1 requirement-test-evidence matrix](../reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md)
  and [Windows runbook](../operations/M0-M1-LIVE-MATRIX-RUNBOOK.md): real SCM service
  with a distinct identity, authorized/unauthorized processes, pipe/storage ACLs,
  DPAPI, restart and reboot. The [existing harness](../../tools/live-matrix/README.md)
  requires a dedicated Windows VM, elevation and an SDK; it is not the Docker-first Core pilot.
- [M3A split-host gate](../operations/M3A-SPLIT-HOST-RUNBOOK.md): Windows legacy simulator
  → Named Pipe → Local Broker → Gateway → synthetic HTTPS/mTLS upstream.
  The [M3A product gate](../reviews/M3A-PRODUCT-GATE-20260805.md) and
  [FR-008 traceability](../traceability/requirements-traceability.md#functional-requirements)
  identify the historical PASS-LIVE run and its scope; the runbook preserves that
  milestone's baseline, Hyper-V prerequisites and handoff.

These tests support the installed-software boundary on attested baselines, not a new
demo or CURRENT qualification. Do not run laboratory commands as an ordinary installation.
MSI, C ABI/COM adapters and production are not qualified; Administrator and SYSTEM
remain privileged residual threats.

## Earlier FSE2 paths

The current entry point is [OfficialTest validation and lookup](../user/fse2-validation-status.md),
with [capabilities summarized here](../../IMPLEMENTATION_STATUS.md#product-status).

- [Validate-only pilot](../user/fse2-officialtest.md): historical for first adoption,
  specific to `fse2-officialtest-validate-cda@1.0.1`. The old runner's limits do not
  describe the current-spec runner; the shared provisioner reference remains useful.
- [Wave 1 spec freeze](../implementation/FSE2-WAVE1-SPEC-FREEZE.md): historical
  11-operation inventory. It does not replace the [14 current-spec routes](../connectors/healthcare/fse2/current-spec.md).
- [Historical profile matrix at the PR #65 baseline](https://github.com/marcobiz/secure-integration-platform/blob/18df69d6eaa34ed636b101bce1d188cd65226e1a/docs/connectors/healthcare/fse2/README.md#historical-profile-capability-matrix):
  also preserves the September 3 trace/`NOT_FOUND` test, distinct from September 4
  workflow `FOUND`. Qualification never transfers automatically between profiles.

## Correct use of history

- Use these files for provenance, decisions on past baselines or audit.
- Do not reconstruct installation, onboarding or invocation procedures from them.
- Do not update an immutable report to correct current status; update the dashboard,
  CURRENT guides and traceability.
- Do not copy SHAs, gate counts or laboratory details into user guides unless they
  support a current, bounded decision.

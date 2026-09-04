# M3 — Production-like vertical slice implementation plan

**Baseline:** `m2-gateway-baseline-2026-08-04`
**Working branch:** `m3/production-like-vertical-slice`
**Rule:** no M4 functionality.

## Buildable increments

1. **Documentation and contracts:** architecture, sequence, runbook, evidence schema and
   traceability for the 7 positive and 15 negative scenarios.
2. **Broker Installation client:** non-exportable CNG ECDSA P-256 key,
   ClientAuth certificate, enrollment/PoP, DPAPI CurrentUser persistence of non-secret
   configuration only and signed BGW1 invocation.
3. **M3A fixture:** synthetic HTTPS Vault, HTTPS/mTLS vendor mock, per-run CA/certificates,
   PostgreSQL provisioning and server-side operations/grants.
4. **Deterministic orchestrator:** installs the real Windows Service, starts containers,
   runs the legacy simulator and positive/negative matrix, no reboot required by M3,
   redacts and validates evidence.
5. **M3A CI:** dedicated job with explicit labels; no in-process replacement of
   the Broker or containers.
6. **M3B Azure:** dev Bicep, OIDC, Managed Identity, Key Vault, synthetic secrets/certificates,
   exact-image deployment and smoke against the mTLS mock.
7. **Gate:** critical review, CI on the exact commit, evidence hash, documents/status and
   annotated tag only after M3A+M3B PASS.

Every increment must leave `eng/build.ps1`, `eng/test.ps1`,
`eng/validate-docs.ps1`, secret scan and `git diff --check` green.

## Scenarios and observation points

| ID | Scenario | Main assertion | No side effects |
|---|---|---|---|
| M3-P01 | enrollment | code consumed, valid P-256 PoP | code cannot be reused |
| M3-P02 | invoke via Broker | real pipe and service | legacy has no vendor secret |
| M3-P03 | server-side tenant | audit/DB use the authenticated Tenant | client tenant ignored/rejected |
| M3-P04 | valid grant | exactly one operation granted | other operations denied |
| M3-P05 | API key from Vault | mock receives the expected canary | Broker/logs do not receive it |
| M3-P06 | vendor mTLS | mock sees the expected certificate | wrong certificate denied |
| M3-P07 | sanitized response | schema/bounds respected | no headers/provider details |
| M3-N01..N15 | required negatives | expected stable code | Vault/egress not reached where applicable |

The complete matrix with test names and evidence paths is updated only with tests
that actually exist; unexecuted checks remain `PENDING`, never an inferred `PASS`.

## Commit separation

- `M3 implementation`: product code, infrastructure and tests;
- `M3 synthetic test configuration`: Compose, generators and public non-secret values;
- `M3 redacted evidence`: approved-run manifest/report/hash only;
- `M3 closure`: status, traceability, review and tag.

Raw evidence, keys, private certificates, activation codes, OIDC tokens, dumps, EVTX and
unredacted logs are prohibited in Git and covered by `.gitignore`/secret scan.

## Operational dependencies that cannot be substituted

- split-host lab with Linux Docker on the HOST and a single reviewed script run
  manually from the VM administrative console;
- GitHub Environment `azure-dev` with OIDC federation and reviewer/protection rules;
- authorized Azure dev subscription/resource group;
- public DNS or an mTLS-compatible dev mock endpoint.

If a dependency is missing, implementation and isolated tests can advance, but the M3 gate
remains `NO-GO`; no baseline tag is created.

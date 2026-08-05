# Repository agent guide

This file applies to the entire repository. More specific `AGENTS.md` files may refine these rules for a subtree, but must not weaken the security or release controls defined here.

## Start here

Before changing code:

1. Read `IMPLEMENTATION_STATUS.md` for the current milestone and approved baselines.
2. Read the relevant ADRs in `docs/adr`, the implementation plan in `docs/implementation`, and `docs/traceability/requirements-traceability.md`.
3. Inspect the current branch, HEAD, upstream and worktree. Preserve unrelated user changes.
4. Confirm the requested scope. Do not start a later milestone, cloud qualification, healthcare connector or commercial adapter unless explicitly authorized.
5. Treat an attested commit or tag as immutable. Never rewrite its history.

## Architectural boundaries

- The open-source Core comprises the Local Broker, Gateway Core, PostgreSQL persistence, Connector Runtime/SDK, provider abstractions, Synthetic Provider, .NET SDK, CLI, Admin UI, local Compose configuration, documentation and tests.
- Core projects must not depend directly or transitively on Azure, AWS, HashiCorp, deployment packs, vertical connector packs or commercial adapters.
- Optional packs may depend on provider-neutral Core contracts; dependency direction must never be reversed.
- Keep provider capabilities separate: secret retrieval, certificate use, signing/key operations, MAC operations, health and capability discovery are distinct contracts.
- Connector definitions contain logical provider, endpoint, secret and certificate bindings. Concrete endpoints and credential material are resolved only on the server.
- The Admin UI communicates only with authenticated same-origin Admin APIs. It never accesses PostgreSQL, providers, the Broker or the host filesystem directly.

Architecture tests and the Core export are release controls, not advisory checks. Update them when an intentional boundary changes.

## Security invariants

- There is no direct or indirect `GetSecret` capability for legacy applications, the Broker or the Admin UI.
- Vendor credentials, private keys, PFX material, connection strings and raw external responses stay server-side.
- Tenant and Installation identity are derived from authenticated server-side state. Never trust a client-supplied tenant identifier as authority.
- Grants are deny-by-default. Connector/operation, endpoint and credential references cannot be selected arbitrarily by clients.
- Published Connector definitions are immutable. Publication requires a valid checksum-specific four-eyes approval by a distinct authorized principal.
- Authorization is enforced server-side even when the UI hides unauthorized actions.
- Keep replay protection, TLS validation, restricted egress, SSRF/DNS-rebinding defenses, CSRF, secure cookies, CSP and metadata-only audit fail-closed.
- Logs, Problem Details, audit records and evidence must not contain secrets, tokens, cookies, authorization headers, plaintext sensitive payloads or stack traces.
- Local Administrator and SYSTEM are residual privileged threats; do not claim they are fully mitigated.

For security-sensitive changes, add both positive and negative tests and update `docs/security/threat-model.md` when the threat surface changes.

## Secrets, evidence and generated artefacts

- Never commit real or reusable secrets, activation codes, tokens, credentials, private certificates, `.env` files, DPAPI blobs, EVTX files, dumps or raw evidence.
- Use only synthetic, per-test material. Do not print bootstrap documents, activation codes or credentials merely because they are synthetic.
- Store gate evidence outside the repository, normally under `C:\SecureEvidence\<run-id>`, with a redacted manifest and SHA-256 sidecar.
- Keep `.artifacts`, build output, browser traces, screenshots containing transient values and exported evidence ignored.
- Run `./eng/scan-secrets.ps1` before publication. A scanner exception requires a narrow documented synthetic/test allowlist, never a broad bypass.
- The definitive open-source license is pending. Do not add a `LICENSE` file until legal/business approval is explicit; see `docs/legal/OPEN-SOURCE-LICENSE-DECISION.md`.

## Implementation conventions

### .NET and PostgreSQL

- Use the SDK pinned by `global.json`, central package versions and locked restores.
- Keep Domain and Application provider-neutral; infrastructure and pack-specific composition belong at the edges.
- Nullable analysis, analyzers and warnings-as-errors must remain enabled.
- Database changes are additive migrations. Preserve idempotency, migration checksums, separate migration/runtime/admin roles and forced RLS where applicable.
- Runtime credentials must not gain migration or administrative privileges.

### Admin Web

- TypeScript remains strict. Use the pinned Node/npm versions and `package-lock.json`.
- Application text belongs in i18n resources; support English and Italian.
- Do not add CDNs, external fonts, analytics, telemetry, service workers, unsafe HTML, `eval`, or sensitive browser storage.
- Change OpenAPI first, regenerate types, and ensure `npm run check:api` is clean.
- Mutations require authentication, CSRF, RBAC, tenant scope, audit and concurrency handling where applicable.
- Maintain keyboard usability and WCAG 2.1 AA-oriented checks; axe critical/serious findings block the gate.

### PowerShell and laboratory tooling

- Scripts used by Windows hosts or VMs must parse under Windows PowerShell 5.1 unless their scope explicitly says otherwise.
- Prefer idempotent, fail-closed phases with stable language-independent error codes.
- Never weaken TLS, ACL, firewall, identity or cleanup checks to make a laboratory run pass.
- Do not simulate a Windows Service, service identity or live path when the acceptance criterion requires the real resource.
- Hyper-V checkpoint, firewall, service and scheduled-task operations require exact ownership and target verification. Do not alter unrelated VM resources or checkpoints.

## Canonical verification

Run checks proportional to the change. For a normal product change, the expected local sequence is:

```powershell
./eng/build.ps1
./eng/test.ps1
./eng/validate-docs.ps1
./eng/scan-secrets.ps1
./eng/generate-sbom.ps1
dotnet list BrokerGateway.slnx package --vulnerable --include-transitive
git diff --check
```

For Admin Web changes:

```powershell
Push-Location src/Admin/Admin.Web
npm ci --ignore-scripts
npm run lint
npm run check:api
npm test
npm run build
npm run test:e2e
npm audit --audit-level=high
Pop-Location
```

Also run the relevant PostgreSQL 18, container, quick-start, architecture-boundary and deterministic M3/M4 regression jobs when their surfaces are affected. Do not use a total test count as the sole evidence: map requirements to named tests and record anything not automated.

Documentation-only changes require at minimum documentation validation, secret scan and `git diff --check`. They do not justify skipping CI on the final PR HEAD.

## Git and review workflow

- Use focused, reviewable commits and conventional messages such as `feat(scope):`, `fix(scope):`, `test(scope):`, `docs(scope):` and `chore(scope):`.
- Do not use force push, history rewriting, squash, rebase, amend or destructive reset on attested work.
- Do not merge a pull request automatically unless the user explicitly requests the merge after the gate and review pass.
- A failed gate remains visible. Fix the cause, add a regression test when appropriate and rerun the entire affected gate on the new commit.
- Keep implementation, synthetic test configuration and redacted evidence conceptually separate. Raw artefacts stay outside Git.
- Update ADRs only for a real architectural deviation or durable decision. Update status, roadmap and traceability when a milestone or requirement state actually changes.

## Definition of done

A change is complete only when:

- requested behavior and negative cases are implemented;
- the repository builds and the relevant named tests pass;
- security and provider boundaries remain enforced;
- migrations, API contracts and generated clients are synchronized;
- documentation and traceability reflect the actual result without overstating live evidence;
- scans and cleanup checks pass;
- the worktree is clean and local/upstream SHAs are reported when publication was requested;
- deferred work, residual risk and blockers are stated explicitly.

When reporting results, distinguish product behavior from laboratory automation, deterministic evidence from live evidence, and a private-preview GO from public-release readiness.

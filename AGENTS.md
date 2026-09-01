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

### Connector delivery and operationalization

- Treat first-use operationalization as connector functionality, not as laboratory setup. Before calling a connector nearly ready, prove the supported path from an empty deployment through environment/provider bootstrap, definition validation, binding/grant, approval/publication and one bounded invocation.
- Document the exact Admin API order and role hand-offs. Security controls such as server-owned bindings, least privilege and four-eyes approval remain mandatory, but operators must not need repository knowledge, manual SQL, direct store access or invented sequencing to satisfy them.
- Prefer one idempotent `plan -> apply -> verify` provisioner or an equivalent guided Admin workflow. It must report the current state, the missing prerequisite, the authorized next action and whether retry is safe.
- Include a clean-state "time to first successful call" acceptance test for each new connector. Test the real provisioning path and effective runtime endpoint, not only schema, catalog or synthetic runtime pieces in isolation.
- Keep qualification proportional: close blockers observed on the connector golden path, reuse existing Core/provider capabilities, and do not add a generic abstraction, exhaustive matrix or enterprise control merely in anticipation of another connector.
- When the same onboarding problem appears in a second connector, address the shared product workflow explicitly instead of duplicating connector-specific runbooks or one-off automation.

### Product delivery, adoption and complexity governance

- Optimize for software that is solid, functional, easy to adopt and inexpensive to operate. Security and usability are joint acceptance criteria: a control is not complete if the normal supported path requires avoidable waiting, repeated login, repository knowledge, manual database work or routine support intervention.
- Treat complexity as a recurring product cost. Choose the simplest design that closes an observed requirement or credible threat. Do not add a generic abstraction, enterprise control, laboratory component or exhaustive matrix for hypothetical future value.
- Freeze scope, user-visible outcomes and the negative-test set before implementation. A review finding may expand blocking scope only when it demonstrates a concrete security exposure, correctness regression or failure of an agreed acceptance criterion; additional hardening belongs in a prioritized backlog.
- Prefer black-box golden-path outcomes and small focused negative tests over proving every internal mechanism in one laboratory. Product instrumentation added for verification must also have clear operational value, remain bounded and privacy-safe, and be simpler than a test-only alternative. Never add production code solely to make evidence more elaborate.
- Estimate product, test/laboratory and evidence effort separately. If test plus evidence work is likely to exceed the implementation effort, or the same slice reaches two consecutive remediation/re-review cycles, stop and perform an explicit scope-and-complexity checkpoint with the project owner before adding more machinery.
- Do not keep work merely because of sunk cost, and do not delete useful work merely to appear simpler. Compare the marginal cost to finish, long-term maintenance cost and reuse value; preserve a safe near-complete component when finishing it is cheaper and useful, otherwise remove evidence-only machinery that creates continuing burden.
- Configure rate limits and similar safeguards from measured capacity, credible abuse and normal burst behavior, with substantial headroom for legitimate use. They are availability controls, not anomaly detectors; ordinary same-NAT, retry-safe or multi-tenant workflows must not be treated as attacks.
- Keep evidence minimal and truthful. Record only what supports the agreed decision, decompose independent properties into focused gates, and do not overclaim internal behavior from constructed counters or synthetic state.
- At closure, freeze the final review contract. P0/P1 findings remain blocking. A P2 blocks only when it invalidates an agreed acceptance criterion or demonstrates a concrete security, correctness, adoption or operability risk; other P2/P3 improvements are documented follow-ups and must not restart an open-ended remediation cycle.

### Minimal and efficient engineering style

Apply these high-level principles inspired by the minimalist engineering approach associated with antirez; do not imitate a person's prose or treat personal style as authority:

- Build the smallest coherent system that solves the demonstrated problem. Prefer direct control flow, explicit state and ordinary data structures over frameworks, indirection, reflection or generic machinery when simple typed code is sufficient.
- Add an abstraction only when it removes measured duplication or complexity in real current use cases. A possible future connector, provider or deployment is not by itself sufficient justification.
- Keep the number of layers, interfaces, services, configuration switches and dependencies low. Every new dependency or long-lived component must provide a clear operational or maintenance benefit greater than its ongoing cost.
- Optimize architecture and data representation before micro-optimizing syntax. Measure relevant hot paths, allocations, database round trips, network calls and startup time; preserve simple code unless evidence shows that optimization is needed.
- Make code locally understandable: use precise names, small cohesive units and explicit invariants. Comments explain non-obvious reasons, trade-offs and safety boundaries, not what the code already says.
- Prefer deterministic, idempotent operations with bounded resource use. Fail closed at genuine trust boundaries, while keeping ordinary successful workflows short, observable and free of unnecessary ceremony.
- Remove dead paths, obsolete compatibility code and evidence-only production machinery once they have no supported consumer. Do not preserve complexity merely because it already exists.
- Test externally meaningful behavior and critical invariants with the smallest reliable fixture. Avoid elaborate harnesses that duplicate the product or make the test harder to understand than the implementation.
- Treat operational simplicity as part of code quality: a concise implementation is not successful if deployment, onboarding, recovery or diagnosis still requires fragile sequencing or specialist intervention.

### Prevent multiplicative design complexity

- Distinguish conscious, replaceable technical debt from a design error that forces compensating behavior elsewhere. A temporary local compromise must have a clear boundary and replacement path; it must not silently become a system invariant.
- Apply the compensation stop rule: when a second mechanism, exception, workflow step or test apparatus is needed primarily to compensate for an earlier design choice, stop implementation and re-examine the original choice with the project owner before adding a third layer.
- Fix the earliest authoritative cause. Prefer removing or simplifying the assumption that creates friction over adding coordination, caching, retry, role choreography, configuration, documentation or operator procedure around its consequences.
- Never normalize a product defect as operator knowledge. Do not turn a workaround into a runbook, UI instruction, required sequencing rule or support playbook unless the underlying constraint is external, unavoidable and explicitly documented as such.
- Treat repeated friction across two connectors, tenants or onboarding runs as evidence of a shared workflow problem. Solve it once at the narrowest shared product boundary rather than adding connector-specific exceptions.
- Keep laboratories diagnostic, not architectural. A test or evidence requirement must not create production concepts, APIs, state or instrumentation without independent operational value. If the laboratory needs more machinery than the behavior under test, simplify or decompose the gate.
- At every complexity checkpoint ask what components, states and procedures would disappear if the earliest disputed assumption were changed. Evaluate that simpler alternative before accepting another additive remediation.
- Track necessary exceptions with an owner, reason and removal condition. An exception without a credible removal condition is architecture and must be reviewed as architecture, not hidden as temporary debt.

### Goal-oriented execution and handoff minimization

- Give one capable owner end-to-end responsibility for a clearly scoped diagnostic, integration or golden-path objective. Do not force a writer, reviewer and host handoff after every evidence-driven iteration when the work remains inside the same authorized scope.
- Define authorization by outcome and material boundaries, not by arbitrary attempt counts. Permit as many purposeful iterations as reasonably necessary to reach the agreed result, while respecting external rate limits and recording a compact decision ledger.
- An iteration is purposeful when it tests a distinct hypothesis, validates a concrete correction or confirms a potentially transient result. Automatic retries and unexplained identical repetitions remain prohibited.
- Ask again only when the work crosses a genuinely new authority boundary: destructive or irreversible action, access to new sensitive material, external registration or third-party coordination, merge, release, or a material expansion of scope. Do not repeatedly request equivalent permission for ordinary reversible steps already covered by the workflow authorization.
- Keep implementation review and release gates at meaningful convergence points. Do not interrupt a bounded diagnostic loop for a full writer/reviewer cycle after each local hypothesis; review the resulting minimal product change before publication or merge.
- Prefer a single accountable execution log over multiple overlapping evidence packages. Record hypothesis, change, result and next decision; preserve raw sensitive material only for the minimum in-memory lifetime required and retain only bounded redacted evidence.
- Stop autonomous iteration when the objective succeeds, a concrete external blocker is proven, continued attempts would be random rather than evidence-driven, or a material authorization boundary is reached. Do not stop merely because a preselected numeric budget was exhausted.
- Parallelize work when tasks are genuinely independent, have disjoint outputs and do not require their changes to be merged. Good candidates include read-only inventories, capability mapping, documentation audits, external research and isolated verification.
- Do not assign multiple development agents to overlapping product surfaces merely to increase apparent throughput. If their branches would touch shared contracts, migrations, generated clients, central documentation or the same runtime path, prefer one end-to-end writer because merge, requalification and semantic-integration cost can exceed the development time saved.
- Before parallel delegation, define each task's ownership, allowed files or external report path, dependencies and integration plan. When results must converge, parallel agents should normally return findings or evidence to one designated writer instead of producing competing patches.
- Use sequential execution when correctness depends on the previous task's result, when a shared test environment would create interference, or when resolving conflicts would require redoing qualification. Optimize total lead time, not the number of agents active.

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
- for connector work, a clean deployment can reach a Published and invocable configuration through documented, supported interfaces with no manual database/store intervention;
- the worktree is clean and local/upstream SHAs are reported when publication was requested;
- deferred work, residual risk and blockers are stated explicitly.

When reporting results, distinguish product behavior from laboratory automation, deterministic evidence from live evidence, and a private-preview GO from public-release readiness.

# Adoption and complexity governance

**Audience:** product owners, maintainers, reviewers and agents.
**Status:** CURRENT; summarizes the binding operational rules in
[AGENTS.md](https://github.com/marcobiz/secure-integration-platform/blob/main/AGENTS.md).

## Outcome before machinery

Build the smallest coherent system that solves a demonstrated problem. Security and
usability are joint criteria: a control is incomplete if the normal path requires
avoidable waiting, repeated login, repository knowledge, SQL, store access or routine support.

For each slice, freeze:

- visible outcome and non-goals;
- authorities/boundaries to preserve;
- minimum negative set;
- black-box adoption metric;
- stop and review criteria.

Estimate product, laboratory/test and evidence effort separately. If test plus
evidence will probably exceed implementation, or the same slice enters two consecutive
remediation/re-review cycles, hold an explicit scope-and-complexity checkpoint.

## Compensation stop rule

A temporary solution must have a boundary, owner and removal condition. When a second
exception, procedure, coordination mechanism or test apparatus mainly compensates for
an earlier choice, stop before adding a third layer.

Ask:

1. what the earliest authoritative cause is;
2. which components, states and procedures would disappear by changing that assumption;
3. whether the new abstraction removes measured duplication in current cases;
4. whether instrumentation has operational value independent of evidence;
5. whether the laboratory is simpler than the behavior it verifies.

Do not normalize a product defect as operator knowledge. If ordinary onboarding,
recovery or testing requires specialist intervention, the adoption experience has
failed. Document the blocker and propose a bounded correction; do not add a workaround
runbook unless the external constraint is unavoidable and explicit.

## Minimalism and reuse

- Prefer direct flow, explicit state and ordinary structures over frameworks,
  reflection or indirection.
- Add an abstraction only when it reduces measured current complexity or duplication.
- Keep layers, interfaces, services, configurations and long-lived dependencies few.
- Optimize architecture, round trips and representation first; measure before micro-optimizing.
- Remove dead paths, compatibility without consumers and evidence-only machinery
  after preserving the necessary authority.
- Resolve the second case of friction at the narrowest shared boundary, not through
  two vertical runbooks.

## Ownership and parallelization

One capable owner retains end-to-end responsibility until the outcome. Purposeful
iterations test distinct hypotheses, validate a correction or confirm a transient
result; unexplained identical retries are prohibited.

Parallelize only independent tasks with disjoint files/outputs and an explicit
integration plan. Do not multiply writers on contracts, migrations, generated clients,
central documentation or the same runtime path: merge and requalification costs often
exceed the gain. Parallel workers normally return findings/evidence to one designated writer.

## Review and closure

Review occurs at convergence points. P0/P1 findings block; a P2 blocks only if it
invalidates an agreed criterion or demonstrates concrete security, correctness,
adoption or operability risk. Other P2/P3 findings are follow-ups and do not reopen
an indefinite cycle.

Evidence is minimal and truthful: no constructed counters as proof of broader behavior,
no sensitive data and no overclaim from synthetic to live/production.

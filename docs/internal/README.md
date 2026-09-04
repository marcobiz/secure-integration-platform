# Internal documentation

**Audience:** maintainers, reviewers and agents working in the repository.
**Status:** CURRENT.

## Order of authority

1. [AGENTS.md](../../AGENTS.md): scope, security, release and working method.
2. [IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md): integrated status and permitted claims.
3. [ADRs](../adr/README.md): durable decisions.
4. [Implementation plan](../implementation/implementation-plan.md) and
   [definition of done](../implementation/definition-of-done.md): roadmap and closure.
5. [Requirements traceability](../traceability/requirements-traceability.md):
   requirement/test/evidence mapping.
6. [Complexity governance](complexity-governance.md): stop rules and adoption criteria.
7. [History index](../history/README.md): non-authoritative earlier evidence and plans.

A historical document, test name, PR or external evidence does not override executable
contracts and CURRENT status. Redacted inputs may justify a documentation change,
but raw evidence and operational material stay outside Git.

## Workflow

- Confirm the exact baseline, branch/upstream, authorized scope and clean worktree.
- Freeze the visible outcome, material boundaries and negative set before writing.
- Give one end-to-end owner overlapping surfaces; parallelize only inventories,
  audits or checks with disjoint outputs.
- Correct the earliest authoritative cause and keep the change minimal.
- Verify with proportionate gates and distinguish product behavior, laboratory
  automation and external evidence.
- Do not merge, release or expand scope without explicit authority.

# Documentazione interna

**Pubblico:** maintainer, reviewer e agenti che lavorano nella repository.
**Stato:** CURRENT.

## Autorità in ordine

1. [AGENTS.md](../../AGENTS.md): scope, sicurezza, release e metodo di lavoro.
2. [IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md): stato integrato e claim
   consentite.
3. [ADRs](../adr/README.md): decisioni durevoli.
4. [Implementation plan](../implementation/implementation-plan.md) e
   [definition of done](../implementation/definition-of-done.md): roadmap e chiusura.
5. [Requirements traceability](../traceability/requirements-traceability.md): mapping
   requisito/test/evidence.
6. [Complexity governance](complexity-governance.md): stop rule e criteri di adozione.
7. [History index](../history/README.md): evidence e piani precedenti non autoritativi.

Un documento storico, un test name, una PR o una evidence esterna non prevalgono su
contratti eseguibili e stato CURRENT. Gli input redatti possono giustificare una modifica
documentale, ma raw evidence e materiale operativo restano fuori Git.

## Flusso di lavoro

- Confermare baseline exact, branch/upstream, scope autorizzato e worktree clean.
- Congelare outcome visibile, confini materiali e negative set prima di scrivere.
- Dare a un solo owner end-to-end le superfici sovrapposte; parallelizzare soltanto
  inventari, audit o verifiche con output disgiunti.
- Correggere la causa autorevole più precoce e mantenere il cambiamento minimo.
- Verificare con gate proporzionati e distinguere product behavior, laboratorio ed
  evidence esterna.
- Non mergeare, rilasciare o ampliare scope senza autorità esplicita.

# Indice storico

**Pubblico:** maintainer, auditor e reviewer.
**Stato:** HISTORICAL index.

Questo indice separa 53 documenti di piani completati, gate, review, report e runbook di
milestone dalle procedure CURRENT. I file restano ai path originali in questa prima
implementazione per non rompere link o riscrivere evidence; non sono autorità sullo stato
attuale e non devono fornire passaggi mancanti a un adottante.

## Classificazione dei 53 documenti

| Gruppo | Conteggio | Path classificati HISTORICAL |
|---|---:|---|
| Architettura milestone | 1 | `docs/architecture/m2-gateway-architecture.md` |
| Piano connector precedente | 1 | `docs/connectors/healthcare/M6-IMPLEMENTATION-PLAN.md` |
| Piani di implementazione completati | 19 | Tutti i file in `docs/implementation/` eccetto `0.1.0-alpha-scope.md`, `implementation-plan.md`, `backlog.md`, `definition-of-done.md`. |
| Runbook/laboratori milestone | 5 | `M0-M1-LIVE-MATRIX-RUNBOOK.md`, `M2-GATEWAY-RUNBOOK.md`, `M3-E2E-RUNBOOK.md`, `M3A-SPLIT-HOST-CODEX-VM.md`, `M3A-SPLIT-HOST-RUNBOOK.md` sotto `docs/operations/`. |
| Review | 16 | Tutti i file versionati in `docs/reviews/` sulla baseline. |
| Report di test/evidence | 9 | Tutti i file in `docs/testing/` eccetto `test-strategy.md`; include il report FSE2 pre-qualifica, ora superato dalla dashboard CURRENT. |
| Tracciabilità di fase | 1 | `docs/traceability/auth-phase2-wave1-oauth.md` |
| Harness M0/M1 | 1 | `tools/live-matrix/README.md` |
| **Totale** | **53** | Nessun file spostato in questa tranche. |

`docs/operations/M4-QUICKSTART.md` è un percorso duplicato e non canonico: conservarlo
come reference di milestone, ma per l’adozione usare soltanto
[docs/user/local-pilot.md](../user/local-pilot.md). I documenti stale/target non compresi
nel conteggio storico non diventano CURRENT per esclusione: l’elenco CURRENT è
esplicitamente definito in [docs/README.md](../README.md).

## Uso corretto della storia

- Usare questi file per provenance, decisioni su baseline passate o audit.
- Non ricostruire da essi il percorso di installazione, onboarding o invocation.
- Non aggiornare un report immutabile per correggere lo stato corrente; aggiornare
  dashboard, guide CURRENT e traceability.
- Non copiare SHA, conteggi di gate o dettagli di laboratorio nelle guide utente salvo
  che supportino una decisione attuale e bounded.

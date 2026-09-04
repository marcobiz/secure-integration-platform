# Indice storico

**Pubblico:** maintainer, auditor e reviewer.
**Stato:** HISTORICAL index.

Questo indice conserva la classificazione iniziale di 53 documenti di piani completati,
gate, review, report e runbook di milestone, e identifica i percorsi successivamente
superati. I file restano ai path originali per non rompere link o riscrivere evidence;
non sono autorità sullo stato attuale e non devono fornire passaggi mancanti a un adottante.

## Classificazione iniziale dei 53 documenti

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

## Prove Windows / Local Broker

- [Matrice M0/M1 requisito-test-evidenza](../reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md)
  e [runbook Windows](../operations/M0-M1-LIVE-MATRIX-RUNBOOK.md): servizio SCM reale
  con identità distinta, processi autorizzati/non autorizzati, ACL pipe/storage, DPAPI,
  restart e reboot. L'[harness esistente](../../tools/live-matrix/README.md) richiede
  VM Windows dedicata, elevazione e SDK; non è il pilot Core Docker-first.
- [Gate M3A split-host](../operations/M3A-SPLIT-HOST-RUNBOOK.md): simulatore legacy
  Windows → Named Pipe → Local Broker → Gateway → fornitore sintetico HTTPS/mTLS.
  Il [gate prodotto M3A](../reviews/M3A-PRODUCT-GATE-20260805.md) e la
  [tracciabilità FR-008](../traceability/requirements-traceability.md#requisiti-funzionali)
  identificano la run PASS-LIVE storica e il relativo perimetro; il runbook conserva
  baseline, prerequisiti Hyper-V e handoff di quella milestone.

Queste prove supportano il confine per software installato sulle baseline attestate,
non una nuova demo o qualifica del CURRENT. Non eseguire i comandi di laboratorio come
installazione ordinaria. MSI, adapter C ABI/COM e produzione non sono qualificati;
Administrator e SYSTEM restano minacce privilegiate residue.

## Percorsi FSE2 precedenti

L'ingresso corrente è [validazione e consultazione OfficialTest](../user/fse2-validation-status.md),
con [capability sintetizzate qui](../../IMPLEMENTATION_STATUS.md#stato-prodotto).

- [Pilot validate-only](../user/fse2-officialtest.md): storico per la prima adozione,
  specifico di `fse2-officialtest-validate-cda@1.0.1`. I limiti del vecchio runner non
  descrivono il runner current-spec; il riferimento al provisioner condiviso resta utile.
- [Spec freeze Wave 1](../implementation/FSE2-WAVE1-SPEC-FREEZE.md): inventory storico
  a 11 operazioni. Non sostituisce le [14 route current-spec](../connectors/healthcare/fse2/current-spec.md).
- [Matrice dei profili storici alla baseline PR #65](https://github.com/marcobiz/secure-integration-platform/blob/18df69d6eaa34ed636b101bce1d188cd65226e1a/docs/connectors/healthcare/fse2/README.md#historical-profile-capability-matrix):
  conserva anche la prova trace/`NOT_FOUND` del 3 settembre, distinta dal workflow
  `FOUND` del 4 settembre. Nessuna qualifica si trasferisce automaticamente tra profili.

## Uso corretto della storia

- Usare questi file per provenance, decisioni su baseline passate o audit.
- Non ricostruire da essi il percorso di installazione, onboarding o invocation.
- Non aggiornare un report immutabile per correggere lo stato corrente; aggiornare
  dashboard, guide CURRENT e traceability.
- Non copiare SHA, conteggi di gate o dettagli di laboratorio nelle guide utente salvo
  che supportino una decisione attuale e bounded.

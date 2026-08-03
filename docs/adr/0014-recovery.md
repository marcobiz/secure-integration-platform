# ADR-0014: Recovery locale

**Stato:** Accepted

## Decisione

MVP: backup metadata/blob e recovery solo con profilo/system-state capace di usare DPAPI. Perdita completa macchina richiede re-enrollment e può rendere i dati cifrati irrecuperabili.

Enterprise: recovery copy per-Installation, wrapped da recovery key centrale, dual-control, revoca e audit. Nessuna master key universale.

## Conseguenze

L'MVP non indebolisce l'isolamento per offrire recovery universale. Il rischio operativo deve essere comunicato e testato.


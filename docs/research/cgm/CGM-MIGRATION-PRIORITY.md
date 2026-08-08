# CGM migration priority

## Criteri

La priorità combina copertura di farmacie/processi, frequenza operativa qualitativa, criticità, codice dismettibile, riduzione dei secret locali, riuso cross-vendor, qualità delle specifiche e costo di onboarding. Non sono disponibili volumi transazionali o tenant counts: nessun punteggio li simula.

## Priorità per seam

| Priority | Seam | Motivo | Exit criteria |
|---|---|---|---|
| P0 | W-01, D-01 | Ricetta SSN nazionale, due caller e alta criticità operativa | MFA ufficiale, negative tests, reconciliation erogazione/prescrizione |
| P0 | W-02, W-04, D-02 | Lombardia ed Emilia-Romagna: profili regionali ricorrenti e riuso auth/core | Specifiche correnti, accreditamento, browser/session challenge |
| P0 | W-09 | Consumer FSE Lombardia osservato in farmacia | Contract search/retrieve e autorizzazione corrente |
| P0 | D-07, D-09, D-11 | Consente FSE2 diretto e ritira producer regionali | GTW 2.23 lifecycle, dual-JWT/mTLS, document type scope |
| P0 | W-19 | DPC quotidiano e boundary semplice token/workflow | Specifica WebDPC, idempotency e state characterization |
| P1 | W-03, W-05..W-08, D-03..D-05 | Restanti ePrescription regionali, auth più complessa | Un profilo alla volta, nessuna astrazione forzata |
| P1 | W-10..W-13, D-06 | Consumer FSE prioritari; forte dismissione di cert/token locali | Accreditamento regionale e vector search/retrieve |
| P1 | W-15 | VetInfo nazionale e riuso cross-vendor | Eliminazione password grant, onboarding ufficiale |
| P1 | W-17 | Adempimento spese sanitarie nazionale | Specifica/accreditamento correnti e ricevute |
| P1 | W-20 | WebCare ad alta utilità farmacia | Stato allowance/dispensing caratterizzato |
| P2 | W-14, W-16, W-18, W-21, W-22 | Profili XDS/legacy/mediati o frequenza inferiore | Prova di uso tenant e contract corrente |
| P2 | D-08, D-10, D-12, D-13 | Consumer Sardegna, search Sogei, vaccini, malattia | Specifiche e feature rollout confermati |
| P3 | D-14 | Servizio regionale accessorio rispetto al core roadmap | Cliente/tenant sponsor e contract |
| P3 | W-23, D-15 | Funzioni CGM private | Restano esterne a SIP |

## Percorso meno rischioso per Wingesfar

1. **Strangler davanti alle facciate esistenti.** Conservare i record layout/facade `WGClient` e sostituire una route alla volta con SIP; nessun big-bang della UI.
2. **Read-only prima dei write.** Per ogni famiglia iniziare da lookup/search/status, poi shadow comparison sanitizzata, quindi write con rollback/reconciliation.
3. **Sistema TS nazionale prima, profili regionali dopo.** Stabilizzare grant, sessione/MFA, audit e fault mapping sul flusso più riusabile.
4. **Canary per regione e farmacia.** Binding server-owned e feature flag pubblicata; fallback legacy esplicito, time-boxed e auditato.
5. **Migrare i secret prima del cutover.** Import controllato in provider, rotazione, prova negativa che il client non possa selezionare reference/endpoint.
6. **FSE consumer separato da FSE2 producer.** Evita di perdere search/retrieve credendo che il GTW li copra.
7. **DPC/WebCare per ondate di piattaforma.** Contract characterization e stato prima di spostare erogazioni.
8. **Broker solo per Puglia/non-exportable key.** Non distribuire un agente locale a tutte le farmacie come prerequisito generale.
9. **Retirement misurabile.** Disabilitare adapter legacy solo dopo un periodo senza fallback e con reconciliation completa.

## Rischi residui

| Rischio | Impatto | Mitigazione |
|---|---|---|
| Specifiche regionali non pubbliche o mutate | Alto | Accreditamento e contract pack per profilo prima del build |
| App drCLOUD AOT limita i call references | Medio | Manifest feature/tenant e trace sanitizzate; non contare classi isolate |
| Session/MFA manuale | Alto | Challenge opaca, expiry, replay protection e UX di rinnovo |
| Write con timeout ambiguo | Alto | Query stato/reconciliation, idempotency ufficiale, niente retry cieco |
| Certificati shared/product | Alto | Ownership inventory, rotazione e provider centralizzato |
| Puglia smartcard/VPN | Alto | Broker ristretto, laboratorio autorizzato, nessuna simulazione del device |
| Mediazioni CGM/associative | Medio | Migrare solo se sostituzione diretta è autorizzata e conveniente |

## Gate per cambiare priorità

Una seam `NEEDS_CHARACTERIZATION` sale a P0/P1 solo con: caller attivo, tenant/feature evidence, contract corrente, auth ownership, test environment, onboarding owner e almeno un vector sintetico di request/response/fault/state.

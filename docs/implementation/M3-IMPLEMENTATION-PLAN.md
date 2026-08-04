# M3 — piano di implementazione del vertical slice production-like

**Baseline:** `m2-gateway-baseline-2026-08-04`  
**Branch di lavoro:** `m3/production-like-vertical-slice`  
**Regola:** nessuna funzionalità M4.

## Incrementi compilabili

1. **Documentazione e contratti:** architettura, sequenza, runbook, evidence schema e
   tracciabilità dei 7 scenari positivi e 15 negativi.
2. **Installation client del Broker:** chiave CNG ECDSA P-256 non esportabile,
   certificato ClientAuth, enrollment/PoP, persistenza DPAPI CurrentUser della sola
   configurazione non segreta e invoke BGW1 firmato.
3. **Fixture M3A:** synthetic Vault HTTPS, vendor mock HTTPS/mTLS, CA/certificati per-run,
   provisioning PostgreSQL e operation/grant server-side.
4. **Orchestratore deterministico:** installa il vero Windows Service, avvia i container,
   esegue legacy simulator e matrice positiva/negativa, reboot non richiesto da M3,
   redige e valida evidence.
5. **CI M3A:** job dedicato con label esplicite; nessuna sostituzione in-process del
   Broker o dei container.
6. **M3B Azure:** Bicep dev, OIDC, Managed Identity, Key Vault, secret/cert sintetici,
   deploy immagine esatta e smoke contro mock mTLS.
7. **Gate:** review critica, CI sul commit esatto, evidence hash, documenti/stato e tag
   annotato soltanto dopo PASS M3A+M3B.

Ogni incremento deve lasciare `eng/build.ps1`, `eng/test.ps1`,
`eng/validate-docs.ps1`, secret scan e `git diff --check` verdi.

## Scenari e punti di osservazione

| ID | Scenario | Assert principale | Nessun side effect |
|---|---|---|---|
| M3-P01 | enrollment | code consumato, PoP P-256 valido | code non riusabile |
| M3-P02 | invoke via Broker | pipe e service reali | legacy senza vendor secret |
| M3-P03 | tenant server-side | audit/DB sul Tenant autenticato | tenant client ignorato/rifiutato |
| M3-P04 | grant valido | una sola operation concessa | altre operation negate |
| M3-P05 | API key da Vault | mock riceve canary attesa | Broker/log non la ricevono |
| M3-P06 | mTLS vendor | mock vede cert atteso | cert errato negato |
| M3-P07 | response sanitizzata | schema/limiti rispettati | header/provider detail assenti |
| M3-N01..N15 | negative richieste | codice stabile atteso | Vault/egress non raggiunti quando applicabile |

La matrice completa con nome dei test ed evidence path viene aggiornata solo con test
realmente presenti; i controlli non eseguiti restano `PENDING`, mai `PASS` inferito.

## Separazione dei commit

- `M3 implementation`: codice prodotto, infrastruttura e test;
- `M3 synthetic test configuration`: compose, generatori e valori pubblici non segreti;
- `M3 redacted evidence`: solo manifest/report/hash della run approvata;
- `M3 closure`: stato, tracciabilità, review e tag.

Raw evidence, chiavi, certificati privati, activation code, token OIDC, dump, EVTX e log
non redatti sono vietati in Git e coperti da `.gitignore`/secret scan.

## Dipendenze operative non sostituibili

- laboratorio split-host con Docker Linux sull'HOST e singolo script revisionato eseguito
  manualmente da console amministrativa VM;
- GitHub Environment `azure-dev` con federazione OIDC e reviewer/protection rules;
- subscription/resource group Azure dev autorizzati;
- DNS pubblico o endpoint di mock dev compatibile mTLS.

Se una dipendenza manca, implementazione e test isolati possono avanzare ma il gate M3
rimane `NO-GO`; non viene creato alcun tag baseline.

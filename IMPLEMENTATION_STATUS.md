# Implementation status

Aggiornato: 2026-08-04

## Stato sintetico

| Ambito richiesto | Stato | Evidenza principale |
|---|---|---|
| M0 — fondamenta repository | Implementato; baseline congelata | commit `7f68442`, tag `baseline-m0-m1-vslice-2026-08-03` |
| M1 — Local Broker minimo | Implementato; **gate live tecnico PASS** | run `m0-m1-20260803-232955`; AC-002/004 PASS-LIVE sul commit testato |
| Primo vertical slice E2E | Completato come harness ripetibile | `E2E_CON_SecureLayer_success_boundaries_failures_timeout_and_replay` |
| M2 — Gateway minimo | Implementato; gate container/CI pendente | build/test HOST e PostgreSQL 18 reale PASS; Docker smoke predisposto in CI |
| M3 e milestone successive | Non iniziate | nessun nuovo vertical slice, Connector lifecycle, Admin o adapter nativo |
| Harness matrice live M0/M1 | Implementato ed eseguito su VM | matrice A-F PASS, reboot reale, bundle con manifest e SHA-256 verificati |

## Gate Review prima di M2

Esito conclusivo: **GO per M2**. La lineage live è stata integrata linearmente: il commit realmente testato resta `24288dbe065ecedc21c0018e8ed37ca844bc8caf`, il tag `m0-m1-live-pass-20260803-232955` non è stato riscritto e il commit documentale successivo `d1113d34a18e166c9eb0c14d8e11c3c1a1a20c12` è la baseline M2.

- **AC-002:** PASS-LIVE sul commit testato; servizio reale osservato come `NT SERVICE\SecureIntegrationBroker`, con restart e persistenza dopo reboot.
- **AC-004:** PASS-LIVE sul commit testato; ACL pipe/storage e negazione DPAPI verificate tra identità Windows distinte.
- IPC v1 è **provvisorio**, non congelato per COM/C ABI/CLI prima di M2/M3.
- review completa: `docs/reviews/M0-M1-GATE-REVIEW.md`;
- matrice requirement/test/evidence: `docs/reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md`.
- pacchetto live automatizzato: `tools/live-matrix`; runbook: `docs/operations/M0-M1-LIVE-MATRIX-RUNBOOK.md`.

## Modifiche implementate

### M0

- solution `.slnx`, struttura monorepo e confini di packaging;
- SDK .NET 10 pinned, central package management, lock file, nullable/analyzer e warning-as-error;
- script riproducibili di restore/build, test, validazione documenti, secret scan e SBOM SPDX;
- GitHub Actions con job Windows, dependency check, gitleaks e SBOM;
- `.gitignore` che esclude toolchain/artifact locali, materiale sensibile `input-docs` e formati di chiavi/certificati;
- skeleton Docker/MSI e release manifest senza anticipare implementazioni successive.

### M1

- framing IPC v1 `BGR1`, network byte order, version negotiation, limiti, sequence, correlation ID, challenge, nonce, deadline, multiplexing e cancel;
- Named Pipe con ACL per service/application SID e più connessioni concorrenti;
- caller identity acquisita dal kernel: PID, handle mantenuto per la connessione, creation time, SID del process token, path canonico, SHA-256 e publisher Authenticode trusted quando richiesto;
- manifest Application deny-by-default per SID, path, publisher/hash opzionale, operazioni Broker e coppie Connector/operation;
- persistenza atomica sotto ACL protette, DPAPI `CurrentUser`, data key casuale per Installation e AES-256-GCM versionato con AAD Installation/Application/purpose/content type;
- `PutLocalSecret` e `DeleteLocalSecret` idempotente per classi Tenant/Session; Vendor/Operator rifiutate; nessuna `GetSecret`;
- `ProtectData`, `UnprotectData`, `ComputeHmac`, `InvokeGateway` vincolata e status redatto;
- SDK .NET sottile per `netstandard2.0` e `net10.0`;
- Windows Service host e script di registrazione con virtual account `NT SERVICE\SecureIntegrationBroker`.
- harness VM fail-closed con account/processi reali distinti, ACL exact, DPAPI cross-identity, restart/reboot, tamper, Event Log e evidence bundle SHA-256.

### Vertical slice

- legacy simulator -> Broker reale -> Gateway HTTPS/mTLS di test -> provider sintetico -> mock REST HTTPS/mTLS;
- endpoint, Connector/operation, API key vendor e certificato client esterno restano centrali;
- test di successo, grant invalido, assenza secret, TLS failure, timeout e replay;
- nessuna capacità M2 production introdotta. Dettagli in `docs/testing/first-vertical-slice-report.md`.

### M2 — Gateway minimo

- modular monolith `Gateway.Domain/Application/Infrastructure/Api` e migration runner separato;
- PostgreSQL 18 con schema additivo, composite FK, ruoli distinti, RLS forzata e locator di autenticazione a superficie stretta;
- Tenant/Application/Environment/Installation, activation HMAC, challenge e PoP ECDSA P-256;
- credential ClientAuth, renewal 30 giorni, overlap massimo 7 giorni, revoca e replay nonce;
- autenticazione BGW1 che copre method, target, timestamp, nonce e body digest e deriva il Tenant dal certificato registrato;
- operation catalog immutabile server-side e grant deny-by-default;
- Azure Key Vault tramite Managed Identity; provider in-memory confinato a Development/Testing;
- egress HTTPS con DNS/IP filtering, socket pinned anti-rebinding, proxy/redirect/cookie disabilitati, bounds, timeout e retry solo idempotente;
- Basic, API key e mTLS applicati esclusivamente dal Gateway senza esporre secret reference;
- API health/readiness, Problem Details redatti, Docker non-root/read-only-compatible, health probe e Bicep contract skeleton;
- architettura, runbook, piano e report in `docs/architecture/m2-gateway-architecture.md`, `docs/operations/M2-GATEWAY-RUNBOOK.md`, `docs/implementation/M2-IMPLEMENTATION-PLAN.md` e `docs/testing/M2-IMPLEMENTATION-REPORT.md`.

## Test ed esiti

| Suite/comando | Esito atteso dell'ultima verifica | Copertura |
|---|---|---|
| `eng/build.ps1` | PASS, zero warning/error | intera solution Release |
| `eng/test.ps1` | PASS | unit, Windows integration, E2E |
| `eng/validate-docs.ps1` | PASS | link/struttura/schema documentali |
| `eng/scan-secrets.ps1` | PASS | repository escluso materiale sorgente riservato |
| `eng/generate-sbom.ps1` | PASS | SBOM SPDX degli artefatti |
| `Broker.Core.Tests` | 26 PASS | lifecycle/grant, AEAD/nonce/AAD/version, framing e hard limits |
| `Broker.Integration.Tests` | 22 PASS | DPAPI, pipe/storage ACL, persistence/corruption, identity/handle, IPC, redaction |
| `VerticalSlice.Tests` | 1 PASS | vertical slice e negative/security path |
| `Gateway.Unit.Tests` | 22 PASS | enrollment/PoP/replay/renew/revoke/version, tenant/grant, Vault/cache/auth modes, SSRF, retry, redaction |
| `Gateway.Integration.Tests` | 6 PASS ordinari | API/Problem/health, schema/RLS statico; test PostgreSQL condizionali |
| PostgreSQL 18 effimero locale | 2 PASS | migration, FORCE RLS, registry enrollment/grant/replay/revoca |
| CI `gateway-postgresql-18` | PENDING indipendente | replica migration/RLS/registry su service container |
| CI `gateway-container` | PENDING | build e health smoke Docker |
| parsing `tools/live-matrix/*.ps1/*.psm1` | 9 PASS | sintassi PowerShell dell'intero harness |
| prerequisite check non elevato | expected FAIL con `LIVE_MATRIX_REQUIRES_ELEVATION` | fail-closed prima di qualsiasi modifica di sistema |
| probe command non valido | expected exit 1 con report redatto `unknown_probe_command` | contratto di errore machine-readable |

In aggiunta, quattro critical test IPC/identity/cancel/redaction sono passati per 20 iterazioni consecutive (80 esecuzioni).

I conteggi e gli esiti definitivi vanno aggiornati se una successiva esecuzione modifica le suite.

La matrice live A-F è PASS sulla VM `DESKTOP-5T30P6J` con RunId `m0-m1-20260803-232955`; il bundle locale e il relativo hash sono registrati nella documentazione di evidence.

## Criteri di accettazione soddisfatti nel perimetro

- **AC-001:** Vendor Secret assente da client e boundary Broker-Gateway, verificato E2E.
- **AC-002:** virtual service account, restart e persistenza post-reboot verificati live.
- **AC-003:** policy automatica e processo realmente distinto sotto lo stesso utente verificati live.
- **AC-004:** separazione service identity/gestionale/altro utente, ACL e DPAPI cross-user verificate live.
- **AC-005:** chiavi e ciphertext differenti tra due Installation.
- **AC-006:** audit strutturato senza payload/secret e verifica E2E sul secret sintetico.
- **AC-007:** il Gateway harness restituisce solo la risposta applicativa, mai il secret.
- **AC-008:** il Broker dipende da `IGatewayInvoker` e non possiede dipendenze o API Vault.
- **AC-009:** il client non espone URL; l'invoker usa esclusivamente la BaseAddress configurata.
- **AC-010:** il client non espone secret reference Gateway e può usare solo grant Connector/operation.
- **AC-011:** il Gateway M2 deriva Tenant/Application/Installation dal digest del certificato registrato.
- **AC-012:** grant cross-Tenant e input Tenant client-side sono negati; FORCE RLS PASS su PostgreSQL 18 reale locale.
- **AC-013:** revoca verificata prima di grant, Vault, DNS e dispatch; il gate E2E completo resta M3.
- **AC-018:** Dockerfile e smoke job implementati; PASS CI ancora necessario.
- **AC-020:** sorgenti, toolchain pinned e istruzioni build/test presenti.
- **AC-021:** E2E ripetibile interamente con servizi e certificati sintetici.
- **AC-023:** esempio Secure Layer eseguito dalla suite E2E.
- **AC-027:** generazione SBOM SPDX verificata.

**AC-002 e AC-004 restano PASS-LIVE sul commit testato invariato.** L'implementazione M2 e PostgreSQL 18 reale locale sono completi, ma M2 non è ancora dichiarata Done finché container smoke e gate CI indipendente non risultano verdi.

## Debito tecnico noto

- il server supporta multiplexing e `Cancel`, ma l'SDK sottile apre ancora una connessione per invocazione e non offre un client persistente condiviso;
- i frame Data/End sono codificati ma l'assembly streaming 16/64 MiB non è ancora esposto dall'SDK; gli input M1 usano control frame base64 e quindi un limite effettivo inferiore;
- key rotation è leggibile dal formato/repository e testata nel core, ma manca un comando operativo atomico di rotazione;
- installazione MSI, upgrade/repair/uninstall e signature appartengono alle milestone di packaging/hardening;
- nessuna compatibilità .NET Framework 4.7.2 o adapter COM/C ABI/CLI: sono esplicitamente M6;
- log/wire redaction copre normal, denied, invalid payload e crypto failure anche nel Windows Event Log live; crash non gestiti e telemetry futura restano aperti;
- il Gateway del vertical slice è un harness, non implementa identity Installation, revoca, replay distribuito, Vault reale o restricted egress production.
- il challenge store M2 è in-memory/single-node come consentito da ADR-0008; prima dello scale-out servirà storage TTL condiviso o challenge stateless firmata;
- i locator PostgreSQL e le funzioni RLS sono PASS su un cluster PostgreSQL 18 effimero locale; resta la replica CI indipendente;
- Key Vault/Managed Identity è implementato ma non provato live senza ambiente Azure;
- non esiste ancora idempotency record/runtime deduplication: l'envelope valida la key e il retry è limitato alle operation server-side idempotenti; la semantica completa resta nel runtime Connector M4;
- Gateway HTTP v1 e IPC v1 restano provvisori fino al gate M3.

## Decisioni ancora aperte

- policy di upgrade applicativo: publisher Authenticode, hash pinning o combinazione per ciascun prodotto;
- procedura di provisioning/backup/recovery del profilo della virtual service identity e delle data key;
- implementazione M9 dell'MSI conforme ad ADR-0017; il contratto architetturale di provisioning è ora accettato;
- semantica streaming e aggregate limits da validare in M2/M3 prima del freeze IPC per M6;
- policy CA/trust chain e certificate forwarding dell'hosting Azure da validare con l'ambiente DEP-02/M9;
- scelta scale-out del challenge store prima di eseguire più repliche Gateway;
- invalidazione proattiva della cache Key Vault e circuit breaker rinviati ai moduli operativi successivi sulla base di metriche reali; M2 usa cache in-process con TTL massimo 5 minuti.

## ADR

Nessun ADR è stato modificato da M2: l'implementazione segue ADR-0002/0005/0007/0008/0013/0015. ADR-0017 resta la decisione per il provisioning MSI futuro. Upgrade policy, recovery, streaming e key rotation restano decisioni operative future.

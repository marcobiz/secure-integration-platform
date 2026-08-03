# Implementation status

Aggiornato: 2026-08-03

## Stato sintetico

| Ambito richiesto | Stato | Evidenza principale |
|---|---|---|
| M0 — fondamenta repository | Implementato; baseline congelata | commit `7f68442`, tag `baseline-m0-m1-vslice-2026-08-03` |
| M1 — Local Broker minimo | Implementato, **gate live non chiuso** | test automatici verdi; AC-002/004 live aperti |
| Primo vertical slice E2E | Completato come harness ripetibile | `E2E_CON_SecureLayer_success_boundaries_failures_timeout_and_replay` |
| M2 e milestone successive | Non implementate | assenza intenzionale di Gateway production, DB, Vault reale, Admin e adapter nativi |
| Harness matrice live M0/M1 | Implementato, **non ancora eseguito su VM** | `tools/live-matrix`; runbook pre/post reboot; nessuna evidenza simulata |

## Gate Review prima di M2

Esito: **NO-GO per M2** fino alla chiusura della matrice live su macchina Windows pulita/VM. L'host disponibile è Windows 10 Pro non elevato e senza Hyper-V/Sandbox/container runtime; non è stato possibile installare un vero servizio, creare identità Windows distinte o osservare DPAPI sotto la virtual service identity.

- **AC-002:** non soddisfatto in modo conclusivo; host/script esistono ma il virtual account non è stato osservato live.
- **AC-004:** non soddisfatto in modo conclusivo; descriptor ACL e DPAPI sono testati, ma non tra gestionale, service identity e altro utente reali.
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

## Test ed esiti

| Suite/comando | Esito atteso dell'ultima verifica | Copertura |
|---|---|---|
| `eng/build.ps1` | PASS, zero warning/error | intera solution Release |
| `eng/test.ps1` | PASS | unit, Windows integration, E2E |
| `eng/validate-docs.ps1` | PASS | link/struttura/schema documentali |
| `eng/scan-secrets.ps1` | PASS | repository escluso materiale sorgente riservato |
| `eng/generate-sbom.ps1` | PASS | SBOM SPDX degli artefatti |
| `Broker.Core.Tests` | 26 PASS | lifecycle/grant, AEAD/nonce/AAD/version, framing e hard limits |
| `Broker.Integration.Tests` | 14 PASS | DPAPI, pipe/storage ACL, persistence/corruption, identity/handle, IPC, redaction |
| `VerticalSlice.Tests` | 1 PASS | vertical slice e negative/security path |
| parsing `tools/live-matrix/*.ps1/*.psm1` | 9 PASS | sintassi PowerShell dell'intero harness |
| prerequisite check non elevato | expected FAIL con `LIVE_MATRIX_REQUIRES_ELEVATION` | fail-closed prima di qualsiasi modifica di sistema |
| probe command non valido | expected exit 1 con report redatto `unknown_probe_command` | contratto di errore machine-readable |

In aggiunta, quattro critical test IPC/identity/cancel/redaction sono passati per 20 iterazioni consecutive (80 esecuzioni).

I conteggi e gli esiti definitivi vanno aggiornati se una successiva esecuzione modifica le suite.

La matrice live A-F non è stata eseguita su questo host: build e controlli statici del pacchetto non sostituiscono le evidenze VM richieste.

## Criteri di accettazione soddisfatti nel perimetro

- **AC-001:** Vendor Secret assente da client e boundary Broker-Gateway, verificato E2E.
- **AC-003:** policy automatica nega hash/publisher/operation non concessi; resta da provare con processo realmente distinto nella matrice live.
- **AC-005:** chiavi e ciphertext differenti tra due Installation.
- **AC-006:** audit strutturato senza payload/secret e verifica E2E sul secret sintetico.
- **AC-007:** il Gateway harness restituisce solo la risposta applicativa, mai il secret.
- **AC-008:** il Broker dipende da `IGatewayInvoker` e non possiede dipendenze o API Vault.
- **AC-009:** il client non espone URL; l'invoker usa esclusivamente la BaseAddress configurata.
- **AC-010:** il client non espone secret reference Gateway e può usare solo grant Connector/operation.
- **AC-020:** sorgenti, toolchain pinned e istruzioni build/test presenti.
- **AC-021:** E2E ripetibile interamente con servizi e certificati sintetici.
- **AC-023:** esempio Secure Layer eseguito dalla suite E2E.
- **AC-027:** generazione SBOM SPDX verificata.

**AC-002 e AC-004 non sono accettati dal gate conclusivo** e sono blocker M2. Gli AC legati a M2+ restano aperti intenzionalmente.

## Debito tecnico noto

- il server supporta multiplexing e `Cancel`, ma l'SDK sottile apre ancora una connessione per invocazione e non offre un client persistente condiviso;
- i frame Data/End sono codificati ma l'assembly streaming 16/64 MiB non è ancora esposto dall'SDK; gli input M1 usano control frame base64 e quindi un limite effettivo inferiore;
- key rotation è leggibile dal formato/repository e testata nel core, ma manca un comando operativo atomico di rotazione;
- installazione MSI, upgrade/repair/uninstall, signature e test live del virtual account appartengono alle milestone di packaging/hardening;
- nessuna compatibilità .NET Framework 4.7.2 o adapter COM/C ABI/CLI: sono esplicitamente M6;
- log/wire redaction copre normal, denied, invalid payload e crypto failure in-memory; Windows Event Log e telemetry live restano aperti;
- il Gateway del vertical slice è un harness, non implementa identity Installation, revoca, replay distribuito, Vault reale o restricted egress production.

## Decisioni ancora aperte

- policy di upgrade applicativo: publisher Authenticode, hash pinning o combinazione per ciascun prodotto;
- procedura di provisioning/backup/recovery del profilo della virtual service identity e delle data key;
- implementazione M9 dell'MSI conforme ad ADR-0017; il contratto architetturale di provisioning è ora accettato;
- semantica streaming e aggregate limits da validare in M2/M3 prima del freeze IPC per M6;
- implementazione M2 di Installation identity, trust chain, Vault e restricted egress prima di trasformare l'harness in servizio production.

## ADR

ADR-0017 è stato aggiunto per il provisioning MSI: manifest firmato, nessun segreto/Installation ID definitivo nel package, identità e chiave CNG non esportabile generate dal Broker al primo avvio, enrollment futuro monouso e semantiche install/repair/upgrade/uninstall/reinstall. Non implementa M2. Upgrade policy, recovery, streaming e key rotation restano decisioni operative future.

# Evidenza matrice live M0/M1

**Data:** 2026-08-03

**RunId:** `m0-m1-20260803-232955`

**SUT baseline:** `39ac4eae23d6a4c43729863ca345fdbf10af0ee6`

**Harness baseline:** `f33bf910b9f7c1f5b8a4ea47476c26f7c49c2170`

**Commit testato:** `24288dbe065ecedc21c0018e8ed37ca844bc8caf`

**Esito tecnico:** **PASS LIVE A-F**

**Decisione M2:** **NO-GO fino all'integrazione del commit testato in `origin/main`**

## Qualificazione osservata

| Evidence ID | Controllo | Risultato |
|---|---|---|
| ENV-001 | `WindowsPrincipal.IsInRole(Administrator)` nel runner | `True` |
| ENV-002 | VM | `DESKTOP-5T30P6J`, Microsoft Virtual Machine, UUID `864384BD-9128-4F51-A741-001485E7DF72` |
| ENV-003 | OS | Windows 11 Pro 10.0.26200, build 26200 |
| ENV-004 | PowerShell | Windows PowerShell 5.1.26100.7920, processo pulito `-NoProfile` |
| ENV-005 | Repository | commit `24288dbe065ecedc21c0018e8ed37ca844bc8caf` |
| ENV-006 | Service identity | `NT SERVICE\SecureIntegrationBroker` |
| ENV-007 | Reboot qualificante | boot UTC `2026-08-03T21:38:33.1818970Z` |

Il preflight ha prodotto `preflightPassed: true` e `overallStatus: InProgress`; non è stato interpretato come risultato globale. `ValidateHarness` ha prodotto `HarnessValidated` prima delle modifiche di sistema.

## A-F: risultato live

| ID | Stato | Evidenza osservata |
|---|---|---|
| LIVE-A | PASS | applicazione autorizzata con pipe, grant limitati, HMAC, Protect/Unprotect e persistenza |
| LIVE-B | PASS | processo distinto sotto lo stesso SID raggiunge la pipe ma viene negato dalla policy; storage negato |
| LIVE-C | PASS | altro utente Windows negato su pipe, storage e DPAPI |
| LIVE-D | PASS | database legacy cifrato leggibile; API secret/key material non disponibili |
| LIVE-E | PASS | tamper envelope e key rifiutati, restore verificato, HMAC e protected data persistenti dopo restart/reboot |
| LIVE-F | PASS | Windows Event Log reale con path normal/denied/invalid/crypto/key failure e redazione verificata |

## ACL e servizio

- Named Pipe protetta con soli SID dell'applicazione autorizzata e del servizio.
- L'ACE applicazione è normalizzata da Windows a `ReadWrite, Synchronize`; il servizio ha `FullControl`.
- ACL storage pre/post reboot protette ed esatte per SYSTEM, Administrators e service SID.
- SCM configurato con `StartName = NT SERVICE\SecureIntegrationBroker`, avvio automatico e service SID `UNRESTRICTED`.
- Dopo un secondo reboot di servicing Windows, successivo al completamento della matrice, il servizio era ancora `Running` e non restavano task LiveMatrix.

## Event Log e redazione

Il bundle contiene 73 eventi del provider; 41 appartengono alla finestra della run corrente. Sono presenti eventi per successo, `application_not_authorized`, `invalid_base64`, `authentication_failed` e `data_key_unwrap_failed`. Il report SYSTEM ha verificato 11 canary protetti senza match; una verifica indipendente sui valori leggibili dalla sessione non elevata non ha trovato leakage né pattern generici di secret.

## Bundle verificato

| Campo | Valore |
|---|---|
| Directory run | `C:\ProgramData\SecureIntegration\LiveMatrix\m0-m1-20260803-232955` |
| ZIP | `evidence\M0-M1-live-matrix-m0-m1-20260803-232955.zip` |
| SHA-256 ZIP | `5B6E9997EF0C5C482B27B7DB63323BA54C96D5C2B083DAAEB4A47255D156C52C` |
| Manifest schema | `secureintegration.live-matrix.evidence/v1` |
| File dichiarati | 24 più `manifest.json` |
| Verifica | nessun file mancante/extra; dimensioni e SHA-256 tutti coincidenti |
| Completamento UTC | `2026-08-03T21:40:05.9525444+00:00` |

Il bundle non è simulato, non è tracciato da Git e resta in ProgramData. Il sidecar SHA-256 coincide con il digest ricalcolato.

## Run bloccate preservate

Le run precedenti restano conservate come failure evidence e non sono state convertite in PASS:

- `m0-m1-20260803-183430`: BLOCKED - HARNESS RUNTIME ERROR;
- `m0-m1-20260803-212513`: BLOCKED - provisioning descrizione account;
- `m0-m1-20260803-215029`: BLOCKED - restore RID;
- `m0-m1-20260803-220555`: BLOCKED - batch logon;
- `m0-m1-20260803-222713`: BLOCKED - ACL output probe;
- `m0-m1-20260803-223835`: BLOCKED - process identity API;
- `m0-m1-20260803-225019`: BLOCKED - virtual service caller identity/Event Log source;
- `m0-m1-20260803-231445`: BLOCKED - ordine process open/impersonation;
- `m0-m1-20260803-232142`: BLOCKED - normalizzazione ACE pipe nel verifier.

Ogni run è stata preservata e ripulita mediante `Remove-LiveMatrix.ps1` senza `PurgeEvidence` prima di avviare da stato pulito la run successiva.

## Nota sui reboot

Windows servicing (`TrustedInstaller.exe` come SYSTEM) ha richiesto due reboot pianificati. Il task post-reboot della matrice è stato eseguito dopo il primo boot e ha completato il bundle PASS prima del secondo reboot. Il secondo reboot è esterno alla matrice e successivo al completamento; lo stato operativo successivo è stato verificato in sola lettura.

## Decisione

AC-002 e AC-004 sono **PASS-LIVE per il commit testato**. La Gate Review resta **NO-GO per M2** perché `origin/main` è ancora `f33bf910b9f7c1f5b8a4ea47476c26f7c49c2170`. La lineage deve essere revisionata e integrata mantenendo lo SHA testato; se viene riscritta con rebase o squash, occorre una nuova matrice completa sul nuovo commit.

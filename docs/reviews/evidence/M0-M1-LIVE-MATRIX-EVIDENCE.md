# Evidenza matrice live M0/M1

**Data tentativo:** 2026-08-03  
**Esito:** BLOCKED — matrice non eseguita  
**Motivo:** nessun runner Windows pulito/VM elevato disponibile

## Qualificazione osservata

| Evidence ID | Controllo | Risultato |
|---|---|---|
| ENV-001 | `WindowsPrincipal.IsInRole(Administrator)` | `False` |
| ENV-002 | `Win32_OperatingSystem` | Windows 10 Pro, 10.0.19045, workstation |
| ENV-003 | `Get-Service vmms` / `Get-Command Get-VM` | non disponibili |
| ENV-004 | `C:\Windows\System32\WindowsSandbox.exe` | assente |
| ENV-005 | `Get-Command docker,podman` | non disponibili |
| ENV-006 | `Get-Service SecureIntegrationBroker` | servizio assente |
| ENV-007 | `Get-WindowsOptionalFeature` | accesso negato: richiede elevazione |

Non è stato tentato un bypass UAC, non è stato aperto un prompt interattivo e non sono stati usati host/cloud esterni non autorizzati.

## A–F: risultato live

| ID | Stato | Evidenza mancante |
|---|---|---|
| LIVE-A | NOT RUN | service PID/token, client legacy distinto, operation transcript, restart persistence |
| LIVE-B | NOT RUN | processo differente stesso SID, pipe/policy denial e storage access denial |
| LIVE-C | NOT RUN | SID differente, pipe/storage AccessDenied e DPAPI unwrap failure |
| LIVE-D | NOT RUN | account gestionale, accesso eventuale DB test e negazione Broker key/secret material |
| LIVE-E | NOT RUN | stop/start SCM, recovery key, pre/post digest, tamper evidence |
| LIVE-F | NOT RUN | export Windows Event Log e scansione normal/denied/invalid/crypto failure |

## Proxy automatici disponibili ma non equivalenti

- `Repository_reopen_recovers_keys_secrets_and_protected_data_under_same_identity` non equivale a un restart SCM.
- `IT_BRK_Authorized_application_uses_pipe_and_unauthorized_hash_is_denied` non equivale a due processi/account Windows distinti.
- i test security descriptor non equivalgono all'enforcement del kernel con service SID reale.
- DPAPI sotto l'account testhost non equivale a DPAPI sotto `NT SERVICE\SecureIntegrationBroker`.
- `Audit_logging_redacts_normal_and_authentication_denied_paths` e il wire redaction test non equivalgono al provider Windows Event Log.

## Evidence pack obbligatorio per la prossima esecuzione

1. snapshot/ID VM, versione OS e stato patch;
2. hash commit/tag e hash binari pubblicati;
3. transcript elevato con tutti gli exit code;
4. `sc.exe qc SecureIntegrationBroker` e `Win32_Service` con `StartName`;
5. PID, creation time e token SID di servizio/simulator/utente estraneo;
6. SDDL Named Pipe e `icacls` ricorsivo della directory Broker;
7. risultati A–F con expected/actual e timestamp;
8. Event Log `.evtx` più report di scansione dei marker sintetici;
9. backup/hash prima del tamper, failure osservata e restore verificato;
10. cleanup o revert snapshot.

Finché questo evidence pack non esiste, AC-002 e AC-004 restano non soddisfatti e la Gate Review resta NO-GO.

## Pacchetto di esecuzione predisposto

Dal 2026-08-03 è disponibile `tools/live-matrix`, con orchestrazione elevata pre/post reboot, account e processi distinti, vero SCM service, ACL exact, DPAPI cross-identity, Event Log/redaction e bundle hashato. Il runbook è `docs/operations/M0-M1-LIVE-MATRIX-RUNBOOK.md`.

**Questo aggiornamento non aggiunge evidenze A-F:** il pacchetto non è stato eseguito sull'host non elevato corrente e tutti gli stati `NOT RUN` sopra restano validi fino a una run VM PASS.

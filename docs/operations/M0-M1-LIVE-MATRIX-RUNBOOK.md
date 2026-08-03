# Runbook: matrice live M0/M1 su VM Windows pulita

## Scopo e risultato atteso

Il runbook installa il Broker tramite SCM come vero Windows Service, usa `NT SERVICE\SecureIntegrationBroker`, crea due account locali standard, esegue la matrice A-F, riavvia la VM e produce un evidence bundle redatto e hashato. Non avvia né implementa M2.

Una run è valida soltanto se termina con `post-reboot-summary.json` avente `passed: true` e matrice A-F tutta `PASS`. Output automatici creati senza reboot o con un failure non sono evidenze di accettazione.

## 1. Preparazione della VM

Usare una nuova VM x64 non unita a dominio, Windows 11 Pro/Enterprise o Windows Server supportato, filesystem NTFS e almeno 10 GB liberi. Acquisire uno snapshot prima dell'esecuzione. Non usare una VM clonata dopo un precedente primo avvio del Broker.

Installare:

1. Windows PowerShell 5.1, normalmente incluso;
2. Git per Windows, se il repository viene clonato;
3. .NET SDK indicato da `global.json` (`10.0.302` per questa revisione);
4. aggiornamenti Windows richiesti dalla policy del laboratorio.

Copiare o clonare il repository nella VM. Non trasferire `.artifacts`, `.dotnet`, precedenti directory `%ProgramData%\SecureIntegration` o output di altre run.

## 2. Verifica iniziale

Aprire **Windows PowerShell come amministratore** e posizionarsi nella root del repository:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
$runId = 'm0-m1-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
.\tools\live-matrix\Test-Prerequisites.ps1 -RunId $runId
```

Il comando deve fallire se la sessione non è elevata, l'host non è riconosciuto come VM, il filesystem non è NTFS, l'SDK non coincide con `global.json` o esiste un servizio omonimo non posseduto dall'harness.

Conservare separatamente l'identificativo snapshot e l'hash del commit:

```powershell
git rev-parse HEAD
git status --short
```

Il worktree deve essere pulito prima della prova; il prerequisite check fallisce altrimenti. L'aggiornamento automatico della matrice documentale renderà il worktree modificato soltanto al PASS finale.

## 3. Esecuzione automatica completa

Avviare la run, includendo il reboot reale:

```powershell
.\tools\live-matrix\Invoke-LiveMatrix.ps1 -Phase All -RunId $runId -Reboot
```

La fase iniziale:

1. pubblica Broker e probe dal commit corrente;
2. crea `SibLiveAuthorized` e `SibLiveDenied` come utenti standard con password casuali custodite mediante DPAPI LocalMachine e ACL amministrative;
3. registra `SecureIntegrationBroker` con `StartName = NT SERVICE\SecureIntegrationBroker` e service SID unrestricted;
4. configura manifest applicativo con SID, path e SHA-256 dell'apphost autorizzato;
5. verifica token del processo servizio, DACL pipe e ACL ricorsive storage;
6. esegue A-D, stop/start SCM e manomissione/ripristino della key DPAPI;
7. registra `SecureIntegration-LiveMatrix-PostReboot-<RunId>` come task `SYSTEM` AtStartup;
8. riavvia la VM.

Dopo il reboot il task verifica il cambio di boot session, attende il servizio automatico, riusa secret reference ed envelope creati prima del reboot, ripete le negazioni critiche, analizza l'Event Log e crea il bundle.

## 4. Controllo del risultato

Dopo essersi riconnessi alla VM, aprire una PowerShell elevata:

```powershell
$runId = Get-Content "$env:ProgramData\SecureIntegration\LiveMatrix\last-run-id.txt"
$runRoot = "$env:ProgramData\SecureIntegration\LiveMatrix\$runId"
Get-Content "$runRoot\raw\post-reboot-summary.json" | ConvertFrom-Json | Format-List
Get-ChildItem "$runRoot\evidence"
Get-FileHash "$runRoot\evidence\M0-M1-live-matrix-$runId.zip" -Algorithm SHA256
Get-Content "$runRoot\evidence\M0-M1-live-matrix-$runId.zip.sha256"
git diff -- docs/reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md
```

I due hash ZIP devono coincidere. Aprire `bundle/manifest.json` e verificare gli hash per-file. Il bundle include configurazione SCM, SID/token, SDDL pipe, ACL storage, report dei processi, Event Log redatto e summary pre/post reboot; esclude password, input con canary, plaintext, secret, key blob, copia DPAPI ed envelope persistente.

## 5. Criteri fail-closed

La run termina con exit code non zero e non aggiorna la matrice documentale se si verifica almeno uno dei seguenti casi:

- PowerShell non elevata o host non qualificato come VM;
- `StartName` o SID del token servizio diversi dalla virtual identity prevista;
- DACL pipe diversa da service SID più SID autorizzato;
- storage accessibile a un SID diverso da service, SYSTEM o Administrators;
- processo con path non registrato accettato dalla policy;
- secondo utente capace di aprire pipe o storage;
- DPAPI CurrentUser capace di unwrap sotto un'identità diversa;
- operazione non concessa o API di estrazione key/secret disponibile;
- envelope o key blob manomessi accettati;
- HMAC o Unprotect non utilizzabili dopo stop/start o reboot;
- Event Log privo di normal path, authentication denied, payload invalido, failure crittografico o key unwrap failure;
- presenza di un canary/secret pattern nei log.

Un failure è un risultato della review, non va convertito manualmente in PASS. Conservare `failure-<Phase>.json`, diagnosticare e ripetere sulla stessa snapshot o su una nuova VM.

## 6. Ripresa e diagnostica

Se il reboot è stato eseguito ma il task non è partito, non simulare la fase. Avviarla manualmente, sempre elevata e sulla stessa boot session post-reboot:

```powershell
.\tools\live-matrix\Invoke-LiveMatrix.ps1 -Phase PostReboot -RunId $runId
```

Per ispezionare un failure:

```powershell
Get-ScheduledTask -TaskName "SecureIntegration-LiveMatrix-PostReboot-$runId" -ErrorAction SilentlyContinue
Get-ScheduledTaskInfo -TaskName "SecureIntegration-LiveMatrix-PostReboot-$runId" -ErrorAction SilentlyContinue
Get-ChildItem "$runRoot\raw"
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='SecureIntegrationBroker' } -MaxEvents 50
sc.exe qc SecureIntegrationBroker
```

La fase post-reboot rifiuta esplicitamente di procedere se non osserva un nuovo `LastBootUpTime`.

## 7. Cleanup

Dopo avere copiato il bundle e il relativo hash fuori dalla VM:

```powershell
.\tools\live-matrix\Remove-LiveMatrix.ps1 -RunId $runId -Confirm:$false
```

Questo rimuove servizio, task, account sintetici, binari, storage Broker, credenziali e exchange, preservando evidence/raw della run. Su una VM destinata al revert si può eliminare anche l'evidenza locale:

```powershell
.\tools\live-matrix\Remove-LiveMatrix.ps1 -RunId $runId -PurgeEvidence -Confirm:$false
```

Infine ripristinare o eliminare la snapshot/VM secondo la policy del laboratorio.

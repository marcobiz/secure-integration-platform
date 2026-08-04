# M3A split-host — esecuzione manuale nella VM

## Mandato

Questa procedura non richiede Codex elevato nella VM. Un operatore apre una console
**Windows PowerShell 5.1 come amministratore** ed esegue un solo script revisionato,
generato e trasferito dal repository candidato. SYSTEM non è usato per orchestrare la
fase VM: l'identità privilegiata serve soltanto a installare il vero Windows Service e a
creare l'utente standard di test.

Non avviare M3B/M4, non modificare o unire la PR #3 e non dichiarare PASS senza
`RESULT.json` PASS e attraversamento reale del Broker.

## Handoff atteso

`Prepare` crea e verifica nella VM la directory:

```text
C:\Lab\M3A\<RUN-ID>\
  input.zip
  input.zip.sha256
  Invoke-M3ASplitVmOperator.ps1
  Invoke-M3ASplitVmOperator.ps1.sha256
  RUNID.txt
```

`input.zip` contiene materiale sintetico raw per-run e non deve essere aperto, stampato,
committato o trasferito altrove. Lo script operatore non contiene segreti. Il suo hash
SHA-256 viene restituito da `Prepare` e deve essere usato nel comando, così una modifica
allo script o al sidecar causa un arresto fail-closed.

## Comando unico

Dalla console amministrativa nella VM eseguire esattamente il valore `operatorCommand`
restituito da `Prepare`. La forma è:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File "C:\Lab\M3A\<RUN-ID>\Invoke-M3ASplitVmOperator.ps1" `
  -RunId <RUN-ID> `
  -ExpectedScriptSha256 <SHA-256-SCRIPT>
```

Non aggiungere activation code, password o contenuto del bootstrap alla command line.

## Contratto dello script

Lo script:

1. richiede una console amministrativa e verifica RunId, hash proprio, hash ZIP e sidecar;
2. estrae l'handoff senza stampare o serializzare `bootstrap.json`;
3. rifiuta endpoint Gateway loopback e una finestra residua inferiore a 45 minuti;
4. richiede worktree VM pulito, esegue `fetch` e passa al candidate commit in detached HEAD;
5. avvia `ValidateVm` in un processo PowerShell 5.1 separato;
6. soltanto dopo `ValidateVm` PASS avvia `Run` con la stessa RunId, lo stesso input, lo
   stesso commit e lo stesso output;
7. lascia al runner l'installazione del Broker come vero servizio con StartName
   `NT SERVICE\SecureIntegrationBroker` e l'esecuzione del Legacy Simulator con utente
   standard e task `RunLevel Limited`;
8. produce sempre il risultato canonico
   `C:\SecureEvidence\<RUN-ID>\RESULT.json`, con soli codici redatti;
9. restituisce exit code zero soltanto quando anche il `RESULT.json` del runner e
   `vm-manifest.json` attestano PASS sul candidate commit.

Un `BLOCKED`, un exit code non zero o l'assenza di uno dei due manifest impedisce il PASS.

## Handoff risultato

In caso di PASS, trasferire all'HOST soltanto:

- `<RunId>-vm-redacted.zip`;
- `<RunId>-vm-redacted.zip.sha256`;
- il `RESULT.json` canonico.

Non trasferire input, bootstrap, PFX, Event Log raw, canary, DPAPI/CNG o directory di
build. L'HOST verifica sidecar e manifest, esegue `Finalize`, correla gli scenari Gateway e
completa il cleanup.

## Cleanup VM

Il runner rimuove servizio, utente, diritto `SeBatchLogonRight`, certificato sintetico,
task e directory protette appartenenti alla RunId. Dopo che l'HOST ha acquisito il
risultato, l'operatore rimuove la sola directory handoff:

```powershell
$runId = '<RUN-ID>'
Set-Location C:\Lab\broker-gateway
.\tools\m3\split-host\Invoke-M3ASplitVm.ps1 -Phase Cleanup -RunId $runId
Remove-Item -LiteralPath ("C:\Lab\M3A\" + $runId) -Recurse -Force
```

Se il cleanup fallisce, ripristinare il checkpoint Hyper-V pre-run. Il checkpoint è la
recovery primaria del laboratorio; i cleanup automatici esistenti sono difesa operativa,
non proprietà di sicurezza del prodotto né criterio bloccante autonomo di M3.

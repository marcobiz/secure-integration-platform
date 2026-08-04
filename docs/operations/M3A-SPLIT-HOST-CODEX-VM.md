# M3A split-host — istruzioni esatte per Codex VM

## Mandato

Operare esclusivamente nella VM Windows 11. Non avviare M3B/M4, non modificare la PR
#3 e non dichiarare PASS senza attraversamento reale del Windows Service. Non usare
PowerShell Direct. Non pubblicare `input.zip`, `bootstrap.json`, activation code, raw
Event Log, canary o materiale CNG/DPAPI.

## 1. Preflight e pacchetto

Aprire **Windows PowerShell 5.1 come amministratore** nella VM:

```powershell
$runId = '<RUN-ID-RICEVUTO-DALL-HOST>'
$packageRoot = "C:\Lab\M3A\$runId"
$inputZip = Join-Path $packageRoot 'input.zip'
$sidecar = $inputZip + '.sha256'

if (-not (Test-Path $inputZip) -or -not (Test-Path $sidecar)) {
    throw 'Pacchetto o sidecar mancante'
}
$expected = ((Get-Content $sidecar -Raw) -split '\s+')[0].ToUpperInvariant()
$actual = (Get-FileHash $inputZip -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw 'SHA-256 pacchetto VM non corrispondente' }

$input = Join-Path $packageRoot 'input'
New-Item -ItemType Directory -Path $input -Force | Out-Null
Expand-Archive -LiteralPath $inputZip -DestinationPath $input -Force
$bootstrap = Get-Content (Join-Path $input 'bootstrap.json') -Raw | ConvertFrom-Json
if ($bootstrap.runId -ne $runId) { throw 'RunId non corrispondente' }
if ($bootstrap.gatewayBaseAddress -match 'localhost|127\.0\.0\.1|\[::1\]') {
    throw 'Endpoint Gateway loopback vietato'
}
Remove-Item -LiteralPath $inputZip, $sidecar -Force
```

Non stampare `$bootstrap`, perché contiene l'activation code. Registrare lo SHA
completo soltanto in memoria:

```powershell
$candidate = [string]$bootstrap.candidateCommit
```

## 2. Repository e collisioni

```powershell
Set-Location C:\Lab\broker-gateway
if (git status --porcelain) { throw 'Worktree VM non pulito' }
git fetch --prune origin
git cat-file -e "$candidate^{commit}"
if ($LASTEXITCODE -ne 0) { throw 'Commit candidato non disponibile' }

Get-CimInstance Win32_Service -Filter "Name='SecureIntegrationBroker'" |
    Select-Object Name,State,StartName,PathName
```

Se il servizio esiste, fermarsi. Rimuoverlo soltanto con il cleanup dell'harness che
lo possiede, dopo aver verificato il binary path. Non usare `sc delete` alla cieca.

Preflight del runner:

```powershell
.\tools\m3\split-host\Invoke-M3ASplitVm.ps1 `
    -Phase ValidateVm -RunId $runId -RepositoryRoot C:\Lab\broker-gateway
```

## 3. Run VM

```powershell
$output = "C:\SecureEvidence\$runId\vm-redacted"
.\tools\m3\split-host\Invoke-M3ASplitVm.ps1 `
    -Phase Run `
    -RunId $runId `
    -InputDirectory $input `
    -OutputDirectory $output `
    -RepositoryRoot C:\Lab\broker-gateway
```

Il runner autonomamente:

1. esegue fetch e detached checkout dello SHA esatto ricevuto;
2. pubblica Broker e Legacy Simulator dal commit;
3. crea un utente locale standard per-run, mai membro Administrators;
4. installa `SecureIntegrationBroker` con
   `NT SERVICE\SecureIntegrationBroker`, service SID unrestricted e ACL protette;
5. importa soltanto la CA sintetica pubblica;
6. esegue il Legacy Simulator mediante task temporaneo `RunLevel Limited`;
7. dimostra P02 e il grant denial attraverso Broker→Gateway HOST;
8. esegue una copia non registrata dello stesso eseguibile sotto lo stesso utente e
   richiede il diniego path-policy con audit `application_not_authorized`;
9. rimuove activation code da registry e disco subito dopo l'enrollment;
10. scansiona report/Event Log, produce evidence redatta e completa il cleanup.

Il runner fallisce se il service token SID non coincide, l'utente è amministratore,
le ACL storage includono altri principal, P02 non passa, l'app non autorizzata passa,
una canary compare o il cleanup non è completo.

## 4. Verifica risultato

```powershell
$archive = "C:\SecureEvidence\$runId\$runId-vm-redacted.zip"
$archiveSidecar = $archive + '.sha256'
$expected = ((Get-Content $archiveSidecar -Raw) -split '\s+')[0].ToUpperInvariant()
$actual = (Get-FileHash $archive -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw 'SHA-256 risultato VM non corrispondente' }

$manifest = Get-Content (Join-Path $output 'vm-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.status -ne 'PASS' -or $manifest.commitSha -ne $candidate) { throw 'Manifest VM non valido' }
if ($manifest.cleanup.status -ne 'PASS' -or $manifest.cleanup.remainingServices -ne 0 -or $manifest.cleanup.remainingTasks -ne 0) {
    throw 'Cleanup VM incompleto'
}
Get-Service SecureIntegrationBroker -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName "SecureIntegration-M3A-$runId-*" -ErrorAction SilentlyContinue
git status --short
```

Le prime due query devono restituire zero elementi; il worktree deve essere pulito.
Non cancellare il risultato redatto finché l'HOST non ne verifica sidecar e contenuto.

## 5. Handoff all'HOST

Trasferire esclusivamente:

- `<RunId>-vm-redacted.zip`;
- `<RunId>-vm-redacted.zip.sha256`.

È ammesso un asset di release **privata** temporanea, mai un commit Git. Prima
dell'upload ispezionare l'archivio e confermare che contenga soltanto:

- `vm-manifest.json`;
- `legacy-simulator.json`;
- `unauthorized-application.json`;
- `broker-events-redacted.json`.

Non caricare la directory input o output raw. Conservare branch remoto e PR #3; non
fare merge, tag baseline, rebase, squash o force push.

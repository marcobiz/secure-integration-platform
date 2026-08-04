# M3A live gate — split-host runbook

## Stato e confini

Questo runbook prepara il gate manuale M3A; non autorizza M3B, M4, il merge della PR
#3 o l'uso di un runner GitHub self-hosted permanente. Il commit candidato è sempre lo
SHA completo scritto da `Prepare` nel pacchetto VM. Una run è valida soltanto se HOST e
VM attestano quello stesso SHA.

```mermaid
flowchart LR
    subgraph VM[Windows 11 Hyper-V]
        L[Legacy Simulator<br/>utente standard] -->|Named Pipe ACL| B[Local Broker<br/>Windows Service<br/>NT SERVICE\\SecureIntegrationBroker]
    end
    subgraph HOST[Windows 10 + Docker Desktop WSL 2]
        G[Gateway HTTPS] --> P[(PostgreSQL 18)]
        G --> V[Synthetic vault HTTPS]
        G -->|API key + mTLS| M[Vendor mock HTTPS/mTLS]
    end
    B -->|installation auth + PoP<br/>solo IP Hyper-V:porta Gateway| G
    F[Windows Firewall<br/>VM IP + Gateway port] -. limita .-> G
```

PostgreSQL, vault e mock sono pubblicati soltanto su `127.0.0.1` dell'HOST. Il
Gateway è associato esclusivamente all'IPv4 dell'adattatore Hyper-V. Il firewall
consente TCP in ingresso soltanto dall'IPv4 della VM e soltanto sulla porta Gateway.
Il pacchetto VM non contiene indirizzi di PostgreSQL, vault o mock.

Il profilo Windows Firewall non è dedotto dal nome della VM o da un profilo scelto
manualmente: deve esistere un solo `Get-NetConnectionProfile` per l'`InterfaceIndex`
dell'IPv4 HOST. Il runner rifiuta l'interfaccia se il profilo non è risolvibile o se
lo stesso profilo è usato da un'altra connessione attiva. Una regola appartenente a
un profilo disabilitato non costituisce enforcement.

## Prerequisiti HOST

- Windows 10 22H2 supportato, virtualizzazione e WSL 2 attivi;
- Docker Desktop avviato con Linux containers e backend WSL 2;
- PowerShell 5.1 elevato per firewall e trust store;
- branch `m3/production-like-vertical-slice` pulito e sincronizzato;
- VM Windows 11 Running e IPv4 stabile sulla rete Hyper-V;
- `C:\SecureEvidence` fuori dal repository.

Verifica non mutante:

```powershell
Set-Location C:\Codice\broker-gateway
$runId = 'm3a-split-' + (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
.\tools\m3\split-host\Invoke-M3ASplitHost.ps1 -Phase ValidateHost -RunId $runId
```

Se compare `M3A_SPLIT_DOCKER_DESKTOP_NOT_INSTALLED`, fermarsi. Scaricare solo
l'installer dalla [pagina ufficiale Docker Desktop per
Windows](https://docs.docker.com/desktop/setup/install/windows-install/), verificare i
requisiti e ottenere l'approvazione dell'utente per licenza, installer ed eventuale
UAC. Per il requisito di questo gate scegliere backend WSL 2 e Linux containers. Non
usare `--accept-license` senza approvazione esplicita. Dopo l'avvio, selezionare **Use
WSL 2 based engine** come indicato dalla [documentazione ufficiale
WSL](https://docs.docker.com/desktop/features/wsl/) e rieseguire `ValidateHost`.

## Selezione rete e VM

Non usare il nome VM come identificatore. In una console Hyper-V elevata:

```powershell
$vmId = [guid]'<VM-ID-UNIVOCO>'
$vm = Get-VM -Id $vmId -ErrorAction Stop
$vm | Format-List Name,Id,State,Status,ConfigurationLocation,Path,Uptime
$vm | Get-VMNetworkAdapter | Format-Table Name,SwitchName,Status,IPAddresses
Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object InterfaceAlias -Like 'vEthernet*' |
    Format-Table InterfaceAlias,IPAddress,PrefixLength
```

La run usa un secondo switch Hyper-V Internal chiamato `M3A-Isolated` e una seconda
NIC VM omonima. La NIC di management collegata al Default Switch non viene sostituita
o scollegata. La configurazione predefinita, subordinata al controllo conflitti, è:

- subnet `192.168.250.0/29`;
- HOST `192.168.250.1/29`;
- VM `192.168.250.2/29`;
- nessun DHCP, NAT, gateway, DNS o forwarding sul segmento;
- DHCP Guard, Router Guard e MAC spoofing disabilitato sulla NIC VM M3A.

Il runner registra inventario e checkpoint prima della mutazione. Un task SYSTEM
per-run ripristina profili firewall e Tailscale e rimuove esclusivamente la NIC e lo
switch M3A dopo 30 minuti. Il Default Switch è fuori dai target di rollback.

Verificare anche l'associazione firewall, senza mutazioni:

```powershell
$hostAddress = '192.168.250.1'
$hostNic = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $hostAddress
Get-NetConnectionProfile -InterfaceIndex $hostNic.InterfaceIndex
Get-NetFirewallProfile -PolicyStore ActiveStore -Name Domain,Private,Public |
    Format-Table Name,Enabled
```

`M3A_SPLIT_FIREWALL_PROFILE_UNRESOLVED_DEDICATED_SWITCH_REQUIRED` e
`M3A_SPLIT_FIREWALL_PROFILE_SHARED_DEDICATED_SWITCH_REQUIRED` sono blocker
pre-handoff. Non aggirarli con `-Profile Any` o abilitando tutti i profili. Predisporre
una rete Hyper-V interna dedicata e sottoporla a nuova verifica; se il relativo profilo
è condiviso con una rete necessaria all'HOST, valutarne prima l'impatto o rendere la
categoria realmente isolata.

## Prepare HOST

```powershell
Set-Location C:\Codice\broker-gateway
git fetch --prune origin
git switch m3/production-like-vertical-slice
git pull --ff-only
$candidate = (git rev-parse HEAD).Trim()
if (git status --porcelain) { throw 'Worktree non pulito' }

$hostHyperVAddress = '192.168.250.1'
$vmAddress = '192.168.250.2'
$vmId = [guid]'5ff35721-5181-4b69-b30a-6ff53fa8c842'
$vmCredential = Get-Credential -UserName 'LabAdmin' `
    -Message 'Credenziale locale VM per configurare esclusivamente la NIC M3A-Isolated'
.\tools\m3\split-host\Invoke-M3ASplitHost.ps1 `
    -Phase Prepare `
    -RunId $runId `
    -CandidateCommit $candidate `
    -HostHyperVAddress $hostHyperVAddress `
    -VmAddress $vmAddress `
    -GatewayPort 28443 `
    -VmId $vmId `
    -VmCredential $vmCredential `
    -IsolatedSwitchName 'M3A-Isolated' `
    -IsolatedVmNicName 'M3A-Isolated' `
    -IsolatedNetworkAddress '192.168.250.0' `
    -IsolatedPrefixLength 29
$vmCredential = $null
```

`Prepare`:

- genera CA e certificati sintetici per-run; il SAN Gateway contiene l'IP HOST e le
  identità realmente usate dal probe interno (`localhost` e `127.0.0.1`);
- avvia Gateway, PostgreSQL 18, vault e mock con un Compose project per-run;
- richiede `healthy` per Gateway/PostgreSQL oltre a live/readiness HTTP 200;
- salva gli stati originali Domain/Private/Public, crea un rollback SYSTEM a scadenza,
  abilita soltanto il profilo associato e crea una regola limitata a interfaccia, IP VM,
  IP HOST e porta Gateway;
- verifica la regola nell'`ActiveStore` e rifiuta un profilo non enforcing;
- disabilita temporaneamente soltanto l'adattatore HOST Tailscale dopo l'attivazione
  del rollback; Private deve risultare associato soltanto a `M3A-Isolated`;
- tramite PowerShell Direct verifica la connettività Internet della NIC management e
  prova che dalla VM siano raggiungibili soltanto HOST `192.168.250.1:28443`, non la
  stessa porta su Default Switch/LAN né PostgreSQL, vault e vendor mock;
- produce `C:\SecureEvidence\<RunId>\<RunId>-vm-input.zip` e sidecar;
- restituisce `AWAITING_VM`, non un PASS.

Il ZIP VM contiene activation code monouso ed è materiale raw temporaneo. Non
caricarlo su GitHub, non inserirlo in evidence redatta e non copiarlo nel repository.
Il task fail-safe scade 30 minuti dopo `Prepare`: completare l'handoff e il test VM
entro tale finestra oppure eseguire cleanup e iniziare una nuova run con nuovi
certificati e activation code.

## Trasferimento HOST → VM

Usare l'integrazione Hyper-V Guest Service Interface, senza PowerShell Direct e senza
eseguire comandi nella VM dall'HOST:

```powershell
$guestService = $vm | Get-VMIntegrationService |
    Where-Object Name -EQ 'Guest Service Interface'
if (-not $guestService.Enabled) {
    throw 'Abilitare Guest Service Interface solo dopo approvazione operativa.'
}
$source = "C:\SecureEvidence\$runId\$runId-vm-input.zip"
$sidecar = $source + '.sha256'
Copy-VMFile -VM $vm -SourcePath $source `
    -DestinationPath "C:\Lab\M3A\$runId\input.zip" `
    -FileSource Host -CreateFullPath
Copy-VMFile -VM $vm -SourcePath $sidecar `
    -DestinationPath "C:\Lab\M3A\$runId\input.zip.sha256" `
    -FileSource Host -CreateFullPath
```

Non abilitare servizi d'integrazione, checkpoint o sessioni remote automaticamente.
Se Guest Service Interface non è già abilitato, fermarsi per la decisione del
responsabile VM.

## Esecuzione Codex VM

Seguire senza variazioni [M3A split-host — istruzioni Codex
VM](M3A-SPLIT-HOST-CODEX-VM.md). Il risultato accettabile è un archivio **redatto**
con sidecar, `vm-manifest.json`, `legacy-simulator.json` e cleanup PASS. Il Broker deve
essere stato osservato Running con process token del service SID; un processo legacy
deve aver attraversato realmente la Named Pipe e il Gateway HOST.

Il risultato VM può essere trasferito tramite asset di una release privata temporanea
GitHub o un canale amministrativo approvato. Non committare evidence. Per una release
privata:

```powershell
# nella VM, dopo aver verificato che l'archivio sia soltanto redatto
$tag = "evidence-$runId"
gh release create $tag --repo marcobiz/secure-integration-platform `
    --prerelease --title "Redacted $runId" --notes "M3A VM redacted evidence only"
gh release upload $tag "C:\SecureEvidence\$runId\$runId-vm-redacted.zip" `
    "C:\SecureEvidence\$runId\$runId-vm-redacted.zip.sha256" `
    --repo marcobiz/secure-integration-platform
```

Sul HOST scaricare in `C:\SecureEvidence\<RunId>\vm-transfer`, verificare il sidecar
e decomprimere in `vm-result`. Il repository Git resta estraneo al trasferimento.

## Finalize HOST

```powershell
$vmResult = "C:\SecureEvidence\$runId\vm-result"
.\tools\m3\split-host\Invoke-M3ASplitHost.ps1 `
    -Phase Finalize `
    -RunId $runId `
    -CandidateCommit $candidate `
    -HostHyperVAddress $hostHyperVAddress `
    -VmAddress $vmAddress `
    -GatewayPort 28443 `
    -VmResultDirectory $vmResult
```

`Finalize` verifica il manifest VM, esegue sullo stack reale N01–N14 con il
SecurityDriver, scansiona log e report usando tutte le canary note all'HOST, registra
digest immagini, checksum migration, fingerprint pubblici, SID, firewall e scenari,
quindi esegue il cleanup prima di creare il bundle redatto.

PASS richiede contemporaneamente:

- P02 e operation-grant denial attraverso il vero Broker Service;
- applicazione locale non autorizzata negata e auditata;
- N01 revoca, N03 replay, N04 tenant alterato, N07 URL arbitrario, N10 secret
  reference arbitraria e gli altri scenari SecurityDriver PASS;
- nessun activation code, vendor key, token, password o payload canary nei log;
- zero container e volumi del project, zero regole firewall temporanee;
- zero network e task rollback temporanei e ripristino esatto degli stati originali
  Domain/Private/Public;
- attestazione VM con zero servizi e task di test residui.

Il risultato è `C:\SecureEvidence\<RunId>\<RunId>-redacted-evidence.zip` con sidecar
SHA-256. Raw evidence rimane fuori Git e soggetta alla retention del laboratorio.

## Cleanup di emergenza

HOST:

```powershell
.\tools\m3\split-host\Invoke-M3ASplitHost.ps1 -Phase Cleanup -RunId $runId
```

VM, dentro una console elevata:

```powershell
Set-Location C:\Lab\broker-gateway
.\tools\m3\split-host\Invoke-M3ASplitVm.ps1 -Phase Cleanup -RunId $runId
```

Gli script rifiutano di eliminare un servizio con binary path esterno alla directory
della run. Una collisione con un `SecureIntegrationBroker` preesistente è un blocker:
identificarne proprietà e ownership prima di rimuoverlo con il relativo harness.

Il cleanup HOST rimuove regola, container, volumi e network, ripristina i tre stati
firewall dal record per-run, riabilita Tailscale se originariamente attivo, rimuove
soltanto la NIC VM e lo switch `M3A-Isolated` e cancella i task di rollback. Se la
sessione termina prima, il task SYSTEM esegue lo stesso ripristino dopo 30 minuti
senza password persistite. Un esito con `firewallProfileRestored=false` o
`isolatedNetworkRestored=false` non è PASS.

[CmdletBinding()]
param(
    [ValidateSet('ValidateHost', 'Prepare', 'Finalize', 'Cleanup')]
    [string] $Phase = 'ValidateHost',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{5,39}$')]
    [string] $RunId = ('m3a-split-' + (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')),
    [string] $CandidateCommit,
    [string] $HostHyperVAddress,
    [string] $VmAddress,
    [ValidateRange(1024, 65535)] [int] $GatewayPort = 28443,
    [string] $EvidenceRoot = 'C:\SecureEvidence',
    [string] $VmResultDirectory,
    [guid] $VmId = [guid]::Empty,
    [Management.Automation.PSCredential] $VmCredential,
    [string] $IsolatedSwitchName = 'M3A-Isolated',
    [string] $IsolatedVmNicName = 'M3A-Isolated',
    [string] $IsolatedNetworkAddress = '192.168.250.0',
    [ValidateRange(29, 30)] [int] $IsolatedPrefixLength = 29,
    [ValidateRange(30, 180)] [int] $RollbackTimeoutMinutes = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$composeFile = Join-Path $repositoryRoot 'deploy\m3\docker-compose.m3a.yml'
$runRoot = Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) $RunId
$rawRoot = Join-Path $runRoot 'raw'
$redactedRoot = Join-Path $runRoot 'redacted'
$statePath = Join-Path $runRoot 'host-state.json'
$firewallStatePath = Join-Path $runRoot 'firewall-state.json'
$firewallRollbackPath = Join-Path $runRoot 'firewall-rollback.ps1'
$networkStatePath = Join-Path $runRoot 'network-state.json'
$networkInventoryPath = Join-Path $runRoot 'pre-network-inventory.json'
$networkRollbackPath = Join-Path $runRoot 'network-rollback.ps1'
$environmentPath = Join-Path $rawRoot 'm3a.env'
$provisioningPath = Join-Path $rawRoot 'provisioning.json'
$firewallName = 'SecureIntegration M3A split ' + $RunId
$projectName = ($RunId.ToLowerInvariant() -replace '[^a-z0-9_-]', '-')
$firewallRollbackTask = 'SecureIntegration-M3A-FirewallRollback-' + ($RunId -replace '[^A-Za-z0-9_-]', '-')
$networkRollbackTask = 'SecureIntegration-M3A-NetworkRollback-' + ($RunId -replace '[^A-Za-z0-9_-]', '-')
$rootThumbprint = $null
Import-Module (Join-Path $PSScriptRoot 'M3ASplitFirewall.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'M3ASplitNetwork.psm1') -Force

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'M3A_SPLIT_REQUIRES_ELEVATION: open Windows PowerShell 5.1 as Administrator.'
    }
}

function Invoke-NativeChecked {
    param([Parameter(Mandatory)] [string] $FilePath, [Parameter(Mandatory)] [string[]] $Arguments)
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $FilePath @Arguments 2>&1 | ForEach-Object { Write-Host $_ }
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousPreference }
    if ($exitCode -ne 0) { throw "M3A_SPLIT_NATIVE_FAILED: $FilePath exited with $exitCode." }
}

function Get-DotnetPath {
    $local = Join-Path $repositoryRoot '.dotnet\dotnet.exe'
    if (Test-Path -LiteralPath $local) { return $local }
    return (Get-Command dotnet -ErrorAction Stop).Source
}

function Read-EnvironmentFile {
    param([Parameter(Mandatory)] [string] $Path)
    $values = @{}
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $separator = $line.IndexOf('=')
        if ($separator -le 0) { throw 'M3A_SPLIT_INVALID_ENVIRONMENT_FILE.' }
        $values[$line.Substring(0, $separator)] = $line.Substring($separator + 1)
    }
    return $values
}

function Write-JsonFile {
    param([Parameter(Mandatory)] $Value, [Parameter(Mandatory)] [string] $Path)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 16), [Text.UTF8Encoding]::new($false))
}

function Add-HostBindingsToEnvironmentFile {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $HostAddress,
        [Parameter(Mandatory)] [int] $Port
    )
    $hostBindings = @(
        ('M3_GATEWAY_BIND_IP=' + $HostAddress)
        ('M3_GATEWAY_PORT=' + $Port)
        'M3_POSTGRES_BIND_IP=127.0.0.1'
        'M3_POSTGRES_PORT=15432'
        'M3_VAULT_BIND_IP=127.0.0.1'
        'M3_VAULT_PORT=18444'
        'M3_VENDOR_BIND_IP=127.0.0.1'
        'M3_VENDOR_PORT=18445'
    )
    [IO.File]::AppendAllText($Path, (($hostBindings -join [Environment]::NewLine) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
}

function Assert-OutsideRepository {
    $repo = [IO.Path]::GetFullPath($repositoryRoot).TrimEnd('\') + '\'
    $target = [IO.Path]::GetFullPath($runRoot).TrimEnd('\') + '\'
    if ($target.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'M3A_SPLIT_EVIDENCE_INSIDE_REPOSITORY.'
    }
}

function Assert-HostPrerequisites {
    $dockerDesktop = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe'),
        (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Docker\Docker\Docker Desktop.exe')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if (-not $dockerDesktop) { throw 'M3A_SPLIT_DOCKER_DESKTOP_NOT_INSTALLED.' }
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if ($null -eq $docker) { throw 'M3A_SPLIT_DOCKER_CLI_NOT_FOUND.' }
    $serverOs = (& $docker.Source version --format '{{.Server.Os}}' 2>$null).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'M3A_SPLIT_DOCKER_ENGINE_UNAVAILABLE.' }
    if ($serverOs -ne 'linux') { throw 'M3A_SPLIT_REQUIRES_LINUX_CONTAINERS.' }
    $compose = (& $docker.Source compose version --short 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($compose)) { throw 'M3A_SPLIT_COMPOSE_UNAVAILABLE.' }
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if ($null -eq $wsl) { throw 'M3A_SPLIT_WSL_NOT_FOUND.' }
    & $wsl.Source --status *> $null
    if ($LASTEXITCODE -ne 0) { throw 'M3A_SPLIT_WSL_UNAVAILABLE.' }
    $kernel = (& $wsl.Source -d docker-desktop -- uname -s 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $kernel -ne 'Linux') { throw 'M3A_SPLIT_WSL2_BACKEND_NOT_ACTIVE.' }
    return [ordered]@{
        dockerDesktop = $dockerDesktop
        dockerServer = (& $docker.Source version --format '{{.Server.Version}}').Trim()
        dockerOs = $serverOs
        compose = $compose
        wslBackend = 'docker-desktop/Linux'
    }
}

function Assert-Address {
    param([Parameter(Mandatory)] [string] $Value, [Parameter(Mandatory)] [string] $Name)
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Value, [ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or [Net.IPAddress]::IsLoopback($parsed)) {
        throw "M3A_SPLIT_INVALID_${Name}_ADDRESS."
    }
}

function Assert-PortFree {
    param([Parameter(Mandatory)] [string] $Address, [Parameter(Mandatory)] [int] $Port)
    if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) {
        throw "M3A_SPLIT_PORT_IN_USE: $Port."
    }
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($Address), $Port)
    try { $listener.Start() } catch { throw "M3A_SPLIT_PORT_NOT_BINDABLE: $Address`:$Port." } finally { $listener.Stop() }
}

function Get-ComposeArguments {
    param([Parameter(Mandatory)] [string[]] $Arguments)
    return @('compose', '-p', $projectName, '--env-file', $environmentPath, '-f', $composeFile) + $Arguments
}

function Wait-Gateway {
    param([Parameter(Mandatory)] [string] $Address)
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(4)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $provisioningPath) {
            try {
                $response = Invoke-WebRequest -UseBasicParsing -Uri $Address -TimeoutSec 5
                if ($response.StatusCode -eq 200) { return }
            }
            catch { }
        }
        Start-Sleep -Seconds 2
    }
    throw 'M3A_SPLIT_GATEWAY_NOT_READY.'
}

function Wait-ComposeServiceState {
    param(
        [Parameter(Mandatory)] [string] $Service,
        [Parameter(Mandatory)] [string] $ExpectedState,
        [string] $ExpectedHealth,
        [int] $TimeoutSeconds = 120
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $container = (& docker compose -p $projectName --env-file $environmentPath -f $composeFile ps -aq $Service 2>$null | Out-String).Trim()
        if ($container) {
            $inspection = (& docker inspect $container | ConvertFrom-Json)[0]
            $state = [string]$inspection.State.Status
            $healthProperty = $inspection.State.PSObject.Properties['Health']
            $health = if ($null -ne $healthProperty -and $null -ne $healthProperty.Value) { [string]$healthProperty.Value.Status } else { $null }
            if ($state -eq $ExpectedState -and ([string]::IsNullOrWhiteSpace($ExpectedHealth) -or $health -eq $ExpectedHealth)) { return }
            if ($health -eq 'unhealthy') { throw "M3A_SPLIT_REQUIRED_CONTAINER_UNHEALTHY: $Service." }
            if ($state -eq 'exited' -and $ExpectedState -ne 'exited') { throw "M3A_SPLIT_REQUIRED_CONTAINER_STOPPED: $Service." }
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "M3A_SPLIT_REQUIRED_CONTAINER_STATE_TIMEOUT: $Service expected $ExpectedState/$ExpectedHealth."
}

function Get-FirewallProfileStates {
    return @(Get-NetFirewallProfile -PolicyStore ActiveStore -Name Domain, Private, Public | ForEach-Object {
        [pscustomobject]@{ Name = [string]$_.Name; Enabled = [bool]$_.Enabled }
    })
}

function Resolve-HostFirewallSelection {
    param([Parameter(Mandatory)] $AddressRecord)

    $upIndices = @(Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty InterfaceIndex)
    $connectionProfiles = @(Get-NetConnectionProfile -ErrorAction Stop | Where-Object { $upIndices -contains [uint32]$_.InterfaceIndex })
    $firewallProfiles = Get-FirewallProfileStates
    return Resolve-M3AFirewallProfileSelection -InterfaceIndex ([uint32]$AddressRecord.InterfaceIndex) -ConnectionProfiles $connectionProfiles -FirewallProfiles $firewallProfiles
}

function Install-FirewallFailSafe {
    param(
        [Parameter(Mandatory)] $Selection,
        [ValidateRange(30, 180)] [int] $TimeoutMinutes
    )

    $profileStates = Get-FirewallProfileStates
    $rollbackAt = (Get-Date).AddMinutes($TimeoutMinutes)
    Write-JsonFile -Path $firewallStatePath -Value ([ordered]@{
        schemaVersion = 1
        runId = $RunId
        firewallRule = $firewallName
        rollbackTask = $firewallRollbackTask
        interfaceAlias = [string]$Selection.InterfaceAlias
        interfaceIndex = [uint32]$Selection.InterfaceIndex
        networkCategory = [string]$Selection.NetworkCategory
        selectedProfile = [string]$Selection.ProfileName
        originalProfiles = $profileStates
        rollbackTimeoutMinutes = $TimeoutMinutes
        rollbackDeadlineUtc = ([DateTimeOffset]$rollbackAt).ToUniversalTime().ToString('O')
        recordedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    })

    $escapedStatePath = $firewallStatePath.Replace("'", "''")
    $escapedTaskName = $firewallRollbackTask.Replace("'", "''")
    $rollback = @"
`$ErrorActionPreference = 'Continue'
`$state = Get-Content -LiteralPath '$escapedStatePath' -Raw | ConvertFrom-Json
Get-NetFirewallRule -DisplayName ([string]`$state.firewallRule) -ErrorAction SilentlyContinue | Remove-NetFirewallRule
foreach (`$profile in @(`$state.originalProfiles)) {
    Set-NetFirewallProfile -Name ([string]`$profile.Name) -Enabled ([string]`$profile.Enabled)
}
Unregister-ScheduledTask -TaskName '$escapedTaskName' -Confirm:`$false -ErrorAction SilentlyContinue
"@
    [IO.File]::WriteAllText($firewallRollbackPath, $rollback, [Text.UTF8Encoding]::new($false))

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $firewallRollbackPath + '"')
    $trigger = New-ScheduledTaskTrigger -Once -At $rollbackAt
    Register-ScheduledTask -TaskName $firewallRollbackTask -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    if ($null -eq (Get-ScheduledTask -TaskName $firewallRollbackTask -ErrorAction SilentlyContinue)) {
        throw 'M3A_SPLIT_FIREWALL_ROLLBACK_TASK_NOT_REGISTERED.'
    }
}

function Enable-SelectedFirewallProfile {
    param([Parameter(Mandatory)] $Selection)

    if (-not [bool]$Selection.OriginallyEnabled) {
        Set-NetFirewallProfile -Name ([string]$Selection.ProfileName) -Enabled True
    }
    $profile = Get-NetFirewallProfile -PolicyStore ActiveStore -Name ([string]$Selection.ProfileName)
    if (-not [bool]$profile.Enabled) { throw 'M3A_SPLIT_FIREWALL_PROFILE_NOT_ENFORCING.' }
}

function Assert-FirewallRuleEnforced {
    param(
        [Parameter(Mandatory)] $Selection,
        [Parameter(Mandatory)] [string] $HostAddress,
        [Parameter(Mandatory)] [string] $RemoteAddress,
        [Parameter(Mandatory)] [int] $Port
    )

    $profile = Get-NetFirewallProfile -PolicyStore ActiveStore -Name ([string]$Selection.ProfileName)
    $rule = Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName $firewallName -ErrorAction Stop
    $addressFilter = $rule | Get-NetFirewallAddressFilter
    $portFilter = $rule | Get-NetFirewallPortFilter
    $interfaceFilter = $rule | Get-NetFirewallInterfaceFilter
    if (
        -not [bool]$profile.Enabled -or
        [string]$rule.Enabled -ne 'True' -or
        [string]$rule.Direction -ne 'Inbound' -or
        [string]$rule.Action -ne 'Allow' -or
        [string]$rule.PrimaryStatus -ne 'OK' -or
        [string]$rule.Profile -notmatch ([regex]::Escape([string]$Selection.ProfileName)) -or
        $addressFilter.LocalAddress -notcontains $HostAddress -or
        $addressFilter.RemoteAddress -notcontains $RemoteAddress -or
        $portFilter.LocalPort -notcontains ([string]$Port) -or
        $interfaceFilter.InterfaceAlias -notcontains [string]$Selection.InterfaceAlias
    ) { throw 'M3A_SPLIT_FIREWALL_RULE_NOT_ENFORCED.' }
}

function Assert-VmExposureContract {
    param(
        [Parameter(Mandatory)] [guid] $ExactVmId,
        [Parameter(Mandatory)] [Management.Automation.PSCredential] $Credential,
        [Parameter(Mandatory)] [string] $DedicatedHostAddress,
        [Parameter(Mandatory)] [string] $DedicatedVmAddress,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [string] $SwitchName
    )
    $exactVm = Get-VM -Id $ExactVmId -ErrorAction Stop
    $expectedPort = @(Get-VMNetworkAdapter -VM $exactVm -Name $IsolatedVmNicName -ErrorAction SilentlyContinue | Where-Object { [string]$_.SwitchName -eq $SwitchName })
    $foreignPorts = @(Get-VM | Where-Object Id -ne $ExactVmId | ForEach-Object { Get-VMNetworkAdapter -VM $_ | Where-Object { [string]$_.SwitchName -eq $SwitchName } })
    if ($expectedPort.Count -ne 1 -or $foreignPorts.Count -ne 0) {
        throw 'M3A_SPLIT_ISOLATED_SWITCH_HAS_UNEXPECTED_PORT.'
    }
    $defaultSwitchAddress = Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -eq 'vEthernet (Default Switch)' | Select-Object -First 1 -ExpandProperty IPAddress
    $lanAddresses = @(Get-NetConnectionProfile | Where-Object { [string]$_.NetworkCategory -in @('Public', '0') } | ForEach-Object {
        Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -ExpandProperty IPAddress
    })
    $session = New-PSSession -VMId $ExactVmId -Credential $Credential
    try {
        $probe = Invoke-Command -Session $session -ArgumentList $DedicatedHostAddress, $DedicatedVmAddress, $Port, $defaultSwitchAddress, $lanAddresses -ScriptBlock {
            param($HostAddress, $VmAddress, $GatewayPort, $DefaultSwitchAddress, $LanAddresses)
            function CanConnect([string]$Address, [int]$TargetPort) {
                if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
                $client = [Net.Sockets.TcpClient]::new()
                try {
                    $pending = $client.BeginConnect($Address, $TargetPort, $null, $null)
                    if (-not $pending.AsyncWaitHandle.WaitOne(3000)) { return $false }
                    $client.EndConnect($pending)
                    return $client.Connected
                }
                catch { return $false }
                finally { $client.Dispose() }
            }
            $dedicatedIp = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $VmAddress -ErrorAction Stop
            $defaultRoutes = @(Get-NetRoute -InterfaceIndex $dedicatedIp.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object DestinationPrefix -eq '0.0.0.0/0')
            [pscustomobject]@{
                gateway = CanConnect $HostAddress $GatewayPort
                defaultSwitchGatewayPort = CanConnect $DefaultSwitchAddress $GatewayPort
                lanGatewayPort = @($LanAddresses | Where-Object { CanConnect $_ $GatewayPort }).Count -ne 0
                postgres = CanConnect $HostAddress 15432
                vault = CanConnect $HostAddress 18444
                vendor = CanConnect $HostAddress 18445
                dedicatedDefaultGatewayCount = $defaultRoutes.Count
            }
        }
    }
    finally { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    if (-not $probe.gateway -or $probe.defaultSwitchGatewayPort -or $probe.lanGatewayPort -or $probe.postgres -or $probe.vault -or $probe.vendor -or $probe.dedicatedDefaultGatewayCount -ne 0) {
        throw 'M3A_SPLIT_VM_EXPOSURE_CONTRACT_FAILED.'
    }
    return $probe
}

function Restore-FirewallState {
    if (-not (Test-Path -LiteralPath $firewallStatePath)) { return $true }
    $firewallState = Get-Content -LiteralPath $firewallStatePath -Raw | ConvertFrom-Json
    Get-NetFirewallRule -DisplayName ([string]$firewallState.firewallRule) -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    foreach ($profile in @($firewallState.originalProfiles)) {
        Set-NetFirewallProfile -Name ([string]$profile.Name) -Enabled ([string]$profile.Enabled)
    }
    Unregister-ScheduledTask -TaskName ([string]$firewallState.rollbackTask) -Confirm:$false -ErrorAction SilentlyContinue
    $restored = Test-M3AFirewallProfileStateRestored -OriginalStates @($firewallState.originalProfiles) -CurrentProfiles (Get-FirewallProfileStates)
    if ($restored) { Remove-Item -LiteralPath $firewallRollbackPath -Force -ErrorAction SilentlyContinue }
    return $restored
}

function Remove-HostResources {
    $state = if (Test-Path -LiteralPath $statePath) { Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } else { $null }
    if (Test-Path -LiteralPath $environmentPath) {
        try { Invoke-NativeChecked -FilePath 'docker.exe' -Arguments (Get-ComposeArguments -Arguments @('down', '--volumes', '--remove-orphans')) } catch { Write-Warning $_ }
    }
    $firewallRestored = Restore-FirewallState
    Get-NetFirewallRule -DisplayName $firewallName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $thumbprint = if ($null -ne $state) { [string]$state.hostRootThumbprint } else { [string]$rootThumbprint }
    if ($thumbprint) {
        Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq $thumbprint | Remove-Item -Force
    }
    $networkRestored = Remove-M3AIsolatedNetwork -StatePath $networkStatePath -RollbackPath $networkRollbackPath
    $remainingContainers = @(& docker ps -aq --filter ('label=com.docker.compose.project=' + $projectName) 2>$null)
    $remainingVolumes = @(& docker volume ls -q --filter ('label=com.docker.compose.project=' + $projectName) 2>$null)
    $remainingNetworks = @(& docker network ls -q --filter ('label=com.docker.compose.project=' + $projectName) 2>$null)
    $remainingRules = @(Get-NetFirewallRule -DisplayName $firewallName -ErrorAction SilentlyContinue)
    $remainingTasks = @(Get-ScheduledTask -TaskName $firewallRollbackTask -ErrorAction SilentlyContinue)
    $remainingNetworkTasks = @(Get-ScheduledTask -TaskName $networkRollbackTask -ErrorAction SilentlyContinue)
    return [ordered]@{
        status = if ($remainingContainers.Count -eq 0 -and $remainingVolumes.Count -eq 0 -and $remainingNetworks.Count -eq 0 -and $remainingRules.Count -eq 0 -and $remainingTasks.Count -eq 0 -and $remainingNetworkTasks.Count -eq 0 -and $firewallRestored -and $networkRestored) { 'PASS' } else { 'FAIL' }
        remainingContainers = $remainingContainers.Count
        remainingVolumes = $remainingVolumes.Count
        remainingNetworks = $remainingNetworks.Count
        remainingFirewallRules = $remainingRules.Count
        remainingFirewallRollbackTasks = $remainingTasks.Count
        remainingNetworkRollbackTasks = $remainingNetworkTasks.Count
        firewallProfileRestored = [bool]$firewallRestored
        isolatedNetworkRestored = [bool]$networkRestored
    }
}

Assert-OutsideRepository
if ($Phase -eq 'ValidateHost') {
    $prerequisites = Assert-HostPrerequisites
    $bindingProbe = [IO.Path]::GetTempFileName()
    try {
        Add-HostBindingsToEnvironmentFile -Path $bindingProbe -HostAddress '192.0.2.10' -Port 28443
        $bindingLines = [IO.File]::ReadAllLines($bindingProbe)
        if ($bindingLines.Count -ne 8 -or $bindingLines[0] -ne 'M3_GATEWAY_BIND_IP=192.0.2.10' -or $bindingLines[7] -ne 'M3_VENDOR_PORT=18445') {
            throw 'M3A_SPLIT_HOST_BINDING_SERIALIZATION_INVALID.'
        }
    }
    finally { Remove-Item -LiteralPath $bindingProbe -Force -ErrorAction SilentlyContinue }
    [pscustomobject]@{ phase = $Phase; runId = $RunId; status = 'PASS'; prerequisites = $prerequisites } | ConvertTo-Json -Depth 6
    exit 0
}

Assert-Administrator
if ($Phase -eq 'Cleanup') {
    $cleanup = Remove-HostResources
    $cleanup | ConvertTo-Json -Depth 5
    if ($cleanup.status -ne 'PASS') { exit 1 }
    exit 0
}

if ([string]::IsNullOrWhiteSpace($CandidateCommit)) { throw 'M3A_SPLIT_CANDIDATE_COMMIT_REQUIRED.' }
if ([string]::IsNullOrWhiteSpace($HostHyperVAddress)) { throw 'M3A_SPLIT_HOST_ADDRESS_REQUIRED.' }
if ([string]::IsNullOrWhiteSpace($VmAddress)) { throw 'M3A_SPLIT_VM_ADDRESS_REQUIRED.' }
Assert-Address -Value $HostHyperVAddress -Name 'HOST'
Assert-Address -Value $VmAddress -Name 'VM'
if ($HostHyperVAddress -eq $VmAddress) { throw 'M3A_SPLIT_ADDRESSES_MUST_DIFFER.' }

if ($Phase -eq 'Prepare') {
    $prerequisites = Assert-HostPrerequisites
    $head = (& git -C $repositoryRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -ne $CandidateCommit) { throw 'M3A_SPLIT_HEAD_MISMATCH.' }
    if (& git -C $repositoryRoot status --porcelain) { throw 'M3A_SPLIT_WORKTREE_NOT_CLEAN.' }
    & git -C $repositoryRoot merge-base --is-ancestor m2-gateway-baseline-2026-08-04 $head
    if ($LASTEXITCODE -ne 0) { throw 'M3A_SPLIT_M2_BASELINE_MISSING.' }
    if (Test-Path -LiteralPath $runRoot) { throw 'M3A_SPLIT_RUN_DIRECTORY_ALREADY_EXISTS.' }
    if ($VmId -eq [guid]::Empty) { throw 'M3A_SPLIT_VM_ID_REQUIRED.' }
    if ($null -eq $VmCredential) { throw 'M3A_SPLIT_VM_CREDENTIAL_REQUIRED.' }
    try {
    $checkpointName = 'pre-m3a-isolated-network-' + (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $network = New-M3AIsolatedNetwork -VmId $VmId -VmCredential $VmCredential -SwitchName $IsolatedSwitchName -VmNicName $IsolatedVmNicName -NetworkAddress $IsolatedNetworkAddress -HostAddress $HostHyperVAddress -VmAddress $VmAddress -PrefixLength $IsolatedPrefixLength -StatePath $networkStatePath -InventoryPath $networkInventoryPath -RollbackPath $networkRollbackPath -RollbackTaskName $networkRollbackTask -CheckpointName $checkpointName -RollbackTimeoutMinutes $RollbackTimeoutMinutes
    $addressRecord = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $HostHyperVAddress -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $addressRecord -or [string]$addressRecord.InterfaceAlias -ne ('vEthernet (' + $IsolatedSwitchName + ')')) { throw 'M3A_SPLIT_HOST_ADDRESS_NOT_ASSIGNED_TO_ISOLATED_SWITCH.' }
    $tailscaleIsolation = Disable-M3ATailscaleForIsolation -StatePath $networkStatePath -DedicatedInterfaceIndex ([uint32]$addressRecord.InterfaceIndex)
    $firewallSelection = Resolve-HostFirewallSelection -AddressRecord $addressRecord
    Assert-PortFree -Address $HostHyperVAddress -Port $GatewayPort
    foreach ($port in 15432, 18444, 18445) { Assert-PortFree -Address '127.0.0.1' -Port $port }
    New-Item -ItemType Directory -Path $rawRoot, $redactedRoot -Force | Out-Null
    $dotnet = Get-DotnetPath
    Invoke-NativeChecked -FilePath $dotnet -Arguments @('run', '--project', (Join-Path $repositoryRoot 'tools\m3\FixtureGenerator\FixtureGenerator.csproj'), '-c', 'Release', '--', $rawRoot, $HostHyperVAddress)
    Add-HostBindingsToEnvironmentFile -Path $environmentPath -HostAddress $HostHyperVAddress -Port $GatewayPort
    $installed = Import-Certificate -FilePath (Join-Path $rawRoot 'certificates\ca.crt') -CertStoreLocation Cert:\LocalMachine\Root
    $rootThumbprint = $installed.Thumbprint
        Install-FirewallFailSafe -Selection $firewallSelection -TimeoutMinutes $RollbackTimeoutMinutes
        Enable-SelectedFirewallProfile -Selection $firewallSelection
        New-NetFirewallRule -DisplayName $firewallName -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $HostHyperVAddress -RemoteAddress $VmAddress -LocalPort $GatewayPort -Profile ([string]$firewallSelection.ProfileName) -InterfaceAlias ([string]$firewallSelection.InterfaceAlias) | Out-Null
        Set-M3ANetworkFirewallRuleState -StatePath $networkStatePath -FirewallRule $firewallName
        Assert-FirewallRuleEnforced -Selection $firewallSelection -HostAddress $HostHyperVAddress -RemoteAddress $VmAddress -Port $GatewayPort
        Invoke-NativeChecked -FilePath 'docker.exe' -Arguments (Get-ComposeArguments -Arguments @('config', '--quiet'))
        Invoke-NativeChecked -FilePath 'docker.exe' -Arguments (Get-ComposeArguments -Arguments @('up', '--build', '--detach'))
        Wait-Gateway -Address ("https://${HostHyperVAddress}:${GatewayPort}/health/ready")
        Wait-ComposeServiceState -Service 'gateway' -ExpectedState 'running' -ExpectedHealth 'healthy'
        Wait-ComposeServiceState -Service 'postgres' -ExpectedState 'running' -ExpectedHealth 'healthy'
        Wait-ComposeServiceState -Service 'vault' -ExpectedState 'running'
        Wait-ComposeServiceState -Service 'vendor' -ExpectedState 'running'
        Wait-ComposeServiceState -Service 'migrations' -ExpectedState 'exited'
        Wait-ComposeServiceState -Service 'provisioner' -ExpectedState 'exited'
        $listener = Get-NetTCPConnection -State Listen -LocalPort $GatewayPort -ErrorAction Stop
        if (@($listener | Where-Object LocalAddress -eq $HostHyperVAddress).Count -eq 0 -or @($listener | Where-Object LocalAddress -ne $HostHyperVAddress).Count -ne 0) {
            throw 'M3A_SPLIT_GATEWAY_BIND_NOT_RESTRICTED.'
        }
        foreach ($port in 15432, 18444, 18445) {
            $internalListener = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction Stop
            if (@($internalListener | Where-Object LocalAddress -ne '127.0.0.1').Count -ne 0) { throw "M3A_SPLIT_INTERNAL_PORT_EXPOSED: $port." }
        }
        $exposure = Assert-VmExposureContract -ExactVmId $VmId -Credential $VmCredential -DedicatedHostAddress $HostHyperVAddress -DedicatedVmAddress $VmAddress -Port $GatewayPort -SwitchName $IsolatedSwitchName
        $provisioning = Get-Content -LiteralPath $provisioningPath -Raw | ConvertFrom-Json
        $vmInput = Join-Path $rawRoot 'vm-input'
        New-Item -ItemType Directory -Path $vmInput -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $rawRoot 'certificates\ca.crt') -Destination (Join-Path $vmInput 'ca.crt')
        $payloadCanary = 'M3_SPLIT_PAYLOAD_' + [Guid]::NewGuid().ToString('N')
        $rollbackDeadlineUtc = [string]((Get-Content -LiteralPath $firewallStatePath -Raw | ConvertFrom-Json).rollbackDeadlineUtc)
        Write-JsonFile -Path (Join-Path $vmInput 'bootstrap.json') -Value ([ordered]@{
            schemaVersion = 1
            runId = $RunId
            candidateCommit = $CandidateCommit
            rollbackDeadlineUtc = $rollbackDeadlineUtc
            gatewayBaseAddress = "https://${HostHyperVAddress}:${GatewayPort}/"
            installationId = [string]$provisioning.installationId
            activationCodeId = [string]$provisioning.activationCodeId
            activationCode = [string]$provisioning.activationCode
            payloadCanary = $payloadCanary
            caFile = 'ca.crt'
        })
        $archive = Join-Path $runRoot ($RunId + '-vm-input.zip')
        Compress-Archive -Path (Join-Path $vmInput '*') -DestinationPath $archive -CompressionLevel Optimal
        $archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
        [IO.File]::WriteAllText(($archive + '.sha256'), ($archiveHash + '  ' + [IO.Path]::GetFileName($archive) + [Environment]::NewLine), [Text.Encoding]::ASCII)
        $operatorSource = Join-Path $PSScriptRoot 'Invoke-M3ASplitVmOperator.ps1'
        $operatorCopy = Join-Path $runRoot 'Invoke-M3ASplitVmOperator.ps1'
        Copy-Item -LiteralPath $operatorSource -Destination $operatorCopy
        $operatorHash = (Get-FileHash -LiteralPath $operatorCopy -Algorithm SHA256).Hash
        [IO.File]::WriteAllText(($operatorCopy + '.sha256'), ($operatorHash + '  Invoke-M3ASplitVmOperator.ps1' + [Environment]::NewLine), [Text.Encoding]::ASCII)
        $runIdFile = Join-Path $runRoot 'RUNID.txt'
        [IO.File]::WriteAllText($runIdFile, ($RunId + [Environment]::NewLine), [Text.Encoding]::ASCII)
        $guestPackageRoot = 'C:\Lab\M3A\' + $RunId
        $handoffSession = New-PSSession -VMId $VmId -Credential $VmCredential
        try {
            Invoke-Command -Session $handoffSession -ArgumentList $guestPackageRoot -ScriptBlock {
                param($Path)
                if (Test-Path -LiteralPath $Path) { throw 'M3A_SPLIT_OPERATOR_HANDOFF_ALREADY_EXISTS.' }
                New-Item -ItemType Directory -Path $Path | Out-Null
            }
            Copy-Item -LiteralPath $archive -Destination (Join-Path $guestPackageRoot 'input.zip') -ToSession $handoffSession
            Copy-Item -LiteralPath ($archive + '.sha256') -Destination (Join-Path $guestPackageRoot 'input.zip.sha256') -ToSession $handoffSession
            Copy-Item -LiteralPath $operatorCopy -Destination (Join-Path $guestPackageRoot 'Invoke-M3ASplitVmOperator.ps1') -ToSession $handoffSession
            Copy-Item -LiteralPath ($operatorCopy + '.sha256') -Destination (Join-Path $guestPackageRoot 'Invoke-M3ASplitVmOperator.ps1.sha256') -ToSession $handoffSession
            Copy-Item -LiteralPath $runIdFile -Destination (Join-Path $guestPackageRoot 'RUNID.txt') -ToSession $handoffSession
            $handoffVerified = Invoke-Command -Session $handoffSession -ArgumentList $guestPackageRoot, $archiveHash, $operatorHash, $RunId -ScriptBlock {
                param($Path, $ExpectedInputHash, $ExpectedOperatorHash, $ExactRunId)
                $input = Join-Path $Path 'input.zip'
                $operator = Join-Path $Path 'Invoke-M3ASplitVmOperator.ps1'
                if ((Get-FileHash -LiteralPath $input -Algorithm SHA256).Hash -ne $ExpectedInputHash -or
                    (Get-FileHash -LiteralPath $operator -Algorithm SHA256).Hash -ne $ExpectedOperatorHash -or
                    [IO.File]::ReadAllText((Join-Path $Path 'RUNID.txt')).Trim() -ne $ExactRunId) {
                    throw 'M3A_SPLIT_OPERATOR_HANDOFF_TRANSFER_MISMATCH.'
                }
                $true
            }
        }
        finally { Remove-PSSession -Session $handoffSession -ErrorAction SilentlyContinue }
        if (-not $handoffVerified) { throw 'M3A_SPLIT_OPERATOR_HANDOFF_NOT_VERIFIED.' }
        Write-JsonFile -Path $statePath -Value ([ordered]@{
            schemaVersion = 1; runId = $RunId; candidateCommit = $CandidateCommit
            hostAddress = $HostHyperVAddress; vmAddress = $VmAddress; gatewayPort = $GatewayPort
            interfaceAlias = [string]$addressRecord.InterfaceAlias; composeProject = $projectName
            firewallRule = $firewallName; firewallProfile = [string]$firewallSelection.ProfileName
            firewallRollbackTask = $firewallRollbackTask; hostRootThumbprint = $rootThumbprint
            vmId = [string]$VmId; isolatedSwitch = $IsolatedSwitchName; isolatedVmNic = $IsolatedVmNicName
            isolatedVmNicMac = [string]$network.vmNicMacAddress; checkpoint = [string]$network.checkpointName
            tailscaleTemporarilyDisabled = [bool]$tailscaleIsolation.disabled; exposureContract = $exposure
            operatorScriptSha256 = $operatorHash; guestHandoffPath = $guestPackageRoot
            preparedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        })
        $operatorCommand = 'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $guestPackageRoot 'Invoke-M3ASplitVmOperator.ps1') + '" -RunId ' + $RunId + ' -ExpectedScriptSha256 ' + $operatorHash
        [pscustomobject]@{ runId = $RunId; status = 'WAITING_FOR_OPERATOR'; commit = $CandidateCommit; vmInput = $archive; vmInputSha256 = $archiveHash; operatorScriptSha256 = $operatorHash; guestHandoff = $guestPackageRoot; operatorCommand = $operatorCommand; gateway = "https://${HostHyperVAddress}:${GatewayPort}/" } | ConvertTo-Json -Compress
    }
    catch {
        try { Remove-HostResources | Out-Null } catch { }
        throw
    }
    exit 0
}

if (-not (Test-Path -LiteralPath $statePath)) { throw 'M3A_SPLIT_HOST_STATE_MISSING.' }
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
if ($state.candidateCommit -ne $CandidateCommit -or $state.hostAddress -ne $HostHyperVAddress -or $state.vmAddress -ne $VmAddress) { throw 'M3A_SPLIT_STATE_MISMATCH.' }
if ([string]::IsNullOrWhiteSpace($VmResultDirectory) -or -not (Test-Path -LiteralPath $VmResultDirectory -PathType Container)) { throw 'M3A_SPLIT_VM_RESULT_REQUIRED.' }
$vmManifestPath = Join-Path $VmResultDirectory 'vm-manifest.json'
$legacyReportPath = Join-Path $VmResultDirectory 'legacy-simulator.json'
if (-not (Test-Path -LiteralPath $vmManifestPath) -or -not (Test-Path -LiteralPath $legacyReportPath)) { throw 'M3A_SPLIT_VM_RESULT_INCOMPLETE.' }
$vmManifest = Get-Content -LiteralPath $vmManifestPath -Raw | ConvertFrom-Json
$legacy = Get-Content -LiteralPath $legacyReportPath -Raw | ConvertFrom-Json
if ($vmManifest.runId -ne $RunId -or $vmManifest.commitSha -ne $CandidateCommit -or $vmManifest.status -ne 'PASS' -or -not $legacy.passed) { throw 'M3A_SPLIT_VM_RESULT_FAILED.' }

try {
$generated = Read-EnvironmentFile -Path $environmentPath
$provisioning = Get-Content -LiteralPath $provisioningPath -Raw | ConvertFrom-Json
foreach ($pair in $generated.GetEnumerator()) { [Environment]::SetEnvironmentVariable($pair.Key, $pair.Value, 'Process') }
$env:M3_GATEWAY_BASE_ADDRESS = "https://${HostHyperVAddress}:${GatewayPort}/"
$env:M3_PROVISIONING_FILE = $provisioningPath
$env:M3_SECURITY_DRIVER_PFX = Join-Path $rawRoot 'certificates\security-driver.pfx'
$env:M3_POSTGRES_ADMIN_CONNECTION = 'Host=127.0.0.1;Port=15432;Database=broker_gateway_m3;Username=postgres;Password=' + $generated.M3_POSTGRES_ADMIN_PASSWORD + ';SSL Mode=Disable;GSS Encryption Mode=Disable'
$env:M3_SECURITY_OUTPUT = Join-Path $redactedRoot 'security-scenarios.json'
Invoke-NativeChecked -FilePath (Get-DotnetPath) -Arguments @('run', '--project', (Join-Path $repositoryRoot 'tools\m3\SecurityDriver\SecurityDriver.csproj'), '-c', 'Release')
$security = Get-Content -LiteralPath $env:M3_SECURITY_OUTPUT -Raw | ConvertFrom-Json
if (-not $security.passed) { throw 'M3A_SPLIT_SECURITY_SCENARIOS_FAILED.' }

& docker compose -p $projectName --env-file $environmentPath -f $composeFile logs --no-color 2>&1 | Set-Content -LiteralPath (Join-Path $rawRoot 'containers.log') -Encoding UTF8
$sensitive = @(
    [string]$provisioning.activationCode, [string]$provisioning.securityActivationCode,
    [string]$generated.M3_VENDOR_API_KEY, [string]$generated.M3_SYNTHETIC_VAULT_TOKEN,
    [string]$generated.M3_VENDOR_CONTROL_TOKEN, [string]$generated.M3_POSTGRES_ADMIN_PASSWORD,
    [string]$generated.M3_POSTGRES_RUNTIME_PASSWORD, [string]$generated.M3_CERTIFICATE_PASSWORD,
    [string]$generated.M3_ACTIVATION_HMAC_BASE64,
    [string](Get-Content -LiteralPath (Join-Path $rawRoot 'vm-input\bootstrap.json') -Raw | ConvertFrom-Json).payloadCanary
)
$scanFiles = @((Join-Path $rawRoot 'containers.log')) + @(Get-ChildItem -LiteralPath $VmResultDirectory -File -Recurse | Select-Object -ExpandProperty FullName)
foreach ($file in $scanFiles) {
    $content = [IO.File]::ReadAllText($file)
    foreach ($value in $sensitive) {
        if ($value -and $content.IndexOf($value, [StringComparison]::Ordinal) -ge 0) { throw "M3A_SPLIT_CANARY_FOUND: $([IO.Path]::GetFileName($file))." }
    }
}
if ((Get-Content -LiteralPath (Join-Path $rawRoot 'containers.log') -Raw) -match 'libgssapi_krb5') { throw 'M3A_SPLIT_GSS_WARNING_REAPPEARED.' }

Copy-Item -LiteralPath $legacyReportPath -Destination (Join-Path $redactedRoot 'legacy-simulator.json')
Copy-Item -LiteralPath $vmManifestPath -Destination (Join-Path $redactedRoot 'vm-manifest.json')
Copy-Item -LiteralPath (Join-Path $rawRoot 'fixture-public.json') -Destination (Join-Path $redactedRoot 'fixture-public.json')
$firewall = Get-NetFirewallRule -DisplayName $firewallName -ErrorAction Stop
$firewallAddress = $firewall | Get-NetFirewallAddressFilter
$firewallPort = $firewall | Get-NetFirewallPortFilter
Write-JsonFile -Path (Join-Path $redactedRoot 'firewall.json') -Value ([ordered]@{
    displayName = $firewallName; enabled = [string]$firewall.Enabled; direction = [string]$firewall.Direction; action = [string]$firewall.Action
    localAddress = @($firewallAddress.LocalAddress); remoteAddress = @($firewallAddress.RemoteAddress); protocol = [string]$firewallPort.Protocol; localPort = @($firewallPort.LocalPort)
})
$images = @()
foreach ($service in 'gateway', 'postgres', 'vault', 'vendor', 'migrations', 'provisioner') {
    $container = (& docker compose -p $projectName --env-file $environmentPath -f $composeFile ps -aq $service).Trim()
    if ($container) {
        $images += [ordered]@{ service = $service; imageDigest = (& docker inspect $container --format '{{.Image}}').Trim() }
    }
}
$migrationSha = (Get-FileHash -LiteralPath (Join-Path $repositoryRoot 'src\Gateway\Gateway.Infrastructure\Persistence\Migrations\0001_gateway_m2.sql') -Algorithm SHA256).Hash
$cleanup = Remove-HostResources
if ($cleanup.status -ne 'PASS') { throw 'M3A_SPLIT_HOST_CLEANUP_FAILED.' }
if ($vmManifest.cleanup.status -ne 'PASS' -or $vmManifest.cleanup.remainingServices -ne 0 -or $vmManifest.cleanup.remainingTasks -ne 0) { throw 'M3A_SPLIT_VM_CLEANUP_NOT_ATTESTED.' }
Remove-Item -LiteralPath (Join-Path $rawRoot 'vm-input\bootstrap.json') -Force -ErrorAction SilentlyContinue
$vmInputArchive = Join-Path $runRoot ($RunId + '-vm-input.zip')
Remove-Item -LiteralPath $vmInputArchive, ($vmInputArchive + '.sha256') -Force -ErrorAction SilentlyContinue
Write-JsonFile -Path (Join-Path $redactedRoot 'manifest.json') -Value ([ordered]@{
    schemaVersion = 1; environment = 'M3A-SPLIT-HOST'; scope = 'production-like-live'
    runId = $RunId; commitSha = $CandidateCommit; m2BaselineTag = 'm2-gateway-baseline-2026-08-04'
    completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O'); images = $images; migrationSha256 = $migrationSha
    brokerService = $vmManifest.brokerService; brokerSid = $vmManifest.brokerSid
    certificateFingerprints = (Get-Content -LiteralPath (Join-Path $rawRoot 'fixture-public.json') -Raw | ConvertFrom-Json)
    scenarios = [ordered]@{ legacy = $legacy.scenarios; gatewaySecurity = $security.scenarios }
    canaryScan = 'PASS'; firewall = 'firewall.json'; cleanup = [ordered]@{ host = $cleanup; vm = $vmManifest.cleanup }
})
$zipPath = Join-Path $runRoot ($RunId + '-redacted-evidence.zip')
Compress-Archive -Path (Join-Path $redactedRoot '*') -DestinationPath $zipPath -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
[IO.File]::WriteAllText(($zipPath + '.sha256'), ($hash + '  ' + [IO.Path]::GetFileName($zipPath) + [Environment]::NewLine), [Text.Encoding]::ASCII)
[pscustomobject]@{ runId = $RunId; status = 'PASS'; commit = $CandidateCommit; evidence = $zipPath; sha256 = $hash; cleanup = $cleanup } | ConvertTo-Json -Depth 8 -Compress
}
catch {
    $finalizeError = $_
    try { Remove-HostResources | Out-Null } catch { }
    throw $finalizeError
}

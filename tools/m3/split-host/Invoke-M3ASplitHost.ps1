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
    [string] $VmResultDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$composeFile = Join-Path $repositoryRoot 'deploy\m3\docker-compose.m3a.yml'
$runRoot = Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) $RunId
$rawRoot = Join-Path $runRoot 'raw'
$redactedRoot = Join-Path $runRoot 'redacted'
$statePath = Join-Path $runRoot 'host-state.json'
$environmentPath = Join-Path $rawRoot 'm3a.env'
$provisioningPath = Join-Path $rawRoot 'provisioning.json'
$firewallName = 'SecureIntegration M3A split ' + $RunId
$projectName = ($RunId.ToLowerInvariant() -replace '[^a-z0-9_-]', '-')
$rootThumbprint = $null

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'M3A_SPLIT_REQUIRES_ELEVATION: open Windows PowerShell 5.1 as Administrator.'
    }
}

function Invoke-NativeChecked {
    param([Parameter(Mandatory)] [string] $FilePath, [Parameter(Mandatory)] [string[]] $Arguments)
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) { throw "M3A_SPLIT_NATIVE_FAILED: $FilePath exited with $LASTEXITCODE." }
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

function Remove-HostResources {
    $state = if (Test-Path -LiteralPath $statePath) { Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } else { $null }
    if (Test-Path -LiteralPath $environmentPath) {
        & docker compose -p $projectName --env-file $environmentPath -f $composeFile down --volumes --remove-orphans 2>$null | Out-Null
    }
    Get-NetFirewallRule -DisplayName $firewallName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $thumbprint = if ($null -ne $state) { [string]$state.hostRootThumbprint } else { [string]$rootThumbprint }
    if ($thumbprint) {
        Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq $thumbprint | Remove-Item -Force
    }
    $remainingContainers = @(& docker ps -aq --filter ('label=com.docker.compose.project=' + $projectName) 2>$null)
    $remainingVolumes = @(& docker volume ls -q --filter ('label=com.docker.compose.project=' + $projectName) 2>$null)
    $remainingRules = @(Get-NetFirewallRule -DisplayName $firewallName -ErrorAction SilentlyContinue)
    return [ordered]@{
        status = if ($remainingContainers.Count -eq 0 -and $remainingVolumes.Count -eq 0 -and $remainingRules.Count -eq 0) { 'PASS' } else { 'FAIL' }
        remainingContainers = $remainingContainers.Count
        remainingVolumes = $remainingVolumes.Count
        remainingFirewallRules = $remainingRules.Count
    }
}

Assert-OutsideRepository
if ($Phase -eq 'ValidateHost') {
    $prerequisites = Assert-HostPrerequisites
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
    $addressRecord = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $HostHyperVAddress -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $addressRecord) { throw 'M3A_SPLIT_HOST_ADDRESS_NOT_ASSIGNED.' }
    Assert-PortFree -Address $HostHyperVAddress -Port $GatewayPort
    foreach ($port in 15432, 18444, 18445) { Assert-PortFree -Address '127.0.0.1' -Port $port }
    if (Test-Path -LiteralPath $runRoot) { throw 'M3A_SPLIT_RUN_DIRECTORY_ALREADY_EXISTS.' }
    New-Item -ItemType Directory -Path $rawRoot, $redactedRoot -Force | Out-Null
    $dotnet = Get-DotnetPath
    Invoke-NativeChecked -FilePath $dotnet -Arguments @('run', '--project', (Join-Path $repositoryRoot 'tools\m3\FixtureGenerator\FixtureGenerator.csproj'), '-c', 'Release', '--', $rawRoot, $HostHyperVAddress)
    [IO.File]::AppendAllLines($environmentPath, @(
        'M3_GATEWAY_BIND_IP=' + $HostHyperVAddress,
        'M3_GATEWAY_PORT=' + $GatewayPort,
        'M3_POSTGRES_BIND_IP=127.0.0.1',
        'M3_POSTGRES_PORT=15432',
        'M3_VAULT_BIND_IP=127.0.0.1',
        'M3_VAULT_PORT=18444',
        'M3_VENDOR_BIND_IP=127.0.0.1',
        'M3_VENDOR_PORT=18445'
    ), [Text.UTF8Encoding]::new($false))
    $installed = Import-Certificate -FilePath (Join-Path $rawRoot 'certificates\ca.crt') -CertStoreLocation Cert:\LocalMachine\Root
    $rootThumbprint = $installed.Thumbprint
    try {
        New-NetFirewallRule -DisplayName $firewallName -Direction Inbound -Action Allow -Protocol TCP -LocalAddress $HostHyperVAddress -RemoteAddress $VmAddress -LocalPort $GatewayPort -Profile Any | Out-Null
        $rule = Get-NetFirewallRule -DisplayName $firewallName -ErrorAction Stop
        $addressFilter = $rule | Get-NetFirewallAddressFilter
        $portFilter = $rule | Get-NetFirewallPortFilter
        if ($rule.Enabled -ne 'True' -or $rule.Action -ne 'Allow' -or $addressFilter.LocalAddress -notcontains $HostHyperVAddress -or $addressFilter.RemoteAddress -notcontains $VmAddress -or $portFilter.LocalPort -notcontains ([string]$GatewayPort)) {
            throw 'M3A_SPLIT_FIREWALL_SCOPE_INVALID.'
        }
        Invoke-NativeChecked -FilePath 'docker.exe' -Arguments (Get-ComposeArguments -Arguments @('config', '--quiet'))
        Invoke-NativeChecked -FilePath 'docker.exe' -Arguments (Get-ComposeArguments -Arguments @('up', '--build', '--detach'))
        Wait-Gateway -Address ("https://${HostHyperVAddress}:${GatewayPort}/health/ready")
        $listener = Get-NetTCPConnection -State Listen -LocalPort $GatewayPort -ErrorAction Stop
        if (@($listener | Where-Object LocalAddress -eq $HostHyperVAddress).Count -eq 0 -or @($listener | Where-Object LocalAddress -in @('0.0.0.0', '::')).Count -ne 0) {
            throw 'M3A_SPLIT_GATEWAY_BIND_NOT_RESTRICTED.'
        }
        foreach ($port in 15432, 18444, 18445) {
            $internalListener = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction Stop
            if (@($internalListener | Where-Object LocalAddress -ne '127.0.0.1').Count -ne 0) { throw "M3A_SPLIT_INTERNAL_PORT_EXPOSED: $port." }
        }
        $provisioning = Get-Content -LiteralPath $provisioningPath -Raw | ConvertFrom-Json
        $vmInput = Join-Path $rawRoot 'vm-input'
        New-Item -ItemType Directory -Path $vmInput -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $rawRoot 'certificates\ca.crt') -Destination (Join-Path $vmInput 'ca.crt')
        $payloadCanary = 'M3_SPLIT_PAYLOAD_' + [Guid]::NewGuid().ToString('N')
        Write-JsonFile -Path (Join-Path $vmInput 'bootstrap.json') -Value ([ordered]@{
            schemaVersion = 1
            runId = $RunId
            candidateCommit = $CandidateCommit
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
        Write-JsonFile -Path $statePath -Value ([ordered]@{
            schemaVersion = 1; runId = $RunId; candidateCommit = $CandidateCommit
            hostAddress = $HostHyperVAddress; vmAddress = $VmAddress; gatewayPort = $GatewayPort
            interfaceAlias = [string]$addressRecord.InterfaceAlias; composeProject = $projectName
            firewallRule = $firewallName; hostRootThumbprint = $rootThumbprint
            preparedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        })
        [pscustomobject]@{ runId = $RunId; status = 'AWAITING_VM'; commit = $CandidateCommit; vmInput = $archive; vmInputSha256 = $archiveHash; gateway = "https://${HostHyperVAddress}:${GatewayPort}/" } | ConvertTo-Json -Compress
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

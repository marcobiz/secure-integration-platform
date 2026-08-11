[CmdletBinding()]
param(
    [ValidateSet('ValidateHarness', 'Run', 'Cleanup')]
    [string] $Phase = 'Run',
    [string] $RunId = ('m3a-' + (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$artifactRoot = Join-Path $repositoryRoot ('.artifacts\m3\' + $RunId)
$rawRoot = Join-Path $artifactRoot 'raw-evidence'
$redactedRoot = Join-Path $artifactRoot 'redacted-evidence'
$composeFile = Join-Path $repositoryRoot 'deploy\m3\docker-compose.m3a.yml'
$serviceName = 'SecureIntegrationBroker'
$dataDirectory = Join-Path $env:ProgramData ('SecureIntegration\M3\' + $RunId)
$installedRootThumbprint = $null

function Assert-M3Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'M3A requires an elevated Windows session.'
    }
}

function Get-M3Dotnet {
    $local = Join-Path $repositoryRoot '.dotnet\dotnet.exe'
    if (Test-Path -LiteralPath $local) { return $local }
    $command = Get-Command dotnet -ErrorAction Stop
    return $command.Source
}

function Invoke-M3Native {
    param([Parameter(Mandatory)] [string] $FilePath, [Parameter(Mandatory)] [string[]] $Arguments)
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Command failed with exit code ${LASTEXITCODE}: $FilePath" }
}

function Get-M3Environment {
    param([Parameter(Mandatory)] [string] $Path)
    $result = @{}
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $separator = $line.IndexOf('=')
        if ($separator -le 0) { throw 'Invalid generated environment file.' }
        $result[$line.Substring(0, $separator)] = $line.Substring($separator + 1)
    }
    return $result
}

function Wait-M3Gateway {
    param([Parameter(Mandatory)] [string] $ProvisioningPath)
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(3)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $ProvisioningPath) {
            try {
                $response = Invoke-WebRequest -UseBasicParsing -Uri 'https://localhost:18443/health/ready' -TimeoutSec 5
                if ($response.StatusCode -eq 200) { return }
            }
            catch { Start-Sleep -Seconds 2 }
        }
        else { Start-Sleep -Seconds 2 }
    }
    throw 'Gateway M3A did not become ready.'
}

function Remove-M3Resources {
    param([hashtable] $GeneratedEnvironment)
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        $expectedPrefix = [IO.Path]::GetFullPath($artifactRoot)
        if (-not $service.PathName.Trim('"').StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove $serviceName because its binary is outside this M3 run."
        }
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName | Out-Null
    }
    if ($null -ne $GeneratedEnvironment -and (Test-Path -LiteralPath $composeFile)) {
        $environmentFile = Join-Path $rawRoot 'm3a.env'
        if (Test-Path -LiteralPath $environmentFile) {
            & docker compose --env-file $environmentFile -f $composeFile down --volumes --remove-orphans | Out-Null
        }
    }
    if ($null -ne $installedRootThumbprint) {
        Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq $installedRootThumbprint | Remove-Item -Force
    }
    if (Test-Path -LiteralPath $dataDirectory) { Remove-Item -LiteralPath $dataDirectory -Recurse -Force }
}

Assert-M3Administrator
$dotnet = Get-M3Dotnet
if ($Phase -eq 'ValidateHarness') {
    $docker = Get-Command docker -ErrorAction Stop
    Invoke-M3Native -FilePath $docker.Source -Arguments @('version')
    Invoke-M3Native -FilePath $docker.Source -Arguments @('compose', 'version')
    Invoke-M3Native -FilePath $dotnet -Arguments @('--info')
    [pscustomobject]@{ phase = $Phase; runId = $RunId; elevated = $true; docker = $true; dotnet = $true } | ConvertTo-Json -Compress
    exit 0
}
if ($Phase -eq 'Cleanup') {
    Remove-M3Resources -GeneratedEnvironment @{}
    [pscustomobject]@{ phase = $Phase; runId = $RunId; cleaned = $true } | ConvertTo-Json -Compress
    exit 0
}

$head = (& git -C $repositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve candidate commit.' }
$status = (& git -C $repositoryRoot status --porcelain)
if ($LASTEXITCODE -ne 0 -or $status) { throw 'M3A requires a clean worktree.' }
if (-not (& git -C $repositoryRoot merge-base --is-ancestor 'm2-gateway-baseline-2026-08-04' $head)) { throw 'Candidate is not based on the approved M2 tag.' }

New-Item -ItemType Directory -Path $rawRoot -Force | Out-Null
New-Item -ItemType Directory -Path $redactedRoot -Force | Out-Null
$generated = $null
$runSucceeded = $false
try {
    Invoke-M3Native -FilePath $dotnet -Arguments @('run', '--project', (Join-Path $repositoryRoot 'tools\m3\FixtureGenerator\FixtureGenerator.csproj'), '-c', 'Release', '--', $rawRoot)
    $environmentFile = Join-Path $rawRoot 'm3a.env'
    $generated = Get-M3Environment -Path $environmentFile
    $certificatePath = Join-Path $rawRoot 'certificates\ca.crt'
    $installed = Import-Certificate -FilePath $certificatePath -CertStoreLocation Cert:\LocalMachine\Root
    $installedRootThumbprint = $installed.Thumbprint

    Invoke-M3Native -FilePath 'docker.exe' -Arguments @('compose', '--env-file', $environmentFile, '-f', $composeFile, 'up', '--build', '--pull', 'always', '--detach')
    $provisioningPath = Join-Path $rawRoot 'provisioning.json'
    Wait-M3Gateway -ProvisioningPath $provisioningPath
    $provisioning = Get-Content -LiteralPath $provisioningPath -Raw | ConvertFrom-Json

    $servicePublish = Join-Path $rawRoot 'broker-service'
    $simulatorPublish = Join-Path $rawRoot 'legacy-simulator'
    Invoke-M3Native -FilePath $dotnet -Arguments @('publish', (Join-Path $repositoryRoot 'src\Broker\Broker.Service\Broker.Service.csproj'), '-c', 'Release', '-r', 'win-x64', '--self-contained', 'false', '-o', $servicePublish)
    Invoke-M3Native -FilePath $dotnet -Arguments @('publish', (Join-Path $repositoryRoot 'tools\m3\LegacySimulator\LegacySimulator.csproj'), '-c', 'Release', '-r', 'win-x64', '--self-contained', 'false', '-o', $simulatorPublish)
    $simulatorExecutable = Join-Path $simulatorPublish 'SecureIntegration.M3.LegacySimulator.exe'
    $simulatorHash = (Get-FileHash -LiteralPath $simulatorExecutable -Algorithm SHA256).Hash
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $brokerConfig = @{
        Broker = @{
            PipeName = 'SecureIntegration.Broker.M3'
            InstallationId = [string]$provisioning.installationId
            DataDirectory = $dataDirectory
            Gateway = @{
                Enabled = $true
                BaseAddress = 'https://localhost:18443/'
                ActivationCodeId = [string]$provisioning.activationCodeId
                ActivationCodeEnvironmentVariable = 'BROKER_GATEWAY_ACTIVATION_CODE'
                CngKeyName = ('SecureIntegration.Broker.M3.' + $RunId)
                BrokerVersion = '1.0.0'
                TimeoutSeconds = 45
            }
            Applications = @(@{
                RegistrationId = 'm3-legacy-simulator'
                AllowedUserSids = @($currentSid)
                ExecutablePaths = @($simulatorExecutable)
                ExecutableSha256 = @($simulatorHash)
                AllowedPublisherThumbprints = @()
                AllowedOperations = @('InvokeGateway')
                GatewayGrants = @('m3-vendor:submit')
            })
        }
    }
    [IO.File]::WriteAllText((Join-Path $servicePublish 'appsettings.json'), ($brokerConfig | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null
    $serviceExecutable = Join-Path $servicePublish 'SecureIntegration.Broker.Service.exe'
    Invoke-M3Native -FilePath 'sc.exe' -Arguments @('create', $serviceName, 'binPath=', ('"' + $serviceExecutable + '"'), 'start=', 'demand', 'obj=', ('NT SERVICE\' + $serviceName))
    Invoke-M3Native -FilePath 'sc.exe' -Arguments @('sidtype', $serviceName, 'unrestricted')
    Invoke-M3Native -FilePath 'icacls.exe' -Arguments @($servicePublish, '/grant', ('NT SERVICE\' + $serviceName + ':(OI)(CI)RX'), '/T', '/C')
    $serviceRegistry = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $serviceName
    New-ItemProperty -Path $serviceRegistry -Name Environment -PropertyType MultiString -Value @(('BROKER_GATEWAY_ACTIVATION_CODE=' + [string]$provisioning.activationCode)) -Force | Out-Null
    Start-Service -Name $serviceName
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(1)
    do {
        Start-Sleep -Seconds 1
        $serviceState = (Get-Service -Name $serviceName).Status
        if ($serviceState -eq 'Stopped') { throw 'Broker Windows Service stopped during startup.' }
    } while ($serviceState -ne 'Running' -and [DateTimeOffset]::UtcNow -lt $deadline)
    if ($serviceState -ne 'Running') { throw 'Broker Windows Service did not reach Running.' }

    $env:M3_BROKER_PIPE_NAME = 'SecureIntegration.Broker.M3'
    $env:M3_APPLICATION_REGISTRATION_ID = 'm3-legacy-simulator'
    $env:M3_PAYLOAD_CANARY = 'M3_PAYLOAD_' + [Guid]::NewGuid().ToString('N')
    $legacyReport = Join-Path $redactedRoot 'legacy-simulator.json'
    Invoke-M3Native -FilePath $simulatorExecutable -Arguments @('--output', $legacyReport)
    Remove-ItemProperty -Path $serviceRegistry -Name Environment -ErrorAction Stop

    foreach ($pair in $generated.GetEnumerator()) { [Environment]::SetEnvironmentVariable($pair.Key, $pair.Value, 'Process') }
    $env:M3_GATEWAY_BASE_ADDRESS = 'https://localhost:18443/'
    $env:M3_PROVISIONING_FILE = $provisioningPath
    $env:M3_SECURITY_DRIVER_PFX = Join-Path $rawRoot 'certificates\security-driver.pfx'
    $env:M3_POSTGRES_ADMIN_CONNECTION = 'Host=127.0.0.1;Port=15432;Database=broker_gateway_m3;Username=postgres;Password=' + $generated.M3_POSTGRES_ADMIN_PASSWORD + ';SSL Mode=Disable;GSS Encryption Mode=Disable'
    $env:M3_SECURITY_OUTPUT = Join-Path $redactedRoot 'security-scenarios.json'
    # PostgreSQL is published only on loopback for the failure-control driver.
    Invoke-M3Native -FilePath $dotnet -Arguments @('run', '--project', (Join-Path $repositoryRoot 'tools\m3\SecurityDriver\SecurityDriver.csproj'), '-c', 'Release')

    & docker compose --env-file $environmentFile -f $composeFile logs --no-color 2>&1 | Set-Content -LiteralPath (Join-Path $rawRoot 'containers.log') -Encoding UTF8
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddHours(-2) } -ErrorAction SilentlyContinue |
        Where-Object ProviderName -eq 'SecureIntegrationBroker' |
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $rawRoot 'broker-eventlog.json') -Encoding UTF8

    $sensitiveValues = @(
        [string]$provisioning.activationCode,
        [string]$provisioning.securityActivationCode,
        $generated.M3_VENDOR_API_KEY,
        $generated.M3_SYNTHETIC_VAULT_TOKEN,
        $generated.M3_VENDOR_CONTROL_TOKEN,
        $generated.M3_POSTGRES_ADMIN_PASSWORD,
        $generated.M3_POSTGRES_RUNTIME_PASSWORD,
        $generated.M3_CERTIFICATE_PASSWORD,
        $generated.M3_ACTIVATION_HMAC_BASE64,
        $env:M3_PAYLOAD_CANARY,
        $generated.M3_VENDOR_CLIENT_THUMBPRINT
    )
    foreach ($file in Get-ChildItem -LiteralPath $rawRoot -File -Recurse | Where-Object { $_.Extension -in '.log', '.json', '.txt' -and $_.Name -ne 'provisioning.json' -and $_.Name -ne 'm3a.env' -and $_.Name -ne 'fixture-public.json' }) {
        $content = [IO.File]::ReadAllText($file.FullName)
        foreach ($value in $sensitiveValues) {
            if (-not [string]::IsNullOrEmpty($value) -and $content.IndexOf($value, [StringComparison]::Ordinal) -ge 0) { throw "Sensitive canary found in $($file.Name)." }
        }
    }

    $legacy = Get-Content -LiteralPath $legacyReport -Raw | ConvertFrom-Json
    $security = Get-Content -LiteralPath $env:M3_SECURITY_OUTPUT -Raw | ConvertFrom-Json
    if (-not $legacy.passed -or -not $security.passed) { throw 'One or more M3A scenarios failed.' }
    $images = & docker compose --env-file $environmentFile -f $composeFile images --format json | ConvertFrom-Json
    $manifest = [ordered]@{
        schemaVersion = 1
        runId = $RunId
        environment = 'M3A'
        commitSha = $head
        m2BaselineTag = 'm2-gateway-baseline-2026-08-04'
        completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        brokerService = @{ name = $serviceName; status = (Get-Service $serviceName).Status.ToString(); identity = 'NT SERVICE\SecureIntegrationBroker' }
        images = @($images | ForEach-Object { @{ repository = $_.Repository; id = $_.ID } })
        canaryScan = 'PASS'
        legacyReport = 'legacy-simulator.json'
        securityReport = 'security-scenarios.json'
    }
    [IO.File]::WriteAllText((Join-Path $redactedRoot 'manifest.json'), ($manifest | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    Copy-Item -LiteralPath (Join-Path $rawRoot 'fixture-public.json') -Destination (Join-Path $redactedRoot 'fixture-public.json')
    $zipPath = Join-Path $artifactRoot ($RunId + '-redacted-evidence.zip')
    Compress-Archive -Path (Join-Path $redactedRoot '*') -DestinationPath $zipPath -CompressionLevel Optimal
    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
    [IO.File]::WriteAllText(($zipPath + '.sha256'), ($zipHash + '  ' + [IO.Path]::GetFileName($zipPath) + [Environment]::NewLine), [Text.Encoding]::ASCII)
    $runSucceeded = $true
    [pscustomobject]@{ runId = $RunId; status = 'PASS'; commit = $head; evidence = $zipPath; sha256 = $zipHash } | ConvertTo-Json -Compress
}
finally {
    try { Remove-M3Resources -GeneratedEnvironment $generated } catch { if ($runSucceeded) { throw } else { Write-Error $_ } }
}

# One operator-assisted qualification, not part of everyday package use. PowerShell 5.1.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $PackageDirectory,
    [Parameter(Mandatory = $true)][string] $BaselineBrokerDirectory,
    [Parameter(Mandatory = $true)][string] $BaselineSampleDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string] $BaselineCommit,
    [Parameter(Mandatory = $true)][string] $ApplicationUserSid,
    [Parameter(Mandatory = $true)][string] $EvidenceDirectory,
    [ValidatePattern('^delivery-[a-z0-9-]{1,25}$')][string] $Instance = 'delivery-20260905',
    [string] $SyntheticBootstrapDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'DELIVERY_ELEVATED_SETUP_REQUIRED' }
$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
$manifest = Get-Content -LiteralPath (Join-Path $package 'package-manifest.json') -Raw | ConvertFrom-Json
& (Join-Path $PSScriptRoot 'Test-LocalBrokerPackage.ps1') -PackageDirectory $package -ExpectedSourceCommit $manifest.sourceCommit
if ($manifest.sourceCommit -ceq $BaselineCommit) { throw 'DELIVERY_TWO_DISTINCT_BUILDS_REQUIRED' }
$lifecycle = Join-Path $package 'Invoke-LocalBroker.ps1'
$name = 'SecureIntegrationBroker.Local.' + $Instance
$root = Join-Path $env:ProgramFiles ('SecureIntegration\LocalBroker\' + $Instance)
$data = Join-Path $env:ProgramData ('SecureIntegration\LocalBroker\' + $Instance)
if ((Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath $data) -or (Get-CimInstance Win32_Service -Filter "Name='$name'")) {
    throw 'DELIVERY_FRESH_INSTANCE_REQUIRED: existing state preserved.'
}
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
if (Test-Path -LiteralPath (Join-Path $evidence 'phase.json')) { throw 'DELIVERY_EVIDENCE_COLLISION' }
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
$phaseFile = Join-Path $evidence 'phase.json'
$settingsPath = Join-Path $root 'broker\appsettings.json'
$serviceRegistry = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $name
$claimed = $false; $installedCa = $null; $standaloneSettings = $null; $ownedEnvironment = $false
$watch = [Diagnostics.Stopwatch]::StartNew()
function Checkpoint([string] $Phase) {
    [IO.File]::WriteAllText($phaseFile, (@{
        phase = $Phase; service = $name; applicationUserSid = $ApplicationUserSid
        sourceCommit = $manifest.sourceCommit; baselineCommit = $BaselineCommit
        elapsedMs = $watch.ElapsedMilliseconds; administrativeToken = $true
    } | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    Write-Output ('PHASE=' + $Phase + ' WAITING_FOR_NON_ELEVATED_APPLICATION_CHECK')
    $null = Read-Host 'Wait for the coordinator to finish the ordinary-token sample checks, then press Enter'
}
function StateDigest {
    $files = @((Join-Path $root 'installation.json')) + @(Get-ChildItem -LiteralPath (Join-Path $data 'keys') -File | Sort-Object Name | Select-Object -ExpandProperty FullName)
    return ((@($files | Get-FileHash -Algorithm SHA256 | Select-Object -ExpandProperty Hash)) -join ',')
}
try {
    & $lifecycle -Command Install -Instance $Instance -ApplicationUserSid $ApplicationUserSid -BrokerPublishDirectory $BaselineBrokerDirectory -SamplePublishDirectory $BaselineSampleDirectory
    $claimed = $true
    & $lifecycle -Command Start -Instance $Instance
    $initialState = StateDigest
    $initialAcl = (Get-Acl -LiteralPath $data).Sddl
    Checkpoint 'BASELINE_READY'
    & $lifecycle -Command Stop -Instance $Instance
    & $lifecycle -Command Stop -Instance $Instance
    & $lifecycle -Command Start -Instance $Instance
    if ((StateDigest) -cne $initialState) { throw 'DELIVERY_RESTART_STATE_CHANGED' }
    Checkpoint 'RESTART_READY'
    & $lifecycle -Command Update -Instance $Instance
    # Failure before the first copy: no upstream invocation and no key reinitialization.
    $missing = Join-Path $package 'intentionally-absent-update-source'
    if (Test-Path -LiteralPath $missing) { throw 'DELIVERY_NEGATIVE_SOURCE_COLLISION' }
    try { & $lifecycle -Command Update -Instance $Instance -BrokerPublishDirectory $missing; throw 'DELIVERY_FAILED_UPDATE_ACCEPTED' }
    catch { if ($_.Exception.Message -notlike 'LOCAL_BROKER_PUBLISH_DIRECTORY_REQUIRED*') { throw } }
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    if ($settings.Broker.InitializeDataKeys) { throw 'DELIVERY_UPDATE_REINITIALIZATION_ENABLED' }
    & $lifecycle -Command Start -Instance $Instance
    if ((StateDigest) -cne $initialState -or (Get-Acl -LiteralPath $data).Sddl -cne $initialAcl) { throw 'DELIVERY_UPDATE_STATE_CHANGED' }
    Checkpoint 'UPDATE_READY'

    if ($SyntheticBootstrapDirectory) {
        # Existing M3 fixture only. This file is not distributed in the package.
        $bootstrap = Get-Content -LiteralPath (Join-Path $SyntheticBootstrapDirectory 'provisioning.json') -Raw | ConvertFrom-Json
        if ($bootstrap.sampleConnector.connectorId -cne 'sample-secure-service' -or $bootstrap.sampleConnector.state -cne 'Published' -or
            [DateTimeOffset]::Parse($bootstrap.expiresAtUtc) -le [DateTimeOffset]::UtcNow) { throw 'DELIVERY_SYNTHETIC_BOOTSTRAP_INVALID_OR_EXPIRED' }
        $caPath = Join-Path $SyntheticBootstrapDirectory 'certificates\ca.crt'
        $ca = [Security.Cryptography.X509Certificates.X509Certificate2]::new($caPath)
        if ($ca.HasPrivateKey -or $ca.Subject -notlike 'CN=M3 Synthetic Root *') { throw 'DELIVERY_SYNTHETIC_CA_INVALID' }
        if (Test-Path -LiteralPath ('Cert:\LocalMachine\Root\' + $ca.Thumbprint)) { throw 'DELIVERY_CA_ALREADY_PRESENT_PRESERVED' }
        $installedCa = (Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\LocalMachine\Root).Thumbprint
        if ($installedCa -cne $ca.Thumbprint) { throw 'DELIVERY_CA_IMPORT_MISMATCH' }
        & $lifecycle -Command Stop -Instance $Instance
        $standaloneSettings = Get-Content -LiteralPath $settingsPath -Raw
        $settings = $standaloneSettings | ConvertFrom-Json
        $settings.Broker.Gateway = @{
            Enabled = $true; BaseAddress = 'https://localhost:18443/'; ActivationCodeId = [string]$bootstrap.activationCodeId
            ActivationCodeEnvironmentVariable = 'BROKER_GATEWAY_ACTIVATION_CODE'; CngKeyName = $name + '.Gateway'
            BrokerVersion = '1.0.0'; TimeoutSeconds = 10
        }
        $settings.Broker.Applications[0].AllowedOperations += 'InvokeGateway'
        $settings.Broker.Applications[0] | Add-Member -NotePropertyName GatewayGrants -NotePropertyValue @('sample-secure-service:submit')
        [IO.File]::WriteAllText($settingsPath, ($settings | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        if (Get-ItemProperty -LiteralPath $serviceRegistry -Name Environment -ErrorAction SilentlyContinue) { throw 'DELIVERY_FOREIGN_SERVICE_ENVIRONMENT_PRESERVED' }
        New-ItemProperty -LiteralPath $serviceRegistry -Name Environment -PropertyType MultiString -Value @('BROKER_GATEWAY_ACTIVATION_CODE=' + [string]$bootstrap.activationCode) | Out-Null
        $ownedEnvironment = $true
        $bootstrap = $null
        & $lifecycle -Command Start -Instance $Instance
        Checkpoint 'REMOTE_READY'
        & $lifecycle -Command Stop -Instance $Instance
        Remove-ItemProperty -LiteralPath $serviceRegistry -Name Environment
        $ownedEnvironment = $false
        $remoteState = (Get-FileHash -LiteralPath (Join-Path $data 'gateway-installation-state.json') -Algorithm SHA256).Hash
        & $lifecycle -Command Start -Instance $Instance
        Checkpoint 'REMOTE_RESTART_READY'
        if ((Get-FileHash -LiteralPath (Join-Path $data 'gateway-installation-state.json') -Algorithm SHA256).Hash -cne $remoteState) { throw 'DELIVERY_REMOTE_IDENTITY_CHANGED' }
    }
    if ((StateDigest) -cne $initialState) { throw 'DELIVERY_FINAL_LOCAL_STATE_CHANGED' }
    Write-Output 'ADMINISTRATIVE_LIFECYCLE=COMPLETE APPLICATION_RESULTS=SEPARATE'
}
finally {
    if ($claimed) {
        & $lifecycle -Command Stop -Instance $Instance
        if ($standaloneSettings) {
            [IO.File]::WriteAllText($settingsPath, $standaloneSettings, [Text.UTF8Encoding]::new($false))
            if ($ownedEnvironment) { Remove-ItemProperty -LiteralPath $serviceRegistry -Name Environment }
        }
    }
    if ($installedCa) { Remove-Item -LiteralPath ('Cert:\LocalMachine\Root\' + $installedCa) }
    Write-Output 'CLEANUP=OWNED_SERVICE_STOPPED_LOCAL_AND_REMOTE_IDENTITY_PRESERVED'
}

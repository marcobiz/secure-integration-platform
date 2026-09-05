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
    [string] $SyntheticBootstrapDirectory,
    [switch] $ResumeBaseline
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
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
if (Test-Path -LiteralPath (Join-Path $evidence 'phase.json')) { throw 'DELIVERY_EVIDENCE_COLLISION' }
$phaseFile = Join-Path $evidence 'phase.json'
$settingsPath = Join-Path $root 'broker\appsettings.json'
$marker = Join-Path $root 'installation.json'
$binaryPath = '"' + (Join-Path $root 'broker\SecureIntegration.Broker.Service.exe') + '" --contentRoot "' + (Join-Path $root 'broker') + '"'
$serviceRegistry = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $name
$claimed = $false; $installedCa = $null; $standaloneSettings = $null; $ownedEnvironment = $false
$watch = [Diagnostics.Stopwatch]::StartNew()
# Reuse the shipped lifecycle's exact read-only ownership checks, without invoking
# Install/Start while validating a retained initial installation.
$tokens = $null; $parseErrors = $null
$lifecycleAst = [Management.Automation.Language.Parser]::ParseFile($lifecycle, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'DELIVERY_LIFECYCLE_INVALID' }
foreach ($functionName in @('Assert-NoReparse', 'Get-OwnedService')) {
    $definition = $lifecycleAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $functionName }, $true)
    if (-not $definition) { throw 'DELIVERY_LIFECYCLE_INVALID' }
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
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
    Assert-NoReparse (Join-Path $data 'keys')
    $files = @((Join-Path $root 'installation.json')) + @(Get-ChildItem -LiteralPath (Join-Path $data 'keys') -File | Sort-Object Name | Select-Object -ExpandProperty FullName)
    $hashes = foreach ($file in $files) { Assert-NoReparse $file; (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash }
    return ($hashes -join ',')
}
function Get-SyntheticBootstrap {
    try {
        Assert-NoReparse $SyntheticBootstrapDirectory
        $documentPath = Join-Path $SyntheticBootstrapDirectory 'provisioning.json'
        $certificatePath = Join-Path $SyntheticBootstrapDirectory 'certificates\ca.crt'
        Assert-NoReparse $documentPath
        Assert-NoReparse $certificatePath
        $document = Get-Content -LiteralPath $documentPath -Raw | ConvertFrom-Json
        $activationId = [guid]::Empty
        if (-not [guid]::TryParse([string]$document.activationCodeId, [ref]$activationId) -or
            [string]::IsNullOrWhiteSpace([string]$document.activationCode)) { throw 'Invalid synthetic activation.' }
        # PS5.1 returns a string; newer pwsh can already have parsed an ISO date.
        # Never stringify a DateTime and then parse its culture-dependent rendering.
        $value = $document.expiresAtUtc
        if ($value -is [DateTimeOffset]) { $expires = $value }
        elseif ($value -is [DateTime] -and $value.Kind -ne [DateTimeKind]::Unspecified) { $expires = [DateTimeOffset]$value }
        elseif ($value -is [string] -and $value -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?(Z|[+-]\d{2}:\d{2})$') {
            $expires = [DateTimeOffset]::Parse($value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None)
        } else { throw 'Invalid expiry.' }
        if ($document.sampleConnector.connectorId -cne 'sample-secure-service' -or $document.sampleConnector.state -cne 'Published' -or
            $expires -le [DateTimeOffset]::UtcNow) { throw 'Invalid or expired bootstrap.' }
        $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificatePath)
        if ($certificate.HasPrivateKey -or $certificate.Subject -notlike 'CN=M3 Synthetic Root *' -or
            $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) { throw 'Invalid synthetic CA.' }
        return @{ Document = $document; Certificate = $certificate; CertificatePath = $certificatePath; Expires = $expires }
    }
    catch { throw 'DELIVERY_SYNTHETIC_BOOTSTRAP_INVALID_OR_EXPIRED: check the bootstrap directory, Published fixture and ISO expiry before retrying.' }
}
function Assert-BaselineResume {
    $owned = Get-OwnedService
    if (-not $owned -or $owned.State -cne 'Stopped') { throw 'DELIVERY_RESUME_REQUIRES_OWNED_STOPPED_BASELINE' }
    Assert-NoReparse $settingsPath
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    $record = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
    $app = $settings.Broker.Applications[0]
    if ($settings.Broker.ServiceName -cne $name -or $settings.Broker.PipeName -cne $name -or
        $settings.Broker.DataDirectory -cne $data -or $settings.Broker.InstallationId -cne $record.installationId -or
        $settings.Broker.InitializeDataKeys -ne $false -or $settings.Broker.Gateway.Enabled -ne $false -or
        $settings.Broker.Applications.Count -ne 1 -or $app.RegistrationId -cne 'local-sample' -or
        $app.AllowedUserSids.Count -ne 1 -or $app.AllowedUserSids[0] -cne $ApplicationUserSid -or
        $app.ExecutablePaths.Count -ne 1 -or $app.ExecutablePaths[0] -cne (Join-Path $root 'sample\SecureIntegration.Samples.LocalBroker.exe') -or
        @(Compare-Object @('ProtectData', 'UnprotectData', 'GetBrokerStatus') @($app.AllowedOperations) -CaseSensitive).Count -ne 0 -or
        $app.AllowedDataProtectionContexts.Count -ne 1 -or $app.AllowedDataProtectionContexts[0].Purpose -cne 'sample' -or
        $app.AllowedDataProtectionContexts[0].ContentType -cne 'text/plain') { throw 'DELIVERY_BASELINE_CONFIGURATION_MISMATCH' }
    foreach ($component in @('broker', 'sample')) {
        $source = if ($component -ceq 'broker') { $BaselineBrokerDirectory } else { $BaselineSampleDirectory }
        Assert-NoReparse $source
        $source = (Resolve-Path -LiteralPath $source).Path.TrimEnd('\')
        $destination = Join-Path $root $component
        $expected = @(Get-ChildItem -LiteralPath $source -Recurse -File | Where-Object { $_.Name -notlike 'appsettings*.json' })
        $actual = @(Get-ChildItem -LiteralPath $destination -Recurse -File | Where-Object { $_.Name -notlike 'appsettings*.json' })
        if ($expected.Count -eq 0 -or $actual.Count -ne $expected.Count) { throw 'DELIVERY_BASELINE_FILES_MISMATCH' }
        foreach ($file in $expected) {
            $target = Join-Path $destination $file.FullName.Substring($source.Length + 1)
            Assert-NoReparse $file.FullName
            Assert-NoReparse $target
            if (-not (Test-Path -LiteralPath $target -PathType Leaf) -or
                (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash) {
                throw 'DELIVERY_BASELINE_FILES_MISMATCH'
            }
        }
    }
    $sampleHash = (Get-FileHash -LiteralPath $app.ExecutablePaths[0] -Algorithm SHA256).Hash
    if ($app.ExecutableSha256.Count -ne 1 -or $app.ExecutableSha256[0] -cne $sampleHash -or
        @(Get-ChildItem -LiteralPath (Join-Path $data 'keys') -File).Count -eq 0) { throw 'DELIVERY_BASELINE_STATE_MISMATCH' }
}

# All input checks precede filesystem, SCM, registry and trust-store mutations.
if ($SyntheticBootstrapDirectory) {
    $validatedBootstrap = Get-SyntheticBootstrap
    if (Test-Path -LiteralPath ('Cert:\LocalMachine\Root\' + $validatedBootstrap.Certificate.Thumbprint)) { throw 'DELIVERY_CA_ALREADY_PRESENT_PRESERVED' }
    $validatedBootstrap.Certificate.Dispose()
    $validatedBootstrap = $null
}
if ($ResumeBaseline) { Assert-BaselineResume }
elseif ((Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath $data) -or (Get-CimInstance Win32_Service -Filter "Name='$name'")) {
    throw 'DELIVERY_FRESH_INSTANCE_REQUIRED: existing state preserved.'
}
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
try {
    if ($ResumeBaseline) { $retainedState = StateDigest }
    else { & $lifecycle -Command Install -Instance $Instance -ApplicationUserSid $ApplicationUserSid -BrokerPublishDirectory $BaselineBrokerDirectory -SamplePublishDirectory $BaselineSampleDirectory }
    $claimed = $true
    & $lifecycle -Command Start -Instance $Instance
    $initialState = StateDigest
    if ($ResumeBaseline -and $initialState -cne $retainedState) { throw 'DELIVERY_RESUME_STATE_CHANGED' }
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
        $validatedBootstrap = Get-SyntheticBootstrap
        $bootstrap = $validatedBootstrap.Document
        $caPath = $validatedBootstrap.CertificatePath
        $ca = $validatedBootstrap.Certificate
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

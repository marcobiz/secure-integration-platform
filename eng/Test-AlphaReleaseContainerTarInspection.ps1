[CmdletBinding()]
param(
    [ValidateSet('All', 'Identity', 'SwappedAndWrongRepoTag', 'ConfigDigestAndRole')]
    [string] $TestName = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AlphaReleaseContainerArchive.psm1') -Force
$productVersion = '0.1.0-alpha.1'
$sourceCommit = 'c' * 40
$shortCommit = $sourceCommit.Substring(0, 12)
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar))
$testRoot = Join-Path $tempBase ('alpha-container-tar-inspection-' + [Guid]::NewGuid().ToString('N'))
if (-not $testRoot.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'ALPHA_ARTIFACT_TAR_TEST_ROOT_INVALID' }

function Write-Utf8NoBom {
    param([Parameter(Mandatory = $true)][string] $Path, [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Value)
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string] $LiteralPath)
    $stream = [IO.File]::OpenRead($LiteralPath)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
    finally { $sha256.Dispose(); $stream.Dispose() }
}

function New-SyntheticContainerTar {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][ValidateSet('gateway', 'migrations')][string] $ConfigRole,
        [Parameter(Mandatory = $true)][string] $RepoTag,
        [switch] $MutateConfigAfterDigest
    )
    $stage = Join-Path $testRoot ('stage-' + $Name)
    $blobDirectory = Join-Path $stage 'blobs\sha256'
    New-Item -ItemType Directory -Path $blobDirectory -Force | Out-Null
    $runtimeConfig = [ordered]@{
        User = '1000'
        Entrypoint = $(if ($ConfigRole -ceq 'gateway') { @('dotnet', 'SecureIntegration.Gateway.Api.dll') } else { @('dotnet', 'SecureIntegration.Gateway.Migrations.dll', 'apply') })
        Labels = [ordered]@{
            'org.opencontainers.image.version' = $productVersion
            'org.opencontainers.image.revision' = $sourceCommit
            'org.opencontainers.image.source' = 'https://github.com/marcobiz/secure-integration-platform'
            'org.opencontainers.image.vendor' = 'ApoCert S.r.l.'
            'org.opencontainers.image.title' = $(if ($ConfigRole -ceq 'gateway') { 'Secure Integration Platform Gateway' } else { 'Secure Integration Platform Migrations' })
            'org.opencontainers.image.licenses' = 'MPL-2.0'
        }
    }
    if ($ConfigRole -ceq 'gateway') { $runtimeConfig.Healthcheck = [ordered]@{ Test = @('CMD', 'dotnet', 'SecureIntegration.Gateway.Api.dll', '--health-probe') } }
    $configDocument = [ordered]@{
        created = '2026-01-01T00:00:00Z'
        architecture = 'amd64'
        os = 'linux'
        config = $runtimeConfig
        rootfs = [ordered]@{ type = 'layers'; diff_ids = @() }
        history = @()
    }
    $configDraft = Join-Path $stage 'config-draft.json'
    Write-Utf8NoBom -Path $configDraft -Value ($configDocument | ConvertTo-Json -Depth 12 -Compress)
    $digest = Get-Sha256Hex -LiteralPath $configDraft
    $configRelative = "blobs/sha256/$digest"
    $configPath = Join-Path $stage $configRelative.Replace('/', [IO.Path]::DirectorySeparatorChar)
    Move-Item -LiteralPath $configDraft -Destination $configPath
    if ($MutateConfigAfterDigest) { [IO.File]::AppendAllText($configPath, ' ', [Text.UTF8Encoding]::new($false)) }
    $manifest = @([ordered]@{ Config = $configRelative; RepoTags = @($RepoTag); Layers = @() })
    Write-Utf8NoBom -Path (Join-Path $stage 'manifest.json') -Value ($manifest | ConvertTo-Json -Depth 8 -Compress)
    $archive = Join-Path $testRoot ($Name + '.tar')
    & tar -cf $archive -C $stage manifest.json blobs
    if ($LASTEXITCODE -ne 0) { throw "ALPHA_ARTIFACT_TAR_TEST_CREATE_FAILED: $Name" }
    return $archive
}

function Invoke-Negative {
    param([string] $Name, [string] $ExpectedCode, [scriptblock] $Action)
    $message = $null
    $captured = @()
    try { $captured = @(& $Action 2>&1 | ForEach-Object { $_.ToString() }) }
    catch { $message = [string]$_.Exception.Message }
    if ([string]::IsNullOrWhiteSpace($message)) { throw "ALPHA_ARTIFACT_TAR_NEGATIVE_DID_NOT_FAIL: $Name" }
    if (-not $message.StartsWith($ExpectedCode, [StringComparison]::Ordinal)) { throw "ALPHA_ARTIFACT_TAR_NEGATIVE_WRONG_CODE: $Name; ACTUAL=$message" }
    if (($captured -join "`n").Contains('PASS')) { throw "ALPHA_ARTIFACT_TAR_NEGATIVE_EMITTED_PASS: $Name" }
    Write-Host "ALPHA_ARTIFACT_TAR_NEGATIVE_OK; NAME=$Name; CODE=$ExpectedCode"
}

New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $gatewayReference = "secure-integration-gateway:$productVersion-$shortCommit"
    $migrationsReference = "secure-integration-migrations:$productVersion-$shortCommit"
    $gatewayTar = New-SyntheticContainerTar -Name 'gateway' -ConfigRole gateway -RepoTag $gatewayReference
    $migrationsTar = New-SyntheticContainerTar -Name 'migrations' -ConfigRole migrations -RepoTag $migrationsReference

    if ($TestName -in @('All', 'Identity')) {
        $gateway = Get-AlphaReleaseContainerTarIdentity -ArchivePath $gatewayTar -Role gateway -ExpectedReference $gatewayReference -ProductVersion $productVersion -SourceCommit $sourceCommit -InspectionDirectory (Join-Path $testRoot 'inspect-gateway')
        $migrations = Get-AlphaReleaseContainerTarIdentity -ArchivePath $migrationsTar -Role migrations -ExpectedReference $migrationsReference -ProductVersion $productVersion -SourceCommit $sourceCommit -InspectionDirectory (Join-Path $testRoot 'inspect-migrations')
        if ([string]$gateway.imageId -cnotmatch '^sha256:[0-9a-f]{64}$' -or [string]$migrations.imageId -cnotmatch '^sha256:[0-9a-f]{64}$' -or [string]$gateway.imageId -ceq [string]$migrations.imageId) {
            throw 'ALPHA_ARTIFACT_TAR_POSITIVE_IDENTITY_FAILED'
        }
        if ([string]$gateway.configImageId -cne [string]$gateway.imageId -or @($gateway.boundImageIds).Count -ne 1 -or
            [string]$migrations.configImageId -cne [string]$migrations.imageId -or @($migrations.boundImageIds).Count -ne 1) {
            throw 'ALPHA_ARTIFACT_TAR_BOUND_IDENTITY_SET_FAILED'
        }
        Write-Host 'ALPHA_ART_CONTAINER_TAR_IDENTITY_PASS'
    }

    if ($TestName -in @('All', 'SwappedAndWrongRepoTag')) {
        Invoke-Negative -Name 'SwappedGatewayTar' -ExpectedCode 'ALPHA_ARTIFACT_TAR_REPOTAG_MISMATCH:' -Action {
            Get-AlphaReleaseContainerTarIdentity -ArchivePath $migrationsTar -Role gateway -ExpectedReference $gatewayReference -ProductVersion $productVersion -SourceCommit $sourceCommit -InspectionDirectory (Join-Path $testRoot 'inspect-swapped')
        }
        $wrongTagTar = New-SyntheticContainerTar -Name 'wrong-repotag' -ConfigRole gateway -RepoTag $migrationsReference
        Invoke-Negative -Name 'OppositeRepoTag' -ExpectedCode 'ALPHA_ARTIFACT_TAR_REPOTAG_MISMATCH:' -Action {
            Get-AlphaReleaseContainerTarIdentity -ArchivePath $wrongTagTar -Role gateway -ExpectedReference $gatewayReference -ProductVersion $productVersion -SourceCommit $sourceCommit -InspectionDirectory (Join-Path $testRoot 'inspect-wrong-tag')
        }
        Write-Host 'ALPHA_ART_CONTAINER_TAR_SWAPPED_AND_REPOTAG_NEGATIVES_PASS'
    }

    if ($TestName -in @('All', 'ConfigDigestAndRole')) {
        $mutatedTar = New-SyntheticContainerTar -Name 'mutated-config' -ConfigRole gateway -RepoTag $gatewayReference -MutateConfigAfterDigest
        Invoke-Negative -Name 'ConfigDigestMismatch' -ExpectedCode 'ALPHA_ARTIFACT_TAR_CONFIG_DIGEST_MISMATCH:' -Action {
            Get-AlphaReleaseContainerTarIdentity -ArchivePath $mutatedTar -Role gateway -ExpectedReference $gatewayReference -ProductVersion $productVersion -SourceCommit $sourceCommit -InspectionDirectory (Join-Path $testRoot 'inspect-mutated')
        }
        $wrongRoleTar = New-SyntheticContainerTar -Name 'wrong-role' -ConfigRole migrations -RepoTag $gatewayReference
        Invoke-Negative -Name 'WrongRoleWithRegeneratedRepoTag' -ExpectedCode 'ALPHA_ARTIFACT_TAR_CONFIG_PROFILE_MISMATCH:' -Action {
            Get-AlphaReleaseContainerTarIdentity -ArchivePath $wrongRoleTar -Role gateway -ExpectedReference $gatewayReference -ProductVersion $productVersion -SourceCommit $sourceCommit -InspectionDirectory (Join-Path $testRoot 'inspect-wrong-role')
        }
        Write-Host 'ALPHA_ART_CONTAINER_TAR_CONFIG_DIGEST_AND_ROLE_NEGATIVES_PASS'
    }
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        $resolved = [IO.Path]::GetFullPath($testRoot)
        if (-not $resolved.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'ALPHA_ARTIFACT_TAR_TEST_CLEANUP_TARGET_INVALID' }
        [IO.Directory]::Delete($resolved, $true)
    }
}

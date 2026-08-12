[CmdletBinding()]
param(
    [ValidateSet('Validate', 'Start', 'Stop')]
    [string] $Phase = 'Validate',
    [Parameter(Mandatory = $true)]
    [string] $ProviderManifestPath,
    [Parameter(Mandatory = $true)]
    [string] $MaterialDirectory,
    [Guid] $EnvironmentId = '907cf0ea-d592-43a7-9b42-2bd5b97fe7b4',
    [string] $DotNetPath,
    [switch] $SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$manifestPath = [IO.Path]::GetFullPath($ProviderManifestPath)
$materialRoot = [IO.Path]::GetFullPath($MaterialDirectory).TrimEnd('\', '/')
$compose = Join-Path $root 'deploy\fse2\docker-compose.fse2-local.yml'
$quickstart = Join-Path $root 'tools\m5\Invoke-M5Quickstart.ps1'
$dotnet = if ([string]::IsNullOrWhiteSpace($DotNetPath)) { Join-Path $root '.dotnet\dotnet.exe' } else { [IO.Path]::GetFullPath($DotNetPath) }
if (-not (Test-Path -LiteralPath $dotnet -PathType Leaf)) {
    if (-not [string]::IsNullOrWhiteSpace($DotNetPath)) { throw 'FSE2_LOCAL_PROVIDER_DOTNET_INVALID' }
    $dotnet = 'dotnet'
}

$manifestFullyQualified = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    $ProviderManifestPath -match '^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+)'
} else { $ProviderManifestPath.StartsWith('/', [StringComparison]::Ordinal) }
$materialFullyQualified = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    $MaterialDirectory -match '^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+)'
} else { $MaterialDirectory.StartsWith('/', [StringComparison]::Ordinal) }
if (-not $manifestFullyQualified -or -not $materialFullyQualified) { throw 'FSE2_LOCAL_PROVIDER_INPUT_PATH_INVALID' }

if ($EnvironmentId -eq [Guid]::Empty) { throw 'FSE2_LOCAL_ENVIRONMENT_ID_INVALID' }
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $materialRoot -PathType Container)) {
    throw 'FSE2_LOCAL_PROVIDER_INPUT_MISSING'
}
$repositoryPrefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if ($manifestPath.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    $materialRoot.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'FSE2_LOCAL_PROVIDER_INPUT_MUST_BE_OUTSIDE_REPOSITORY'
}

$manifestInfo = [IO.FileInfo]::new($manifestPath)
$materialInfo = [IO.DirectoryInfo]::new($materialRoot)
if (($manifestInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    ($materialInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'FSE2_LOCAL_PROVIDER_LINK_DENIED' }
if ($manifestInfo.Length -lt 1 -or $manifestInfo.Length -gt 262144) { throw 'FSE2_LOCAL_PROVIDER_MANIFEST_SIZE_INVALID' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ([int]$manifest.schemaVersion -ne 1 -or @($manifest.resources).Count -lt 2) { throw 'FSE2_LOCAL_PROVIDER_MANIFEST_INVALID' }
$auth = @($manifest.resources | Where-Object { $_.id -eq 'fse2-auth' -and $_.kind -eq 'ClientCertificate' })
$sign = @($manifest.resources | Where-Object { $_.id -eq 'fse2-sign' -and $_.kind -eq 'SigningCertificate' })
if ($auth.Count -ne 1 -or $sign.Count -ne 1 -or
    [string]::IsNullOrWhiteSpace([string]$auth[0].version) -or
    [string]::IsNullOrWhiteSpace([string]$sign[0].version)) {
    throw 'FSE2_LOCAL_PROVIDER_REQUIRED_RESOURCES_INVALID'
}

function Set-LabEnvironment {
    $values = @{
        FSE2_PROVIDER_MANIFEST_PATH = $manifestPath
        FSE2_PROVIDER_MATERIAL_DIRECTORY = $materialRoot
        FSE2_TEST_ENVIRONMENT_ID = $EnvironmentId.ToString('D')
        M3_PRIMARY_ENVIRONMENT_ID = $EnvironmentId.ToString('D')
        FSE2_AUTH_CERT_VERSION = [string]$auth[0].version
        FSE2_SIGN_CERT_VERSION = [string]$sign[0].version
    }
    foreach ($entry in $values.GetEnumerator()) {
        $script:previousLabEnvironment[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
}

function Clear-LabEnvironment {
    foreach ($entry in $script:previousLabEnvironment.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
}

function Invoke-Checked {
    param([Parameter(Mandatory = $true)][string] $File, [Parameter(Mandatory = $true)][string[]] $Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "FSE2_LOCAL_PROVIDER_COMMAND_FAILED:$File" }
}

$previousLabEnvironment = @{}
Set-LabEnvironment
try {
    if ($Phase -eq 'Validate') {
        Invoke-Checked $dotnet @('restore', (Join-Path $root 'BrokerGateway.LocalPkcs12.slnx'), '--locked-mode')
        Invoke-Checked $dotnet @('build', (Join-Path $root 'BrokerGateway.LocalPkcs12.slnx'), '--configuration', 'Release', '--no-restore')
        Invoke-Checked $dotnet @('test', (Join-Path $root 'BrokerGateway.LocalPkcs12.slnx'), '--configuration', 'Release', '--no-build', '--no-restore')
        Invoke-Checked 'docker' @('compose',
            '--file', (Join-Path $root 'deploy\m3\docker-compose.m3a.yml'),
            '--file', (Join-Path $root 'deploy\m5\docker-compose.m5.yml'),
            '--file', $compose, 'config', '--no-interpolate', '--quiet')
        Write-Host 'FSE2_LOCAL_PROVIDER_VALIDATE_PASS'
        return
    }

    $quickstartArguments = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $quickstart,
        '-Phase', $Phase, '-AdditionalComposeFile', $compose)
    if ($dotnet -ne 'dotnet') { $quickstartArguments += @('-DotNetPath', $dotnet) }
    if ($SkipBuild) { $quickstartArguments += '-SkipBuild' }
    Invoke-Checked 'powershell.exe' $quickstartArguments

    if ($Phase -eq 'Start') {
        $container = (& docker ps --quiet --filter 'label=com.docker.compose.project=secure-integration-m5-quickstart' --filter 'label=com.docker.compose.service=gateway')
        if ($LASTEXITCODE -ne 0 -or @($container).Count -ne 1) { throw 'FSE2_LOCAL_PROVIDER_GATEWAY_NOT_FOUND' }
        $containerId = [string]@($container)[0]
        if ((& docker inspect $containerId --format '{{.HostConfig.ReadonlyRootfs}}').Trim() -ne 'true' -or
            (& docker exec $containerId id -u).Trim() -eq '0') { throw 'FSE2_LOCAL_PROVIDER_CONTAINER_HARDENING_FAILED' }
        Invoke-Checked 'docker' @('exec', $containerId, 'test', '-r', '/run/fse2-provider/manifest.json')
        Invoke-Checked 'docker' @('exec', $containerId, 'test', '-r', '/app/packs/local-pkcs12/SecureIntegration.Providers.LocalPkcs12.dll')
        Invoke-Checked 'docker' @('exec', $containerId, 'test', '-r', '/app/packs/healthcare-fse2/SecureIntegration.ConnectorPacks.Healthcare.FSE2.dll')
        Write-Host 'FSE2_LOCAL_PROVIDER_START_PASS; LIVE_FSE2_CALLS=0'
    }
    else {
        $remaining = (& docker ps -aq --filter 'label=com.docker.compose.project=secure-integration-m5-quickstart')
        if ($LASTEXITCODE -ne 0 -or $remaining) { throw 'FSE2_LOCAL_PROVIDER_CLEANUP_FAILED' }
        Write-Host 'FSE2_LOCAL_PROVIDER_STOP_PASS'
    }
}
finally {
    Clear-LabEnvironment
}

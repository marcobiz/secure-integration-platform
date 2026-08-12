[CmdletBinding()]
param(
    [ValidateSet('Validate', 'Start', 'Workflow', 'Stop')]
    [string] $Phase = 'Start',
    [switch] $SkipBuild,
    [string] $AdditionalComposeFile,
    [string] $DotNetPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$artifactRoot = Join-Path $root '.artifacts\m5\quickstart'
$rawRoot = Join-Path $artifactRoot 'raw'
$envFile = Join-Path $rawRoot 'm3a.env'
$baseCompose = Join-Path $root 'deploy\m3\docker-compose.m3a.yml'
$overlayCompose = Join-Path $root 'deploy\m5\docker-compose.m5.yml'
$project = 'secure-integration-m5-quickstart'
$dotnet = if ([string]::IsNullOrWhiteSpace($DotNetPath)) { Join-Path $root '.dotnet\dotnet.exe' } else { [IO.Path]::GetFullPath($DotNetPath) }
if (-not (Test-Path -LiteralPath $dotnet -PathType Leaf)) {
    if (-not [string]::IsNullOrWhiteSpace($DotNetPath)) { throw 'M5_QUICKSTART_DOTNET_INVALID' }
    $dotnet = 'dotnet'
}

function Invoke-Checked {
    param([Parameter(Mandatory)] [string] $File, [Parameter(Mandatory)] [string[]] $Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "M5_QUICKSTART_COMMAND_FAILED: $File" }
}

function ComposeArguments {
    param([string[]] $Tail, [switch] $IncludeAdditional)
    $arguments = @('compose', '--project-name', $project, '--env-file', $envFile, '--file', $baseCompose, '--file', $overlayCompose)
    if ($IncludeAdditional -and -not [string]::IsNullOrWhiteSpace($AdditionalComposeFile)) { $arguments += @('--file', $AdditionalComposeFile) }
    return $arguments + $Tail
}

if (-not [string]::IsNullOrWhiteSpace($AdditionalComposeFile)) {
    $additionalFullPath = [IO.Path]::GetFullPath($AdditionalComposeFile)
    $allowedAdditionalCompose = [IO.Path]::GetFullPath((Join-Path $root 'deploy\fse2\docker-compose.fse2-local.yml'))
    if ($additionalFullPath -ne $allowedAdditionalCompose -or -not (Test-Path -LiteralPath $additionalFullPath -PathType Leaf)) {
        throw 'M5_QUICKSTART_ADDITIONAL_COMPOSE_DENIED'
    }
    $AdditionalComposeFile = $additionalFullPath
}

if ($Phase -eq 'Workflow') {
    & (Join-Path $PSScriptRoot 'Invoke-M5FullStack.ps1') -UseExistingImages:$SkipBuild
    if ($LASTEXITCODE -ne 0) { throw 'M5_QUICKSTART_WORKFLOW_FAILED' }
    Write-Host 'M5_QUICKSTART_WORKFLOW_PASS'
    exit 0
}

if ($Phase -eq 'Validate') {
    Invoke-Checked 'docker' @('version')
    Invoke-Checked 'docker' @('compose', 'version')
    Invoke-Checked 'node' @('--version')
    Push-Location (Join-Path $root 'src\Admin\Admin.Web')
    try {
        Invoke-Checked 'npm' @('ci', '--ignore-scripts')
        Invoke-Checked 'npm' @('run', 'lint')
        Invoke-Checked 'npm' @('test')
        Invoke-Checked 'npm' @('run', 'build')
    } finally { Pop-Location }
    Write-Host 'M5_QUICKSTART_VALIDATE_PASS'
    exit 0
}

if ($Phase -eq 'Stop') {
    if (Test-Path -LiteralPath $envFile) { Invoke-Checked 'docker' (ComposeArguments @('down', '--volumes', '--remove-orphans')) }
    Write-Host 'M5_QUICKSTART_STOP_PASS'
    exit 0
}

New-Item -ItemType Directory -Path $rawRoot -Force | Out-Null
Invoke-Checked $dotnet @('run', '--project', (Join-Path $root 'tools\m3\FixtureGenerator\FixtureGenerator.csproj'), '--configuration', 'Release', '--', $rawRoot)
$adminPasswordBytes = New-Object byte[] 32
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($adminPasswordBytes) } finally { $random.Dispose() }
$adminPassword = [Convert]::ToBase64String($adminPasswordBytes)
[Array]::Clear($adminPasswordBytes, 0, $adminPasswordBytes.Length)
[IO.File]::AppendAllText($envFile, "M5_POSTGRES_ADMIN_API_PASSWORD=$adminPassword`n", [Text.UTF8Encoding]::new($false))
$adminPassword = $null
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { Invoke-Checked 'chmod' @('0777', $rawRoot) }
Invoke-Checked 'docker' (ComposeArguments @('config', '--quiet'))
$up = @('up', '--detach')
if (-not $SkipBuild) { $up = @('up', '--build', '--pull', 'always', '--detach') }
Invoke-Checked 'docker' (ComposeArguments $up)

$deadline = [DateTimeOffset]::UtcNow.AddMinutes(6)
$ready = $false
do {
    $container = (& docker @((ComposeArguments @('ps', '--quiet', 'gateway'))))
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($container)) {
        $health = (& docker inspect $container.Trim() --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}')
        if ($LASTEXITCODE -eq 0 -and $health.Trim() -eq 'healthy') { $ready = $true; break }
    }
    Start-Sleep -Seconds 2
} while ([DateTimeOffset]::UtcNow -lt $deadline)
if (-not $ready) { throw 'M5_QUICKSTART_GATEWAY_NOT_READY' }

# Consume the synthetic one-time activation through the real challenge/PoP
# enrollment client. The report is metadata-only; provisioning secrets remain
# confined to the ignored raw fixture directory.
$environment = @{}
foreach ($line in Get-Content -LiteralPath $envFile) {
    $separator = $line.IndexOf('=')
    if ($separator -gt 0) { $environment[$line.Substring(0, $separator)] = $line.Substring($separator + 1) }
}
$securityOutput = Join-Path $artifactRoot 'enrollment-status.json'
$env:M3_GATEWAY_BASE_ADDRESS = 'https://localhost:18443/'
$env:M3_GATEWAY_CA_FILE = Join-Path $rawRoot 'certificates\ca.crt'
$env:M3_PROVISIONING_FILE = Join-Path $rawRoot 'provisioning.json'
$env:M3_SECURITY_DRIVER_PFX = Join-Path $rawRoot 'certificates\security-driver.pfx'
$env:M3_CERTIFICATE_PASSWORD = [string]$environment.M3_CERTIFICATE_PASSWORD
$env:M3_SECURITY_OUTPUT = $securityOutput
$env:M3_SECURITY_SCOPE = 'smoke'
Invoke-Checked $dotnet @('run', '--project', (Join-Path $root 'tools\m3\SecurityDriver\SecurityDriver.csproj'), '--configuration', 'Release')
$enrollment = Get-Content -LiteralPath $securityOutput -Raw | ConvertFrom-Json
if (-not $enrollment.passed) { throw 'M5_QUICKSTART_ENROLLMENT_FAILED' }
$provisioning = Get-Content -LiteralPath (Join-Path $rawRoot 'provisioning.json') -Raw | ConvertFrom-Json
$status = (& docker @((ComposeArguments @('exec', '-T', 'postgres', 'psql', '-U', 'postgres', '-d', 'broker_gateway_m3', '-Atc', "SELECT status FROM gateway.installation WHERE id='$($provisioning.securityInstallationId)';"))))
if ($LASTEXITCODE -ne 0 -or $status.Trim() -ne 'active') { throw 'M5_QUICKSTART_INSTALLATION_NOT_ACTIVE' }

# An optional deployment overlay is applied only after the canonical Synthetic-provider
# enrollment and sample invocation have passed. This preserves the default quickstart gate while
# allowing a provider-specific Gateway image to reuse the qualified database and environment.
if (-not [string]::IsNullOrWhiteSpace($AdditionalComposeFile)) {
    $providerUp = @('up', '--detach', '--no-deps', '--force-recreate', 'gateway')
    if (-not $SkipBuild) { $providerUp = @('up', '--build', '--pull', 'always', '--detach', '--no-deps', '--force-recreate', 'gateway') }
    Invoke-Checked 'docker' (ComposeArguments -Tail $providerUp -IncludeAdditional)
    $providerDeadline = [DateTimeOffset]::UtcNow.AddMinutes(3)
    $providerReady = $false
    do {
        $providerContainer = (& docker @((ComposeArguments -Tail @('ps', '--quiet', 'gateway') -IncludeAdditional)))
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($providerContainer)) {
            $providerHealth = (& docker inspect $providerContainer.Trim() --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}')
            if ($LASTEXITCODE -eq 0 -and $providerHealth.Trim() -eq 'healthy') { $providerReady = $true; break }
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $providerDeadline)
    if (-not $providerReady) { throw 'M5_QUICKSTART_ADDITIONAL_PROVIDER_NOT_READY' }
}

$html = Join-Path $artifactRoot 'admin-index.html'
# Schannel otherwise attempts Internet revocation checks for the intentionally offline,
# per-run synthetic CA. Certificate chain and hostname validation remain enabled.
$curl = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'curl.exe' } else { 'curl' }
$curlArguments = @('--fail', '--silent', '--show-error')
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { $curlArguments += '--ssl-no-revoke' }
$curlArguments += @('--cacert', (Join-Path $rawRoot 'certificates\ca.crt'), 'https://localhost:18443/admin/', '--output', $html)
Invoke-Checked $curl $curlArguments
$content = Get-Content -Raw -LiteralPath $html
if ($content -notmatch '<div id="root"></div>' -or $content.IndexOf('__CSP_NONCE__', [StringComparison]::Ordinal) -ge 0) { throw 'M5_QUICKSTART_ADMIN_UI_INVALID' }
Write-Host 'M5_QUICKSTART_START_PASS'
Write-Host 'Synthetic enrollment: Active (challenge, proof-of-possession and activation completed).'
Write-Host 'Admin UI: https://localhost:18443/admin/'
Write-Host 'Stop with: powershell -NoProfile -File tools/m5/Invoke-M5Quickstart.ps1 -Phase Stop'

[CmdletBinding()]
param(
    [ValidateSet('Validate', 'Start', 'Stop')]
    [string] $Phase = 'Start'
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
$dotnet = Join-Path $root '.dotnet\dotnet.exe'
if (-not (Test-Path -LiteralPath $dotnet)) { $dotnet = 'dotnet' }

function Invoke-Checked {
    param([Parameter(Mandatory)] [string] $File, [Parameter(Mandatory)] [string[]] $Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "M5_QUICKSTART_COMMAND_FAILED: $File" }
}

function ComposeArguments {
    param([string[]] $Tail)
    return @('compose', '--project-name', $project, '--env-file', $envFile, '--file', $baseCompose, '--file', $overlayCompose) + $Tail
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
Invoke-Checked 'docker' (ComposeArguments @('up', '--build', '--detach'))

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
Write-Host 'Admin UI: https://localhost:18443/admin/'
Write-Host 'Stop with: powershell -NoProfile -File tools/m5/Invoke-M5Quickstart.ps1 -Phase Stop'

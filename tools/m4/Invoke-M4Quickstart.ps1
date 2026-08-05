[CmdletBinding()]
param(
    [ValidateSet('Validate', 'Start', 'Stop')]
    [string] $Phase = 'Start'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$artifactRoot = Join-Path $root '.artifacts\m4\quickstart'
$rawRoot = Join-Path $artifactRoot 'raw'
$envFile = Join-Path $rawRoot 'm3a.env'
$baseCompose = Join-Path $root 'deploy\m3\docker-compose.m3a.yml'
$overlayCompose = Join-Path $root 'deploy\m4\docker-compose.m4.yml'
$project = 'broker-gateway-m4-quickstart'
$dotnet = Join-Path $root '.dotnet\dotnet.exe'
if (-not (Test-Path -LiteralPath $dotnet)) { $dotnet = 'dotnet' }

function Invoke-Checked {
    param([Parameter(Mandatory)] [string] $File, [Parameter(Mandatory)] [string[]] $Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "M4_QUICKSTART_COMMAND_FAILED: $File" }
}

function ComposeArguments {
    param([string[]] $Tail)
    return @('compose', '--project-name', $project, '--env-file', $envFile, '--file', $baseCompose, '--file', $overlayCompose) + $Tail
}

if ($Phase -eq 'Validate') {
    Invoke-Checked 'docker' @('version')
    Invoke-Checked 'docker' @('compose', 'version')
    Invoke-Checked $dotnet @('run', '--project', (Join-Path $root 'tools\connector-cli\Connector.Cli.csproj'), '--configuration', 'Release', '--', '--help')
    Write-Host 'M4_QUICKSTART_VALIDATE_PASS'
    exit 0
}

if ($Phase -eq 'Stop') {
    if (Test-Path -LiteralPath $envFile) { Invoke-Checked 'docker' (ComposeArguments @('down', '--volumes', '--remove-orphans')) }
    Write-Host 'M4_QUICKSTART_STOP_PASS'
    exit 0
}

New-Item -ItemType Directory -Path $rawRoot -Force | Out-Null
Invoke-Checked $dotnet @('run', '--project', (Join-Path $root 'tools\m3\FixtureGenerator\FixtureGenerator.csproj'), '--configuration', 'Release', '--', $rawRoot)
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    # The fixture services use fixed non-root UIDs. The directory is disposable raw test
    # evidence and must be writable through a Linux bind mount without running as root.
    Invoke-Checked 'chmod' @('0777', $rawRoot)
}
$adminKeyBytes = New-Object byte[] 32
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($adminKeyBytes) } finally { $random.Dispose() }
$adminKey = [Convert]::ToBase64String($adminKeyBytes)
[Array]::Clear($adminKeyBytes, 0, $adminKeyBytes.Length)
[IO.File]::AppendAllText($envFile, "M4_QUICKSTART_ADMIN_KEY=$adminKey`n", [Text.UTF8Encoding]::new($false))
Invoke-Checked 'docker' (ComposeArguments @('config', '--quiet'))
Invoke-Checked 'docker' (ComposeArguments @('up', '--build', '--detach'))

$deadline = [DateTimeOffset]::UtcNow.AddMinutes(4)
$ready = $false
do {
    $gatewayContainer = (& docker @((ComposeArguments @('ps', '--quiet', 'gateway'))))
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($gatewayContainer)) {
        $health = (& docker inspect $gatewayContainer.Trim() --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}')
        if ($LASTEXITCODE -eq 0 -and $health.Trim() -eq 'healthy') { $ready = $true; break }
    }
    Start-Sleep -Seconds 2
} while ([DateTimeOffset]::UtcNow -lt $deadline)
if (-not $ready) { throw 'M4_QUICKSTART_GATEWAY_NOT_READY' }

$provisioning = Get-Content -Raw -LiteralPath (Join-Path $rawRoot 'provisioning.json') | ConvertFrom-Json
$previousUrl = $env:CONNECTOR_GATEWAY_URL
$previousKey = $env:GATEWAY_ADMIN_API_KEY
$previousCa = $env:CONNECTOR_GATEWAY_CA_FILE
try {
    $env:CONNECTOR_GATEWAY_URL = 'https://localhost:18443/'
    $env:GATEWAY_ADMIN_API_KEY = $adminKey
    $env:CONNECTOR_GATEWAY_CA_FILE = Join-Path $rawRoot 'certificates\ca.crt'
    Invoke-Checked $dotnet @('run', '--project', (Join-Path $root 'tools\connector-cli\Connector.Cli.csproj'), '--configuration', 'Release', '--', 'list')
    Invoke-Checked $dotnet @('run', '--project', (Join-Path $root 'tools\connector-cli\Connector.Cli.csproj'), '--configuration', 'Release', '--', 'test', 'sample-secure-service', 'submit', [string]$provisioning.environmentId)
}
finally {
    $env:CONNECTOR_GATEWAY_URL = $previousUrl
    $env:GATEWAY_ADMIN_API_KEY = $previousKey
    $env:CONNECTOR_GATEWAY_CA_FILE = $previousCa
    $adminKey = $null
}
Write-Host 'M4_QUICKSTART_START_PASS'
Write-Host 'Stop with: powershell -NoProfile -File tools/m4/Invoke-M4Quickstart.ps1 -Phase Stop'

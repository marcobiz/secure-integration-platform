[CmdletBinding()]
param(
    [switch]$Reset,
    [switch]$SmokeTest,
    [switch]$NoBrowser
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dotnet = Join-Path $repo '.dotnet\dotnet.exe'
$web = Join-Path $repo 'src\Admin\Admin.Web'
$compose = Join-Path $repo 'deploy\m5\docker-compose.admin-dev.yml'
$state = Join-Path $repo '.artifacts\m5\admin-dev'
$passwordPath = Join-Path $state 'postgres-password.txt'
$gatewayLog = Join-Path $state 'gateway.log'
$gatewayErrorLog = Join-Path $state 'gateway.error.log'
$viteLog = Join-Path $state 'vite.log'
$viteErrorLog = Join-Path $state 'vite.error.log'
$httpsPfx = Join-Path $state 'localhost.pfx'
$httpsPem = Join-Path $state 'localhost.crt.pem'
$viteDevelopmentEnvironment = Join-Path $web '.env.development'
$proxySetting = Get-Content $viteDevelopmentEnvironment | Where-Object { $_ -match '^VITE_ADMIN_PROXY_TARGET=' } | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($proxySetting)) { throw 'M5_ADMIN_DEV_PROXY_TARGET_MISSING' }
$gatewayUrl = ($proxySetting -split '=', 2)[1].Trim()
$gatewayUri = New-Object Uri($gatewayUrl)
if ($gatewayUri.Scheme -ne 'https' -or -not $gatewayUri.IsLoopback) { throw 'M5_ADMIN_DEV_PROXY_TARGET_INVALID' }
$uiUrl = 'https://localhost:5173/admin/'
$postgresPort = 15435
$composeProject = 'broker-gateway-admin-dev'
$gatewayProcess = $null
$viteProcess = $null
$operationSucceeded = $false

function Invoke-NativeChecked {
    param([string]$FilePath, [string[]]$Arguments, [string]$ErrorCode)
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$ErrorCode ($LASTEXITCODE)" }
}

function New-LocalSecret {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Test-PortAvailable {
    param([int]$Port)
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $Port)
    try { $listener.Start(); return $true } catch { return $false } finally { $listener.Stop() }
}

function Wait-Http {
    param([string]$Uri, [Diagnostics.Process]$Process, [string]$ErrorCode)
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(2)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if ($null -ne $Process -and $Process.HasExited) { throw "$ErrorCode process exited with $($Process.ExitCode)." }
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 3
            if ($response.StatusCode -eq 200) { return }
        } catch { Start-Sleep -Milliseconds 750 }
    }
    throw "$ErrorCode timeout waiting for $Uri."
}

function Stop-ProcessTree {
    param([Diagnostics.Process]$Process)
    if ($null -eq $Process -or $Process.HasExited) { return }
    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($Process.Id)" -ErrorAction SilentlyContinue)
    foreach ($child in $children) {
        $childProcess = Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue
        if ($null -ne $childProcess) { Stop-ProcessTree -Process $childProcess }
    }
    Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
}

function Restore-Environment {
    param([hashtable]$Original)
    foreach ($name in $Original.Keys) { [Environment]::SetEnvironmentVariable($name, $Original[$name], 'Process') }
}

if (-not (Test-Path -LiteralPath $dotnet -PathType Leaf)) { throw 'M5_ADMIN_DEV_DOTNET_MISSING: run eng/bootstrap-dotnet.ps1.' }
foreach ($command in @('docker', 'node', 'npm.cmd')) {
    if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) { throw "M5_ADMIN_DEV_PREREQUISITE_MISSING: $command" }
}
Invoke-NativeChecked docker @('info', '--format', '{{.OSType}}') 'M5_ADMIN_DEV_DOCKER_UNAVAILABLE'
if ((& docker info --format '{{.OSType}}').Trim() -ne 'linux') { throw 'M5_ADMIN_DEV_LINUX_CONTAINERS_REQUIRED' }
& $dotnet dev-certs https --check --trust | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'M5_ADMIN_DEV_HTTPS_CERTIFICATE_NOT_TRUSTED: run .\.dotnet\dotnet.exe dev-certs https --trust once.' }

New-Item -ItemType Directory -Force -Path $state | Out-Null
$env:M5_ADMIN_DEV_POSTGRES_PORT = $postgresPort.ToString([Globalization.CultureInfo]::InvariantCulture)
if ($Reset) {
    if (Test-Path $passwordPath) { $env:M5_ADMIN_DEV_POSTGRES_PASSWORD = (Get-Content $passwordPath -Raw).Trim() }
    $savedErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & docker compose -p $composeProject -f $compose down --volumes --remove-orphans 2>&1 | Out-Null
    $resetExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedErrorPreference
    if ($resetExitCode -ne 0) { throw "M5_ADMIN_DEV_RESET_FAILED ($resetExitCode)" }
    Remove-Item -LiteralPath $passwordPath -Force -ErrorAction SilentlyContinue
}
if (-not (Test-Path $passwordPath)) { [IO.File]::WriteAllText($passwordPath, (New-LocalSecret), [Text.Encoding]::UTF8) }
$postgresPassword = (Get-Content $passwordPath -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($postgresPassword)) { throw 'M5_ADMIN_DEV_STATE_INVALID' }
$env:M5_ADMIN_DEV_POSTGRES_PASSWORD = $postgresPassword

if (-not (Test-PortAvailable $gatewayUri.Port)) { throw "M5_ADMIN_DEV_GATEWAY_PORT_IN_USE: 127.0.0.1:$($gatewayUri.Port)" }
if (-not (Test-PortAvailable 5173)) { throw 'M5_ADMIN_DEV_UI_PORT_IN_USE: 127.0.0.1:5173' }

$runtimePassword = New-LocalSecret
$adminPassword = New-LocalSecret
$httpsPassword = New-LocalSecret
$httpsExport = & $dotnet dev-certs https --export-path $httpsPfx --password $httpsPassword 2>&1
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $httpsPfx)) { throw 'M5_ADMIN_DEV_HTTPS_CERTIFICATE_EXPORT_FAILED' }
$certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2($httpsPfx, $httpsPassword)
$encodedCertificate = [Convert]::ToBase64String($certificate.RawData, [Base64FormattingOptions]::InsertLineBreaks)
[IO.File]::WriteAllText($httpsPem, "-----BEGIN CERTIFICATE-----`r`n$encodedCertificate`r`n-----END CERTIFICATE-----`r`n", [Text.Encoding]::ASCII)
$activationBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($activationBytes)
$activationKey = [Convert]::ToBase64String($activationBytes)
$postgresAdmin = "Host=127.0.0.1;Port=$postgresPort;Database=broker_gateway_admin_dev;Username=postgres;Password=$postgresPassword;SSL Mode=Disable;GSS Encryption Mode=Disable"
$postgresRuntime = "Host=127.0.0.1;Port=$postgresPort;Database=broker_gateway_admin_dev;Username=m5_admin_dev_runtime;Password=$runtimePassword;SSL Mode=Disable;GSS Encryption Mode=Disable"
$postgresAdminApi = "Host=127.0.0.1;Port=$postgresPort;Database=broker_gateway_admin_dev;Username=m5_admin_dev_admin;Password=$adminPassword;SSL Mode=Disable;GSS Encryption Mode=Disable"

$managedEnvironment = @{
    'ASPNETCORE_ENVIRONMENT' = 'Development'
    'ASPNETCORE_URLS' = $gatewayUrl
    'ConnectionStrings__GatewayDatabase' = $postgresRuntime
    'ConnectionStrings__GatewayAdminDatabase' = $postgresAdminApi
    'Gateway__Admin__Mode' = 'DevelopmentAuth'
    'Gateway__Admin__RequireFourEyes' = 'true'
    'Gateway__Provider__Kind' = 'InMemory'
    'Gateway__ActivationHmacKeyBase64' = $activationKey
    'VITE_ADMIN_PROXY_TARGET' = $gatewayUrl
    'GATEWAY_MIGRATION_CONNECTION' = $postgresAdmin
    'M5_ADMIN_DEV_POSTGRES_ADMIN_CONNECTION' = $postgresAdmin
    'M5_ADMIN_DEV_RUNTIME_PASSWORD' = $runtimePassword
    'M5_ADMIN_DEV_ADMIN_PASSWORD' = $adminPassword
    'M5_ADMIN_DEV_SEED' = 'true'
    'ASPNETCORE_Kestrel__Certificates__Default__Path' = $httpsPfx
    'ASPNETCORE_Kestrel__Certificates__Default__Password' = $httpsPassword
    'M5_ADMIN_DEV_HTTPS_PFX' = $httpsPfx
    'M5_ADMIN_DEV_HTTPS_PFX_PASSWORD' = $httpsPassword
    'NODE_EXTRA_CA_CERTS' = $httpsPem
}
$originalEnvironment = @{}
foreach ($name in $managedEnvironment.Keys) {
    $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    [Environment]::SetEnvironmentVariable($name, $managedEnvironment[$name], 'Process')
}

try {
    Invoke-NativeChecked docker @('compose', '-p', $composeProject, '-f', $compose, 'up', '-d', '--wait', 'postgres') 'M5_ADMIN_DEV_POSTGRES_START_FAILED'
    Invoke-NativeChecked $dotnet @('run', '--project', (Join-Path $repo 'src\Gateway\Gateway.Migrations\Gateway.Migrations.csproj'), '--configuration', 'Debug', '--', 'apply') 'M5_ADMIN_DEV_MIGRATION_FAILED'
    Invoke-NativeChecked $dotnet @('run', '--project', (Join-Path $repo 'tools\m5\DevelopmentSeed\DevelopmentSeed.csproj'), '--configuration', 'Debug') 'M5_ADMIN_DEV_SEED_FAILED'

    $lockHash = (Get-FileHash (Join-Path $web 'package-lock.json') -Algorithm SHA256).Hash
    $stampPath = Join-Path $state 'package-lock.sha256'
    $nodeModules = Join-Path $web 'node_modules\.bin\vite.cmd'
    $stamp = if (Test-Path $stampPath) { (Get-Content $stampPath -Raw).Trim() } else { '' }
    if (-not (Test-Path $nodeModules) -or $stamp -ne $lockHash) {
        Push-Location $web
        try { Invoke-NativeChecked npm.cmd @('ci', '--ignore-scripts') 'M5_ADMIN_DEV_NPM_CI_FAILED' }
        finally { Pop-Location }
        [IO.File]::WriteAllText($stampPath, $lockHash, [Text.Encoding]::ASCII)
    }

    Remove-Item $gatewayLog, $gatewayErrorLog, $viteLog, $viteErrorLog -Force -ErrorAction SilentlyContinue
    $gatewayProcess = Start-Process -FilePath $dotnet -ArgumentList @('run', '--project', (Join-Path $repo 'src\Gateway\Gateway.Api\Gateway.Api.csproj'), '--configuration', 'Debug', '--no-launch-profile') -WorkingDirectory $repo -RedirectStandardOutput $gatewayLog -RedirectStandardError $gatewayErrorLog -PassThru -WindowStyle Hidden
    Wait-Http "$gatewayUrl/health/live" $gatewayProcess 'M5_ADMIN_DEV_GATEWAY_LIVE_FAILED'
    Wait-Http "$gatewayUrl/health/ready" $gatewayProcess 'M5_ADMIN_DEV_GATEWAY_READY_FAILED'

    $node = (Get-Command node).Source
    $viteProcess = Start-Process -FilePath $node -ArgumentList @((Join-Path $web 'node_modules\vite\bin\vite.js'), '--strictPort') -WorkingDirectory $web -RedirectStandardOutput $viteLog -RedirectStandardError $viteErrorLog -PassThru -WindowStyle Hidden
    Wait-Http $uiUrl $viteProcess 'M5_ADMIN_DEV_VITE_FAILED'

    Write-Host ''
    Write-Host 'M5 Admin UI locale pronta.' -ForegroundColor Green
    Write-Host 'PostgreSQL   READY'
    Write-Host 'Migrations   APPLIED'
    Write-Host 'Gateway      READY'
    Write-Host 'Admin UI     READY'
    Write-Host "Admin UI:    $uiUrl"
    Write-Host "Gateway:     $gatewayUrl"
    Write-Host "Health:      $gatewayUrl/health/ready"
    Write-Host 'Demo seed:   PRESENT'
    Write-Host 'Login: scegli uno degli utenti DevelopmentAuth nella schermata (consigliato: Security Administrator).'
    Write-Host 'Arresto: Ctrl+C. Il database demo viene conservato; usa -Reset per ricrearlo.'
    Write-Host ''

    if ($SmokeTest) {
        Push-Location $web
        try {
            $env:M5_ADMIN_DEV_BASE_URL = $uiUrl
            Invoke-NativeChecked npm.cmd @('run', 'test:local-dev') 'M5_ADMIN_DEV_BROWSER_SMOKE_FAILED'
        } finally { Pop-Location }
        Invoke-NativeChecked $dotnet @('run', '--project', (Join-Path $repo 'tools\m5\DevelopmentSeed\DevelopmentSeed.csproj'), '--configuration', 'Debug', '--no-build') 'M5_ADMIN_DEV_SEED_IDEMPOTENCY_FAILED'
        Write-Host 'M5_ADMIN_DEV_SMOKE_PASS' -ForegroundColor Green
        $operationSucceeded = $true
    } else {
        if (-not $NoBrowser) { Start-Process $uiUrl | Out-Null }
        while (-not $gatewayProcess.HasExited -and -not $viteProcess.HasExited) { Start-Sleep -Seconds 1 }
        throw 'M5_ADMIN_DEV_CHILD_EXITED: inspect .artifacts/m5/admin-dev logs.'
    }
}
finally {
    Stop-ProcessTree $viteProcess
    Stop-ProcessTree $gatewayProcess
    $savedErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & docker compose -p $composeProject -f $compose down --remove-orphans 2>&1 | Out-Null
    $cleanupExitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedErrorPreference
    $remainingContainers = @(& docker ps -aq --filter "label=com.docker.compose.project=$composeProject")
    $remainingNetworks = @(& docker network ls -q --filter "label=com.docker.compose.project=$composeProject")
    if ($remainingContainers.Count -ne 0 -or $remainingNetworks.Count -ne 0) { $cleanupExitCode = 1 }
    Restore-Environment $originalEnvironment
    Remove-Item Env:M5_ADMIN_DEV_POSTGRES_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item $httpsPfx, $httpsPem -Force -ErrorAction SilentlyContinue
    if ($cleanupExitCode -ne 0) {
        if ($operationSucceeded) { throw "M5_ADMIN_DEV_CLEANUP_FAILED ($cleanupExitCode)" }
        Write-Warning "M5_ADMIN_DEV_CLEANUP_FAILED ($cleanupExitCode)"
    } elseif ($operationSucceeded) {
        Write-Host 'M5_ADMIN_DEV_CLEANUP_PASS' -ForegroundColor Green
    }
}

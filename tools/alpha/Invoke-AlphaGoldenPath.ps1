[CmdletBinding()]
param(
    [ValidateSet('Validate', 'Run', 'Stop')]
    [string] $Phase = 'Run',
    [switch] $SkipBuild,
    [string] $DotNetPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$quickstart = Join-Path $root 'tools\m5\Invoke-M5Quickstart.ps1'
$artifactRoot = Join-Path $root '.artifacts\m5\quickstart'
$rawRoot = Join-Path $artifactRoot 'raw'
$envFile = Join-Path $rawRoot 'm3a.env'
$baseCompose = Join-Path $root 'deploy\m3\docker-compose.m3a.yml'
$overlayCompose = Join-Path $root 'deploy\m5\docker-compose.m5.yml'
$project = 'secure-integration-m5-quickstart'
$dotnet = if ([string]::IsNullOrWhiteSpace($DotNetPath)) { Join-Path $root '.dotnet\dotnet.exe' } else { [IO.Path]::GetFullPath($DotNetPath) }
if (-not (Test-Path -LiteralPath $dotnet -PathType Leaf)) { $dotnet = 'dotnet' }

function Invoke-Checked {
    param([Parameter(Mandatory)] [string] $File, [Parameter(Mandatory)] [string[]] $Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "ALPHA_GOLDEN_PATH_COMMAND_FAILED: $File" }
}

function Get-ExactProjectResources {
    param([Parameter(Mandatory)][ValidateSet('container', 'network', 'volume')][string] $Kind)
    $arguments = switch ($Kind) {
        'container' { @('ps', '-aq', '--filter', ('label=com.docker.compose.project=' + $project)) }
        'network' { @('network', 'ls', '-q', '--filter', ('label=com.docker.compose.project=' + $project)) }
        'volume' { @('volume', 'ls', '-q', '--filter', ('label=com.docker.compose.project=' + $project)) }
    }
    $values = @(& docker @arguments)
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_GOLDEN_PATH_RESOURCE_ENUMERATION_FAILED' }
    return @($values | ForEach-Object { ([string]$_).Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Assert-ZeroProjectResources {
    if (@(Get-ExactProjectResources -Kind container).Count -ne 0 -or
        @(Get-ExactProjectResources -Kind network).Count -ne 0 -or
        @(Get-ExactProjectResources -Kind volume).Count -ne 0) {
        throw 'ALPHA_GOLDEN_PATH_RESIDUAL_PROJECT_RESOURCES'
    }
}

function Read-EnvironmentFile {
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $envFile) {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0) { $values[$line.Substring(0, $separator)] = $line.Substring($separator + 1) }
    }
    return $values
}

function Invoke-ControlJson {
    param(
        [Parameter(Mandatory)][string] $HostName,
        [Parameter(Mandatory)][int] $Port,
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $HeaderName,
        [Parameter(Mandatory)][string] $HeaderValue,
        [Parameter(Mandatory)][string] $OutputPath,
        [Parameter(Mandatory)][string] $CaPath
    )
    $curl = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'curl.exe' } else { 'curl' }
    $arguments = @('--fail', '--silent', '--show-error', '--max-time', '15')
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { $arguments += '--ssl-no-revoke' }
    $arguments += @('--cacert', $CaPath, '--resolve', "${HostName}:${Port}:127.0.0.1", '--header', ($HeaderName + ': ' + $HeaderValue), '--output', $OutputPath, "https://${HostName}:${Port}${Path}")
    Invoke-Checked $curl $arguments
    return Get-Content -LiteralPath $OutputPath -Raw | ConvertFrom-Json
}

function Restart-GatewayAndWait {
    $composeArguments = @('compose', '--project-name', $project, '--env-file', $envFile, '--file', $baseCompose, '--file', $overlayCompose)
    Invoke-Checked 'docker' ($composeArguments + @('restart', 'gateway'))
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(2)
    do {
        $container = (& docker @($composeArguments + @('ps', '--quiet', 'gateway')))
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($container)) {
            $health = (& docker inspect $container.Trim() --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}')
            if ($LASTEXITCODE -eq 0 -and $health.Trim() -eq 'healthy') { return }
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'ALPHA_GOLDEN_PATH_GATEWAY_NOT_READY_AFTER_RESTART'
}

function Get-ReadCount {
    param([Parameter(Mandatory)] $Stats, [Parameter(Mandatory)][string] $Name)
    $property = $Stats.reads.PSObject.Properties[$Name]
    if ($null -eq $property) { return 0L }
    return [long]$property.Value
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)][byte[]] $Bytes)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($Bytes)
        try { return ([BitConverter]::ToString($digest)).Replace('-', '') }
        finally { [Array]::Clear($digest, 0, $digest.Length) }
    }
    finally { $sha256.Dispose() }
}

function Assert-RedactedText {
    param([Parameter(Mandatory)][string] $Text, [Parameter(Mandatory)][object[]] $Canaries)
    foreach ($canary in $Canaries) {
        $value = [string]$canary.Value
        if ($value.Length -ge 8 -and $Text.IndexOf($value, [StringComparison]::Ordinal) -ge 0) {
            throw "ALPHA_GOLDEN_PATH_REDACTION_FAILED:$($canary.Name)"
        }
    }
    foreach ($pattern in @(
        '-----BEGIN (?:RSA |EC |)PRIVATE KEY-----',
        '(?i)authorization\s*:\s*\S+',
        '(?i)cookie\s*:\s*\S+',
        '__Host-SecureIntegration\.Admin=[^;\s]+',
        '(?m)^\s+at\s+[A-Za-z0-9_.+`<>]+\(')) {
        if ([regex]::IsMatch($Text, $pattern)) { throw 'ALPHA_GOLDEN_PATH_REDACTION_PATTERN_FAILED' }
    }
}

if ($Phase -eq 'Validate') {
    Invoke-Checked 'docker' @('version')
    Invoke-Checked 'docker' @('compose', 'version')
    Invoke-Checked $dotnet @('--version')
    Invoke-Checked $dotnet @('restore', (Join-Path $root 'samples\DirectGatewayClient\DirectGatewayClient.csproj'), '--locked-mode')
    Invoke-Checked $dotnet @('build', (Join-Path $root 'samples\DirectGatewayClient\DirectGatewayClient.csproj'), '--configuration', 'Release', '--no-restore')
    Write-Host 'ALPHA_GOLDEN_PATH_VALIDATE_PASS'
    exit 0
}

if ($Phase -eq 'Stop') {
    & $quickstart -Phase Stop
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_GOLDEN_PATH_STOP_FAILED' }
    Assert-ZeroProjectResources
    if (Test-Path -LiteralPath $artifactRoot) { throw 'ALPHA_GOLDEN_PATH_ARTIFACT_CLEANUP_FAILED' }
    Write-Host 'ALPHA_GOLDEN_PATH_STOP_PASS; CONTAINERS=0; NETWORKS=0; VOLUMES=0; SYNTHETIC_MATERIAL=0'
    exit 0
}

Assert-ZeroProjectResources
if (Test-Path -LiteralPath $artifactRoot) { throw 'ALPHA_GOLDEN_PATH_ARTIFACT_ROOT_NOT_CLEAN' }
$cleanupRequired = $true
$failure = $null
$previousEnvironment = @{}
$environmentNames = @(
    'DIRECT_GATEWAY_URL',
    'DIRECT_GATEWAY_CA_FILE',
    'DIRECT_GATEWAY_ACTIVATION_CODE_ID',
    'DIRECT_GATEWAY_ACTIVATION_CODE',
    'DIRECT_GATEWAY_CONNECTOR_ID',
    'DIRECT_GATEWAY_OPERATION_ID',
    'DIRECT_GATEWAY_CORRELATION_ID',
    'DOTNET_NOLOGO',
    'DOTNET_CLI_TELEMETRY_OPTOUT',
    'DOTNET_SKIP_FIRST_TIME_EXPERIENCE')
foreach ($name in $environmentNames) { $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }

try {
    & $quickstart -Phase Start -SkipBuild:$SkipBuild -DotNetPath $dotnet
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_GOLDEN_PATH_START_FAILED' }

    $environment = Read-EnvironmentFile
    $provisioning = Get-Content -LiteralPath (Join-Path $rawRoot 'provisioning.json') -Raw | ConvertFrom-Json
    $fixture = Get-Content -LiteralPath (Join-Path $rawRoot 'fixture-public.json') -Raw | ConvertFrom-Json
    foreach ($name in @('directInstallationId', 'directActivationCodeId', 'directActivationCode')) {
        if ($null -eq $provisioning.PSObject.Properties[$name] -or [string]::IsNullOrWhiteSpace([string]$provisioning.$name)) {
            throw "ALPHA_GOLDEN_PATH_DIRECT_FIXTURE_MISSING:$name"
        }
    }

    $controlRoot = Join-Path $artifactRoot 'control'
    New-Item -ItemType Directory -Path $controlRoot | Out-Null
    $caPath = Join-Path $rawRoot 'certificates\ca.crt'
    $vendorBefore = Invoke-ControlJson -HostName 'vendor.m3.test' -Port 18445 -Path '/m3/stats' -HeaderName 'X-M3-Control-Token' -HeaderValue ([string]$environment.M3_VENDOR_CONTROL_TOKEN) -OutputPath (Join-Path $controlRoot 'vendor-before.json') -CaPath $caPath
    $vaultBefore = Invoke-ControlJson -HostName 'vault.m3.test' -Port 18444 -Path '/m3/stats' -HeaderName 'X-M3-Vault-Token' -HeaderValue ([string]$environment.M3_SYNTHETIC_VAULT_TOKEN) -OutputPath (Join-Path $controlRoot 'vault-before.json') -CaPath $caPath
    Restart-GatewayAndWait

    $correlationId = [Guid]::NewGuid()
    $env:DIRECT_GATEWAY_URL = 'https://localhost:18443'
    $env:DIRECT_GATEWAY_CA_FILE = $caPath
    $env:DIRECT_GATEWAY_ACTIVATION_CODE_ID = [string]$provisioning.directActivationCodeId
    $env:DIRECT_GATEWAY_ACTIVATION_CODE = [string]$provisioning.directActivationCode
    $env:DIRECT_GATEWAY_CONNECTOR_ID = 'sample-secure-service'
    $env:DIRECT_GATEWAY_OPERATION_ID = 'submit'
    $env:DIRECT_GATEWAY_CORRELATION_ID = $correlationId.ToString('D')
    $env:DOTNET_NOLOGO = '1'
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
    $sampleOutput = @(& $dotnet run --project (Join-Path $root 'samples\DirectGatewayClient\DirectGatewayClient.csproj') --configuration Release 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_GOLDEN_PATH_DIRECT_SAMPLE_FAILED' }
    $sampleLines = @($sampleOutput | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_.StartsWith('{', [StringComparison]::Ordinal) })
    if ($sampleLines.Count -ne 1) { throw 'ALPHA_GOLDEN_PATH_DIRECT_SAMPLE_OUTPUT_INVALID' }
    $sampleResult = $sampleLines[0] | ConvertFrom-Json
    if ($sampleResult.accepted -ne $true -or [string]$sampleResult.vendorReference -cne 'synthetic-order') {
        throw 'ALPHA_GOLDEN_PATH_DIRECT_SAMPLE_RESPONSE_INVALID'
    }

    $vendorAfter = Invoke-ControlJson -HostName 'vendor.m3.test' -Port 18445 -Path '/m3/stats' -HeaderName 'X-M3-Control-Token' -HeaderValue ([string]$environment.M3_VENDOR_CONTROL_TOKEN) -OutputPath (Join-Path $controlRoot 'vendor-after.json') -CaPath $caPath
    $vaultAfter = Invoke-ControlJson -HostName 'vault.m3.test' -Port 18444 -Path '/m3/stats' -HeaderName 'X-M3-Vault-Token' -HeaderValue ([string]$environment.M3_SYNTHETIC_VAULT_TOKEN) -OutputPath (Join-Path $controlRoot 'vault-after.json') -CaPath $caPath
    $outboundCount = [long]$vendorAfter.accepted - [long]$vendorBefore.accepted
    if ($outboundCount -ne 1 -or $null -eq $vendorAfter.lastAccepted) { throw 'ALPHA_GOLDEN_PATH_OUTBOUND_COUNT_INVALID' }
    [byte[]] $expectedBody = [Text.Encoding]::UTF8.GetBytes('{"message":"direct-gateway-sample"}')
    try { $expectedBodySha256 = Get-Sha256Hex -Bytes $expectedBody }
    finally { [Array]::Clear($expectedBody, 0, $expectedBody.Length) }
    if ([string]$vendorAfter.lastAccepted.method -cne 'POST' -or
        [string]$vendorAfter.lastAccepted.path -cne '/vendor/orders' -or
        [string]$vendorAfter.lastAccepted.contentType -cne 'application/json' -or
        [string]$vendorAfter.lastAccepted.bodySha256 -cne $expectedBodySha256 -or
        [string]$vendorAfter.lastAccepted.clientCertificateSha256 -cne [string]$fixture.vendorClientCertificateSha256) {
        throw 'ALPHA_GOLDEN_PATH_OUTBOUND_METADATA_INVALID'
    }
    $apiKeyReads = (Get-ReadCount -Stats $vaultAfter -Name 'vendor-api-key') - (Get-ReadCount -Stats $vaultBefore -Name 'vendor-api-key')
    $certificateReads = (Get-ReadCount -Stats $vaultAfter -Name 'vendor-client-certificate') - (Get-ReadCount -Stats $vaultBefore -Name 'vendor-client-certificate')
    if ($apiKeyReads -lt 1 -or $certificateReads -lt 1) { throw 'ALPHA_GOLDEN_PATH_SYNTHETIC_PROVIDER_NOT_USED' }

    $postgres = @(& docker ps -q --filter ('label=com.docker.compose.project=' + $project) --filter 'label=com.docker.compose.service=postgres')
    if ($LASTEXITCODE -ne 0 -or $postgres.Count -ne 1) { throw 'ALPHA_GOLDEN_PATH_POSTGRES_NOT_FOUND' }
    $sql = "SELECT json_build_object('action',action,'outcome',outcome,'reasonCode',reason_code,'metadata',metadata_redacted)::text FROM gateway.audit_event WHERE correlation_id='$($correlationId.ToString('D'))' AND action='operation.invoke' AND outcome='success';"
    $auditRows = @(& docker exec ([string]$postgres[0]) psql -U postgres -d broker_gateway_m3 -Atc $sql)
    if ($LASTEXITCODE -ne 0 -or $auditRows.Count -ne 1) { throw 'ALPHA_GOLDEN_PATH_AUDIT_INVALID' }
    $auditText = [string]$auditRows[0]
    $audit = $auditText | ConvertFrom-Json
    if ([string]$audit.action -cne 'operation.invoke' -or [string]$audit.outcome -cne 'success') { throw 'ALPHA_GOLDEN_PATH_AUDIT_INVALID' }

    $canaries = @()
    foreach ($name in @('M3_VENDOR_API_KEY','M3_SYNTHETIC_VAULT_TOKEN','M3_VENDOR_CONTROL_TOKEN','M3_POSTGRES_ADMIN_PASSWORD','M3_POSTGRES_RUNTIME_PASSWORD','M3_CERTIFICATE_PASSWORD','M3_ACTIVATION_HMAC_BASE64','M5_POSTGRES_ADMIN_API_PASSWORD')) {
        if ($environment.ContainsKey($name)) { $canaries += [pscustomobject]@{ Name = $name; Value = [string]$environment[$name] } }
    }
    $canaries += [pscustomobject]@{ Name = 'DIRECT_ACTIVATION_CODE'; Value = [string]$provisioning.directActivationCode }
    Assert-RedactedText -Text ($sampleOutput -join [Environment]::NewLine) -Canaries $canaries
    Assert-RedactedText -Text $auditText -Canaries $canaries
    $composeArguments = @('compose', '--project-name', $project, '--env-file', $envFile, '--file', $baseCompose, '--file', $overlayCompose, 'logs', '--no-color')
    $containerLogs = (& docker @composeArguments 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_GOLDEN_PATH_LOG_COLLECTION_FAILED' }
    Assert-RedactedText -Text $containerLogs -Canaries $canaries

    Write-Host 'ALPHA_GOLDEN_PATH_DIRECT_PASS; CONNECTOR=sample-secure-service; OPERATION=submit; VERSION=1.0.0'
    Write-Host "ALPHA_GOLDEN_PATH_OUTBOUND_PASS; POSITIVE_OUTBOUND_COUNT=$outboundCount; METHOD=POST; PATH=/vendor/orders; CONTENT_TYPE=application/json"
    Write-Host "ALPHA_GOLDEN_PATH_PROVIDER_PASS; API_KEY_READS=$apiKeyReads; CERTIFICATE_READS=$certificateReads"
    Write-Host 'ALPHA_GOLDEN_PATH_RESPONSE_PASS; SANITIZED=YES; AUDIT=METADATA_ONLY; LOGS=REDACTED'
}
catch { $failure = $_ }
finally {
    foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process') }
    if ($cleanupRequired) {
        try {
            & $quickstart -Phase Stop
            if ($LASTEXITCODE -ne 0) { throw 'ALPHA_GOLDEN_PATH_STOP_FAILED' }
        }
        catch {
            if ($null -eq $failure) { $failure = $_ }
        }
    }
}

if ($null -ne $failure) { throw $failure }
Assert-ZeroProjectResources
if (Test-Path -LiteralPath $artifactRoot) { throw 'ALPHA_GOLDEN_PATH_ARTIFACT_CLEANUP_FAILED' }
Write-Host 'ALPHA_GOLDEN_PATH_CLEANUP_PASS; CONTAINERS=0; NETWORKS=0; VOLUMES=0; SYNTHETIC_MATERIAL=0'
Write-Host 'ALPHA_GOLDEN_PATH_PASS'

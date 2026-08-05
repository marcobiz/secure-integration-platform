[CmdletBinding()]
param([switch] $UseExistingImages)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$quickstart = Join-Path $PSScriptRoot 'Invoke-M5Quickstart.ps1'
$web = Join-Path $root 'src\Admin\Admin.Web'
$results = Join-Path $root '.artifacts\m5\full-stack-results'
$project = 'secure-integration-m5-quickstart'
$nodeVolume = "$project-playwright-node-modules"
$started = $false
if (Test-Path -LiteralPath $results) { Remove-Item -LiteralPath $results -Recurse -Force }
New-Item -ItemType Directory -Path $results -Force | Out-Null

try {
    & $quickstart -Phase Start -SkipBuild:$UseExistingImages
    if ($LASTEXITCODE -ne 0) { throw 'M5_FULLSTACK_START_FAILED' }
    $started = $true
    $gateway = (& docker compose --project-name $project --env-file (Join-Path $root '.artifacts\m5\quickstart\raw\m3a.env') --file (Join-Path $root 'deploy\m3\docker-compose.m3a.yml') --file (Join-Path $root 'deploy\m5\docker-compose.m5.yml') ps --quiet gateway).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gateway)) { throw 'M5_FULLSTACK_GATEWAY_CONTAINER_MISSING' }
    & docker volume create --label "com.docker.compose.project=$project" $nodeVolume | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'M5_FULLSTACK_NODE_VOLUME_FAILED' }
    $webMount = ($web -replace '\\', '/')
    $resultsMount = ($results -replace '\\', '/')
    & docker run --rm --name "$project-playwright" --network "container:$gateway" `
        --volume "${webMount}:/work:ro" --volume "${nodeVolume}:/work/node_modules" --volume "${resultsMount}:/work/test-results" `
        --workdir /work --env M5_FULLSTACK_BASE_URL=https://localhost:8443/admin/ `
        mcr.microsoft.com/playwright:v1.62.1-noble `
        /bin/bash -lc 'npm ci --ignore-scripts --loglevel=error && npx playwright test --config playwright.fullstack.config.ts'
    if ($LASTEXITCODE -ne 0) { throw 'M5_FULLSTACK_PLAYWRIGHT_FAILED' }
    $envFile = Join-Path $root '.artifacts\m5\quickstart\raw\m3a.env'
    $containerLog = Join-Path $results 'container.log'
    & docker compose --project-name $project --env-file $envFile --file (Join-Path $root 'deploy\m3\docker-compose.m3a.yml') --file (Join-Path $root 'deploy\m5\docker-compose.m5.yml') logs --no-color *> $containerLog
    if ($LASTEXITCODE -ne 0) { throw 'M5_FULLSTACK_LOG_COLLECTION_FAILED' }
    $sensitiveNames = @('M3_VENDOR_API_KEY','M3_SYNTHETIC_VAULT_TOKEN','M3_VENDOR_CONTROL_TOKEN','M3_POSTGRES_ADMIN_PASSWORD','M3_POSTGRES_RUNTIME_PASSWORD','M3_CERTIFICATE_PASSWORD','M3_ACTIVATION_HMAC_BASE64','M5_POSTGRES_ADMIN_API_PASSWORD')
    $canaries = foreach ($line in Get-Content -LiteralPath $envFile) {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0 -and $line.Substring(0, $separator) -in $sensitiveNames) {
            [pscustomobject]@{ Name = $line.Substring(0, $separator); Value = $line.Substring($separator + 1) }
        }
    }
    $redactedFiles = Get-ChildItem -LiteralPath $results -File -Recurse
    foreach ($canary in $canaries) {
        if ([string]::IsNullOrWhiteSpace($canary.Value) -or $canary.Value.Length -lt 8) { continue }
        foreach ($file in $redactedFiles) {
            if (Select-String -LiteralPath $file.FullName -SimpleMatch $canary.Value -Quiet -ErrorAction SilentlyContinue) {
                throw "M5_FULLSTACK_REDACTION_FAILED:$($canary.Name):$($file.Name)"
            }
        }
    }
    Write-Host 'M5_FULLSTACK_REDACTION_PASS'
    Write-Host 'M5_FULLSTACK_PASS'
} catch {
    if ($started) {
        $envFile = Join-Path $root '.artifacts\m5\quickstart\raw\m3a.env'
        if (Test-Path -LiteralPath $envFile) {
            New-Item -ItemType Directory -Path $results -Force | Out-Null
            & docker compose --project-name $project --env-file $envFile --file (Join-Path $root 'deploy\m3\docker-compose.m3a.yml') --file (Join-Path $root 'deploy\m5\docker-compose.m5.yml') logs --no-color *> (Join-Path $results 'container-failure.log')
        }
    }
    throw
} finally {
    if ($started -or (Test-Path -LiteralPath (Join-Path $root '.artifacts\m5\quickstart\raw\m3a.env'))) {
        & $quickstart -Phase Stop
        if ($LASTEXITCODE -ne 0) { throw 'M5_FULLSTACK_CLEANUP_FAILED' }
    }
    & docker volume rm --force $nodeVolume 2>$null | Out-Null
}

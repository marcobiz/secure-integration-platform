[CmdletBinding()]
param(
    [string] $SbomDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) '.artifacts\sbom'),
    [switch] $SkipContainer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expected = [ordered]@{
    'gateway.spdx.json' = @('SecureIntegration.Gateway.Api', 'Npgsql')
    'broker.spdx.json' = @('SecureIntegration.Broker.Service', 'System.Security.Cryptography.ProtectedData')
    'sdk-dotnet.spdx.json' = @('SecureIntegration.Broker.Sdk', 'System.Text.Json')
    'connector-cli.spdx.json' = @('SecureIntegration.Connector.Cli', 'JsonSchema.Net')
    'auth-certificate-signing.spdx.json' = @('SecureIntegration.Authentication.CertificateSigning', 'SecureIntegration.Providers.Abstractions')
    'admin-frontend.spdx.json' = @('@secure-integration/admin-web', 'react')
}
if (-not $SkipContainer) { $expected['gateway-container.spdx.json'] = @('SecureIntegration.Gateway.Api', 'Npgsql') }
$manifestPath = Join-Path $SbomDirectory 'aggregate-manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath)) { throw 'SBOM_AGGREGATE_MANIFEST_MISSING' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
foreach ($entry in $expected.GetEnumerator()) {
    $path = Join-Path $SbomDirectory $entry.Key
    if (-not (Test-Path -LiteralPath $path)) { throw "SBOM_ARTIFACT_MISSING_$($entry.Key)" }
    $document = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($document.spdxVersion -notin @('SPDX-2.2','SPDX-2.3')) { throw "SBOM_FORMAT_INVALID_$($entry.Key)" }
    $names = @($document.packages | ForEach-Object { [string]$_.name })
    foreach ($name in $entry.Value) {
        if (-not ($names | Where-Object { $_ -ieq $name -or $_ -like "*$name*" })) { throw "SBOM_COMPONENT_MISSING_$($entry.Key)_$name" }
    }
    $record = @($manifest.artifacts | Where-Object file -eq $entry.Key)
    if ($record.Count -ne 1) { throw "SBOM_MANIFEST_ENTRY_INVALID_$($entry.Key)" }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $record[0].sha256) { throw "SBOM_HASH_MISMATCH_$($entry.Key)" }
}
Write-Host 'SBOM_VALIDATION_PASS'

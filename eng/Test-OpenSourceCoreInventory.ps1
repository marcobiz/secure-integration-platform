[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $ExportDirectory,
    [string] $ExpectedSourceCommit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$exportRoot = [IO.Path]::GetFullPath($ExportDirectory)
if (-not (Test-Path -LiteralPath $exportRoot -PathType Container)) { throw 'CORE_INVENTORY_EXPORT_MISSING' }
Import-Module (Join-Path $PSScriptRoot 'CoreExportInventory.psm1') -Force

$manifestPath = Join-Path $exportRoot 'OPEN_SOURCE_EXPORT_MANIFEST.json'
$manifestSidecarPath = $manifestPath + '.sha256'
$inventoryPath = Join-Path $exportRoot 'OPEN_SOURCE_EXPORT_INVENTORY.normalized.json'
$inventorySidecarPath = $inventoryPath + '.sha256'
foreach ($required in @($manifestPath, $manifestSidecarPath, $inventoryPath, $inventorySidecarPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw 'CORE_INVENTORY_METADATA_MISSING' }
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ([int]$manifest.schemaVersion -ne 1 -or $null -eq $manifest.generatedAtUtc -or
    [string]::IsNullOrWhiteSpace([string]$manifest.generatedAtUtc)) { throw 'CORE_INVENTORY_MANIFEST_INVALID' }
$sourceCommit = [string]$manifest.sourceCommit
if (-not [string]::IsNullOrWhiteSpace($ExpectedSourceCommit) -and $sourceCommit -cne $ExpectedSourceCommit) {
    throw 'CORE_INVENTORY_SOURCE_COMMIT_MISMATCH'
}
$files = @($manifest.files)
if ([int]$manifest.fileCount -ne $files.Count) { throw 'CORE_INVENTORY_FILE_COUNT_MISMATCH' }
$identity = New-CoreInventoryIdentity -SourceCommit $sourceCommit -Files $files
if ([string]$manifest.normalizedInventorySha256 -cne $identity.normalizedInventorySha256) {
    throw 'CORE_INVENTORY_NORMALIZED_DIGEST_MISMATCH'
}

[byte[]]$expectedInventoryBytes = [Text.UTF8Encoding]::new($false).GetBytes($identity.canonicalJson)
try {
    [byte[]]$actualInventoryBytes = [IO.File]::ReadAllBytes($inventoryPath)
    try {
        if ($actualInventoryBytes.Length -ne $expectedInventoryBytes.Length) { throw 'CORE_INVENTORY_CANONICAL_PAYLOAD_MISMATCH' }
        for ($index = 0; $index -lt $actualInventoryBytes.Length; $index++) {
            if ($actualInventoryBytes[$index] -ne $expectedInventoryBytes[$index]) { throw 'CORE_INVENTORY_CANONICAL_PAYLOAD_MISMATCH' }
        }
    }
    finally { [Array]::Clear($actualInventoryBytes, 0, $actualInventoryBytes.Length) }
}
finally { [Array]::Clear($expectedInventoryBytes, 0, $expectedInventoryBytes.Length) }

$inventorySidecar = (Get-Content -LiteralPath $inventorySidecarPath -Raw).Trim()
if ($inventorySidecar -cne ($identity.normalizedInventorySha256 + '  OPEN_SOURCE_EXPORT_INVENTORY.normalized.json')) {
    throw 'CORE_INVENTORY_NORMALIZED_SIDECAR_MISMATCH'
}
$rawManifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
$manifestSidecar = (Get-Content -LiteralPath $manifestSidecarPath -Raw).Trim()
if ($manifestSidecar -cne ($rawManifestSha256 + '  OPEN_SOURCE_EXPORT_MANIFEST.json')) {
    throw 'CORE_INVENTORY_RAW_MANIFEST_SIDECAR_MISMATCH'
}

$expectedPaths = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach ($entry in $files) {
    $relative = [string]$entry.path
    [void]$expectedPaths.Add($relative)
    $fullPath = [IO.Path]::GetFullPath((Join-Path $exportRoot $relative))
    if (-not $fullPath.StartsWith($exportRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { throw "CORE_INVENTORY_FILE_MISSING: $relative" }
    $actualBytes = [IO.FileInfo]::new($fullPath).Length
    $actualSha256 = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash
    if ($actualBytes -ne [long]$entry.bytes -or $actualSha256 -cne [string]$entry.sha256) {
        throw "CORE_INVENTORY_FILE_CONTENT_MISMATCH: $relative"
    }
}

$metadataNames = @(
    'OPEN_SOURCE_EXPORT_MANIFEST.json',
    'OPEN_SOURCE_EXPORT_MANIFEST.json.sha256',
    'OPEN_SOURCE_EXPORT_INVENTORY.normalized.json',
    'OPEN_SOURCE_EXPORT_INVENTORY.normalized.json.sha256')
foreach ($file in Get-ChildItem -LiteralPath $exportRoot -Recurse -File) {
    $relative = $file.FullName.Substring($exportRoot.Length + 1).Replace('\', '/')
    if (-not $expectedPaths.Contains($relative) -and $metadataNames -cnotcontains $relative) {
        throw "CORE_INVENTORY_UNEXPECTED_FILE: $relative"
    }
}

[pscustomobject]@{
    status = 'PASS'
    sourceCommit = $sourceCommit
    fileCount = $files.Count
    rawManifestSha256 = $rawManifestSha256
    normalizedInventorySha256 = $identity.normalizedInventorySha256
} | ConvertTo-Json -Compress

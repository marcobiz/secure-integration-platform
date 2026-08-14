[CmdletBinding()]
param(
    [ValidateSet('All', 'DriveQualifiedPaths', 'AdsPaths')]
    [string] $TestName = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $PSScriptRoot 'CoreExportInventory.psm1') -Force

function Assert-CoreInventoryPathRejected {
    param([Parameter(Mandatory = $true)][string] $Path, [Parameter(Mandatory = $true)][string] $FailureCode)
    $failed = $false
    try {
        New-CoreInventoryIdentity -SourceCommit ('a' * 40) -Files @([pscustomobject]@{ path = $Path; bytes = 1; sha256 = 'B' * 64 }) *> $null
    }
    catch {
        if (-not $_.Exception.Message.StartsWith('CORE_INVENTORY_PATH_INVALID:', [StringComparison]::Ordinal)) { throw }
        $failed = $true
    }
    if (-not $failed) { throw $FailureCode }
}

if ($TestName -in @('All', 'DriveQualifiedPaths')) {
    Assert-CoreInventoryPathRejected -Path 'C:/a.txt' -FailureCode 'CORE_INVENTORY_DRIVE_QUALIFIED_FORWARD_SLASH_DID_NOT_FAIL'
    Assert-CoreInventoryPathRejected -Path 'C:\a.txt' -FailureCode 'CORE_INVENTORY_DRIVE_QUALIFIED_BACKSLASH_DID_NOT_FAIL'
    Write-Host 'CORE_INVENTORY_DRIVE_QUALIFIED_PATH_NEGATIVE_PASS'
}
if ($TestName -in @('All', 'AdsPaths')) {
    Assert-CoreInventoryPathRejected -Path 'a.txt:stream' -FailureCode 'CORE_INVENTORY_ADS_ROOT_PATH_DID_NOT_FAIL'
    Assert-CoreInventoryPathRejected -Path 'folder/a.txt:stream' -FailureCode 'CORE_INVENTORY_ADS_NESTED_PATH_DID_NOT_FAIL'
    Write-Host 'CORE_INVENTORY_ADS_PATH_NEGATIVE_PASS'
}
if ($TestName -ne 'All') { return }

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar))
$testRoot = Join-Path $tempBase ('core-inventory-determinism-' + [Guid]::NewGuid().ToString('N'))
if (-not $testRoot.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'CORE_INVENTORY_TEST_ROOT_INVALID'
}
New-Item -ItemType Directory -Path $testRoot | Out-Null

function Copy-InventoryFiles([object[]] $Files) {
    return @(($Files | ConvertTo-Json -Depth 8) | ConvertFrom-Json)
}

function Get-Identity([string] $SourceCommit, [object[]] $Files) {
    return New-CoreInventoryIdentity -SourceCommit $SourceCommit -Files $Files
}

try {
    $run1 = Join-Path $testRoot 'run-1'
    $run2 = Join-Path $testRoot 'run-2'
    & (Join-Path $PSScriptRoot 'Export-OpenSourceCore.ps1') -OutputDirectory $run1 -SkipVerification *> $null
    Start-Sleep -Milliseconds 20
    & (Join-Path $PSScriptRoot 'Export-OpenSourceCore.ps1') -OutputDirectory $run2 -SkipVerification *> $null

    $manifest1 = Get-Content -LiteralPath (Join-Path $run1 'OPEN_SOURCE_EXPORT_MANIFEST.json') -Raw | ConvertFrom-Json
    $manifest2 = Get-Content -LiteralPath (Join-Path $run2 'OPEN_SOURCE_EXPORT_MANIFEST.json') -Raw | ConvertFrom-Json
    if ([string]$manifest1.generatedAtUtc -ceq [string]$manifest2.generatedAtUtc) { throw 'CORE_INVENTORY_TIMESTAMP_CONTROL_INVALID' }
    if ([string]$manifest1.normalizedInventorySha256 -cne [string]$manifest2.normalizedInventorySha256) { throw 'CORE_INVENTORY_SAME_COMMIT_UNSTABLE' }

    $timestampOnly = Get-Identity -SourceCommit ([string]$manifest1.sourceCommit) -Files @($manifest1.files)
    if ($timestampOnly.normalizedInventorySha256 -cne [string]$manifest1.normalizedInventorySha256) { throw 'CORE_INVENTORY_TIMESTAMP_CHANGED_DIGEST' }

    $contentFiles = Copy-InventoryFiles -Files @($manifest1.files)
    $contentFiles[0].sha256 = if ([string]$contentFiles[0].sha256 -ceq ('A' * 64)) { 'B' * 64 } else { 'A' * 64 }
    $contentIdentity = Get-Identity -SourceCommit ([string]$manifest1.sourceCommit) -Files $contentFiles
    if ($contentIdentity.normalizedInventorySha256 -ceq [string]$manifest1.normalizedInventorySha256) { throw 'CORE_INVENTORY_CONTENT_NEGATIVE_FAILED' }

    $pathFiles = Copy-InventoryFiles -Files @($manifest1.files)
    $pathFiles[0].path = [string]$pathFiles[0].path + '.controlled-path-change'
    $pathIdentity = Get-Identity -SourceCommit ([string]$manifest1.sourceCommit) -Files $pathFiles
    if ($pathIdentity.normalizedInventorySha256 -ceq [string]$manifest1.normalizedInventorySha256) { throw 'CORE_INVENTORY_PATH_NEGATIVE_FAILED' }

    $sizeHashFiles = Copy-InventoryFiles -Files @($manifest1.files)
    $sizeHashFiles[0].bytes = [long]$sizeHashFiles[0].bytes + 1
    $sizeHashFiles[0].sha256 = if ([string]$sizeHashFiles[0].sha256 -ceq ('C' * 64)) { 'D' * 64 } else { 'C' * 64 }
    $sizeHashIdentity = Get-Identity -SourceCommit ([string]$manifest1.sourceCommit) -Files $sizeHashFiles
    if ($sizeHashIdentity.normalizedInventorySha256 -ceq [string]$manifest1.normalizedInventorySha256) { throw 'CORE_INVENTORY_SIZE_HASH_NEGATIVE_FAILED' }

    $tamperedRelative = [string]$manifest1.files[0].path
    $tamperedPath = Join-Path $run1 $tamperedRelative
    [IO.File]::AppendAllText($tamperedPath, "`ncontrolled-tamper", [Text.UTF8Encoding]::new($false))
    $failedClosed = $false
    try { & (Join-Path $PSScriptRoot 'Test-OpenSourceCoreInventory.ps1') -ExportDirectory $run1 *> $null }
    catch { $failedClosed = $true }
    if (-not $failedClosed) { throw 'CORE_INVENTORY_VERIFIER_DID_NOT_FAIL_CLOSED' }

    Write-Host "CORE_INVENTORY_SAME_COMMIT_STABLE_PASS; DIGEST=$($manifest2.normalizedInventorySha256)"
    Write-Host 'CORE_INVENTORY_TIMESTAMP_NEGATIVE_PASS'
    Write-Host 'CORE_INVENTORY_CONTENT_NEGATIVE_PASS'
    Write-Host 'CORE_INVENTORY_PATH_NEGATIVE_PASS'
    Write-Host 'CORE_INVENTORY_SIZE_HASH_NEGATIVE_PASS'
    Write-Host 'CORE_INVENTORY_FAIL_CLOSED_PASS'
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        $resolved = [IO.Path]::GetFullPath($testRoot)
        if (-not $resolved.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'CORE_INVENTORY_TEST_CLEANUP_TARGET_INVALID'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

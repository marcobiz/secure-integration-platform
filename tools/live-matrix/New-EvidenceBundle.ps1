[CmdletBinding()]
param([Parameter(Mandatory)] [string] $RunId)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'LiveMatrix.Common.psm1') -Force -DisableNameChecking
Assert-LiveMatrixAdministrator

$paths = Get-LiveMatrixPaths -RunId $RunId
$bundleDirectory = Join-Path $paths.Evidence 'bundle'
if (Test-Path -LiteralPath $bundleDirectory) {
    $resolved = [IO.Path]::GetFullPath($bundleDirectory)
    if (-not $resolved.StartsWith([IO.Path]::GetFullPath($paths.Evidence), [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing to clean an unexpected evidence directory.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
New-Item -ItemType Directory -Path $bundleDirectory -Force | Out-Null

$allowList = @(
    'prerequisites.json', 'installation.json', 'scm-configuration.json',
    'authorized-pre.json', 'same-user-policy.json', 'same-user-storage.json',
    'other-user-pipe.json', 'other-user-storage.json',
    'authorized-dpapi-denied.json', 'same-user-dpapi-denied.json', 'other-user-dpapi-denied.json',
    'legacy-encrypted-database.json', 'after-service-restart.json', 'tampered-key.json',
    'after-tamper-restore.json', 'pre-reboot-summary.json', 'post-reboot-authorized.json',
    'post-reboot-other-user.json', 'post-reboot-summary.json', 'pipe-acl.json',
    'storage-acl.json', 'post-reboot-storage-acl.json', 'event-log.json', 'redaction-scan.json'
)
foreach ($name in $allowList) {
    $source = Join-Path $paths.Raw $name
    if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination (Join-Path $bundleDirectory $name) -Force }
}

$prerequisites = Get-Content -Raw -LiteralPath (Join-Path $paths.Raw 'prerequisites.json') | ConvertFrom-Json
$commit = [string]$prerequisites.repositoryCommit
if ($commit -notmatch '^[a-fA-F0-9]{40}$') { throw 'The recorded repository commit is invalid.' }
$files = @()
foreach ($file in Get-ChildItem -LiteralPath $bundleDirectory -File | Sort-Object Name) {
    $files += [ordered]@{ name = $file.Name; bytes = $file.Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash }
}
$manifest = [ordered]@{
    schema = 'secureintegration.live-matrix.evidence/v1'
    runId = $RunId
    repositoryCommit = $commit
    generatedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    redaction = 'Canary and generic secret-pattern scans passed before bundle creation. Credentials, inputs, plaintext, secret values, key blobs and persistent envelopes are excluded.'
    manifestSelfHash = 'excluded-to-avoid-circular-hash'
    files = $files
}
Write-LiveMatrixJson -Value $manifest -Path (Join-Path $bundleDirectory 'manifest.json')

$zipPath = Join-Path $paths.Evidence ("M0-M1-live-matrix-$RunId.zip")
Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $bundleDirectory '*') -DestinationPath $zipPath -CompressionLevel Optimal
$zipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash
[IO.File]::WriteAllText(($zipPath + '.sha256'), "$zipHash  $([IO.Path]::GetFileName($zipPath))`r`n", [Text.UTF8Encoding]::new($false))

[pscustomobject]@{ BundlePath = $zipPath; Sha256 = $zipHash; ManifestPath = Join-Path $bundleDirectory 'manifest.json' }

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $EvidenceDirectory,
    [Parameter(Mandatory = $true)][string] $ExpectedSourceCommit,
    [Parameter(Mandatory = $true)][string] $ExpectedRunId,
    [Parameter(Mandatory = $true)][string] $ExpectedNormalizedDigest,
    [Parameter(Mandatory = $true)][string] $ExpectedProductVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AlphaReleaseEvidenceContract.psm1') -Force
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
if (-not (Test-Path -LiteralPath $evidence -PathType Container)) { throw 'ALPHA_ART_EVIDENCE_DIRECTORY_MISSING' }
if ($ExpectedSourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'ALPHA_ART_EVIDENCE_EXPECTED_SOURCE_INVALID' }
if ($ExpectedRunId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{5,127}$') { throw 'ALPHA_ART_EVIDENCE_EXPECTED_RUN_ID_INVALID' }
if ($ExpectedNormalizedDigest -cnotmatch '^[0-9A-F]{64}$') { throw 'ALPHA_ART_EVIDENCE_EXPECTED_NORMALIZED_DIGEST_INVALID' }
if ($ExpectedProductVersion -cne '0.1.0-alpha.1') { throw 'ALPHA_ART_EVIDENCE_EXPECTED_PRODUCT_VERSION_INVALID' }

function Get-Sha256Hex {
    param([string] $LiteralPath)
    $stream = [IO.File]::OpenRead($LiteralPath)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace('-', '') }
    finally { $sha256.Dispose(); $stream.Dispose() }
}

$manifestPath = Join-Path $evidence 'evidence-manifest.json'
$sidecarPath = Join-Path $evidence 'evidence-manifest.json.sha256'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or -not (Test-Path -LiteralPath $sidecarPath -PathType Leaf)) { throw 'ALPHA_ART_EVIDENCE_MANIFEST_MISSING' }
try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json }
catch { throw 'ALPHA_ART_EVIDENCE_MANIFEST_INVALID' }
if ([string]$manifest.schema -cne 'secure-integration.alpha-release-evidence.v1') { throw 'ALPHA_ART_EVIDENCE_MANIFEST_SCHEMA_INVALID' }
$runId = [string]$manifest.runId
$sourceCommit = [string]$manifest.sourceRevision
$normalizedDigest = [string]$manifest.normalizedInventorySha256
$productVersion = [string]$manifest.productVersion
if ($runId -cne $ExpectedRunId) { throw 'ALPHA_ART_EVIDENCE_RUN_ID_MISMATCH: evidence-manifest.json' }
if ($sourceCommit -cne $ExpectedSourceCommit) { throw 'ALPHA_ART_EVIDENCE_SOURCE_SHA_MISMATCH: evidence-manifest.json' }
if ($normalizedDigest -cnotmatch '^[0-9A-F]{64}$') { throw 'ALPHA_ART_EVIDENCE_NORMALIZED_DIGEST_INVALID' }
if ($normalizedDigest -cne $ExpectedNormalizedDigest) { throw 'ALPHA_ART_EVIDENCE_NORMALIZED_DIGEST_MISMATCH: evidence-manifest.json' }
if ($productVersion -cne $ExpectedProductVersion) { throw 'ALPHA_ART_EVIDENCE_PRODUCT_VERSION_MISMATCH: evidence-manifest.json' }

$records = @($manifest.records)
$recordNames = @($records | ForEach-Object { [string]$_.name })
Assert-AlphaReleaseEvidenceRecordInventory -RecordName $recordNames
$recordByName = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
foreach ($record in $records) {
    $name = [string]$record.name
    $recordByName.Add($name, $record)
}

$physical = @(Get-ChildItem -LiteralPath $evidence -File | Where-Object { $_.Name -notin @('evidence-manifest.json', 'evidence-manifest.json.sha256') })
if ($physical.Count -ne $recordByName.Count) { throw 'ALPHA_ART_EVIDENCE_RECORD_SET_MISMATCH' }
foreach ($file in $physical) {
    if (-not $recordByName.ContainsKey($file.Name)) { throw "ALPHA_ART_EVIDENCE_RECORD_UNEXPECTED: $($file.Name)" }
    $record = $recordByName[$file.Name]
    if ([long]$record.bytes -ne $file.Length) { throw "ALPHA_ART_EVIDENCE_FILE_SIZE_MISMATCH: $($file.Name)" }
    if ([string]$record.sha256 -cne (Get-Sha256Hex -LiteralPath $file.FullName)) { throw "ALPHA_ART_EVIDENCE_FILE_HASH_MISMATCH: $($file.Name)" }
}

$manifestSha256 = Get-Sha256Hex -LiteralPath $manifestPath
if ((Get-Content -LiteralPath $sidecarPath -Raw).Trim() -cne "$manifestSha256  evidence-manifest.json") { throw 'ALPHA_ART_EVIDENCE_MANIFEST_SIDECAR_MISMATCH' }
foreach ($name in Get-AlphaReleaseEvidenceRecordInventory) {
    try { $document = Get-Content -LiteralPath (Join-Path $evidence $name) -Raw | ConvertFrom-Json }
    catch { throw "ALPHA_ART_EVIDENCE_RECORD_INVALID: $name" }
    Assert-AlphaReleaseEvidenceRecord -Record $document -RecordName $name -ExpectedRunId $ExpectedRunId -ExpectedSourceCommit $ExpectedSourceCommit -ExpectedNormalizedDigest $ExpectedNormalizedDigest -ExpectedProductVersion $ExpectedProductVersion
}

$sensitivePatterns = @(
    '(?i)[A-Z]:\\(?:Users|Codice|SecureEvidence|Lab)\\',
    '(?i)/home/[^/\s]+/',
    '-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----',
    '(?i)authorization\s*:\s*(?:bearer|basic)\s+\S+',
    '(?i)(?:client_secret|password|activationCode)\s*[=:]\s*["''][^"'']{8,}')
foreach ($file in Get-ChildItem -LiteralPath $evidence -File) {
    $text = Get-Content -LiteralPath $file.FullName -Raw
    foreach ($pattern in $sensitivePatterns) {
        if ([regex]::IsMatch($text, $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
            throw "ALPHA_ART_EVIDENCE_REDACTION_FAILED: $($file.Name)"
        }
    }
}

[pscustomobject]@{
    status = 'PASS'
    runId = $runId
    sourceRevision = $sourceCommit
    normalizedInventorySha256 = $normalizedDigest
    productVersion = $productVersion
    recordCount = $recordByName.Count
    evidenceManifestSha256 = $manifestSha256
} | ConvertTo-Json -Compress

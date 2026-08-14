[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $EvidenceDirectory,
    [Parameter(Mandatory = $true)][string] $ExpectedSourceCommit,
    [Parameter(Mandatory = $true)][string] $ExpectedRunId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
if (-not (Test-Path -LiteralPath $evidence -PathType Container)) { throw 'ALPHA_ART_EVIDENCE_DIRECTORY_MISSING' }
if ($ExpectedSourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'ALPHA_ART_EVIDENCE_EXPECTED_SOURCE_INVALID' }
if ($ExpectedRunId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{5,127}$') { throw 'ALPHA_ART_EVIDENCE_EXPECTED_RUN_ID_INVALID' }

function Get-Sha256Hex {
    param([string] $LiteralPath)
    $stream = [IO.File]::OpenRead($LiteralPath)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace('-', '') }
    finally { $sha256.Dispose(); $stream.Dispose() }
}

function Assert-RecordIdentity {
    param($Record, [string] $Name, [string] $RunId, [string] $SourceCommit, [string] $NormalizedDigest)
    if ([string]$Record.runId -cne $RunId) { throw "ALPHA_ART_EVIDENCE_RUN_ID_MISMATCH: $Name" }
    if ([string]$Record.sourceRevision -cne $SourceCommit) { throw "ALPHA_ART_EVIDENCE_SOURCE_SHA_MISMATCH: $Name" }
    if ([string]$Record.normalizedInventorySha256 -cne $NormalizedDigest) { throw "ALPHA_ART_EVIDENCE_NORMALIZED_DIGEST_MISMATCH: $Name" }
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
if ($runId -cne $ExpectedRunId) { throw 'ALPHA_ART_EVIDENCE_RUN_ID_MISMATCH: evidence-manifest.json' }
if ($sourceCommit -cne $ExpectedSourceCommit) { throw 'ALPHA_ART_EVIDENCE_SOURCE_SHA_MISMATCH: evidence-manifest.json' }
if ($normalizedDigest -cnotmatch '^[0-9A-F]{64}$') { throw 'ALPHA_ART_EVIDENCE_NORMALIZED_DIGEST_INVALID' }

$records = @($manifest.records)
$recordByName = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
$namesIgnoreCase = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($record in $records) {
    $name = [string]$record.name
    if ($name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*\.(?:json|txt)$' -or -not $namesIgnoreCase.Add($name) -or $recordByName.ContainsKey($name)) {
        throw 'ALPHA_ART_EVIDENCE_RECORD_NAME_INVALID'
    }
    if ($name -in @('evidence-manifest.json', 'evidence-manifest.json.sha256')) { throw 'ALPHA_ART_EVIDENCE_RECORD_NAME_INVALID' }
    $recordByName.Add($name, $record)
}
foreach ($required in @('release-set.json', 'targeted-tests.json', 'qualification-summary.json')) {
    if (-not $recordByName.ContainsKey($required)) { throw "ALPHA_ART_EVIDENCE_REQUIRED_RECORD_MISSING: $required" }
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
foreach ($name in @('release-set.json', 'targeted-tests.json', 'qualification-summary.json')) {
    try { $document = Get-Content -LiteralPath (Join-Path $evidence $name) -Raw | ConvertFrom-Json }
    catch { throw "ALPHA_ART_EVIDENCE_RECORD_INVALID: $name" }
    Assert-RecordIdentity -Record $document -Name $name -RunId $runId -SourceCommit $sourceCommit -NormalizedDigest $normalizedDigest
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
    recordCount = $recordByName.Count
    evidenceManifestSha256 = $manifestSha256
} | ConvertTo-Json -Compress

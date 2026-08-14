[CmdletBinding()]
param(
    [ValidateSet('All', 'StaleOrCrossRun')]
    [string] $TestName = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$validator = Join-Path $PSScriptRoot 'Test-AlphaReleaseEvidence.ps1'
$sourceCommit = 'c' * 40
$normalizedDigest = ('D' * 64)
$runId = 'current-run-001'
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar))
$testRoot = Join-Path $tempBase ('alpha-evidence-consistency-' + [Guid]::NewGuid().ToString('N'))
if (-not $testRoot.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'ALPHA_ART_EVIDENCE_TEST_ROOT_INVALID' }

function Write-Utf8NoBom {
    param([string] $Path, [AllowEmptyString()][string] $Value)
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}

function Get-Sha256Hex {
    param([string] $LiteralPath)
    $stream = [IO.File]::OpenRead($LiteralPath)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace('-', '') }
    finally { $sha256.Dispose(); $stream.Dispose() }
}

function Write-EvidenceManifest {
    param([string] $Directory)
    $records = @(Get-ChildItem -LiteralPath $Directory -File | Where-Object { $_.Name -notin @('evidence-manifest.json','evidence-manifest.json.sha256') } | Sort-Object Name | ForEach-Object {
        [ordered]@{ name = $_.Name; bytes = $_.Length; sha256 = Get-Sha256Hex -LiteralPath $_.FullName }
    })
    $manifest = [ordered]@{
        schema = 'secure-integration.alpha-release-evidence.v1'; generatedAtUtc = '2026-01-01T00:00:00Z'; runId = $runId
        sourceRevision = $sourceCommit; normalizedInventorySha256 = $normalizedDigest; redacted = $true; records = $records
    }
    $manifestPath = Join-Path $Directory 'evidence-manifest.json'
    Write-Utf8NoBom -Path $manifestPath -Value ($manifest | ConvertTo-Json -Depth 12)
    [IO.File]::WriteAllText((Join-Path $Directory 'evidence-manifest.json.sha256'), "$(Get-Sha256Hex -LiteralPath $manifestPath)  evidence-manifest.json`r`n", [Text.Encoding]::ASCII)
}

function New-BaselineEvidence {
    param([string] $Directory)
    New-Item -ItemType Directory -Path $Directory | Out-Null
    foreach ($name in @('release-set.json','targeted-tests.json','qualification-summary.json')) {
        $record = [ordered]@{
            schema = 'synthetic-evidence-consistency-test.v1'; runId = $runId; sourceRevision = $sourceCommit
            normalizedInventorySha256 = $normalizedDigest; status = 'PASS'; recordName = $name
        }
        Write-Utf8NoBom -Path (Join-Path $Directory $name) -Value ($record | ConvertTo-Json -Depth 6)
    }
    Write-EvidenceManifest -Directory $Directory
}

function Invoke-Negative {
    param([string] $Name, [string] $ExpectedCode, [scriptblock] $Mutation, [string] $Baseline)
    $case = Join-Path $testRoot ('case-' + $Name)
    Copy-Item -LiteralPath $Baseline -Destination $case -Recurse
    & $Mutation $case
    $message = $null
    $captured = @()
    try { $captured = @(& $validator -EvidenceDirectory $case -ExpectedSourceCommit $sourceCommit -ExpectedRunId $runId 2>&1 | ForEach-Object { $_.ToString() }) }
    catch { $message = [string]$_.Exception.Message }
    if ([string]::IsNullOrWhiteSpace($message)) { throw "ALPHA_ART_EVIDENCE_NEGATIVE_DID_NOT_FAIL: $Name" }
    if (-not $message.StartsWith($ExpectedCode, [StringComparison]::Ordinal)) { throw "ALPHA_ART_EVIDENCE_NEGATIVE_WRONG_CODE: $Name; ACTUAL=$message" }
    if (($captured -join "`n").Contains('PASS')) { throw "ALPHA_ART_EVIDENCE_NEGATIVE_EMITTED_PASS: $Name" }
    Write-Host "ALPHA_ART_EVIDENCE_NEGATIVE_OK; NAME=$Name; CODE=$ExpectedCode"
}

New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $baseline = Join-Path $testRoot 'baseline'
    New-BaselineEvidence -Directory $baseline
    $positive = (& $validator -EvidenceDirectory $baseline -ExpectedSourceCommit $sourceCommit -ExpectedRunId $runId | Out-String).Trim() | ConvertFrom-Json
    if ([string]$positive.status -cne 'PASS' -or [string]$positive.normalizedInventorySha256 -cne $normalizedDigest) { throw 'ALPHA_ART_EVIDENCE_POSITIVE_FAILED' }

    if ($TestName -in @('All', 'StaleOrCrossRun')) {
        Invoke-Negative -Name 'StaleTargetedDigest' -ExpectedCode 'ALPHA_ART_EVIDENCE_NORMALIZED_DIGEST_MISMATCH:' -Baseline $baseline -Mutation {
            param($case); $path=Join-Path $case 'targeted-tests.json'; $record=Get-Content $path -Raw | ConvertFrom-Json; $record.normalizedInventorySha256='E' * 64; Write-Utf8NoBom -Path $path -Value ($record | ConvertTo-Json -Depth 6); Write-EvidenceManifest -Directory $case
        }
        Invoke-Negative -Name 'StaleSummaryDigest' -ExpectedCode 'ALPHA_ART_EVIDENCE_NORMALIZED_DIGEST_MISMATCH:' -Baseline $baseline -Mutation {
            param($case); $path=Join-Path $case 'qualification-summary.json'; $record=Get-Content $path -Raw | ConvertFrom-Json; $record.normalizedInventorySha256='E' * 64; Write-Utf8NoBom -Path $path -Value ($record | ConvertTo-Json -Depth 6); Write-EvidenceManifest -Directory $case
        }
        Invoke-Negative -Name 'CrossRunTargetedRecord' -ExpectedCode 'ALPHA_ART_EVIDENCE_RUN_ID_MISMATCH:' -Baseline $baseline -Mutation {
            param($case); $path=Join-Path $case 'targeted-tests.json'; $record=Get-Content $path -Raw | ConvertFrom-Json; $record.runId='previous-run-001'; Write-Utf8NoBom -Path $path -Value ($record | ConvertTo-Json -Depth 6); Write-EvidenceManifest -Directory $case
        }
        Invoke-Negative -Name 'StaleReleaseSource' -ExpectedCode 'ALPHA_ART_EVIDENCE_SOURCE_SHA_MISMATCH:' -Baseline $baseline -Mutation {
            param($case); $path=Join-Path $case 'release-set.json'; $record=Get-Content $path -Raw | ConvertFrom-Json; $record.sourceRevision='b' * 40; Write-Utf8NoBom -Path $path -Value ($record | ConvertTo-Json -Depth 6); Write-EvidenceManifest -Directory $case
        }
        Invoke-Negative -Name 'UnsealedRecordMutation' -ExpectedCode 'ALPHA_ART_EVIDENCE_FILE_SIZE_MISMATCH:' -Baseline $baseline -Mutation {
            param($case); [IO.File]::AppendAllText((Join-Path $case 'targeted-tests.json'), ' ', [Text.UTF8Encoding]::new($false))
        }
        Write-Host 'ALPHA_ART_EVIDENCE_STALE_OR_CROSS_RUN_NEGATIVES_PASS'
    }
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        $resolved = [IO.Path]::GetFullPath($testRoot)
        if (-not $resolved.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'ALPHA_ART_EVIDENCE_TEST_CLEANUP_TARGET_INVALID' }
        [IO.Directory]::Delete($resolved, $true)
    }
}

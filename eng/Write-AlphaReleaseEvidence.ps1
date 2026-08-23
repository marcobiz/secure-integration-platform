[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $ReleaseDirectory,
    [Parameter(Mandatory = $true)][string] $TargetedTestsRecordPath,
    [Parameter(Mandatory = $true)][string] $QualificationSummaryRecordPath,
    [Parameter(Mandatory = $true)][string] $OutputDirectory,
    [Parameter(Mandatory = $true)][string] $ExpectedSourceCommit,
    [Parameter(Mandatory = $true)][string] $RunId,
    [string[]] $SupplementalRecordPath = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AlphaReleaseEvidenceContract.psm1') -Force
$release = [IO.Path]::GetFullPath($ReleaseDirectory)
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (-not (Test-Path -LiteralPath $release -PathType Container)) { throw 'ALPHA_ART_EVIDENCE_RELEASE_DIRECTORY_MISSING' }
if (Test-Path -LiteralPath $output) { throw 'ALPHA_ART_EVIDENCE_OUTPUT_MUST_NOT_EXIST' }
if ($ExpectedSourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'ALPHA_ART_EVIDENCE_EXPECTED_SOURCE_INVALID' }
if ($RunId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{5,127}$') { throw 'ALPHA_ART_EVIDENCE_EXPECTED_RUN_ID_INVALID' }
$createdOutput = $false

function Get-Sha256Hex {
    param([string] $LiteralPath)
    $stream = [IO.File]::OpenRead($LiteralPath)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace('-', '') }
    finally { $sha256.Dispose(); $stream.Dispose() }
}

function Write-Utf8NoBom {
    param([string] $Path, [AllowEmptyString()][string] $Value)
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}

try {
    $validationText = (& (Join-Path $PSScriptRoot 'Test-AlphaReleaseArtifacts.ps1') -RunDirectory $release -ExpectedSourceCommit $ExpectedSourceCommit -ReleaseSetOnly | Out-String).Trim()
    try { $releaseValidation = $validationText | ConvertFrom-Json }
    catch { throw 'ALPHA_ART_EVIDENCE_RELEASE_VALIDATION_INVALID' }
    if ([string]$releaseValidation.status -cne 'PASS') { throw 'ALPHA_ART_EVIDENCE_RELEASE_VALIDATION_FAILED' }
    $productVersion = [string]$releaseValidation.productVersion
    $sourceCommit = [string]$releaseValidation.sourceRevision
    $normalizedDigest = ([string]$releaseValidation.normalizedInventorySha256).ToUpperInvariant()
    if ($productVersion -cne '0.1.0-alpha.1') { throw 'ALPHA_ART_EVIDENCE_PRODUCT_VERSION_MISMATCH: release-set' }
    if ($sourceCommit -cne $ExpectedSourceCommit) { throw 'ALPHA_ART_EVIDENCE_SOURCE_SHA_MISMATCH: release-set' }
    if ($normalizedDigest -cnotmatch '^[0-9A-F]{64}$') { throw 'ALPHA_ART_EVIDENCE_NORMALIZED_DIGEST_INVALID' }

    try { $targetedTests = Get-Content -LiteralPath ([IO.Path]::GetFullPath($TargetedTestsRecordPath)) -Raw | ConvertFrom-Json }
    catch { throw 'ALPHA_ART_EVIDENCE_TARGETED_TESTS_INVALID' }
    try { $qualificationSummary = Get-Content -LiteralPath ([IO.Path]::GetFullPath($QualificationSummaryRecordPath)) -Raw | ConvertFrom-Json }
    catch { throw 'ALPHA_ART_EVIDENCE_QUALIFICATION_SUMMARY_INVALID' }
    Assert-AlphaReleaseEvidenceRecord -Record $targetedTests -RecordName 'targeted-tests.json' -ExpectedRunId $RunId -ExpectedSourceCommit $sourceCommit -ExpectedNormalizedDigest $normalizedDigest -ExpectedProductVersion $productVersion
    Assert-AlphaReleaseEvidenceRecord -Record $qualificationSummary -RecordName 'qualification-summary.json' -ExpectedRunId $RunId -ExpectedSourceCommit $sourceCommit -ExpectedNormalizedDigest $normalizedDigest -ExpectedProductVersion $productVersion

    $supplementalByName = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $supplementalNamesIgnoreCase = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($supplementalPath in @($SupplementalRecordPath)) {
        $full = [IO.Path]::GetFullPath($supplementalPath)
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'ALPHA_ART_EVIDENCE_SUPPLEMENTAL_RECORD_MISSING' }
        $name = [IO.Path]::GetFileName($full)
        if (-not $supplementalNamesIgnoreCase.Add($name)) { throw "ALPHA_ART_EVIDENCE_RECORD_DUPLICATE: $name" }
        try { $document = Get-Content -LiteralPath $full -Raw | ConvertFrom-Json }
        catch { throw "ALPHA_ART_EVIDENCE_RECORD_INVALID: $name" }
        Assert-AlphaReleaseEvidenceRecord -Record $document -RecordName $name -ExpectedRunId $RunId -ExpectedSourceCommit $sourceCommit -ExpectedNormalizedDigest $normalizedDigest -ExpectedProductVersion $productVersion
        $supplementalByName.Add($name, $full)
    }
    Assert-AlphaReleaseEvidenceRecordInventory -RecordName (@('release-set.json','targeted-tests.json','qualification-summary.json') + @($supplementalByName.Keys))

    $releaseManifestPath = Join-Path $release 'manifest.json'
    $releaseManifestHash = Get-Sha256Hex -LiteralPath $releaseManifestPath
    if ((Get-Content -LiteralPath (Join-Path $release 'manifest.json.sha256') -Raw).Trim() -cne "$releaseManifestHash  manifest.json") {
        throw 'ALPHA_ART_EVIDENCE_RELEASE_MANIFEST_SIDECAR_MISMATCH'
    }

    New-Item -ItemType Directory -Path $output | Out-Null
    $createdOutput = $true
    $releaseRecord = [ordered]@{
        schema = 'secure-integration.alpha-release-set-record.v1'
        runId = $RunId
        sourceRevision = $sourceCommit
        normalizedInventorySha256 = $normalizedDigest
        productVersion = $productVersion
        releaseManifestBytes = [IO.FileInfo]::new($releaseManifestPath).Length
        releaseManifestSha256 = $releaseManifestHash
        artifactCount = [int]$releaseValidation.actualArtifactCount
        sbomSubjectCount = [int]$releaseValidation.actualSbomSubjectCount
    }
    Assert-AlphaReleaseEvidenceRecord -Record ([pscustomobject]$releaseRecord) -RecordName 'release-set.json' -ExpectedRunId $RunId -ExpectedSourceCommit $sourceCommit -ExpectedNormalizedDigest $normalizedDigest -ExpectedProductVersion $productVersion
    Write-Utf8NoBom -Path (Join-Path $output 'release-set.json') -Value ($releaseRecord | ConvertTo-Json -Depth 8)
    Write-Utf8NoBom -Path (Join-Path $output 'targeted-tests.json') -Value ($targetedTests | ConvertTo-Json -Depth 32)
    Write-Utf8NoBom -Path (Join-Path $output 'qualification-summary.json') -Value ($qualificationSummary | ConvertTo-Json -Depth 32)

    foreach ($name in @($supplementalByName.Keys | Sort-Object)) {
        [IO.File]::Copy([string]$supplementalByName[$name], (Join-Path $output $name), $false)
    }

    $sensitivePattern = '(?i)([A-Z]:\\(?:Users|Codice|SecureEvidence|Lab)\\|/home/[^/\s]+/|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|authorization\s*:\s*(?:bearer|basic)|client_secret|activationCode)'
    foreach ($file in Get-ChildItem -LiteralPath $output -File) {
        if ([regex]::IsMatch((Get-Content -LiteralPath $file.FullName -Raw), $sensitivePattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
            throw "ALPHA_ART_EVIDENCE_REDACTION_FAILED: $($file.Name)"
        }
    }

    $records = @(Get-ChildItem -LiteralPath $output -File | Sort-Object Name | ForEach-Object {
        [ordered]@{ name = $_.Name; bytes = $_.Length; sha256 = Get-Sha256Hex -LiteralPath $_.FullName }
    })
    Assert-AlphaReleaseEvidenceRecordInventory -RecordName @($records | ForEach-Object { [string]$_.name })
    $evidenceManifest = [ordered]@{
        schema = 'secure-integration.alpha-release-evidence.v1'
        generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        runId = $RunId
        sourceRevision = $sourceCommit
        normalizedInventorySha256 = $normalizedDigest
        productVersion = $productVersion
        redacted = $true
        records = $records
    }
    $evidenceManifestPath = Join-Path $output 'evidence-manifest.json'
    Write-Utf8NoBom -Path $evidenceManifestPath -Value ($evidenceManifest | ConvertTo-Json -Depth 12)
    $evidenceManifestHash = Get-Sha256Hex -LiteralPath $evidenceManifestPath
    [IO.File]::WriteAllText((Join-Path $output 'evidence-manifest.json.sha256'), "$evidenceManifestHash  evidence-manifest.json`r`n", [Text.Encoding]::ASCII)
    $result = & (Join-Path $PSScriptRoot 'Test-AlphaReleaseEvidence.ps1') -EvidenceDirectory $output -ExpectedSourceCommit $sourceCommit -ExpectedRunId $RunId -ExpectedNormalizedDigest $normalizedDigest -ExpectedProductVersion $productVersion | Out-String
    $createdOutput = $false
    $result.Trim()
}
catch {
    if ($createdOutput -and (Test-Path -LiteralPath $output)) { [IO.Directory]::Delete($output, $true) }
    throw
}

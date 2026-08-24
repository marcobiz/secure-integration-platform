[CmdletBinding()]
param(
    [ValidateSet('All', 'StaleOrCrossRun', 'ClosedInventory')]
    [string] $TestName = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$writer = Join-Path $PSScriptRoot 'Write-AlphaReleaseEvidence.ps1'
$validator = Join-Path $PSScriptRoot 'Test-AlphaReleaseEvidence.ps1'
$productVersion = '0.1.0-alpha.1'
$sourceCommit = 'c' * 40
$normalizedDigest = 'D' * 64
$runId = 'current-run-001'
$shortCommit = $sourceCommit.Substring(0, 12)
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

function Get-FileRecord {
    param([string] $RunDirectory, [string] $RelativePath, [string] $Kind)
    $fullPath = Join-Path $RunDirectory $RelativePath.Replace('/', '\')
    return [ordered]@{ file = $RelativePath; kind = $Kind; bytes = [IO.FileInfo]::new($fullPath).Length; sha256 = Get-Sha256Hex -LiteralPath $fullPath }
}

function New-ContainerSbom {
    param([string] $Name, [string] $ImageId, [string] $Tag)
    return [ordered]@{
        spdxVersion = 'SPDX-2.3'; dataLicense = 'CC0-1.0'; SPDXID = 'SPDXRef-DOCUMENT'; name = "$Name evidence-test SBOM"
        documentNamespace = "urn:secure-integration:spdx:evidence-test:${Name}:$ImageId"
        creationInfo = [ordered]@{ created = '2026-01-01T00:00:00Z'; creators = @('Tool: Test-AlphaReleaseEvidenceConsistency.ps1') }
        packages = @([ordered]@{
            SPDXID = 'SPDXRef-DocumentRoot'; name = $Name; versionInfo = $Tag; downloadLocation = 'NOASSERTION'; filesAnalyzed = $false
            licenseConcluded = 'MPL-2.0'; licenseDeclared = 'MPL-2.0'; copyrightText = 'Copyright 2026 ApoCert S.r.l.'
            externalRefs = @([ordered]@{ referenceCategory = 'PACKAGE-MANAGER'; referenceType = 'purl'; referenceLocator = "pkg:oci/$Name@$ImageId`?repository_url=docker.io&tag=$Tag" })
        })
        relationships = @([ordered]@{ spdxElementId = 'SPDXRef-DOCUMENT'; relationshipType = 'DESCRIBES'; relatedSpdxElement = 'SPDXRef-DocumentRoot' })
    }
}

function Write-ReleaseManifestAndSidecar {
    param([string] $RunDirectory, $Manifest)
    $manifestPath = Join-Path $RunDirectory 'manifest.json'
    Write-Utf8NoBom -Path $manifestPath -Value ($Manifest | ConvertTo-Json -Depth 16)
    [IO.File]::WriteAllText((Join-Path $RunDirectory 'manifest.json.sha256'), "$(Get-Sha256Hex -LiteralPath $manifestPath)  manifest.json`r`n", [Text.Encoding]::ASCII)
}

function New-SyntheticReleaseSet {
    param([string] $RunDirectory)
    New-Item -ItemType Directory -Path (Join-Path $RunDirectory 'artifacts'), (Join-Path $RunDirectory 'sbom') -Force | Out-Null
    $gatewayArtifact = "artifacts/gateway-image-$productVersion-$shortCommit.tar"
    $migrationsArtifact = "artifacts/migrations-image-$productVersion-$shortCommit.tar"
    $artifactDefinitions = @(
        [pscustomobject]@{ path = "artifacts/SecureIntegration.Broker.Sdk.$productVersion.nupkg"; kind = 'nuget'; licenseExpression = 'Apache-2.0' },
        [pscustomobject]@{ path = "artifacts/admin-web-$productVersion.zip"; kind = 'admin-static-archive'; licenseExpression = 'MPL-2.0' },
        [pscustomobject]@{ path = $gatewayArtifact; kind = 'oci-image-archive'; licenseExpression = 'MPL-2.0' },
        [pscustomobject]@{ path = $migrationsArtifact; kind = 'oci-image-archive'; licenseExpression = 'MPL-2.0' },
        [pscustomobject]@{ path = "artifacts/secure-integration-core-$productVersion-source.zip"; kind = 'core-source-archive'; licenseExpression = 'MPL-2.0 AND Apache-2.0' })
    foreach ($definition in $artifactDefinitions) {
        Write-Utf8NoBom -Path (Join-Path $RunDirectory ([string]$definition.path).Replace('/', '\')) -Value ("evidence-test-artifact:" + [string]$definition.path)
    }

    $gatewayImageId = 'sha256:' + ('a' * 64)
    $migrationsImageId = 'sha256:' + ('b' * 64)
    $gatewayReference = "secure-integration-gateway:$productVersion-$shortCommit"
    $migrationsReference = "secure-integration-migrations:$productVersion-$shortCommit"
    Write-Utf8NoBom -Path (Join-Path $RunDirectory 'sbom\gateway-container.spdx.json') -Value ((New-ContainerSbom -Name 'secure-integration-gateway' -ImageId $gatewayImageId -Tag "$productVersion-$shortCommit") | ConvertTo-Json -Depth 12)
    Write-Utf8NoBom -Path (Join-Path $RunDirectory 'sbom\migrations-container.spdx.json') -Value ((New-ContainerSbom -Name 'secure-integration-migrations' -ImageId $migrationsImageId -Tag "$productVersion-$shortCommit") | ConvertTo-Json -Depth 12)
    foreach ($name in @('admin-frontend.spdx.json','auth-certificate-signing.spdx.json','broker.spdx.json','connector-cli.spdx.json','gateway.spdx.json','sdk-dotnet.spdx.json')) {
        Write-Utf8NoBom -Path (Join-Path $RunDirectory ('sbom\' + $name)) -Value '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}'
    }
    Write-Utf8NoBom -Path (Join-Path $RunDirectory 'sbom\aggregate-manifest.json') -Value '{"schemaVersion":1,"aggregateLicenseExpression":"MPL-2.0 AND Apache-2.0","artifacts":[]}'

    $artifactEntries = @($artifactDefinitions | ForEach-Object { $record = Get-FileRecord -RunDirectory $RunDirectory -RelativePath ([string]$_.path) -Kind ([string]$_.kind); $record['licenseExpression'] = [string]$_.licenseExpression; $record })
    $sbomEntries = @(Get-ChildItem -LiteralPath (Join-Path $RunDirectory 'sbom') -File | Sort-Object Name | ForEach-Object { $record = Get-FileRecord -RunDirectory $RunDirectory -RelativePath ('sbom/' + $_.Name) -Kind 'spdx-or-aggregate'; $record['subjectLicenseExpression'] = if ($_.Name -ceq 'sdk-dotnet.spdx.json') { 'Apache-2.0' } elseif ($_.Name -ceq 'aggregate-manifest.json') { 'MPL-2.0 AND Apache-2.0' } else { 'MPL-2.0' }; $record })
    $manifest = [ordered]@{
        schemaVersion = 1; product = 'SecureIntegrationPlatform'; version = $productVersion; sourceRevision = $sourceCommit; releaseChannel = 'public-technical-preview'; releaseClass = 'PUBLIC TECHNICAL PREVIEW'; distributionTarget = 'GitHub public prerelease v0.1.0-alpha.1'
        generatedAtUtc = '2026-01-01T00:00:00.0000000+00:00'; claims = [ordered]@{ publicReleaseGo = $false; productionReady = $false }
        versionIdentity = [ordered]@{ productVersion = $productVersion; protocolVersion = '1.0'; canonicalConnectorVersion = '1.0.0'; imageRevision = $sourceCommit; openApiVersion = $productVersion }
        licensePolicy = [ordered]@{ default = 'MPL-2.0'; sdk = 'Apache-2.0'; contractsProtocol = 'Apache-2.0'; syntheticExamples = 'Apache-2.0'; genericReference = 'MPL-2.0 OR Apache-2.0'; coreSourceArchive = 'MPL-2.0 AND Apache-2.0' }
        coreExport = [ordered]@{ fileCount = 452; rawManifestSha256RunSpecific = 'E' * 64; normalizedInventorySha256 = $normalizedDigest }
        images = @(
            [ordered]@{ role = 'gateway'; reference = $gatewayReference; imageId = $gatewayImageId; versionLabel = $productVersion; revisionLabel = $sourceCommit; sourceLabel = 'https://github.com/marcobiz/secure-integration-platform'; vendorLabel = 'ApoCert S.r.l.'; titleLabel = 'Secure Integration Platform Gateway'; licenseLabel = 'MPL-2.0' },
            [ordered]@{ role = 'migrations'; reference = $migrationsReference; imageId = $migrationsImageId; versionLabel = $productVersion; revisionLabel = $sourceCommit; sourceLabel = 'https://github.com/marcobiz/secure-integration-platform'; vendorLabel = 'ApoCert S.r.l.'; titleLabel = 'Secure Integration Platform Migrations'; licenseLabel = 'MPL-2.0' })
        artifacts = $artifactEntries; sbom = $sbomEntries
        sbomSubjects = @(
            [ordered]@{ role = 'gateway'; sbomFile = 'sbom/gateway-container.spdx.json'; artifactFile = $gatewayArtifact; imageReference = $gatewayReference; imageId = $gatewayImageId; licenseExpression = 'MPL-2.0' },
            [ordered]@{ role = 'migrations'; sbomFile = 'sbom/migrations-container.spdx.json'; artifactFile = $migrationsArtifact; imageReference = $migrationsReference; imageId = $migrationsImageId; licenseExpression = 'MPL-2.0' })
        signatures = @(); knownFollowUps = @('NONDETERMINISTIC_UI_MOCK_20_AXE_SNAPSHOT')
    }
    Write-ReleaseManifestAndSidecar -RunDirectory $RunDirectory -Manifest $manifest
    $checksumLines = @($artifactDefinitions | ForEach-Object {
        $fullPath = Join-Path $RunDirectory ([string]$_.path).Replace('/', '\')
        "$(Get-Sha256Hex -LiteralPath $fullPath)  $([string]$_.path)"
    })
    [Array]::Sort($checksumLines, [StringComparer]::Ordinal)
    [IO.File]::WriteAllLines((Join-Path $RunDirectory 'SHA256SUMS'), $checksumLines, [Text.Encoding]::ASCII)
}

function Add-Identity {
    param([System.Collections.IDictionary] $Record)
    $Record.runId = $runId
    $Record.sourceRevision = $sourceCommit
    $Record.normalizedInventorySha256 = $normalizedDigest
    $Record.productVersion = $productVersion
    return $Record
}

function New-InputRecords {
    param([string] $Directory)
    New-Item -ItemType Directory -Path $Directory | Out-Null
    $records = [ordered]@{
        'targeted-tests.json' = Add-Identity ([ordered]@{ schema = 'secure-integration.alpha-release-targeted-tests.v1'; status = 'PASS'; zeroSkip = $true; namedTests = @('ALPHA_ART_evidence_all_records_are_semantically_bound') })
        'qualification-summary.json' = Add-Identity ([ordered]@{ schema = 'secure-integration.alpha-release-qualification-summary.v1'; status = 'PASS'; releaseSets = 2; artifactCountPerSet = 5; containerSbomSubjectsPerSet = 2; normalizedDigestRun1 = $normalizedDigest; normalizedDigestRun2 = $normalizedDigest; normalizedDigestStable = $true })
        'tar-image-matrix.json' = Add-Identity ([ordered]@{ schema = 'secure-integration.alpha-release-tar-image-matrix.v1'; runs = @([ordered]@{ run = 1; containers = @([ordered]@{ role = 'gateway'; subjectBound = $true },[ordered]@{ role = 'migrations'; subjectBound = $true }) },[ordered]@{ run = 2; containers = @([ordered]@{ role = 'gateway'; subjectBound = $true },[ordered]@{ role = 'migrations'; subjectBound = $true }) }) })
        'ci-summary.json' = Add-Identity ([ordered]@{ schema = 'secure-integration.alpha-release-ci-summary.v1'; general = [ordered]@{ conclusion = 'success'; passed = 6; total = 6 }; m5Admin = [ordered]@{ conclusion = 'success'; passed = 15; total = 15 }; automaticRerunUsed = $false })
        'golden-path.json' = Add-Identity ([ordered]@{ schema = 'secure-integration.alpha-release-golden-path.v1'; status = 'PASS'; positiveOutboundCount = 1; auditMetadataOnly = $true; logsRedacted = $true; remainingContainers = 0; remainingNetworks = 0; remainingVolumes = 0; remainingSyntheticResources = 0 })
        'core-export.json' = Add-Identity ([ordered]@{ schema = 'secure-integration.alpha-release-core-export.v1'; status = 'PASS'; fileCount = 452; warnings = 0; errors = 0; secretScan = 'PASS'; sidecar = 'PASS' })
        'postgresql-18.json' = Add-Identity ([ordered]@{ schema = 'secure-integration.alpha-release-postgresql18.v1'; status = 'PASS'; freshMigration = 'PASS'; idempotentNoOp = 'PASS'; rlsAndLeastPrivilege = 'PASS'; integrationTests = 'PASS' })
        'cleanup.json' = Add-Identity ([ordered]@{ schema = 'secure-integration.alpha-release-cleanup.v1'; status = 'PASS'; candidateTagsRemaining = 0; taskOwnedImageTagsRemaining = 0; taskOwnedContainersRemaining = 0; taskOwnedNetworksRemaining = 0; taskOwnedVolumesRemaining = 0; foreignResourcesPreserved = $true; automaticPruneUsed = $false })
    }
    foreach ($entry in $records.GetEnumerator()) { Write-Utf8NoBom -Path (Join-Path $Directory $entry.Key) -Value ($entry.Value | ConvertTo-Json -Depth 16) }
}

function Get-SupplementalPaths {
    param([string] $InputDirectory)
    return @('tar-image-matrix.json','ci-summary.json','golden-path.json','core-export.json','postgresql-18.json','cleanup.json') | ForEach-Object { Join-Path $InputDirectory $_ }
}

function Invoke-Writer {
    param([string] $InputDirectory, [string] $OutputDirectory, [string[]] $SupplementalPath = @())
    if ($SupplementalPath.Count -eq 0) { $SupplementalPath = @(Get-SupplementalPaths -InputDirectory $InputDirectory) }
    return (& $writer -ReleaseDirectory (Join-Path $testRoot 'release') -TargetedTestsRecordPath (Join-Path $InputDirectory 'targeted-tests.json') -QualificationSummaryRecordPath (Join-Path $InputDirectory 'qualification-summary.json') -OutputDirectory $OutputDirectory -ExpectedSourceCommit $sourceCommit -RunId $runId -SupplementalRecordPath $SupplementalPath | Out-String).Trim()
}

function Write-EvidenceManifest {
    param([string] $Directory, [switch] $DuplicateCiRecord, [string] $ManifestDigest = $normalizedDigest)
    $records = @(Get-ChildItem -LiteralPath $Directory -File | Where-Object { $_.Name -notin @('evidence-manifest.json','evidence-manifest.json.sha256') } | Sort-Object Name | ForEach-Object {
        [ordered]@{ name = $_.Name; bytes = $_.Length; sha256 = Get-Sha256Hex -LiteralPath $_.FullName }
    })
    if ($DuplicateCiRecord) { $records += @($records | Where-Object { [string]$_.name -ceq 'ci-summary.json' }) }
    $manifest = [ordered]@{
        schema = 'secure-integration.alpha-release-evidence.v1'; generatedAtUtc = '2026-01-01T00:00:00Z'; runId = $runId
        sourceRevision = $sourceCommit; normalizedInventorySha256 = $ManifestDigest; productVersion = $productVersion; redacted = $true; records = $records
    }
    $manifestPath = Join-Path $Directory 'evidence-manifest.json'
    Write-Utf8NoBom -Path $manifestPath -Value ($manifest | ConvertTo-Json -Depth 12)
    [IO.File]::WriteAllText((Join-Path $Directory 'evidence-manifest.json.sha256'), "$(Get-Sha256Hex -LiteralPath $manifestPath)  evidence-manifest.json`r`n", [Text.Encoding]::ASCII)
}

function Invoke-ExpectedFailure {
    param([string] $Name, [string] $ExpectedCode, [scriptblock] $Action, [string] $OutputDirectory)
    $message = $null
    $captured = @()
    try { $captured = @(& $Action 2>&1 | ForEach-Object { $_.ToString() }) }
    catch { $message = [string]$_.Exception.Message }
    if ([string]::IsNullOrWhiteSpace($message)) { throw "ALPHA_ART_EVIDENCE_NEGATIVE_DID_NOT_FAIL: $Name" }
    if (-not $message.StartsWith($ExpectedCode, [StringComparison]::Ordinal)) { throw "ALPHA_ART_EVIDENCE_NEGATIVE_WRONG_CODE: $Name; ACTUAL=$message" }
    if (($captured -join "`n").Contains('"status":"PASS"')) { throw "ALPHA_ART_EVIDENCE_NEGATIVE_EMITTED_PASS: $Name" }
    if (-not [string]::IsNullOrWhiteSpace($OutputDirectory) -and (Test-Path -LiteralPath $OutputDirectory)) { throw "ALPHA_ART_EVIDENCE_WRITER_NEGATIVE_LEFT_OUTPUT: $Name" }
    Write-Host "ALPHA_ART_EVIDENCE_NEGATIVE_OK; NAME=$Name; CODE=$ExpectedCode"
}

function Invoke-WriterIdentityNegative {
    param([string] $Name, [string] $PropertyName, [string] $Value, [string] $ExpectedCode)
    $inputs = Join-Path $testRoot ('writer-input-' + $Name)
    Copy-Item -LiteralPath (Join-Path $testRoot 'inputs') -Destination $inputs -Recurse
    $path = Join-Path $inputs 'ci-summary.json'
    $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $record.$PropertyName = $Value
    Write-Utf8NoBom -Path $path -Value ($record | ConvertTo-Json -Depth 16)
    $output = Join-Path $testRoot ('writer-output-' + $Name)
    Invoke-ExpectedFailure -Name ("Writer$Name") -ExpectedCode $ExpectedCode -OutputDirectory $output -Action { Invoke-Writer -InputDirectory $inputs -OutputDirectory $output }
}

function Invoke-ValidatorIdentityNegative {
    param([string] $Name, [string] $PropertyName, [string] $Value, [string] $ExpectedCode)
    $case = Join-Path $testRoot ('validator-' + $Name)
    Copy-Item -LiteralPath (Join-Path $testRoot 'evidence-positive') -Destination $case -Recurse
    $path = Join-Path $case 'ci-summary.json'
    $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $record.$PropertyName = $Value
    Write-Utf8NoBom -Path $path -Value ($record | ConvertTo-Json -Depth 16)
    Write-EvidenceManifest -Directory $case
    Invoke-ExpectedFailure -Name ("ValidatorResealed$Name") -ExpectedCode $ExpectedCode -OutputDirectory '' -Action { & $validator -EvidenceDirectory $case -ExpectedSourceCommit $sourceCommit -ExpectedRunId $runId -ExpectedNormalizedDigest $normalizedDigest -ExpectedProductVersion $productVersion }
}

New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    New-SyntheticReleaseSet -RunDirectory (Join-Path $testRoot 'release')
    New-InputRecords -Directory (Join-Path $testRoot 'inputs')
    $positiveOutput = Join-Path $testRoot 'evidence-positive'
    $writerResult = (Invoke-Writer -InputDirectory (Join-Path $testRoot 'inputs') -OutputDirectory $positiveOutput) | ConvertFrom-Json
    if ([string]$writerResult.status -cne 'PASS' -or [int]$writerResult.recordCount -ne 9 -or [string]$writerResult.productVersion -cne $productVersion) { throw 'ALPHA_ART_EVIDENCE_WRITER_POSITIVE_FAILED' }
    $validatorResult = (& $validator -EvidenceDirectory $positiveOutput -ExpectedSourceCommit $sourceCommit -ExpectedRunId $runId -ExpectedNormalizedDigest $normalizedDigest -ExpectedProductVersion $productVersion | Out-String).Trim() | ConvertFrom-Json
    if ([string]$validatorResult.status -cne 'PASS' -or [int]$validatorResult.recordCount -ne 9 -or [string]$validatorResult.productVersion -cne $productVersion) { throw 'ALPHA_ART_EVIDENCE_VALIDATOR_POSITIVE_FAILED' }
    Write-Host 'ALPHA_ART_EVIDENCE_ALL_RECORDS_POSITIVE_PASS'

    if ($TestName -in @('All', 'StaleOrCrossRun')) {
        Invoke-WriterIdentityNegative -Name 'StaleSource' -PropertyName 'sourceRevision' -Value ('b' * 40) -ExpectedCode 'ALPHA_ART_EVIDENCE_SOURCE_SHA_MISMATCH:'
        Invoke-WriterIdentityNegative -Name 'CrossRun' -PropertyName 'runId' -Value 'previous-run-001' -ExpectedCode 'ALPHA_ART_EVIDENCE_RUN_ID_MISMATCH:'
        Invoke-WriterIdentityNegative -Name 'StaleDigest' -PropertyName 'normalizedInventorySha256' -Value ('E' * 64) -ExpectedCode 'ALPHA_ART_EVIDENCE_NORMALIZED_DIGEST_MISMATCH:'
        Invoke-WriterIdentityNegative -Name 'WrongVersion' -PropertyName 'productVersion' -Value '0.1.0-alpha.0' -ExpectedCode 'ALPHA_ART_EVIDENCE_PRODUCT_VERSION_MISMATCH:'
        Invoke-ValidatorIdentityNegative -Name 'StaleSource' -PropertyName 'sourceRevision' -Value ('b' * 40) -ExpectedCode 'ALPHA_ART_EVIDENCE_SOURCE_SHA_MISMATCH:'
        Invoke-ValidatorIdentityNegative -Name 'CrossRun' -PropertyName 'runId' -Value 'previous-run-001' -ExpectedCode 'ALPHA_ART_EVIDENCE_RUN_ID_MISMATCH:'
        Invoke-ValidatorIdentityNegative -Name 'StaleDigest' -PropertyName 'normalizedInventorySha256' -Value ('E' * 64) -ExpectedCode 'ALPHA_ART_EVIDENCE_NORMALIZED_DIGEST_MISMATCH:'
        Invoke-ValidatorIdentityNegative -Name 'WrongVersion' -PropertyName 'productVersion' -Value '0.1.0-alpha.0' -ExpectedCode 'ALPHA_ART_EVIDENCE_PRODUCT_VERSION_MISMATCH:'

        $allStale = Join-Path $testRoot 'validator-AllRecordsStaleDigest'
        Copy-Item -LiteralPath $positiveOutput -Destination $allStale -Recurse
        foreach ($path in Get-ChildItem -LiteralPath $allStale -File -Filter '*.json' | Where-Object { $_.Name -ne 'evidence-manifest.json' }) {
            $record = Get-Content -LiteralPath $path.FullName -Raw | ConvertFrom-Json
            $record.normalizedInventorySha256 = 'E' * 64
            if ($path.Name -ceq 'qualification-summary.json') { $record.normalizedDigestRun1 = 'E' * 64; $record.normalizedDigestRun2 = 'E' * 64 }
            Write-Utf8NoBom -Path $path.FullName -Value ($record | ConvertTo-Json -Depth 16)
        }
        Write-EvidenceManifest -Directory $allStale -ManifestDigest ('E' * 64)
        Invoke-ExpectedFailure -Name 'ValidatorResealedAllRecordsStaleDigest' -ExpectedCode 'ALPHA_ART_EVIDENCE_NORMALIZED_DIGEST_MISMATCH: evidence-manifest.json' -OutputDirectory '' -Action { & $validator -EvidenceDirectory $allStale -ExpectedSourceCommit $sourceCommit -ExpectedRunId $runId -ExpectedNormalizedDigest $normalizedDigest -ExpectedProductVersion $productVersion }
        Write-Host 'ALPHA_ART_EVIDENCE_STALE_OR_CROSS_RUN_NEGATIVES_PASS'
    }

    if ($TestName -in @('All', 'ClosedInventory')) {
        $unknownInputs = Join-Path $testRoot 'writer-input-Unknown'
        Copy-Item -LiteralPath (Join-Path $testRoot 'inputs') -Destination $unknownInputs -Recurse
        $unknown = Add-Identity ([ordered]@{ schema = 'secure-integration.alpha-release-unknown.v1'; status = 'PASS' })
        Write-Utf8NoBom -Path (Join-Path $unknownInputs 'unknown.json') -Value ($unknown | ConvertTo-Json -Depth 8)
        $unknownOutput = Join-Path $testRoot 'writer-output-Unknown'
        $unknownSupplemental = @(Get-SupplementalPaths -InputDirectory $unknownInputs) + @((Join-Path $unknownInputs 'unknown.json'))
        Invoke-ExpectedFailure -Name 'WriterUnknownRecord' -ExpectedCode 'ALPHA_ART_EVIDENCE_RECORD_UNKNOWN:' -OutputDirectory $unknownOutput -Action { Invoke-Writer -InputDirectory $unknownInputs -OutputDirectory $unknownOutput -SupplementalPath $unknownSupplemental }

        $duplicateOutput = Join-Path $testRoot 'writer-output-Duplicate'
        $duplicateSupplemental = @(Get-SupplementalPaths -InputDirectory (Join-Path $testRoot 'inputs')) + @((Join-Path $testRoot 'inputs\ci-summary.json'))
        Invoke-ExpectedFailure -Name 'WriterDuplicateRecord' -ExpectedCode 'ALPHA_ART_EVIDENCE_RECORD_DUPLICATE:' -OutputDirectory $duplicateOutput -Action { Invoke-Writer -InputDirectory (Join-Path $testRoot 'inputs') -OutputDirectory $duplicateOutput -SupplementalPath $duplicateSupplemental }

        $replacedInputs = Join-Path $testRoot 'writer-input-Replaced'
        Copy-Item -LiteralPath (Join-Path $testRoot 'inputs') -Destination $replacedInputs -Recurse
        Copy-Item -LiteralPath (Join-Path $replacedInputs 'cleanup.json') -Destination (Join-Path $replacedInputs 'ci-summary.json') -Force
        $replacedOutput = Join-Path $testRoot 'writer-output-Replaced'
        Invoke-ExpectedFailure -Name 'WriterReplacedRecord' -ExpectedCode 'ALPHA_ART_EVIDENCE_RECORD_SCHEMA_MISMATCH:' -OutputDirectory $replacedOutput -Action { Invoke-Writer -InputDirectory $replacedInputs -OutputDirectory $replacedOutput }

        $unknownCase = Join-Path $testRoot 'validator-Unknown'
        Copy-Item -LiteralPath $positiveOutput -Destination $unknownCase -Recurse
        Write-Utf8NoBom -Path (Join-Path $unknownCase 'unknown.json') -Value ($unknown | ConvertTo-Json -Depth 8)
        Write-EvidenceManifest -Directory $unknownCase
        Invoke-ExpectedFailure -Name 'ValidatorResealedUnknownRecord' -ExpectedCode 'ALPHA_ART_EVIDENCE_RECORD_UNKNOWN:' -OutputDirectory '' -Action { & $validator -EvidenceDirectory $unknownCase -ExpectedSourceCommit $sourceCommit -ExpectedRunId $runId -ExpectedNormalizedDigest $normalizedDigest -ExpectedProductVersion $productVersion }

        $duplicateCase = Join-Path $testRoot 'validator-Duplicate'
        Copy-Item -LiteralPath $positiveOutput -Destination $duplicateCase -Recurse
        Write-EvidenceManifest -Directory $duplicateCase -DuplicateCiRecord
        Invoke-ExpectedFailure -Name 'ValidatorResealedDuplicateRecord' -ExpectedCode 'ALPHA_ART_EVIDENCE_RECORD_DUPLICATE:' -OutputDirectory '' -Action { & $validator -EvidenceDirectory $duplicateCase -ExpectedSourceCommit $sourceCommit -ExpectedRunId $runId -ExpectedNormalizedDigest $normalizedDigest -ExpectedProductVersion $productVersion }

        $replacedCase = Join-Path $testRoot 'validator-Replaced'
        Copy-Item -LiteralPath $positiveOutput -Destination $replacedCase -Recurse
        Copy-Item -LiteralPath (Join-Path $replacedCase 'cleanup.json') -Destination (Join-Path $replacedCase 'ci-summary.json') -Force
        Write-EvidenceManifest -Directory $replacedCase
        Invoke-ExpectedFailure -Name 'ValidatorResealedReplacedRecord' -ExpectedCode 'ALPHA_ART_EVIDENCE_RECORD_SCHEMA_MISMATCH:' -OutputDirectory '' -Action { & $validator -EvidenceDirectory $replacedCase -ExpectedSourceCommit $sourceCommit -ExpectedRunId $runId -ExpectedNormalizedDigest $normalizedDigest -ExpectedProductVersion $productVersion }

        $unsealedCase = Join-Path $testRoot 'validator-UnsealedMutation'
        Copy-Item -LiteralPath $positiveOutput -Destination $unsealedCase -Recurse
        [IO.File]::AppendAllText((Join-Path $unsealedCase 'ci-summary.json'), ' ', [Text.UTF8Encoding]::new($false))
        Invoke-ExpectedFailure -Name 'ValidatorPhysicalIntegrity' -ExpectedCode 'ALPHA_ART_EVIDENCE_FILE_SIZE_MISMATCH:' -OutputDirectory '' -Action { & $validator -EvidenceDirectory $unsealedCase -ExpectedSourceCommit $sourceCommit -ExpectedRunId $runId -ExpectedNormalizedDigest $normalizedDigest -ExpectedProductVersion $productVersion }
        Write-Host 'ALPHA_ART_EVIDENCE_CLOSED_INVENTORY_NEGATIVES_PASS'
    }
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        $resolved = [IO.Path]::GetFullPath($testRoot)
        if (-not $resolved.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'ALPHA_ART_EVIDENCE_TEST_CLEANUP_TARGET_INVALID' }
        Get-ChildItem -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Attributes = [IO.FileAttributes]::Normal } catch {} }
        [IO.Directory]::Delete($resolved, $true)
    }
}

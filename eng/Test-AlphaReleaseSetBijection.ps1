[CmdletBinding()]
param(
    [ValidateSet('All', 'ArtifactBijection', 'ArtifactMissingUnexpected', 'SbomBijection', 'SbomWrongExtra')]
    [string] $TestName = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$validator = Join-Path $PSScriptRoot 'Test-AlphaReleaseArtifacts.ps1'
$productVersion = '0.1.0-alpha.1'
$sourceCommit = 'c' * 40
$shortCommit = $sourceCommit.Substring(0, 12)
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar))
$testRoot = Join-Path $tempBase ('alpha-release-bijection-' + [Guid]::NewGuid().ToString('N'))
if (-not $testRoot.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'ALPHA_RELEASE_BIJECTION_TEST_ROOT_INVALID' }

function Write-Utf8NoBom {
    param([Parameter(Mandatory = $true)][string] $Path, [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Value)
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}

function Get-FileRecord {
    param([Parameter(Mandatory = $true)][string] $RunDirectory, [Parameter(Mandatory = $true)][string] $RelativePath, [Parameter(Mandatory = $true)][string] $Kind)
    $fullPath = Join-Path $RunDirectory $RelativePath.Replace('/', '\')
    return [ordered]@{ file = $RelativePath; kind = $Kind; bytes = [IO.FileInfo]::new($fullPath).Length; sha256 = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash }
}

function New-ContainerSbom {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $ImageId,
        [Parameter(Mandatory = $true)][string] $Tag
    )
    return [ordered]@{
        spdxVersion = 'SPDX-2.3'
        dataLicense = 'CC0-1.0'
        SPDXID = 'SPDXRef-DOCUMENT'
        name = "$Name synthetic negative-test SBOM"
        documentNamespace = "urn:secure-integration:spdx:synthetic:$Name:$ImageId"
        creationInfo = [ordered]@{ created = '2026-01-01T00:00:00Z'; creators = @('Tool: Test-AlphaReleaseSetBijection.ps1') }
        packages = @([ordered]@{
            SPDXID = 'SPDXRef-DocumentRoot'
            name = $Name
            versionInfo = $Tag
            downloadLocation = 'NOASSERTION'
            filesAnalyzed = $false
            licenseConcluded = 'NOASSERTION'
            licenseDeclared = 'NOASSERTION'
            copyrightText = 'NOASSERTION'
            externalRefs = @([ordered]@{ referenceCategory = 'PACKAGE-MANAGER'; referenceType = 'purl'; referenceLocator = "pkg:oci/$Name@$ImageId`?repository_url=docker.io&tag=$Tag" })
        })
        relationships = @([ordered]@{ spdxElementId = 'SPDXRef-DOCUMENT'; relationshipType = 'DESCRIBES'; relatedSpdxElement = 'SPDXRef-DocumentRoot' })
    }
}

function Write-ManifestAndSidecar {
    param([Parameter(Mandatory = $true)][string] $RunDirectory, [Parameter(Mandatory = $true)] $Manifest)
    $manifestPath = Join-Path $RunDirectory 'manifest.json'
    Write-Utf8NoBom -Path $manifestPath -Value ($Manifest | ConvertTo-Json -Depth 16)
    $hash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    [IO.File]::WriteAllText((Join-Path $RunDirectory 'manifest.json.sha256'), "$hash  manifest.json`r`n", [Text.Encoding]::ASCII)
}

function Sync-SbomManifestRecord {
    param([Parameter(Mandatory = $true)][string] $RunDirectory, [Parameter(Mandatory = $true)] $Manifest, [Parameter(Mandatory = $true)][string] $RelativePath)
    $records = @($Manifest.sbom | Where-Object { [string]$_.file -ceq $RelativePath })
    if ($records.Count -ne 1) { throw 'ALPHA_RELEASE_BIJECTION_FIXTURE_SBOM_RECORD_INVALID' }
    $fullPath = Join-Path $RunDirectory $RelativePath.Replace('/', '\')
    $records[0].bytes = [IO.FileInfo]::new($fullPath).Length
    $records[0].sha256 = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash
}

function New-SyntheticReleaseSet {
    param([Parameter(Mandatory = $true)][string] $RunDirectory)
    New-Item -ItemType Directory -Path (Join-Path $RunDirectory 'artifacts'), (Join-Path $RunDirectory 'sbom') -Force | Out-Null
    $gatewayArtifact = "artifacts/gateway-image-$productVersion-$shortCommit.tar"
    $migrationsArtifact = "artifacts/migrations-image-$productVersion-$shortCommit.tar"
    $artifactDefinitions = @(
        [pscustomobject]@{ path = "artifacts/SecureIntegration.Broker.Sdk.$productVersion.nupkg"; kind = 'nuget' },
        [pscustomobject]@{ path = "artifacts/admin-web-$productVersion.zip"; kind = 'admin-static-archive' },
        [pscustomobject]@{ path = $gatewayArtifact; kind = 'oci-image-archive' },
        [pscustomobject]@{ path = $migrationsArtifact; kind = 'oci-image-archive' },
        [pscustomobject]@{ path = "artifacts/secure-integration-core-$productVersion-source.zip"; kind = 'core-source-archive' })
    foreach ($definition in $artifactDefinitions) {
        $path = Join-Path $RunDirectory ([string]$definition.path).Replace('/', '\')
        Write-Utf8NoBom -Path $path -Value ("synthetic-artifact-bytes:" + [string]$definition.path)
    }

    $gatewayImageId = 'sha256:' + ('a' * 64)
    $migrationsImageId = 'sha256:' + ('b' * 64)
    $gatewayReference = "secure-integration-gateway:$productVersion-$shortCommit"
    $migrationsReference = "secure-integration-migrations:$productVersion-$shortCommit"
    $gatewayTag = $gatewayReference.Substring($gatewayReference.IndexOf(':') + 1)
    $migrationsTag = $migrationsReference.Substring($migrationsReference.IndexOf(':') + 1)
    $gatewaySbomPath = Join-Path $RunDirectory 'sbom\gateway-container.spdx.json'
    $migrationsSbomPath = Join-Path $RunDirectory 'sbom\migrations-container.spdx.json'
    Write-Utf8NoBom -Path $gatewaySbomPath -Value ((New-ContainerSbom -Name 'secure-integration-gateway' -ImageId $gatewayImageId -Tag $gatewayTag) | ConvertTo-Json -Depth 12)
    Write-Utf8NoBom -Path $migrationsSbomPath -Value ((New-ContainerSbom -Name 'secure-integration-migrations' -ImageId $migrationsImageId -Tag $migrationsTag) | ConvertTo-Json -Depth 12)
    foreach ($name in @(
        'admin-frontend.spdx.json',
        'auth-certificate-signing.spdx.json',
        'broker.spdx.json',
        'connector-cli.spdx.json',
        'gateway.spdx.json',
        'sdk-dotnet.spdx.json')) {
        Write-Utf8NoBom -Path (Join-Path $RunDirectory ('sbom\' + $name)) -Value '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}'
    }
    Write-Utf8NoBom -Path (Join-Path $RunDirectory 'sbom\aggregate-manifest.json') -Value '{"schemaVersion":1,"artifacts":[]}'

    $artifactEntries = @($artifactDefinitions | ForEach-Object { Get-FileRecord -RunDirectory $RunDirectory -RelativePath ([string]$_.path) -Kind ([string]$_.kind) })
    $sbomEntries = @(Get-ChildItem -LiteralPath (Join-Path $RunDirectory 'sbom') -File | Sort-Object Name | ForEach-Object {
        Get-FileRecord -RunDirectory $RunDirectory -RelativePath ('sbom/' + $_.Name) -Kind 'spdx-or-aggregate'
    })
    $manifest = [ordered]@{
        schemaVersion = 1
        product = 'SecureIntegrationPlatform'
        version = $productVersion
        sourceRevision = $sourceCommit
        releaseChannel = 'private-preview'
        generatedAtUtc = '2026-01-01T00:00:00.0000000+00:00'
        claims = [ordered]@{ publicReleaseGo = $false; productionReady = $false }
        versionIdentity = [ordered]@{ productVersion = $productVersion; protocolVersion = '1.0'; canonicalConnectorVersion = '1.0.0'; imageRevision = $sourceCommit; openApiVersion = $productVersion }
        coreExport = [ordered]@{ fileCount = 0; rawManifestSha256RunSpecific = 'D' * 64; normalizedInventorySha256 = 'E' * 64 }
        images = @(
            [ordered]@{ role = 'gateway'; reference = $gatewayReference; imageId = $gatewayImageId; versionLabel = $productVersion; revisionLabel = $sourceCommit },
            [ordered]@{ role = 'migrations'; reference = $migrationsReference; imageId = $migrationsImageId; versionLabel = $productVersion; revisionLabel = $sourceCommit })
        artifacts = $artifactEntries
        sbom = $sbomEntries
        sbomSubjects = @(
            [ordered]@{ role = 'gateway'; sbomFile = 'sbom/gateway-container.spdx.json'; artifactFile = $gatewayArtifact; imageReference = $gatewayReference; imageId = $gatewayImageId },
            [ordered]@{ role = 'migrations'; sbomFile = 'sbom/migrations-container.spdx.json'; artifactFile = $migrationsArtifact; imageReference = $migrationsReference; imageId = $migrationsImageId })
        signatures = @()
        knownFollowUps = @('NONDETERMINISTIC_UI_MOCK_20_AXE_SNAPSHOT')
    }
    Write-ManifestAndSidecar -RunDirectory $RunDirectory -Manifest $manifest
    [string[]]$checksumLines = @($artifactDefinitions | ForEach-Object {
        $fullPath = Join-Path $RunDirectory ([string]$_.path).Replace('/', '\')
        "$(Get-FileHash -LiteralPath $fullPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash)  $([string]$_.path)"
    })
    [Array]::Sort($checksumLines, [StringComparer]::Ordinal)
    [IO.File]::WriteAllLines((Join-Path $RunDirectory 'SHA256SUMS'), $checksumLines, [Text.Encoding]::ASCII)
}

function Invoke-PositiveBaseline {
    param([Parameter(Mandatory = $true)][string] $RunDirectory)
    $output = (& $validator -RunDirectory $RunDirectory -ExpectedSourceCommit $sourceCommit -ReleaseSetOnly | Out-String).Trim()
    $result = $output | ConvertFrom-Json
    if ([string]$result.status -cne 'PASS' -or [int]$result.expectedArtifactCount -ne 5 -or [int]$result.actualArtifactCount -ne 5 -or
        [int]$result.expectedSbomSubjectCount -ne 2 -or [int]$result.actualSbomSubjectCount -ne 2) {
        throw 'ALPHA_RELEASE_BIJECTION_POSITIVE_BASELINE_FAILED'
    }
}

function Invoke-NegativeCase {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $ExpectedCode,
        [Parameter(Mandatory = $true)][scriptblock] $Mutation,
        [Parameter(Mandatory = $true)][string] $BaselineDirectory
    )
    $caseDirectory = Join-Path $testRoot ('case-' + $Name)
    Copy-Item -LiteralPath $BaselineDirectory -Destination $caseDirectory -Recurse
    & $Mutation $caseDirectory
    $captured = @()
    $failureMessage = $null
    try { $captured = @(& $validator -RunDirectory $caseDirectory -ExpectedSourceCommit $sourceCommit -ReleaseSetOnly 2>&1 | ForEach-Object { $_.ToString() }) }
    catch { $failureMessage = [string]$_.Exception.Message }
    if ([string]::IsNullOrWhiteSpace($failureMessage)) { throw "ALPHA_RELEASE_NEGATIVE_DID_NOT_FAIL: $Name" }
    if (-not $failureMessage.StartsWith($ExpectedCode, [StringComparison]::Ordinal)) { throw "ALPHA_RELEASE_NEGATIVE_WRONG_CODE: $Name; ACTUAL=$failureMessage" }
    if (($captured -join "`n").Contains('"status":"PASS"')) { throw "ALPHA_RELEASE_NEGATIVE_EMITTED_PASS: $Name" }
    Write-Host "ALPHA_RELEASE_NEGATIVE_OK; NAME=$Name; CODE=$ExpectedCode"
}

New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $baseline = Join-Path $testRoot 'baseline'
    New-SyntheticReleaseSet -RunDirectory $baseline
    Invoke-PositiveBaseline -RunDirectory $baseline

    if ($TestName -in @('All', 'ArtifactBijection')) {
        Invoke-NegativeCase -Name 'MissingChecksum' -ExpectedCode 'ALPHA_ARTIFACT_CHECKSUM_MISSING:' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); $lines = @(Get-Content (Join-Path $caseRoot 'SHA256SUMS')); [IO.File]::WriteAllLines((Join-Path $caseRoot 'SHA256SUMS'), @($lines | Select-Object -Skip 1), [Text.Encoding]::ASCII)
        }
        Invoke-NegativeCase -Name 'DuplicateChecksum' -ExpectedCode 'ALPHA_ARTIFACT_CHECKSUM_DUPLICATE' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); $path = Join-Path $caseRoot 'SHA256SUMS'; $lines = @(Get-Content $path); [IO.File]::WriteAllLines($path, @($lines + $lines[0]), [Text.Encoding]::ASCII)
        }
        Invoke-NegativeCase -Name 'ChecksumAssociatedWithWrongFile' -ExpectedCode 'ALPHA_ARTIFACT_CHECKSUM_MISMATCH:' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); $path = Join-Path $caseRoot 'SHA256SUMS'; $lines = @(Get-Content $path); $firstHash = $lines[0].Substring(0, 64); $secondHash = $lines[1].Substring(0, 64); $firstPath = $lines[0].Substring(66); $secondPath = $lines[1].Substring(66); $lines[0] = "$secondHash  $firstPath"; $lines[1] = "$firstHash  $secondPath"; [IO.File]::WriteAllLines($path, $lines, [Text.Encoding]::ASCII)
        }
        Invoke-NegativeCase -Name 'MutatedArtifact' -ExpectedCode 'ALPHA_ARTIFACT_CHECKSUM_MISMATCH:' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); [IO.File]::AppendAllText((Join-Path $caseRoot "artifacts\admin-web-$productVersion.zip"), 'controlled-mutation', [Text.UTF8Encoding]::new($false))
        }
        Invoke-NegativeCase -Name 'ChecksumSelfReference' -ExpectedCode 'ALPHA_ARTIFACT_CHECKSUM_SELF_REFERENCE' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); $path = Join-Path $caseRoot 'SHA256SUMS'; $lines = @(Get-Content $path); [IO.File]::WriteAllLines($path, @($lines + (('F' * 64) + '  SHA256SUMS')), [Text.Encoding]::ASCII)
        }
        Invoke-NegativeCase -Name 'ChecksumAdsPath' -ExpectedCode 'ALPHA_ARTIFACT_CHECKSUM_PATH_INVALID' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); $path = Join-Path $caseRoot 'SHA256SUMS'; $lines = @(Get-Content $path); [IO.File]::WriteAllLines($path, @($lines + (('F' * 64) + '  artifacts/admin.zip:stream')), [Text.Encoding]::ASCII)
        }
        Write-Host 'ALPHA_ART_RELEASE_SET_EXACT_BIJECTION_PASS'
    }

    if ($TestName -in @('All', 'ArtifactMissingUnexpected')) {
        Invoke-NegativeCase -Name 'ManifestArtifactOmitted' -ExpectedCode 'ALPHA_ARTIFACT_MANIFEST_ARTIFACT_MISSING:' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); $manifest = Get-Content (Join-Path $caseRoot 'manifest.json') -Raw | ConvertFrom-Json; $manifest.artifacts = @($manifest.artifacts | Select-Object -Skip 1); Write-ManifestAndSidecar -RunDirectory $caseRoot -Manifest $manifest
        }
        Invoke-NegativeCase -Name 'PhysicalArtifactOmitted' -ExpectedCode 'ALPHA_ARTIFACT_EXPECTED_FILE_MISSING:' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); Remove-Item -LiteralPath (Join-Path $caseRoot "artifacts\SecureIntegration.Broker.Sdk.$productVersion.nupkg") -Force
        }
        Invoke-NegativeCase -Name 'UnexpectedArtifact' -ExpectedCode 'ALPHA_ARTIFACT_UNEXPECTED_FILE:' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); Write-Utf8NoBom -Path (Join-Path $caseRoot 'artifacts\unexpected.zip') -Value 'unexpected'
        }
        Invoke-NegativeCase -Name 'ExtraChecksum' -ExpectedCode 'ALPHA_ARTIFACT_CHECKSUM_UNEXPECTED:' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); $path = Join-Path $caseRoot 'SHA256SUMS'; $lines = @(Get-Content $path); $manifestHash = (Get-FileHash (Join-Path $caseRoot 'manifest.json') -Algorithm SHA256).Hash; [IO.File]::WriteAllLines($path, @($lines + "$manifestHash  manifest.json"), [Text.Encoding]::ASCII)
        }
        Invoke-NegativeCase -Name 'ManifestArtifactCaseCollision' -ExpectedCode 'ALPHA_ARTIFACT_MANIFEST_ARTIFACT_DUPLICATE' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); $manifest = Get-Content (Join-Path $caseRoot 'manifest.json') -Raw | ConvertFrom-Json; $duplicate = @($manifest.artifacts[0] | ConvertTo-Json -Depth 5 | ConvertFrom-Json)[0]; $duplicate.file = ([string]$duplicate.file).ToUpperInvariant(); $manifest.artifacts = @($manifest.artifacts) + @($duplicate); Write-ManifestAndSidecar -RunDirectory $caseRoot -Manifest $manifest
        }
        Write-Host 'ALPHA_ART_RELEASE_SET_MISSING_UNEXPECTED_NEGATIVES_PASS'
    }

    if ($TestName -in @('All', 'SbomBijection')) {
        Invoke-NegativeCase -Name 'MissingGatewaySbom' -ExpectedCode 'ALPHA_ARTIFACT_SBOM_FILE_MISSING:' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); Remove-Item -LiteralPath (Join-Path $caseRoot 'sbom\gateway-container.spdx.json') -Force
        }
        Invoke-NegativeCase -Name 'DuplicateSbomAssociation' -ExpectedCode 'ALPHA_ARTIFACT_SBOM_ASSOCIATION_DUPLICATE' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); $manifest = Get-Content (Join-Path $caseRoot 'manifest.json') -Raw | ConvertFrom-Json; $manifest.sbomSubjects = @($manifest.sbomSubjects) + @($manifest.sbomSubjects[0]); Write-ManifestAndSidecar -RunDirectory $caseRoot -Manifest $manifest
        }
        Invoke-NegativeCase -Name 'WrongGatewaySbomDigest' -ExpectedCode 'ALPHA_ARTIFACT_SBOM_SUBJECT_MISMATCH:' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); $relative = 'sbom/gateway-container.spdx.json'; $path = Join-Path $caseRoot $relative.Replace('/', '\'); $document = Get-Content $path -Raw | ConvertFrom-Json; $document.packages[0].externalRefs[0].referenceLocator = ([string]$document.packages[0].externalRefs[0].referenceLocator) -replace ('a' * 64), ('d' * 64); Write-Utf8NoBom -Path $path -Value ($document | ConvertTo-Json -Depth 12); $manifest = Get-Content (Join-Path $caseRoot 'manifest.json') -Raw | ConvertFrom-Json; Sync-SbomManifestRecord -RunDirectory $caseRoot -Manifest $manifest -RelativePath $relative; Write-ManifestAndSidecar -RunDirectory $caseRoot -Manifest $manifest
        }
        Write-Host 'ALPHA_ART_RELEASE_SET_EXACT_SBOM_SUBJECT_BIJECTION_PASS'
    }

    if ($TestName -in @('All', 'SbomWrongExtra')) {
        Invoke-NegativeCase -Name 'ExtraSbom' -ExpectedCode 'ALPHA_ARTIFACT_SBOM_FILE_UNEXPECTED:' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); Copy-Item -LiteralPath (Join-Path $caseRoot 'sbom\gateway-container.spdx.json') -Destination (Join-Path $caseRoot 'sbom\foreign-container.spdx.json')
        }
        Invoke-NegativeCase -Name 'SwappedGatewayMigrationsSbom' -ExpectedCode 'ALPHA_ARTIFACT_SBOM_SUBJECT_MISMATCH:' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); $gatewayRelative = 'sbom/gateway-container.spdx.json'; $migrationsRelative = 'sbom/migrations-container.spdx.json'; $gatewayPath = Join-Path $caseRoot $gatewayRelative.Replace('/', '\'); $migrationsPath = Join-Path $caseRoot $migrationsRelative.Replace('/', '\'); [byte[]]$gatewayBytes = [IO.File]::ReadAllBytes($gatewayPath); [byte[]]$migrationsBytes = [IO.File]::ReadAllBytes($migrationsPath); try { [IO.File]::WriteAllBytes($gatewayPath, $migrationsBytes); [IO.File]::WriteAllBytes($migrationsPath, $gatewayBytes) } finally { [Array]::Clear($gatewayBytes, 0, $gatewayBytes.Length); [Array]::Clear($migrationsBytes, 0, $migrationsBytes.Length) }; $manifest = Get-Content (Join-Path $caseRoot 'manifest.json') -Raw | ConvertFrom-Json; Sync-SbomManifestRecord -RunDirectory $caseRoot -Manifest $manifest -RelativePath $gatewayRelative; Sync-SbomManifestRecord -RunDirectory $caseRoot -Manifest $manifest -RelativePath $migrationsRelative; Write-ManifestAndSidecar -RunDirectory $caseRoot -Manifest $manifest
        }
        Invoke-NegativeCase -Name 'WrongSbomManifestAssociation' -ExpectedCode 'ALPHA_ARTIFACT_SBOM_ASSOCIATION_MISMATCH:' -BaselineDirectory $baseline -Mutation {
            param($caseRoot); $manifest = Get-Content (Join-Path $caseRoot 'manifest.json') -Raw | ConvertFrom-Json; $gateway = [string]$manifest.sbomSubjects[0].sbomFile; $manifest.sbomSubjects[0].sbomFile = [string]$manifest.sbomSubjects[1].sbomFile; $manifest.sbomSubjects[1].sbomFile = $gateway; Write-ManifestAndSidecar -RunDirectory $caseRoot -Manifest $manifest
        }
        Write-Host 'ALPHA_ART_RELEASE_SET_WRONG_EXTRA_SBOM_NEGATIVES_PASS'
    }
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        $resolved = [IO.Path]::GetFullPath($testRoot)
        if (-not $resolved.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'ALPHA_RELEASE_BIJECTION_TEST_CLEANUP_TARGET_INVALID' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

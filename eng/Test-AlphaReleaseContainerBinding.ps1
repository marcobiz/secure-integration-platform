[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $GatewaySourceReference,
    [Parameter(Mandatory = $true)][string] $MigrationsSourceReference,
    [Parameter(Mandatory = $true)][string] $ExpectedSourceCommit,
    [ValidateSet('All', 'Positive', 'PreexistingTags', 'SwappedTar', 'IdentityMismatch')]
    [string] $TestName = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$validator = Join-Path $PSScriptRoot 'Test-AlphaReleaseArtifacts.ps1'
Import-Module (Join-Path $PSScriptRoot 'AlphaReleaseContainerArchive.psm1') -Force
$productVersion = '0.1.0-alpha.1'
if ($ExpectedSourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'ALPHA_ARTIFACT_BINDING_TEST_SOURCE_INVALID' }
$shortCommit = $ExpectedSourceCommit.Substring(0, 12)
$gatewayReference = "secure-integration-gateway:$productVersion-$shortCommit"
$migrationsReference = "secure-integration-migrations:$productVersion-$shortCommit"
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar))
$testRoot = Join-Path $tempBase ('alpha-container-binding-' + [Guid]::NewGuid().ToString('N'))
if (-not $testRoot.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'ALPHA_ARTIFACT_BINDING_TEST_ROOT_INVALID' }
$ownedCandidateReferences = @{}

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

function Get-ImageId {
    param([string] $Reference)
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $ids = @(& docker image ls --quiet --no-trunc $Reference 2>$null | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previous }
    if ($exitCode -ne 0 -or $ids.Count -gt 1) { throw "ALPHA_ARTIFACT_BINDING_IMAGE_LOOKUP_FAILED: $Reference" }
    return $(if ($ids.Count -eq 1) { $ids[0] } else { '' })
}

function Assert-CandidateAbsent {
    foreach ($reference in @($gatewayReference, $migrationsReference)) {
        if (-not [string]::IsNullOrWhiteSpace((Get-ImageId -Reference $reference))) { throw "ALPHA_ARTIFACT_BINDING_FIXTURE_TAG_PREEXISTING: $reference" }
    }
}

function Add-OwnedCandidateTag {
    param([string] $SourceReference, [string] $CandidateReference, [string] $ExpectedImageId)
    if (-not [string]::IsNullOrWhiteSpace((Get-ImageId -Reference $CandidateReference))) { throw "ALPHA_ARTIFACT_BINDING_FIXTURE_TAG_PREEXISTING: $CandidateReference" }
    & docker image tag $SourceReference $CandidateReference
    if ($LASTEXITCODE -ne 0 -or (Get-ImageId -Reference $CandidateReference) -cne $ExpectedImageId) { throw "ALPHA_ARTIFACT_BINDING_FIXTURE_TAG_FAILED: $CandidateReference" }
    $ownedCandidateReferences[$CandidateReference] = $ExpectedImageId
}

function Remove-OwnedCandidateTags {
    foreach ($reference in @($ownedCandidateReferences.Keys)) {
        $current = Get-ImageId -Reference $reference
        if ([string]::IsNullOrWhiteSpace($current)) { $ownedCandidateReferences.Remove($reference); continue }
        if ($current -cne [string]$ownedCandidateReferences[$reference]) { throw "ALPHA_ARTIFACT_BINDING_FIXTURE_CLEANUP_OWNERSHIP_FAILED: $reference" }
        & docker image rm $reference *> $null
        if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace((Get-ImageId -Reference $reference))) { throw "ALPHA_ARTIFACT_BINDING_FIXTURE_CLEANUP_FAILED: $reference" }
        $ownedCandidateReferences.Remove($reference)
    }
}

function Get-FileRecord {
    param([string] $RunDirectory, [string] $RelativePath, [string] $Kind)
    $full = Join-Path $RunDirectory $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
    return [ordered]@{ file = $RelativePath; kind = $Kind; bytes = [IO.FileInfo]::new($full).Length; sha256 = Get-Sha256Hex -LiteralPath $full }
}

function New-ContainerSbom {
    param([string] $Name, [string] $ImageId, [string] $Tag)
    return [ordered]@{
        spdxVersion = 'SPDX-2.3'; dataLicense = 'CC0-1.0'; SPDXID = 'SPDXRef-DOCUMENT'; name = "$Name container binding test SBOM"
        documentNamespace = "urn:secure-integration:spdx:container-binding:${Name}:$ImageId"
        creationInfo = [ordered]@{ created = '2026-01-01T00:00:00Z'; creators = @('Tool: Test-AlphaReleaseContainerBinding.ps1') }
        packages = @([ordered]@{
            SPDXID = 'SPDXRef-DocumentRoot'; name = $Name; versionInfo = $Tag; downloadLocation = 'NOASSERTION'; filesAnalyzed = $false
            licenseConcluded = 'MPL-2.0'; licenseDeclared = 'MPL-2.0'; copyrightText = 'Copyright 2026 ApoCert S.r.l.'
            externalRefs = @([ordered]@{ referenceCategory = 'PACKAGE-MANAGER'; referenceType = 'purl'; referenceLocator = "pkg:oci/$Name@$ImageId`?repository_url=docker.io&tag=$Tag" })
        })
        relationships = @([ordered]@{ spdxElementId = 'SPDXRef-DOCUMENT'; relationshipType = 'DESCRIBES'; relatedSpdxElement = 'SPDXRef-DocumentRoot' })
    }
}

function Write-ManifestAndSidecar {
    param([string] $RunDirectory, $Manifest)
    $path = Join-Path $RunDirectory 'manifest.json'
    Write-Utf8NoBom -Path $path -Value ($Manifest | ConvertTo-Json -Depth 16)
    [IO.File]::WriteAllText((Join-Path $RunDirectory 'manifest.json.sha256'), "$(Get-Sha256Hex -LiteralPath $path)  manifest.json`r`n", [Text.Encoding]::ASCII)
}

function Sync-ReleaseRecords {
    param([string] $RunDirectory, $Manifest)
    foreach ($artifact in @($Manifest.artifacts)) {
        $full = Join-Path $RunDirectory ([string]$artifact.file).Replace('/', [IO.Path]::DirectorySeparatorChar)
        $artifact.bytes = [IO.FileInfo]::new($full).Length
        $artifact.sha256 = Get-Sha256Hex -LiteralPath $full
    }
    foreach ($sbom in @($Manifest.sbom)) {
        $full = Join-Path $RunDirectory ([string]$sbom.file).Replace('/', [IO.Path]::DirectorySeparatorChar)
        $sbom.bytes = [IO.FileInfo]::new($full).Length
        $sbom.sha256 = Get-Sha256Hex -LiteralPath $full
    }
    [string[]]$checksumLines = @($Manifest.artifacts | ForEach-Object { "$([string]$_.sha256)  $([string]$_.file)" })
    [Array]::Sort($checksumLines, [StringComparer]::Ordinal)
    [IO.File]::WriteAllLines((Join-Path $RunDirectory 'SHA256SUMS'), $checksumLines, [Text.Encoding]::ASCII)
    Write-ManifestAndSidecar -RunDirectory $RunDirectory -Manifest $Manifest
}

function New-ReleaseFixture {
    param([string] $RunDirectory, [string] $GatewayImageId, [string] $MigrationsImageId)
    New-Item -ItemType Directory -Path (Join-Path $RunDirectory 'artifacts'), (Join-Path $RunDirectory 'sbom') -Force | Out-Null
    $gatewayArtifact = "artifacts/gateway-image-$productVersion-$shortCommit.tar"
    $migrationsArtifact = "artifacts/migrations-image-$productVersion-$shortCommit.tar"
    & docker image save --output (Join-Path $RunDirectory $gatewayArtifact.Replace('/', [IO.Path]::DirectorySeparatorChar)) $gatewayReference
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_BINDING_GATEWAY_SAVE_FAILED' }
    & docker image save --output (Join-Path $RunDirectory $migrationsArtifact.Replace('/', [IO.Path]::DirectorySeparatorChar)) $migrationsReference
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_BINDING_MIGRATIONS_SAVE_FAILED' }
    $gatewayIdentity = Get-AlphaReleaseContainerTarIdentity -ArchivePath (Join-Path $RunDirectory $gatewayArtifact.Replace('/', [IO.Path]::DirectorySeparatorChar)) `
        -Role gateway -ExpectedReference $gatewayReference -ProductVersion $productVersion -SourceCommit $ExpectedSourceCommit `
        -InspectionDirectory (Join-Path $testRoot ('fixture-inspect-gateway-' + [Guid]::NewGuid().ToString('N')))
    $migrationsIdentity = Get-AlphaReleaseContainerTarIdentity -ArchivePath (Join-Path $RunDirectory $migrationsArtifact.Replace('/', [IO.Path]::DirectorySeparatorChar)) `
        -Role migrations -ExpectedReference $migrationsReference -ProductVersion $productVersion -SourceCommit $ExpectedSourceCommit `
        -InspectionDirectory (Join-Path $testRoot ('fixture-inspect-migrations-' + [Guid]::NewGuid().ToString('N')))
    if (@($gatewayIdentity.boundImageIds | ForEach-Object { [string]$_ }) -cnotcontains $GatewayImageId -or
        @($migrationsIdentity.boundImageIds | ForEach-Object { [string]$_ }) -cnotcontains $MigrationsImageId) {
        throw 'ALPHA_ARTIFACT_BINDING_SOURCE_ID_NOT_BOUND_TO_TAR'
    }
    $artifactDefinitions = @(
        [pscustomobject]@{ path = "artifacts/SecureIntegration.Broker.Sdk.$productVersion.nupkg"; kind = 'nuget'; licenseExpression = 'Apache-2.0' },
        [pscustomobject]@{ path = "artifacts/admin-web-$productVersion.zip"; kind = 'admin-static-archive'; licenseExpression = 'MPL-2.0' },
        [pscustomobject]@{ path = $gatewayArtifact; kind = 'oci-image-archive'; licenseExpression = 'MPL-2.0' },
        [pscustomobject]@{ path = $migrationsArtifact; kind = 'oci-image-archive'; licenseExpression = 'MPL-2.0' },
        [pscustomobject]@{ path = "artifacts/secure-integration-core-$productVersion-source.zip"; kind = 'core-source-archive'; licenseExpression = 'MPL-2.0 AND Apache-2.0' })
    foreach ($definition in @($artifactDefinitions | Where-Object { $_.kind -cne 'oci-image-archive' })) {
        Write-Utf8NoBom -Path (Join-Path $RunDirectory ([string]$definition.path).Replace('/', [IO.Path]::DirectorySeparatorChar)) -Value ('fixture:' + [string]$definition.path)
    }
    $gatewayTag = $gatewayReference.Substring($gatewayReference.IndexOf(':') + 1)
    $migrationsTag = $migrationsReference.Substring($migrationsReference.IndexOf(':') + 1)
    Write-Utf8NoBom -Path (Join-Path $RunDirectory 'sbom\gateway-container.spdx.json') -Value ((New-ContainerSbom -Name 'secure-integration-gateway' -ImageId $GatewayImageId -Tag $gatewayTag) | ConvertTo-Json -Depth 12)
    Write-Utf8NoBom -Path (Join-Path $RunDirectory 'sbom\migrations-container.spdx.json') -Value ((New-ContainerSbom -Name 'secure-integration-migrations' -ImageId $MigrationsImageId -Tag $migrationsTag) | ConvertTo-Json -Depth 12)
    foreach ($name in @('admin-frontend.spdx.json','auth-certificate-signing.spdx.json','broker.spdx.json','connector-cli.spdx.json','gateway.spdx.json','sdk-dotnet.spdx.json')) {
        Write-Utf8NoBom -Path (Join-Path $RunDirectory ('sbom\' + $name)) -Value '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}'
    }
    Write-Utf8NoBom -Path (Join-Path $RunDirectory 'sbom\aggregate-manifest.json') -Value '{"schemaVersion":1,"aggregateLicenseExpression":"MPL-2.0 AND Apache-2.0","artifacts":[]}'
    $manifest = [ordered]@{
        schemaVersion = 1; product = 'SecureIntegrationPlatform'; version = $productVersion; sourceRevision = $ExpectedSourceCommit; releaseChannel = 'public-technical-preview'; releaseClass = 'PUBLIC TECHNICAL PREVIEW'; distributionTarget = 'GitHub public prerelease v0.1.0-alpha.1'
        generatedAtUtc = '2026-01-01T00:00:00.0000000+00:00'; claims = [ordered]@{ publicReleaseGo = $false; productionReady = $false }
        versionIdentity = [ordered]@{ productVersion = $productVersion; protocolVersion = '1.0'; canonicalConnectorVersion = '1.0.0'; imageRevision = $ExpectedSourceCommit; openApiVersion = $productVersion }
        licensePolicy = [ordered]@{ default = 'MPL-2.0'; sdk = 'Apache-2.0'; contractsProtocol = 'Apache-2.0'; syntheticExamples = 'Apache-2.0'; genericReference = 'MPL-2.0 OR Apache-2.0'; coreSourceArchive = 'MPL-2.0 AND Apache-2.0' }
        coreExport = [ordered]@{ fileCount = 0; rawManifestSha256RunSpecific = 'D' * 64; normalizedInventorySha256 = 'E' * 64 }
        images = @(
            [ordered]@{ role = 'gateway'; reference = $gatewayReference; imageId = $GatewayImageId; versionLabel = $productVersion; revisionLabel = $ExpectedSourceCommit; sourceLabel = 'https://github.com/marcobiz/secure-integration-platform'; vendorLabel = 'ApoCert S.r.l.'; titleLabel = 'Secure Integration Platform Gateway'; licenseLabel = 'MPL-2.0' },
            [ordered]@{ role = 'migrations'; reference = $migrationsReference; imageId = $MigrationsImageId; versionLabel = $productVersion; revisionLabel = $ExpectedSourceCommit; sourceLabel = 'https://github.com/marcobiz/secure-integration-platform'; vendorLabel = 'ApoCert S.r.l.'; titleLabel = 'Secure Integration Platform Migrations'; licenseLabel = 'MPL-2.0' })
        artifacts = @($artifactDefinitions | ForEach-Object { $record = Get-FileRecord -RunDirectory $RunDirectory -RelativePath ([string]$_.path) -Kind ([string]$_.kind); $record['licenseExpression'] = [string]$_.licenseExpression; $record })
        sbom = @(Get-ChildItem -LiteralPath (Join-Path $RunDirectory 'sbom') -File | Sort-Object Name | ForEach-Object { $record = Get-FileRecord -RunDirectory $RunDirectory -RelativePath ('sbom/' + $_.Name) -Kind 'spdx-or-aggregate'; $record['subjectLicenseExpression'] = if ($_.Name -ceq 'sdk-dotnet.spdx.json') { 'Apache-2.0' } elseif ($_.Name -ceq 'aggregate-manifest.json') { 'MPL-2.0 AND Apache-2.0' } else { 'MPL-2.0' }; $record })
        sbomSubjects = @(
            [ordered]@{ role = 'gateway'; sbomFile = 'sbom/gateway-container.spdx.json'; artifactFile = $gatewayArtifact; imageReference = $gatewayReference; imageId = $GatewayImageId; licenseExpression = 'MPL-2.0' },
            [ordered]@{ role = 'migrations'; sbomFile = 'sbom/migrations-container.spdx.json'; artifactFile = $migrationsArtifact; imageReference = $migrationsReference; imageId = $MigrationsImageId; licenseExpression = 'MPL-2.0' })
        signatures = @(); knownFollowUps = @('NONDETERMINISTIC_UI_MOCK_20_AXE_SNAPSHOT')
    }
    Sync-ReleaseRecords -RunDirectory $RunDirectory -Manifest $manifest
}

function New-CaseDirectory {
    param([string] $Name, [string] $BaselineDirectory)
    $case = Join-Path $testRoot ('case-' + $Name)
    Copy-Item -LiteralPath $BaselineDirectory -Destination $case -Recurse
    return $case
}

function Invoke-ValidatorNegative {
    param([string] $Name, [string] $RunDirectory, [string] $ExpectedCode)
    $message = $null
    $captured = @()
    try { $captured = @(& $validator -RunDirectory $RunDirectory -ExpectedSourceCommit $ExpectedSourceCommit -ContainerBindingOnly 2>&1 | ForEach-Object { $_.ToString() }) }
    catch { $message = [string]$_.Exception.Message }
    if ([string]::IsNullOrWhiteSpace($message)) { throw "ALPHA_ARTIFACT_BINDING_NEGATIVE_DID_NOT_FAIL: $Name" }
    if (-not $message.StartsWith($ExpectedCode, [StringComparison]::Ordinal)) { throw "ALPHA_ARTIFACT_BINDING_NEGATIVE_WRONG_CODE: $Name; ACTUAL=$message" }
    if (($captured -join "`n").Contains('PASS')) { throw "ALPHA_ARTIFACT_BINDING_NEGATIVE_EMITTED_PASS: $Name" }
    Write-Host "ALPHA_ARTIFACT_BINDING_NEGATIVE_OK; NAME=$Name; CODE=$ExpectedCode"
}

function New-MinimalMutatedConfigTar {
    param([string] $SourceTar, [string] $DestinationTar, [switch] $WrongRoleWithGatewayTag)
    $stage = Join-Path $testRoot ('tar-stage-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage | Out-Null
    & tar -xf $SourceTar -C $stage manifest.json
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_BINDING_TAR_EXTRACT_FAILED' }
    $tarManifestPath = Join-Path $stage 'manifest.json'
    $tarManifestRaw = Get-Content -LiteralPath $tarManifestPath -Raw
    $tarManifestEntries = @($tarManifestRaw | ConvertFrom-Json)
    if ($tarManifestEntries.Count -ne 1) { throw 'ALPHA_ARTIFACT_BINDING_TAR_MANIFEST_CARDINALITY_INVALID' }
    $tarManifest = $tarManifestEntries[0]
    $configPath = [string]$tarManifest.Config
    & tar -xf $SourceTar -C $stage $configPath
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_BINDING_CONFIG_EXTRACT_FAILED' }
    if ($WrongRoleWithGatewayTag) {
        if (-not $tarManifestRaw.Contains($migrationsReference)) { throw 'ALPHA_ARTIFACT_BINDING_TAR_REPOTAGS_MISSING' }
        $tarManifestRaw = $tarManifestRaw.Replace($migrationsReference, $gatewayReference)
    }
    else { [IO.File]::AppendAllText((Join-Path $stage $configPath.Replace('/', [IO.Path]::DirectorySeparatorChar)), ' ', [Text.UTF8Encoding]::new($false)) }
    Write-Utf8NoBom -Path $tarManifestPath -Value $tarManifestRaw
    & tar -cf $DestinationTar -C $stage manifest.json blobs
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_BINDING_TAR_CREATE_FAILED' }
}

New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $gatewaySourceId = Get-ImageId -Reference $GatewaySourceReference
    $migrationsSourceId = Get-ImageId -Reference $MigrationsSourceReference
    if ($gatewaySourceId -cnotmatch '^sha256:[0-9a-f]{64}$' -or $migrationsSourceId -cnotmatch '^sha256:[0-9a-f]{64}$' -or $gatewaySourceId -ceq $migrationsSourceId) {
        throw 'ALPHA_ARTIFACT_BINDING_SOURCE_IMAGES_INVALID'
    }
    Assert-CandidateAbsent
    Add-OwnedCandidateTag -SourceReference $GatewaySourceReference -CandidateReference $gatewayReference -ExpectedImageId $gatewaySourceId
    Add-OwnedCandidateTag -SourceReference $MigrationsSourceReference -CandidateReference $migrationsReference -ExpectedImageId $migrationsSourceId
    $baseline = Join-Path $testRoot 'baseline'
    New-ReleaseFixture -RunDirectory $baseline -GatewayImageId $gatewaySourceId -MigrationsImageId $migrationsSourceId
    Remove-OwnedCandidateTags

    if ($TestName -in @('All', 'Positive')) {
        $result = (& $validator -RunDirectory $baseline -ExpectedSourceCommit $ExpectedSourceCommit -ContainerBindingOnly | Out-String).Trim() | ConvertFrom-Json
        if ([string]$result.status -cne 'PASS' -or [string]$result.tarImageIdMatch -cne 'PASS') { throw 'ALPHA_ARTIFACT_BINDING_POSITIVE_FAILED' }
        Assert-CandidateAbsent
        if ((Get-ImageId -Reference $GatewaySourceReference) -cne $gatewaySourceId -or (Get-ImageId -Reference $MigrationsSourceReference) -cne $migrationsSourceId) { throw 'ALPHA_ARTIFACT_BINDING_FOREIGN_SOURCE_MUTATED' }
        Write-Host 'ALPHA_ART_CONTAINER_BINDING_POSITIVE_PASS'
        Write-Host 'ALPHA_ART_CONTAINER_TASK_OWNED_TAG_CLEANUP_PASS'
        Write-Host 'ALPHA_ART_CONTAINER_FOREIGN_IMAGES_PRESERVED_PASS'
    }

    if ($TestName -in @('All', 'PreexistingTags')) {
        Add-OwnedCandidateTag -SourceReference $GatewaySourceReference -CandidateReference $gatewayReference -ExpectedImageId $gatewaySourceId
        Invoke-ValidatorNegative -Name 'PreexistingGatewayTag' -RunDirectory $baseline -ExpectedCode 'ALPHA_ART_CANDIDATE_IMAGE_TAG_PREEXISTING:'
        if ((Get-ImageId -Reference $gatewayReference) -cne $gatewaySourceId) { throw 'ALPHA_ARTIFACT_BINDING_PREEXISTING_GATEWAY_MUTATED' }
        Remove-OwnedCandidateTags
        Add-OwnedCandidateTag -SourceReference $MigrationsSourceReference -CandidateReference $migrationsReference -ExpectedImageId $migrationsSourceId
        Invoke-ValidatorNegative -Name 'PreexistingMigrationsTag' -RunDirectory $baseline -ExpectedCode 'ALPHA_ART_CANDIDATE_IMAGE_TAG_PREEXISTING:'
        if ((Get-ImageId -Reference $migrationsReference) -cne $migrationsSourceId) { throw 'ALPHA_ARTIFACT_BINDING_PREEXISTING_MIGRATIONS_MUTATED' }
        Remove-OwnedCandidateTags
        Add-OwnedCandidateTag -SourceReference $GatewaySourceReference -CandidateReference $gatewayReference -ExpectedImageId $gatewaySourceId
        Add-OwnedCandidateTag -SourceReference $MigrationsSourceReference -CandidateReference $migrationsReference -ExpectedImageId $migrationsSourceId
        Invoke-ValidatorNegative -Name 'BothPreexistingTags' -RunDirectory $baseline -ExpectedCode 'ALPHA_ART_CANDIDATE_IMAGE_TAG_PREEXISTING:'
        if ((Get-ImageId -Reference $gatewayReference) -cne $gatewaySourceId -or (Get-ImageId -Reference $migrationsReference) -cne $migrationsSourceId) { throw 'ALPHA_ARTIFACT_BINDING_PREEXISTING_TAGS_MUTATED' }
        Remove-OwnedCandidateTags
        Write-Host 'ALPHA_ART_CONTAINER_PREEXISTING_TAG_NEGATIVES_PASS'
    }

    if ($TestName -in @('All', 'SwappedTar')) {
        $swapped = New-CaseDirectory -Name 'swapped' -BaselineDirectory $baseline
        $gatewayTar = Join-Path $swapped "artifacts\gateway-image-$productVersion-$shortCommit.tar"
        $migrationsTar = Join-Path $swapped "artifacts\migrations-image-$productVersion-$shortCommit.tar"
        $swapTemp = Join-Path $swapped 'artifacts\swap.tmp'
        Move-Item -LiteralPath $gatewayTar -Destination $swapTemp
        Move-Item -LiteralPath $migrationsTar -Destination $gatewayTar
        Move-Item -LiteralPath $swapTemp -Destination $migrationsTar
        $swappedManifest = Get-Content -LiteralPath (Join-Path $swapped 'manifest.json') -Raw | ConvertFrom-Json
        Sync-ReleaseRecords -RunDirectory $swapped -Manifest $swappedManifest
        Invoke-ValidatorNegative -Name 'SwappedTarEmptyDaemon' -RunDirectory $swapped -ExpectedCode 'ALPHA_ARTIFACT_TAR_REPOTAG_MISMATCH:'
        Add-OwnedCandidateTag -SourceReference $GatewaySourceReference -CandidateReference $gatewayReference -ExpectedImageId $gatewaySourceId
        Add-OwnedCandidateTag -SourceReference $MigrationsSourceReference -CandidateReference $migrationsReference -ExpectedImageId $migrationsSourceId
        Invoke-ValidatorNegative -Name 'SwappedTarPreloadedTags' -RunDirectory $swapped -ExpectedCode 'ALPHA_ART_CANDIDATE_IMAGE_TAG_PREEXISTING:'
        if ((Get-ImageId -Reference $gatewayReference) -cne $gatewaySourceId -or (Get-ImageId -Reference $migrationsReference) -cne $migrationsSourceId) { throw 'ALPHA_ARTIFACT_BINDING_PRELOADED_TAGS_MUTATED' }
        Remove-OwnedCandidateTags
        $wrongGateway = New-CaseDirectory -Name 'wrong-gateway-tar-correct-sbom' -BaselineDirectory $baseline
        Copy-Item -LiteralPath (Join-Path $baseline "artifacts\migrations-image-$productVersion-$shortCommit.tar") -Destination (Join-Path $wrongGateway "artifacts\gateway-image-$productVersion-$shortCommit.tar") -Force
        $wrongGatewayManifest = Get-Content -LiteralPath (Join-Path $wrongGateway 'manifest.json') -Raw | ConvertFrom-Json
        Sync-ReleaseRecords -RunDirectory $wrongGateway -Manifest $wrongGatewayManifest
        Invoke-ValidatorNegative -Name 'WrongRepoTagAndWrongTarWithCorrectSbom' -RunDirectory $wrongGateway -ExpectedCode 'ALPHA_ARTIFACT_TAR_REPOTAG_MISMATCH:'
        Write-Host 'ALPHA_ART_CONTAINER_SWAPPED_TAR_NEGATIVES_PASS'
    }

    if ($TestName -in @('All', 'IdentityMismatch')) {
        $configMismatch = New-CaseDirectory -Name 'config-mismatch' -BaselineDirectory $baseline
        $configMismatchTar = Join-Path $configMismatch "artifacts\gateway-image-$productVersion-$shortCommit.tar"
        New-MinimalMutatedConfigTar -SourceTar (Join-Path $baseline "artifacts\gateway-image-$productVersion-$shortCommit.tar") -DestinationTar $configMismatchTar
        $configManifest = Get-Content -LiteralPath (Join-Path $configMismatch 'manifest.json') -Raw | ConvertFrom-Json
        Sync-ReleaseRecords -RunDirectory $configMismatch -Manifest $configManifest
        Invoke-ValidatorNegative -Name 'ConfigDigestMismatch' -RunDirectory $configMismatch -ExpectedCode 'ALPHA_ARTIFACT_TAR_CONFIG_DIGEST_MISMATCH:'

        $regenerated = New-CaseDirectory -Name 'regenerated-wrong-role' -BaselineDirectory $baseline
        $regeneratedGatewayTar = Join-Path $regenerated "artifacts\gateway-image-$productVersion-$shortCommit.tar"
        New-MinimalMutatedConfigTar -SourceTar (Join-Path $baseline "artifacts\migrations-image-$productVersion-$shortCommit.tar") -DestinationTar $regeneratedGatewayTar -WrongRoleWithGatewayTag
        $regeneratedManifest = Get-Content -LiteralPath (Join-Path $regenerated 'manifest.json') -Raw | ConvertFrom-Json
        $regeneratedManifest.images[0].imageId = $migrationsSourceId
        $regeneratedManifest.sbomSubjects[0].imageId = $migrationsSourceId
        $gatewaySbomPath = Join-Path $regenerated 'sbom\gateway-container.spdx.json'
        $gatewayTag = $gatewayReference.Substring($gatewayReference.IndexOf(':') + 1)
        Write-Utf8NoBom -Path $gatewaySbomPath -Value ((New-ContainerSbom -Name 'secure-integration-gateway' -ImageId $migrationsSourceId -Tag $gatewayTag) | ConvertTo-Json -Depth 12)
        Sync-ReleaseRecords -RunDirectory $regenerated -Manifest $regeneratedManifest
        Invoke-ValidatorNegative -Name 'RegeneratedManifestAndSbomForWrongTarRole' -RunDirectory $regenerated -ExpectedCode 'ALPHA_ARTIFACT_TAR_CONFIG_PROFILE_MISMATCH:'
        Write-Host 'ALPHA_ART_CONTAINER_CONFIG_AND_SUBJECT_IDENTITY_NEGATIVES_PASS'
    }

    if ((Get-ImageId -Reference $GatewaySourceReference) -cne $gatewaySourceId -or (Get-ImageId -Reference $MigrationsSourceReference) -cne $migrationsSourceId) { throw 'ALPHA_ARTIFACT_BINDING_FOREIGN_IMAGES_NOT_PRESERVED' }
    Write-Host 'ALPHA_ART_CONTAINER_BINDING_ALL_REQUESTED_TESTS_PASS'
}
finally {
    Remove-OwnedCandidateTags
    if (Test-Path -LiteralPath $testRoot) {
        $resolved = [IO.Path]::GetFullPath($testRoot)
        if (-not $resolved.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'ALPHA_ARTIFACT_BINDING_TEST_CLEANUP_TARGET_INVALID' }
        [IO.Directory]::Delete($resolved, $true)
    }
}

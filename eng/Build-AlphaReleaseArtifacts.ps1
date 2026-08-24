[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $OutputDirectory,
    [string] $ExpectedSourceCommit,
    [string] $DotNetPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
$rootPrefix = $root.TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)) + [IO.Path]::DirectorySeparatorChar
if ($output.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or $output.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'ALPHA_RELEASE_OUTPUT_MUST_BE_OUTSIDE_REPOSITORY'
}
if (Test-Path -LiteralPath $output) { throw 'ALPHA_RELEASE_OUTPUT_MUST_NOT_EXIST' }

$status = @(& git -C $root status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0) { throw 'ALPHA_RELEASE_GIT_STATUS_FAILED' }
if ($status.Count -ne 0) { throw 'ALPHA_RELEASE_SOURCE_MUST_BE_CLEAN' }
$sourceCommit = (& git -C $root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'ALPHA_RELEASE_SOURCE_COMMIT_INVALID' }
if (-not [string]::IsNullOrWhiteSpace($ExpectedSourceCommit) -and $sourceCommit -cne $ExpectedSourceCommit) {
    throw 'ALPHA_RELEASE_SOURCE_COMMIT_MISMATCH'
}

$versionDocument = [xml](Get-Content -LiteralPath (Join-Path $root 'Directory.Build.props') -Raw)
$productVersionNode = $versionDocument.SelectSingleNode('/Project/PropertyGroup/ProductVersion')
$productVersion = if ($null -eq $productVersionNode) { '' } else { [string]$productVersionNode.InnerText }
if ($productVersion -cne '0.1.0-alpha.1') { throw 'ALPHA_RELEASE_PRODUCT_VERSION_INVALID' }
$templatePath = Join-Path $root 'deploy\release-manifest.template.json'
$template = Get-Content -LiteralPath $templatePath -Raw | ConvertFrom-Json
if ([int]$template.schemaVersion -ne 1 -or [string]$template.product -cne 'SecureIntegrationPlatform' -or
    [string]$template.releaseChannel -cne 'public-technical-preview' -or
    [string]$template.releaseClass -cne 'PUBLIC TECHNICAL PREVIEW' -or
    [string]$template.licensePolicy.coreSourceArchive -cne 'MPL-2.0 AND Apache-2.0') { throw 'ALPHA_RELEASE_MANIFEST_TEMPLATE_INVALID' }
$repositoryDotNet = Join-Path $root '.dotnet\dotnet.exe'
$dotnet = if (-not [string]::IsNullOrWhiteSpace($DotNetPath)) { [IO.Path]::GetFullPath($DotNetPath) }
    elseif (Test-Path -LiteralPath $repositoryDotNet -PathType Leaf) { $repositoryDotNet }
    else { 'dotnet' }
if ($dotnet -cne 'dotnet' -and -not (Test-Path -LiteralPath $dotnet -PathType Leaf)) { throw 'ALPHA_RELEASE_DOTNET_PATH_INVALID' }

$artifactsDirectory = Join-Path $output 'artifacts'
$sbomDirectory = Join-Path $output 'sbom'
$validationDirectory = Join-Path $output 'validation'
$workDirectory = Join-Path $output '.work'
New-Item -ItemType Directory -Path $artifactsDirectory, $sbomDirectory, $validationDirectory, $workDirectory | Out-Null

function Invoke-Checked {
    param([Parameter(Mandatory = $true)][string] $File, [Parameter(Mandatory = $true)][string[]] $Arguments, [Parameter(Mandatory = $true)][string] $FailureCode)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw $FailureCode }
}

function Get-FileRecord {
    param([Parameter(Mandatory = $true)][IO.FileInfo] $File, [Parameter(Mandatory = $true)][string] $BaseDirectory, [Parameter(Mandatory = $true)][string] $Kind)
    $relative = $File.FullName.Substring($BaseDirectory.Length + 1).Replace('\', '/')
    return [ordered]@{ file = $relative; kind = $Kind; bytes = $File.Length; sha256 = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash }
}

function Compress-DirectoryContents {
    param([Parameter(Mandatory = $true)][string] $SourceDirectory, [Parameter(Mandatory = $true)][string] $DestinationArchive)
    if (Test-Path -LiteralPath $DestinationArchive) { throw 'ALPHA_RELEASE_ARCHIVE_ALREADY_EXISTS' }
    $children = @(Get-ChildItem -LiteralPath $SourceDirectory -Force)
    if ($children.Count -eq 0) { throw 'ALPHA_RELEASE_ARCHIVE_SOURCE_EMPTY' }
    Compress-Archive -Path ($children | Select-Object -ExpandProperty FullName) -DestinationPath $DestinationArchive -CompressionLevel Optimal
}

function Get-DockerImageIdByReference {
    param([Parameter(Mandatory = $true)][string] $Reference)
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $ids = @(& docker image ls --quiet --no-trunc $Reference 2>$null | ForEach-Object { ([string]$_).Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousErrorActionPreference }
    if ($exitCode -ne 0) { throw 'ALPHA_RELEASE_IMAGE_LOOKUP_FAILED' }
    if ($ids.Count -gt 1) { throw 'ALPHA_RELEASE_IMAGE_LOOKUP_AMBIGUOUS' }
    return $(if ($ids.Count -eq 1) { $ids[0] } else { '' })
}

function Remove-TaskOwnedImageReference {
    param([Parameter(Mandatory = $true)][string] $Reference, [Parameter(Mandatory = $true)][string] $ExpectedImageId)
    $currentImageId = Get-DockerImageIdByReference -Reference $Reference
    if ([string]::IsNullOrWhiteSpace($currentImageId)) { return }
    if ($currentImageId -cne $ExpectedImageId) { throw "ALPHA_RELEASE_IMAGE_CLEANUP_OWNERSHIP_FAILED: $Reference" }
    & docker image rm $Reference *> $null
    if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace((Get-DockerImageIdByReference -Reference $Reference))) {
        throw "ALPHA_RELEASE_IMAGE_CLEANUP_FAILED: $Reference"
    }
}

$ownedBuildReferences = @{}
try {
    $sdkProject = Join-Path $root 'sdk\dotnet\Broker.Sdk\Broker.Sdk.csproj'
    Invoke-Checked -File $dotnet -Arguments @('restore', $sdkProject, '--locked-mode', '/p:AlphaReleasePack=true') -FailureCode 'ALPHA_RELEASE_SDK_RESTORE_FAILED'
    Invoke-Checked -File $dotnet -Arguments @(
        'pack', $sdkProject, '--configuration', 'Release', '--no-restore', '--output', $artifactsDirectory,
        '/p:ContinuousIntegrationBuild=true', ('/p:PathMap=' + $root + '=/_/src'),
        '/p:AlphaReleasePack=true') -FailureCode 'ALPHA_RELEASE_SDK_PACK_FAILED'
    $packages = @(Get-ChildItem -LiteralPath $artifactsDirectory -File -Filter '*.nupkg')
    if ($packages.Count -ne 1 -or $packages[0].Name -cne "SecureIntegration.Broker.Sdk.$productVersion.nupkg") {
        throw 'ALPHA_RELEASE_NUGET_INVENTORY_INVALID'
    }

    $adminRoot = Join-Path $root 'src\Admin\Admin.Web'
    Push-Location $adminRoot
    try {
        Invoke-Checked -File 'npm' -Arguments @('ci', '--ignore-scripts') -FailureCode 'ALPHA_RELEASE_ADMIN_RESTORE_FAILED'
        Invoke-Checked -File 'npm' -Arguments @('run', 'build') -FailureCode 'ALPHA_RELEASE_ADMIN_BUILD_FAILED'
    }
    finally { Pop-Location }
    $adminStage = Join-Path $workDirectory 'admin-web'
    New-Item -ItemType Directory -Path $adminStage | Out-Null
    foreach ($child in Get-ChildItem -LiteralPath (Join-Path $adminRoot 'dist') -Force) {
        Copy-Item -LiteralPath $child.FullName -Destination $adminStage -Recurse
    }
    Copy-Item -LiteralPath (Join-Path $root 'LICENSE') -Destination (Join-Path $adminStage 'LICENSE')
    Copy-Item -LiteralPath (Join-Path $root 'NOTICE') -Destination (Join-Path $adminStage 'NOTICE')
    $adminArchive = Join-Path $artifactsDirectory "admin-web-$productVersion.zip"
    Compress-DirectoryContents -SourceDirectory $adminStage -DestinationArchive $adminArchive

    $coreExportDirectory = Join-Path $workDirectory 'core-export'
    & (Join-Path $PSScriptRoot 'Export-OpenSourceCore.ps1') -OutputDirectory $coreExportDirectory -SkipVerification
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_RELEASE_CORE_EXPORT_FAILED' }
    $coreManifestPath = Join-Path $coreExportDirectory 'OPEN_SOURCE_EXPORT_MANIFEST.json'
    $coreManifest = Get-Content -LiteralPath $coreManifestPath -Raw | ConvertFrom-Json
    $coreRawManifestSha256 = (Get-FileHash -LiteralPath $coreManifestPath -Algorithm SHA256).Hash
    $coreNormalizedInventorySha256 = [string]$coreManifest.normalizedInventorySha256
    $coreFileCount = [int]$coreManifest.fileCount
    $coreArchive = Join-Path $artifactsDirectory "secure-integration-core-$productVersion-source.zip"
    Compress-DirectoryContents -SourceDirectory $coreExportDirectory -DestinationArchive $coreArchive

    $shortCommit = $sourceCommit.Substring(0, 12)
    $gatewayImage = "secure-integration-gateway:$productVersion-$shortCommit"
    $migrationsImage = "secure-integration-migrations:$productVersion-$shortCommit"
    foreach ($reference in @($gatewayImage, $migrationsImage)) {
        if (-not [string]::IsNullOrWhiteSpace((Get-DockerImageIdByReference -Reference $reference))) {
            throw "ALPHA_RELEASE_CANDIDATE_IMAGE_TAG_PREEXISTING: $reference"
        }
    }
    $commonBuildArguments = @(
        'build', '--pull', '--no-cache', '--provenance=false',
        '--build-arg', "PRODUCT_VERSION=$productVersion",
        '--build-arg', "SOURCE_REVISION=$sourceCommit")
    Invoke-Checked -File 'docker' -Arguments ($commonBuildArguments + @(
        '--file', (Join-Path $root 'src\Gateway\Gateway.Api\Dockerfile'), '--tag', $gatewayImage, $root)) -FailureCode 'ALPHA_RELEASE_GATEWAY_IMAGE_BUILD_FAILED'
    $gatewayBuiltImageId = Get-DockerImageIdByReference -Reference $gatewayImage
    if ($gatewayBuiltImageId -cnotmatch '^sha256:[0-9a-f]{64}$') { throw 'ALPHA_RELEASE_GATEWAY_IMAGE_ID_INVALID' }
    $ownedBuildReferences[$gatewayImage] = $gatewayBuiltImageId
    Invoke-Checked -File 'docker' -Arguments ($commonBuildArguments + @(
        '--file', (Join-Path $root 'src\Gateway\Gateway.Migrations\Dockerfile'), '--tag', $migrationsImage, $root)) -FailureCode 'ALPHA_RELEASE_MIGRATIONS_IMAGE_BUILD_FAILED'
    $migrationsBuiltImageId = Get-DockerImageIdByReference -Reference $migrationsImage
    if ($migrationsBuiltImageId -cnotmatch '^sha256:[0-9a-f]{64}$') { throw 'ALPHA_RELEASE_MIGRATIONS_IMAGE_ID_INVALID' }
    $ownedBuildReferences[$migrationsImage] = $migrationsBuiltImageId

    $gatewayImageArchive = Join-Path $artifactsDirectory "gateway-image-$productVersion-$shortCommit.tar"
    $migrationsImageArchive = Join-Path $artifactsDirectory "migrations-image-$productVersion-$shortCommit.tar"
    Invoke-Checked -File 'docker' -Arguments @('image', 'save', '--output', $gatewayImageArchive, $gatewayImage) -FailureCode 'ALPHA_RELEASE_GATEWAY_IMAGE_SAVE_FAILED'
    Invoke-Checked -File 'docker' -Arguments @('image', 'save', '--output', $migrationsImageArchive, $migrationsImage) -FailureCode 'ALPHA_RELEASE_MIGRATIONS_IMAGE_SAVE_FAILED'

    $gatewayInspect = @(& docker image inspect $gatewayImage | ConvertFrom-Json)[0]
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_RELEASE_GATEWAY_IMAGE_INSPECT_FAILED' }
    $migrationsInspect = @(& docker image inspect $migrationsImage | ConvertFrom-Json)[0]
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_RELEASE_MIGRATIONS_IMAGE_INSPECT_FAILED' }
    foreach ($inspect in @($gatewayInspect, $migrationsInspect)) {
        if ([string]$inspect.Config.Labels.'org.opencontainers.image.version' -cne $productVersion -or
            [string]$inspect.Config.Labels.'org.opencontainers.image.revision' -cne $sourceCommit -or
            [string]$inspect.Config.Labels.'org.opencontainers.image.source' -cne 'https://github.com/marcobiz/secure-integration-platform' -or
            [string]$inspect.Config.Labels.'org.opencontainers.image.vendor' -cne 'ApoCert S.r.l.' -or
            [string]$inspect.Config.Labels.'org.opencontainers.image.licenses' -cne 'MPL-2.0') {
            throw 'ALPHA_RELEASE_OCI_LABEL_MISMATCH'
        }
        if ([string]::IsNullOrWhiteSpace([string]$inspect.Config.User) -or [string]$inspect.Config.User -ceq '0' -or [string]$inspect.Config.User -ceq 'root') {
            throw 'ALPHA_RELEASE_OCI_USER_INVALID'
        }
    }

    & (Join-Path $PSScriptRoot 'generate-sbom.ps1') -GatewayImage $gatewayImage -MigrationsImage $migrationsImage -OutputDirectory $sbomDirectory
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_RELEASE_SBOM_FAILED' }

    $artifactFiles = @(Get-ChildItem -LiteralPath $artifactsDirectory -File)
    [string[]]$artifactNames = @($artifactFiles.Name)
    [Array]::Sort($artifactNames, [StringComparer]::Ordinal)
    $artifactByName = @{}
    foreach ($file in $artifactFiles) { $artifactByName[$file.Name] = $file }
    $artifactEntries = foreach ($name in $artifactNames) {
        $kind = if ($name.EndsWith('.nupkg', [StringComparison]::Ordinal)) { 'nuget' }
            elseif ($name.StartsWith('gateway-image-', [StringComparison]::Ordinal)) { 'oci-image-archive' }
            elseif ($name.StartsWith('migrations-image-', [StringComparison]::Ordinal)) { 'oci-image-archive' }
            elseif ($name.StartsWith('admin-web-', [StringComparison]::Ordinal)) { 'admin-static-archive' }
            else { 'core-source-archive' }
        $record = Get-FileRecord -File $artifactByName[$name] -BaseDirectory $output -Kind $kind
        $record['licenseExpression'] = if ($kind -ceq 'nuget') { 'Apache-2.0' }
            elseif ($kind -ceq 'core-source-archive') { 'MPL-2.0 AND Apache-2.0' }
            else { 'MPL-2.0' }
        $record
    }
    $sbomFiles = @(Get-ChildItem -LiteralPath $sbomDirectory -File)
    [string[]]$sbomNames = @($sbomFiles.Name)
    [Array]::Sort($sbomNames, [StringComparer]::Ordinal)
    $sbomByName = @{}
    foreach ($file in $sbomFiles) { $sbomByName[$file.Name] = $file }
    $sbomEntries = foreach ($name in $sbomNames) {
        $record = Get-FileRecord -File $sbomByName[$name] -BaseDirectory $output -Kind 'spdx-or-aggregate'
        $record['subjectLicenseExpression'] = if ($name -ceq 'sdk-dotnet.spdx.json') { 'Apache-2.0' }
            elseif ($name -ceq 'aggregate-manifest.json') { 'MPL-2.0 AND Apache-2.0' }
            else { 'MPL-2.0' }
        $record
    }
    $gatewayArtifactFile = 'artifacts/' + [IO.Path]::GetFileName($gatewayImageArchive)
    $migrationsArtifactFile = 'artifacts/' + [IO.Path]::GetFileName($migrationsImageArchive)
    $imageEntries = @(
        [ordered]@{ role = 'gateway'; reference = $gatewayImage; imageId = [string]$gatewayInspect.Id; versionLabel = $productVersion; revisionLabel = $sourceCommit; sourceLabel = 'https://github.com/marcobiz/secure-integration-platform'; vendorLabel = 'ApoCert S.r.l.'; titleLabel = 'Secure Integration Platform Gateway'; licenseLabel = 'MPL-2.0' },
        [ordered]@{ role = 'migrations'; reference = $migrationsImage; imageId = [string]$migrationsInspect.Id; versionLabel = $productVersion; revisionLabel = $sourceCommit; sourceLabel = 'https://github.com/marcobiz/secure-integration-platform'; vendorLabel = 'ApoCert S.r.l.'; titleLabel = 'Secure Integration Platform Migrations'; licenseLabel = 'MPL-2.0' })
    $sbomSubjectEntries = @(
        [ordered]@{ role = 'gateway'; sbomFile = 'sbom/gateway-container.spdx.json'; artifactFile = $gatewayArtifactFile; imageReference = $gatewayImage; imageId = [string]$gatewayInspect.Id; licenseExpression = 'MPL-2.0' },
        [ordered]@{ role = 'migrations'; sbomFile = 'sbom/migrations-container.spdx.json'; artifactFile = $migrationsArtifactFile; imageReference = $migrationsImage; imageId = [string]$migrationsInspect.Id; licenseExpression = 'MPL-2.0' })

    $manifest = [ordered]@{
        schemaVersion = 1
        product = 'SecureIntegrationPlatform'
        version = $productVersion
        sourceRevision = $sourceCommit
        releaseChannel = 'public-technical-preview'
        releaseClass = 'PUBLIC TECHNICAL PREVIEW'
        distributionTarget = 'GitHub public prerelease v0.1.0-alpha.1'
        generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        claims = [ordered]@{ publicReleaseGo = $false; productionReady = $false }
        versionIdentity = [ordered]@{ productVersion = $productVersion; protocolVersion = '1.0'; canonicalConnectorVersion = '1.0.0'; imageRevision = $sourceCommit; openApiVersion = $productVersion }
        licensePolicy = [ordered]@{ default = 'MPL-2.0'; sdk = 'Apache-2.0'; contractsProtocol = 'Apache-2.0'; syntheticExamples = 'Apache-2.0'; genericReference = 'MPL-2.0 OR Apache-2.0'; coreSourceArchive = 'MPL-2.0 AND Apache-2.0' }
        coreExport = [ordered]@{ fileCount = $coreFileCount; rawManifestSha256RunSpecific = $coreRawManifestSha256; normalizedInventorySha256 = $coreNormalizedInventorySha256 }
        images = $imageEntries
        artifacts = @($artifactEntries)
        sbom = @($sbomEntries)
        sbomSubjects = $sbomSubjectEntries
        signatures = @()
        knownFollowUps = @('NONDETERMINISTIC_UI_MOCK_20_AXE_SNAPSHOT')
    }
    $manifestPath = Join-Path $output 'manifest.json'
    [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    $manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    Set-Content -LiteralPath (Join-Path $output 'manifest.json.sha256') -Value "$manifestSha256  manifest.json" -Encoding ASCII

    $checksumFiles = @(Get-ChildItem -LiteralPath $artifactsDirectory -File)
    [string[]]$checksumRelativePaths = @($checksumFiles | ForEach-Object { $_.FullName.Substring($output.Length + 1).Replace('\', '/') })
    [Array]::Sort($checksumRelativePaths, [StringComparer]::Ordinal)
    $checksumByRelativePath = @{}
    foreach ($file in $checksumFiles) { $checksumByRelativePath[$file.FullName.Substring($output.Length + 1).Replace('\', '/')] = $file.FullName }
    $checksumLines = foreach ($relative in $checksumRelativePaths) { "$(Get-FileHash -LiteralPath $checksumByRelativePath[$relative] -Algorithm SHA256 | Select-Object -ExpandProperty Hash)  $relative" }
    Set-Content -LiteralPath (Join-Path $output 'SHA256SUMS') -Value $checksumLines -Encoding ASCII

    Remove-TaskOwnedImageReference -Reference $gatewayImage -ExpectedImageId ([string]$gatewayInspect.Id)
    Remove-TaskOwnedImageReference -Reference $migrationsImage -ExpectedImageId ([string]$migrationsInspect.Id)
    $validation = & (Join-Path $PSScriptRoot 'Test-AlphaReleaseArtifacts.ps1') -RunDirectory $output -ExpectedSourceCommit $sourceCommit -DotNetPath $dotnet | Out-String
    [IO.File]::WriteAllText((Join-Path $validationDirectory 'artifact-validation.json'), $validation.Trim(), [Text.UTF8Encoding]::new($false))

    [pscustomobject]@{
        status = 'PASS'
        productVersion = $productVersion
        sourceRevision = $sourceCommit
        artifactCount = $artifactEntries.Count
        coreExportFileCount = $coreFileCount
        rawManifestSha256RunSpecific = $coreRawManifestSha256
        normalizedInventorySha256 = $coreNormalizedInventorySha256
        manifestSha256 = $manifestSha256
        gatewayImage = $gatewayImage
        migrationsImage = $migrationsImage
    } | ConvertTo-Json -Depth 4
}
finally {
    foreach ($reference in @($ownedBuildReferences.Keys)) {
        Remove-TaskOwnedImageReference -Reference $reference -ExpectedImageId ([string]$ownedBuildReferences[$reference])
    }
    if (Test-Path -LiteralPath $workDirectory) {
        $resolvedWork = [IO.Path]::GetFullPath($workDirectory)
        $outputPrefix = $output.TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)) + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedWork.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'ALPHA_RELEASE_WORK_CLEANUP_TARGET_INVALID' }
        Remove-Item -LiteralPath $resolvedWork -Recurse -Force
    }
}

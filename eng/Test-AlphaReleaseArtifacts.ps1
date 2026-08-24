[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $RunDirectory,
    [string] $SecondRunDirectory,
    [string] $ExpectedSourceCommit,
    [string] $DotNetPath,
    [switch] $RunConsumerInstall,
    [switch] $RunContainerRuntime,
    [switch] $ReleaseSetOnly,
    [switch] $ContainerBindingOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$run = [IO.Path]::GetFullPath($RunDirectory)
if (-not (Test-Path -LiteralPath $run -PathType Container)) { throw 'ALPHA_ARTIFACT_RUN_MISSING' }
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar))
$testRoot = Join-Path $tempBase ('alpha-artifact-validation-' + [Guid]::NewGuid().ToString('N'))
if (-not $testRoot.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'ALPHA_ARTIFACT_TEST_ROOT_INVALID' }
New-Item -ItemType Directory -Path $testRoot | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
Import-Module (Join-Path $PSScriptRoot 'AlphaReleaseContainerArchive.psm1') -Force
$repositoryDotNet = Join-Path $root '.dotnet\dotnet.exe'
$dotnet = if (-not [string]::IsNullOrWhiteSpace($DotNetPath)) { [IO.Path]::GetFullPath($DotNetPath) }
    elseif (Test-Path -LiteralPath $repositoryDotNet -PathType Leaf) { $repositoryDotNet }
    else { 'dotnet' }
if ($dotnet -cne 'dotnet' -and -not (Test-Path -LiteralPath $dotnet -PathType Leaf)) { throw 'ALPHA_ARTIFACT_DOTNET_PATH_INVALID' }

function Get-ZipEntries([string] $ArchivePath) {
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        return @($archive.Entries |
            ForEach-Object { $_.FullName.Replace('\', '/') } |
            Where-Object { $_.Length -gt 0 -and -not $_.EndsWith('/', [StringComparison]::Ordinal) })
    }
    finally { $archive.Dispose() }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string] $LiteralPath)
    $stream = [IO.File]::OpenRead($LiteralPath)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace('-', '') }
    finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Test-ArchiveEntryPath([string] $Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.StartsWith('/', [StringComparison]::Ordinal) -or
        $Path.Contains('\') -or $Path.Contains(':') -or $Path.Contains('//')) { return $false }
    foreach ($character in $Path.ToCharArray()) { if ([char]::IsControl($character)) { return $false } }
    foreach ($segment in $Path.Split('/')) { if ($segment.Length -eq 0 -or $segment -eq '.' -or $segment -eq '..') { return $false } }
    return $true
}

function Get-ObjectArrayProperty {
    param([Parameter(Mandatory = $true)] $Object, [Parameter(Mandatory = $true)][string] $Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return @() }
    return @($property.Value)
}

function Get-RequiredPropertyValue {
    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { throw $FailureCode }
    return $property.Value
}

function Get-AlphaReleaseProfile {
    param(
        [Parameter(Mandatory = $true)][string] $ProductVersion,
        [Parameter(Mandatory = $true)][string] $SourceCommit
    )
    if ($ProductVersion -cne '0.1.0-alpha.1') { throw 'ALPHA_ARTIFACT_PRODUCT_VERSION_MISMATCH' }
    if ($SourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'ALPHA_ARTIFACT_SOURCE_REVISION_INVALID' }
    $shortCommit = $SourceCommit.Substring(0, 12)
    $gatewayArtifact = "artifacts/gateway-image-$ProductVersion-$shortCommit.tar"
    $migrationsArtifact = "artifacts/migrations-image-$ProductVersion-$shortCommit.tar"
    $gatewayReference = "secure-integration-gateway:$ProductVersion-$shortCommit"
    $migrationsReference = "secure-integration-migrations:$ProductVersion-$shortCommit"
    return [pscustomobject]@{
        artifacts = @(
            [pscustomobject]@{ path = "artifacts/SecureIntegration.Broker.Sdk.$ProductVersion.nupkg"; kind = 'nuget'; licenseExpression = 'Apache-2.0' },
            [pscustomobject]@{ path = "artifacts/admin-web-$ProductVersion.zip"; kind = 'admin-static-archive'; licenseExpression = 'MPL-2.0' },
            [pscustomobject]@{ path = $gatewayArtifact; kind = 'oci-image-archive'; licenseExpression = 'MPL-2.0' },
            [pscustomobject]@{ path = $migrationsArtifact; kind = 'oci-image-archive'; licenseExpression = 'MPL-2.0' },
            [pscustomobject]@{ path = "artifacts/secure-integration-core-$ProductVersion-source.zip"; kind = 'core-source-archive'; licenseExpression = 'MPL-2.0 AND Apache-2.0' })
        sbomFiles = @(
            'sbom/admin-frontend.spdx.json',
            'sbom/aggregate-manifest.json',
            'sbom/auth-certificate-signing.spdx.json',
            'sbom/broker.spdx.json',
            'sbom/connector-cli.spdx.json',
            'sbom/gateway-container.spdx.json',
            'sbom/gateway.spdx.json',
            'sbom/migrations-container.spdx.json',
            'sbom/sdk-dotnet.spdx.json')
        sbomSubjects = @(
            [pscustomobject]@{ role = 'gateway'; sbomFile = 'sbom/gateway-container.spdx.json'; artifactFile = $gatewayArtifact; imageName = 'secure-integration-gateway'; imageReference = $gatewayReference; licenseExpression = 'MPL-2.0' },
            [pscustomobject]@{ role = 'migrations'; sbomFile = 'sbom/migrations-container.spdx.json'; artifactFile = $migrationsArtifact; imageName = 'secure-integration-migrations'; imageReference = $migrationsReference; licenseExpression = 'MPL-2.0' })
    }
}

function Get-RelativeFilePath {
    param(
        [Parameter(Mandatory = $true)][string] $BaseDirectory,
        [Parameter(Mandatory = $true)][IO.FileInfo] $File,
        [Parameter(Mandatory = $true)][string] $FailureCode
    )
    $relative = $File.FullName.Substring($BaseDirectory.Length + 1).Replace('\', '/')
    if (-not (Test-ArchiveEntryPath -Path $relative)) { throw $FailureCode }
    return $relative
}

function Assert-AlphaReleaseSetBijection {
    param(
        [Parameter(Mandatory = $true)][string] $RunDirectory,
        [Parameter(Mandatory = $true)] $Manifest,
        [Parameter(Mandatory = $true)] $Profile
    )

    $expectedArtifacts = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    foreach ($definition in @($Profile.artifacts)) { $expectedArtifacts.Add([string]$definition.path, $definition) }
    $actualArtifacts = New-Object 'Collections.Generic.Dictionary[string,IO.FileInfo]' ([StringComparer]::Ordinal)
    $actualArtifactsIgnoreCase = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $artifactDirectory = Join-Path $RunDirectory 'artifacts'
    if (-not (Test-Path -LiteralPath $artifactDirectory -PathType Container)) { throw 'ALPHA_ARTIFACT_EXPECTED_FILE_MISSING' }
    foreach ($file in Get-ChildItem -LiteralPath $artifactDirectory -Recurse -File) {
        $relative = Get-RelativeFilePath -BaseDirectory $RunDirectory -File $file -FailureCode 'ALPHA_ARTIFACT_FILE_PATH_INVALID'
        if (-not $actualArtifactsIgnoreCase.Add($relative) -or $actualArtifacts.ContainsKey($relative)) { throw 'ALPHA_ARTIFACT_FILE_CASE_COLLISION' }
        if (-not $expectedArtifacts.ContainsKey($relative)) { throw "ALPHA_ARTIFACT_UNEXPECTED_FILE: $relative" }
        $actualArtifacts.Add($relative, $file)
    }
    foreach ($expected in $expectedArtifacts.Keys) {
        if (-not $actualArtifacts.ContainsKey($expected)) { throw "ALPHA_ARTIFACT_EXPECTED_FILE_MISSING: $expected" }
    }

    $manifestArtifacts = @(Get-ObjectArrayProperty -Object $Manifest -Name 'artifacts')
    $manifestArtifactByPath = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $manifestArtifactPathsIgnoreCase = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $manifestArtifacts) {
        $relative = [string](Get-RequiredPropertyValue -Object $entry -Name 'file' -FailureCode 'ALPHA_ARTIFACT_MANIFEST_ARTIFACT_SHAPE_INVALID')
        if (-not (Test-ArchiveEntryPath -Path $relative)) { throw 'ALPHA_ARTIFACT_MANIFEST_ARTIFACT_PATH_INVALID' }
        if (-not $manifestArtifactPathsIgnoreCase.Add($relative) -or $manifestArtifactByPath.ContainsKey($relative)) { throw 'ALPHA_ARTIFACT_MANIFEST_ARTIFACT_DUPLICATE' }
        if (-not $expectedArtifacts.ContainsKey($relative)) { throw "ALPHA_ARTIFACT_MANIFEST_ARTIFACT_UNEXPECTED: $relative" }
        $kind = [string](Get-RequiredPropertyValue -Object $entry -Name 'kind' -FailureCode 'ALPHA_ARTIFACT_MANIFEST_ARTIFACT_SHAPE_INVALID')
        if ($kind -cne [string]$expectedArtifacts[$relative].kind) { throw "ALPHA_ARTIFACT_MANIFEST_KIND_MISMATCH: $relative" }
        if ([string](Get-RequiredPropertyValue -Object $entry -Name 'licenseExpression' -FailureCode 'ALPHA_ARTIFACT_MANIFEST_ARTIFACT_SHAPE_INVALID') -cne [string]$expectedArtifacts[$relative].licenseExpression) {
            throw "ALPHA_ARTIFACT_MANIFEST_LICENSE_MISMATCH: $relative"
        }
        [void](Get-RequiredPropertyValue -Object $entry -Name 'bytes' -FailureCode 'ALPHA_ARTIFACT_MANIFEST_ARTIFACT_SHAPE_INVALID')
        [void](Get-RequiredPropertyValue -Object $entry -Name 'sha256' -FailureCode 'ALPHA_ARTIFACT_MANIFEST_ARTIFACT_SHAPE_INVALID')
        $manifestArtifactByPath.Add($relative, $entry)
    }
    foreach ($expected in $expectedArtifacts.Keys) {
        if (-not $manifestArtifactByPath.ContainsKey($expected)) { throw "ALPHA_ARTIFACT_MANIFEST_ARTIFACT_MISSING: $expected" }
    }

    $checksumPath = Join-Path $RunDirectory 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) { throw 'ALPHA_ARTIFACT_CHECKSUM_FILE_MISSING' }
    $checksumByPath = New-Object 'Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    $checksumPathsIgnoreCase = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in @(Get-Content -LiteralPath $checksumPath)) {
        if ($line -cnotmatch '^([0-9A-F]{64})  ([^\\]+)$') { throw 'ALPHA_ARTIFACT_CHECKSUM_FORMAT_INVALID' }
        $expectedHash = $Matches[1]
        $relative = $Matches[2]
        if (-not (Test-ArchiveEntryPath -Path $relative)) { throw 'ALPHA_ARTIFACT_CHECKSUM_PATH_INVALID' }
        if ($relative -ceq 'SHA256SUMS') { throw 'ALPHA_ARTIFACT_CHECKSUM_SELF_REFERENCE' }
        if (-not $checksumPathsIgnoreCase.Add($relative) -or $checksumByPath.ContainsKey($relative)) { throw 'ALPHA_ARTIFACT_CHECKSUM_DUPLICATE' }
        if (-not $expectedArtifacts.ContainsKey($relative)) { throw "ALPHA_ARTIFACT_CHECKSUM_UNEXPECTED: $relative" }
        $checksumByPath.Add($relative, $expectedHash)
    }
    foreach ($expected in $expectedArtifacts.Keys) {
        if (-not $checksumByPath.ContainsKey($expected)) { throw "ALPHA_ARTIFACT_CHECKSUM_MISSING: $expected" }
        $actualHash = Get-Sha256Hex -LiteralPath $actualArtifacts[$expected].FullName
        if ($actualHash -cne $checksumByPath[$expected]) { throw "ALPHA_ARTIFACT_CHECKSUM_MISMATCH: $expected" }
    }

    foreach ($expected in $expectedArtifacts.Keys) {
        $entry = $manifestArtifactByPath[$expected]
        try { $declaredBytes = [Convert]::ToInt64($entry.bytes, [Globalization.CultureInfo]::InvariantCulture) }
        catch { throw "ALPHA_ARTIFACT_MANIFEST_SIZE_INVALID: $expected" }
        $declaredSha256 = ([string]$entry.sha256).ToUpperInvariant()
        if ($declaredBytes -ne $actualArtifacts[$expected].Length -or $declaredSha256 -cne $checksumByPath[$expected]) {
            throw "ALPHA_ARTIFACT_MANIFEST_FILE_MISMATCH: $expected"
        }
    }

    $expectedSbomFiles = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($relative in @($Profile.sbomFiles)) { [void]$expectedSbomFiles.Add([string]$relative) }
    $actualSbomFiles = New-Object 'Collections.Generic.Dictionary[string,IO.FileInfo]' ([StringComparer]::Ordinal)
    $actualSbomPathsIgnoreCase = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $sbomDirectory = Join-Path $RunDirectory 'sbom'
    if (-not (Test-Path -LiteralPath $sbomDirectory -PathType Container)) { throw 'ALPHA_ARTIFACT_SBOM_FILE_MISSING' }
    foreach ($file in Get-ChildItem -LiteralPath $sbomDirectory -Recurse -File) {
        $relative = Get-RelativeFilePath -BaseDirectory $RunDirectory -File $file -FailureCode 'ALPHA_ARTIFACT_SBOM_PATH_INVALID'
        if (-not $actualSbomPathsIgnoreCase.Add($relative) -or $actualSbomFiles.ContainsKey($relative)) { throw 'ALPHA_ARTIFACT_SBOM_FILE_DUPLICATE' }
        if (-not $expectedSbomFiles.Contains($relative)) { throw "ALPHA_ARTIFACT_SBOM_FILE_UNEXPECTED: $relative" }
        $actualSbomFiles.Add($relative, $file)
    }
    foreach ($expected in $expectedSbomFiles) {
        if (-not $actualSbomFiles.ContainsKey($expected)) { throw "ALPHA_ARTIFACT_SBOM_FILE_MISSING: $expected" }
    }

    $manifestSboms = @(Get-ObjectArrayProperty -Object $Manifest -Name 'sbom')
    $manifestSbomByPath = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $manifestSbomPathsIgnoreCase = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $manifestSboms) {
        $relative = [string](Get-RequiredPropertyValue -Object $entry -Name 'file' -FailureCode 'ALPHA_ARTIFACT_SBOM_MANIFEST_SHAPE_INVALID')
        if (-not (Test-ArchiveEntryPath -Path $relative)) { throw 'ALPHA_ARTIFACT_SBOM_MANIFEST_PATH_INVALID' }
        if (-not $manifestSbomPathsIgnoreCase.Add($relative) -or $manifestSbomByPath.ContainsKey($relative)) { throw 'ALPHA_ARTIFACT_SBOM_MANIFEST_DUPLICATE' }
        if (-not $expectedSbomFiles.Contains($relative)) { throw "ALPHA_ARTIFACT_SBOM_MANIFEST_UNEXPECTED: $relative" }
        [void](Get-RequiredPropertyValue -Object $entry -Name 'bytes' -FailureCode 'ALPHA_ARTIFACT_SBOM_MANIFEST_SHAPE_INVALID')
        [void](Get-RequiredPropertyValue -Object $entry -Name 'sha256' -FailureCode 'ALPHA_ARTIFACT_SBOM_MANIFEST_SHAPE_INVALID')
        $manifestSbomByPath.Add($relative, $entry)
    }
    foreach ($expected in $expectedSbomFiles) {
        if (-not $manifestSbomByPath.ContainsKey($expected)) { throw "ALPHA_ARTIFACT_SBOM_MANIFEST_MISSING: $expected" }
        $entry = $manifestSbomByPath[$expected]
        $actualHash = Get-Sha256Hex -LiteralPath $actualSbomFiles[$expected].FullName
        try { $declaredBytes = [Convert]::ToInt64($entry.bytes, [Globalization.CultureInfo]::InvariantCulture) }
        catch { throw "ALPHA_ARTIFACT_SBOM_MANIFEST_SIZE_INVALID: $expected" }
        if ($declaredBytes -ne $actualSbomFiles[$expected].Length -or ([string]$entry.sha256).ToUpperInvariant() -cne $actualHash) {
            throw "ALPHA_ARTIFACT_SBOM_MANIFEST_FILE_MISMATCH: $expected"
        }
        $expectedSubjectLicense = if ($expected -ceq 'sbom/sdk-dotnet.spdx.json') { 'Apache-2.0' }
            elseif ($expected -ceq 'sbom/aggregate-manifest.json') { 'MPL-2.0 AND Apache-2.0' }
            else { 'MPL-2.0' }
        if ([string]$entry.subjectLicenseExpression -cne $expectedSubjectLicense) { throw "ALPHA_ARTIFACT_SBOM_MANIFEST_LICENSE_MISMATCH: $expected" }
        if ($expected -ceq 'sbom/aggregate-manifest.json' -and -not $ReleaseSetOnly -and -not $ContainerBindingOnly) {
            $aggregateSbom = Get-Content -LiteralPath $actualSbomFiles[$expected].FullName -Raw | ConvertFrom-Json
            if ([string]$aggregateSbom.aggregateLicenseExpression -cne 'MPL-2.0 AND Apache-2.0') { throw 'ALPHA_ARTIFACT_SBOM_AGGREGATE_LICENSE_MISMATCH' }
        }
        elseif ($expected -cne 'sbom/aggregate-manifest.json' -and -not $ReleaseSetOnly -and -not $ContainerBindingOnly) {
            $spdx = Get-Content -LiteralPath $actualSbomFiles[$expected].FullName -Raw | ConvertFrom-Json
            $spdxDescribedIds = @($spdx.relationships | Where-Object { [string]$_.relationshipType -ceq 'DESCRIBES' } | ForEach-Object { [string]$_.relatedSpdxElement })
            $spdxSubjects = @($spdx.packages | Where-Object { $spdxDescribedIds -ccontains [string]$_.SPDXID })
            if ($spdxSubjects.Count -eq 0 -or @($spdxSubjects | Where-Object { [string]$_.licenseDeclared -cne $expectedSubjectLicense -or [string]$_.licenseConcluded -cne $expectedSubjectLicense }).Count -ne 0) {
                throw "ALPHA_ARTIFACT_SBOM_SUBJECT_LICENSE_MISMATCH: $expected"
            }
        }
    }

    $expectedSubjectsByRole = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    foreach ($subject in @($Profile.sbomSubjects)) { $expectedSubjectsByRole.Add([string]$subject.role, $subject) }
    $imagesByRole = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $imageRolesIgnoreCase = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($image in @(Get-ObjectArrayProperty -Object $Manifest -Name 'images')) {
        $role = [string](Get-RequiredPropertyValue -Object $image -Name 'role' -FailureCode 'ALPHA_ARTIFACT_IMAGE_MANIFEST_INVALID')
        if (-not $imageRolesIgnoreCase.Add($role) -or $imagesByRole.ContainsKey($role)) { throw 'ALPHA_ARTIFACT_IMAGE_MANIFEST_DUPLICATE' }
        if (-not $expectedSubjectsByRole.ContainsKey($role)) { throw "ALPHA_ARTIFACT_IMAGE_MANIFEST_UNEXPECTED: $role" }
        $expectedSubject = $expectedSubjectsByRole[$role]
        $reference = [string](Get-RequiredPropertyValue -Object $image -Name 'reference' -FailureCode 'ALPHA_ARTIFACT_IMAGE_MANIFEST_INVALID')
        $imageId = [string](Get-RequiredPropertyValue -Object $image -Name 'imageId' -FailureCode 'ALPHA_ARTIFACT_IMAGE_MANIFEST_INVALID')
        if ($reference -cne [string]$expectedSubject.imageReference -or $imageId -cnotmatch '^sha256:[0-9a-f]{64}$') { throw "ALPHA_ARTIFACT_IMAGE_MANIFEST_MISMATCH: $role" }
        if ([string]$image.versionLabel -cne '0.1.0-alpha.1' -or [string]$image.revisionLabel -cne [string]$Manifest.sourceRevision) { throw "ALPHA_ARTIFACT_IMAGE_MANIFEST_MISMATCH: $role" }
        $expectedTitle = if ($role -ceq 'gateway') { 'Secure Integration Platform Gateway' } else { 'Secure Integration Platform Migrations' }
        if ([string]$image.sourceLabel -cne 'https://github.com/marcobiz/secure-integration-platform' -or
            [string]$image.vendorLabel -cne 'ApoCert S.r.l.' -or [string]$image.titleLabel -cne $expectedTitle -or
            [string]$image.licenseLabel -cne 'MPL-2.0') { throw "ALPHA_ARTIFACT_IMAGE_LICENSE_MISMATCH: $role" }
        $imagesByRole.Add($role, $image)
    }
    foreach ($role in $expectedSubjectsByRole.Keys) {
        if (-not $imagesByRole.ContainsKey($role)) { throw "ALPHA_ARTIFACT_IMAGE_MANIFEST_MISSING: $role" }
    }

    $associationsByRole = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $associationRolesIgnoreCase = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($association in @(Get-ObjectArrayProperty -Object $Manifest -Name 'sbomSubjects')) {
        $role = [string](Get-RequiredPropertyValue -Object $association -Name 'role' -FailureCode 'ALPHA_ARTIFACT_SBOM_ASSOCIATION_SHAPE_INVALID')
        if (-not $associationRolesIgnoreCase.Add($role) -or $associationsByRole.ContainsKey($role)) { throw 'ALPHA_ARTIFACT_SBOM_ASSOCIATION_DUPLICATE' }
        if (-not $expectedSubjectsByRole.ContainsKey($role)) { throw "ALPHA_ARTIFACT_SBOM_ASSOCIATION_UNEXPECTED: $role" }
        $expectedSubject = $expectedSubjectsByRole[$role]
        $image = $imagesByRole[$role]
        if ([string]$association.sbomFile -cne [string]$expectedSubject.sbomFile -or
            [string]$association.artifactFile -cne [string]$expectedSubject.artifactFile -or
            [string]$association.imageReference -cne [string]$expectedSubject.imageReference -or
            [string]$association.imageId -cne [string]$image.imageId -or
            [string]$association.licenseExpression -cne [string]$expectedSubject.licenseExpression) {
            throw "ALPHA_ARTIFACT_SBOM_ASSOCIATION_MISMATCH: $role"
        }
        $associationsByRole.Add($role, $association)
    }
    foreach ($role in $expectedSubjectsByRole.Keys) {
        if (-not $associationsByRole.ContainsKey($role)) { throw "ALPHA_ARTIFACT_SBOM_ASSOCIATION_MISSING: $role" }
    }

    foreach ($role in $expectedSubjectsByRole.Keys) {
        $expectedSubject = $expectedSubjectsByRole[$role]
        try { $document = Get-Content -LiteralPath $actualSbomFiles[[string]$expectedSubject.sbomFile].FullName -Raw | ConvertFrom-Json }
        catch { throw "ALPHA_ARTIFACT_SBOM_SUBJECT_INVALID: $role" }
        if ([string]$document.spdxVersion -cne 'SPDX-2.3' -or [string]$document.SPDXID -cne 'SPDXRef-DOCUMENT') { throw "ALPHA_ARTIFACT_SBOM_SUBJECT_INVALID: $role" }
        $describedIds = @($document.relationships | Where-Object { [string]$_.spdxElementId -ceq 'SPDXRef-DOCUMENT' -and [string]$_.relationshipType -ceq 'DESCRIBES' } | ForEach-Object { [string]$_.relatedSpdxElement })
        if ($describedIds.Count -ne 1) { throw "ALPHA_ARTIFACT_SBOM_SUBJECT_INVALID: $role" }
        $subjectPackages = @($document.packages | Where-Object { [string]$_.SPDXID -ceq $describedIds[0] })
        if ($subjectPackages.Count -ne 1 -or [string]$subjectPackages[0].name -cne [string]$expectedSubject.imageName -or
            [string]$subjectPackages[0].licenseDeclared -cne [string]$expectedSubject.licenseExpression -or
            [string]$subjectPackages[0].licenseConcluded -cne [string]$expectedSubject.licenseExpression) { throw "ALPHA_ARTIFACT_SBOM_SUBJECT_MISMATCH: $role" }
        $purls = @($subjectPackages[0].externalRefs | Where-Object { [string]$_.referenceCategory -ceq 'PACKAGE-MANAGER' -and [string]$_.referenceType -ceq 'purl' -and [string]$_.referenceLocator -clike 'pkg:oci/*' } | ForEach-Object { [string]$_.referenceLocator })
        if ($purls.Count -ne 1) { throw "ALPHA_ARTIFACT_SBOM_SUBJECT_INVALID: $role" }
        $imageId = [string]$imagesByRole[$role].imageId
        $digest = $imageId.Substring('sha256:'.Length)
        $reference = [string]$expectedSubject.imageReference
        $tag = $reference.Substring($reference.IndexOf(':') + 1)
        if ($purls[0] -cnotmatch ('^pkg:oci/' + [regex]::Escape([string]$expectedSubject.imageName) + '@sha256:' + $digest + '(?:\?|$)') -or
            $purls[0] -cnotmatch ('(?:[?&])tag=' + [regex]::Escape($tag) + '(?:&|$)')) {
            throw "ALPHA_ARTIFACT_SBOM_SUBJECT_MISMATCH: $role"
        }
    }

    return [pscustomobject]@{
        expectedArtifactCount = $expectedArtifacts.Count
        actualArtifactCount = $actualArtifacts.Count
        expectedSbomSubjectCount = $expectedSubjectsByRole.Count
        actualSbomSubjectCount = $associationsByRole.Count
    }
}

function Assert-NoLocalPathOrSecretText([string] $Text) {
    foreach ($pattern in @(
        '(?i)[A-Z]:\\(?:Users|Codice|SecureEvidence|Lab)\\',
        '(?i)/home/[^/\s]+/',
        '-----BEGIN (?:RSA |EC |)PRIVATE KEY-----',
        '(?i)authorization\s*:\s*(?:bearer|basic)\s+\S+',
        '(?i)(?:client_secret|password|token)\s*[=:]\s*["''][^"'']{8,}')) {
        if ([regex]::IsMatch($Text, $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
            throw 'ALPHA_ARTIFACT_SENSITIVE_OR_LOCAL_TEXT_FOUND'
        }
    }
}

function Test-ByteSequence([byte[]] $Bytes, [byte[]] $Needle) {
    if ($Needle.Length -eq 0 -or $Needle.Length -gt $Bytes.Length) { return $false }
    for ($offset = 0; $offset -le $Bytes.Length - $Needle.Length; $offset++) {
        $matches = $true
        for ($index = 0; $index -lt $Needle.Length; $index++) {
            if ($Bytes[$offset + $index] -ne $Needle[$index]) { $matches = $false; break }
        }
        if ($matches) { return $true }
    }
    return $false
}

function Read-Manifest([string] $Directory) {
    $path = Join-Path $Directory 'manifest.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'ALPHA_ARTIFACT_MANIFEST_MISSING' }
    return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
}

function Get-ReleaseInventory([string] $Directory) {
    $paths = @(
        Get-ChildItem -LiteralPath (Join-Path $Directory 'artifacts') -File | ForEach-Object { 'artifacts/' + $_.Name }
        Get-ChildItem -LiteralPath (Join-Path $Directory 'sbom') -File | ForEach-Object { 'sbom/' + $_.Name })
    [string[]]$sorted = @($paths)
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    return $sorted
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
    if ($exitCode -ne 0) { throw 'ALPHA_ARTIFACT_IMAGE_LOOKUP_FAILED' }
    if ($ids.Count -gt 1) { throw 'ALPHA_ARTIFACT_IMAGE_LOOKUP_AMBIGUOUS' }
    return $(if ($ids.Count -eq 1) { $ids[0] } else { '' })
}

function Assert-CandidateImageTagsAbsent {
    param([Parameter(Mandatory = $true)][string[]] $References)
    foreach ($reference in $References) {
        if (-not [string]::IsNullOrWhiteSpace((Get-DockerImageIdByReference -Reference $reference))) {
            throw "ALPHA_ART_CANDIDATE_IMAGE_TAG_PREEXISTING: $reference"
        }
    }
}

function Invoke-ContainerArtifactBindingValidation {
    param(
        [Parameter(Mandatory = $true)][string] $RunDirectory,
        [Parameter(Mandatory = $true)] $Manifest,
        [Parameter(Mandatory = $true)] $Profile,
        [Parameter(Mandatory = $true)][string] $InspectionRoot,
        [Parameter(Mandatory = $true)][hashtable] $OwnedReferences
    )

    $imagesByRole = @{}
    foreach ($image in @($Manifest.images)) { $imagesByRole[[string]$image.role] = $image }
    $associationsByRole = @{}
    foreach ($association in @($Manifest.sbomSubjects)) { $associationsByRole[[string]$association.role] = $association }
    $artifactRecordsByPath = @{}
    foreach ($artifact in @($Manifest.artifacts)) { $artifactRecordsByPath[[string]$artifact.file] = $artifact }
    $subjectsByRole = @{}
    foreach ($subject in @($Profile.sbomSubjects)) { $subjectsByRole[[string]$subject.role] = $subject }
    $roles = @('gateway', 'migrations')
    $references = @($roles | ForEach-Object { [string]$subjectsByRole[$_].imageReference })

    Assert-CandidateImageTagsAbsent -References $references
    $identitiesByRole = @{}
    foreach ($role in $roles) {
        $subject = $subjectsByRole[$role]
        $archivePath = Join-Path $RunDirectory ([string]$subject.artifactFile).Replace('/', [IO.Path]::DirectorySeparatorChar)
        $identity = Get-AlphaReleaseContainerTarIdentity -ArchivePath $archivePath -Role $role `
            -ExpectedReference ([string]$subject.imageReference) -ProductVersion ([string]$Manifest.version) `
            -SourceCommit ([string]$Manifest.sourceRevision) -InspectionDirectory (Join-Path $InspectionRoot $role)
        $image = $imagesByRole[$role]
        $association = $associationsByRole[$role]
        $artifact = $artifactRecordsByPath[[string]$subject.artifactFile]
        $declaredImageId = [string]$image.imageId
        $boundImageIds = @($identity.boundImageIds | ForEach-Object { [string]$_ })
        if ($null -eq $image -or $null -eq $association -or $null -eq $artifact -or
            [string]$identity.artifactSha256 -cne ([string]$artifact.sha256).ToUpperInvariant() -or
            [string]$identity.repoTag -cne [string]$image.reference -or
            $boundImageIds.Count -eq 0 -or $boundImageIds -cnotcontains $declaredImageId -or
            [string]$identity.repoTag -cne [string]$association.imageReference -or
            $declaredImageId -cne [string]$association.imageId -or
            [string]$subject.artifactFile -cne [string]$association.artifactFile) {
            throw "ALPHA_ARTIFACT_TAR_SUBJECT_IDENTITY_MISMATCH: $role"
        }
        $identity.imageId = $declaredImageId
        $identitiesByRole[$role] = $identity
    }

    foreach ($role in $roles) {
        $identity = $identitiesByRole[$role]
        $oppositeRole = if ($role -ceq 'gateway') { 'migrations' } else { 'gateway' }
        $oppositeReference = [string]$identitiesByRole[$oppositeRole].repoTag
        $expectedBefore = Get-DockerImageIdByReference -Reference ([string]$identity.repoTag)
        $oppositeBefore = Get-DockerImageIdByReference -Reference $oppositeReference
        if (-not [string]::IsNullOrWhiteSpace($expectedBefore)) { throw "ALPHA_ART_CANDIDATE_IMAGE_TAG_PREEXISTING: $([string]$identity.repoTag)" }
        if ($role -ceq 'gateway' -and -not [string]::IsNullOrWhiteSpace($oppositeBefore)) {
            throw "ALPHA_ART_CANDIDATE_IMAGE_TAG_PREEXISTING: $oppositeReference"
        }
        $archivePath = Join-Path $RunDirectory ([string]$subjectsByRole[$role].artifactFile).Replace('/', [IO.Path]::DirectorySeparatorChar)
        & docker image load --input $archivePath *> $null
        if ($LASTEXITCODE -ne 0) { throw "ALPHA_ARTIFACT_IMAGE_LOAD_FAILED: $role" }
        $loadedImageId = Get-DockerImageIdByReference -Reference ([string]$identity.repoTag)
        if ($loadedImageId -ceq [string]$identity.imageId) { $OwnedReferences[[string]$identity.repoTag] = [string]$identity.imageId }
        if ($loadedImageId -cne [string]$identity.imageId) { throw "ALPHA_ARTIFACT_TAR_IMAGE_ID_MISMATCH: $role" }
        $oppositeAfter = Get-DockerImageIdByReference -Reference $oppositeReference
        if ($oppositeAfter -cne $oppositeBefore) { throw "ALPHA_ARTIFACT_TAR_OPPOSITE_TAG_MUTATED: $role" }
    }

    return @($roles | ForEach-Object { $identitiesByRole[$_] })
}

$ownedImageReferences = @{}
try {
    $manifest = Read-Manifest -Directory $run
    $productVersion = [string]$manifest.version
    $sourceCommit = [string]$manifest.sourceRevision
    if ($productVersion -cne '0.1.0-alpha.1') { throw 'ALPHA_ARTIFACT_PRODUCT_VERSION_MISMATCH' }
    if ($sourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'ALPHA_ARTIFACT_SOURCE_REVISION_INVALID' }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSourceCommit) -and $sourceCommit -cne $ExpectedSourceCommit) { throw 'ALPHA_ARTIFACT_SOURCE_REVISION_MISMATCH' }
    if ($manifest.claims.publicReleaseGo -ne $false -or $manifest.claims.productionReady -ne $false) { throw 'ALPHA_ARTIFACT_RELEASE_CLAIM_INVALID' }
    if ([string]$manifest.releaseChannel -cne 'public-technical-preview' -or [string]$manifest.releaseClass -cne 'PUBLIC TECHNICAL PREVIEW' -or
        [string]$manifest.distributionTarget -cne 'GitHub public prerelease v0.1.0-alpha.1' -or
        [string]$manifest.licensePolicy.default -cne 'MPL-2.0' -or [string]$manifest.licensePolicy.sdk -cne 'Apache-2.0' -or
        [string]$manifest.licensePolicy.genericReference -cne 'MPL-2.0 OR Apache-2.0' -or
        [string]$manifest.licensePolicy.coreSourceArchive -cne 'MPL-2.0 AND Apache-2.0') { throw 'ALPHA_ARTIFACT_RELEASE_LICENSE_POLICY_INVALID' }
    if ([string]$manifest.versionIdentity.protocolVersion -cne '1.0' -or [string]$manifest.versionIdentity.canonicalConnectorVersion -cne '1.0.0' -or
        [string]$manifest.versionIdentity.openApiVersion -cne $productVersion -or [string]$manifest.versionIdentity.imageRevision -cne $sourceCommit) {
        throw 'ALPHA_ARTIFACT_VERSION_IDENTITY_INVALID'
    }

    $manifestPath = Join-Path $run 'manifest.json'
    $manifestSha256 = Get-Sha256Hex -LiteralPath $manifestPath
    if ((Get-Content -LiteralPath (Join-Path $run 'manifest.json.sha256') -Raw).Trim() -cne "$manifestSha256  manifest.json") {
        throw 'ALPHA_ARTIFACT_MANIFEST_SIDECAR_MISMATCH'
    }

    $profile = Get-AlphaReleaseProfile -ProductVersion $productVersion -SourceCommit $sourceCommit
    $releaseSetValidation = Assert-AlphaReleaseSetBijection -RunDirectory $run -Manifest $manifest -Profile $profile
    if ($ReleaseSetOnly) {
        [pscustomobject]@{
            status = 'PASS'
            productVersion = $productVersion
            sourceRevision = $sourceCommit
            artifactFileSetBijection = 'PASS'
            manifestBijection = 'PASS'
            sha256SumsBijection = 'PASS'
            sbomSubjectBijection = 'PASS'
            expectedArtifactCount = $releaseSetValidation.expectedArtifactCount
            actualArtifactCount = $releaseSetValidation.actualArtifactCount
            expectedSbomSubjectCount = $releaseSetValidation.expectedSbomSubjectCount
            actualSbomSubjectCount = $releaseSetValidation.actualSbomSubjectCount
            normalizedInventorySha256 = [string]$manifest.coreExport.normalizedInventorySha256
        } | ConvertTo-Json -Compress
        return
    }

    if (-not $ContainerBindingOnly) {
    $artifactFiles = @(Get-ChildItem -LiteralPath (Join-Path $run 'artifacts') -File)
    foreach ($file in $artifactFiles) {
        if ($file.Name -match '(?i)(healthcare|fse2|azure|deployment|evidence|secret|\.env|\.p12|\.pfx|\.pem|\.key)') { throw 'ALPHA_ARTIFACT_FORBIDDEN_FILE_NAME' }
    }

    $package = @(Get-ChildItem -LiteralPath (Join-Path $run 'artifacts') -File -Filter '*.nupkg')
    if ($package.Count -ne 1 -or $package[0].Name -cne "SecureIntegration.Broker.Sdk.$productVersion.nupkg") { throw 'ALPHA_ARTIFACT_NUGET_INVENTORY_INVALID' }
    [string[]]$packageEntries = @(Get-ZipEntries -ArchivePath $package[0].FullName)
    foreach ($entry in $packageEntries) {
        if (-not (Test-ArchiveEntryPath -Path $entry) -or $entry -cnotmatch '^(?:_rels/\.rels|\[Content_Types\]\.xml|SecureIntegration\.Broker\.Sdk\.nuspec|LICENSE-APACHE-2\.0|NOTICE|package/services/metadata/core-properties/[0-9a-f-]+\.psmdcp|lib/(?:net10\.0|netstandard2\.0)/SecureIntegration\.(?:Broker\.Sdk|Contracts)\.(?:dll|xml))$') {
            throw "ALPHA_ARTIFACT_NUGET_CONTENT_NOT_ALLOWLISTED: $entry"
        }
    }
    $packageExtract = Join-Path $testRoot 'package'
    [IO.Compression.ZipFile]::ExtractToDirectory($package[0].FullName, $packageExtract)
    [xml]$nuspec = Get-Content -LiteralPath (Join-Path $packageExtract 'SecureIntegration.Broker.Sdk.nuspec') -Raw
    if ([string]$nuspec.package.metadata.version -cne $productVersion) { throw 'ALPHA_ARTIFACT_NUGET_VERSION_MISMATCH' }
    if ([string]$nuspec.package.metadata.license.type -cne 'expression' -or [string]$nuspec.package.metadata.license.'#text' -cne 'Apache-2.0') { throw 'ALPHA_ARTIFACT_NUGET_LICENSE_MISMATCH' }
    if ((Get-Sha256Hex -LiteralPath (Join-Path $packageExtract 'LICENSE-APACHE-2.0')) -cne 'CFC7749B96F63BD31C3C42B5C471BF756814053E847C10F3EB003417BC523D30' -or
        -not (Test-Path -LiteralPath (Join-Path $packageExtract 'NOTICE') -PathType Leaf)) { throw 'ALPHA_ARTIFACT_NUGET_LICENSE_CONTENT_INVALID' }
    [byte[]]$rootBytes = [Text.Encoding]::UTF8.GetBytes($root)
    try {
        foreach ($assembly in Get-ChildItem -LiteralPath (Join-Path $packageExtract 'lib') -Recurse -File -Filter '*.dll') {
            [byte[]]$assemblyBytes = [IO.File]::ReadAllBytes($assembly.FullName)
            try { if (Test-ByteSequence -Bytes $assemblyBytes -Needle $rootBytes) { throw 'ALPHA_ARTIFACT_LOCAL_BUILD_PATH_FOUND' } }
            finally { [Array]::Clear($assemblyBytes, 0, $assemblyBytes.Length) }
        }
    }
    finally { [Array]::Clear($rootBytes, 0, $rootBytes.Length) }

    $coreArchive = @(Get-ChildItem -LiteralPath (Join-Path $run 'artifacts') -File -Filter '*-source.zip')
    if ($coreArchive.Count -ne 1) { throw 'ALPHA_ARTIFACT_CORE_ARCHIVE_INVENTORY_INVALID' }
    $coreEntries = @(Get-ZipEntries -ArchivePath $coreArchive[0].FullName)
    foreach ($entry in $coreEntries) {
        if (-not (Test-ArchiveEntryPath -Path $entry) -or $entry -match '(^|/)(?:packs|\.artifacts|bin|obj|node_modules)(/|$)' -or
            $entry -match '(?i)(healthcare|fse2|raw-evidence|evidence-raw|\.p12$|\.pfx$|\.pem$|\.key$)') { throw "ALPHA_ARTIFACT_CORE_BOUNDARY_FAILED: $entry" }
    }
    $coreExtract = Join-Path $testRoot 'core'
    [IO.Compression.ZipFile]::ExtractToDirectory($coreArchive[0].FullName, $coreExtract)
    if ((Get-Sha256Hex -LiteralPath (Join-Path $coreExtract 'LICENSE')) -cne '3F3D9E0024B1921B067D6F7F88DEB4A60CBE7A78E76C64E3F1D7FC3B779B9D04' -or
        (Get-Sha256Hex -LiteralPath (Join-Path $coreExtract 'LICENSE-APACHE-2.0')) -cne 'CFC7749B96F63BD31C3C42B5C471BF756814053E847C10F3EB003417BC523D30' -or
        -not (Test-Path -LiteralPath (Join-Path $coreExtract 'LICENSING.md') -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $coreExtract 'NOTICE') -PathType Leaf)) { throw 'ALPHA_ARTIFACT_CORE_LICENSE_CONTENT_INVALID' }
    & (Join-Path $coreExtract 'eng\Test-OpenSourceCoreInventory.ps1') -ExportDirectory $coreExtract -ExpectedSourceCommit $sourceCommit *> $null
    & (Join-Path $coreExtract 'eng\scan-secrets.ps1') *> $null
    $coreManifest = Get-Content -LiteralPath (Join-Path $coreExtract 'OPEN_SOURCE_EXPORT_MANIFEST.json') -Raw | ConvertFrom-Json
    if ([int]$coreManifest.fileCount -ne [int]$manifest.coreExport.fileCount -or
        [string]$coreManifest.normalizedInventorySha256 -cne [string]$manifest.coreExport.normalizedInventorySha256 -or
        (Get-Sha256Hex -LiteralPath (Join-Path $coreExtract 'OPEN_SOURCE_EXPORT_MANIFEST.json')) -cne [string]$manifest.coreExport.rawManifestSha256RunSpecific) {
        throw 'ALPHA_ARTIFACT_CORE_MANIFEST_MISMATCH'
    }

    $adminArchive = @(Get-ChildItem -LiteralPath (Join-Path $run 'artifacts') -File -Filter 'admin-web-*.zip')
    if ($adminArchive.Count -ne 1) { throw 'ALPHA_ARTIFACT_ADMIN_ARCHIVE_INVENTORY_INVALID' }
    foreach ($entry in Get-ZipEntries -ArchivePath $adminArchive[0].FullName) {
        if (-not (Test-ArchiveEntryPath -Path $entry) -or $entry.EndsWith('.map', [StringComparison]::OrdinalIgnoreCase) -or
            $entry -match '(?i)(\.env|evidence|secret|\.p12$|\.pfx$|\.pem$|\.key$)') { throw "ALPHA_ARTIFACT_ADMIN_CONTENT_INVALID: $entry" }
    }
    $adminExtract = Join-Path $testRoot 'admin'
    [IO.Compression.ZipFile]::ExtractToDirectory($adminArchive[0].FullName, $adminExtract)
    if ((Get-Sha256Hex -LiteralPath (Join-Path $adminExtract 'LICENSE')) -cne '3F3D9E0024B1921B067D6F7F88DEB4A60CBE7A78E76C64E3F1D7FC3B779B9D04' -or
        -not (Test-Path -LiteralPath (Join-Path $adminExtract 'NOTICE') -PathType Leaf)) { throw 'ALPHA_ARTIFACT_ADMIN_LICENSE_CONTENT_INVALID' }
    foreach ($textFile in Get-ChildItem -LiteralPath $adminExtract -Recurse -File | Where-Object { $_.Extension -in '.html', '.js', '.css', '.json', '.svg' }) {
        Assert-NoLocalPathOrSecretText -Text (Get-Content -LiteralPath $textFile.FullName -Raw)
    }
    }

    $gatewayImage = @($manifest.images | Where-Object { [string]$_.role -ceq 'gateway' })
    $migrationsImage = @($manifest.images | Where-Object { [string]$_.role -ceq 'migrations' })
    if ($gatewayImage.Count -ne 1 -or $migrationsImage.Count -ne 1) { throw 'ALPHA_ARTIFACT_IMAGE_MANIFEST_INVALID' }
    $gatewayTar = @(Get-ChildItem -LiteralPath (Join-Path $run 'artifacts') -File -Filter 'gateway-image-*.tar')
    $migrationsTar = @(Get-ChildItem -LiteralPath (Join-Path $run 'artifacts') -File -Filter 'migrations-image-*.tar')
    if ($gatewayTar.Count -ne 1 -or $migrationsTar.Count -ne 1) { throw 'ALPHA_ARTIFACT_IMAGE_ARCHIVE_INVENTORY_INVALID' }
    $containerTarIdentities = Invoke-ContainerArtifactBindingValidation -RunDirectory $run -Manifest $manifest -Profile $profile `
        -InspectionRoot (Join-Path $testRoot 'container-tar-inspection') -OwnedReferences $ownedImageReferences
    foreach ($image in @($gatewayImage[0], $migrationsImage[0])) {
        $inspect = @(& docker image inspect ([string]$image.reference) | ConvertFrom-Json)[0]
        $imageUser = [string]$inspect.Config.User
        if ($LASTEXITCODE -ne 0 -or [string]$inspect.Config.Labels.'org.opencontainers.image.version' -cne $productVersion -or
            [string]$inspect.Config.Labels.'org.opencontainers.image.revision' -cne $sourceCommit -or
            [string]$inspect.Config.Labels.'org.opencontainers.image.source' -cne 'https://github.com/marcobiz/secure-integration-platform' -or
            [string]$inspect.Config.Labels.'org.opencontainers.image.vendor' -cne 'ApoCert S.r.l.' -or
            [string]$inspect.Config.Labels.'org.opencontainers.image.licenses' -cne 'MPL-2.0' -or
            [string]$inspect.Id -cne [string]$image.imageId -or [string]::IsNullOrWhiteSpace($imageUser) -or
            $imageUser -in @('0', 'root')) { throw 'ALPHA_ARTIFACT_IMAGE_METADATA_INVALID' }
        $history = (& docker image history --no-trunc --format '{{.CreatedBy}}' ([string]$image.reference) | Out-String)
        if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_IMAGE_HISTORY_FAILED' }
        Assert-NoLocalPathOrSecretText -Text $history
    }
    $gatewayInspect = @(& docker image inspect ([string]$gatewayImage[0].reference) | ConvertFrom-Json)[0]
    if ($null -eq $gatewayInspect.Config.Healthcheck -or @($gatewayInspect.Config.Healthcheck.Test).Count -eq 0) { throw 'ALPHA_ARTIFACT_GATEWAY_HEALTHCHECK_MISSING' }

    if ($ContainerBindingOnly) {
        [pscustomobject]@{
            status = 'PASS'
            productVersion = $productVersion
            sourceRevision = $sourceCommit
            normalizedInventorySha256 = [string]$manifest.coreExport.normalizedInventorySha256
            containerTarIdentity = 'PASS'
            candidateTagPrecondition = 'PASS'
            tarImageIdMatch = 'PASS'
            releaseSubjectImageIdMatch = 'PASS'
            sbomSubjectImageIdMatch = 'PASS'
            identities = @($containerTarIdentities)
        } | ConvertTo-Json -Depth 8 -Compress
        return
    }

    foreach ($file in Get-ChildItem -LiteralPath $run -Recurse -File | Where-Object { $_.Extension -in '.json', '.sha256', '.spdx', '.txt' -or $_.Name -eq 'SHA256SUMS' }) {
        Assert-NoLocalPathOrSecretText -Text (Get-Content -LiteralPath $file.FullName -Raw)
    }

    if (-not [string]::IsNullOrWhiteSpace($SecondRunDirectory)) {
        $second = [IO.Path]::GetFullPath($SecondRunDirectory)
        $secondManifest = Read-Manifest -Directory $second
        if ([string]$secondManifest.sourceRevision -cne $sourceCommit -or [string]$secondManifest.coreExport.normalizedInventorySha256 -cne [string]$manifest.coreExport.normalizedInventorySha256) {
            throw 'ALPHA_ARTIFACT_SECOND_RUN_DIGEST_MISMATCH'
        }
        [string[]]$firstInventory = @(Get-ReleaseInventory -Directory $run)
        [string[]]$secondInventory = @(Get-ReleaseInventory -Directory $second)
        if ($firstInventory.Count -ne $secondInventory.Count) { throw 'ALPHA_ARTIFACT_SECOND_RUN_INVENTORY_MISMATCH' }
        for ($index = 0; $index -lt $firstInventory.Count; $index++) {
            if ($firstInventory[$index] -cne $secondInventory[$index]) { throw 'ALPHA_ARTIFACT_SECOND_RUN_INVENTORY_MISMATCH' }
        }
    }

    if ($RunConsumerInstall) {
        $consumer = Join-Path $testRoot 'consumer'
        New-Item -ItemType Directory -Path $consumer | Out-Null
        $project = @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><TreatWarningsAsErrors>true</TreatWarningsAsErrors></PropertyGroup>
  <ItemGroup><PackageReference Include="SecureIntegration.Broker.Sdk" Version="$productVersion" /></ItemGroup>
</Project>
"@
        $program = @"
using System;
using System.Reflection;
using SecureIntegration.Broker.Sdk;
Assembly assembly = typeof(AssemblyMarker).Assembly;
string informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "";
if (assembly.GetName().Version?.ToString() != "0.1.0.0" || informational != "$productVersion") return 2;
Console.WriteLine("ALPHA_CLEAN_CONSUMER_INSTALL_PASS");
return 0;
"@
        [IO.File]::WriteAllText((Join-Path $consumer 'Consumer.csproj'), $project.Trim(), [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $consumer 'Program.cs'), $program.Trim(), [Text.UTF8Encoding]::new($false))
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & $dotnet restore (Join-Path $consumer 'Consumer.csproj') --source (Join-Path $run 'artifacts') --source 'https://api.nuget.org/v3/index.json' *> $null
            $restoreExitCode = $LASTEXITCODE
            $runExitCode = -1
            if ($restoreExitCode -eq 0) {
                & $dotnet run --project (Join-Path $consumer 'Consumer.csproj') --configuration Release --no-restore *> $null
                $runExitCode = $LASTEXITCODE
            }
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        if ($restoreExitCode -ne 0) { throw 'ALPHA_ARTIFACT_CONSUMER_RESTORE_FAILED' }
        if ($runExitCode -ne 0) { throw 'ALPHA_ARTIFACT_CONSUMER_RUN_FAILED' }
    }

    if ($RunContainerRuntime) {
        $containerName = 'alpha-artifact-runtime-' + [Guid]::NewGuid().ToString('N')
        $containerLabel = 'secure-integration.alpha-artifact-validation=' + $sourceCommit
        try {
            $containerId = (& docker run --detach --name $containerName --label $containerLabel --read-only --tmpfs /tmp --env ASPNETCORE_ENVIRONMENT=Testing --env Gateway__Admin__Mode=DevelopmentAuth --env ASPNETCORE_URLS=http://+:8080 ([string]$gatewayImage[0].reference)).Trim()
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerId)) { throw 'ALPHA_ARTIFACT_CONTAINER_START_FAILED' }
            $deadline = [DateTimeOffset]::UtcNow.AddMinutes(2)
            $healthy = $false
            do {
                $state = (& docker inspect $containerName --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}').Trim()
                if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_CONTAINER_INSPECT_FAILED' }
                if ($state -ceq 'healthy') { $healthy = $true; break }
                if ($state -in @('exited', 'dead')) { break }
                Start-Sleep -Seconds 2
            } while ([DateTimeOffset]::UtcNow -lt $deadline)
            if (-not $healthy) { throw 'ALPHA_ARTIFACT_CONTAINER_HEALTH_FAILED' }
        }
        finally {
            $containerIdForCleanup = (& docker ps --all --quiet --filter "name=^/$containerName$" | Out-String).Trim()
            if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_CONTAINER_CLEANUP_LOOKUP_FAILED' }
            if (-not [string]::IsNullOrWhiteSpace($containerIdForCleanup)) {
                $inspectText = (& docker inspect $containerIdForCleanup | Out-String)
                if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_CONTAINER_CLEANUP_INSPECT_FAILED' }
                $containerInspect = @($inspectText | ConvertFrom-Json)[0]
                $owned = [string]$containerInspect.Config.Labels.'secure-integration.alpha-artifact-validation'
                if ($owned -cne $sourceCommit) { throw 'ALPHA_ARTIFACT_CONTAINER_CLEANUP_OWNERSHIP_FAILED' }
                & docker rm --force $containerIdForCleanup *> $null
                if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_CONTAINER_CLEANUP_FAILED' }
            }
        }
    }

    [pscustomobject]@{
        status = 'PASS'
        productVersion = $productVersion
        sourceRevision = $sourceCommit
        sha256Sums = 'PASS'
        artifactFileSetBijection = 'PASS'
        manifestBijection = 'PASS'
        sha256SumsBijection = 'PASS'
        sbomSubjectBijection = 'PASS'
        expectedArtifactCount = $releaseSetValidation.expectedArtifactCount
        actualArtifactCount = $releaseSetValidation.actualArtifactCount
        expectedSbomSubjectCount = $releaseSetValidation.expectedSbomSubjectCount
        actualSbomSubjectCount = $releaseSetValidation.actualSbomSubjectCount
        packageContentAllowlist = 'PASS'
        corePackBoundary = 'PASS'
        artifactSecretScan = 'PASS'
        cleanConsumerInstall = $(if ($RunConsumerInstall) { 'PASS' } else { 'NOT_RUN' })
        containerRuntime = $(if ($RunContainerRuntime) { 'PASS' } else { 'NOT_RUN' })
        normalizedInventorySha256 = [string]$manifest.coreExport.normalizedInventorySha256
        secondRunStable = $(if ([string]::IsNullOrWhiteSpace($SecondRunDirectory)) { 'NOT_RUN' } else { 'PASS' })
    } | ConvertTo-Json -Compress
}
finally {
    foreach ($reference in @($ownedImageReferences.Keys)) {
        $currentImageId = Get-DockerImageIdByReference -Reference $reference
        if ([string]::IsNullOrWhiteSpace($currentImageId)) { continue }
        if ($currentImageId -cne [string]$ownedImageReferences[$reference]) { throw "ALPHA_ARTIFACT_IMAGE_CLEANUP_OWNERSHIP_FAILED: $reference" }
        & docker image rm $reference *> $null
        if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace((Get-DockerImageIdByReference -Reference $reference))) {
            throw "ALPHA_ARTIFACT_IMAGE_CLEANUP_FAILED: $reference"
        }
    }
    if (Test-Path -LiteralPath $testRoot) {
        $resolved = [IO.Path]::GetFullPath($testRoot)
        if (-not $resolved.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'ALPHA_ARTIFACT_TEST_CLEANUP_TARGET_INVALID' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

param(
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$sdkNonAlpine = 'mcr.microsoft.com/dotnet/sdk:10.0.302@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0'
$sdkAlpine = 'mcr.microsoft.com/dotnet/sdk:10.0.302-alpine3.24@sha256:979da27fc87dc255f4675b7642556cdcba9307459f8891f85f3cc26edcd7e766'
$aspnetNonAlpine = 'mcr.microsoft.com/dotnet/aspnet:10.0.11@sha256:207cc51496778557731c81ff670333d8ade4a4fec22768fd1be8e78474a84ecf'
$runtimeNonAlpine = 'mcr.microsoft.com/dotnet/runtime:10.0.11@sha256:acad02eb5c4fbf57d15296f9c08d56cd4036e915bdae5b4dd48a06523d452617'
$aspnetAlpine = 'mcr.microsoft.com/dotnet/aspnet:10.0.11-alpine3.24@sha256:c4b29bf368004ad9076c1ab9bc91fb373561e3905b4345637e14e8b8c57e3be8'
$runtimeAlpine = 'mcr.microsoft.com/dotnet/runtime:10.0.11-alpine3.24@sha256:216f4e2027da6ae806e0bc4b448669ac0faa00125908e308f31dd70598e58136'

$approvedDigests = @{
    'sdk:10.0.302' = '72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0'
    'sdk:10.0.302-alpine3.24' = '979da27fc87dc255f4675b7642556cdcba9307459f8891f85f3cc26edcd7e766'
    'aspnet:10.0.11' = '207cc51496778557731c81ff670333d8ade4a4fec22768fd1be8e78474a84ecf'
    'runtime:10.0.11' = 'acad02eb5c4fbf57d15296f9c08d56cd4036e915bdae5b4dd48a06523d452617'
    'aspnet:10.0.11-alpine3.24' = 'c4b29bf368004ad9076c1ab9bc91fb373561e3905b4345637e14e8b8c57e3be8'
    'runtime:10.0.11-alpine3.24' = '216f4e2027da6ae806e0bc4b448669ac0faa00125908e308f31dd70598e58136'
}

$repositoryExpectedReferencesByPath = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
$repositoryExpectedReferencesByPath.Add('src/Gateway/Gateway.Api/Dockerfile', [string[]]@($sdkNonAlpine, $aspnetNonAlpine))
$repositoryExpectedReferencesByPath.Add('src/Gateway/Gateway.Migrations/Dockerfile', [string[]]@($sdkNonAlpine, $runtimeNonAlpine))
$repositoryExpectedReferencesByPath.Add('packs/deployment/azure/Dockerfile', [string[]]@($sdkNonAlpine, $aspnetNonAlpine))
$repositoryExpectedReferencesByPath.Add('packs/deployment/local-pkcs12/Dockerfile', [string[]]@($sdkNonAlpine, $aspnetNonAlpine))
$repositoryExpectedReferencesByPath.Add('tools/m3/VendorMock/Dockerfile', [string[]]@($sdkAlpine, $aspnetAlpine))
$repositoryExpectedReferencesByPath.Add('tools/m3/SyntheticVault/Dockerfile', [string[]]@($sdkAlpine, $aspnetAlpine))
$repositoryExpectedReferencesByPath.Add('tools/m3/Provisioner/Dockerfile', [string[]]@($sdkAlpine, $runtimeAlpine))

function New-ValidationFinding {
    param(
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$Line
    )

    [pscustomobject]@{
        Code = $Code
        Path = $Path
        Line = $Line
    }
}

function ConvertTo-NormalizedRepositoryPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $normalized = $Path.Replace('\', '/').Trim()
    while ($normalized.StartsWith('./', [StringComparison]::Ordinal)) {
        $normalized = $normalized.Substring(2)
    }

    if ([string]::IsNullOrWhiteSpace($normalized) -or
        [IO.Path]::IsPathRooted($normalized) -or
        $normalized.Contains('//')) {
        return $null
    }

    foreach ($segment in $normalized.Split('/')) {
        if ($segment.Length -eq 0 -or $segment -eq '.' -or $segment -eq '..') {
            return $null
        }
    }

    return $normalized
}

function Get-ValidationProfile {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

    $coreExportManifestPath = Join-Path $RepositoryRoot 'OPEN_SOURCE_EXPORT_MANIFEST.json'
    $gitMetadataPath = Join-Path $RepositoryRoot '.git'
    $isGitWorktreeRoot = Test-Path -LiteralPath $gitMetadataPath
    $isCoreExport = (-not $isGitWorktreeRoot) -and
        (Test-Path -LiteralPath $coreExportManifestPath -PathType Leaf)
    $expectedReferencesByPath = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)

    foreach ($entry in $repositoryExpectedReferencesByPath.GetEnumerator()) {
        if (-not $isCoreExport -or -not $entry.Key.StartsWith('packs/deployment/', [StringComparison]::Ordinal)) {
            $expectedReferencesByPath.Add($entry.Key, [string[]]@($entry.Value))
        }
    }

    [pscustomobject]@{
        Name = $(if ($isCoreExport) { 'core-export' } else { 'repository' })
        IsCoreExport = $isCoreExport
        CoreExportManifestPath = $coreExportManifestPath
        ExpectedReferencesByPath = $expectedReferencesByPath
        ExpectedDockerfileCount = $(if ($isCoreExport) { 5 } else { 7 })
        ExpectedDotNetFromCount = $(if ($isCoreExport) { 10 } else { 14 })
    }
}

function Test-DotNetReference {
    param(
        [Parameter(Mandatory = $true)][string]$Reference,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$Line,
        [Parameter(Mandatory = $true)][string]$GlobalSdkVersion
    )

    $familyMatch = [regex]::Match(
        $Reference,
        '^mcr\.microsoft\.com/dotnet/(?<family>[^:/@\s]+)',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $familyMatch.Success) {
        New-ValidationFinding -Code 'DOTNET_BASE_REFERENCE_SYNTAX_INVALID' -Path $Path -Line $Line
        return
    }

    $family = $familyMatch.Groups['family'].Value.ToLowerInvariant()
    if ($family -notin @('sdk', 'aspnet', 'runtime')) {
        New-ValidationFinding -Code 'DOTNET_BASE_IMAGE_FAMILY_UNAPPROVED' -Path $Path -Line $Line
        return
    }

    if ($Reference -notmatch '@sha256:') {
        New-ValidationFinding -Code 'DOTNET_BASE_TAG_WITHOUT_DIGEST' -Path $Path -Line $Line
        return
    }

    $referenceMatch = [regex]::Match(
        $Reference,
        '^mcr\.microsoft\.com/dotnet/(?<family>sdk|aspnet|runtime):(?<tag>[^@\s]+)@sha256:(?<digest>[0-9a-fA-F]{64})$',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $referenceMatch.Success) {
        New-ValidationFinding -Code 'DOTNET_BASE_DIGEST_FORMAT_INVALID' -Path $Path -Line $Line
        return
    }

    $tag = $referenceMatch.Groups['tag'].Value
    $digest = $referenceMatch.Groups['digest'].Value.ToLowerInvariant()
    $approvalKey = '{0}:{1}' -f $family, $tag
    if (-not $approvedDigests.ContainsKey($approvalKey)) {
        New-ValidationFinding -Code 'DOTNET_BASE_TAG_UNAPPROVED' -Path $Path -Line $Line
        return
    }

    if ($approvedDigests[$approvalKey] -ne $digest) {
        New-ValidationFinding -Code 'DOTNET_BASE_DIGEST_UNAPPROVED' -Path $Path -Line $Line
    }

    if ($family -eq 'sdk') {
        $sdkTagVersion = ($tag -split '-', 2)[0]
        if ($sdkTagVersion -ne $GlobalSdkVersion) {
            New-ValidationFinding -Code 'DOTNET_SDK_GLOBAL_JSON_MISMATCH' -Path $Path -Line $Line
        }
    }
}

function Invoke-RepositoryValidation {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

    $profile = Get-ValidationProfile -RepositoryRoot $RepositoryRoot
    $expectedReferencesByPath = $profile.ExpectedReferencesByPath
    $findings = @()
    $globalJsonPath = Join-Path $RepositoryRoot 'global.json'
    if (-not (Test-Path -LiteralPath $globalJsonPath -PathType Leaf)) {
        $findings += New-ValidationFinding -Code 'GLOBAL_JSON_MISSING' -Path 'global.json' -Line 0
        return [pscustomobject]@{ Profile = $profile; Findings = $findings; TrackedDockerfileCount = 0; DotNetFromCount = 0 }
    }

    $globalJson = Get-Content -LiteralPath $globalJsonPath -Raw | ConvertFrom-Json
    $globalSdkVersion = [string]$globalJson.sdk.version
    if ([string]::IsNullOrWhiteSpace($globalSdkVersion)) {
        $findings += New-ValidationFinding -Code 'GLOBAL_JSON_SDK_VERSION_MISSING' -Path 'global.json' -Line 0
        return [pscustomobject]@{ Profile = $profile; Findings = $findings; TrackedDockerfileCount = 0; DotNetFromCount = 0 }
    }

    if ($profile.IsCoreExport) {
        $exportManifest = Get-Content -LiteralPath $profile.CoreExportManifestPath -Raw | ConvertFrom-Json
        if ([int]$exportManifest.schemaVersion -ne 1) {
            $findings += New-ValidationFinding -Code 'CORE_EXPORT_MANIFEST_VERSION_INVALID' -Path 'OPEN_SOURCE_EXPORT_MANIFEST.json' -Line 0
            return [pscustomobject]@{ Profile = $profile; Findings = $findings; TrackedDockerfileCount = 0; DotNetFromCount = 0 }
        }
        $trackedCandidates = @($exportManifest.files | ForEach-Object { [string]$_.path } | Where-Object {
            [IO.Path]::GetFileName($_) -match 'dockerfile'
        })
    }
    else {
        $allTrackedFiles = @(& git -C $RepositoryRoot ls-files)
        if ($LASTEXITCODE -ne 0) {
            $findings += New-ValidationFinding -Code 'GIT_TRACKED_FILE_ENUMERATION_FAILED' -Path 'repository' -Line 0
            return [pscustomobject]@{ Profile = $profile; Findings = $findings; TrackedDockerfileCount = 0; DotNetFromCount = 0 }
        }
        $trackedCandidates = @($allTrackedFiles | Where-Object {
            [IO.Path]::GetFileName($_) -match 'dockerfile'
        })
    }

    $trackedPaths = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
    $trackedPathsIgnoreCase = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($candidate in $trackedCandidates) {
        $normalizedPath = ConvertTo-NormalizedRepositoryPath -Path ([string]$candidate)
        if ($null -eq $normalizedPath) {
            $findings += New-ValidationFinding -Code 'TRACKED_DOCKERFILE_PATH_AMBIGUOUS' -Path 'repository' -Line 0
            continue
        }
        if ($trackedPaths.ContainsKey($normalizedPath) -or $trackedPathsIgnoreCase.ContainsKey($normalizedPath)) {
            $findings += New-ValidationFinding -Code 'TRACKED_DOCKERFILE_PATH_AMBIGUOUS' -Path $normalizedPath -Line 0
            continue
        }
        $trackedPaths.Add($normalizedPath, $normalizedPath)
        $trackedPathsIgnoreCase.Add($normalizedPath, $normalizedPath)
    }

    $trackedDockerfileCount = $trackedPaths.Count
    $inventoryMismatch = $trackedDockerfileCount -ne $profile.ExpectedDockerfileCount
    if ($inventoryMismatch) {
        $findings += New-ValidationFinding -Code 'TRACKED_DOCKERFILE_COUNT_INVALID' -Path 'repository' -Line $trackedDockerfileCount
    }

    foreach ($trackedPath in $trackedPaths.Keys) {
        if (-not $expectedReferencesByPath.ContainsKey($trackedPath)) {
            $inventoryMismatch = $true
            $findings += New-ValidationFinding -Code 'TRACKED_DOCKERFILE_UNAPPROVED' -Path $trackedPath -Line 0
        }
    }
    foreach ($expectedPath in $expectedReferencesByPath.Keys) {
        if (-not $trackedPaths.ContainsKey($expectedPath)) {
            $inventoryMismatch = $true
            $findings += New-ValidationFinding -Code 'EXPECTED_DOCKERFILE_MISSING' -Path $expectedPath -Line 0
        }
    }
    if ($inventoryMismatch) {
        $findings += New-ValidationFinding -Code 'TRACKED_DOCKERFILE_SET_MISMATCH' -Path 'repository' -Line 0
    }

    $actualReferencesByPath = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $dotNetFromCount = 0
    foreach ($normalizedPath in $trackedPaths.Keys) {
        $actualReferencesByPath.Add($normalizedPath, [string[]]@())
        $fullPath = Join-Path $RepositoryRoot ($normalizedPath.Replace('/', [IO.Path]::DirectorySeparatorChar))
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            $findings += New-ValidationFinding -Code 'TRACKED_DOCKERFILE_WORKTREE_MISSING' -Path $normalizedPath -Line 0
            continue
        }

        $lines = [IO.File]::ReadAllLines($fullPath)
        for ($index = 0; $index -lt $lines.Length; $index++) {
            $line = $lines[$index]
            $lineNumber = $index + 1
            $containsDotNetReference = $line -match 'mcr\.microsoft\.com/dotnet/'

            if ($line -match '^\s*ARG\b' -and $containsDotNetReference) {
                $findings += New-ValidationFinding -Code 'DOTNET_BASE_ARG_FORBIDDEN' -Path $normalizedPath -Line $lineNumber
            }
            if ($line -notmatch '^\s*FROM\b') {
                continue
            }

            if ($containsDotNetReference) {
                $dotNetFromCount++
            }
            if ($line -match '\$') {
                $findings += New-ValidationFinding -Code 'CONTAINER_FROM_INTERPOLATION_FORBIDDEN' -Path $normalizedPath -Line $lineNumber
            }

            $fromMatch = [regex]::Match(
                $line,
                '^\s*FROM\s+(?:(?<platform>--platform=(?<platformValue>[A-Za-z0-9_./-]+))\s+)?(?<reference>[^\s#]+)(?:\s+AS\s+(?<stage>[A-Za-z0-9_.-]+))?\s*(?:#.*)?$',
                [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if (-not $fromMatch.Success) {
                $findings += New-ValidationFinding -Code 'CONTAINER_FROM_SYNTAX_UNSUPPORTED' -Path $normalizedPath -Line $lineNumber
                if ($containsDotNetReference) {
                    $findings += New-ValidationFinding -Code 'DOTNET_FROM_SYNTAX_UNSUPPORTED' -Path $normalizedPath -Line $lineNumber
                }
                continue
            }

            $reference = $fromMatch.Groups['reference'].Value
            $parsedDotNetReference = $reference -match '^mcr\.microsoft\.com/dotnet/'
            if ($containsDotNetReference -and -not $parsedDotNetReference) {
                $findings += New-ValidationFinding -Code 'DOTNET_FROM_REFERENCE_NOT_PARSED' -Path $normalizedPath -Line $lineNumber
                continue
            }
            if (-not $parsedDotNetReference) {
                continue
            }

            if ($fromMatch.Groups['platform'].Success) {
                $findings += New-ValidationFinding -Code 'DOTNET_FROM_PLATFORM_FORBIDDEN' -Path $normalizedPath -Line $lineNumber
            }

            $actualReferencesByPath[$normalizedPath] = [string[]]@($actualReferencesByPath[$normalizedPath]) + $reference
            foreach ($finding in @(Test-DotNetReference -Reference $reference -Path $normalizedPath -Line $lineNumber -GlobalSdkVersion $globalSdkVersion)) {
                $findings += $finding
            }
            if (-not $expectedReferencesByPath.ContainsKey($normalizedPath)) {
                $findings += New-ValidationFinding -Code 'DOTNET_DOCKERFILE_UNAPPROVED' -Path $normalizedPath -Line $lineNumber
            }
        }
    }

    if ($dotNetFromCount -ne $profile.ExpectedDotNetFromCount) {
        $findings += New-ValidationFinding -Code 'DOTNET_FROM_COUNT_INVALID' -Path 'repository' -Line $dotNetFromCount
    }

    foreach ($expectedPath in $expectedReferencesByPath.Keys) {
        if (-not $actualReferencesByPath.ContainsKey($expectedPath)) {
            continue
        }
        $expected = [string[]]@($expectedReferencesByPath[$expectedPath])
        $actual = [string[]]@($actualReferencesByPath[$expectedPath])
        if ($actual.Count -ne $expected.Count) {
            $findings += New-ValidationFinding -Code 'DOTNET_FROM_FILE_COUNT_INVALID' -Path $expectedPath -Line $actual.Count
            continue
        }
        for ($index = 0; $index -lt $expected.Count; $index++) {
            if ($actual[$index] -cne $expected[$index]) {
                $findings += New-ValidationFinding -Code 'DOTNET_BASE_REFERENCE_NOT_APPROVED_FOR_FILE' -Path $expectedPath -Line ($index + 1)
            }
        }
    }

    [pscustomobject]@{
        Profile = $profile
        Findings = $findings
        TrackedDockerfileCount = $trackedDockerfileCount
        DotNetFromCount = $dotNetFromCount
    }
}

function New-SyntheticRepository {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $repositoryRoot = Join-Path $Parent $Name
    [IO.Directory]::CreateDirectory($repositoryRoot) | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $repositoryRoot 'global.json'),
        '{"sdk":{"version":"10.0.302","rollForward":"latestPatch"}}')

    foreach ($entry in $repositoryExpectedReferencesByPath.GetEnumerator()) {
        $fullPath = Join-Path $repositoryRoot ($entry.Key.Replace('/', [IO.Path]::DirectorySeparatorChar))
        [IO.Directory]::CreateDirectory((Split-Path -Parent $fullPath)) | Out-Null
        $references = [string[]]@($entry.Value)
        $content = @(
            '  from {0} aS build # mixed case and whitespace are supported' -f $references[0]
            'FROM {0} AS runtime # synthetic validator fixture' -f $references[1]
        ) -join [Environment]::NewLine
        [IO.File]::WriteAllText($fullPath, $content)
    }

    & git -C $repositoryRoot init --quiet 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'SYNTHETIC_GIT_INIT_FAILED' }
    & git -C $repositoryRoot add -- . 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'SYNTHETIC_GIT_ADD_FAILED' }
    return $repositoryRoot
}

function Assert-ValidationCase {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Result,
        [Parameter(Mandatory = $true)][bool]$ShouldPass,
        [string[]]$ExpectedCodes = @()
    )

    $codes = @($Result.Findings | ForEach-Object { $_.Code })
    if ($ShouldPass) {
        if ($codes.Count -ne 0 -or
            $Result.TrackedDockerfileCount -ne $Result.Profile.ExpectedDockerfileCount -or
            $Result.DotNetFromCount -ne $Result.Profile.ExpectedDotNetFromCount) {
            throw ('END_TO_END_CONTROL_FAILED:{0}' -f $Name)
        }
    }
    else {
        if ($codes.Count -eq 0) {
            throw ('END_TO_END_CONTROL_FAILED:{0}' -f $Name)
        }
        foreach ($expectedCode in $ExpectedCodes) {
            if ($expectedCode -notin $codes) {
                throw ('END_TO_END_CONTROL_FAILED:{0}:{1}' -f $Name, $expectedCode)
            }
        }
    }

    Write-Output ('{0}_PASS' -f $Name)
}

function Invoke-EndToEndSelfTests {
    $tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
    $selfTestRoot = Join-Path $tempParent ('broker-gateway-container-validator-{0}' -f [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($selfTestRoot) | Out-Null

    try {
        $canonical = New-SyntheticRepository -Parent $selfTestRoot -Name 'canonical'
        Assert-ValidationCase -Name 'CANONICAL_REPOSITORY_POSITIVE' -Result (Invoke-RepositoryValidation -RepositoryRoot $canonical) -ShouldPass $true

        $platformMobile = New-SyntheticRepository -Parent $selfTestRoot -Name 'platform-mobile'
        $extraPath = Join-Path $platformMobile 'synthetic\Dockerfile'
        [IO.Directory]::CreateDirectory((Split-Path -Parent $extraPath)) | Out-Null
        [IO.File]::WriteAllText($extraPath, 'FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:10.0')
        & git -C $platformMobile add -- synthetic/Dockerfile 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'SYNTHETIC_GIT_ADD_FAILED' }
        Assert-ValidationCase -Name 'EXTRA_DOCKERFILE_NEGATIVE' -Result (Invoke-RepositoryValidation -RepositoryRoot $platformMobile) -ShouldPass $false -ExpectedCodes @('TRACKED_DOCKERFILE_SET_MISMATCH', 'DOTNET_FROM_PLATFORM_FORBIDDEN', 'DOTNET_BASE_TAG_WITHOUT_DIGEST')
        Write-Output 'PLATFORM_MOBILE_BYPASS_NEGATIVE_PASS'

        $coreExportMarkerBypass = New-SyntheticRepository -Parent $selfTestRoot -Name 'core-export-marker-bypass'
        $extraPath = Join-Path $coreExportMarkerBypass 'synthetic\Dockerfile'
        [IO.Directory]::CreateDirectory((Split-Path -Parent $extraPath)) | Out-Null
        [IO.File]::WriteAllText($extraPath, 'FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:10.0')
        $manifestPath = Join-Path $coreExportMarkerBypass 'OPEN_SOURCE_EXPORT_MANIFEST.json'
        $manifest = [ordered]@{
            schemaVersion = 1
            files = @(
                @{ path = 'src/Gateway/Gateway.Api/Dockerfile' }
                @{ path = 'src/Gateway/Gateway.Migrations/Dockerfile' }
                @{ path = 'tools/m3/VendorMock/Dockerfile' }
                @{ path = 'tools/m3/SyntheticVault/Dockerfile' }
                @{ path = 'tools/m3/Provisioner/Dockerfile' }
            )
        } | ConvertTo-Json -Depth 3
        [IO.File]::WriteAllText($manifestPath, $manifest)
        & git -C $coreExportMarkerBypass add -- OPEN_SOURCE_EXPORT_MANIFEST.json synthetic/Dockerfile 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'SYNTHETIC_GIT_ADD_FAILED' }
        $coreExportMarkerResult = Invoke-RepositoryValidation -RepositoryRoot $coreExportMarkerBypass
        if ($coreExportMarkerResult.Profile.Name -ne 'repository') {
            throw 'END_TO_END_CONTROL_FAILED:CORE_EXPORT_MARKER_SELECTED_REDUCED_PROFILE'
        }
        Assert-ValidationCase -Name 'CORE_EXPORT_MARKER_BYPASS_NEGATIVE' -Result $coreExportMarkerResult -ShouldPass $false -ExpectedCodes @('TRACKED_DOCKERFILE_SET_MISMATCH', 'DOTNET_FROM_PLATFORM_FORBIDDEN', 'DOTNET_BASE_TAG_WITHOUT_DIGEST')

        $extraNonDotNet = New-SyntheticRepository -Parent $selfTestRoot -Name 'extra-non-dotnet'
        $extraPath = Join-Path $extraNonDotNet 'synthetic\Dockerfile'
        [IO.Directory]::CreateDirectory((Split-Path -Parent $extraPath)) | Out-Null
        [IO.File]::WriteAllText($extraPath, 'FROM alpine:3.24')
        & git -C $extraNonDotNet add -- synthetic/Dockerfile 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'SYNTHETIC_GIT_ADD_FAILED' }
        Assert-ValidationCase -Name 'EXTRA_NON_DOTNET_DOCKERFILE_NEGATIVE' -Result (Invoke-RepositoryValidation -RepositoryRoot $extraNonDotNet) -ShouldPass $false -ExpectedCodes @('TRACKED_DOCKERFILE_COUNT_INVALID', 'TRACKED_DOCKERFILE_SET_MISMATCH', 'TRACKED_DOCKERFILE_UNAPPROVED')

        $missing = New-SyntheticRepository -Parent $selfTestRoot -Name 'missing'
        & git -C $missing rm --quiet --force -- 'packs/deployment/azure/Dockerfile' 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'SYNTHETIC_GIT_REMOVE_FAILED' }
        Assert-ValidationCase -Name 'MISSING_DOCKERFILE_NEGATIVE' -Result (Invoke-RepositoryValidation -RepositoryRoot $missing) -ShouldPass $false -ExpectedCodes @('TRACKED_DOCKERFILE_COUNT_INVALID', 'TRACKED_DOCKERFILE_SET_MISMATCH', 'EXPECTED_DOCKERFILE_MISSING')

        $pinnedPlatform = New-SyntheticRepository -Parent $selfTestRoot -Name 'pinned-platform'
        $path = Join-Path $pinnedPlatform 'src\Gateway\Gateway.Api\Dockerfile'
        $lines = [IO.File]::ReadAllLines($path)
        $lines[0] = 'FROM --platform=linux/amd64 {0} AS build' -f $sdkNonAlpine
        [IO.File]::WriteAllLines($path, $lines)
        & git -C $pinnedPlatform add -- 'src/Gateway/Gateway.Api/Dockerfile' 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'SYNTHETIC_GIT_ADD_FAILED' }
        Assert-ValidationCase -Name 'PINNED_PLATFORM_NEGATIVE' -Result (Invoke-RepositoryValidation -RepositoryRoot $pinnedPlatform) -ShouldPass $false -ExpectedCodes @('DOTNET_FROM_PLATFORM_FORBIDDEN')

        $mobileCanonical = New-SyntheticRepository -Parent $selfTestRoot -Name 'mobile-canonical'
        $path = Join-Path $mobileCanonical 'src\Gateway\Gateway.Api\Dockerfile'
        $lines = [IO.File]::ReadAllLines($path)
        $lines[0] = 'FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build'
        [IO.File]::WriteAllLines($path, $lines)
        & git -C $mobileCanonical add -- 'src/Gateway/Gateway.Api/Dockerfile' 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'SYNTHETIC_GIT_ADD_FAILED' }
        Assert-ValidationCase -Name 'MOBILE_TAG_NEGATIVE' -Result (Invoke-RepositoryValidation -RepositoryRoot $mobileCanonical) -ShouldPass $false -ExpectedCodes @('DOTNET_BASE_TAG_WITHOUT_DIGEST', 'DOTNET_BASE_REFERENCE_NOT_APPROVED_FOR_FILE')

        $crossImageDigest = New-SyntheticRepository -Parent $selfTestRoot -Name 'cross-image-digest'
        $path = Join-Path $crossImageDigest 'src\Gateway\Gateway.Api\Dockerfile'
        $lines = [IO.File]::ReadAllLines($path)
        $lines[0] = 'FROM mcr.microsoft.com/dotnet/sdk:10.0.302@sha256:207cc51496778557731c81ff670333d8ade4a4fec22768fd1be8e78474a84ecf AS build'
        [IO.File]::WriteAllLines($path, $lines)
        & git -C $crossImageDigest add -- 'src/Gateway/Gateway.Api/Dockerfile' 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'SYNTHETIC_GIT_ADD_FAILED' }
        Assert-ValidationCase -Name 'UNAPPROVED_DIGEST_NEGATIVE' -Result (Invoke-RepositoryValidation -RepositoryRoot $crossImageDigest) -ShouldPass $false -ExpectedCodes @('DOTNET_BASE_DIGEST_UNAPPROVED', 'DOTNET_BASE_REFERENCE_NOT_APPROVED_FOR_FILE')

        $globalMismatch = New-SyntheticRepository -Parent $selfTestRoot -Name 'global-mismatch'
        [IO.File]::WriteAllText((Join-Path $globalMismatch 'global.json'), '{"sdk":{"version":"10.0.999","rollForward":"latestPatch"}}')
        & git -C $globalMismatch add -- global.json 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'SYNTHETIC_GIT_ADD_FAILED' }
        Assert-ValidationCase -Name 'GLOBAL_JSON_MISMATCH_NEGATIVE' -Result (Invoke-RepositoryValidation -RepositoryRoot $globalMismatch) -ShouldPass $false -ExpectedCodes @('DOTNET_SDK_GLOBAL_JSON_MISMATCH')
    }
    finally {
        $resolvedSelfTestRoot = [IO.Path]::GetFullPath($selfTestRoot).TrimEnd('\', '/')
        $expectedPrefix = $tempParent + [IO.Path]::DirectorySeparatorChar + 'broker-gateway-container-validator-'
        if (-not $resolvedSelfTestRoot.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'SELF_TEST_CLEANUP_TARGET_INVALID'
        }
        if (Test-Path -LiteralPath $resolvedSelfTestRoot) {
            Remove-Item -LiteralPath $resolvedSelfTestRoot -Recurse -Force
        }
    }
}

try {
    $repositoryResult = Invoke-RepositoryValidation -RepositoryRoot $root
    if (@($repositoryResult.Findings).Count -ne 0) {
        foreach ($finding in @($repositoryResult.Findings)) {
            [Console]::Error.WriteLine(
                'CONTAINER_BASE_IMAGE_VALIDATION_FAILED:{0}:{1}:{2}',
                $finding.Code,
                $finding.Path,
                $finding.Line)
        }
        exit 1
    }

    Write-Output (
        'CONTAINER_BASE_IMAGE_VALIDATION_PASS:profile={0}:tracked_dockerfiles={1}:tracked_set=exact_match:dotnet_from={2}' -f
        $repositoryResult.Profile.Name,
        $repositoryResult.TrackedDockerfileCount,
        $repositoryResult.DotNetFromCount)

    if ($SelfTest) {
        Invoke-EndToEndSelfTests
    }
}
catch {
    [Console]::Error.WriteLine('CONTAINER_BASE_IMAGE_VALIDATION_FAILED:VALIDATOR_INTERNAL_ERROR:repository:0')
    exit 1
}

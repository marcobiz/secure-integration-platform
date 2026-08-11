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

$repositoryExpectedReferencesByPath = @{
    'src/Gateway/Gateway.Api/Dockerfile' = @($sdkNonAlpine, $aspnetNonAlpine)
    'src/Gateway/Gateway.Migrations/Dockerfile' = @($sdkNonAlpine, $runtimeNonAlpine)
    'packs/deployment/azure/Dockerfile' = @($sdkNonAlpine, $aspnetNonAlpine)
    'tools/m3/VendorMock/Dockerfile' = @($sdkAlpine, $aspnetAlpine)
    'tools/m3/SyntheticVault/Dockerfile' = @($sdkAlpine, $aspnetAlpine)
    'tools/m3/Provisioner/Dockerfile' = @($sdkAlpine, $runtimeAlpine)
}

$coreExportManifestPath = Join-Path $root 'OPEN_SOURCE_EXPORT_MANIFEST.json'
$isCoreExport = Test-Path -LiteralPath $coreExportManifestPath -PathType Leaf
if ($isCoreExport) {
    $expectedReferencesByPath = @{}
    foreach ($path in @($repositoryExpectedReferencesByPath.Keys)) {
        if ($path -ne 'packs/deployment/azure/Dockerfile') {
            $expectedReferencesByPath[$path] = $repositoryExpectedReferencesByPath[$path]
        }
    }
    $validationProfile = 'core-export'
    $expectedDockerfileCount = 5
    $expectedDotNetFromCount = 10
}
else {
    $expectedReferencesByPath = $repositoryExpectedReferencesByPath
    $validationProfile = 'repository'
    $expectedDockerfileCount = 6
    $expectedDotNetFromCount = 12
}

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
    $globalJsonPath = Join-Path $root 'global.json'
    if (-not (Test-Path -LiteralPath $globalJsonPath -PathType Leaf)) {
        return @(New-ValidationFinding -Code 'GLOBAL_JSON_MISSING' -Path 'global.json' -Line 0)
    }

    $globalJson = Get-Content -LiteralPath $globalJsonPath -Raw | ConvertFrom-Json
    $globalSdkVersion = [string]$globalJson.sdk.version
    if ([string]::IsNullOrWhiteSpace($globalSdkVersion)) {
        return @(New-ValidationFinding -Code 'GLOBAL_JSON_SDK_VERSION_MISSING' -Path 'global.json' -Line 0)
    }

    if ($isCoreExport) {
        $exportManifest = Get-Content -LiteralPath $coreExportManifestPath -Raw | ConvertFrom-Json
        if ([int]$exportManifest.schemaVersion -ne 1) {
            return @(New-ValidationFinding -Code 'CORE_EXPORT_MANIFEST_VERSION_INVALID' -Path 'OPEN_SOURCE_EXPORT_MANIFEST.json' -Line 0)
        }
        $trackedCandidates = @($exportManifest.files | ForEach-Object { [string]$_.path } | Where-Object { $_ -like '*Dockerfile*' })
    }
    else {
        $trackedCandidates = @(& git -C $root ls-files -- '*Dockerfile*')
        if ($LASTEXITCODE -ne 0) {
            return @(New-ValidationFinding -Code 'GIT_TRACKED_FILE_ENUMERATION_FAILED' -Path 'repository' -Line 0)
        }
    }

    $trackedDockerfiles = @($trackedCandidates | Where-Object {
        [IO.Path]::GetFileName($_) -match '^Dockerfile(?:\..+)?$'
    })
    if ($trackedDockerfiles.Count -eq 0) {
        return @(New-ValidationFinding -Code 'TRACKED_DOCKERFILES_MISSING' -Path 'repository' -Line 0)
    }

    $findings = @()
    $actualReferencesByPath = @{}
    $dotNetFromCount = 0

    foreach ($relativePath in $trackedDockerfiles) {
        $normalizedPath = $relativePath.Replace('\', '/')
        $actualReferencesByPath[$normalizedPath] = @()
        $fullPath = Join-Path $root ($normalizedPath.Replace('/', [IO.Path]::DirectorySeparatorChar))
        $lines = [IO.File]::ReadAllLines($fullPath)

        for ($index = 0; $index -lt $lines.Length; $index++) {
            $line = $lines[$index]
            $lineNumber = $index + 1

            if ($line -match '^\s*ARG\b' -and $line -match 'mcr\.microsoft\.com/dotnet/') {
                $findings += New-ValidationFinding -Code 'DOTNET_BASE_ARG_FORBIDDEN' -Path $normalizedPath -Line $lineNumber
            }

            if ($line -notmatch '^\s*FROM\b') { continue }

            if ($line -match '\$') {
                $findings += New-ValidationFinding -Code 'CONTAINER_FROM_INTERPOLATION_FORBIDDEN' -Path $normalizedPath -Line $lineNumber
                continue
            }

            $fromMatch = [regex]::Match(
                $line,
                '^\s*FROM\s+(?<reference>\S+)(?:\s+AS\s+[A-Za-z0-9_.-]+)?\s*(?:#.*)?$',
                [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if (-not $fromMatch.Success) {
                if ($line -match 'mcr\.microsoft\.com/dotnet/') {
                    $findings += New-ValidationFinding -Code 'DOTNET_FROM_SYNTAX_UNSUPPORTED' -Path $normalizedPath -Line $lineNumber
                }
                continue
            }

            $reference = $fromMatch.Groups['reference'].Value
            if ($reference -notmatch '^mcr\.microsoft\.com/dotnet/') { continue }

            $dotNetFromCount++
            $actualReferencesByPath[$normalizedPath] = @($actualReferencesByPath[$normalizedPath]) + $reference
            foreach ($finding in @(Test-DotNetReference -Reference $reference -Path $normalizedPath -Line $lineNumber -GlobalSdkVersion $globalSdkVersion)) {
                $findings += $finding
            }

            if (-not $expectedReferencesByPath.ContainsKey($normalizedPath)) {
                $findings += New-ValidationFinding -Code 'DOTNET_DOCKERFILE_UNAPPROVED' -Path $normalizedPath -Line $lineNumber
            }
        }
    }

    if ($dotNetFromCount -ne $expectedDotNetFromCount) {
        $findings += New-ValidationFinding -Code 'DOTNET_FROM_COUNT_INVALID' -Path 'repository' -Line $dotNetFromCount
    }

    foreach ($expectedPath in @($expectedReferencesByPath.Keys | Sort-Object)) {
        if (-not $actualReferencesByPath.ContainsKey($expectedPath)) {
            $findings += New-ValidationFinding -Code 'EXPECTED_DOTNET_DOCKERFILE_MISSING' -Path $expectedPath -Line 0
            continue
        }

        $expected = @($expectedReferencesByPath[$expectedPath])
        $actual = @($actualReferencesByPath[$expectedPath])
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

    return $findings
}

function Test-NegativeControl {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ExpectedCode,
        [Parameter(Mandatory = $true)][string]$Reference,
        [Parameter(Mandatory = $true)][string]$GlobalSdkVersion
    )

    $controlFindings = @(Test-DotNetReference -Reference $Reference -Path 'synthetic/Dockerfile' -Line 1 -GlobalSdkVersion $GlobalSdkVersion)
    if ($ExpectedCode -notin @($controlFindings | ForEach-Object { $_.Code })) {
        throw ('NEGATIVE_CONTROL_FAILED:{0}' -f $Name)
    }

    Write-Output ('{0}_PASS' -f $Name)
}

try {
    $repositoryFindings = @(Invoke-RepositoryValidation)
    if ($repositoryFindings.Count -ne 0) {
        foreach ($finding in $repositoryFindings) {
            [Console]::Error.WriteLine(
                'CONTAINER_BASE_IMAGE_VALIDATION_FAILED:{0}:{1}:{2}',
                $finding.Code,
                $finding.Path,
                $finding.Line)
        }
        exit 1
    }

    Write-Output ('CONTAINER_BASE_IMAGE_VALIDATION_PASS:profile={0}:dockerfiles={1}:dotnet_from={2}' -f $validationProfile, $expectedDockerfileCount, $expectedDotNetFromCount)

    if ($SelfTest) {
        Test-NegativeControl `
            -Name 'MOBILE_TAG_NEGATIVE' `
            -ExpectedCode 'DOTNET_BASE_TAG_WITHOUT_DIGEST' `
            -Reference 'mcr.microsoft.com/dotnet/sdk:10.0' `
            -GlobalSdkVersion '10.0.302'
        Test-NegativeControl `
            -Name 'UNAPPROVED_DIGEST_NEGATIVE' `
            -ExpectedCode 'DOTNET_BASE_DIGEST_UNAPPROVED' `
            -Reference 'mcr.microsoft.com/dotnet/sdk:10.0.302@sha256:0000000000000000000000000000000000000000000000000000000000000000' `
            -GlobalSdkVersion '10.0.302'
        Test-NegativeControl `
            -Name 'GLOBAL_JSON_MISMATCH_NEGATIVE' `
            -ExpectedCode 'DOTNET_SDK_GLOBAL_JSON_MISMATCH' `
            -Reference $sdkNonAlpine `
            -GlobalSdkVersion '10.0.999'
    }
}
catch {
    [Console]::Error.WriteLine('CONTAINER_BASE_IMAGE_VALIDATION_FAILED:VALIDATOR_INTERNAL_ERROR:repository:0')
    exit 1
}

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$validator = Join-Path $PSScriptRoot 'Test-LicensePolicy.ps1'
Import-Module (Join-Path $PSScriptRoot 'LicensePolicy.psm1') -Force

function Assert-Equal([string] $Name, [object] $Actual, [object] $Expected) {
    if ($Actual -cne $Expected) { throw "$Name expected=$Expected actual=$Actual" }
    Write-Host "$Name PASS"
}

function Assert-ValidatorRejects {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Path,
        [Parameter(Mandatory = $true)][string] $ExpectedFailure
    )

    $failure = $null
    try { & $validator -RepositoryRoot $repositoryRoot -AdditionalPathToValidate @($Path) -Json *> $null }
    catch { $failure = $_.Exception.Message }
    if ([string]::IsNullOrWhiteSpace($failure) -or $failure -cnotlike "$ExpectedFailure*") {
        throw "$Name expectedFailure=$ExpectedFailure actualFailure=$failure"
    }
    Write-Host "$Name PASS"
}

$previousOutputEncoding = [Console]::OutputEncoding
try {
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
    $tracked = @(& git -C $repositoryRoot -c core.quotepath=false ls-files)
    $gitInventoryExitCode = $LASTEXITCODE
}
finally { [Console]::OutputEncoding = $previousOutputEncoding }
if ($gitInventoryExitCode -ne 0 -or $tracked.Count -eq 0) { throw 'LICENSE_POLICY_SELF_TEST_GIT_INVENTORY_FAILED' }
$trackedSet = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
foreach ($path in $tracked) {
    if (-not $trackedSet.Add($path)) { throw 'LICENSE_POLICY_SELF_TEST_DUPLICATE_INVENTORY' }
}

$baseline = & $validator -RepositoryRoot $repositoryRoot -Json | ConvertFrom-Json
Assert-Equal 'ALPHA_LIC_all_tracked_paths_have_one_policy' ([int]$baseline.trackedPathsClassified) $tracked.Count
Assert-Equal 'ALPHA_LIC_unclassified_paths_are_zero' ([int]$baseline.unclassifiedPaths) 0
Assert-Equal 'ALPHA_LIC_overlapping_paths_are_zero' ([int]$baseline.overlappingPaths) 0
Assert-Equal 'ALPHA_LIC_apache_override_is_exact' (Get-RepositoryLicensePolicy -Path 'sdk/dotnet/Broker.Sdk/Broker.Sdk.csproj' -TrackedPathSet $trackedSet).spdxExpression 'Apache-2.0'
Assert-Equal 'ALPHA_LIC_generic_reference_expression_is_exact' (Get-RepositoryLicensePolicy -Path 'docs/connectors/examples/LICENSE.md' -TrackedPathSet $trackedSet).spdxExpression 'MPL-2.0 OR Apache-2.0'
Assert-Equal 'ALPHA_LIC_tests_default_to_mpl' (Get-RepositoryLicensePolicy -Path 'tests/architecture/Architecture.Tests/AlphaReleaseArtifactTests.cs' -TrackedPathSet $trackedSet).spdxExpression 'MPL-2.0'

Assert-ValidatorRejects 'ALPHA_LIC_empty_path_negative' '' 'LICENSE_POLICY_PATH_EMPTY'
Assert-ValidatorRejects 'ALPHA_LIC_root_slash_negative' '/sdk/file' 'LICENSE_POLICY_PATH_ROOTED'
Assert-ValidatorRejects 'ALPHA_LIC_root_backslash_negative' '\sdk\file' 'LICENSE_POLICY_PATH_ROOTED'
Assert-ValidatorRejects 'ALPHA_LIC_unc_path_negative' '\\server\share\file' 'LICENSE_POLICY_PATH_ROOTED'
Assert-ValidatorRejects 'ALPHA_LIC_device_path_negative' '\\?\C:\sdk\file' 'LICENSE_POLICY_PATH_ROOTED'
Assert-ValidatorRejects 'ALPHA_LIC_parent_prefix_negative' '../sdk/file' 'LICENSE_POLICY_PATH_TRAVERSAL_SEGMENT'
Assert-ValidatorRejects 'ALPHA_LIC_parent_backslash_negative' '..\sdk\file' 'LICENSE_POLICY_PATH_BACKSLASH'
Assert-ValidatorRejects 'ALPHA_LIC_current_segment_prefix_negative' './sdk/file' 'LICENSE_POLICY_PATH_TRAVERSAL_SEGMENT'
Assert-ValidatorRejects 'ALPHA_LIC_parent_segment_negative' 'sdk/../file' 'LICENSE_POLICY_PATH_TRAVERSAL_SEGMENT'
Assert-ValidatorRejects 'ALPHA_LIC_drive_backslash_negative' 'C:\sdk\file' 'LICENSE_POLICY_PATH_DRIVE_QUALIFIED'
Assert-ValidatorRejects 'ALPHA_LIC_drive_slash_negative' 'C:/sdk/file' 'LICENSE_POLICY_PATH_DRIVE_QUALIFIED'
Assert-ValidatorRejects 'ALPHA_LIC_drive_relative_negative' 'C:sdk/file' 'LICENSE_POLICY_PATH_DRIVE_QUALIFIED'
Assert-ValidatorRejects 'ALPHA_LIC_backslash_negative' 'sdk\file' 'LICENSE_POLICY_PATH_BACKSLASH'
Assert-ValidatorRejects 'ALPHA_LIC_ads_negative' 'sdk/file.txt:stream' 'LICENSE_POLICY_PATH_ADS_OR_COLON'
Assert-ValidatorRejects 'ALPHA_LIC_double_slash_negative' 'sdk//file' 'LICENSE_POLICY_PATH_EMPTY_SEGMENT'
Assert-ValidatorRejects 'ALPHA_LIC_trailing_slash_negative' 'sdk/file/' 'LICENSE_POLICY_PATH_TRAILING_SLASH'
Assert-ValidatorRejects 'ALPHA_LIC_unknown_path_negative' 'unknown/path.txt' 'LICENSE_POLICY_PATH_NOT_TRACKED'
Assert-ValidatorRejects 'ALPHA_LIC_case_variant_negative' '.CONFIG/dotnet-tools.json' 'LICENSE_POLICY_PATH_NOT_TRACKED'
Assert-ValidatorRejects 'ALPHA_LIC_nul_character_negative' ("sdk/$([char]0)file") 'LICENSE_POLICY_PATH_CONTROL_CHARACTER'
Assert-ValidatorRejects 'ALPHA_LIC_control_character_negative' ("sdk/$([char]1)file") 'LICENSE_POLICY_PATH_CONTROL_CHARACTER'

$unicodePath = 'tests/architecture/Architecture.Tests/Fixtures/licenza-' + [char]0x00E8 + '.txt'
$unicodeTrackedSet = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
[void]$unicodeTrackedSet.Add($unicodePath)
$unicodePolicy = Get-RepositoryLicensePolicy -Path $unicodePath -TrackedPathSet $unicodeTrackedSet
Assert-Equal 'ALPHA_LIC_valid_unicode_path_identity_is_unchanged' ([string]$unicodePolicy.path) $unicodePath
$unicodeTempBase = [IO.Path]::GetTempPath().TrimEnd([IO.Path]::DirectorySeparatorChar)
$unicodeRoot = Join-Path $unicodeTempBase ('secure-integration-license-unicode-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $unicodeRoot | Out-Null
    $validatorFixturePaths = @(
        'LICENSE',
        'LICENSE-APACHE-2.0',
        'DCO.md',
        'LICENSING.md',
        'Directory.Build.props',
        'sdk/dotnet/Broker.Sdk/Broker.Sdk.csproj',
        'src/Shared/SecureIntegration.Contracts/SecureIntegration.Contracts.csproj',
        'src/Admin/Admin.Web/package.json',
        'src/Admin/Admin.Web/package-lock.json',
        'docs/api/gateway-openapi.yaml',
        'docs/connectors/examples/LICENSE.md',
        'src/Gateway/Gateway.Api/Dockerfile',
        'src/Gateway/Gateway.Migrations/Dockerfile',
        'deploy/release-manifest.template.json',
        'eng/generate-sbom.ps1'
    )
    foreach ($fixturePath in $validatorFixturePaths) {
        $fixtureDestination = Join-Path $unicodeRoot $fixturePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
        New-Item -ItemType Directory -Path (Split-Path -Parent $fixtureDestination) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $repositoryRoot $fixturePath.Replace('/', [IO.Path]::DirectorySeparatorChar)) -Destination $fixtureDestination
    }
    $unicodeFullPath = Join-Path $unicodeRoot $unicodePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
    New-Item -ItemType Directory -Path (Split-Path -Parent $unicodeFullPath) -Force | Out-Null
    [IO.File]::WriteAllText($unicodeFullPath, 'Unicode Git path identity fixture.', [Text.UTF8Encoding]::new($false))
    & git -C $unicodeRoot init --quiet
    if ($LASTEXITCODE -ne 0) { throw 'LICENSE_POLICY_SELF_TEST_UNICODE_GIT_INIT_FAILED' }
    & git -C $unicodeRoot -c core.autocrlf=false add -- .
    if ($LASTEXITCODE -ne 0) { throw 'LICENSE_POLICY_SELF_TEST_UNICODE_GIT_ADD_FAILED' }
    & $validator -RepositoryRoot $unicodeRoot -AdditionalPathToValidate @($unicodePath) -Json *> $null
    Write-Host 'ALPHA_LIC_valid_unicode_path_full_validator PASS'
}
finally {
    if (Test-Path -LiteralPath $unicodeRoot) {
        $resolvedUnicodeRoot = [IO.Path]::GetFullPath($unicodeRoot)
        if (-not $resolvedUnicodeRoot.StartsWith($unicodeTempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'LICENSE_POLICY_SELF_TEST_UNICODE_CLEANUP_TARGET_INVALID'
        }
        Remove-Item -LiteralPath $resolvedUnicodeRoot -Recurse -Force
    }
}

$ambiguousRejected = $false
try { Assert-RepositorySpdxExpression 'MPL / Apache' } catch { $ambiguousRejected = $_.Exception.Message -match 'AMBIGUOUS' }
Assert-Equal 'ALPHA_LIC_ambiguous_expression_is_rejected' $ambiguousRejected $true
$aggregateRejectedWithoutContext = $false
try { Assert-RepositorySpdxExpression 'MPL-2.0 AND Apache-2.0' } catch { $aggregateRejectedWithoutContext = $true }
Assert-Equal 'ALPHA_LIC_and_is_aggregate_only' $aggregateRejectedWithoutContext $true
Assert-RepositorySpdxExpression 'MPL-2.0 AND Apache-2.0' -AllowAggregate

$tempBase = [IO.Path]::GetTempPath().TrimEnd([IO.Path]::DirectorySeparatorChar)
$overlapRoot = Join-Path $tempBase ('secure-integration-license-overlap-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $overlapRoot | Out-Null
    $overlapModule = Join-Path $overlapRoot 'LicensePolicy.psm1'
    $overlapValidator = Join-Path $overlapRoot 'Test-LicensePolicy.ps1'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'LicensePolicy.psm1') -Destination $overlapModule
    Copy-Item -LiteralPath $validator -Destination $overlapValidator
    $moduleText = [IO.File]::ReadAllText($overlapModule)
    $needle = '$script:ApacheExactPaths = @('
    if (-not $moduleText.Contains($needle)) { throw 'LICENSE_POLICY_SELF_TEST_OVERLAP_FIXTURE_INVALID' }
    $moduleText = $moduleText.Replace($needle, $needle + "`n    'docs/connectors/examples/LICENSE.md',")
    [IO.File]::WriteAllText($overlapModule, $moduleText, [Text.UTF8Encoding]::new($false))

    $overlapFailure = $null
    try { & $overlapValidator -RepositoryRoot $repositoryRoot -Json *> $null }
    catch { $overlapFailure = $_.Exception.Message }
    if ([string]::IsNullOrWhiteSpace($overlapFailure) -or $overlapFailure -cnotlike 'LICENSE_POLICY_EXPLICIT_RULE_OVERLAP:*') {
        throw "LICENSE_POLICY_SELF_TEST_OVERLAP_NOT_REJECTED: $overlapFailure"
    }
    Write-Host 'ALPHA_LIC_explicit_rule_overlap_full_validator_negative PASS'
}
finally {
    if (Test-Path -LiteralPath $overlapRoot) {
        $resolvedOverlapRoot = [IO.Path]::GetFullPath($overlapRoot)
        if (-not $resolvedOverlapRoot.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'LICENSE_POLICY_SELF_TEST_CLEANUP_TARGET_INVALID'
        }
        Remove-Item -LiteralPath $resolvedOverlapRoot -Recurse -Force
    }
}

Write-Host 'ALPHA_LIC_license_policy_self_tests PASS'

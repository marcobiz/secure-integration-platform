[CmdletBinding()]
param(
    [string] $RepositoryRoot,
    [switch] $Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) { (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path } else { (Resolve-Path -LiteralPath $RepositoryRoot).Path }
Import-Module (Join-Path $PSScriptRoot 'LicensePolicy.psm1') -Force

function Assert-TextContains {
    param([string] $RelativePath, [string] $Needle, [string] $FailureCode)
    $text = Get-Content -LiteralPath (Join-Path $root $RelativePath) -Raw
    if (-not $text.Contains($Needle)) { throw $FailureCode }
}

function Assert-CanonicalSha256 {
    param([string] $RelativePath, [string] $ExpectedSha256, [string] $FailureCode)
    $actual = (Get-FileHash -LiteralPath (Join-Path $root $RelativePath) -Algorithm SHA256).Hash
    if ($actual -cne $ExpectedSha256) { throw "$FailureCode expected=$ExpectedSha256 actual=$actual" }
}

$gitMetadataPath = Join-Path $root '.git'
$insideGitWorktree = $false
if (Test-Path -LiteralPath $gitMetadataPath) {
    $insideGitWorktree = ((& git -C $root rev-parse --is-inside-work-tree | Out-String).Trim() -ceq 'true') -and $LASTEXITCODE -eq 0
}
if ($insideGitWorktree) {
    $tracked = @(& git -C $root -c core.quotepath=false ls-files)
    if ($LASTEXITCODE -ne 0 -or $tracked.Count -eq 0) { throw 'LICENSE_POLICY_GIT_INVENTORY_FAILED' }
}
else {
    $exportManifestPath = Join-Path $root 'OPEN_SOURCE_EXPORT_MANIFEST.json'
    if (-not (Test-Path -LiteralPath $exportManifestPath -PathType Leaf)) { throw 'LICENSE_POLICY_GIT_INVENTORY_FAILED' }
    try { $exportManifest = Get-Content -LiteralPath $exportManifestPath -Raw | ConvertFrom-Json }
    catch { throw 'LICENSE_POLICY_EXPORT_INVENTORY_INVALID' }
    $tracked = @($exportManifest.files | ForEach-Object { [string]$_.path })
    if ($tracked.Count -eq 0 -or [int]$exportManifest.fileCount -ne $tracked.Count) { throw 'LICENSE_POLICY_EXPORT_INVENTORY_INVALID' }
}
$trackedSet = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
$unclassified = [Collections.Generic.List[string]]::new()
$multiple = [Collections.Generic.List[string]]::new()
$classifications = [Collections.Generic.List[object]]::new()
foreach ($path in $tracked) {
    if (-not $trackedSet.Add($path)) { $multiple.Add($path); continue }
    $policy = @(Get-RepositoryLicensePolicy -Path $path)
    if ($policy.Count -eq 0) { $unclassified.Add($path); continue }
    if ($policy.Count -ne 1) { $multiple.Add($path); continue }
    Assert-RepositorySpdxExpression -Expression ([string]$policy[0].spdxExpression)
    $classifications.Add($policy[0])
}
if ($unclassified.Count -ne 0) { throw "LICENSE_POLICY_UNCLASSIFIED_PATHS: $($unclassified -join ', ')" }
if ($multiple.Count -ne 0) { throw "LICENSE_POLICY_MULTIPLE_CLASSIFICATIONS: $($multiple -join ', ')" }
if ($classifications.Count -ne $tracked.Count) { throw 'LICENSE_POLICY_CLASSIFICATION_CARDINALITY_MISMATCH' }

Assert-CanonicalSha256 'LICENSE' '3F3D9E0024B1921B067D6F7F88DEB4A60CBE7A78E76C64E3F1D7FC3B779B9D04' 'LICENSE_POLICY_MPL_TEXT_MISMATCH'
Assert-CanonicalSha256 'LICENSE-APACHE-2.0' 'CFC7749B96F63BD31C3C42B5C471BF756814053E847C10F3EB003417BC523D30' 'LICENSE_POLICY_APACHE_TEXT_MISMATCH'
Assert-CanonicalSha256 'DCO.md' 'DAC2B0A921AAF4BCAF484DC082FBEA072398BEDECF5F1D4DCCE7E122BBE5D2D5' 'LICENSE_POLICY_DCO_TEXT_MISMATCH'

$licensing = Get-Content -LiteralPath (Join-Path $root 'LICENSING.md') -Raw
foreach ($required in @('MPL-2.0 OR Apache-2.0', 'MPL-2.0 AND Apache-2.0', 'Moving a file across a boundary does not automatically relicense', 'separate private repositories', 'not included in this repository')) {
    if (-not $licensing.Contains($required)) { throw "LICENSE_POLICY_DOCUMENT_INCOMPLETE: $required" }
}
if ($licensing.Contains('MPL / Apache')) { throw 'LICENSE_POLICY_AMBIGUOUS_DOCUMENT_EXPRESSION' }
if (Test-Path -LiteralPath (Join-Path $root 'packs/customer')) { throw 'LICENSE_POLICY_PRIVATE_CUSTOMER_REPOSITORY_INCLUDED' }

Assert-TextContains 'Directory.Build.props' '<RepositoryUrl>https://github.com/marcobiz/secure-integration-platform</RepositoryUrl>' 'LICENSE_POLICY_DOTNET_REPOSITORY_URL_INVALID'
Assert-TextContains 'Directory.Build.props' '<PackageLicenseExpression>MPL-2.0</PackageLicenseExpression>' 'LICENSE_POLICY_DOTNET_DEFAULT_INVALID'
Assert-TextContains 'Directory.Build.props' '<Company>ApoCert S.r.l.</Company>' 'LICENSE_POLICY_DOTNET_COMPANY_INVALID'
Assert-TextContains 'Directory.Build.props' '<Copyright>Copyright © 2026 ApoCert S.r.l.</Copyright>' 'LICENSE_POLICY_DOTNET_COPYRIGHT_INVALID'
Assert-TextContains 'sdk/dotnet/Broker.Sdk/Broker.Sdk.csproj' '<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>' 'LICENSE_POLICY_SDK_METADATA_INVALID'
Assert-TextContains 'src/Shared/SecureIntegration.Contracts/SecureIntegration.Contracts.csproj' '<PackageLicenseExpression>Apache-2.0</PackageLicenseExpression>' 'LICENSE_POLICY_CONTRACTS_METADATA_INVALID'

$adminPackage = Get-Content -LiteralPath (Join-Path $root 'src/Admin/Admin.Web/package.json') -Raw | ConvertFrom-Json
$adminLockText = Get-Content -LiteralPath (Join-Path $root 'src/Admin/Admin.Web/package-lock.json') -Raw
if ([string]$adminPackage.license -cne 'MPL-2.0' -or
    -not [regex]::IsMatch($adminLockText, '"packages"\s*:\s*\{\s*""\s*:\s*\{(?:(?!\}\s*,).)*"license"\s*:\s*"MPL-2\.0"', [Text.RegularExpressions.RegexOptions]::Singleline -bor [Text.RegularExpressions.RegexOptions]::CultureInvariant)) {
    throw 'LICENSE_POLICY_ADMIN_METADATA_INVALID'
}

Assert-TextContains 'docs/api/gateway-openapi.yaml' 'identifier: Apache-2.0' 'LICENSE_POLICY_OPENAPI_METADATA_INVALID'
Assert-TextContains 'docs/connectors/examples/LICENSE.md' 'SPDX-License-Identifier: MPL-2.0 OR Apache-2.0' 'LICENSE_POLICY_GENERIC_REFERENCE_METADATA_INVALID'
foreach ($dockerfile in @('src/Gateway/Gateway.Api/Dockerfile', 'src/Gateway/Gateway.Migrations/Dockerfile')) {
    foreach ($needle in @('org.opencontainers.image.source="https://github.com/marcobiz/secure-integration-platform"', 'org.opencontainers.image.vendor="ApoCert S.r.l."', 'org.opencontainers.image.licenses="MPL-2.0"', 'COPY LICENSE NOTICE /licenses/')) {
        Assert-TextContains $dockerfile $needle 'LICENSE_POLICY_OCI_METADATA_INVALID'
    }
}

$releaseTemplate = Get-Content -LiteralPath (Join-Path $root 'deploy/release-manifest.template.json') -Raw | ConvertFrom-Json
if ([string]$releaseTemplate.releaseChannel -cne 'public-technical-preview' -or [string]$releaseTemplate.licensePolicy.coreSourceArchive -cne 'MPL-2.0 AND Apache-2.0' -or
    [string]$releaseTemplate.licensePolicy.genericReference -cne 'MPL-2.0 OR Apache-2.0' -or $releaseTemplate.claims.publicReleaseGo -ne $false -or $releaseTemplate.claims.productionReady -ne $false) {
    throw 'LICENSE_POLICY_RELEASE_TEMPLATE_INVALID'
}
Assert-TextContains 'eng/generate-sbom.ps1' "licenseDeclared=`$LicenseExpression" 'LICENSE_POLICY_SBOM_METADATA_NOT_BOUND'

$publicSurfacePatterns = @(
    ('Pro' + 'prietary'),
    ('UN' + 'LICENSED'),
    ('example' + '.invalid')
)
$publicSurfaceExtensions = @('.cs', '.csproj', '.json', '.md', '.props', '.ps1', '.psm1', '.ts', '.tsx', '.yaml', '.yml', '.xml')
$placeholderHits = [Collections.Generic.List[string]]::new()
foreach ($path in $tracked) {
    $extension = [IO.Path]::GetExtension($path)
    if ($publicSurfaceExtensions -cnotcontains $extension -and $path -cnotin @('NOTICE', 'LICENSE')) { continue }
    $fullPath = Join-Path $root $path
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { continue }
    $text = Get-Content -LiteralPath $fullPath -Raw
    foreach ($pattern in $publicSurfacePatterns) {
        if ($text.Contains($pattern)) { $placeholderHits.Add("$path::$pattern") }
    }
}
if ($placeholderHits.Count -ne 0) { throw "LICENSE_POLICY_PUBLISHABLE_PLACEHOLDER_FOUND: $($placeholderHits -join ', ')" }

$result = [ordered]@{
    status = 'PASS'
    trackedPathsClassified = $classifications.Count
    unclassifiedPaths = $unclassified.Count
    multipleClassificationPaths = $multiple.Count
    licenseTextsCanonical = 'PASS'
    spdxValidation = 'PASS'
    packageMetadata = 'PASS'
    ociMetadata = 'PASS'
    releaseMetadata = 'PASS'
    sbomMetadata = 'PASS'
    publishablePlaceholders = 0
}
if ($Json) { $result | ConvertTo-Json -Compress } else { $result | Format-List | Out-String | Write-Host; Write-Host 'LICENSE_POLICY_PASS' }

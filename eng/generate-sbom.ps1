[CmdletBinding()]
param(
    [string] $Version,
    [string] $GatewayImage = 'secure-integration-m5-quickstart-gateway:latest',
    [string] $MigrationsImage,
    [string] $OutputDirectory,
    [switch] $SkipContainer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$versionProps = [xml](Get-Content -LiteralPath (Join-Path $root 'Directory.Build.props') -Raw)
$canonicalVersionNode = $versionProps.SelectSingleNode('/Project/PropertyGroup/ProductVersion')
$canonicalVersion = if ($null -eq $canonicalVersionNode) { '' } else { [string]$canonicalVersionNode.InnerText }
if ([string]::IsNullOrWhiteSpace($canonicalVersion)) { throw 'SBOM_PRODUCT_VERSION_SOURCE_MISSING' }
if ([string]::IsNullOrWhiteSpace($Version)) { $Version = $canonicalVersion }
if ($Version -cne $canonicalVersion) { throw 'SBOM_PRODUCT_VERSION_MISMATCH' }
$output = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { Join-Path $root '.artifacts\sbom' } else { [IO.Path]::GetFullPath($OutputDirectory) }
New-Item -ItemType Directory -Force -Path $output | Out-Null
Get-ChildItem -LiteralPath $output -File -Filter '*.spdx.json' -ErrorAction SilentlyContinue | Remove-Item -Force
Remove-Item -LiteralPath (Join-Path $output 'aggregate-manifest.json') -Force -ErrorAction SilentlyContinue

function ConvertTo-SpdxId([string] $Value) { 'SPDXRef-' + ($Value -replace '[^A-Za-z0-9.-]', '-') }

function Set-SpdxDescribedPackageLicense {
    param([Parameter(Mandatory = $true)][string] $Path, [Parameter(Mandatory = $true)][string] $LicenseExpression)
    $document = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $describedIds = @($document.relationships | Where-Object { [string]$_.relationshipType -ceq 'DESCRIBES' } | ForEach-Object { [string]$_.relatedSpdxElement })
    if ($describedIds.Count -eq 0) { throw "SBOM_DESCRIBED_PACKAGE_MISSING: $Path" }
    $subjects = @($document.packages | Where-Object { $describedIds -ccontains [string]$_.SPDXID })
    if ($subjects.Count -eq 0) { throw "SBOM_DESCRIBED_PACKAGE_MISSING: $Path" }
    foreach ($subject in $subjects) {
        foreach ($property in @(
            [pscustomobject]@{ name = 'licenseDeclared'; value = $LicenseExpression },
            [pscustomobject]@{ name = 'licenseConcluded'; value = $LicenseExpression },
            [pscustomobject]@{ name = 'copyrightText'; value = 'Copyright 2026 ApoCert S.r.l.' })) {
            if ($null -eq $subject.PSObject.Properties[[string]$property.name]) {
                $subject | Add-Member -MemberType NoteProperty -Name ([string]$property.name) -Value ([string]$property.value)
            }
            else { $subject.PSObject.Properties[[string]$property.name].Value = [string]$property.value }
        }
    }
    [IO.File]::WriteAllText($Path, ($document | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
}

function New-DotNetSbom {
    param([string] $Id, [string] $Name, [string] $LicenseExpression, [string[]] $LockFiles)
    $components = [ordered]@{}
    foreach ($relativeLock in $LockFiles) {
        $lock = Get-Content -LiteralPath (Join-Path $root $relativeLock) -Raw | ConvertFrom-Json
        foreach ($framework in $lock.dependencies.psobject.Properties) {
            foreach ($dependency in $framework.Value.psobject.Properties) {
                $resolvedProperty = $dependency.Value.psobject.Properties['resolved']
                $resolved = if ($null -eq $resolvedProperty) { '0.0.0-project' } else { [string]$resolvedProperty.Value }
                if ([string]::IsNullOrWhiteSpace($resolved)) { $resolved = '0.0.0-project' }
                $components[$dependency.Name.ToLowerInvariant()] = [pscustomobject]@{ Name = $dependency.Name; Version = $resolved }
            }
        }
    }
    $rootId = ConvertTo-SpdxId $Id
    $packages = [Collections.Generic.List[object]]::new()
    $packages.Add([ordered]@{ SPDXID=$rootId; name=$Name; versionInfo=$Version; downloadLocation='NOASSERTION'; filesAnalyzed=$false; licenseConcluded=$LicenseExpression; licenseDeclared=$LicenseExpression; copyrightText='Copyright 2026 ApoCert S.r.l.'; externalRefs=@([ordered]@{referenceCategory='PACKAGE-MANAGER';referenceType='purl';referenceLocator="pkg:generic/$($Name.ToLowerInvariant())@$Version"}) })
    $relationships = [Collections.Generic.List[object]]::new()
    $relationships.Add([ordered]@{ spdxElementId='SPDXRef-DOCUMENT'; relationshipType='DESCRIBES'; relatedSpdxElement=$rootId })
    foreach ($component in $components.Values) {
        $componentId = ConvertTo-SpdxId ("nuget-$($component.Name)-$($component.Version)")
        $packages.Add([ordered]@{ SPDXID=$componentId; name=$component.Name; versionInfo=$component.Version; downloadLocation='NOASSERTION'; filesAnalyzed=$false; licenseConcluded='NOASSERTION'; licenseDeclared='NOASSERTION'; copyrightText='NOASSERTION'; externalRefs=@([ordered]@{referenceCategory='PACKAGE-MANAGER';referenceType='purl';referenceLocator="pkg:nuget/$([Uri]::EscapeDataString($component.Name))@$($component.Version)"}) })
        $relationships.Add([ordered]@{ spdxElementId=$rootId; relationshipType='DEPENDS_ON'; relatedSpdxElement=$componentId })
    }
    $document = [ordered]@{
        spdxVersion='SPDX-2.3'; dataLicense='CC0-1.0'; SPDXID='SPDXRef-DOCUMENT'; name="$Name $Version"
        documentNamespace="https://github.com/marcobiz/secure-integration-platform/sbom/$Id/$Version"
        creationInfo=[ordered]@{ created=[DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); creators=@('Tool: eng/generate-sbom.ps1') }
        packages=$packages; relationships=$relationships
    }
    $path = Join-Path $output "$Id.spdx.json"
    [IO.File]::WriteAllText($path, ($document | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
}

New-DotNetSbom gateway 'SecureIntegration.Gateway.Api' 'MPL-2.0' @(
    'src/Gateway/Gateway.Api/packages.lock.json',
    'src/Gateway/Gateway.Infrastructure/packages.lock.json')
New-DotNetSbom broker 'SecureIntegration.Broker.Service' 'MPL-2.0' @(
    'src/Broker/Broker.Service/packages.lock.json',
    'src/Broker/Broker.Infrastructure.Windows/packages.lock.json',
    'src/Broker/Broker.Core/packages.lock.json')
New-DotNetSbom sdk-dotnet 'SecureIntegration.Broker.Sdk' 'Apache-2.0' @('sdk/dotnet/Broker.Sdk/packages.lock.json')
New-DotNetSbom connector-cli 'SecureIntegration.Connector.Cli' 'MPL-2.0' @('tools/connector-cli/packages.lock.json')
New-DotNetSbom fse2-officialtest-provisioner 'SecureIntegration.Tools.Fse2.OfficialTestProvisioner' 'MPL-2.0' @(
    'tools/fse2/OfficialTestProvisioner/packages.lock.json',
    'src/ConnectorPacks/Healthcare/Healthcare.FSE2/packages.lock.json')
New-DotNetSbom auth-certificate-signing 'SecureIntegration.Authentication.CertificateSigning' 'MPL-2.0' @(
    'src/Authentication/CertificateSigning/packages.lock.json',
    'src/Providers/Abstractions/packages.lock.json')

Push-Location (Join-Path $root 'src\Admin\Admin.Web')
try {
    & npm ci --ignore-scripts *> $null
    if ($LASTEXITCODE -ne 0) { throw 'SBOM_FRONTEND_RESTORE_FAILED' }
    $frontendSbom = (& npm sbom --sbom-format spdx | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'SBOM_FRONTEND_GENERATION_FAILED' }
    $adminSbomPath = Join-Path $output 'admin-frontend.spdx.json'
    [IO.File]::WriteAllText($adminSbomPath, $frontendSbom, [Text.UTF8Encoding]::new($false))
    Set-SpdxDescribedPackageLicense -Path $adminSbomPath -LicenseExpression 'MPL-2.0'
} finally { Pop-Location }

if (-not $SkipContainer) {
    & docker image inspect $GatewayImage *> $null
    if ($LASTEXITCODE -ne 0) {
        $GatewayImage = 'secure-integration-gateway:m5-sbom'
        & docker build --pull --file (Join-Path $root 'src\Gateway\Gateway.Api\Dockerfile') --tag $GatewayImage $root
        if ($LASTEXITCODE -ne 0) { throw 'SBOM_GATEWAY_IMAGE_BUILD_FAILED' }
    }

    function New-ContainerSbom([string] $Image, [string] $FileName) {
        $containerSbom = Join-Path $output $FileName
        if ($null -ne (Get-Command syft -ErrorAction SilentlyContinue)) {
            & syft scan $Image --output "spdx-json=$containerSbom"
            if ($LASTEXITCODE -ne 0) { throw 'SBOM_CONTAINER_SYFT_GENERATION_FAILED' }
        } else {
            & docker scout version *> $null
            if ($LASTEXITCODE -ne 0) { throw 'SBOM_CONTAINER_TOOL_MISSING' }
            & docker scout sbom --format spdx --output $containerSbom "local://$Image"
            if ($LASTEXITCODE -ne 0) { throw 'SBOM_CONTAINER_SCOUT_GENERATION_FAILED' }
        }
    }
    New-ContainerSbom -Image $GatewayImage -FileName 'gateway-container.spdx.json'
    Set-SpdxDescribedPackageLicense -Path (Join-Path $output 'gateway-container.spdx.json') -LicenseExpression 'MPL-2.0'
    if (-not [string]::IsNullOrWhiteSpace($MigrationsImage)) {
        & docker image inspect $MigrationsImage *> $null
        if ($LASTEXITCODE -ne 0) { throw 'SBOM_MIGRATIONS_IMAGE_MISSING' }
        New-ContainerSbom -Image $MigrationsImage -FileName 'migrations-container.spdx.json'
        Set-SpdxDescribedPackageLicense -Path (Join-Path $output 'migrations-container.spdx.json') -LicenseExpression 'MPL-2.0'
    }
}

$entries = foreach ($file in Get-ChildItem -LiteralPath $output -File -Filter '*.spdx.json' | Sort-Object Name) {
    $subjectLicenseExpression = if ($file.Name -ceq 'sdk-dotnet.spdx.json') { 'Apache-2.0' } else { 'MPL-2.0' }
    [ordered]@{ file=$file.Name; sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash; bytes=$file.Length; format='SPDX'; version=((Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json).spdxVersion); subjectLicenseExpression=$subjectLicenseExpression }
}
$aggregate = [ordered]@{ schemaVersion=1; productVersion=$Version; commitSha=(& git -C $root rev-parse HEAD).Trim(); generatedAtUtc=[DateTimeOffset]::UtcNow.ToString('O'); aggregateLicenseExpression='MPL-2.0 AND Apache-2.0'; artifacts=$entries }
$aggregatePath = Join-Path $output 'aggregate-manifest.json'
[IO.File]::WriteAllText($aggregatePath, ($aggregate | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
& (Join-Path $PSScriptRoot 'validate-sbom.ps1') -SbomDirectory $output -SkipContainer:$SkipContainer
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "SBOM_GENERATION_PASS: $output"

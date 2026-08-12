[CmdletBinding()]
param(
    [string] $Version = '0.1.0-dev',
    [string] $GatewayImage = 'secure-integration-m5-quickstart-gateway:latest',
    [switch] $SkipContainer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$output = Join-Path $root '.artifacts\sbom'
New-Item -ItemType Directory -Force -Path $output | Out-Null
Get-ChildItem -LiteralPath $output -File -Filter '*.spdx.json' -ErrorAction SilentlyContinue | Remove-Item -Force
Remove-Item -LiteralPath (Join-Path $output 'aggregate-manifest.json') -Force -ErrorAction SilentlyContinue

function ConvertTo-SpdxId([string] $Value) { 'SPDXRef-' + ($Value -replace '[^A-Za-z0-9.-]', '-') }

function New-DotNetSbom {
    param([string] $Id, [string] $Name, [string[]] $LockFiles)
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
    $packages.Add([ordered]@{ SPDXID=$rootId; name=$Name; versionInfo=$Version; downloadLocation='NOASSERTION'; filesAnalyzed=$false; licenseConcluded='NOASSERTION'; licenseDeclared='NOASSERTION'; copyrightText='NOASSERTION'; externalRefs=@([ordered]@{referenceCategory='PACKAGE-MANAGER';referenceType='purl';referenceLocator="pkg:generic/$($Name.ToLowerInvariant())@$Version"}) })
    $relationships = [Collections.Generic.List[object]]::new()
    $relationships.Add([ordered]@{ spdxElementId='SPDXRef-DOCUMENT'; relationshipType='DESCRIBES'; relatedSpdxElement=$rootId })
    foreach ($component in $components.Values) {
        $componentId = ConvertTo-SpdxId ("nuget-$($component.Name)-$($component.Version)")
        $packages.Add([ordered]@{ SPDXID=$componentId; name=$component.Name; versionInfo=$component.Version; downloadLocation='NOASSERTION'; filesAnalyzed=$false; licenseConcluded='NOASSERTION'; licenseDeclared='NOASSERTION'; copyrightText='NOASSERTION'; externalRefs=@([ordered]@{referenceCategory='PACKAGE-MANAGER';referenceType='purl';referenceLocator="pkg:nuget/$([Uri]::EscapeDataString($component.Name))@$($component.Version)"}) })
        $relationships.Add([ordered]@{ spdxElementId=$rootId; relationshipType='DEPENDS_ON'; relatedSpdxElement=$componentId })
    }
    $document = [ordered]@{
        spdxVersion='SPDX-2.3'; dataLicense='CC0-1.0'; SPDXID='SPDXRef-DOCUMENT'; name="$Name $Version"
        documentNamespace="https://example.invalid/secure-integration-platform/sbom/$Id/$Version"
        creationInfo=[ordered]@{ created=[DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'); creators=@('Tool: eng/generate-sbom.ps1') }
        packages=$packages; relationships=$relationships
    }
    $path = Join-Path $output "$Id.spdx.json"
    [IO.File]::WriteAllText($path, ($document | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
}

New-DotNetSbom gateway 'SecureIntegration.Gateway.Api' @(
    'src/Gateway/Gateway.Api/packages.lock.json',
    'src/Gateway/Gateway.Infrastructure/packages.lock.json')
New-DotNetSbom broker 'SecureIntegration.Broker.Service' @(
    'src/Broker/Broker.Service/packages.lock.json',
    'src/Broker/Broker.Infrastructure.Windows/packages.lock.json',
    'src/Broker/Broker.Core/packages.lock.json')
New-DotNetSbom sdk-dotnet 'SecureIntegration.Broker.Sdk' @('sdk/dotnet/Broker.Sdk/packages.lock.json')
New-DotNetSbom connector-cli 'SecureIntegration.Connector.Cli' @('tools/connector-cli/packages.lock.json')
New-DotNetSbom auth-certificate-signing 'SecureIntegration.Authentication.CertificateSigning' @(
    'src/Authentication/CertificateSigning/packages.lock.json',
    'src/Providers/Abstractions/packages.lock.json')

Push-Location (Join-Path $root 'src\Admin\Admin.Web')
try {
    & npm ci --ignore-scripts *> $null
    if ($LASTEXITCODE -ne 0) { throw 'SBOM_FRONTEND_RESTORE_FAILED' }
    $frontendSbom = (& npm sbom --sbom-format spdx | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'SBOM_FRONTEND_GENERATION_FAILED' }
    [IO.File]::WriteAllText((Join-Path $output 'admin-frontend.spdx.json'), $frontendSbom, [Text.UTF8Encoding]::new($false))
} finally { Pop-Location }

if (-not $SkipContainer) {
    & docker image inspect $GatewayImage *> $null
    if ($LASTEXITCODE -ne 0) {
        $GatewayImage = 'secure-integration-gateway:m5-sbom'
        & docker build --pull --file (Join-Path $root 'src\Gateway\Gateway.Api\Dockerfile') --tag $GatewayImage $root
        if ($LASTEXITCODE -ne 0) { throw 'SBOM_GATEWAY_IMAGE_BUILD_FAILED' }
    }

    $containerSbom = Join-Path $output 'gateway-container.spdx.json'
    if ($null -ne (Get-Command syft -ErrorAction SilentlyContinue)) {
        & syft scan $GatewayImage --output "spdx-json=$containerSbom"
        if ($LASTEXITCODE -ne 0) { throw 'SBOM_CONTAINER_SYFT_GENERATION_FAILED' }
    } else {
        & docker scout version *> $null
        if ($LASTEXITCODE -ne 0) { throw 'SBOM_CONTAINER_TOOL_MISSING' }
        & docker scout sbom --format spdx --output $containerSbom "local://$GatewayImage"
        if ($LASTEXITCODE -ne 0) { throw 'SBOM_CONTAINER_SCOUT_GENERATION_FAILED' }
    }
}

$entries = foreach ($file in Get-ChildItem -LiteralPath $output -File -Filter '*.spdx.json' | Sort-Object Name) {
    [ordered]@{ file=$file.Name; sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash; bytes=$file.Length; format='SPDX'; version=((Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json).spdxVersion) }
}
$aggregate = [ordered]@{ schemaVersion=1; productVersion=$Version; commitSha=(& git -C $root rev-parse HEAD).Trim(); generatedAtUtc=[DateTimeOffset]::UtcNow.ToString('O'); artifacts=$entries }
$aggregatePath = Join-Path $output 'aggregate-manifest.json'
[IO.File]::WriteAllText($aggregatePath, ($aggregate | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
& (Join-Path $PSScriptRoot 'validate-sbom.ps1') -SbomDirectory $output -SkipContainer:$SkipContainer
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "SBOM_GENERATION_PASS: $output"

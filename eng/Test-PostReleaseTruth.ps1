[CmdletBinding()]
param(
    [ValidateSet('All', 'Attestation', 'Documents', 'FutureContract')]
    [string] $TestName = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$releaseUrl = 'https://github.com/marcobiz/secure-integration-platform/releases/tag/v0.1.0-alpha.1'
$sourceCommit = 'ee3072be5e34a7b0477907a2580dcf454b8a4aba'
$expectedAssets = @{
    'admin-web-0.1.0-alpha.1.zip' = @(405298, '025e96940b3c70556d5ddd803691669243b024636151056ef1cb0f54c6a816dc')
    'gateway-container.spdx.json' = @(1986648, 'b2efe488015e4427b998ea9dd82d60d2426539d20a77f1a3ac841155536d9b23')
    'gateway-image-0.1.0-alpha.1-ee3072be5e34.tar' = @(100960256, '230bf346d7cd0f1958a86cc6bf5765bafb1bbac7253f8b18368e71d80fcf8f2f')
    'migrations-container.spdx.json' = @(1598160, '61b432f3794a32867a718b6d71c58f698015d7c2aab7fd1663f54d77a73e96e8')
    'migrations-image-0.1.0-alpha.1-ee3072be5e34.tar' = @(86171136, '02c6b91c594f91b9ec35229aafdb469768f34f840439dc0fa52ce316447915ea')
    'release-manifest.json' = @(9960, '431af84eb2264ceab03c39e666d1d5cfe23231cf4f7f7b8c6b3285f116f23385')
    'secure-integration-core-0.1.0-alpha.1-source.zip' = @(1274657, '7474c4b67e6a6c7687fd02cf76d3bef5ed4e296637119ea4d2a21ac8614fa817')
    'SecureIntegration.Broker.Sdk.0.1.0-alpha.1.nupkg' = @(82769, '6dd4192220b642f7359cc2e42c4d4e81b90ec1b77556e2bcd7195b1ae37369dc')
    'SHA256SUMS' = @(604, '256de635fe074c5cf0402ac77a56ab3c366bac823bc76f63e5a6de19e8adee53')
}

function Assert-True {
    param([Parameter(Mandatory = $true)][bool] $Condition, [Parameter(Mandatory = $true)][string] $FailureCode)
    if (-not $Condition) { throw $FailureCode }
}

function Assert-Contains {
    param([Parameter(Mandatory = $true)][string] $Text, [Parameter(Mandatory = $true)][string] $Needle, [Parameter(Mandatory = $true)][string] $FailureCode)
    if (-not $Text.Contains($Needle)) { throw $FailureCode }
}

function Assert-ExactStringSet {
    param([Parameter(Mandatory = $true)][object[]] $Actual, [Parameter(Mandatory = $true)][string[]] $Expected, [Parameter(Mandatory = $true)][string] $FailureCode)
    [string[]]$actualStrings = @($Actual | ForEach-Object { [string]$_ })
    [string[]]$expectedStrings = @($Expected)
    [Array]::Sort($actualStrings, [StringComparer]::Ordinal)
    [Array]::Sort($expectedStrings, [StringComparer]::Ordinal)
    if (($actualStrings -join "`n") -cne ($expectedStrings -join "`n")) { throw $FailureCode }
}

if ($TestName -in @('All', 'Attestation')) {
    $attestationPath = Join-Path $root 'docs\releases\0.1.0-alpha.1-publication-attestation.json'
    $attestationText = Get-Content -Raw -LiteralPath $attestationPath
    try { $attestation = $attestationText | ConvertFrom-Json }
    catch { throw 'POST_RELEASE_ATTESTATION_JSON_INVALID' }

    $allowedTopLevel = @(
        'schemaVersion', 'tag', 'tagTarget', 'releaseId', 'releaseUrl', 'publishedAt',
        'sourceCommit', 'uploadedAssetCount', 'productArtifactCount', 'publicSbomAssetCount',
        'internalSbomRecordCount', 'uploadedAssets', 'releaseManifestSha256',
        'sha256SumsSha256', 'manifestFalseGoClassification', 'publicSbomAssets',
        'internalBuildSbomRecords', 'productionReady', 'fse2OfficialTestQualified')
    Assert-ExactStringSet -Actual @($attestation.PSObject.Properties.Name) -Expected $allowedTopLevel -FailureCode 'POST_RELEASE_ATTESTATION_TOP_LEVEL_INVENTORY_INVALID'
    Assert-True ([int]$attestation.schemaVersion -eq 1) 'POST_RELEASE_ATTESTATION_SCHEMA_INVALID'
    Assert-True ([string]$attestation.tag -ceq 'v0.1.0-alpha.1') 'POST_RELEASE_ATTESTATION_TAG_INVALID'
    Assert-True ([string]$attestation.tagTarget -ceq $sourceCommit) 'POST_RELEASE_ATTESTATION_TAG_TARGET_INVALID'
    Assert-True ([int64]$attestation.releaseId -eq 375842367) 'POST_RELEASE_ATTESTATION_RELEASE_ID_INVALID'
    Assert-True ([string]$attestation.releaseUrl -ceq $releaseUrl) 'POST_RELEASE_ATTESTATION_RELEASE_URL_INVALID'
    Assert-True ([string]$attestation.publishedAt -ceq '2026-08-24T16:38:04Z') 'POST_RELEASE_ATTESTATION_PUBLISHED_AT_INVALID'
    Assert-True ([string]$attestation.sourceCommit -ceq $sourceCommit) 'POST_RELEASE_ATTESTATION_SOURCE_INVALID'
    Assert-True ([int]$attestation.uploadedAssetCount -eq 9 -and @($attestation.uploadedAssets).Count -eq 9) 'POST_RELEASE_ATTESTATION_ASSET_COUNT_INVALID'
    Assert-True ([int]$attestation.productArtifactCount -eq 5) 'POST_RELEASE_ATTESTATION_PRODUCT_COUNT_INVALID'
    Assert-True ([int]$attestation.publicSbomAssetCount -eq 2) 'POST_RELEASE_ATTESTATION_PUBLIC_SBOM_COUNT_INVALID'
    Assert-True ([int]$attestation.internalSbomRecordCount -eq 9) 'POST_RELEASE_ATTESTATION_INTERNAL_SBOM_COUNT_INVALID'

    $assetNames = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($asset in @($attestation.uploadedAssets)) {
        $name = [string]$asset.name
        Assert-True ($assetNames.Add($name)) 'POST_RELEASE_ATTESTATION_ASSET_DUPLICATE'
        Assert-True ($expectedAssets.ContainsKey($name)) 'POST_RELEASE_ATTESTATION_ASSET_UNEXPECTED'
        Assert-True (@($asset.PSObject.Properties).Count -eq 3) 'POST_RELEASE_ATTESTATION_ASSET_SHAPE_INVALID'
        Assert-True ([int64]$asset.bytes -eq [int64]$expectedAssets[$name][0]) "POST_RELEASE_ATTESTATION_ASSET_BYTES_INVALID: $name"
        Assert-True ([string]$asset.githubSha256 -ceq [string]$expectedAssets[$name][1]) "POST_RELEASE_ATTESTATION_ASSET_HASH_INVALID: $name"
    }
    Assert-True ($assetNames.Count -eq $expectedAssets.Count) 'POST_RELEASE_ATTESTATION_ASSET_INVENTORY_INVALID'
    Assert-True (-not $assetNames.Contains('manifest.json') -and -not $assetNames.Contains('manifest.json.sha256')) 'POST_RELEASE_ATTESTATION_PHANTOM_ASSET_PRESENT'
    Assert-True ([string]$attestation.releaseManifestSha256 -ceq [string]$expectedAssets['release-manifest.json'][1]) 'POST_RELEASE_ATTESTATION_MANIFEST_HASH_INVALID'
    Assert-True ([string]$attestation.sha256SumsSha256 -ceq [string]$expectedAssets['SHA256SUMS'][1]) 'POST_RELEASE_ATTESTATION_CHECKSUM_HASH_INVALID'
    Assert-True ([string]$attestation.manifestFalseGoClassification -ceq 'HISTORICAL_PRE_PUBLICATION_STATE_ERRATUM_NO_INTEGRITY_IMPACT') 'POST_RELEASE_ATTESTATION_FALSE_GO_CLASSIFICATION_INVALID'
    Assert-ExactStringSet -Actual @($attestation.publicSbomAssets) -Expected @('gateway-container.spdx.json', 'migrations-container.spdx.json') -FailureCode 'POST_RELEASE_ATTESTATION_PUBLIC_SBOM_INVALID'
    Assert-ExactStringSet -Actual @($attestation.internalBuildSbomRecords) -Expected @(
        'sbom/admin-frontend.spdx.json', 'sbom/aggregate-manifest.json',
        'sbom/auth-certificate-signing.spdx.json', 'sbom/broker.spdx.json',
        'sbom/connector-cli.spdx.json', 'sbom/gateway-container.spdx.json',
        'sbom/gateway.spdx.json', 'sbom/migrations-container.spdx.json',
        'sbom/sdk-dotnet.spdx.json') -FailureCode 'POST_RELEASE_ATTESTATION_INTERNAL_SBOM_INVALID'
    Assert-True ($attestation.productionReady -eq $false -and $attestation.fse2OfficialTestQualified -eq $false) 'POST_RELEASE_ATTESTATION_QUALIFICATION_INVALID'
    Assert-True (-not [regex]::IsMatch($attestationText, '(?i)([A-Z]:\\|/home/|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|authorization\s*:\s*(?:bearer|basic)|client_secret|activationCode)', [Text.RegularExpressions.RegexOptions]::CultureInvariant)) 'POST_RELEASE_ATTESTATION_PUBLIC_METADATA_INVALID'
    Write-Host 'POST_RELEASE_TRUTH_ATTESTATION_PASS'
}

if ($TestName -in @('All', 'Documents')) {
    $status = Get-Content -Raw -LiteralPath (Join-Path $root 'IMPLEMENTATION_STATUS.md')
    $readme = Get-Content -Raw -LiteralPath (Join-Path $root 'README.md')
    $backlog = Get-Content -Raw -LiteralPath (Join-Path $root 'docs\implementation\backlog.md')
    $notes = Get-Content -Raw -LiteralPath (Join-Path $root 'docs\releases\0.1.0-alpha.1.md')
    $body = Get-Content -Raw -LiteralPath (Join-Path $root 'docs\releases\0.1.0-alpha.1-release-body-update.md')
    foreach ($document in @($status, $readme, $notes, $body)) {
        Assert-Contains -Text $document -Needle $releaseUrl -FailureCode 'POST_RELEASE_DOCUMENT_RELEASE_URL_MISSING'
    }
    foreach ($document in @($readme, $notes, $body)) {
        Assert-Contains -Text $document -Needle 'not production-ready' -FailureCode 'POST_RELEASE_DOCUMENT_PRODUCTION_LIMIT_MISSING'
    }
    Assert-Contains -Text $status -Needle 'PRODUCTION_READY = NO' -FailureCode 'POST_RELEASE_STATUS_PRODUCTION_LIMIT_MISSING'
    Assert-Contains -Text $status -Needle "Baseline CURRENT: ``origin/main`` = ``$sourceCommit``" -FailureCode 'POST_RELEASE_STATUS_BASELINE_INVALID'
    foreach ($slice in @('ALPHA-LIC', 'ALPHA-SEC', 'ALPHA-DOC-04', 'ALPHA-REL')) {
        Assert-True ([regex]::IsMatch($status, "(?m)^\| $slice \| \*\*PASS")) "POST_RELEASE_STATUS_SLICE_NOT_PASS: $slice"
    }
    Assert-True (-not $status.Contains('governance candidate; non pubblicata') -and -not $status.Contains('**NOT CLOSED**')) 'POST_RELEASE_STATUS_STALE_CANDIDATE'
    Assert-True ([regex]::Matches($backlog, '(?m)^\| DOC-(?:CONTRACT-ROUTES|BROKER-CONTRACT|CONNECTOR-SPEC) \|').Count -eq 3) 'POST_RELEASE_BACKLOG_FOLLOWUP_INVENTORY_INVALID'
    Assert-True ([regex]::IsMatch($backlog, '(?m)^\| ALPHA-REL \|.*\| PASS \|')) 'POST_RELEASE_BACKLOG_ALPHA_REL_NOT_PASS'
    Assert-Contains -Text $backlog -Needle 'TM-083`..`TM-086' -FailureCode 'POST_RELEASE_BACKLOG_TM_DUPLICATES_MISSING'
    Assert-Contains -Text $backlog -Needle 'in gestione al writer FSE2' -FailureCode 'POST_RELEASE_BACKLOG_FSE2_WRITER_MISSING'
    foreach ($name in $expectedAssets.Keys) {
        Assert-Contains -Text $notes -Needle $name -FailureCode "POST_RELEASE_NOTES_ASSET_MISSING: $name"
        Assert-Contains -Text $body -Needle $name -FailureCode "POST_RELEASE_BODY_ASSET_MISSING: $name"
    }
    foreach ($document in @($notes, $body)) {
        Assert-True (-not $document.Contains('release-note candidate') -and -not $document.Contains('does not create the tag or GitHub Release')) 'POST_RELEASE_DOCUMENT_STALE_BODY_PRESENT'
        foreach ($match in [regex]::Matches($document, '\[[^\]]+\]\(([^)]+)\)')) {
            Assert-True ($match.Groups[1].Value.StartsWith('https://', [StringComparison]::Ordinal)) 'POST_RELEASE_DOCUMENT_RELATIVE_LINK_PRESENT'
        }
        Assert-Contains -Text $document -Needle 'historical state erratum' -FailureCode 'POST_RELEASE_DOCUMENT_ERRATUM_MISSING'
        Assert-Contains -Text $document -Needle 'nine uploaded assets' -FailureCode 'POST_RELEASE_DOCUMENT_ASSET_COUNT_MISSING'
    }
    Write-Host 'POST_RELEASE_TRUTH_DOCUMENTS_PASS'
}

if ($TestName -in @('All', 'FutureContract')) {
    $templatePath = Join-Path $root 'deploy\release-manifest.template.json'
    $templateText = Get-Content -Raw -LiteralPath $templatePath
    $template = $templateText | ConvertFrom-Json
    Assert-True ([int]$template.schemaVersion -eq 2) 'POST_RELEASE_FUTURE_CONTRACT_SCHEMA_INVALID'
    Assert-True ([string]$template.publication.state -ceq 'pre-publication-candidate' -and $template.publication.occurred -eq $false) 'POST_RELEASE_FUTURE_CONTRACT_STATE_INVALID'
    Assert-True ([string]$template.publication.candidateManifestName -ceq 'manifest.json' -and [string]$template.publication.publicManifestName -ceq 'release-manifest.json') 'POST_RELEASE_FUTURE_CONTRACT_MANIFEST_NAMES_INVALID'
    Assert-True ([string]$template.publication.checksumsName -ceq 'SHA256SUMS' -and [string]$template.publication.integrityClosure -ceq 'sidecar-or-publication-attestation-required') 'POST_RELEASE_FUTURE_CONTRACT_INTEGRITY_INVALID'
    Assert-ExactStringSet -Actual @($template.publication.publicSbomAssets) -Expected @('gateway-container.spdx.json', 'migrations-container.spdx.json') -FailureCode 'POST_RELEASE_FUTURE_CONTRACT_PUBLIC_SBOM_INVALID'
    Assert-True (@($template.publication.internalEvidenceSboms).Count -eq 9) 'POST_RELEASE_FUTURE_CONTRACT_INTERNAL_SBOM_INVALID'
    Assert-True ($null -eq $template.claims.PSObject.Properties['publicReleaseGo'] -and $template.claims.productionReady -eq $false) 'POST_RELEASE_FUTURE_CONTRACT_CLAIMS_INVALID'
    $contract = Get-Content -Raw -LiteralPath (Join-Path $root 'docs\releases\publication-contract.md')
    foreach ($needle in @('pre-publication candidate', 'release-manifest.json', 'publicSbomAssets', 'internalEvidenceSboms', 'sidecars or a repository-reviewed public publication')) {
        Assert-Contains -Text $contract -Needle $needle -FailureCode "POST_RELEASE_FUTURE_CONTRACT_DOCUMENT_INCOMPLETE: $needle"
    }
    Write-Host 'POST_RELEASE_TRUTH_FUTURE_CONTRACT_PASS'
}

Write-Host 'POST_RELEASE_TRUTH_PASS'

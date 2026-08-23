Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RecordSchemas = [ordered]@{
    'release-set.json' = 'secure-integration.alpha-release-set-record.v1'
    'targeted-tests.json' = 'secure-integration.alpha-release-targeted-tests.v1'
    'qualification-summary.json' = 'secure-integration.alpha-release-qualification-summary.v1'
    'tar-image-matrix.json' = 'secure-integration.alpha-release-tar-image-matrix.v1'
    'ci-summary.json' = 'secure-integration.alpha-release-ci-summary.v1'
    'golden-path.json' = 'secure-integration.alpha-release-golden-path.v1'
    'core-export.json' = 'secure-integration.alpha-release-core-export.v1'
    'postgresql-18.json' = 'secure-integration.alpha-release-postgresql18.v1'
    'cleanup.json' = 'secure-integration.alpha-release-cleanup.v1'
}

function Get-AlphaReleaseEvidenceRecordInventory {
    return @($script:RecordSchemas.Keys)
}

function Get-RequiredRecordProperty {
    param(
        [Parameter(Mandatory = $true)] $Record,
        [Parameter(Mandatory = $true)][string] $RecordName,
        [Parameter(Mandatory = $true)][string] $PropertyName
    )
    $properties = @($Record.PSObject.Properties | Where-Object { $_.Name -ceq $PropertyName })
    if ($properties.Count -ne 1 -or $null -eq $properties[0].Value) {
        throw "ALPHA_ART_EVIDENCE_RECORD_FIELD_MISSING: $RecordName/$PropertyName"
    }
    return $properties[0].Value
}

function Assert-StringPropertyEquals {
    param($Record, [string] $RecordName, [string] $PropertyName, [string] $ExpectedValue, [string] $ErrorCode)
    $actual = [string](Get-RequiredRecordProperty -Record $Record -RecordName $RecordName -PropertyName $PropertyName)
    if ($actual -cne $ExpectedValue) { throw "${ErrorCode}: $RecordName" }
}

function Assert-IntegerPropertyEquals {
    param($Record, [string] $RecordName, [string] $PropertyName, [int] $ExpectedValue)
    $actual = Get-RequiredRecordProperty -Record $Record -RecordName $RecordName -PropertyName $PropertyName
    if ($actual -isnot [ValueType] -or [int]$actual -ne $ExpectedValue) {
        throw "ALPHA_ART_EVIDENCE_RECORD_SEMANTICS_INVALID: $RecordName/$PropertyName"
    }
}

function Assert-BooleanPropertyEquals {
    param($Record, [string] $RecordName, [string] $PropertyName, [bool] $ExpectedValue)
    $actual = Get-RequiredRecordProperty -Record $Record -RecordName $RecordName -PropertyName $PropertyName
    if ($actual -isnot [bool] -or [bool]$actual -ne $ExpectedValue) {
        throw "ALPHA_ART_EVIDENCE_RECORD_SEMANTICS_INVALID: $RecordName/$PropertyName"
    }
}

function Assert-PassProperty {
    param($Record, [string] $RecordName, [string] $PropertyName)
    Assert-StringPropertyEquals -Record $Record -RecordName $RecordName -PropertyName $PropertyName -ExpectedValue 'PASS' -ErrorCode 'ALPHA_ART_EVIDENCE_RECORD_SEMANTICS_INVALID'
}

function Assert-AlphaReleaseEvidenceRecordInventory {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]] $RecordName)
    $seenIgnoreCase = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $seenOrdinal = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $allowedOrdinal = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($allowed in $script:RecordSchemas.Keys) { [void]$allowedOrdinal.Add($allowed) }
    foreach ($name in @($RecordName)) {
        if ($name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*\.json$') { throw "ALPHA_ART_EVIDENCE_RECORD_NAME_INVALID: $name" }
        if (-not $seenIgnoreCase.Add($name)) { throw "ALPHA_ART_EVIDENCE_RECORD_DUPLICATE: $name" }
        if (-not $allowedOrdinal.Contains($name)) { throw "ALPHA_ART_EVIDENCE_RECORD_UNKNOWN: $name" }
        [void]$seenOrdinal.Add($name)
    }
    foreach ($required in $script:RecordSchemas.Keys) {
        if (-not $seenOrdinal.Contains($required)) { throw "ALPHA_ART_EVIDENCE_RECORD_MISSING: $required" }
    }
    if ($seenOrdinal.Count -ne $script:RecordSchemas.Count) { throw 'ALPHA_ART_EVIDENCE_RECORD_INVENTORY_MISMATCH' }
}

function Assert-AlphaReleaseEvidenceRecord {
    param(
        [Parameter(Mandatory = $true)] $Record,
        [Parameter(Mandatory = $true)][string] $RecordName,
        [Parameter(Mandatory = $true)][string] $ExpectedRunId,
        [Parameter(Mandatory = $true)][string] $ExpectedSourceCommit,
        [Parameter(Mandatory = $true)][string] $ExpectedNormalizedDigest,
        [Parameter(Mandatory = $true)][string] $ExpectedProductVersion
    )
    if ($null -eq $Record -or $Record -is [Array] -or $Record -is [string] -or $Record -is [ValueType]) {
        throw "ALPHA_ART_EVIDENCE_RECORD_JSON_OBJECT_REQUIRED: $RecordName"
    }
    if (-not $script:RecordSchemas.Contains($RecordName)) { throw "ALPHA_ART_EVIDENCE_RECORD_UNKNOWN: $RecordName" }
    Assert-StringPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'schema' -ExpectedValue ([string]$script:RecordSchemas[$RecordName]) -ErrorCode 'ALPHA_ART_EVIDENCE_RECORD_SCHEMA_MISMATCH'
    Assert-StringPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'runId' -ExpectedValue $ExpectedRunId -ErrorCode 'ALPHA_ART_EVIDENCE_RUN_ID_MISMATCH'
    Assert-StringPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'sourceRevision' -ExpectedValue $ExpectedSourceCommit -ErrorCode 'ALPHA_ART_EVIDENCE_SOURCE_SHA_MISMATCH'
    Assert-StringPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'normalizedInventorySha256' -ExpectedValue $ExpectedNormalizedDigest -ErrorCode 'ALPHA_ART_EVIDENCE_NORMALIZED_DIGEST_MISMATCH'
    Assert-StringPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'productVersion' -ExpectedValue $ExpectedProductVersion -ErrorCode 'ALPHA_ART_EVIDENCE_PRODUCT_VERSION_MISMATCH'

    switch -CaseSensitive ($RecordName) {
        'release-set.json' {
            $manifestBytes = Get-RequiredRecordProperty -Record $Record -RecordName $RecordName -PropertyName 'releaseManifestBytes'
            $manifestSha = [string](Get-RequiredRecordProperty -Record $Record -RecordName $RecordName -PropertyName 'releaseManifestSha256')
            if ([long]$manifestBytes -le 0 -or $manifestSha -cnotmatch '^[0-9A-F]{64}$') { throw "ALPHA_ART_EVIDENCE_RECORD_SEMANTICS_INVALID: $RecordName/releaseManifest" }
            Assert-IntegerPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'artifactCount' -ExpectedValue 5
            Assert-IntegerPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'sbomSubjectCount' -ExpectedValue 2
        }
        'targeted-tests.json' {
            Assert-PassProperty -Record $Record -RecordName $RecordName -PropertyName 'status'
            Assert-BooleanPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'zeroSkip' -ExpectedValue $true
            if (@(Get-RequiredRecordProperty -Record $Record -RecordName $RecordName -PropertyName 'namedTests').Count -lt 1) { throw "ALPHA_ART_EVIDENCE_RECORD_SEMANTICS_INVALID: $RecordName/namedTests" }
        }
        'qualification-summary.json' {
            Assert-PassProperty -Record $Record -RecordName $RecordName -PropertyName 'status'
            Assert-IntegerPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'releaseSets' -ExpectedValue 2
            Assert-IntegerPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'artifactCountPerSet' -ExpectedValue 5
            Assert-IntegerPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'containerSbomSubjectsPerSet' -ExpectedValue 2
            Assert-StringPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'normalizedDigestRun1' -ExpectedValue $ExpectedNormalizedDigest -ErrorCode 'ALPHA_ART_EVIDENCE_NORMALIZED_DIGEST_MISMATCH'
            Assert-StringPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'normalizedDigestRun2' -ExpectedValue $ExpectedNormalizedDigest -ErrorCode 'ALPHA_ART_EVIDENCE_NORMALIZED_DIGEST_MISMATCH'
            Assert-BooleanPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'normalizedDigestStable' -ExpectedValue $true
        }
        'tar-image-matrix.json' {
            $runs = @(Get-RequiredRecordProperty -Record $Record -RecordName $RecordName -PropertyName 'runs')
            if ($runs.Count -ne 2) { throw "ALPHA_ART_EVIDENCE_RECORD_SEMANTICS_INVALID: $RecordName/runs" }
            foreach ($run in $runs) {
                $roles = @(@(Get-RequiredRecordProperty -Record $run -RecordName $RecordName -PropertyName 'containers') | ForEach-Object { [string]$_.role } | Sort-Object)
                if ($roles.Count -ne 2 -or $roles[0] -cne 'gateway' -or $roles[1] -cne 'migrations') { throw "ALPHA_ART_EVIDENCE_RECORD_SEMANTICS_INVALID: $RecordName/containers" }
                foreach ($container in @($run.containers)) {
                    if ($container.subjectBound -ne $true) { throw "ALPHA_ART_EVIDENCE_RECORD_SEMANTICS_INVALID: $RecordName/subjectBound" }
                }
            }
        }
        'ci-summary.json' {
            foreach ($property in @('general','m5Admin')) {
                $gate = Get-RequiredRecordProperty -Record $Record -RecordName $RecordName -PropertyName $property
                if ([string]$gate.conclusion -cne 'success' -or [int]$gate.passed -ne [int]$gate.total -or [int]$gate.total -le 0) { throw "ALPHA_ART_EVIDENCE_RECORD_SEMANTICS_INVALID: $RecordName/$property" }
            }
            Assert-BooleanPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'automaticRerunUsed' -ExpectedValue $false
        }
        'golden-path.json' {
            Assert-PassProperty -Record $Record -RecordName $RecordName -PropertyName 'status'
            Assert-IntegerPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'positiveOutboundCount' -ExpectedValue 1
            Assert-BooleanPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'auditMetadataOnly' -ExpectedValue $true
            Assert-BooleanPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'logsRedacted' -ExpectedValue $true
            foreach ($property in @('remainingContainers','remainingNetworks','remainingVolumes','remainingSyntheticResources')) { Assert-IntegerPropertyEquals -Record $Record -RecordName $RecordName -PropertyName $property -ExpectedValue 0 }
        }
        'core-export.json' {
            Assert-PassProperty -Record $Record -RecordName $RecordName -PropertyName 'status'
            if ([int](Get-RequiredRecordProperty -Record $Record -RecordName $RecordName -PropertyName 'fileCount') -le 0) { throw "ALPHA_ART_EVIDENCE_RECORD_SEMANTICS_INVALID: $RecordName/fileCount" }
            Assert-IntegerPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'warnings' -ExpectedValue 0
            Assert-IntegerPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'errors' -ExpectedValue 0
            Assert-PassProperty -Record $Record -RecordName $RecordName -PropertyName 'secretScan'
            Assert-PassProperty -Record $Record -RecordName $RecordName -PropertyName 'sidecar'
        }
        'postgresql-18.json' {
            Assert-PassProperty -Record $Record -RecordName $RecordName -PropertyName 'status'
            foreach ($property in @('freshMigration','idempotentNoOp','rlsAndLeastPrivilege','integrationTests')) { Assert-PassProperty -Record $Record -RecordName $RecordName -PropertyName $property }
        }
        'cleanup.json' {
            Assert-PassProperty -Record $Record -RecordName $RecordName -PropertyName 'status'
            foreach ($property in @('candidateTagsRemaining','taskOwnedImageTagsRemaining','taskOwnedContainersRemaining','taskOwnedNetworksRemaining','taskOwnedVolumesRemaining')) { Assert-IntegerPropertyEquals -Record $Record -RecordName $RecordName -PropertyName $property -ExpectedValue 0 }
            Assert-BooleanPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'foreignResourcesPreserved' -ExpectedValue $true
            Assert-BooleanPropertyEquals -Record $Record -RecordName $RecordName -PropertyName 'automaticPruneUsed' -ExpectedValue $false
        }
    }
}

Export-ModuleMember -Function Get-AlphaReleaseEvidenceRecordInventory, Assert-AlphaReleaseEvidenceRecordInventory, Assert-AlphaReleaseEvidenceRecord

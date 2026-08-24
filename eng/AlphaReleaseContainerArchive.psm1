Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AlphaReleaseSha256Hex {
    param([Parameter(Mandatory = $true)][string] $LiteralPath)
    $stream = [IO.File]::OpenRead($LiteralPath)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace('-', '') }
    finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Test-AlphaReleaseTarEntryPath {
    param([Parameter(Mandatory = $true)][string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $candidate = if ($Path.EndsWith('/', [StringComparison]::Ordinal)) { $Path.Substring(0, $Path.Length - 1) } else { $Path }
    if ([string]::IsNullOrWhiteSpace($candidate) -or $candidate.StartsWith('/', [StringComparison]::Ordinal) -or
        $candidate.Contains('\') -or $candidate.Contains(':') -or $candidate.Contains('//')) { return $false }
    foreach ($character in $candidate.ToCharArray()) { if ([char]::IsControl($character)) { return $false } }
    foreach ($segment in $candidate.Split('/')) { if ($segment.Length -eq 0 -or $segment -eq '.' -or $segment -eq '..') { return $false } }
    return $true
}

function Get-AlphaReleaseContainerTarIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $ArchivePath,
        [Parameter(Mandatory = $true)][ValidateSet('gateway', 'migrations')][string] $Role,
        [Parameter(Mandatory = $true)][string] $ExpectedReference,
        [Parameter(Mandatory = $true)][string] $ProductVersion,
        [Parameter(Mandatory = $true)][string] $SourceCommit,
        [Parameter(Mandatory = $true)][string] $InspectionDirectory
    )

    $archive = [IO.Path]::GetFullPath($ArchivePath)
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) { throw "ALPHA_ARTIFACT_TAR_MISSING: $Role" }
    if ($ExpectedReference -cnotmatch '^secure-integration-(?:gateway|migrations):0\.1\.0-alpha\.1-[0-9a-f]{12}$') {
        throw "ALPHA_ARTIFACT_TAR_EXPECTED_REPOTAG_INVALID: $Role"
    }
    if ($SourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw "ALPHA_ARTIFACT_TAR_SOURCE_REVISION_INVALID: $Role" }
    if ($ProductVersion -cne '0.1.0-alpha.1') { throw "ALPHA_ARTIFACT_TAR_PRODUCT_VERSION_INVALID: $Role" }
    $tarCommands = @(Get-Command tar -CommandType Application -ErrorAction SilentlyContinue)
    if ($tarCommands.Count -eq 0) { throw 'ALPHA_ARTIFACT_TAR_TOOL_MISSING' }
    $tarCommand = $tarCommands[0]

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $entries = @(& $tarCommand.Source -tf $archive 2>$null | ForEach-Object { [string]$_ })
        $listExitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousErrorActionPreference }
    if ($listExitCode -ne 0 -or $entries.Count -eq 0) { throw "ALPHA_ARTIFACT_TAR_UNREADABLE: $Role" }

    $entryCounts = New-Object 'Collections.Generic.Dictionary[string,int]' ([StringComparer]::Ordinal)
    $entriesIgnoreCase = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        if (-not (Test-AlphaReleaseTarEntryPath -Path $entry)) { throw "ALPHA_ARTIFACT_TAR_ENTRY_PATH_INVALID: $Role" }
        $normalized = if ($entry.EndsWith('/', [StringComparison]::Ordinal)) { $entry.Substring(0, $entry.Length - 1) } else { $entry }
        if (-not $entriesIgnoreCase.Add($normalized)) { throw "ALPHA_ARTIFACT_TAR_ENTRY_DUPLICATE: $Role" }
        $entryCounts.Add($normalized, 1)
    }
    if (-not $entryCounts.ContainsKey('manifest.json')) { throw "ALPHA_ARTIFACT_TAR_MANIFEST_MISSING: $Role" }

    $inspection = [IO.Path]::GetFullPath($InspectionDirectory)
    if (Test-Path -LiteralPath $inspection) { throw "ALPHA_ARTIFACT_TAR_INSPECTION_NOT_EMPTY: $Role" }
    New-Item -ItemType Directory -Path $inspection | Out-Null
    try {
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & $tarCommand.Source -xf $archive -C $inspection manifest.json 2>$null
            $manifestExtractExitCode = $LASTEXITCODE
        }
        finally { $ErrorActionPreference = $previousErrorActionPreference }
        if ($manifestExtractExitCode -ne 0) { throw "ALPHA_ARTIFACT_TAR_MANIFEST_EXTRACT_FAILED: $Role" }
        try { $imageManifest = @(Get-Content -LiteralPath (Join-Path $inspection 'manifest.json') -Raw | ConvertFrom-Json) }
        catch { throw "ALPHA_ARTIFACT_TAR_MANIFEST_INVALID: $Role" }
        if ($imageManifest.Count -ne 1) { throw "ALPHA_ARTIFACT_TAR_MANIFEST_CARDINALITY_INVALID: $Role" }
        $repoTags = @($imageManifest[0].RepoTags | ForEach-Object { [string]$_ })
        if ($repoTags.Count -ne 1 -or $repoTags[0] -cne $ExpectedReference) { throw "ALPHA_ARTIFACT_TAR_REPOTAG_MISMATCH: $Role" }

        $configPath = [string]$imageManifest[0].Config
        if (-not (Test-AlphaReleaseTarEntryPath -Path $configPath) -or -not $entryCounts.ContainsKey($configPath)) {
            throw "ALPHA_ARTIFACT_TAR_CONFIG_PATH_INVALID: $Role"
        }
        $declaredConfigDigest = if ($configPath -cmatch '^blobs/sha256/([0-9a-f]{64})$') { $Matches[1] }
            elseif ($configPath -cmatch '^([0-9a-f]{64})\.json$') { $Matches[1] }
            else { '' }
        if ([string]::IsNullOrWhiteSpace($declaredConfigDigest)) { throw "ALPHA_ARTIFACT_TAR_CONFIG_PATH_INVALID: $Role" }

        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & $tarCommand.Source -xf $archive -C $inspection $configPath 2>$null
            $configExtractExitCode = $LASTEXITCODE
        }
        finally { $ErrorActionPreference = $previousErrorActionPreference }
        if ($configExtractExitCode -ne 0) { throw "ALPHA_ARTIFACT_TAR_CONFIG_EXTRACT_FAILED: $Role" }
        $configFullPath = Join-Path $inspection $configPath.Replace('/', [IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $configFullPath -PathType Leaf)) { throw "ALPHA_ARTIFACT_TAR_CONFIG_MISSING: $Role" }
        $actualConfigDigest = (Get-AlphaReleaseSha256Hex -LiteralPath $configFullPath).ToLowerInvariant()
        if ($actualConfigDigest -cne $declaredConfigDigest) { throw "ALPHA_ARTIFACT_TAR_CONFIG_DIGEST_MISMATCH: $Role" }

        $configImageId = 'sha256:' + $actualConfigDigest
        $ociManifestImageId = ''
        $boundImageIds = @($configImageId)
        $derivedImageId = $configImageId
        if ($entryCounts.ContainsKey('index.json')) {
            $previousErrorActionPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                & $tarCommand.Source -xf $archive -C $inspection index.json 2>$null
                $indexExtractExitCode = $LASTEXITCODE
            }
            finally { $ErrorActionPreference = $previousErrorActionPreference }
            if ($indexExtractExitCode -ne 0) { throw "ALPHA_ARTIFACT_TAR_INDEX_EXTRACT_FAILED: $Role" }
            try { $indexDocument = Get-Content -LiteralPath (Join-Path $inspection 'index.json') -Raw | ConvertFrom-Json }
            catch { throw "ALPHA_ARTIFACT_TAR_INDEX_INVALID: $Role" }
            $descriptors = @($indexDocument.manifests)
            if ([int]$indexDocument.schemaVersion -ne 2 -or $descriptors.Count -ne 1) { throw "ALPHA_ARTIFACT_TAR_INDEX_CARDINALITY_INVALID: $Role" }
            $descriptorDigest = [string]$descriptors[0].digest
            if ($descriptorDigest -cnotmatch '^sha256:([0-9a-f]{64})$') { throw "ALPHA_ARTIFACT_TAR_INDEX_DIGEST_INVALID: $Role" }
            $imageManifestDigest = $Matches[1]
            $imageManifestPath = "blobs/sha256/$imageManifestDigest"
            if (-not $entryCounts.ContainsKey($imageManifestPath)) { throw "ALPHA_ARTIFACT_TAR_IMAGE_MANIFEST_MISSING: $Role" }
            $annotatedReference = [string]$descriptors[0].annotations.'io.containerd.image.name'
            if (-not [string]::IsNullOrWhiteSpace($annotatedReference) -and
                $annotatedReference -cne $ExpectedReference -and $annotatedReference -cne ('docker.io/library/' + $ExpectedReference)) {
                throw "ALPHA_ARTIFACT_TAR_INDEX_REPOTAG_MISMATCH: $Role"
            }
            $previousErrorActionPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                & $tarCommand.Source -xf $archive -C $inspection $imageManifestPath 2>$null
                $imageManifestExtractExitCode = $LASTEXITCODE
            }
            finally { $ErrorActionPreference = $previousErrorActionPreference }
            if ($imageManifestExtractExitCode -ne 0) { throw "ALPHA_ARTIFACT_TAR_IMAGE_MANIFEST_EXTRACT_FAILED: $Role" }
            $imageManifestFullPath = Join-Path $inspection $imageManifestPath.Replace('/', [IO.Path]::DirectorySeparatorChar)
            if ((Get-AlphaReleaseSha256Hex -LiteralPath $imageManifestFullPath).ToLowerInvariant() -cne $imageManifestDigest) {
                throw "ALPHA_ARTIFACT_TAR_IMAGE_MANIFEST_DIGEST_MISMATCH: $Role"
            }
            if ([long]$descriptors[0].size -ne [IO.FileInfo]::new($imageManifestFullPath).Length) { throw "ALPHA_ARTIFACT_TAR_IMAGE_MANIFEST_SIZE_MISMATCH: $Role" }
            try { $ociImageManifest = Get-Content -LiteralPath $imageManifestFullPath -Raw | ConvertFrom-Json }
            catch { throw "ALPHA_ARTIFACT_TAR_IMAGE_MANIFEST_INVALID: $Role" }
            if ([int]$ociImageManifest.schemaVersion -ne 2 -or [string]$ociImageManifest.config.digest -cne ('sha256:' + $actualConfigDigest) -or
                [long]$ociImageManifest.config.size -ne [IO.FileInfo]::new($configFullPath).Length) {
                throw "ALPHA_ARTIFACT_TAR_IMAGE_MANIFEST_CONFIG_MISMATCH: $Role"
            }
            $ociManifestImageId = $descriptorDigest
            if ($boundImageIds -cnotcontains $ociManifestImageId) { $boundImageIds += $ociManifestImageId }
            $derivedImageId = $ociManifestImageId
        }

        try { $configDocument = Get-Content -LiteralPath $configFullPath -Raw | ConvertFrom-Json }
        catch { throw "ALPHA_ARTIFACT_TAR_CONFIG_INVALID: $Role" }
        $runtimeConfig = $configDocument.config
        if ($null -eq $runtimeConfig) { throw "ALPHA_ARTIFACT_TAR_CONFIG_INVALID: $Role" }
        $expectedEntrypoint = if ($Role -ceq 'gateway') { @('dotnet', 'SecureIntegration.Gateway.Api.dll') }
            else { @('dotnet', 'SecureIntegration.Gateway.Migrations.dll', 'apply') }
        $actualEntrypoint = @($runtimeConfig.Entrypoint | ForEach-Object { [string]$_ })
        if ($actualEntrypoint.Count -ne $expectedEntrypoint.Count) { throw "ALPHA_ARTIFACT_TAR_CONFIG_PROFILE_MISMATCH: $Role" }
        for ($index = 0; $index -lt $expectedEntrypoint.Count; $index++) {
            if ($actualEntrypoint[$index] -cne $expectedEntrypoint[$index]) { throw "ALPHA_ARTIFACT_TAR_CONFIG_PROFILE_MISMATCH: $Role" }
        }
        if ([string]$runtimeConfig.Labels.'org.opencontainers.image.version' -cne $ProductVersion -or
            [string]$runtimeConfig.Labels.'org.opencontainers.image.revision' -cne $SourceCommit -or
            [string]$runtimeConfig.Labels.'org.opencontainers.image.source' -cne 'https://github.com/marcobiz/secure-integration-platform' -or
            [string]$runtimeConfig.Labels.'org.opencontainers.image.vendor' -cne 'ApoCert S.r.l.' -or
            [string]$runtimeConfig.Labels.'org.opencontainers.image.licenses' -cne 'MPL-2.0' -or
            [string]$runtimeConfig.Labels.'org.opencontainers.image.title' -cne $(if ($Role -ceq 'gateway') { 'Secure Integration Platform Gateway' } else { 'Secure Integration Platform Migrations' }) -or
            [string]::IsNullOrWhiteSpace([string]$runtimeConfig.User) -or [string]$runtimeConfig.User -in @('0', 'root')) {
            throw "ALPHA_ARTIFACT_TAR_CONFIG_PROFILE_MISMATCH: $Role"
        }
        if ($Role -ceq 'gateway' -and ($null -eq $runtimeConfig.Healthcheck -or @($runtimeConfig.Healthcheck.Test).Count -eq 0)) {
            throw "ALPHA_ARTIFACT_TAR_CONFIG_PROFILE_MISMATCH: $Role"
        }

        return [pscustomobject]@{
            role = $Role
            artifactSha256 = Get-AlphaReleaseSha256Hex -LiteralPath $archive
            repoTag = $repoTags[0]
            configPath = $configPath
            configSha256 = $actualConfigDigest.ToUpperInvariant()
            configImageId = $configImageId
            ociManifestImageId = $ociManifestImageId
            boundImageIds = @($boundImageIds)
            imageId = $derivedImageId
        }
    }
    finally {
        if (Test-Path -LiteralPath $inspection) {
            [IO.Directory]::Delete($inspection, $true)
        }
    }
}

Export-ModuleMember -Function Get-AlphaReleaseContainerTarIdentity

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $RunDirectory,
    [string] $SecondRunDirectory,
    [string] $ExpectedSourceCommit,
    [string] $DotNetPath,
    [switch] $RunConsumerInstall,
    [switch] $RunContainerRuntime
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

function Test-ArchiveEntryPath([string] $Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.StartsWith('/', [StringComparison]::Ordinal) -or $Path.Contains('\') -or $Path.Contains('//')) { return $false }
    foreach ($segment in $Path.Split('/')) { if ($segment.Length -eq 0 -or $segment -eq '.' -or $segment -eq '..') { return $false } }
    return $true
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

function Ensure-ImageAvailable([string] $Reference, [string] $ArchivePath) {
    & docker image inspect $Reference *> $null
    if ($LASTEXITCODE -eq 0) { return }
    & docker image load --input $ArchivePath *> $null
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_IMAGE_LOAD_FAILED' }
    & docker image inspect $Reference *> $null
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_IMAGE_NOT_AVAILABLE' }
}

try {
    $manifest = Read-Manifest -Directory $run
    $productVersion = [string]$manifest.version
    $sourceCommit = [string]$manifest.sourceRevision
    if ($productVersion -cne '0.1.0-alpha.1') { throw 'ALPHA_ARTIFACT_PRODUCT_VERSION_MISMATCH' }
    if ($sourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'ALPHA_ARTIFACT_SOURCE_REVISION_INVALID' }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedSourceCommit) -and $sourceCommit -cne $ExpectedSourceCommit) { throw 'ALPHA_ARTIFACT_SOURCE_REVISION_MISMATCH' }
    if ($manifest.claims.publicReleaseGo -ne $false -or $manifest.claims.productionReady -ne $false) { throw 'ALPHA_ARTIFACT_RELEASE_CLAIM_INVALID' }
    if ([string]$manifest.versionIdentity.protocolVersion -cne '1.0' -or [string]$manifest.versionIdentity.canonicalConnectorVersion -cne '1.0.0' -or
        [string]$manifest.versionIdentity.openApiVersion -cne $productVersion -or [string]$manifest.versionIdentity.imageRevision -cne $sourceCommit) {
        throw 'ALPHA_ARTIFACT_VERSION_IDENTITY_INVALID'
    }

    $manifestPath = Join-Path $run 'manifest.json'
    $manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    if ((Get-Content -LiteralPath (Join-Path $run 'manifest.json.sha256') -Raw).Trim() -cne "$manifestSha256  manifest.json") {
        throw 'ALPHA_ARTIFACT_MANIFEST_SIDECAR_MISMATCH'
    }

    $checksumPath = Join-Path $run 'SHA256SUMS'
    $seenChecksums = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($line in Get-Content -LiteralPath $checksumPath) {
        if ($line -cnotmatch '^([0-9A-F]{64})  ([^\\]+)$') { throw 'ALPHA_ARTIFACT_CHECKSUM_FORMAT_INVALID' }
        $expectedHash = $Matches[1]
        $relative = $Matches[2]
        if (-not (Test-ArchiveEntryPath -Path $relative) -or -not $seenChecksums.Add($relative)) { throw 'ALPHA_ARTIFACT_CHECKSUM_PATH_INVALID' }
        $fullPath = [IO.Path]::GetFullPath((Join-Path $run $relative))
        if (-not $fullPath.StartsWith($run + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            throw 'ALPHA_ARTIFACT_CHECKSUM_TARGET_MISSING'
        }
        if ((Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash -cne $expectedHash) { throw 'ALPHA_ARTIFACT_CHECKSUM_MISMATCH' }
    }
    foreach ($required in (Get-ReleaseInventory -Directory $run) + @('manifest.json', 'manifest.json.sha256')) {
        if (-not $seenChecksums.Contains($required)) { throw "ALPHA_ARTIFACT_CHECKSUM_COVERAGE_MISSING: $required" }
    }

    $artifactFiles = @(Get-ChildItem -LiteralPath (Join-Path $run 'artifacts') -File)
    if ($artifactFiles.Count -ne 5) { throw 'ALPHA_ARTIFACT_FILE_COUNT_INVALID' }
    foreach ($entry in @($manifest.artifacts)) {
        $file = Join-Path $run ([string]$entry.file)
        if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or [IO.FileInfo]::new($file).Length -ne [long]$entry.bytes -or
            (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -cne [string]$entry.sha256) { throw 'ALPHA_ARTIFACT_MANIFEST_FILE_MISMATCH' }
    }
    foreach ($file in $artifactFiles) {
        if ($file.Name -match '(?i)(healthcare|fse2|azure|deployment|evidence|secret|\.env|\.p12|\.pfx|\.pem|\.key)') { throw 'ALPHA_ARTIFACT_FORBIDDEN_FILE_NAME' }
    }

    $package = @(Get-ChildItem -LiteralPath (Join-Path $run 'artifacts') -File -Filter '*.nupkg')
    if ($package.Count -ne 1 -or $package[0].Name -cne "SecureIntegration.Broker.Sdk.$productVersion.nupkg") { throw 'ALPHA_ARTIFACT_NUGET_INVENTORY_INVALID' }
    [string[]]$packageEntries = @(Get-ZipEntries -ArchivePath $package[0].FullName)
    foreach ($entry in $packageEntries) {
        if (-not (Test-ArchiveEntryPath -Path $entry) -or $entry -cnotmatch '^(?:_rels/\.rels|\[Content_Types\]\.xml|SecureIntegration\.Broker\.Sdk\.nuspec|package/services/metadata/core-properties/[0-9a-f-]+\.psmdcp|lib/(?:net10\.0|netstandard2\.0)/SecureIntegration\.(?:Broker\.Sdk|Contracts)\.(?:dll|xml))$') {
            throw "ALPHA_ARTIFACT_NUGET_CONTENT_NOT_ALLOWLISTED: $entry"
        }
    }
    $packageExtract = Join-Path $testRoot 'package'
    [IO.Compression.ZipFile]::ExtractToDirectory($package[0].FullName, $packageExtract)
    [xml]$nuspec = Get-Content -LiteralPath (Join-Path $packageExtract 'SecureIntegration.Broker.Sdk.nuspec') -Raw
    if ([string]$nuspec.package.metadata.version -cne $productVersion) { throw 'ALPHA_ARTIFACT_NUGET_VERSION_MISMATCH' }
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
    & (Join-Path $coreExtract 'eng\Test-OpenSourceCoreInventory.ps1') -ExportDirectory $coreExtract -ExpectedSourceCommit $sourceCommit *> $null
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_CORE_INVENTORY_FAILED' }
    & (Join-Path $coreExtract 'eng\scan-secrets.ps1') *> $null
    if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_CORE_SECRET_SCAN_FAILED' }
    $coreManifest = Get-Content -LiteralPath (Join-Path $coreExtract 'OPEN_SOURCE_EXPORT_MANIFEST.json') -Raw | ConvertFrom-Json
    if ([int]$coreManifest.fileCount -ne [int]$manifest.coreExport.fileCount -or
        [string]$coreManifest.normalizedInventorySha256 -cne [string]$manifest.coreExport.normalizedInventorySha256 -or
        (Get-FileHash -LiteralPath (Join-Path $coreExtract 'OPEN_SOURCE_EXPORT_MANIFEST.json') -Algorithm SHA256).Hash -cne [string]$manifest.coreExport.rawManifestSha256RunSpecific) {
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
    foreach ($textFile in Get-ChildItem -LiteralPath $adminExtract -Recurse -File | Where-Object { $_.Extension -in '.html', '.js', '.css', '.json', '.svg' }) {
        Assert-NoLocalPathOrSecretText -Text (Get-Content -LiteralPath $textFile.FullName -Raw)
    }

    $gatewayImage = @($manifest.images | Where-Object { [string]$_.role -ceq 'gateway' })
    $migrationsImage = @($manifest.images | Where-Object { [string]$_.role -ceq 'migrations' })
    if ($gatewayImage.Count -ne 1 -or $migrationsImage.Count -ne 1) { throw 'ALPHA_ARTIFACT_IMAGE_MANIFEST_INVALID' }
    $gatewayTar = @(Get-ChildItem -LiteralPath (Join-Path $run 'artifacts') -File -Filter 'gateway-image-*.tar')
    $migrationsTar = @(Get-ChildItem -LiteralPath (Join-Path $run 'artifacts') -File -Filter 'migrations-image-*.tar')
    if ($gatewayTar.Count -ne 1 -or $migrationsTar.Count -ne 1) { throw 'ALPHA_ARTIFACT_IMAGE_ARCHIVE_INVENTORY_INVALID' }
    Ensure-ImageAvailable -Reference ([string]$gatewayImage[0].reference) -ArchivePath $gatewayTar[0].FullName
    Ensure-ImageAvailable -Reference ([string]$migrationsImage[0].reference) -ArchivePath $migrationsTar[0].FullName
    foreach ($image in @($gatewayImage[0], $migrationsImage[0])) {
        $inspect = @(& docker image inspect ([string]$image.reference) | ConvertFrom-Json)[0]
        $imageUser = [string]$inspect.Config.User
        if ($LASTEXITCODE -ne 0 -or [string]$inspect.Config.Labels.'org.opencontainers.image.version' -cne $productVersion -or
            [string]$inspect.Config.Labels.'org.opencontainers.image.revision' -cne $sourceCommit -or
            [string]$inspect.Id -cne [string]$image.imageId -or [string]::IsNullOrWhiteSpace($imageUser) -or
            $imageUser -in @('0', 'root')) { throw 'ALPHA_ARTIFACT_IMAGE_METADATA_INVALID' }
        $history = (& docker image history --no-trunc --format '{{.CreatedBy}}' ([string]$image.reference) | Out-String)
        if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_IMAGE_HISTORY_FAILED' }
        Assert-NoLocalPathOrSecretText -Text $history
    }
    $gatewayInspect = @(& docker image inspect ([string]$gatewayImage[0].reference) | ConvertFrom-Json)[0]
    if ($null -eq $gatewayInspect.Config.Healthcheck -or @($gatewayInspect.Config.Healthcheck.Test).Count -eq 0) { throw 'ALPHA_ARTIFACT_GATEWAY_HEALTHCHECK_MISSING' }

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
        & $dotnet restore (Join-Path $consumer 'Consumer.csproj') --source (Join-Path $run 'artifacts') --source 'https://api.nuget.org/v3/index.json' *> $null
        if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_CONSUMER_RESTORE_FAILED' }
        & $dotnet run --project (Join-Path $consumer 'Consumer.csproj') --configuration Release --no-restore *> $null
        if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_CONSUMER_RUN_FAILED' }
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
            $inspectText = (& docker inspect $containerName 2>$null | Out-String)
            if ($LASTEXITCODE -eq 0) {
                $containerInspect = @($inspectText | ConvertFrom-Json)[0]
                $owned = [string]$containerInspect.Config.Labels.'secure-integration.alpha-artifact-validation'
                if ($owned -cne $sourceCommit) { throw 'ALPHA_ARTIFACT_CONTAINER_CLEANUP_OWNERSHIP_FAILED' }
                & docker rm --force $containerName *> $null
                if ($LASTEXITCODE -ne 0) { throw 'ALPHA_ARTIFACT_CONTAINER_CLEANUP_FAILED' }
            }
        }
    }

    [pscustomobject]@{
        status = 'PASS'
        productVersion = $productVersion
        sourceRevision = $sourceCommit
        sha256Sums = 'PASS'
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
    if (Test-Path -LiteralPath $testRoot) {
        $resolved = [IO.Path]::GetFullPath($testRoot)
        if (-not $resolved.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'ALPHA_ARTIFACT_TEST_CLEANUP_TARGET_INVALID' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

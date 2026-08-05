[CmdletBinding()]
param(
    [string] $OutputDirectory,
    [switch] $SkipVerification
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$allowlistPath = Join-Path $PSScriptRoot 'open-source-core.allowlist'
$dotnet = Join-Path $root '.dotnet\dotnet.exe'
if (-not (Test-Path -LiteralPath $dotnet)) { $dotnet = 'dotnet' }

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path ([IO.Path]::GetTempPath()) ('secure-integration-core-' + [Guid]::NewGuid().ToString('N'))
}
$destination = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $destination) { throw 'OSS_EXPORT_DESTINATION_MUST_NOT_EXIST' }
New-Item -ItemType Directory -Path $destination | Out-Null

$allowlist = @(Get-Content -LiteralPath $allowlistPath | ForEach-Object { $_.Trim().Replace('\', '/') } | Where-Object { $_ -and -not $_.StartsWith('#', [StringComparison]::Ordinal) })
$tracked = @(& git -C $root ls-files)
if ($LASTEXITCODE -ne 0) { throw 'OSS_EXPORT_GIT_INVENTORY_FAILED' }

function Test-Allowlisted([string] $relative) {
    foreach ($entry in $allowlist) {
        if ($entry.EndsWith('/', [StringComparison]::Ordinal)) {
            if ($relative.StartsWith($entry, [StringComparison]::Ordinal)) { return $true }
        }
        elseif ($relative.Equals($entry, [StringComparison]::Ordinal)) { return $true }
    }
    return $false
}

$forbidden = @(
    '^packs/', '^\.artifacts/', '(^|/)raw-evidence/', '(^|/)evidence-raw/',
    '(^|/).*\.evtx$', '(^|/).*\.(pfx|p12|pem|key|dmp|dump)$',
    '^docs/reviews/', 'healthcare', 'commercial'
)

$exported = [Collections.Generic.List[string]]::new()
foreach ($relativeRaw in $tracked) {
    $relative = $relativeRaw.Replace('\', '/')
    if (-not (Test-Allowlisted $relative)) { continue }
    foreach ($pattern in $forbidden) {
        if ($relative -match $pattern) { throw "OSS_EXPORT_FORBIDDEN_PATH: $relative" }
    }
    $source = Join-Path $root $relative
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { continue }
    $target = Join-Path $destination $relative
    $targetParent = Split-Path -Parent $target
    if (-not (Test-Path -LiteralPath $targetParent)) { New-Item -ItemType Directory -Path $targetParent -Force | Out-Null }
    Copy-Item -LiteralPath $source -Destination $target
    $exported.Add($relative)
}

if ($exported.Count -lt 20) { throw 'OSS_EXPORT_ALLOWLIST_TOO_NARROW' }

$manifestEntries = foreach ($relative in ($exported | Sort-Object)) {
    $path = Join-Path $destination $relative
    if (-not [IO.File]::Exists($path)) { throw "OSS_EXPORT_COPIED_FILE_MISSING: $relative" }
    [ordered]@{ path = $relative; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash; bytes = [IO.FileInfo]::new($path).Length }
}
$manifest = [ordered]@{
    schemaVersion = 1
    sourceCommit = (& git -C $root rev-parse HEAD).Trim()
    generatedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    fileCount = $manifestEntries.Count
    files = @($manifestEntries)
}
$manifestPath = Join-Path $destination 'OPEN_SOURCE_EXPORT_MANIFEST.json'
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
$manifestHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash
Set-Content -LiteralPath ($manifestPath + '.sha256') -Value "$manifestHash  OPEN_SOURCE_EXPORT_MANIFEST.json" -Encoding ASCII

if (-not $SkipVerification) {
    $powerShellExecutable = (Get-Process -Id $PID).Path
    $powerShellArguments = @('-NoLogo', '-NoProfile')
    if ($PSVersionTable.PSEdition -eq 'Desktop') { $powerShellArguments += @('-ExecutionPolicy', 'Bypass') }
    $powerShellArguments += @('-File', (Join-Path (Join-Path $destination 'eng') 'scan-secrets.ps1'))
    & $powerShellExecutable @powerShellArguments
    if ($LASTEXITCODE -ne 0) { throw 'OSS_EXPORT_SECRET_SCAN_FAILED' }
    $scanTargets = @((Join-Path $destination 'src'), (Join-Path $destination 'sdk'))
    $boundaryPattern = '(Azure\.Identity|Azure\.Security|ManagedIdentityCredential|SecretClient|packs/deployment|BEGIN (RSA |EC )?PRIVATE KEY)'
    $ripgrep = Get-Command rg -ErrorAction SilentlyContinue
    if ($ripgrep) {
        $forbiddenContent = & $ripgrep.Source -l --hidden --glob '!**/packages.lock.json' --glob '!**/obj/**' --glob '!**/bin/**' $boundaryPattern @scanTargets 2>$null
        if ($LASTEXITCODE -notin 0, 1) { throw 'OSS_EXPORT_BOUNDARY_SCAN_FAILED' }
    }
    else {
        $forbiddenContent = @(Get-ChildItem -LiteralPath $scanTargets -Recurse -File |
            Where-Object { $_.Name -ne 'packages.lock.json' -and $_.FullName -notmatch '[/\\](obj|bin)[/\\]' -and $_.Length -le 10MB } |
            Select-String -Pattern $boundaryPattern |
            Select-Object -ExpandProperty Path -Unique)
    }
    if ($forbiddenContent) { throw ('OSS_EXPORT_FORBIDDEN_CONTENT: ' + (($forbiddenContent | Sort-Object -Unique) -join ', ')) }
    $brokenLinks = [Collections.Generic.List[string]]::new()
    foreach ($markdown in Get-ChildItem -LiteralPath $destination -Recurse -Filter '*.md' -File) {
        $content = Get-Content -LiteralPath $markdown.FullName -Raw
        foreach ($match in [regex]::Matches($content, '\[[^\]]+\]\(([^)]+)\)')) {
            $target = $match.Groups[1].Value
            if ($target -match '^(https?://|mailto:|#)') { continue }
            $relativeTarget = [uri]::UnescapeDataString(($target -split '#')[0])
            if (-not [string]::IsNullOrWhiteSpace($relativeTarget)) {
                $resolved = [IO.Path]::GetFullPath((Join-Path $markdown.DirectoryName $relativeTarget))
                if (-not $resolved.StartsWith($destination + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $resolved)) {
                    $brokenLinks.Add("$($markdown.FullName): $target")
                }
            }
        }
    }
    if ($brokenLinks.Count -gt 0) { throw ('OSS_EXPORT_BROKEN_LINKS: ' + (($brokenLinks | Sort-Object -Unique) -join ', ')) }
    $publicTextFiles = @(Get-ChildItem -LiteralPath $destination -Recurse -File | Where-Object { $_.Extension -in '.md', '.json', '.yml', '.yaml' -and $_.Length -le 5MB })
    $excludedReferences = @($publicTextFiles | Select-String -Pattern 'docs[/\\](reviews|implementation|traceability)[/\\]|C:\\(Users|SecureEvidence|Lab|Codice)\\' | Select-Object -ExpandProperty Path -Unique)
    if ($excludedReferences) { throw ('OSS_EXPORT_EXCLUDED_REFERENCE: ' + (($excludedReferences | Sort-Object -Unique) -join ', ')) }
    $solution = Join-Path $destination 'BrokerGateway.Core.slnx'
    $isWindowsHost = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)
    $platformArguments = @()
    if (-not $isWindowsHost) { $platformArguments += '/p:EnableWindowsTargeting=true' }
    & $dotnet restore $solution @platformArguments
    if ($LASTEXITCODE -ne 0) { throw 'OSS_EXPORT_RESTORE_FAILED' }
    & $dotnet build $solution --configuration Release --no-restore @platformArguments
    if ($LASTEXITCODE -ne 0) { throw 'OSS_EXPORT_BUILD_FAILED' }
    $coreTests = @(
        @{ Path = 'tests/architecture/Architecture.Tests/Architecture.Tests.csproj'; Filter = $null },
        @{ Path = 'tests/unit/Broker.Core.Tests/Broker.Core.Tests.csproj'; Filter = $null },
        @{ Path = 'tests/unit/Gateway.Unit.Tests/Gateway.Unit.Tests.csproj'; Filter = $null },
        @{ Path = 'tests/integration/Gateway.Integration.Tests/Gateway.Integration.Tests.csproj'; Filter = $null }
    )
    if ($isWindowsHost) {
        $coreTests += @(
            @{ Path = 'tests/integration/Broker.Integration.Tests/Broker.Integration.Tests.csproj'; Filter = 'FullyQualifiedName!~Live_matrix&FullyQualifiedName!~Windows_service_uses_the_event_source_provisioned_by_the_installer' },
            @{ Path = 'tests/e2e/VerticalSlice.Tests/VerticalSlice.Tests.csproj'; Filter = $null }
        )
    }
    foreach ($test in $coreTests) {
        $testArguments = @('test', (Join-Path $destination $test.Path), '--configuration', 'Release', '--no-restore', '--no-build') + $platformArguments
        if ($test.Filter) { $testArguments += @('--filter', $test.Filter) }
        & $dotnet @testArguments
        if ($LASTEXITCODE -ne 0) { throw "OSS_EXPORT_TEST_FAILED: $($test.Path)" }
    }
    $web = Join-Path $destination 'src\Admin\Admin.Web'
    if (Test-Path -LiteralPath (Join-Path $web 'package-lock.json')) {
        Push-Location $web
        try {
            & npm ci --ignore-scripts
            if ($LASTEXITCODE -ne 0) { throw 'OSS_EXPORT_FRONTEND_RESTORE_FAILED' }
            & npm run lint
            if ($LASTEXITCODE -ne 0) { throw 'OSS_EXPORT_FRONTEND_LINT_FAILED' }
            & npm test
            if ($LASTEXITCODE -ne 0) { throw 'OSS_EXPORT_FRONTEND_TEST_FAILED' }
            & npm run build
            if ($LASTEXITCODE -ne 0) { throw 'OSS_EXPORT_FRONTEND_BUILD_FAILED' }
            & node (Join-Path $destination 'tools\m5\check-frontend-licenses.mjs')
            if ($LASTEXITCODE -ne 0) { throw 'OSS_EXPORT_FRONTEND_LICENSE_FAILED' }
        }
        finally { Pop-Location }
    }
}

[pscustomobject]@{
    status = 'PASS'
    outputDirectory = $destination
    sourceCommit = $manifest.sourceCommit
    fileCount = $manifest.fileCount
    manifestSha256 = $manifestHash
} | ConvertTo-Json -Depth 3

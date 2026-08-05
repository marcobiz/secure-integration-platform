param(
    [string]$Version = '0.1.0-dev'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dotnet = Join-Path $root '.dotnet\dotnet.exe'
if (-not (Test-Path -LiteralPath $dotnet)) { $dotnet = 'dotnet' }
$output = Join-Path $root '.artifacts\sbom'
New-Item -ItemType Directory -Force -Path $output | Out-Null

& $dotnet tool restore
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$toolAssembly = Join-Path $root '.artifacts\nuget\packages\microsoft.sbom.dotnettool\4.1.5\tools\net8.0\any\Microsoft.Sbom.DotNetTool.dll'
$netEightHost = $dotnet
if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if (-not [string]::IsNullOrWhiteSpace($programFiles)) {
        $candidate = Join-Path $programFiles 'dotnet\dotnet.exe'
        if (Test-Path -LiteralPath $candidate) { $netEightHost = $candidate }
    }
}
$env:DeleteManifestDirIfPresent = 'true'
& $netEightHost $toolAssembly generate -b $output -bc $root -pn 'SecureIntegrationPlatform' -pv $Version -ps 'Secure Integration Platform Contributors' -nsb 'https://example.invalid/secure-integration-platform'
exit $LASTEXITCODE

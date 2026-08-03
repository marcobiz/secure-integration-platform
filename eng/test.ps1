param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dotnet = Join-Path $root '.dotnet\dotnet.exe'
if (-not (Test-Path -LiteralPath $dotnet)) { $dotnet = 'dotnet' }

& $dotnet test (Join-Path $root 'BrokerGateway.slnx') --configuration $Configuration --no-restore --no-build --logger 'console;verbosity=normal'
exit $LASTEXITCODE


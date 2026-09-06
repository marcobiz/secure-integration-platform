param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string]$ResultsDirectory = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dotnet = Join-Path $root '.dotnet\dotnet.exe'
if (-not (Test-Path -LiteralPath $dotnet)) { $dotnet = 'dotnet' }

$resultArguments = @()
if ($ResultsDirectory) { $resultArguments = @('--logger', 'trx', '--results-directory', [IO.Path]::GetFullPath($ResultsDirectory)) }
& $dotnet test (Join-Path $root 'BrokerGateway.slnx') --configuration $Configuration --no-restore --no-build --logger 'console;verbosity=normal' @resultArguments
exit $LASTEXITCODE


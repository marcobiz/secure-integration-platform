[CmdletBinding()]
param(
    [switch]$Reset,
    [switch]$SmokeTest,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot '..\tools\m5\Invoke-M5AdminDev.ps1') -Reset:$Reset -SmokeTest:$SmokeTest -NoBrowser:$NoBrowser
exit $LASTEXITCODE

[CmdletBinding()]
param(
    [string] $RunId = ('m0-m1-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'LiveMatrix.Common.psm1') -Force -DisableNameChecking

Assert-LiveMatrixAdministrator
if ($PSVersionTable.PSVersion.Major -lt 5) { throw 'Windows PowerShell 5.1 or later is required.' }
if (-not [Environment]::Is64BitOperatingSystem) { throw 'A 64-bit Windows VM is required.' }

$computer = Get-CimInstance Win32_ComputerSystem
$computerProduct = Get-CimInstance Win32_ComputerSystemProduct
$os = Get-CimInstance Win32_OperatingSystem
$virtualPattern = 'Virtual Machine|VMware|VirtualBox|KVM|HVM|Parallels|QEMU|Xen|Amazon EC2|Google Compute Engine'
if (([string]$computer.Manufacturer + ' ' + [string]$computer.Model) -notmatch $virtualPattern) {
    throw "LIVE_MATRIX_REQUIRES_VM: detected '$($computer.Manufacturer) $($computer.Model)'."
}

foreach ($command in 'dotnet', 'git', 'Get-LocalUser', 'New-LocalUser', 'Register-ScheduledTask', 'Get-WinEvent', 'Get-CimInstance') {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "Missing prerequisite: $command" }
}

$repositoryRoot = Get-LiveMatrixRepositoryRoot
$repositoryCommit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $repositoryCommit -notmatch '^[a-fA-F0-9]{40}$') { throw 'The repository commit cannot be identified.' }
$repositoryStatus = @(& git -C $repositoryRoot status --porcelain)
if ($LASTEXITCODE -ne 0 -or $repositoryStatus.Count -ne 0) { throw 'LIVE_MATRIX_REQUIRES_CLEAN_WORKTREE: commit or discard repository changes before collecting evidence.' }
$requiredSdk = (Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot 'global.json') | ConvertFrom-Json).sdk.version
$actualSdk = (& dotnet --version).Trim()
if ($LASTEXITCODE -ne 0 -or $actualSdk -ne $requiredSdk) { throw "Required .NET SDK $requiredSdk; active SDK is $actualSdk." }

$programDataDrive = [IO.Path]::GetPathRoot($env:ProgramData).TrimEnd('\')
$programFilesDrive = [IO.Path]::GetPathRoot($env:ProgramFiles).TrimEnd('\')
$programDataVolume = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$programDataDrive'"
$programFilesVolume = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$programFilesDrive'"
if ($programDataVolume.FileSystem -ne 'NTFS' -or $programFilesVolume.FileSystem -ne 'NTFS') { throw 'ProgramData and Program Files must use NTFS for the required ACLs.' }

$existing = Get-CimInstance Win32_Service -Filter "Name='SecureIntegrationBroker'" -ErrorAction SilentlyContinue
$paths = Get-LiveMatrixPaths -RunId $RunId
if ($null -ne $existing -and -not (Test-Path -LiteralPath (Join-Path $paths.Root 'harness-owned-service.marker'))) {
    throw 'SecureIntegrationBroker already exists and is not marked as owned by this harness.'
}

$result = [ordered]@{
    runId = $RunId
    passed = $true
    elevated = $true
    computerName = $env:COMPUTERNAME
    manufacturer = [string]$computer.Manufacturer
    model = [string]$computer.Model
    vmUuid = [string]$computerProduct.UUID
    osCaption = [string]$os.Caption
    osVersion = [string]$os.Version
    osBuild = [string]$os.BuildNumber
    powershell = $PSVersionTable.PSVersion.ToString()
    dotnetSdk = $actualSdk
    repositoryRoot = $repositoryRoot
    repositoryCommit = $repositoryCommit
    bootTimeUtc = (Get-LiveMatrixBootTimeUtc).ToString('o')
    checkedUtc = [DateTimeOffset]::UtcNow.ToString('o')
}

New-Item -ItemType Directory -Path $paths.Raw -Force | Out-Null
Write-LiveMatrixJson -Value $result -Path (Join-Path $paths.Raw 'prerequisites.json')
$result | ConvertTo-Json -Depth 4

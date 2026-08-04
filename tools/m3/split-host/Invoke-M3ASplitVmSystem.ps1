[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{5,39}$')] [string] $RunId,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{40}$')] [string] $CandidateCommit,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9A-Fa-f]{64}$')] [string] $ExecutorModuleSha256,
    [Parameter(Mandatory)] [string] $RepositoryRoot,
    [Parameter(Mandatory)] [string] $PackageRoot,
    [Parameter(Mandatory)] [string] $OutputDirectory,
    [Parameter(Mandatory)] [string] $StatusPath,
    [Parameter(Mandatory)] [string] $ExpectedHostName,
    [Parameter(Mandatory)] [DateTimeOffset] $DeadlineUtc
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$executorModule = Join-Path $PSScriptRoot 'M3ASplitVmExecutor.psm1'
if (-not (Test-Path -LiteralPath $executorModule) -or (Get-FileHash -LiteralPath $executorModule -Algorithm SHA256).Hash -ne $ExecutorModuleSha256.ToUpperInvariant()) {
    throw 'M3A_SPLIT_EXECUTE_VM_MODULE_HASH_MISMATCH.'
}
Import-Module $executorModule -Force
$taskName = 'SecureIntegration-M3A-ExecuteVm-' + $RunId
$validateResult = 'NOT_RUN'
$runResult = 'NOT_RUN'
$classification = 'BLOCKED'
$errorCode = $null
$resultPath = Join-Path $OutputDirectory 'RESULT.json'
$manifestPath = Join-Path $OutputDirectory 'vm-manifest.json'

function Write-LaunchStatus {
    param([Parameter(Mandatory)] [string] $Status)
    $parent = Split-Path -Parent $StatusPath
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $document = [ordered]@{
        schemaVersion = 1
        runId = $RunId
        candidateCommit = $CandidateCommit
        hostName = $env:COMPUTERNAME
        principal = $identity.Name
        system = ($identity.User.Value -eq 'S-1-5-18')
        elevated = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        validateVm = $validateResult
        run = $runResult
        status = $Status
        errorCode = $errorCode
        timestampUtc = [DateTimeOffset]::UtcNow.ToString('O')
        resultPath = if (Test-Path -LiteralPath $resultPath) { $resultPath } else { $null }
        artefactManifestPath = if (Test-Path -LiteralPath $manifestPath) { $manifestPath } else { $null }
    }
    [IO.File]::WriteAllText($StatusPath, ($document | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
}

function New-LaunchFailureArchive {
    $failureRoot = Join-Path (Split-Path -Parent $OutputDirectory) 'vm-launch-failure'
    New-Item -ItemType Directory -Path $failureRoot -Force | Out-Null
    Copy-Item -LiteralPath $StatusPath -Destination (Join-Path $failureRoot 'VM-ELEVATED-LAUNCH-STATUS.json') -Force
    $archive = Join-Path (Split-Path -Parent $OutputDirectory) ($RunId + '-vm-launch-failure-redacted.zip')
    if (-not (Test-Path -LiteralPath $archive)) {
        Compress-Archive -Path (Join-Path $failureRoot '*') -DestinationPath $archive -CompressionLevel Optimal
        $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
        [IO.File]::WriteAllText(($archive + '.sha256'), ($hash + '  ' + [IO.Path]::GetFileName($archive) + [Environment]::NewLine), [Text.Encoding]::ASCII)
    }
}

try {
    Write-LaunchStatus -Status 'BLOCKED'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -ne 'S-1-5-18') { throw 'M3A_SPLIT_EXECUTE_VM_REQUIRES_SYSTEM.' }
    if ($env:COMPUTERNAME -ne $ExpectedHostName) { throw 'M3A_SPLIT_EXECUTE_VM_HOST_MISMATCH.' }
    [void](Assert-M3AExecuteVmWindow -DeadlineUtc $DeadlineUtc -MinimumRemainingMinutes 45)
    $executionRoot = Join-Path $env:ProgramData ('SecureIntegration\M3A\Executions\' + $RunId)
    Assert-M3AExecuteVmPath -Path $PSCommandPath -RequiredParent $executionRoot -ErrorCode 'M3A_SPLIT_EXECUTE_VM_LAUNCHER_OUTSIDE_RUN_DIRECTORY.'
    $runIdFile = Join-Path $PackageRoot 'RUNID.txt'
    $inputZip = Join-Path $PackageRoot 'input.zip'
    $sidecar = $inputZip + '.sha256'
    $input = Join-Path $PackageRoot 'input'
    foreach ($required in $runIdFile, $inputZip, $sidecar, $input, (Join-Path $input 'bootstrap.json')) {
        if (-not (Test-Path -LiteralPath $required)) { throw 'M3A_SPLIT_EXECUTE_VM_HANDOFF_INCOMPLETE.' }
    }
    if ([IO.File]::ReadAllText($runIdFile).Trim() -ne $RunId) { throw 'M3A_SPLIT_EXECUTE_VM_RUN_ID_MISMATCH.' }
    $expectedHash = (([IO.File]::ReadAllText($sidecar)) -split '\s+')[0].ToUpperInvariant()
    $actualHash = (Get-FileHash -LiteralPath $inputZip -Algorithm SHA256).Hash
    if ($expectedHash -ne $actualHash) { throw 'M3A_SPLIT_EXECUTE_VM_HANDOFF_HASH_MISMATCH.' }
    $bootstrap = Get-Content -LiteralPath (Join-Path $input 'bootstrap.json') -Raw | ConvertFrom-Json
    if ([string]$bootstrap.runId -ne $RunId -or [string]$bootstrap.candidateCommit -ne $CandidateCommit) { throw 'M3A_SPLIT_EXECUTE_VM_BOOTSTRAP_MISMATCH.' }
    $gateway = [Uri][string]$bootstrap.gatewayBaseAddress
    if (-not $gateway.IsAbsoluteUri -or $gateway.Scheme -ne 'https' -or [Net.IPAddress]::IsLoopback(([Net.IPAddress]::Parse($gateway.Host)))) {
        throw 'M3A_SPLIT_EXECUTE_VM_GATEWAY_INVALID.'
    }
    $safeRepository = $RepositoryRoot.Replace('\', '/')
    $env:GIT_CONFIG_COUNT = '1'
    $env:GIT_CONFIG_KEY_0 = 'safe.directory'
    $env:GIT_CONFIG_VALUE_0 = $safeRepository
    $worktree = (& git.exe -C $RepositoryRoot status --porcelain | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $worktree) { throw 'M3A_SPLIT_EXECUTE_VM_WORKTREE_NOT_CLEAN.' }
    $head = (& git.exe -C $RepositoryRoot rev-parse HEAD | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -ne $CandidateCommit) { throw 'M3A_SPLIT_EXECUTE_VM_HEAD_MISMATCH.' }
    $runner = Join-Path $RepositoryRoot 'tools\m3\split-host\Invoke-M3ASplitVm.ps1'
    & $runner -Phase ValidateVm -RunId $RunId -RepositoryRoot $RepositoryRoot *> $null
    if ($LASTEXITCODE -ne 0) { throw 'M3A_SPLIT_EXECUTE_VM_VALIDATE_FAILED.' }
    $validateResult = 'PASS'
    Write-LaunchStatus -Status 'BLOCKED'
    & $runner -Phase Run -RunId $RunId -InputDirectory $input -OutputDirectory $OutputDirectory -RepositoryRoot $RepositoryRoot *> $null
    if ($LASTEXITCODE -ne 0) { throw 'M3A_SPLIT_EXECUTE_VM_RUN_FAILED.' }
    $runResult = 'PASS'
    if (-not (Test-Path -LiteralPath $resultPath) -or -not (Test-Path -LiteralPath $manifestPath)) {
        throw 'M3A_SPLIT_EXECUTE_VM_RESULT_MISSING.'
    }
    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if ([string]$result.status -ne 'PASS' -or [string]$result.commitSha -ne $CandidateCommit) {
        throw 'M3A_SPLIT_EXECUTE_VM_RESULT_INVALID.'
    }
    $classification = 'PASS'
    Write-LaunchStatus -Status 'PASS'
    exit 0
}
catch {
    $errorCode = Get-M3AExecuteVmErrorCode -ErrorRecord $_
    if ($validateResult -eq 'NOT_RUN') { $validateResult = 'FAIL' }
    elseif ($runResult -eq 'NOT_RUN') { $runResult = 'FAIL' }
    Write-LaunchStatus -Status $classification
    New-LaunchFailureArchive
    exit 1
}

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{5,39}$')]
    [string] $RunId,
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedScriptSha256,
    [string] $RepositoryRoot = 'C:\Lab\broker-gateway',
    [string] $EvidenceRoot = 'C:\SecureEvidence'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$packageRoot = $PSScriptRoot
$inputZip = Join-Path $packageRoot 'input.zip'
$inputSidecar = $inputZip + '.sha256'
$scriptSidecar = $PSCommandPath + '.sha256'
$runIdPath = Join-Path $packageRoot 'RUNID.txt'
$inputDirectory = Join-Path $packageRoot 'input'
$runEvidenceRoot = Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) $RunId
$outputDirectory = Join-Path $runEvidenceRoot 'vm-redacted'
$canonicalResultPath = Join-Path $runEvidenceRoot 'RESULT.json'
$candidateCommit = $null
$validateStatus = 'NOT_RUN'
$runStatus = 'NOT_RUN'
$stage = 'INITIALIZE'

function Write-CanonicalResult {
    param(
        [Parameter(Mandatory)] [string] $Status,
        [Parameter(Mandatory)] [string] $ErrorCode
    )
    New-Item -ItemType Directory -Path $runEvidenceRoot -Force | Out-Null
    $document = [ordered]@{
        schemaVersion = 1
        environment = 'M3A-SPLIT-VM-OPERATOR'
        runId = $RunId
        commitSha = $candidateCommit
        status = $Status
        classification = if ($Status -eq 'PASS') { 'COMPLETED' } else { 'OPERATOR_RUN_BLOCKED' }
        validateVm = $validateStatus
        run = $runStatus
        stage = $stage
        errorCode = if ($Status -eq 'PASS') { $null } else { $ErrorCode }
        completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        resultPath = if (Test-Path -LiteralPath (Join-Path $outputDirectory 'RESULT.json')) { Join-Path $outputDirectory 'RESULT.json' } else { $null }
        artefactManifestPath = if (Test-Path -LiteralPath (Join-Path $outputDirectory 'vm-manifest.json')) { Join-Path $outputDirectory 'vm-manifest.json' } else { $null }
    }
    [IO.File]::WriteAllText($canonicalResultPath, ($document | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
}

function Get-SanitizedErrorCode {
    param(
        [Parameter(Mandatory)] [Management.Automation.ErrorRecord] $ErrorRecord,
        [Parameter(Mandatory)] [string] $Stage
    )
    $message = [string]$ErrorRecord.Exception.Message
    if ($message -match '^(M3A_[A-Z0-9_]+)') { return $Matches[1] }
    return 'M3A_SPLIT_VM_OPERATOR_' + ($Stage -replace '[^A-Z0-9_]', '_') + '_FAILURE'
}

function Invoke-GitOperatorChecked {
    param(
        [Parameter(Mandatory)] [string[]] $Arguments,
        [Parameter(Mandatory)] [string] $ErrorCode,
        [switch] $CaptureOutput
    )
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $nativeOutput = @(& git.exe @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousPreference }
    if ($exitCode -ne 0) { throw $ErrorCode }
    if ($CaptureOutput) { return ($nativeOutput -join [Environment]::NewLine) }
}

try {
    $stage = 'ELEVATION'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'M3A_SPLIT_VM_OPERATOR_REQUIRES_ELEVATION.'
    }
    foreach ($required in $inputZip, $inputSidecar, $scriptSidecar, $runIdPath) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw 'M3A_SPLIT_VM_OPERATOR_HANDOFF_INCOMPLETE.' }
    }
    $stage = 'HANDOFF_HASH'
    if ([IO.File]::ReadAllText($runIdPath).Trim() -ne $RunId) { throw 'M3A_SPLIT_VM_OPERATOR_RUN_ID_MISMATCH.' }
    $actualScriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    $sidecarScriptHash = (([IO.File]::ReadAllText($scriptSidecar)) -split '\s+')[0].ToUpperInvariant()
    if ($actualScriptHash -ne $ExpectedScriptSha256.ToUpperInvariant() -or $actualScriptHash -ne $sidecarScriptHash) {
        throw 'M3A_SPLIT_VM_OPERATOR_SCRIPT_HASH_MISMATCH.'
    }
    $expectedInputHash = (([IO.File]::ReadAllText($inputSidecar)) -split '\s+')[0].ToUpperInvariant()
    if ((Get-FileHash -LiteralPath $inputZip -Algorithm SHA256).Hash -ne $expectedInputHash) {
        throw 'M3A_SPLIT_VM_OPERATOR_HANDOFF_HASH_MISMATCH.'
    }
    if (Test-Path -LiteralPath $inputDirectory) { throw 'M3A_SPLIT_VM_OPERATOR_INPUT_ALREADY_EXTRACTED.' }
    New-Item -ItemType Directory -Path $inputDirectory | Out-Null
    Expand-Archive -LiteralPath $inputZip -DestinationPath $inputDirectory
    $stage = 'BOOTSTRAP'
    $bootstrapPath = Join-Path $inputDirectory 'bootstrap.json'
    if (-not (Test-Path -LiteralPath $bootstrapPath -PathType Leaf)) { throw 'M3A_SPLIT_VM_OPERATOR_BOOTSTRAP_MISSING.' }
    $bootstrap = Get-Content -LiteralPath $bootstrapPath -Raw | ConvertFrom-Json
    if ([string]$bootstrap.runId -ne $RunId -or [string]$bootstrap.candidateCommit -notmatch '^[0-9a-f]{40}$') {
        throw 'M3A_SPLIT_VM_OPERATOR_BOOTSTRAP_INVALID.'
    }
    $candidateCommit = [string]$bootstrap.candidateCommit
    $gatewayUri = [Uri][string]$bootstrap.gatewayBaseAddress
    $gatewayIp = $null
    if (-not $gatewayUri.IsAbsoluteUri -or $gatewayUri.Scheme -ne 'https' -or -not [Net.IPAddress]::TryParse($gatewayUri.Host, [ref]$gatewayIp) -or [Net.IPAddress]::IsLoopback($gatewayIp)) {
        throw 'M3A_SPLIT_VM_OPERATOR_GATEWAY_INVALID.'
    }
    if ($bootstrap.PSObject.Properties.Name -contains 'rollbackDeadlineUtc') {
        $deadline = [DateTimeOffset]::Parse([string]$bootstrap.rollbackDeadlineUtc).ToUniversalTime()
        if (($deadline - [DateTimeOffset]::UtcNow).TotalMinutes -lt 45) { throw 'M3A_SPLIT_VM_OPERATOR_WINDOW_TOO_SHORT.' }
    }
    $stage = 'GIT_STATUS'
    if (-not (Test-Path -LiteralPath (Join-Path $RepositoryRoot '.git'))) { throw 'M3A_SPLIT_VM_OPERATOR_REPOSITORY_MISSING.' }
    $safeRepository = $RepositoryRoot.Replace('\', '/')
    $gitPrefix = @('-c', ('safe.directory=' + $safeRepository), '-C', $RepositoryRoot)
    $worktree = (Invoke-GitOperatorChecked -Arguments ($gitPrefix + @('status', '--porcelain')) -ErrorCode 'M3A_SPLIT_VM_OPERATOR_GIT_STATUS_FAILED.' -CaptureOutput).Trim()
    if ($worktree) { throw 'M3A_SPLIT_VM_OPERATOR_WORKTREE_NOT_CLEAN.' }
    $stage = 'GIT_FETCH'
    [void](Invoke-GitOperatorChecked -Arguments ($gitPrefix + @('fetch', '--prune', 'origin')) -ErrorCode 'M3A_SPLIT_VM_OPERATOR_FETCH_FAILED.')
    $stage = 'GIT_COMMIT'
    [void](Invoke-GitOperatorChecked -Arguments ($gitPrefix + @('cat-file', '-e', ($candidateCommit + '^{commit}'))) -ErrorCode 'M3A_SPLIT_VM_OPERATOR_COMMIT_MISSING.')
    $head = (Invoke-GitOperatorChecked -Arguments ($gitPrefix + @('rev-parse', 'HEAD')) -ErrorCode 'M3A_SPLIT_VM_OPERATOR_HEAD_READ_FAILED.' -CaptureOutput).Trim()
    if ($head -ne $candidateCommit) {
        $stage = 'GIT_SWITCH'
        [void](Invoke-GitOperatorChecked -Arguments ($gitPrefix + @('switch', '--detach', $candidateCommit)) -ErrorCode 'M3A_SPLIT_VM_OPERATOR_SWITCH_FAILED.')
        $head = (Invoke-GitOperatorChecked -Arguments ($gitPrefix + @('rev-parse', 'HEAD')) -ErrorCode 'M3A_SPLIT_VM_OPERATOR_HEAD_READ_FAILED.' -CaptureOutput).Trim()
    }
    if ($head -ne $candidateCommit) { throw 'M3A_SPLIT_VM_OPERATOR_HEAD_MISMATCH.' }
    $stage = 'VALIDATE_VM'
    $runner = Join-Path $RepositoryRoot 'tools\m3\split-host\Invoke-M3ASplitVm.ps1'
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $runner -Phase ValidateVm -RunId $RunId -RepositoryRoot $RepositoryRoot *> $null
    if ($LASTEXITCODE -ne 0) { throw 'M3A_SPLIT_VM_OPERATOR_VALIDATE_FAILED.' }
    $validateStatus = 'PASS'
    $stage = 'RUN'
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $runner -Phase Run -RunId $RunId -InputDirectory $inputDirectory -OutputDirectory $outputDirectory -RepositoryRoot $RepositoryRoot *> $null
    if ($LASTEXITCODE -ne 0) { throw 'M3A_SPLIT_VM_OPERATOR_RUN_FAILED.' }
    $runStatus = 'PASS'
    $stage = 'RESULT'
    $runnerResultPath = Join-Path $outputDirectory 'RESULT.json'
    if (-not (Test-Path -LiteralPath $runnerResultPath) -or -not (Test-Path -LiteralPath (Join-Path $outputDirectory 'vm-manifest.json'))) {
        throw 'M3A_SPLIT_VM_OPERATOR_RESULT_MISSING.'
    }
    $runnerResult = Get-Content -LiteralPath $runnerResultPath -Raw | ConvertFrom-Json
    if ([string]$runnerResult.status -ne 'PASS' -or [string]$runnerResult.commitSha -ne $candidateCommit) {
        throw 'M3A_SPLIT_VM_OPERATOR_RESULT_INVALID.'
    }
    Write-CanonicalResult -Status 'PASS' -ErrorCode ''
    Write-Output ('M3A_SPLIT_VM_OPERATOR_PASS RunId=' + $RunId + ' Commit=' + $candidateCommit)
    exit 0
}
catch {
    $errorCode = Get-SanitizedErrorCode -ErrorRecord $_ -Stage $stage
    Write-CanonicalResult -Status 'BLOCKED' -ErrorCode $errorCode
    Write-Error $errorCode
    exit 1
}

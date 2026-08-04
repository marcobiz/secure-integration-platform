[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$hostRunnerPath = Join-Path $root 'tools\m3\split-host\Invoke-M3ASplitHost.ps1'
$operatorPath = Join-Path $root 'tools\m3\split-host\Invoke-M3ASplitVmOperator.ps1'
$hostRunner = [IO.File]::ReadAllText($hostRunnerPath)
$operator = [IO.File]::ReadAllText($operatorPath)

foreach ($required in @(
    'WAITING_FOR_OPERATOR',
    'operatorScriptSha256',
    'New-PSSession -VMId $VmId -Credential $VmCredential',
    "Copy-Item -LiteralPath `$operatorCopy",
    "Copy-Item -LiteralPath `$archive",
    'M3A_SPLIT_OPERATOR_HANDOFF_TRANSFER_MISMATCH',
    'rollbackDeadlineUtc = $rollbackDeadlineUtc'
)) {
    if ($hostRunner.IndexOf($required, [StringComparison]::Ordinal) -lt 0) { throw "Missing HOST operator handoff control: $required" }
}

foreach ($required in @(
    'M3A_SPLIT_VM_OPERATOR_SCRIPT_HASH_MISMATCH',
    'M3A_SPLIT_VM_OPERATOR_HANDOFF_HASH_MISMATCH',
    'M3A_SPLIT_VM_OPERATOR_WINDOW_TOO_SHORT',
    'M3A_SPLIT_VM_OPERATOR_WORKTREE_NOT_CLEAN',
    'switch --detach $candidateCommit',
    '-Phase ValidateVm',
    '-Phase Run',
    "Join-Path `$runEvidenceRoot 'RESULT.json'",
    "Write-CanonicalResult -Status 'BLOCKED'",
    "Write-CanonicalResult -Status 'PASS'",
    'Get-SanitizedErrorCode',
    'M3A_SPLIT_VM_OPERATOR_PASS'
)) {
    if ($operator.IndexOf($required, [StringComparison]::Ordinal) -lt 0) { throw "Missing VM operator control: $required" }
}

$validateIndex = $operator.IndexOf('-Phase ValidateVm', [StringComparison]::Ordinal)
$runIndex = $operator.IndexOf('-Phase Run', [StringComparison]::Ordinal)
if ($validateIndex -lt 0 -or $runIndex -le $validateIndex) { throw 'ValidateVm must precede Run.' }
if ($operator -match '(?im)^\s*(Write-Host|Write-Output|Out-Host).*(\$bootstrap|activationCode)' -or $operator -match 'ConvertTo-Json[^\r\n]*\$bootstrap') {
    throw 'Operator script may not print or serialize bootstrap material.'
}
if ($operator -match 'Register-ScheduledTask|New-ScheduledTaskPrincipal|NT AUTHORITY\\SYSTEM') {
    throw 'Manual operator flow must not register a privileged executor task.'
}
if ($hostRunner -match "ValidateSet\([^\)]*ExecuteVm") {
    throw 'SYSTEM ExecuteVm phase must remain outside the M3 gate branch.'
}

Write-Output 'M3A_OPERATOR_HANDOFF_TEST_PASS'

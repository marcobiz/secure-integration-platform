[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$hostRunnerPath = Join-Path $root 'tools\m3\split-host\Invoke-M3ASplitHost.ps1'
$operatorPath = Join-Path $root 'tools\m3\split-host\Invoke-M3ASplitVmOperator.ps1'
$vmRunnerPath = Join-Path $root 'tools\m3\split-host\Invoke-M3ASplitVm.ps1'
$legacySimulatorPath = Join-Path $root 'tools\m3\LegacySimulator\Program.cs'
$hostRunner = [IO.File]::ReadAllText($hostRunnerPath)
$operator = [IO.File]::ReadAllText($operatorPath)
$vmRunner = [IO.File]::ReadAllText($vmRunnerPath)
$legacySimulator = [IO.File]::ReadAllText($legacySimulatorPath)

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
    "@('switch', '--detach', `$candidateCommit)",
    '-Phase ValidateVm',
    '-Phase Run',
    "Join-Path `$runEvidenceRoot 'RESULT.json'",
    "Write-CanonicalResult -Status 'BLOCKED'",
    "Write-CanonicalResult -Status 'PASS'",
    'Get-SanitizedErrorCode',
    'Invoke-GitOperatorChecked',
    "`$ErrorActionPreference = 'Continue'",
    "if (`$head -ne `$candidateCommit)",
    "stage = `$stage",
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
if ($operator -match '&\s+git\.exe[^\r\n]+\*>\s*\$null') {
    throw 'Raw git invocation may not rely on PowerShell 5.1 stderr redirection.'
}
if ($operator.IndexOf('[Parameter(Mandatory)] [AllowEmptyString()] [string] $ErrorCode', [StringComparison]::Ordinal) -lt 0 -or
    $operator.IndexOf("Write-CanonicalResult -Status 'PASS' -ErrorCode ''", [StringComparison]::Ordinal) -lt 0) {
    throw 'VM operator must allow the empty error code used by its canonical PASS result.'
}
if ($hostRunner -match "ValidateSet\([^\)]*ExecuteVm") {
    throw 'SYSTEM ExecuteVm phase must remain outside the M3 gate branch.'
}
foreach ($required in @(
    'function Invoke-GitVmChecked',
    "`$ErrorActionPreference = 'Continue'",
    "if (`$head -ne `$candidateCommit)",
    "@('switch', '--detach', `$candidateCommit)",
    'M3A_SPLIT_VM_SWITCH_FAILED'
)) {
    if ($vmRunner.IndexOf($required, [StringComparison]::Ordinal) -lt 0) { throw "Missing VM runner Git control: $required" }
}
if ($vmRunner -match "Invoke-NativeChecked\s+-FilePath\s+'git\.exe'" -or $vmRunner -match '&\s+git(?:\.exe)?[^\r\n]+switch') {
    throw 'VM runner must use the PowerShell 5.1-safe Git wrapper.'
}
if ($vmRunner.IndexOf('[Parameter(Mandatory)] [AllowEmptyString()] [string] $Suffix', [StringComparison]::Ordinal) -lt 0 -or
    $vmRunner.IndexOf("New-VmEvidenceArchive -Suffix '' -Result `$successResult", [StringComparison]::Ordinal) -lt 0) {
    throw 'VM runner must allow the empty success-archive suffix used by Windows PowerShell 5.1.'
}
if ($legacySimulator.IndexOf('exception.Code == "gateway_operation_not_granted"', [StringComparison]::Ordinal) -lt 0 -or
    $legacySimulator.IndexOf('exception.Code == "operation_not_granted"', [StringComparison]::Ordinal) -ge 0) {
    throw 'M3 Legacy Simulator must assert the Gateway grant denial contract, not the local operation denial code.'
}

Write-Output 'M3A_OPERATOR_HANDOFF_TEST_PASS'

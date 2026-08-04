Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-M3AExecuteVmIdentifier {
    param([Parameter(Mandatory)] [string] $RunId)
    if ($RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{5,39}$') {
        throw 'M3A_SPLIT_EXECUTE_VM_RUN_ID_INVALID.'
    }
}

function Assert-M3AExecuteVmPath {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $RequiredParent,
        [Parameter(Mandatory)] [string] $ErrorCode
    )
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.IndexOf('"') -ge 0 -or $Path.IndexOf("`r") -ge 0 -or $Path.IndexOf("`n") -ge 0) {
        throw $ErrorCode
    }
    $candidate = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetFullPath($RequiredParent).TrimEnd('\') + '\'
    if (-not $candidate.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase)) { throw $ErrorCode }
}

function Assert-M3AExecuteVmWindow {
    param(
        [Parameter(Mandatory)] [DateTimeOffset] $DeadlineUtc,
        [DateTimeOffset] $NowUtc = [DateTimeOffset]::UtcNow,
        [ValidateRange(45, 120)] [int] $MinimumRemainingMinutes = 45
    )
    if ($DeadlineUtc -le $NowUtc) { throw 'M3A_SPLIT_EXECUTE_VM_DEADLINE_EXPIRED.' }
    $remaining = ($DeadlineUtc - $NowUtc).TotalMinutes
    if ($remaining -lt $MinimumRemainingMinutes) { throw 'M3A_SPLIT_EXECUTE_VM_WINDOW_TOO_SHORT.' }
    return $remaining
}

function New-M3AExecuteVmTaskContract {
    param(
        [Parameter(Mandatory)] [string] $RunId,
        [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{40}$')] [string] $CandidateCommit,
        [Parameter(Mandatory)] [string] $LauncherPath,
        [Parameter(Mandatory)] [ValidatePattern('^[0-9A-Fa-f]{64}$')] [string] $ExecutorModuleSha256,
        [Parameter(Mandatory)] [string] $ExecutionRoot,
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter(Mandatory)] [string] $PackageRoot,
        [Parameter(Mandatory)] [string] $OutputDirectory,
        [Parameter(Mandatory)] [string] $StatusPath,
        [Parameter(Mandatory)] [string] $ExpectedHostName,
        [Parameter(Mandatory)] [DateTimeOffset] $DeadlineUtc,
        [ValidateRange(15, 120)] [int] $TimeoutMinutes = 90
    )
    Assert-M3AExecuteVmIdentifier -RunId $RunId
    Assert-M3AExecuteVmPath -Path $LauncherPath -RequiredParent $ExecutionRoot -ErrorCode 'M3A_SPLIT_EXECUTE_VM_LAUNCHER_OUTSIDE_RUN_DIRECTORY.'
    foreach ($value in $RepositoryRoot, $PackageRoot, $OutputDirectory, $StatusPath, $ExpectedHostName) {
        if ([string]::IsNullOrWhiteSpace($value) -or $value.IndexOf('"') -ge 0 -or $value.IndexOf("`r") -ge 0 -or $value.IndexOf("`n") -ge 0) {
            throw 'M3A_SPLIT_EXECUTE_VM_ARGUMENT_INVALID.'
        }
    }
    $remaining = Assert-M3AExecuteVmWindow -DeadlineUtc $DeadlineUtc
    if ($TimeoutMinutes -ge [Math]::Floor($remaining)) { throw 'M3A_SPLIT_EXECUTE_VM_TIMEOUT_EXCEEDS_WINDOW.' }
    $executable = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', ('"' + $LauncherPath + '"'),
        '-ExecutorModuleSha256', $ExecutorModuleSha256.ToUpperInvariant(),
        '-RunId', $RunId,
        '-CandidateCommit', $CandidateCommit,
        '-RepositoryRoot', ('"' + $RepositoryRoot + '"'),
        '-PackageRoot', ('"' + $PackageRoot + '"'),
        '-OutputDirectory', ('"' + $OutputDirectory + '"'),
        '-StatusPath', ('"' + $StatusPath + '"'),
        '-ExpectedHostName', $ExpectedHostName,
        '-DeadlineUtc', $DeadlineUtc.ToUniversalTime().ToString('O')
    ) -join ' '
    if ($arguments -match '(?i)activation.?code|password|client.?secret|bootstrap\.json') {
        throw 'M3A_SPLIT_EXECUTE_VM_SECRET_IN_TASK_ARGUMENTS.'
    }
    return [pscustomobject]@{
        TaskName = 'SecureIntegration-M3A-ExecuteVm-' + $RunId
        Principal = 'SYSTEM'
        LogonType = 'ServiceAccount'
        RunLevel = 'Highest'
        Executable = $executable
        Arguments = $arguments
        WorkingDirectory = $ExecutionRoot
        TimeoutMinutes = $TimeoutMinutes
        DeadlineUtc = $DeadlineUtc.ToUniversalTime().ToString('O')
    }
}

function Assert-M3AExecuteVmTaskDefinition {
    param(
        [Parameter(Mandatory)] $Task,
        [Parameter(Mandatory)] $Contract,
        [Parameter(Mandatory)] [string] $ActualLauncherHash,
        [Parameter(Mandatory)] [ValidatePattern('^[0-9A-Fa-f]{64}$')] [string] $ExpectedLauncherHash
    )
    $actions = @($Task.Actions)
    if ($actions.Count -ne 1 -or
        [string]$Task.Principal.UserId -notin @('SYSTEM', 'NT AUTHORITY\SYSTEM', 'S-1-5-18') -or
        [string]$Task.Principal.LogonType -ne $Contract.LogonType -or
        [string]$Task.Principal.RunLevel -ne $Contract.RunLevel -or
        [string]$actions[0].Execute -ne $Contract.Executable -or
        [string]$actions[0].Arguments -ne $Contract.Arguments -or
        [string]$actions[0].WorkingDirectory -ne $Contract.WorkingDirectory) {
        throw 'M3A_SPLIT_EXECUTE_VM_TASK_CONTRACT_MISMATCH.'
    }
    if ($ActualLauncherHash.ToUpperInvariant() -ne $ExpectedLauncherHash.ToUpperInvariant()) {
        throw 'M3A_SPLIT_EXECUTE_VM_LAUNCHER_HASH_MISMATCH.'
    }
    if ([string]$actions[0].Arguments -match '(?i)activation.?code|password|client.?secret|bootstrap\.json') {
        throw 'M3A_SPLIT_EXECUTE_VM_SECRET_IN_TASK_ARGUMENTS.'
    }
    return $true
}

function Get-M3AExecuteVmErrorCode {
    param([Parameter(Mandatory)] [Management.Automation.ErrorRecord] $ErrorRecord)
    $message = [string]$ErrorRecord.Exception.Message
    if ($message -match '^(M3A_[A-Z0-9_]+)') { return $Matches[1] }
    $typeName = $ErrorRecord.Exception.GetType().Name.ToUpperInvariant() -replace '[^A-Z0-9_]', '_'
    return 'M3A_SPLIT_EXECUTE_VM_' + $typeName
}

Export-ModuleMember -Function @(
    'Assert-M3AExecuteVmIdentifier',
    'Assert-M3AExecuteVmPath',
    'Assert-M3AExecuteVmWindow',
    'New-M3AExecuteVmTaskContract',
    'Assert-M3AExecuteVmTaskDefinition',
    'Get-M3AExecuteVmErrorCode'
)

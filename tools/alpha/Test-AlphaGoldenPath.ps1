[CmdletBinding()]
param(
    [ValidateSet('AlphaGoldenPath_failed_child_output_is_redacted_and_cleanup_still_runs')]
    [string] $TestName = 'AlphaGoldenPath_failed_child_output_is_redacted_and_cleanup_still_runs'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$runner = Join-Path $PSScriptRoot 'Invoke-AlphaGoldenPath.ps1'
$artifactRoot = Join-Path $root '.artifacts\m5\quickstart'
$project = 'secure-integration-m5-quickstart'
$powerShellHost = try { (Get-Process -Id $PID -ErrorAction Stop).Path } catch { $null }
if ([string]::IsNullOrWhiteSpace($powerShellHost)) {
    $powerShellHost = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'powershell.exe' } else { 'pwsh' }
}

function Assert-True {
    param([Parameter(Mandatory = $true)][bool] $Condition)
    if (-not $Condition) { throw 'ALPHA_GOLDEN_PATH_FAILURE_TEST_ASSERTION_FAILED' }
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string] $Value)
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"'
}

function Invoke-Captured {
    param([Parameter(Mandatory = $true)][string] $File, [Parameter(Mandatory = $true)][string[]] $Arguments)
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $File
    $start.WorkingDirectory = $root
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if ($null -ne $start.PSObject.Properties['ArgumentList']) {
        foreach ($argument in $Arguments) { [void]$start.ArgumentList.Add($argument) }
    }
    else { $start.Arguments = (($Arguments | ForEach-Object { ConvertTo-NativeArgument ([string]$_) }) -join ' ') }
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'ALPHA_GOLDEN_PATH_FAILURE_TEST_CHILD_START_FAILED' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            StdOut = $stdoutTask.GetAwaiter().GetResult()
            StdErr = $stderrTask.GetAwaiter().GetResult()
        }
    }
    finally { $process.Dispose() }
}

function Get-ProjectResourceCount {
    $total = 0
    foreach ($arguments in @(
        @('ps', '-aq', '--filter', ('label=com.docker.compose.project=' + $project)),
        @('network', 'ls', '-q', '--filter', ('label=com.docker.compose.project=' + $project)),
        @('volume', 'ls', '-q', '--filter', ('label=com.docker.compose.project=' + $project)))) {
        $result = Invoke-Captured -File 'docker' -Arguments $arguments
        if ($result.ExitCode -ne 0) { throw 'ALPHA_GOLDEN_PATH_FAILURE_TEST_DOCKER_FAILED' }
        $total += @($result.StdOut -split '\r?\n' | Where-Object { $_.Trim().Length -gt 0 }).Count
    }
    return $total
}

try {
    Assert-True ((Get-ProjectResourceCount) -eq 0)
    Assert-True (-not (Test-Path -LiteralPath $artifactRoot))
    $result = Invoke-Captured -File $powerShellHost -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $runner, '-Phase', 'FailureOutputProbe')
    $combined = $result.StdOut + $result.StdErr
    Assert-True ($result.ExitCode -ne 0)
    Assert-True ($result.StdOut.Trim().Length -eq 0)
    Assert-True ($result.StdErr.Trim() -ceq 'ALPHA_GOLDEN_PATH_CHILD_EXIT_NONZERO;COMPONENT=FailureProbe;EXIT_CODE=37')
    foreach ($forbidden in @(
        'alpha-probe-payload-canary-2f4d68f3',
        'alpha-probe-token-canary-b619f4e8',
        'alpha-probe-password-canary-c2971a05',
        'Sensitive.cs',
        'Authorization:',
        'Password=',
        'System.InvalidOperationException',
        $root)) {
        Assert-True ($combined.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -lt 0)
    }
    Assert-True ($combined.IndexOf('ALPHA_GOLDEN_PATH_PASS', [StringComparison]::Ordinal) -lt 0)
    Assert-True ((Get-ProjectResourceCount) -eq 0)
    Assert-True (-not (Test-Path -LiteralPath $artifactRoot))
    Write-Host "$TestName PASS"
}
catch {
    [Console]::Error.WriteLine('ALPHA_GOLDEN_PATH_FAILURE_TEST_FAILED')
    exit 1
}

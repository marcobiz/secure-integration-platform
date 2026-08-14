[CmdletBinding()]
param(
    [ValidateSet(
        'All',
        'AlphaGoldenPath_failed_child_output_is_redacted_and_cleanup_still_runs',
        'AlphaGoldenPath_child_timeout_is_bounded_and_cleanup_runs',
        'AlphaGoldenPath_child_output_limit_is_bounded_and_redacted',
        'AlphaGoldenPath_missing_compatible_dotnet_sdk_returns_actionable_stable_error',
        'AlphaGoldenPath_missing_dotnet_host_returns_distinct_stable_error',
        'AlphaGoldenPath_sdk_preflight_does_not_expose_raw_cli_output_or_local_paths')]
    [string] $TestName = 'All'
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
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $backslashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) { [void]$builder.Append(('\' * $backslashes)); $backslashes = 0 }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) { [void]$builder.Append(('\' * ($backslashes * 2))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-Captured {
    param([Parameter(Mandatory = $true)][string] $File, [Parameter(Mandatory = $true)][string[]] $Arguments)
    $captureId = [Guid]::NewGuid().ToString('N')
    $captureRoot = Join-Path ([IO.Path]::GetTempPath()) ('broker-gateway-alpha-capture-' + $captureId)
    New-Item -ItemType Directory -Path $captureRoot | Out-Null
    $stdoutPath = Join-Path $captureRoot 'stdout.txt'
    $stderrPath = Join-Path $captureRoot 'stderr.txt'
    $invocationJson = @{ File = $File; Arguments = @($Arguments) } | ConvertTo-Json -Compress
    $invocationBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($invocationJson))
    $wrapper = @'
$invocationJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:ALPHA_TEST_INVOCATION))
$invocation = $invocationJson | ConvertFrom-Json
$target = [string]$invocation.File
$targetArguments = @($invocation.Arguments | ForEach-Object { [string]$_ })
$child = Start-Process -FilePath $target -ArgumentList $targetArguments -NoNewWindow -Wait -PassThru -RedirectStandardOutput $env:ALPHA_TEST_STDOUT -RedirectStandardError $env:ALPHA_TEST_STDERR
exit $child.ExitCode
'@
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $powerShellHost
    $start.WorkingDirectory = $root
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $wrapperArguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $wrapper)
    if ($null -ne $start.PSObject.Properties['ArgumentList']) {
        foreach ($argument in $wrapperArguments) { [void]$start.ArgumentList.Add($argument) }
    }
    else { $start.Arguments = (($wrapperArguments | ForEach-Object { ConvertTo-NativeArgument ([string]$_) }) -join ' ') }
    $start.EnvironmentVariables['ALPHA_TEST_INVOCATION'] = $invocationBase64
    $start.EnvironmentVariables['ALPHA_TEST_STDOUT'] = $stdoutPath
    $start.EnvironmentVariables['ALPHA_TEST_STDERR'] = $stderrPath
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    $captureLimit = 65536
    try {
        if (-not $process.Start()) { throw 'ALPHA_GOLDEN_PATH_FAILURE_TEST_CHILD_START_FAILED' }
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
        while (-not $process.WaitForExit(100)) {
            $stdoutLength = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) { (Get-Item -LiteralPath $stdoutPath).Length } else { 0L }
            $stderrLength = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) { (Get-Item -LiteralPath $stderrPath).Length } else { 0L }
            if (($stdoutLength + $stderrLength) -gt $captureLimit) {
                try { $process.Kill() } catch { }
                [void]$process.WaitForExit(5000)
                throw 'ALPHA_GOLDEN_PATH_FAILURE_TEST_OUTPUT_LIMIT'
            }
            if ([DateTimeOffset]::UtcNow -ge $deadline) {
                try { $process.Kill() } catch { }
                [void]$process.WaitForExit(5000)
                throw 'ALPHA_GOLDEN_PATH_FAILURE_TEST_CHILD_TIMEOUT'
            }
        }
        $stdoutLength = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) { (Get-Item -LiteralPath $stdoutPath).Length } else { 0L }
        $stderrLength = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) { (Get-Item -LiteralPath $stderrPath).Length } else { 0L }
        if (($stdoutLength + $stderrLength) -gt $captureLimit) { throw 'ALPHA_GOLDEN_PATH_FAILURE_TEST_OUTPUT_LIMIT' }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            StdOut = $(if ($stdoutLength -gt 0) { [IO.File]::ReadAllText($stdoutPath) } else { '' })
            StdErr = $(if ($stderrLength -gt 0) { [IO.File]::ReadAllText($stderrPath) } else { '' })
        }
    }
    finally {
        $process.Dispose()
        $separators = [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd($separators) + [IO.Path]::DirectorySeparatorChar
        $canonicalCaptureRoot = [IO.Path]::GetFullPath($captureRoot)
        if (-not $canonicalCaptureRoot.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            -not ([IO.Path]::GetFileName($canonicalCaptureRoot)).StartsWith('broker-gateway-alpha-capture-', [StringComparison]::Ordinal)) {
            throw 'ALPHA_GOLDEN_PATH_FAILURE_TEST_CAPTURE_CLEANUP_DENIED'
        }
        if (Test-Path -LiteralPath $canonicalCaptureRoot) { Remove-Item -LiteralPath $canonicalCaptureRoot -Recurse -Force }
    }
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

function Assert-ProbeFailure {
    param(
        [Parameter(Mandatory = $true)][string] $Phase,
        [Parameter(Mandatory = $true)][string] $ExpectedError,
        [Parameter(Mandatory = $true)][string[]] $Forbidden,
        [int] $MaximumElapsedSeconds = 30
    )
    Assert-True ((Get-ProjectResourceCount) -eq 0)
    Assert-True (-not (Test-Path -LiteralPath $artifactRoot))
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-Captured -File $powerShellHost -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $runner, '-Phase', $Phase)
    $timer.Stop()
    $combined = $result.StdOut + $result.StdErr
    Assert-True ($result.ExitCode -ne 0)
    Assert-True ($result.StdOut.Trim().Length -eq 0)
    Assert-True ($result.StdErr.Trim() -ceq $ExpectedError)
    Assert-True ($timer.Elapsed.TotalSeconds -lt $MaximumElapsedSeconds)
    foreach ($forbidden in @($Forbidden + @('Authorization:', 'Password=', 'System.InvalidOperationException', $root))) {
        Assert-True ($combined.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -lt 0)
    }
    Assert-True ($combined.IndexOf('ALPHA_GOLDEN_PATH_PASS', [StringComparison]::Ordinal) -lt 0)
    Assert-True ((Get-ProjectResourceCount) -eq 0)
    Assert-True (-not (Test-Path -LiteralPath $artifactRoot))
}

function Test-FailedChildOutput {
    Assert-ProbeFailure `
        -Phase 'FailureOutputProbe' `
        -ExpectedError 'ALPHA_GOLDEN_PATH_CHILD_EXIT_NONZERO;COMPONENT=FailureProbe;EXIT_CODE=37' `
        -Forbidden @(
            'alpha-probe-payload-canary-2f4d68f3',
            'alpha-probe-token-canary-b619f4e8',
            'alpha-probe-password-canary-c2971a05',
            'Sensitive.cs')
}

function Test-ChildTimeout {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $powerShellHost
    $start.Arguments = '-NoLogo -NoProfile -NonInteractive -Command "Start-Sleep -Seconds 60"'
    $start.WorkingDirectory = $root
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $unrelatedProcess = New-Object Diagnostics.Process
    $unrelatedProcess.StartInfo = $start
    try {
        Assert-True ($unrelatedProcess.Start())
        Assert-ProbeFailure `
            -Phase 'FailureTimeoutProbe' `
            -ExpectedError 'ALPHA_GOLDEN_PATH_CHILD_TIMEOUT;COMPONENT=TimeoutProbe' `
            -Forbidden @('alpha-timeout-probe-canary-a12f8029')
        Assert-True (-not $unrelatedProcess.HasExited)
    }
    finally {
        try {
            if (-not $unrelatedProcess.HasExited) {
                $unrelatedProcess.Kill()
                [void]$unrelatedProcess.WaitForExit(5000)
            }
        }
        catch { }
        $unrelatedProcess.Dispose()
    }
}

function Test-ChildOutputLimit {
    Assert-ProbeFailure `
        -Phase 'FailureOutputLimitProbe' `
        -ExpectedError 'ALPHA_GOLDEN_PATH_CHILD_OUTPUT_LIMIT_EXCEEDED;COMPONENT=OutputLimitProbe' `
        -Forbidden @('alpha-output-limit-probe-canary-33c1b471')
}

function Assert-PreflightFailure {
    param(
        [Parameter(Mandatory = $true)][string] $Phase,
        [Parameter(Mandatory = $true)][string] $ExpectedError,
        [string[]] $Forbidden = @()
    )
    Assert-True (-not (Test-Path -LiteralPath $artifactRoot))
    $result = Invoke-Captured -File $powerShellHost -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $runner, '-Phase', $Phase)
    $combined = $result.StdOut + $result.StdErr
    Assert-True ($result.ExitCode -ne 0)
    Assert-True ($result.StdOut.Trim().Length -eq 0)
    Assert-True ($result.StdErr.Trim() -ceq $ExpectedError)
    foreach ($value in @($Forbidden + @($root, 'System.InvalidOperationException', 'Authorization:', 'Password='))) {
        Assert-True ($combined.IndexOf($value, [StringComparison]::OrdinalIgnoreCase) -lt 0)
    }
    Assert-True (-not (Test-Path -LiteralPath $artifactRoot))
}

function Test-MissingCompatibleDotNetSdk {
    Assert-PreflightFailure `
        -Phase 'DotNetSdkUnavailableProbe' `
        -ExpectedError 'ALPHA_GOLDEN_PATH_DOTNET_SDK_UNAVAILABLE;BASELINE=10.0.302;ROLL_FORWARD=latestPatch'
}

function Test-MissingDotNetHost {
    Assert-PreflightFailure `
        -Phase 'DotNetHostMissingProbe' `
        -ExpectedError 'ALPHA_GOLDEN_PATH_DOTNET_HOST_NOT_FOUND'
}

function Test-DotNetPreflightRedaction {
    Assert-PreflightFailure `
        -Phase 'DotNetSdkUnavailableProbe' `
        -ExpectedError 'ALPHA_GOLDEN_PATH_DOTNET_SDK_UNAVAILABLE;BASELINE=10.0.302;ROLL_FORWARD=latestPatch' `
        -Forbidden @('alpha-dotnet-sdk-stdout-canary-7b61d8d2', 'No compatible SDK under')
}

try {
    $tests = if ($TestName -eq 'All') {
        @(
            'AlphaGoldenPath_failed_child_output_is_redacted_and_cleanup_still_runs',
            'AlphaGoldenPath_child_timeout_is_bounded_and_cleanup_runs',
            'AlphaGoldenPath_child_output_limit_is_bounded_and_redacted',
            'AlphaGoldenPath_missing_compatible_dotnet_sdk_returns_actionable_stable_error',
            'AlphaGoldenPath_missing_dotnet_host_returns_distinct_stable_error',
            'AlphaGoldenPath_sdk_preflight_does_not_expose_raw_cli_output_or_local_paths')
    }
    else { @($TestName) }
    foreach ($test in $tests) {
        switch ($test) {
            'AlphaGoldenPath_failed_child_output_is_redacted_and_cleanup_still_runs' { Test-FailedChildOutput }
            'AlphaGoldenPath_child_timeout_is_bounded_and_cleanup_runs' { Test-ChildTimeout }
            'AlphaGoldenPath_child_output_limit_is_bounded_and_redacted' { Test-ChildOutputLimit }
            'AlphaGoldenPath_missing_compatible_dotnet_sdk_returns_actionable_stable_error' { Test-MissingCompatibleDotNetSdk }
            'AlphaGoldenPath_missing_dotnet_host_returns_distinct_stable_error' { Test-MissingDotNetHost }
            'AlphaGoldenPath_sdk_preflight_does_not_expose_raw_cli_output_or_local_paths' { Test-DotNetPreflightRedaction }
        }
        Write-Host "$test PASS"
    }
}
catch {
    [Console]::Error.WriteLine('ALPHA_GOLDEN_PATH_FAILURE_TEST_FAILED')
    exit 1
}

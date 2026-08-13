[CmdletBinding()]
param(
    [ValidateSet(
        'All',
        'M5_Quickstart_Stop_rejects_reparse_artifact_root_without_traversal',
        'M5_Quickstart_Stop_cleans_owned_partial_start_artifacts',
        'M5_Quickstart_Stop_preserves_unowned_artifacts')]
    [string] $TestName = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True {
    param([Parameter(Mandatory = $true)][bool] $Condition)
    if (-not $Condition) { throw 'M5_QUICKSTART_SAFETY_ASSERTION_FAILED' }
}

function Invoke-QuickstartStop {
    param(
        [Parameter(Mandatory = $true)][string] $Script,
        [Parameter(Mandatory = $true)][string] $ArtifactRoot,
        [Parameter(Mandatory = $true)][string] $FakeBin,
        [Parameter(Mandatory = $true)][string] $DockerCalled
    )
    $previousPath = $env:PATH
    $previousCalled = $env:M5_TEST_DOCKER_CALLED
    $previousErrorAction = $ErrorActionPreference
    try {
        $env:PATH = $FakeBin + [IO.Path]::PathSeparator + $previousPath
        $env:M5_TEST_DOCKER_CALLED = $DockerCalled
        $ErrorActionPreference = 'Continue'
        $output = @(& powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Script -Phase Stop -ArtifactRoot $ArtifactRoot 2>&1 |
            ForEach-Object { ([string]$_).Trim() } | Where-Object { $_.Length -gt 0 })
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Lines = $output }
    }
    finally {
        $env:PATH = $previousPath
        $env:M5_TEST_DOCKER_CALLED = $previousCalled
        $ErrorActionPreference = $previousErrorAction
    }
}

function New-TestCase {
    param([Parameter(Mandatory = $true)][string] $Name)
    $base = Join-Path ([IO.Path]::GetTempPath()) ('broker-gateway-m5-safety-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $base | Out-Null
    $fakeBin = Join-Path $base 'fake-bin'
    New-Item -ItemType Directory -Path $fakeBin | Out-Null
    $docker = Join-Path $fakeBin 'docker.cmd'
    $batch = @(
        '@echo off',
        '>>"%M5_TEST_DOCKER_CALLED%" echo called',
        'if "%1"=="ps" exit /b 0',
        'if "%1"=="network" if "%2"=="ls" exit /b 0',
        'if "%1"=="volume" if "%2"=="ls" exit /b 0',
        'exit /b 77',
        '') -join "`r`n"
    [IO.File]::WriteAllText($docker, $batch, [Text.Encoding]::ASCII)
    return [pscustomobject]@{ Root = $base; FakeBin = $fakeBin; DockerCalled = (Join-Path $base 'docker-called.txt'); Name = $Name }
}

function Remove-TestCase {
    param([Parameter(Mandatory = $true)] $Case)
    $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $resolved = [IO.Path]::GetFullPath([string]$Case.Root)
    if (-not $resolved.StartsWith($temp, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFileName($resolved)).StartsWith('broker-gateway-m5-safety-', [StringComparison]::Ordinal)) {
        throw 'M5_QUICKSTART_SAFETY_CLEANUP_DENIED'
    }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}

function Test-ReparseArtifactRoot {
    param([Parameter(Mandatory = $true)][string] $Script)
    $case = New-TestCase -Name 'reparse'
    try {
        $target = Join-Path $case.Root 'target'
        New-Item -ItemType Directory -Path $target | Out-Null
        [IO.File]::WriteAllText((Join-Path $target '.m5-quickstart-owner'), 'secure-integration-m5-quickstart-artifacts-v1', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $target 'sentinel.txt'), 'preserve', [Text.UTF8Encoding]::new($false))
        $junction = Join-Path $case.Root 'artifact-junction'
        New-Item -ItemType Junction -Path $junction -Target $target | Out-Null

        $result = Invoke-QuickstartStop -Script $Script -ArtifactRoot $junction -FakeBin $case.FakeBin -DockerCalled $case.DockerCalled
        Assert-True ($result.ExitCode -ne 0)
        Assert-True ($result.Lines.Count -eq 1)
        Assert-True ([string]$result.Lines[0] -ceq 'M5_QUICKSTART_ARTIFACT_REPARSE_DENIED')
        Assert-True (-not (Test-Path -LiteralPath $case.DockerCalled))
        Assert-True (Test-Path -LiteralPath $junction)
        Assert-True (Test-Path -LiteralPath (Join-Path $target 'sentinel.txt') -PathType Leaf)

        $junctionItem = Get-Item -LiteralPath $junction -Force
        Assert-True (($junctionItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        [IO.Directory]::Delete($junction)
        Assert-True (Test-Path -LiteralPath (Join-Path $target 'sentinel.txt') -PathType Leaf)
    }
    finally { Remove-TestCase -Case $case }
}

function Test-PartialStartCleanup {
    param([Parameter(Mandatory = $true)][string] $Script)
    $case = New-TestCase -Name 'partial'
    try {
        $artifact = Join-Path $case.Root 'partial-artifact'
        $raw = Join-Path $artifact 'raw'
        New-Item -ItemType Directory -Path $raw | Out-Null
        [IO.File]::WriteAllText((Join-Path $artifact '.m5-quickstart-owner'), 'secure-integration-m5-quickstart-artifacts-v1', [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $raw 'partial.txt'), 'synthetic', [Text.UTF8Encoding]::new($false))

        $result = Invoke-QuickstartStop -Script $Script -ArtifactRoot $artifact -FakeBin $case.FakeBin -DockerCalled $case.DockerCalled
        Assert-True ($result.ExitCode -eq 0)
        Assert-True ($result.Lines.Count -eq 1)
        Assert-True ([string]$result.Lines[0] -ceq 'M5_QUICKSTART_STOP_PASS')
        Assert-True (Test-Path -LiteralPath $case.DockerCalled -PathType Leaf)
        Assert-True (-not (Test-Path -LiteralPath $artifact))
    }
    finally { Remove-TestCase -Case $case }
}

function Test-UnownedArtifactPreserved {
    param([Parameter(Mandatory = $true)][string] $Script)
    $case = New-TestCase -Name 'unowned'
    try {
        $artifact = Join-Path $case.Root 'unowned-artifact'
        New-Item -ItemType Directory -Path $artifact | Out-Null
        $sentinel = Join-Path $artifact 'sentinel.txt'
        [IO.File]::WriteAllText($sentinel, 'preserve', [Text.UTF8Encoding]::new($false))

        $result = Invoke-QuickstartStop -Script $Script -ArtifactRoot $artifact -FakeBin $case.FakeBin -DockerCalled $case.DockerCalled
        Assert-True ($result.ExitCode -ne 0)
        Assert-True ($result.Lines.Count -eq 1)
        Assert-True ([string]$result.Lines[0] -ceq 'M5_QUICKSTART_ARTIFACT_ROOT_NOT_OWNED')
        Assert-True (-not (Test-Path -LiteralPath $case.DockerCalled))
        Assert-True (Test-Path -LiteralPath $sentinel -PathType Leaf)
    }
    finally { Remove-TestCase -Case $case }
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'M5_QUICKSTART_SAFETY_WINDOWS_REQUIRED' }
    $script = Join-Path $PSScriptRoot 'Invoke-M5Quickstart.ps1'
    $tests = if ($TestName -eq 'All') {
        @(
            'M5_Quickstart_Stop_rejects_reparse_artifact_root_without_traversal',
            'M5_Quickstart_Stop_cleans_owned_partial_start_artifacts',
            'M5_Quickstart_Stop_preserves_unowned_artifacts')
    } else { @($TestName) }
    foreach ($test in $tests) {
        switch ($test) {
            'M5_Quickstart_Stop_rejects_reparse_artifact_root_without_traversal' { Test-ReparseArtifactRoot -Script $script }
            'M5_Quickstart_Stop_cleans_owned_partial_start_artifacts' { Test-PartialStartCleanup -Script $script }
            'M5_Quickstart_Stop_preserves_unowned_artifacts' { Test-UnownedArtifactPreserved -Script $script }
        }
        Write-Host "$test PASS"
    }
    exit 0
}
catch {
    [Console]::Error.WriteLine('M5_QUICKSTART_SAFETY_TEST_FAILED')
    exit 1
}

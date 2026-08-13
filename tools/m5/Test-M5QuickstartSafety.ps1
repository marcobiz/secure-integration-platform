[CmdletBinding()]
param(
    [ValidateSet(
        'All',
        'M5_Quickstart_cleans_owned_artifacts_inside_authorized_base',
        'M5_Quickstart_rejects_artifact_root_outside_server_owned_base',
        'M5_Quickstart_rejects_repository_and_home_artifact_roots',
        'M5_Quickstart_Stop_rejects_reparse_artifact_root_without_traversal',
        'M5_Quickstart_Stop_cleans_owned_partial_start_artifacts',
        'M5_Quickstart_Stop_preserves_unowned_artifacts')]
    [string] $TestName = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$authorizedBase = [IO.Path]::GetFullPath((Join-Path $repository '.artifacts\m5'))
$authorizedTestsBase = Join-Path $authorizedBase 'tests'
$markerName = '.m5-quickstart-owner'
$markerValue = 'secure-integration-m5-quickstart-artifacts-v1'

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
    $suffix = [Guid]::NewGuid().ToString('N')
    $controlRoot = Join-Path ([IO.Path]::GetTempPath()) ('broker-gateway-m5-safety-' + $suffix)
    New-Item -ItemType Directory -Path $controlRoot | Out-Null
    New-Item -ItemType Directory -Path $authorizedTestsBase -Force | Out-Null
    $fakeBin = Join-Path $controlRoot 'fake-bin'
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
    return [pscustomobject]@{
        Name = $Name
        ControlRoot = $controlRoot
        ArtifactRoot = (Join-Path $authorizedTestsBase ("$Name-$suffix"))
        FakeBin = $fakeBin
        DockerCalled = (Join-Path $controlRoot 'docker-called.txt')
    }
}

function Remove-TestCase {
    param([Parameter(Mandatory = $true)] $Case)
    $comparison = [StringComparison]::OrdinalIgnoreCase
    $allowedPrefix = $authorizedTestsBase.TrimEnd('\') + '\'
    $artifact = [IO.Path]::GetFullPath([string]$Case.ArtifactRoot)
    if (-not $artifact.StartsWith($allowedPrefix, $comparison)) { throw 'M5_QUICKSTART_SAFETY_CLEANUP_DENIED' }
    if (Test-Path -LiteralPath $artifact) {
        $item = Get-Item -LiteralPath $artifact -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { [IO.Directory]::Delete($artifact) }
        else { Remove-Item -LiteralPath $artifact -Recurse -Force }
    }
    $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $control = [IO.Path]::GetFullPath([string]$Case.ControlRoot)
    if (-not $control.StartsWith($tempPrefix, $comparison) -or
        -not ([IO.Path]::GetFileName($control)).StartsWith('broker-gateway-m5-safety-', [StringComparison]::Ordinal)) {
        throw 'M5_QUICKSTART_SAFETY_CLEANUP_DENIED'
    }
    if (Test-Path -LiteralPath $control) { Remove-Item -LiteralPath $control -Recurse -Force }
    if (Test-Path -LiteralPath $authorizedTestsBase) {
        $remaining = @(Get-ChildItem -LiteralPath $authorizedTestsBase -Force)
        if ($remaining.Count -eq 0) { [IO.Directory]::Delete($authorizedTestsBase) }
    }
}

function Assert-StableDenial {
    param(
        [Parameter(Mandatory = $true)] $Result,
        [Parameter(Mandatory = $true)][string] $Code,
        [Parameter(Mandatory = $true)][string] $DockerCalled
    )
    Assert-True ($Result.ExitCode -ne 0)
    Assert-True ($Result.Lines.Count -eq 1)
    Assert-True ([string]$Result.Lines[0] -ceq $Code)
    Assert-True (-not (Test-Path -LiteralPath $DockerCalled))
}

function Test-AuthorizedCleanup {
    param([Parameter(Mandatory = $true)][string] $Script)
    $case = New-TestCase -Name 'authorized'
    try {
        New-Item -ItemType Directory -Path $case.ArtifactRoot | Out-Null
        [IO.File]::WriteAllText((Join-Path $case.ArtifactRoot $markerName), $markerValue, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $case.ArtifactRoot 'sentinel.txt'), 'owned', [Text.UTF8Encoding]::new($false))
        $result = Invoke-QuickstartStop -Script $Script -ArtifactRoot $case.ArtifactRoot -FakeBin $case.FakeBin -DockerCalled $case.DockerCalled
        Assert-True ($result.ExitCode -eq 0)
        Assert-True ($result.Lines.Count -eq 1)
        Assert-True ([string]$result.Lines[0] -ceq 'M5_QUICKSTART_STOP_PASS')
        Assert-True (Test-Path -LiteralPath $case.DockerCalled -PathType Leaf)
        Assert-True (-not (Test-Path -LiteralPath $case.ArtifactRoot))
    }
    finally { Remove-TestCase -Case $case }
}

function Test-OutsideBaseDenied {
    param([Parameter(Mandatory = $true)][string] $Script)
    $case = New-TestCase -Name 'outside'
    try {
        $outside = Join-Path $case.ControlRoot 'outside-artifact'
        New-Item -ItemType Directory -Path $outside | Out-Null
        [IO.File]::WriteAllText((Join-Path $outside $markerName), $markerValue, [Text.UTF8Encoding]::new($false))
        $sentinel = Join-Path $outside 'sentinel.txt'
        [IO.File]::WriteAllText($sentinel, 'preserve', [Text.UTF8Encoding]::new($false))
        $result = Invoke-QuickstartStop -Script $Script -ArtifactRoot $outside -FakeBin $case.FakeBin -DockerCalled $case.DockerCalled
        Assert-StableDenial -Result $result -Code 'M5_QUICKSTART_ARTIFACT_ROOT_OUTSIDE_ALLOWED_BASE' -DockerCalled $case.DockerCalled
        Assert-True (Test-Path -LiteralPath $outside -PathType Container)
        Assert-True ((Get-Content -LiteralPath $sentinel -Raw) -ceq 'preserve')
    }
    finally { Remove-TestCase -Case $case }
}

function Test-RepositoryHomeAndBaseDenied {
    param([Parameter(Mandatory = $true)][string] $Script)
    $case = New-TestCase -Name 'broad-roots'
    try {
        $userProfileRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
        $volumeRoot = [IO.Path]::GetPathRoot($repository)
        $repositorySibling = Join-Path (Split-Path -Parent $repository) 'broker-gateway-artifact-sibling'
        foreach ($candidate in @($repository, (Join-Path $repository 'src'), (Join-Path $repository 'tools'), (Join-Path $repository '.artifacts'), $authorizedBase, $userProfileRoot, $volumeRoot, $repositorySibling)) {
            $result = Invoke-QuickstartStop -Script $Script -ArtifactRoot $candidate -FakeBin $case.FakeBin -DockerCalled $case.DockerCalled
            Assert-StableDenial -Result $result -Code 'M5_QUICKSTART_ARTIFACT_ROOT_OUTSIDE_ALLOWED_BASE' -DockerCalled $case.DockerCalled
        }
        foreach ($candidate in @(
            (Join-Path $authorizedBase 'tests\..\traversal'),
            (Join-Path $authorizedBase 'tests\artifact:stream'),
            '\\localhost\c$\broker-gateway-artifact-root')) {
            $result = Invoke-QuickstartStop -Script $Script -ArtifactRoot $candidate -FakeBin $case.FakeBin -DockerCalled $case.DockerCalled
            Assert-StableDenial -Result $result -Code 'M5_QUICKSTART_ARTIFACT_ROOT_INVALID' -DockerCalled $case.DockerCalled
        }
    }
    finally { Remove-TestCase -Case $case }
}

function Test-ReparseArtifactRoot {
    param([Parameter(Mandatory = $true)][string] $Script)
    $case = New-TestCase -Name 'reparse'
    try {
        $target = Join-Path $case.ControlRoot 'target'
        New-Item -ItemType Directory -Path $target | Out-Null
        [IO.File]::WriteAllText((Join-Path $target $markerName), $markerValue, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $target 'sentinel.txt'), 'preserve', [Text.UTF8Encoding]::new($false))
        New-Item -ItemType Junction -Path $case.ArtifactRoot -Target $target | Out-Null

        $result = Invoke-QuickstartStop -Script $Script -ArtifactRoot $case.ArtifactRoot -FakeBin $case.FakeBin -DockerCalled $case.DockerCalled
        Assert-StableDenial -Result $result -Code 'M5_QUICKSTART_ARTIFACT_REPARSE_DENIED' -DockerCalled $case.DockerCalled
        Assert-True (Test-Path -LiteralPath $case.ArtifactRoot)
        Assert-True ((Get-Content -LiteralPath (Join-Path $target 'sentinel.txt') -Raw) -ceq 'preserve')
    }
    finally { Remove-TestCase -Case $case }
}

function Test-PartialStartCleanup {
    param([Parameter(Mandatory = $true)][string] $Script)
    $case = New-TestCase -Name 'partial'
    try {
        $raw = Join-Path $case.ArtifactRoot 'raw'
        New-Item -ItemType Directory -Path $raw | Out-Null
        [IO.File]::WriteAllText((Join-Path $case.ArtifactRoot $markerName), $markerValue, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $raw 'partial.txt'), 'synthetic', [Text.UTF8Encoding]::new($false))
        $result = Invoke-QuickstartStop -Script $Script -ArtifactRoot $case.ArtifactRoot -FakeBin $case.FakeBin -DockerCalled $case.DockerCalled
        Assert-True ($result.ExitCode -eq 0)
        Assert-True ($result.Lines.Count -eq 1)
        Assert-True ([string]$result.Lines[0] -ceq 'M5_QUICKSTART_STOP_PASS')
        Assert-True (-not (Test-Path -LiteralPath $case.ArtifactRoot))
    }
    finally { Remove-TestCase -Case $case }
}

function Test-UnownedArtifactPreserved {
    param([Parameter(Mandatory = $true)][string] $Script)
    $case = New-TestCase -Name 'unowned'
    try {
        New-Item -ItemType Directory -Path $case.ArtifactRoot | Out-Null
        $sentinel = Join-Path $case.ArtifactRoot 'sentinel.txt'
        [IO.File]::WriteAllText($sentinel, 'preserve', [Text.UTF8Encoding]::new($false))
        $result = Invoke-QuickstartStop -Script $Script -ArtifactRoot $case.ArtifactRoot -FakeBin $case.FakeBin -DockerCalled $case.DockerCalled
        Assert-StableDenial -Result $result -Code 'M5_QUICKSTART_ARTIFACT_ROOT_NOT_OWNED' -DockerCalled $case.DockerCalled
        Assert-True ((Get-Content -LiteralPath $sentinel -Raw) -ceq 'preserve')
    }
    finally { Remove-TestCase -Case $case }
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'M5_QUICKSTART_SAFETY_WINDOWS_REQUIRED' }
    $script = Join-Path $PSScriptRoot 'Invoke-M5Quickstart.ps1'
    $tests = if ($TestName -eq 'All') {
        @(
            'M5_Quickstart_cleans_owned_artifacts_inside_authorized_base',
            'M5_Quickstart_rejects_artifact_root_outside_server_owned_base',
            'M5_Quickstart_rejects_repository_and_home_artifact_roots',
            'M5_Quickstart_Stop_rejects_reparse_artifact_root_without_traversal',
            'M5_Quickstart_Stop_cleans_owned_partial_start_artifacts',
            'M5_Quickstart_Stop_preserves_unowned_artifacts')
    } else { @($TestName) }
    foreach ($test in $tests) {
        switch ($test) {
            'M5_Quickstart_cleans_owned_artifacts_inside_authorized_base' { Test-AuthorizedCleanup -Script $script }
            'M5_Quickstart_rejects_artifact_root_outside_server_owned_base' { Test-OutsideBaseDenied -Script $script }
            'M5_Quickstart_rejects_repository_and_home_artifact_roots' { Test-RepositoryHomeAndBaseDenied -Script $script }
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

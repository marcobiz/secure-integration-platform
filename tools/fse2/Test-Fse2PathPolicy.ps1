[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $PSScriptRoot 'Fse2PathPolicy.psm1') -Force
$runId = [Guid]::NewGuid().ToString('N')
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('fse2-path-policy-test-' + $runId)
$testRootPlan = Get-Fse2PathSnapshot -Path $testRoot -Kind OutputDirectory -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_ROOT'
Assert-Fse2PathSnapshot -Snapshot $testRootPlan | Out-Null
New-Item -ItemType Directory -Path $testRoot | Out-Null
$testRootSnapshot = Get-Fse2PathSnapshot -Path $testRoot -Kind Directory -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_ROOT'
$testRootMarker = New-Fse2OwnershipMarker -DirectorySnapshot $testRootSnapshot -RunId $runId
$reparsePoints = New-Object System.Collections.Generic.List[string]

function Assert-Denied {
    param([Parameter(Mandatory = $true)][scriptblock] $Action, [Parameter(Mandatory = $true)][string] $Case)
    try { & $Action; throw ('FSE2_PATH_TEST_EXPECTED_DENIAL_MISSING:' + $Case) }
    catch {
        if ($_.Exception.Message -like 'FSE2_PATH_TEST_EXPECTED_DENIAL_MISSING:*') { throw }
        Write-Host ('FSE2_PATH_POLICY_NEGATIVE_PASS=' + $Case)
    }
}

try {
    $safe = Join-Path $testRoot 'safe'
    $alternate = Join-Path $testRoot 'alternate'
    New-Item -ItemType Directory -Path $safe | Out-Null
    New-Item -ItemType Directory -Path $alternate | Out-Null
    $source = Join-Path $safe 'source.txt'
    [IO.File]::WriteAllText($source, 'synthetic', [Text.Encoding]::ASCII)
    $sourceSnapshot = Get-Fse2PathSnapshot -Path $source -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_SOURCE' -MaximumBytes 1024
    Assert-Fse2PathSnapshot -Snapshot $sourceSnapshot | Out-Null

    Assert-Denied { Get-Fse2PathSnapshot -Path (Join-Path $root 'global.json') -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_REPO_SOURCE' | Out-Null } 'repository-source'
    Assert-Denied { Get-Fse2PathSnapshot -Path (Join-Path $root '.artifacts\forbidden-output-' + $runId) -Kind OutputDirectory -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_REPO_OUTPUT' | Out-Null } 'repository-output'
    Assert-Denied { Get-Fse2PathSnapshot -Path 'relative\source.txt' -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_RELATIVE' | Out-Null } 'relative'

    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        Assert-Denied { Get-Fse2PathSnapshot -Path '\\server\share\source.txt' -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_UNC' | Out-Null } 'unc'
        Assert-Denied { Get-Fse2PathSnapshot -Path '\\?\C:\source.txt' -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_DEVICE' | Out-Null } 'device'
        Assert-Denied { Get-Fse2PathSnapshot -Path ($source + ':stream') -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_ADS' | Out-Null } 'alternate-data-stream'

        $junction = Join-Path $testRoot 'ancestor-junction'
        New-Item -ItemType Junction -Path $junction -Target $safe | Out-Null
        $reparsePoints.Add($junction)
        Assert-Denied { Get-Fse2PathSnapshot -Path (Join-Path $junction 'source.txt') -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_JUNCTION' | Out-Null } 'ancestor-junction'

        $directorySymlink = Join-Path $testRoot 'ancestor-symlink'
        try { New-Item -ItemType SymbolicLink -Path $directorySymlink -Target $safe | Out-Null }
        catch [UnauthorizedAccessException] {
            New-Item -ItemType Junction -Path $directorySymlink -Target $safe | Out-Null
            Write-Host 'FSE2_PATH_POLICY_WINDOWS_SYMLINK_SURROGATE=JUNCTION; ACTUAL_SYMLINK_REQUIRED_ON_LINUX'
        }
        $reparsePoints.Add($directorySymlink)
        Assert-Denied { Get-Fse2PathSnapshot -Path (Join-Path $directorySymlink 'source.txt') -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_SYMLINK' | Out-Null } 'ancestor-symlink'

        $leafSymlink = Join-Path $testRoot 'leaf-symlink.txt'
        $leafKind = 'File'
        try { New-Item -ItemType SymbolicLink -Path $leafSymlink -Target $source | Out-Null }
        catch [UnauthorizedAccessException] {
            $leafSymlink = Join-Path $testRoot 'leaf-reparse-directory'
            New-Item -ItemType Junction -Path $leafSymlink -Target $safe | Out-Null
            $leafKind = 'Directory'
        }
        $reparsePoints.Add($leafSymlink)
        Assert-Denied { Get-Fse2PathSnapshot -Path $leafSymlink -Kind $leafKind -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_LEAF' | Out-Null } 'leaf-reparse'
    } else {
        Assert-Denied { Get-Fse2PathSnapshot -Path '//server/share/source.txt' -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_NETWORK' | Out-Null } 'network-path'
        $directorySymlink = Join-Path $testRoot 'ancestor-symlink'
        New-Item -ItemType SymbolicLink -Path $directorySymlink -Target $safe | Out-Null
        $reparsePoints.Add($directorySymlink)
        Assert-Denied { Get-Fse2PathSnapshot -Path (Join-Path $directorySymlink 'source.txt') -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_SYMLINK' | Out-Null } 'ancestor-symlink'
        $leafSymlink = Join-Path $testRoot 'leaf-symlink.txt'
        New-Item -ItemType SymbolicLink -Path $leafSymlink -Target $source | Out-Null
        $reparsePoints.Add($leafSymlink)
        Assert-Denied { Get-Fse2PathSnapshot -Path $leafSymlink -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_LEAF' | Out-Null } 'leaf-reparse'
    }

    $writeParent = Join-Path $testRoot 'write-parent'
    New-Item -ItemType Directory -Path $writeParent | Out-Null
    $writePlan = Get-Fse2PathSnapshot -Path (Join-Path $writeParent 'output') -Kind OutputDirectory -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_WRITE'
    $movedWriteParent = Join-Path $testRoot 'write-parent-original'
    Move-Item -LiteralPath $writeParent -Destination $movedWriteParent
    New-Item -ItemType Directory -Path $writeParent | Out-Null
    Assert-Denied { Assert-Fse2PathSnapshot -Snapshot $writePlan | Out-Null } 'parent-substituted-before-write'
    if (Test-Path -LiteralPath (Join-Path $writeParent 'output')) { throw 'FSE2_PATH_TEST_UNAUTHORIZED_OUTPUT_CREATED' }

    $cleanupParent = Join-Path $testRoot 'cleanup-parent'
    $owned = Join-Path $cleanupParent 'owned'
    New-Item -ItemType Directory -Path $cleanupParent | Out-Null
    New-Item -ItemType Directory -Path $owned | Out-Null
    $ownedSnapshot = Get-Fse2PathSnapshot -Path $owned -Kind Directory -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_CLEANUP'
    $ownedMarker = New-Fse2OwnershipMarker -DirectorySnapshot $ownedSnapshot -RunId $runId
    $movedCleanupParent = Join-Path $testRoot 'cleanup-parent-original'
    Move-Item -LiteralPath $cleanupParent -Destination $movedCleanupParent
    New-Item -ItemType Directory -Path $cleanupParent | Out-Null
    Assert-Denied { Remove-Fse2OwnedDirectory -DirectorySnapshot $ownedSnapshot -MarkerSnapshot $ownedMarker -RunId $runId } 'parent-substituted-before-cleanup'
    if (-not (Test-Path -LiteralPath (Join-Path $movedCleanupParent 'owned'))) { throw 'FSE2_PATH_TEST_ORIGINAL_TARGET_REMOVED' }

    $hostile = Join-Path $testRoot 'hostile-marker'
    New-Item -ItemType Directory -Path $hostile | Out-Null
    $hostileSnapshot = Get-Fse2PathSnapshot -Path $hostile -Kind Directory -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_HOSTILE'
    $hostileMarker = New-Fse2OwnershipMarker -DirectorySnapshot $hostileSnapshot -RunId $runId
    [IO.File]::WriteAllText($hostileMarker.FullPath, '{"schemaVersion":1,"runId":"00000000000000000000000000000000","directoryIdentity":"hostile"}', [Text.Encoding]::ASCII)
    $hostileMarker = Get-Fse2PathSnapshot -Path $hostileMarker.FullPath -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PATH_TEST_HOSTILE_MARKER' -MaximumBytes 4096
    Assert-Denied { Remove-Fse2OwnedDirectory -DirectorySnapshot $hostileSnapshot -MarkerSnapshot $hostileMarker -RunId $runId } 'hostile-cleanup-marker'
    if (-not (Test-Path -LiteralPath $hostile)) { throw 'FSE2_PATH_TEST_HOSTILE_TARGET_REMOVED' }

    Write-Host 'FSE2_PATH_POLICY_SELF_TEST_PASS; UNAUTHORIZED_OUTPUTS=0'
}
finally {
    foreach ($reparsePoint in $reparsePoints) {
        if (Test-Path -LiteralPath $reparsePoint) {
            $item = Get-Item -LiteralPath $reparsePoint -Force
            if ($item.PSIsContainer) { [IO.Directory]::Delete($reparsePoint) } else { [IO.File]::Delete($reparsePoint) }
        }
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Fse2OwnedDirectory -DirectorySnapshot $testRootSnapshot -MarkerSnapshot $testRootMarker -RunId $runId
    }
}

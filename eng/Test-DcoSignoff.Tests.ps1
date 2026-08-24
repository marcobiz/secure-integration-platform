[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$target = Join-Path $PSScriptRoot 'Test-DcoSignoff.ps1'
$tempBase = [IO.Path]::GetTempPath().TrimEnd([IO.Path]::DirectorySeparatorChar)
$testRoot = Join-Path $tempBase ('secure-integration-dco-' + [Guid]::NewGuid().ToString('N'))

function Invoke-Git {
    param([string[]] $Arguments)
    & git -C $testRoot @Arguments *> $null
    if ($LASTEXITCODE -ne 0) { throw "DCO_SELF_TEST_GIT_FAILED: $($Arguments -join ' ')" }
}

function New-TestCommit {
    param([string] $Subject, [string] $Body)
    $marker = Join-Path $testRoot 'marker.txt'
    [IO.File]::AppendAllText($marker, "$Subject`n", [Text.UTF8Encoding]::new($false))
    Invoke-Git @('add', 'marker.txt')
    & git -C $testRoot commit -m $Subject -m $Body *> $null
    if ($LASTEXITCODE -ne 0) { throw 'DCO_SELF_TEST_COMMIT_FAILED' }
    return (& git -C $testRoot rev-parse HEAD).Trim()
}

try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    Invoke-Git @('init')
    Invoke-Git @('config', 'core.autocrlf', 'false')
    Invoke-Git @('config', 'user.name', 'DCO Test Author')
    Invoke-Git @('config', 'user.email', 'dco-test@example.test')

    $baseline = New-TestCommit 'unsigned baseline predating policy' 'No sign-off is intentionally present.'
    $signed = New-TestCommit 'signed contribution' 'Signed-off-by: DCO Test Author <dco-test@example.test>'
    & $target -RepositoryPath $testRoot -BaseCommit $baseline -HeadCommit $signed *> $null
    if ($LASTEXITCODE -ne 0) { throw 'DCO_SELF_TEST_POSITIVE_FAILED' }
    Write-Host 'ALPHA_DCO_new_human_commit_with_matching_signoff PASS'
    Write-Host 'ALPHA_DCO_pre_policy_history_is_not_evaluated_retroactively PASS'

    $unsigned = New-TestCommit 'unsigned contribution' 'No trailer.'
    $unsignedRejected = $false
    try { & $target -RepositoryPath $testRoot -BaseCommit $signed -HeadCommit $unsigned *> $null } catch { $unsignedRejected = $_.Exception.Message -match 'DCO_SIGNOFF_MISSING_OR_MISMATCHED' }
    if (-not $unsignedRejected) { throw 'DCO_SELF_TEST_UNSIGNED_NOT_REJECTED' }
    Write-Host 'ALPHA_DCO_unsigned_human_commit_is_rejected PASS'

    $mismatch = New-TestCommit 'mismatched contribution' 'Signed-off-by: Different Person <different@example.test>'
    $mismatchRejected = $false
    try { & $target -RepositoryPath $testRoot -BaseCommit $unsigned -HeadCommit $mismatch *> $null } catch { $mismatchRejected = $_.Exception.Message -match 'DCO_SIGNOFF_MISSING_OR_MISMATCHED' }
    if (-not $mismatchRejected) { throw 'DCO_SELF_TEST_MISMATCH_NOT_REJECTED' }
    Write-Host 'ALPHA_DCO_mismatched_signoff_is_rejected PASS'
    Write-Host 'ALPHA_DCO_self_tests PASS'
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        $resolved = [IO.Path]::GetFullPath($testRoot)
        if (-not $resolved.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'DCO_SELF_TEST_CLEANUP_TARGET_INVALID' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

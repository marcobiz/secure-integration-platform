[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $BaseCommit,
    [Parameter(Mandatory = $true)][string] $HeadCommit,
    [string] $RepositoryPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repository = if ([string]::IsNullOrWhiteSpace($RepositoryPath)) { (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path } else { (Resolve-Path -LiteralPath $RepositoryPath).Path }
if ($BaseCommit -cnotmatch '^[0-9a-f]{40}$' -or $HeadCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'DCO_COMMIT_RANGE_INVALID' }

function Invoke-GitText {
    param(
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][string] $FailureCode,
        [switch] $AllowEmpty
    )

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = @(& git -C $repository @Arguments 2>$null)
        $gitExitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousErrorActionPreference }
    if ($gitExitCode -ne 0) { throw $FailureCode }
    $text = ($lines -join "`n").TrimEnd([char[]]"`r`n")
    if (-not $AllowEmpty -and [string]::IsNullOrWhiteSpace($text)) { throw $FailureCode }
    return $text
}

function Invoke-GitStatus {
    param([Parameter(Mandatory = $true)][string[]] $Arguments)

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & git -C $repository @Arguments *> $null
        $gitExitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousErrorActionPreference }
    return $gitExitCode
}

$shallow = Invoke-GitText -Arguments @('rev-parse', '--is-shallow-repository') -FailureCode 'DCO_HISTORY_UNREADABLE'
if ($shallow -cne 'false') { throw 'DCO_SHALLOW_HISTORY_UNAVAILABLE' }

if ((Invoke-GitStatus -Arguments @('cat-file', '-e', "$BaseCommit^{commit}")) -ne 0) { throw 'DCO_BASE_COMMIT_MISSING' }
if ((Invoke-GitStatus -Arguments @('cat-file', '-e', "$HeadCommit^{commit}")) -ne 0) { throw 'DCO_HEAD_COMMIT_MISSING' }
if ((Invoke-GitStatus -Arguments @('merge-base', '--is-ancestor', $BaseCommit, $HeadCommit)) -ne 0) { throw 'DCO_BASE_NOT_ANCESTOR_OF_HEAD' }

$commits = @(& git -C $repository rev-list --reverse "$BaseCommit..$HeadCommit" 2>$null)
if ($LASTEXITCODE -ne 0) { throw 'DCO_COMMIT_RANGE_ENUMERATION_FAILED' }
if ($commits.Count -eq 0) { throw 'DCO_COMMIT_RANGE_EMPTY' }

$signedOffCount = 0
foreach ($commit in $commits) {
    if ($commit -cnotmatch '^[0-9a-f]{40}$') { throw 'DCO_COMMIT_RANGE_ENUMERATION_INVALID' }
    $authorName = Invoke-GitText -Arguments @('show', '-s', '--no-show-signature', '--format=%an', $commit) -FailureCode "DCO_COMMIT_METADATA_INVALID: $commit"
    $authorEmail = Invoke-GitText -Arguments @('show', '-s', '--no-show-signature', '--format=%ae', $commit) -FailureCode "DCO_COMMIT_METADATA_INVALID: $commit"
    $message = Invoke-GitText -Arguments @('show', '-s', '--no-show-signature', '--format=%B', $commit) -FailureCode "DCO_COMMIT_MESSAGE_INVALID: $commit" -AllowEmpty

    $parsedTrailers = @($message | & git -C $repository interpret-trailers --parse 2>$null)
    if ($LASTEXITCODE -ne 0) { throw "DCO_TRAILER_PARSE_FAILED: $commit" }
    $expected = "Signed-off-by: $authorName <$authorEmail>"
    $canonicalTrailerBlock = $parsedTrailers -join "`n"
    if ([string]::IsNullOrWhiteSpace($canonicalTrailerBlock) -or
        -not $message.EndsWith("`n`n$canonicalTrailerBlock", [StringComparison]::Ordinal)) {
        throw "DCO_SIGNOFF_MISSING_OR_MISMATCHED: $commit expected=$expected"
    }
    $signoffTrailers = @($parsedTrailers | Where-Object { $_.StartsWith('Signed-off-by:', [StringComparison]::Ordinal) })
    if ($signoffTrailers.Count -eq 0) { throw "DCO_SIGNOFF_MISSING_OR_MISMATCHED: $commit expected=$expected" }
    foreach ($signoff in $signoffTrailers) {
        if ($signoff -cne $expected) { throw "DCO_SIGNOFF_MISSING_OR_MISMATCHED: $commit expected=$expected" }
    }
    $signedOffCount++
}

[pscustomobject]@{
    status = 'PASS'
    baseCommit = $BaseCommit
    headCommit = $HeadCommit
    commitsChecked = $commits.Count
    signedOffCommitsChecked = $signedOffCount
    botExemption = 'NONE'
    trailerParser = 'git interpret-trailers --parse'
    historyRetroactive = $false
} | ConvertTo-Json -Compress

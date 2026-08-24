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

& git -C $repository cat-file -e "$BaseCommit^{commit}"
if ($LASTEXITCODE -ne 0) { throw 'DCO_BASE_COMMIT_MISSING' }
& git -C $repository cat-file -e "$HeadCommit^{commit}"
if ($LASTEXITCODE -ne 0) { throw 'DCO_HEAD_COMMIT_MISSING' }
& git -C $repository merge-base --is-ancestor $BaseCommit $HeadCommit
if ($LASTEXITCODE -ne 0) { throw 'DCO_BASE_NOT_ANCESTOR_OF_HEAD' }

$commits = @(& git -C $repository rev-list --reverse "$BaseCommit..$HeadCommit")
if ($LASTEXITCODE -ne 0) { throw 'DCO_COMMIT_RANGE_ENUMERATION_FAILED' }
$humanCount = 0
$botCount = 0
foreach ($commit in $commits) {
    $authorName = (& git -C $repository show -s --format=%an $commit | Out-String).Trim()
    $authorEmail = (& git -C $repository show -s --format=%ae $commit | Out-String).Trim()
    $message = (& git -C $repository show -s --format=%B $commit | Out-String).TrimEnd()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($authorName) -or [string]::IsNullOrWhiteSpace($authorEmail)) {
        throw "DCO_COMMIT_METADATA_INVALID: $commit"
    }

    $strictGithubBot = $authorName -cmatch '^[A-Za-z0-9_.-]+\[bot\]$' -and
        $authorEmail -cmatch '^[0-9]+\+[A-Za-z0-9_.-]+\[bot\]@users\.noreply\.github\.com$'
    if ($strictGithubBot) { $botCount++; continue }

    $humanCount++
    $expected = "Signed-off-by: $authorName <$authorEmail>"
    $matchingTrailers = @($message -split "`r?`n" | Where-Object { $_ -ceq $expected })
    if ($matchingTrailers.Count -eq 0) { throw "DCO_SIGNOFF_MISSING_OR_MISMATCHED: $commit expected=$expected" }
}

[pscustomobject]@{
    status = 'PASS'
    baseCommit = $BaseCommit
    headCommit = $HeadCommit
    commitsChecked = $commits.Count
    humanCommitsChecked = $humanCount
    strictGithubAppBotCommitsSkipped = $botCount
    historyRetroactive = $false
} | ConvertTo-Json -Compress

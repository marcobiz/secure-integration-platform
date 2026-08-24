[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$target = Join-Path $PSScriptRoot 'Test-DcoSignoff.ps1'
$tempBase = [IO.Path]::GetTempPath().TrimEnd([IO.Path]::DirectorySeparatorChar)
$testRoot = Join-Path $tempBase ('secure-integration-dco-' + [Guid]::NewGuid().ToString('N'))
$shallowRoot = $testRoot + '-shallow'
$script:commitOrdinal = 0

function Invoke-Git {
    param([string[]] $Arguments)
    & git -C $testRoot @Arguments *> $null
    if ($LASTEXITCODE -ne 0) { throw "DCO_SELF_TEST_GIT_FAILED: $($Arguments -join ' ')" }
}

function New-TestCommit {
    param(
        [Parameter(Mandatory = $true)][string] $Message,
        [string] $AuthorName = 'DCO Test Author',
        [string] $AuthorEmail = 'dco-test@example.test'
    )

    $script:commitOrdinal++
    $marker = Join-Path $testRoot 'marker.txt'
    $messagePath = Join-Path $testRoot 'commit-message.txt'
    [IO.File]::AppendAllText($marker, "$($script:commitOrdinal)`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($messagePath, $Message, [Text.UTF8Encoding]::new($false))
    Invoke-Git @('add', 'marker.txt')
    & git -C $testRoot -c "user.name=$AuthorName" -c "user.email=$AuthorEmail" commit --file $messagePath --cleanup=verbatim *> $null
    if ($LASTEXITCODE -ne 0) { throw 'DCO_SELF_TEST_COMMIT_FAILED' }
    $commit = (& git -C $testRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -cnotmatch '^[0-9a-f]{40}$') { throw 'DCO_SELF_TEST_HEAD_INVALID' }
    return $commit
}

function Assert-DcoPasses {
    param([string] $Name, [string] $Base, [string] $Head)
    $result = & $target -RepositoryPath $testRoot -BaseCommit $Base -HeadCommit $Head | ConvertFrom-Json
    if ([string]$result.status -cne 'PASS' -or [int]$result.commitsChecked -ne 1 -or
        [int]$result.signedOffCommitsChecked -ne 1 -or [string]$result.botExemption -cne 'NONE' -or
        [string]$result.trailerParser -cne 'git interpret-trailers --parse') {
        throw "$Name returned an invalid result"
    }
    Write-Host "$Name PASS"
}

function Assert-DcoRejects {
    param(
        [string] $Name,
        [string] $Base,
        [string] $Head,
        [string] $ExpectedFailure,
        [string] $RepositoryPath = $testRoot
    )

    $failure = $null
    try { & $target -RepositoryPath $RepositoryPath -BaseCommit $Base -HeadCommit $Head *> $null }
    catch { $failure = $_.Exception.Message }
    if ([string]::IsNullOrWhiteSpace($failure) -or $failure -cnotlike "$ExpectedFailure*") {
        throw "$Name expectedFailure=$ExpectedFailure actualFailure=$failure"
    }
    Write-Host "$Name PASS"
}

function Remove-TestDirectory {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not $resolved.StartsWith($tempBase + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'DCO_SELF_TEST_CLEANUP_TARGET_INVALID'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    Invoke-Git @('init')
    Invoke-Git @('config', 'core.autocrlf', 'false')

    $baseline = New-TestCommit "unsigned baseline predating policy`n`nNo sign-off is intentionally present.`n"
    $signed = New-TestCommit "signed contribution`n`nSigned-off-by: DCO Test Author <dco-test@example.test>`n"
    Assert-DcoPasses 'ALPHA_DCO_canonical_final_trailer_positive' $baseline $signed
    Write-Host 'ALPHA_DCO_pre_policy_history_is_not_evaluated_retroactively PASS'

    $withOtherTrailer = New-TestCommit "signed contribution with review`n`nReviewed-by: DCO Reviewer <reviewer@example.test>`nSigned-off-by: DCO Test Author <dco-test@example.test>`n"
    Assert-DcoPasses 'ALPHA_DCO_other_git_trailers_with_signoff_positive' $signed $withOtherTrailer

    $subjectPseudo = New-TestCommit "Signed-off-by: DCO Test Author <dco-test@example.test>`n"
    Assert-DcoRejects 'ALPHA_DCO_subject_pseudo_trailer_negative' $withOtherTrailer $subjectPseudo 'DCO_SIGNOFF_MISSING_OR_MISMATCHED'

    $bodyPseudo = New-TestCommit "body pseudo trailer`n`nSigned-off-by: DCO Test Author <dco-test@example.test>`n`nThis prose follows the pseudo trailer.`n"
    Assert-DcoRejects 'ALPHA_DCO_body_pseudo_trailer_negative' $subjectPseudo $bodyPseudo 'DCO_SIGNOFF_MISSING_OR_MISMATCHED'

    $textAfterTrailer = New-TestCommit "text after presumed trailer`n`nSigned-off-by: DCO Test Author <dco-test@example.test>`nNot a Git trailer line.`n"
    Assert-DcoRejects 'ALPHA_DCO_text_after_presumed_trailer_negative' $bodyPseudo $textAfterTrailer 'DCO_SIGNOFF_MISSING_OR_MISMATCHED'

    $malformed = New-TestCommit "malformed trailer`n`nSigned-off-by DCO Test Author <dco-test@example.test>`n"
    Assert-DcoRejects 'ALPHA_DCO_malformed_trailer_negative' $textAfterTrailer $malformed 'DCO_SIGNOFF_MISSING_OR_MISMATCHED'

    $emptyTrailer = New-TestCommit "empty trailer`n`nSigned-off-by:`n"
    Assert-DcoRejects 'ALPHA_DCO_empty_trailer_negative' $malformed $emptyTrailer 'DCO_SIGNOFF_MISSING_OR_MISMATCHED'

    $emailMismatch = New-TestCommit "email mismatch`n`nSigned-off-by: DCO Test Author <different@example.test>`n"
    Assert-DcoRejects 'ALPHA_DCO_author_email_mismatch_negative' $emptyTrailer $emailMismatch 'DCO_SIGNOFF_MISSING_OR_MISMATCHED'

    $nameMismatch = New-TestCommit "name mismatch`n`nSigned-off-by: Different Person <dco-test@example.test>`n"
    Assert-DcoRejects 'ALPHA_DCO_author_name_mismatch_negative' $emailMismatch $nameMismatch 'DCO_SIGNOFF_MISSING_OR_MISMATCHED'

    $botName = New-TestCommit "unsigned bot-name spoof`n`nNo sign-off.`n" -AuthorName 'dependabot[bot]' -AuthorEmail 'dependabot@example.test'
    Assert-DcoRejects 'ALPHA_DCO_bot_name_spoof_negative' $nameMismatch $botName 'DCO_SIGNOFF_MISSING_OR_MISMATCHED'

    $botEmail = New-TestCommit "unsigned bot-email spoof`n`nNo sign-off.`n" -AuthorName 'Ordinary Author' -AuthorEmail '123+dependabot[bot]@users.noreply.github.com'
    Assert-DcoRejects 'ALPHA_DCO_bot_email_spoof_negative' $botName $botEmail 'DCO_SIGNOFF_MISSING_OR_MISMATCHED'

    $selfDeclaredBot = New-TestCommit "unsigned self-declared bot`n`nNo sign-off.`n" -AuthorName 'Human[bot]' -AuthorEmail '999+Human[bot]@users.noreply.github.com'
    Assert-DcoRejects 'ALPHA_DCO_human_self_declared_bot_negative' $botEmail $selfDeclaredBot 'DCO_SIGNOFF_MISSING_OR_MISMATCHED'

    $missing = New-TestCommit "missing signoff`n`nNo trailer is present.`n"
    Assert-DcoRejects 'ALPHA_DCO_missing_signoff_negative' $selfDeclaredBot $missing 'DCO_SIGNOFF_MISSING_OR_MISMATCHED'
    Assert-DcoRejects 'ALPHA_DCO_empty_range_negative' $missing $missing 'DCO_COMMIT_RANGE_EMPTY'
    Assert-DcoRejects 'ALPHA_DCO_missing_history_negative' ('0' * 40) $missing 'DCO_BASE_COMMIT_MISSING'

    $sourceUri = 'file:///' + $testRoot.Replace('\', '/')
    & git clone --quiet --depth 1 $sourceUri $shallowRoot *> $null
    if ($LASTEXITCODE -ne 0) { throw 'DCO_SELF_TEST_SHALLOW_CLONE_FAILED' }
    Assert-DcoRejects 'ALPHA_DCO_shallow_history_negative' $selfDeclaredBot $missing 'DCO_SHALLOW_HISTORY_UNAVAILABLE' $shallowRoot

    Write-Host 'ALPHA_DCO_bot_exemption_none PASS'
    Write-Host 'ALPHA_DCO_self_tests PASS'
}
finally {
    Remove-TestDirectory $shallowRoot
    Remove-TestDirectory $testRoot
}

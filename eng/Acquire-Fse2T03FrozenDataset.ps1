[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DestinationPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repository = 'https://github.com/ministero-salute/it-fse-accreditamento'
$commit = 'd937255fd7e9c079c5641c537da17fe98a2f2259'
$fullDestination = [System.IO.Path]::GetFullPath($DestinationPath)
$parent = [System.IO.Path]::GetDirectoryName($fullDestination)
if ([string]::IsNullOrWhiteSpace($parent)) { throw 'FSE2_T03_DATASET_DESTINATION_INVALID' }
if (Test-Path -LiteralPath $fullDestination) { throw 'FSE2_T03_DATASET_DESTINATION_ALREADY_EXISTS' }
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    [void](New-Item -ItemType Directory -Path $parent)
}

$created = $false
try {
    $created = $true
    & git clone --no-checkout --depth 1 -- $repository $fullDestination
    if ($LASTEXITCODE -ne 0) { throw 'FSE2_T03_DATASET_CLONE_FAILED' }

    & git -C $fullDestination cat-file -e "$commit`^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) {
        & git -C $fullDestination fetch --depth 1 origin $commit
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_T03_DATASET_COMMIT_FETCH_FAILED' }
    }

    # The public tree contains NTFS-incompatible names. Point detached HEAD at the
    # frozen commit without materializing a working tree; the gate reads Git objects.
    & git -C $fullDestination update-ref --no-deref HEAD $commit
    if ($LASTEXITCODE -ne 0) { throw 'FSE2_T03_DATASET_DETACH_FAILED' }

    $head = (& git -C $fullDestination rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -cne $commit) { throw 'FSE2_T03_DATASET_HEAD_MISMATCH' }
    & git -C $fullDestination symbolic-ref -q HEAD 2>$null
    if ($LASTEXITCODE -eq 0) { throw 'FSE2_T03_DATASET_HEAD_NOT_DETACHED' }
    if ($LASTEXITCODE -ne 1) { throw 'FSE2_T03_DATASET_HEAD_UNREADABLE' }

    $remote = (& git -C $fullDestination config --get remote.origin.url).Trim().TrimEnd('/')
    if ($remote.EndsWith('.git', [StringComparison]::OrdinalIgnoreCase)) { $remote = $remote.Substring(0, $remote.Length - 4) }
    if ($remote -cne $repository) { throw 'FSE2_T03_DATASET_REMOTE_MISMATCH' }

    & git -C $fullDestination config --get extensions.partialClone 2>$null
    if ($LASTEXITCODE -eq 0) { throw 'FSE2_T03_DATASET_PARTIAL_CLONE_FORBIDDEN' }
    if ($LASTEXITCODE -ne 1) { throw 'FSE2_T03_DATASET_CONFIGURATION_UNREADABLE' }
    & git -C $fullDestination config --get-regexp '^remote\..*\.promisor$' 2>$null
    if ($LASTEXITCODE -eq 0) { throw 'FSE2_T03_DATASET_PROMISOR_FORBIDDEN' }
    if ($LASTEXITCODE -ne 1) { throw 'FSE2_T03_DATASET_CONFIGURATION_UNREADABLE' }

    & git -C $fullDestination fsck --full --no-dangling
    if ($LASTEXITCODE -ne 0) { throw 'FSE2_T03_DATASET_OBJECT_INTEGRITY_FAILED' }

    [pscustomobject]@{
        Repository = $repository
        Commit = $commit
        Head = $head
        Detached = $true
        ObjectOnly = $true
        DestinationPath = $fullDestination
    }
}
catch {
    if ($created -and (Test-Path -LiteralPath $fullDestination)) {
        $resolved = (Resolve-Path -LiteralPath $fullDestination -ErrorAction Stop).Path
        $expectedPrefix = $parent.TrimEnd('\') + '\'
        if (-not $resolved.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "FSE2_T03_DATASET_CLEANUP_PATH_REJECTED: $resolved"
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
    throw
}

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$trackedRoots = @('src', 'sdk', 'tests', 'deploy', 'docs', 'eng', '.github')
$patterns = @(
    'BEGIN (RSA |EC )?PRIVATE KEY',
    'Authorization:\s*Bearer\s+[A-Za-z0-9._-]{12,}',
    '(?i)client[_-]?secret\s*[:=]\s*[A-Za-z0-9._-]{8,}',
    '(?i)password\s*[:=]\s*[A-Za-z0-9!@#$%^&*._-]{8,}'
)

$hits = @()
$ripgrep = Get-Command rg -ErrorAction SilentlyContinue
if ($null -ne $ripgrep) {
    foreach ($relative in $trackedRoots) {
        $path = Join-Path $root $relative
        if (-not (Test-Path -LiteralPath $path)) { continue }
        foreach ($pattern in $patterns) {
            $matches = & $ripgrep.Source -l --pcre2 $pattern $path 2>$null
            if ($matches) { $hits += $matches }
        }
    }
}
else {
    $trackedFiles = @(& git -C $root ls-files -- @trackedRoots)
    if ($LASTEXITCODE -ne 0) { throw 'Unable to enumerate tracked files for secret scanning.' }
    foreach ($relativePath in $trackedFiles) {
        $path = Join-Path $root $relativePath
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        foreach ($pattern in $patterns) {
            if (Select-String -LiteralPath $path -Pattern $pattern -Quiet -ErrorAction SilentlyContinue) {
                $hits += $path
                break
            }
        }
    }
}

if ($hits.Count -gt 0) {
    $hits | Sort-Object -Unique | Write-Error
    exit 1
}

Write-Host 'Conservative secret scan succeeded.'
exit 0

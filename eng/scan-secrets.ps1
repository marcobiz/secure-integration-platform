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
foreach ($relative in $trackedRoots) {
    $path = Join-Path $root $relative
    if (-not (Test-Path -LiteralPath $path)) { continue }
    foreach ($pattern in $patterns) {
        if ($ripgrep) {
            $matches = & $ripgrep.Source -l --pcre2 $pattern $path 2>$null
        }
        else {
            # Git is already a repository prerequisite and its PCRE engine keeps
            # this gate functional on clean Windows runners that do not ship rg.
            $matches = & git -C $root grep -Il -P -e $pattern -- $relative 2>$null
            if ($LASTEXITCODE -notin 0, 1) {
                throw "Secret scan failed while inspecting '$relative'."
            }
        }
        if ($matches) { $hits += $matches }
    }
}

if ($hits.Count -gt 0) {
    $hits | Sort-Object -Unique | Write-Error
    exit 1
}

Write-Host 'Conservative secret scan succeeded.'
exit 0

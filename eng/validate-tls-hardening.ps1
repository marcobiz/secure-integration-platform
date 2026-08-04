[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$self = 'eng/validate-tls-hardening.ps1'
$extensions = @('.cs', '.ps1', '.yml', '.yaml', '.dockerfile')
$patterns = [ordered]@{
    'curl disables certificate validation' = '(?im)\bcurl(?:\.exe)?\b[^\r\n]*(?:\s-k(?:\s|$)|\s--insecure(?:\s|=|$))'
    'dangerous .NET certificate validator' = 'DangerousAcceptAnyServerCertificateValidator'
    'permissive server certificate callback' = '(?is)ServerCertificateCustomValidationCallback\s*=\s*[^;]*(?:=>\s*true|return\s+true)'
    'permissive handler callback' = '(?is)ServerCertificateValidationCallback\s*=\s*[^;]*(?:=>\s*true|return\s+true)'
}

$violations = @()
$tracked = @(& git -C $root ls-files)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate tracked files for TLS validation.' }
foreach ($relative in $tracked) {
    $normalized = $relative.Replace('\', '/')
    if ($normalized -eq $self) { continue }
    $extension = [IO.Path]::GetExtension($normalized).ToLowerInvariant()
    if ($extensions -notcontains $extension -and [IO.Path]::GetFileName($normalized) -ne 'Dockerfile') { continue }
    $path = Join-Path $root $relative
    $content = [IO.File]::ReadAllText($path)
    foreach ($entry in $patterns.GetEnumerator()) {
        if ([regex]::IsMatch($content, $entry.Value)) {
            $violations += "${normalized}: $($entry.Key)"
        }
    }
}
if ($violations.Count -ne 0) { throw ('TLS hardening validation failed: ' + ($violations -join '; ')) }
Write-Output 'TLS_HARDENING_VALIDATION_PASS'

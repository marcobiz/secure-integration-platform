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
$allowedApplicationValidatedClientCertificateBoundaries = @(
    'src/Gateway/Gateway.Api/Program.cs',
    'tools/m3/VendorMock/Program.cs'
)

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
    if ($content -match '\bAllowAnyClientCertificate\s*\(' -and $allowedApplicationValidatedClientCertificateBoundaries -notcontains $normalized) {
        $violations += "${normalized}: client certificate chain validation bypass outside an approved application-validation boundary"
    }
    foreach ($entry in $patterns.GetEnumerator()) {
        if ([regex]::IsMatch($content, $entry.Value)) {
            $violations += "${normalized}: $($entry.Key)"
        }
    }
}
$gatewayProgram = [IO.File]::ReadAllText((Join-Path $root 'src/Gateway/Gateway.Api/Program.cs'))
$securityDriver = [IO.File]::ReadAllText((Join-Path $root 'tools/m3/SecurityDriver/Program.cs'))
if ($gatewayProgram -notmatch '\bAllowAnyClientCertificate\s*\(' -or $securityDriver -notmatch 'M3-TLS-SELF-SIGNED-APPLICATION-BOUNDARY') {
    $violations += 'Gateway self-signed installation TLS boundary is not paired with its application-rejection regression'
}
if ($securityDriver -notmatch 'OperatingSystem\.IsWindows\(\)[\s\S]*X509KeyStorageFlags\.UserKeySet[\s\S]*X509KeyStorageFlags\.EphemeralKeySet' -or
    $securityDriver -match 'LoadPkcs12FromFile\([^\r\n]+X509KeyStorageFlags\.EphemeralKeySet\s*\)') {
    $violations += 'SecurityDriver must use a Schannel-compatible persisted client key on Windows while retaining ephemeral keys elsewhere'
}
if ($violations.Count -ne 0) { throw ('TLS hardening validation failed: ' + ($violations -join '; ')) }
Write-Output 'TLS_HARDENING_VALIDATION_PASS'

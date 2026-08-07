[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Throw-ValidationError {
    param([Parameter(Mandatory = $true)][string]$Message)

    throw "HEALTHCARE_FIXTURE_VALIDATION_FAILED: $Message"
}

function Get-RelativeFixturePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $rootWithSeparator = $PSScriptRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $Path.StartsWith($rootWithSeparator, [StringComparison]::OrdinalIgnoreCase)) {
        Throw-ValidationError "Fixture path is outside the corpus root."
    }

    return $Path.Substring($rootWithSeparator.Length).Replace('\', '/')
}

function Read-JsonFixture {
    param([Parameter(Mandatory = $true)][IO.FileInfo]$File)

    try {
        return (Get-Content -LiteralPath $File.FullName -Raw -Encoding UTF8 | ConvertFrom-Json)
    }
    catch {
        Throw-ValidationError "Invalid JSON in $(Get-RelativeFixturePath -Path $File.FullName)."
    }
}

function Test-XmlFixture {
    param([Parameter(Mandatory = $true)][IO.FileInfo]$File)

    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = $null
    try {
        $reader = [System.Xml.XmlReader]::Create($File.FullName, $settings)
        $document = New-Object System.Xml.XmlDocument
        $document.XmlResolver = $null
        $document.Load($reader)
        if ($document.DocumentElement.LocalName -ne 'Envelope') {
            Throw-ValidationError "XML root is not an Envelope in $(Get-RelativeFixturePath -Path $File.FullName)."
        }
    }
    catch {
        if ($_.Exception.Message.StartsWith('HEALTHCARE_FIXTURE_VALIDATION_FAILED:', [StringComparison]::Ordinal)) {
            throw
        }
        Throw-ValidationError "Invalid or unsafe XML in $(Get-RelativeFixturePath -Path $File.FullName)."
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
    }
}

function Test-SyntheticContent {
    param([Parameter(Mandatory = $true)][IO.FileInfo]$File)

    $relativePath = Get-RelativeFixturePath -Path $File.FullName
    $content = Get-Content -LiteralPath $File.FullName -Raw -Encoding UTF8

    $forbiddenPatterns = @(
        '(?i)-----BEGIN[ -]',
        '(?i)"(?:private_key|client_secret|password|certificate_der|certificate_pem|pfx|pkcs12)"\s*:',
        '(?i)\b(?:Basic|Bearer)\s+[A-Za-z0-9+/_=-]{8,}',
        '(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])',
        '[A-Za-z0-9+/]{80,}={0,2}'
    )

    foreach ($pattern in $forbiddenPatterns) {
        if ([Text.RegularExpressions.Regex]::IsMatch($content, $pattern)) {
            Throw-ValidationError "Forbidden credential, key, certificate, or compact-token material in $relativePath."
        }
    }

    $httpMatches = [Text.RegularExpressions.Regex]::Matches($content, 'https?://[^\s"''<>]+', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($match in $httpMatches) {
        try {
            $uri = New-Object Uri($match.Value, [UriKind]::Absolute)
        }
        catch {
            Throw-ValidationError "Malformed HTTP URI in $relativePath."
        }
        if ($uri.Host -ne 'example.invalid') {
            Throw-ValidationError "Non-example HTTP host in $relativePath."
        }
    }

    $urnMatches = [Text.RegularExpressions.Regex]::Matches($content, '(?i)\burn:[A-Za-z0-9][A-Za-z0-9:._-]*')
    foreach ($match in $urnMatches) {
        if (-not $match.Value.StartsWith('urn:example', [StringComparison]::OrdinalIgnoreCase)) {
            Throw-ValidationError "Non-example URN namespace in $relativePath."
        }
    }

    $domainMatches = [Text.RegularExpressions.Regex]::Matches($content, '(?i)(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![A-Za-z0-9-])')
    foreach ($match in $domainMatches) {
        if (-not $match.Value.EndsWith('example.invalid', [StringComparison]::OrdinalIgnoreCase)) {
            Throw-ValidationError "Non-example domain in $relativePath."
        }
    }
}

$expectedFiles = @(
    'sogei-basic-session/login-request.xml',
    'sogei-basic-session/login-accepted.xml',
    'sogei-basic-session/session-expired-fault.xml',
    'sogei-basic-session/session-reference.json',
    'lombardia-oauth-helper/helper-session.json',
    'lombardia-oauth-helper/token-response.json',
    'lombardia-oauth-helper/token-expired-error.json',
    'fvg-pkce-jwt/pkce.json',
    'fvg-pkce-jwt/token-response.json',
    'fvg-pkce-jwt/jwt-claims.json',
    'fvg-pkce-jwt/oauth-error.json',
    'umbria-mtls-jwt/certificate-metadata.json',
    'umbria-mtls-jwt/access-token-claims.json',
    'umbria-mtls-jwt/signature-claims.json',
    'umbria-mtls-jwt/jwt-expired-error.json',
    'umbria-mtls-jwt/mtls-error.json'
)

foreach ($relativePath in $expectedFiles) {
    $candidate = Join-Path -Path $PSScriptRoot -ChildPath $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        Throw-ValidationError "Missing expected fixture $relativePath."
    }
}

$fixtureFiles = @(Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -File | Where-Object { $_.Extension -in @('.json', '.xml') })
if ($fixtureFiles.Count -ne $expectedFiles.Count) {
    Throw-ValidationError "Expected $($expectedFiles.Count) JSON/XML fixtures but found $($fixtureFiles.Count)."
}

foreach ($file in $fixtureFiles) {
    Test-SyntheticContent -File $file
    if ($file.Extension -eq '.json') {
        $null = Read-JsonFixture -File $file
    }
    else {
        Test-XmlFixture -File $file
    }
}

$pkceFile = Get-Item -LiteralPath (Join-Path $PSScriptRoot 'fvg-pkce-jwt\pkce.json')
$pkce = Read-JsonFixture -File $pkceFile
$verifier = [string]$pkce.code_verifier
if ($verifier.Length -lt 43 -or $verifier.Length -gt 128 -or $verifier -notmatch '^[A-Za-z0-9._~-]+$') {
    Throw-ValidationError 'PKCE verifier does not satisfy RFC 7636 length/character constraints.'
}
if ([string]$pkce.code_challenge_method -ne 'S256') {
    Throw-ValidationError 'PKCE challenge method must be S256.'
}

$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $digest = $sha256.ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier))
}
finally {
    $sha256.Dispose()
}
$computedChallenge = [Convert]::ToBase64String($digest).TrimEnd('=').Replace('+', '-').Replace('/', '_')
if ($computedChallenge -cne [string]$pkce.code_challenge) {
    Throw-ValidationError 'PKCE S256 challenge does not match the verifier.'
}

$certificateFile = Get-Item -LiteralPath (Join-Path $PSScriptRoot 'umbria-mtls-jwt\certificate-metadata.json')
$certificateMetadata = Read-JsonFixture -File $certificateFile
if (@($certificateMetadata.certificates).Count -ne 2) {
    Throw-ValidationError 'Umbria metadata must contain exactly two purpose-separated certificates.'
}
foreach ($certificate in @($certificateMetadata.certificates)) {
    if ($certificate.material_included -ne $false) {
        Throw-ValidationError 'Certificate metadata must explicitly exclude certificate material.'
    }
    if (-not ([string]$certificate.certificate_reference).StartsWith('urn:example:', [StringComparison]::Ordinal)) {
        Throw-ValidationError 'Certificate references must use urn:example.'
    }
}
$certificatePurposes = @($certificateMetadata.certificates | ForEach-Object { [string]$_.purpose })
if ($certificatePurposes -notcontains 'mtls-client-authentication' -or $certificatePurposes -notcontains 'jwt-signing') {
    Throw-ValidationError 'Umbria metadata must separate mTLS and JWT-signing purposes.'
}

$claimFiles = @(
    'fvg-pkce-jwt\jwt-claims.json',
    'umbria-mtls-jwt\access-token-claims.json',
    'umbria-mtls-jwt\signature-claims.json'
)
foreach ($claimPath in $claimFiles) {
    $claimFile = Get-Item -LiteralPath (Join-Path $PSScriptRoot $claimPath)
    $claims = Read-JsonFixture -File $claimFile
    foreach ($requiredClaim in @('iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp')) {
        if ($null -eq $claims.PSObject.Properties[$requiredClaim]) {
            Throw-ValidationError "Missing decoded JWT claim $requiredClaim in $(Get-RelativeFixturePath -Path $claimFile.FullName)."
        }
    }
    if ([Int64]$claims.exp -le [Int64]$claims.nbf) {
        Throw-ValidationError "JWT exp must be after nbf in $(Get-RelativeFixturePath -Path $claimFile.FullName)."
    }
}

Write-Output "HEALTHCARE_FIXTURES_VALID: $($fixtureFiles.Count) JSON/XML fixtures parsed; PKCE and synthetic-content checks passed."

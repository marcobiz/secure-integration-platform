[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][string] $AuthCertificatePath,
    [Parameter(Mandatory = $true)][string] $AuthPrivateKeyPath,
    [Parameter(Mandatory = $true)][string] $SignCertificatePath,
    [Parameter(Mandatory = $true)][string] $SignPrivateKeyPath,
    [Parameter(Mandatory = $true)][string] $TrustAnchorPath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedAuthFingerprintSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedSignFingerprintSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedTrustAnchorFingerprintSha256,
    [Parameter(Mandatory = $true)][string] $OutputDirectory,
    [string] $OpenSsl = 'openssl',
    [switch] $Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$clientAuthOid = '1.3.6.1.5.5.7.3.2'
if ($OpenSsl -eq 'openssl' -and -not (Get-Command -Name $OpenSsl -ErrorAction SilentlyContinue)) {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'FSE2_LOCAL_IMPORT_OPENSSL_NOT_FOUND' }
    $gitOpenSsl = @(
        (Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe'),
        (Join-Path $env:ProgramFiles 'Git\mingw64\bin\openssl.exe')) |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if ($null -eq $gitOpenSsl) { throw 'FSE2_LOCAL_IMPORT_OPENSSL_NOT_FOUND' }
    $OpenSsl = $gitOpenSsl
}

function Resolve-SourceFile {
    param([Parameter(Mandatory = $true)][string] $Path)
    $fullyQualified = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $Path -match '^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+)'
    } else { $Path.StartsWith('/', [StringComparison]::Ordinal) }
    if ([string]::IsNullOrWhiteSpace($Path) -or -not $fullyQualified) {
        throw 'FSE2_LOCAL_IMPORT_SOURCE_PATH_INVALID'
    }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $fullPath -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -lt 1 -or $item.Length -gt 1048576) {
        throw 'FSE2_LOCAL_IMPORT_SOURCE_INVALID'
    }
    return $fullPath
}

function Invoke-OpenSsl {
    param([Parameter(Mandatory = $true)][string[]] $Arguments)
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $Arguments = @($Arguments | ForEach-Object {
            if ($_ -match '^(?:file:)?[A-Za-z]:\\') { $_.Replace('\', '/') } else { $_ }
        })
    }
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $OpenSsl @Arguments *> $null
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousErrorAction }
    if ($exitCode -ne 0) { throw ('FSE2_LOCAL_IMPORT_OPENSSL_FAILED:' + $Arguments[0]) }
}

function Get-Fingerprint {
    param([Parameter(Mandatory = $true)][Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Certificate.RawData))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Test-FixedHex {
    param([Parameter(Mandatory = $true)][string] $Left, [Parameter(Mandatory = $true)][string] $Right)
    return $Left.Equals($Right, [StringComparison]::OrdinalIgnoreCase)
}

function New-RandomPassword {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
        return [Convert]::ToBase64String($bytes)
    }
    finally {
        $rng.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Set-RestrictedDirectoryAcl {
    param([Parameter(Mandatory = $true)][string] $Path)
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $principal = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls $Path /inheritance:r *> $null
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_IMPORT_ACL_FAILED' }
        & icacls $Path /grant:r "${principal}:(OI)(CI)(F)" 'BUILTIN\Administrators:(OI)(CI)(F)' 'NT AUTHORITY\SYSTEM:(OI)(CI)(F)' *> $null
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_IMPORT_ACL_FAILED' }
    }
    else {
        & chmod 0700 $Path
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_IMPORT_ACL_FAILED' }
    }
}

function Set-RestrictedFileAcl {
    param([Parameter(Mandatory = $true)][string] $Path)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        & chmod 0600 $Path
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_IMPORT_ACL_FAILED' }
    }
}

$authCertificate = Resolve-SourceFile $AuthCertificatePath
$authKey = Resolve-SourceFile $AuthPrivateKeyPath
$signCertificate = Resolve-SourceFile $SignCertificatePath
$signKey = Resolve-SourceFile $SignPrivateKeyPath
$trustAnchor = Resolve-SourceFile $TrustAnchorPath
$outputFullyQualified = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    $OutputDirectory -match '^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+)'
} else { $OutputDirectory.StartsWith('/', [StringComparison]::Ordinal) }
if ([string]::IsNullOrWhiteSpace($OutputDirectory) -or -not $outputFullyQualified) {
    throw 'FSE2_LOCAL_IMPORT_OUTPUT_INVALID'
}
$output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\', '/')
$repositoryPrefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if ($output.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    $output -eq $root -or (Test-Path -LiteralPath $output)) {
    throw 'FSE2_LOCAL_IMPORT_OUTPUT_INVALID'
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('fse2-local-import-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
try {
    $authDer = Join-Path $temporaryRoot 'auth.der'
    $signDer = Join-Path $temporaryRoot 'sign.der'
    $rootDer = Join-Path $temporaryRoot 'root.der'
    $authCertPublicPem = Join-Path $temporaryRoot 'auth-cert-public.pem'
    $authKeyPublicPem = Join-Path $temporaryRoot 'auth-key-public.pem'
    $signCertPublicPem = Join-Path $temporaryRoot 'sign-cert-public.pem'
    $signKeyPublicPem = Join-Path $temporaryRoot 'sign-key-public.pem'
    $authCertSpki = Join-Path $temporaryRoot 'auth-cert-spki.der'
    $authKeySpki = Join-Path $temporaryRoot 'auth-key-spki.der'
    $signCertSpki = Join-Path $temporaryRoot 'sign-cert-spki.der'
    $signKeySpki = Join-Path $temporaryRoot 'sign-key-spki.der'

    Invoke-OpenSsl @('x509', '-in', $authCertificate, '-outform', 'DER', '-out', $authDer)
    Invoke-OpenSsl @('x509', '-in', $signCertificate, '-outform', 'DER', '-out', $signDer)
    Invoke-OpenSsl @('x509', '-in', $trustAnchor, '-outform', 'DER', '-out', $rootDer)
    Invoke-OpenSsl @('x509', '-in', $authCertificate, '-pubkey', '-noout', '-out', $authCertPublicPem)
    Invoke-OpenSsl @('pkey', '-in', $authKey, '-passin', 'pass:', '-pubout', '-out', $authKeyPublicPem)
    Invoke-OpenSsl @('x509', '-in', $signCertificate, '-pubkey', '-noout', '-out', $signCertPublicPem)
    Invoke-OpenSsl @('pkey', '-in', $signKey, '-passin', 'pass:', '-pubout', '-out', $signKeyPublicPem)
    Invoke-OpenSsl @('pkey', '-pubin', '-in', $authCertPublicPem, '-outform', 'DER', '-out', $authCertSpki)
    Invoke-OpenSsl @('pkey', '-pubin', '-in', $authKeyPublicPem, '-outform', 'DER', '-out', $authKeySpki)
    Invoke-OpenSsl @('pkey', '-pubin', '-in', $signCertPublicPem, '-outform', 'DER', '-out', $signCertSpki)
    Invoke-OpenSsl @('pkey', '-pubin', '-in', $signKeyPublicPem, '-outform', 'DER', '-out', $signKeySpki)
    try { Invoke-OpenSsl @('verify', '-purpose', 'any', '-trusted', $trustAnchor, $authCertificate) }
    catch { throw 'FSE2_LOCAL_IMPORT_AUTH_CHAIN_INVALID' }
    try { Invoke-OpenSsl @('verify', '-purpose', 'any', '-trusted', $trustAnchor, $signCertificate) }
    catch { throw 'FSE2_LOCAL_IMPORT_SIGN_CHAIN_INVALID' }

    $authCertSpkiHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $authCertSpki).Hash
    $authKeySpkiHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $authKeySpki).Hash
    $signCertSpkiHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $signCertSpki).Hash
    $signKeySpkiHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $signKeySpki).Hash
    if (-not (Test-FixedHex $authCertSpkiHash $authKeySpkiHash) -or
        -not (Test-FixedHex $signCertSpkiHash $signKeySpkiHash) -or
        (Test-FixedHex $authCertSpkiHash $signCertSpkiHash)) {
        throw 'FSE2_LOCAL_IMPORT_KEY_CORRELATION_FAILED'
    }

    $auth = [Security.Cryptography.X509Certificates.X509Certificate2]::new([IO.File]::ReadAllBytes($authDer))
    $sign = [Security.Cryptography.X509Certificates.X509Certificate2]::new([IO.File]::ReadAllBytes($signDer))
    $rootCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new([IO.File]::ReadAllBytes($rootDer))
    try {
        $authFingerprint = Get-Fingerprint $auth
        $signFingerprint = Get-Fingerprint $sign
        $rootFingerprint = Get-Fingerprint $rootCertificate
        if (-not (Test-FixedHex $authFingerprint $ExpectedAuthFingerprintSha256) -or
            -not (Test-FixedHex $signFingerprint $ExpectedSignFingerprintSha256) -or
            -not (Test-FixedHex $rootFingerprint $ExpectedTrustAnchorFingerprintSha256)) {
            throw 'FSE2_LOCAL_IMPORT_FINGERPRINT_MISMATCH'
        }
        $now = [DateTime]::UtcNow
        if ($auth.NotBefore.ToUniversalTime() -gt $now -or $auth.NotAfter.ToUniversalTime() -le $now -or
            $sign.NotBefore.ToUniversalTime() -gt $now -or $sign.NotAfter.ToUniversalTime() -le $now) {
            throw 'FSE2_LOCAL_IMPORT_CERTIFICATE_TIME_INVALID'
        }
        $authKeyUsage = @($auth.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension] })
        $authEku = @($auth.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] })
        $signKeyUsage = @($sign.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension] })
        if ($authKeyUsage.Count -ne 1 -or
            ($authKeyUsage[0].KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) -eq 0 -or
            $authEku.Count -ne 1 -or
            -not @($authEku[0].EnhancedKeyUsages | ForEach-Object { $_.Value }).Contains($clientAuthOid) -or
            $signKeyUsage.Count -ne 1 -or
            ($signKeyUsage[0].KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::NonRepudiation) -eq 0) {
            throw 'FSE2_LOCAL_IMPORT_CERTIFICATE_ROLE_INVALID'
        }

        if (-not $Execute) {
            [pscustomobject]@{
                status = 'PASS_READ_ONLY_PREFLIGHT'
                authFingerprintSha256 = $authFingerprint
                signFingerprintSha256 = $signFingerprint
                trustAnchorFingerprintSha256 = $rootFingerprint
                identitiesDistinct = $true
                outputCreated = $false
            } | ConvertTo-Json -Depth 3
            return
        }

        if (-not $PSCmdlet.ShouldProcess($output, 'Create restricted FSE2 local PKCS#12 runtime material')) {
            throw 'FSE2_LOCAL_IMPORT_NOT_CONFIRMED'
        }
        New-Item -ItemType Directory -Path $output | Out-Null
        Set-RestrictedDirectoryAcl $output
        $material = Join-Path $output 'material'
        New-Item -ItemType Directory -Path $material | Out-Null
        Set-RestrictedDirectoryAcl $material

        $authPassword = New-RandomPassword
        $signPassword = New-RandomPassword
        try {
            [IO.File]::WriteAllText((Join-Path $material 'auth.password'), $authPassword, [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText((Join-Path $material 'sign.password'), $signPassword, [Text.UTF8Encoding]::new($false))
            Invoke-OpenSsl @('pkcs12', '-export', '-inkey', $authKey, '-passin', 'pass:', '-in', $authCertificate, '-certfile', $trustAnchor,
                '-name', 'fse2-auth', '-out', (Join-Path $material 'auth.p12'), '-passout', ('file:' + (Join-Path $material 'auth.password')))
            Invoke-OpenSsl @('pkcs12', '-export', '-inkey', $signKey, '-passin', 'pass:', '-in', $signCertificate, '-certfile', $trustAnchor,
                '-name', 'fse2-sign', '-out', (Join-Path $material 'sign.p12'), '-passout', ('file:' + (Join-Path $material 'sign.password')))
        }
        finally {
            $authPassword = $null
            $signPassword = $null
        }

        Invoke-OpenSsl @('pkcs12', '-in', (Join-Path $material 'auth.p12'), '-passin', ('file:' + (Join-Path $material 'auth.password')), '-noout')
        Invoke-OpenSsl @('pkcs12', '-in', (Join-Path $material 'sign.p12'), '-passin', ('file:' + (Join-Path $material 'sign.password')), '-noout')
        Invoke-OpenSsl @('x509', '-in', $authCertificate, '-out', (Join-Path $material 'auth-leaf.pem'))
        Invoke-OpenSsl @('x509', '-in', $signCertificate, '-out', (Join-Path $material 'sign-leaf.pem'))
        Invoke-OpenSsl @('x509', '-in', $trustAnchor, '-out', (Join-Path $material 'root.pem'))

        $runtimeManifest = [ordered]@{
            schemaVersion = 1
            resources = @(
                [ordered]@{
                    id = 'fse2-auth'; kind = 'ClientCertificate'; pkcs12FileName = 'auth.p12'; passwordFileName = 'auth.password'
                    leafFileName = 'auth-leaf.pem'; certificateSha256 = $authFingerprint; subjectPublicKeyInfoSha256 = $authCertSpkiHash
                    version = $auth.SerialNumber; chain = @([ordered]@{ fileName = 'root.pem'; certificateSha256 = $rootFingerprint })
                },
                [ordered]@{
                    id = 'fse2-sign'; kind = 'SigningCertificate'; pkcs12FileName = 'sign.p12'; passwordFileName = 'sign.password'
                    leafFileName = 'sign-leaf.pem'; certificateSha256 = $signFingerprint; subjectPublicKeyInfoSha256 = $signCertSpkiHash
                    version = $sign.SerialNumber; chain = @([ordered]@{ fileName = 'root.pem'; certificateSha256 = $rootFingerprint })
                }
            )
        }
        $manifestPath = Join-Path $output 'manifest.json'
        $manifestJson = $runtimeManifest | ConvertTo-Json -Depth 6
        [IO.File]::WriteAllText($manifestPath, $manifestJson, [Text.UTF8Encoding]::new($false))
        $manifestHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash
        [IO.File]::WriteAllText((Join-Path $output 'manifest.json.sha256'), "$manifestHash  manifest.json`n", [Text.Encoding]::ASCII)
        foreach ($file in Get-ChildItem -LiteralPath $output -File -Recurse) { Set-RestrictedFileAcl $file.FullName }

        [pscustomobject]@{
            status = 'PASS_CREATED'
            outputDirectory = $output
            manifestSha256 = $manifestHash
            authFingerprintSha256 = $authFingerprint
            signFingerprintSha256 = $signFingerprint
            trustAnchorFingerprintSha256 = $rootFingerprint
            privateKeysExportedByProvider = $false
            liveFse2Calls = 0
        } | ConvertTo-Json -Depth 3
    }
    finally {
        $auth.Dispose()
        $sign.Dispose()
        $rootCertificate.Dispose()
    }
}
catch {
    if (Test-Path -LiteralPath $output) {
        $resolvedOutput = [IO.Path]::GetFullPath($output).TrimEnd('\', '/')
        if ($resolvedOutput -ne $root -and -not $resolvedOutput.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedOutput -Recurse -Force
        }
    }
    throw
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolvedTemporary = [IO.Path]::GetFullPath($temporaryRoot).TrimEnd('\', '/')
        $expectedTemporaryPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar + 'fse2-local-import-'
        if (-not $resolvedTemporary.StartsWith($expectedTemporaryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'FSE2_LOCAL_IMPORT_TEMP_CLEANUP_TARGET_INVALID'
        }
        Remove-Item -LiteralPath $resolvedTemporary -Recurse -Force
    }
}

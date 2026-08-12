[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][string] $AuthCertificatePath,
    [Parameter(Mandatory = $true)][string] $AuthPrivateKeyPath,
    [Parameter(Mandatory = $true)][string] $AuthCsrPath,
    [Parameter(Mandatory = $true)][string] $SignCertificatePath,
    [Parameter(Mandatory = $true)][string] $SignPrivateKeyPath,
    [Parameter(Mandatory = $true)][string] $SignCsrPath,
    [Parameter(Mandatory = $true)][string] $TrustAnchorPath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedAuthFingerprintSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedSignFingerprintSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedTrustAnchorFingerprintSha256,
    [Parameter(Mandatory = $true)][string] $OutputDirectory,
    [Parameter(Mandatory = $true)][string] $RuntimePrincipal,
    [string] $OpenSsl = 'openssl',
    [switch] $Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $PSScriptRoot 'Fse2PathPolicy.psm1') -Force
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

function Invoke-OpenSsl {
    param([Parameter(Mandatory = $true)][string[]] $Arguments, [switch] $RequireCsrSignatureValid)
    foreach ($snapshot in $script:sourceSnapshots) { Assert-Fse2PathSnapshot -Snapshot $snapshot | Out-Null }
    if ($null -ne $script:temporarySnapshot) { Assert-Fse2PathSnapshot -Snapshot $script:temporarySnapshot | Out-Null }
    if ($null -ne $script:outputSnapshot) { Assert-Fse2PathSnapshot -Snapshot $script:outputSnapshot | Out-Null }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $Arguments = @($Arguments | ForEach-Object {
            if ($_ -match '^(?:file:)?[A-Za-z]:\\') { $_.Replace('\', '/') } else { $_ }
        })
    }
    $previousErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        if ($RequireCsrSignatureValid) {
            $commandOutput = (& $OpenSsl @Arguments 2>&1 | Out-String)
        } else {
            & $OpenSsl @Arguments *> $null
        }
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousErrorAction }
    if ($exitCode -ne 0 -or ($RequireCsrSignatureValid -and $commandOutput -notmatch '(?im)verify\s+OK\s*$')) {
        throw ('FSE2_LOCAL_IMPORT_OPENSSL_FAILED:' + $Arguments[0])
    }
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

function Resolve-RuntimePrincipal {
    param([Parameter(Mandatory = $true)][string] $Principal)
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        try {
            $sid = if ($Principal -match '^S-\d-(?:\d+-){1,14}\d+$') {
                [Security.Principal.SecurityIdentifier]::new($Principal)
            } else {
                ([Security.Principal.NTAccount]::new($Principal)).Translate([Security.Principal.SecurityIdentifier])
            }
            $denied = @('S-1-1-0', 'S-1-5-7', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-544')
            if ($denied -contains $sid.Value) { throw 'denied' }
            $account = $sid.Translate([Security.Principal.NTAccount]).Value
            if ([string]::IsNullOrWhiteSpace($account)) { throw 'unresolved' }
            if ($sid.Value -notmatch '^S-1-5-80-(?:\d+-){4}\d+$') {
                $userAccounts = @(Get-CimInstance -ClassName Win32_UserAccount `
                    -Filter ("SID = '{0}'" -f $sid.Value) -ErrorAction Stop)
                if ($userAccounts.Count -ne 1) { throw 'group-or-unsupported-principal' }
            }
            return [pscustomobject]@{ Value = $sid.Value; Account = $account; IsWindows = $true }
        }
        catch { throw 'FSE2_LOCAL_IMPORT_RUNTIME_PRINCIPAL_INVALID' }
    }
    $identityLookupFailed = $false
    if ($Principal -match '^uid:(\d+)$') { $uid = $Matches[1] }
    else {
        $uid = (& id -u -- $Principal 2>$null | Out-String).Trim()
        $identityLookupFailed = $LASTEXITCODE -ne 0
    }
    if ($identityLookupFailed -or $uid -notmatch '^\d+$' -or $uid -eq '0' -or $uid -eq '65534') {
        throw 'FSE2_LOCAL_IMPORT_RUNTIME_PRINCIPAL_INVALID'
    }
    return [pscustomobject]@{ Value = $uid; Account = $uid; IsWindows = $false }
}

function Set-BuildDirectoryAcl {
    param([Parameter(Mandatory = $true)][string] $Path)
    Assert-Fse2PathSnapshot -Snapshot $script:outputSnapshot | Out-Null
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        & icacls $Path /inheritance:r *> $null
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_IMPORT_ACL_FAILED' }
        $operator = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls $Path /grant:r "${operator}:(OI)(CI)(F)" 'BUILTIN\Administrators:(OI)(CI)(F)' 'NT AUTHORITY\SYSTEM:(OI)(CI)(F)' *> $null
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_IMPORT_ACL_FAILED' }
    } else {
        & chmod 0700 $Path
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_IMPORT_ACL_FAILED' }
    }
}

function Set-FinalRuntimeAcl {
    param([Parameter(Mandatory = $true)][string] $Path)
    Assert-Fse2PathSnapshot -Snapshot $script:outputSnapshot | Out-Null
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
        $runtimeSid = [Security.Principal.SecurityIdentifier]::new($script:runtimeIdentity.Value)
        $operatorSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $items = @((Get-Item -LiteralPath $Path -Force)) + @(Get-ChildItem -LiteralPath $Path -Recurse -Force)
        foreach ($item in $items) {
            Assert-Fse2PathSnapshot -Snapshot $script:outputSnapshot | Out-Null
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'FSE2_LOCAL_IMPORT_ACL_REPARSE_DENIED' }
            $isDirectory = $item.PSIsContainer
            $systemGrant = if ($isDirectory) { '*S-1-5-18:(OI)(CI)(F)' } else { '*S-1-5-18:(F)' }
            $adminGrant = if ($isDirectory) { '*S-1-5-32-544:(OI)(CI)(F)' } else { '*S-1-5-32-544:(F)' }
            $runtimeGrant = if ($isDirectory) { ('*' + $runtimeSid.Value + ':(OI)(CI)(RX)') } else { ('*' + $runtimeSid.Value + ':(R)') }
            & icacls $item.FullName /inheritance:r /grant:r $systemGrant $adminGrant $runtimeGrant *> $null
            if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_IMPORT_ACL_FAILED' }
            if ($operatorSid.Value -ne $runtimeSid.Value -and $operatorSid.Value -ne $adminSid.Value -and $operatorSid.Value -ne $systemSid.Value) {
                & icacls $item.FullName /remove:g ('*' + $operatorSid.Value) *> $null
                if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_IMPORT_ACL_FAILED' }
            }
        }
    } else {
        $currentUid = (& id -u | Out-String).Trim()
        if ($currentUid -ne $script:runtimeIdentity.Value) {
            & chown -R -- ($script:runtimeIdentity.Account + ':' + $script:runtimeIdentity.Account) $Path
            if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_IMPORT_ACL_FAILED' }
        }
        foreach ($directory in @((Get-Item -LiteralPath $Path)) + @(Get-ChildItem -LiteralPath $Path -Directory -Recurse -Force)) {
            & chmod 0550 $directory.FullName
            if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_IMPORT_ACL_FAILED' }
        }
        foreach ($file in Get-ChildItem -LiteralPath $Path -File -Recurse -Force) {
            & chmod 0440 $file.FullName
            if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_IMPORT_ACL_FAILED' }
        }
    }
    Assert-Fse2PathSnapshot -Snapshot $script:outputSnapshot | Out-Null
    Assert-Fse2ExactRuntimeAcl -Path $Path -RuntimeIdentity $script:runtimeIdentity
}

$authCertificateSnapshot = Get-Fse2PathSnapshot -Path $AuthCertificatePath -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_LOCAL_IMPORT_AUTH_CERT_PATH' -MaximumBytes 1048576
$authKeySnapshot = Get-Fse2PathSnapshot -Path $AuthPrivateKeyPath -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_LOCAL_IMPORT_AUTH_KEY_PATH' -MaximumBytes 1048576
$authCsrSnapshot = Get-Fse2PathSnapshot -Path $AuthCsrPath -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_LOCAL_IMPORT_AUTH_CSR_PATH' -MaximumBytes 1048576
$signCertificateSnapshot = Get-Fse2PathSnapshot -Path $SignCertificatePath -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_LOCAL_IMPORT_SIGN_CERT_PATH' -MaximumBytes 1048576
$signKeySnapshot = Get-Fse2PathSnapshot -Path $SignPrivateKeyPath -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_LOCAL_IMPORT_SIGN_KEY_PATH' -MaximumBytes 1048576
$signCsrSnapshot = Get-Fse2PathSnapshot -Path $SignCsrPath -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_LOCAL_IMPORT_SIGN_CSR_PATH' -MaximumBytes 1048576
$trustAnchorSnapshot = Get-Fse2PathSnapshot -Path $TrustAnchorPath -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_LOCAL_IMPORT_ROOT_PATH' -MaximumBytes 1048576
$sourceSnapshots = @($authCertificateSnapshot, $authKeySnapshot, $authCsrSnapshot, $signCertificateSnapshot, $signKeySnapshot, $signCsrSnapshot, $trustAnchorSnapshot)
$authCertificate = $authCertificateSnapshot.FullPath
$authKey = $authKeySnapshot.FullPath
$authCsr = $authCsrSnapshot.FullPath
$signCertificate = $signCertificateSnapshot.FullPath
$signKey = $signKeySnapshot.FullPath
$signCsr = $signCsrSnapshot.FullPath
$trustAnchor = $trustAnchorSnapshot.FullPath
$runtimeIdentity = Resolve-RuntimePrincipal $RuntimePrincipal
$outputPlan = Get-Fse2PathSnapshot -Path $OutputDirectory -Kind OutputDirectory -RepositoryRoot $root -ErrorCodePrefix 'FSE2_LOCAL_IMPORT_OUTPUT'
$output = $outputPlan.FullPath
$runId = [Guid]::NewGuid().ToString('N')
$outputSnapshot = $null
$outputMarker = $null
$temporaryPlan = Get-Fse2PathSnapshot -Path (Join-Path ([IO.Path]::GetTempPath()) ('fse2-local-import-' + $runId)) `
    -Kind OutputDirectory -RepositoryRoot $root -ErrorCodePrefix 'FSE2_LOCAL_IMPORT_TEMP'
$temporaryRoot = $temporaryPlan.FullPath
Assert-Fse2PathSnapshot -Snapshot $temporaryPlan | Out-Null
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
$temporarySnapshot = Get-Fse2PathSnapshot -Path $temporaryRoot -Kind Directory -RepositoryRoot $root -ErrorCodePrefix 'FSE2_LOCAL_IMPORT_TEMP'
$temporaryMarker = New-Fse2OwnershipMarker -DirectorySnapshot $temporarySnapshot -RunId $runId
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
    $authCsrPublicPem = Join-Path $temporaryRoot 'auth-csr-public.pem'
    $authCsrSpki = Join-Path $temporaryRoot 'auth-csr-spki.der'
    $signCertSpki = Join-Path $temporaryRoot 'sign-cert-spki.der'
    $signKeySpki = Join-Path $temporaryRoot 'sign-key-spki.der'
    $signCsrPublicPem = Join-Path $temporaryRoot 'sign-csr-public.pem'
    $signCsrSpki = Join-Path $temporaryRoot 'sign-csr-spki.der'

    Invoke-OpenSsl @('x509', '-in', $authCertificate, '-outform', 'DER', '-out', $authDer)
    Invoke-OpenSsl @('x509', '-in', $signCertificate, '-outform', 'DER', '-out', $signDer)
    Invoke-OpenSsl @('x509', '-in', $trustAnchor, '-outform', 'DER', '-out', $rootDer)
    Invoke-OpenSsl @('x509', '-in', $authCertificate, '-pubkey', '-noout', '-out', $authCertPublicPem)
    Invoke-OpenSsl @('pkey', '-in', $authKey, '-passin', 'pass:', '-pubout', '-out', $authKeyPublicPem)
    try { Invoke-OpenSsl -Arguments @('req', '-in', $authCsr, '-verify', '-noout') -RequireCsrSignatureValid }
    catch { throw 'FSE2_LOCAL_IMPORT_AUTH_CSR_SIGNATURE_INVALID' }
    Invoke-OpenSsl @('req', '-in', $authCsr, '-pubkey', '-noout', '-out', $authCsrPublicPem)
    Invoke-OpenSsl @('x509', '-in', $signCertificate, '-pubkey', '-noout', '-out', $signCertPublicPem)
    Invoke-OpenSsl @('pkey', '-in', $signKey, '-passin', 'pass:', '-pubout', '-out', $signKeyPublicPem)
    try { Invoke-OpenSsl -Arguments @('req', '-in', $signCsr, '-verify', '-noout') -RequireCsrSignatureValid }
    catch { throw 'FSE2_LOCAL_IMPORT_SIGN_CSR_SIGNATURE_INVALID' }
    Invoke-OpenSsl @('req', '-in', $signCsr, '-pubkey', '-noout', '-out', $signCsrPublicPem)
    Invoke-OpenSsl @('pkey', '-pubin', '-in', $authCertPublicPem, '-outform', 'DER', '-out', $authCertSpki)
    Invoke-OpenSsl @('pkey', '-pubin', '-in', $authKeyPublicPem, '-outform', 'DER', '-out', $authKeySpki)
    Invoke-OpenSsl @('pkey', '-pubin', '-in', $authCsrPublicPem, '-outform', 'DER', '-out', $authCsrSpki)
    Invoke-OpenSsl @('pkey', '-pubin', '-in', $signCertPublicPem, '-outform', 'DER', '-out', $signCertSpki)
    Invoke-OpenSsl @('pkey', '-pubin', '-in', $signKeyPublicPem, '-outform', 'DER', '-out', $signKeySpki)
    Invoke-OpenSsl @('pkey', '-pubin', '-in', $signCsrPublicPem, '-outform', 'DER', '-out', $signCsrSpki)
    try { Invoke-OpenSsl @('verify', '-purpose', 'any', '-trusted', $trustAnchor, $authCertificate) }
    catch { throw 'FSE2_LOCAL_IMPORT_AUTH_CHAIN_INVALID' }
    try { Invoke-OpenSsl @('verify', '-purpose', 'any', '-trusted', $trustAnchor, $signCertificate) }
    catch { throw 'FSE2_LOCAL_IMPORT_SIGN_CHAIN_INVALID' }

    $authCertSpkiHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $authCertSpki).Hash
    $authKeySpkiHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $authKeySpki).Hash
    $authCsrSpkiHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $authCsrSpki).Hash
    $signCertSpkiHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $signCertSpki).Hash
    $signKeySpkiHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $signKeySpki).Hash
    $signCsrSpkiHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $signCsrSpki).Hash
    if (-not (Test-FixedHex $authCertSpkiHash $authKeySpkiHash) -or
        -not (Test-FixedHex $authCertSpkiHash $authCsrSpkiHash) -or
        -not (Test-FixedHex $signCertSpkiHash $signKeySpkiHash) -or
        -not (Test-FixedHex $signCertSpkiHash $signCsrSpkiHash) -or
        (Test-FixedHex $authCertSpkiHash $signCertSpkiHash)) {
        throw 'FSE2_LOCAL_IMPORT_KEY_CSR_CERTIFICATE_CORRELATION_FAILED'
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
                provenance = 'KEY_CSR_CERTIFICATE_EXACT_SPKI'
                identitiesDistinct = $true
                outputCreated = $false
            } | ConvertTo-Json -Depth 3
            return
        }

        if (-not $PSCmdlet.ShouldProcess($output, 'Create restricted FSE2 local PKCS#12 runtime material')) {
            throw 'FSE2_LOCAL_IMPORT_NOT_CONFIRMED'
        }
        foreach ($snapshot in $sourceSnapshots) { Assert-Fse2PathSnapshot -Snapshot $snapshot | Out-Null }
        Assert-Fse2PathSnapshot -Snapshot $outputPlan | Out-Null
        New-Item -ItemType Directory -Path $output | Out-Null
        $outputSnapshot = Get-Fse2PathSnapshot -Path $output -Kind Directory -RepositoryRoot $root -ErrorCodePrefix 'FSE2_LOCAL_IMPORT_OUTPUT'
        $outputMarker = New-Fse2OwnershipMarker -DirectorySnapshot $outputSnapshot -RunId $runId
        Set-BuildDirectoryAcl $output
        $material = Join-Path $output 'material'
        Assert-Fse2PathSnapshot -Snapshot $outputSnapshot | Out-Null
        New-Item -ItemType Directory -Path $material | Out-Null
        Set-BuildDirectoryAcl $material

        $authPassword = New-RandomPassword
        $signPassword = New-RandomPassword
        try {
            Assert-Fse2PathSnapshot -Snapshot $outputSnapshot | Out-Null
            [IO.File]::WriteAllText((Join-Path $material 'auth.password'), $authPassword, [Text.UTF8Encoding]::new($false))
            Assert-Fse2PathSnapshot -Snapshot $outputSnapshot | Out-Null
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
        Assert-Fse2PathSnapshot -Snapshot $outputSnapshot | Out-Null
        $authPkcs12Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $material 'auth.p12')).Hash
        $authPasswordFileHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $material 'auth.password')).Hash
        $signPkcs12Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $material 'sign.p12')).Hash
        $signPasswordFileHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $material 'sign.password')).Hash

        $runtimeManifest = [ordered]@{
            schemaVersion = 1
            resources = @(
                [ordered]@{
                    id = 'fse2-auth'; kind = 'ClientCertificate'; pkcs12FileName = 'auth.p12'; pkcs12Sha256 = $authPkcs12Hash
                    passwordFileName = 'auth.password'; passwordFileSha256 = $authPasswordFileHash
                    leafFileName = 'auth-leaf.pem'; certificateSha256 = $authFingerprint; subjectPublicKeyInfoSha256 = $authCertSpkiHash
                    version = $auth.SerialNumber; chain = @([ordered]@{ fileName = 'root.pem'; certificateSha256 = $rootFingerprint })
                },
                [ordered]@{
                    id = 'fse2-sign'; kind = 'SigningCertificate'; pkcs12FileName = 'sign.p12'; pkcs12Sha256 = $signPkcs12Hash
                    passwordFileName = 'sign.password'; passwordFileSha256 = $signPasswordFileHash
                    leafFileName = 'sign-leaf.pem'; certificateSha256 = $signFingerprint; subjectPublicKeyInfoSha256 = $signCertSpkiHash
                    version = $sign.SerialNumber; chain = @([ordered]@{ fileName = 'root.pem'; certificateSha256 = $rootFingerprint })
                }
            )
        }
        $manifestPath = Join-Path $output 'manifest.json'
        $manifestJson = $runtimeManifest | ConvertTo-Json -Depth 6
        Assert-Fse2PathSnapshot -Snapshot $outputSnapshot | Out-Null
        [IO.File]::WriteAllText($manifestPath, $manifestJson, [Text.UTF8Encoding]::new($false))
        $manifestHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath).Hash
        Assert-Fse2PathSnapshot -Snapshot $outputSnapshot | Out-Null
        [IO.File]::WriteAllText((Join-Path $output 'manifest.json.sha256'), "$manifestHash  manifest.json`n", [Text.Encoding]::ASCII)
        Set-FinalRuntimeAcl $output

        [pscustomobject]@{
            status = 'PASS_CREATED'
            provenance = 'KEY_CSR_CERTIFICATE_EXACT_SPKI'
            runtimePrincipalApplied = $true
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
    if ($null -ne $outputSnapshot -and $null -ne $outputMarker -and (Test-Path -LiteralPath $outputSnapshot.FullPath)) {
        Remove-Fse2OwnedDirectory -DirectorySnapshot $outputSnapshot -MarkerSnapshot $outputMarker -RunId $runId
    }
    throw
}
finally {
    if ($null -ne $temporarySnapshot -and $null -ne $temporaryMarker -and (Test-Path -LiteralPath $temporarySnapshot.FullPath)) {
        Remove-Fse2OwnedDirectory -DirectorySnapshot $temporarySnapshot -MarkerSnapshot $temporaryMarker -RunId $runId
    }
}

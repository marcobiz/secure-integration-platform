[CmdletBinding()]
param(
    [string] $OpenSsl = 'openssl',
    [string] $DotNetPath,
    [switch] $ValidateCompose,
    [switch] $StartLab
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$importer = Join-Path $PSScriptRoot 'New-Fse2LocalPkcs12Material.ps1'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('fse2-local-pkcs12-self-test-' + [Guid]::NewGuid().ToString('N'))
$output = Join-Path $testRoot 'output'
if ($OpenSsl -eq 'openssl' -and -not (Get-Command -Name $OpenSsl -ErrorAction SilentlyContinue)) {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'FSE2_LOCAL_SELF_TEST_OPENSSL_NOT_FOUND' }
    $gitOpenSsl = @(
        (Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe'),
        (Join-Path $env:ProgramFiles 'Git\mingw64\bin\openssl.exe')) |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
    if ($null -eq $gitOpenSsl) { throw 'FSE2_LOCAL_SELF_TEST_OPENSSL_NOT_FOUND' }
    $OpenSsl = $gitOpenSsl
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
        $commandOutput = (& $OpenSsl @Arguments 2>&1 | Out-String).Trim()
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousErrorAction }
    if ($exitCode -ne 0) { throw ('FSE2_LOCAL_SELF_TEST_OPENSSL_FAILED:' + $commandOutput) }
}

function Get-CertificateFingerprint {
    param([Parameter(Mandatory = $true)][string] $Path)
    $der = Join-Path $testRoot ([Guid]::NewGuid().ToString('N') + '.der')
    Invoke-OpenSsl @('x509', '-in', $Path, '-outform', 'DER', '-out', $der)
    try { return (Get-FileHash -Algorithm SHA256 -LiteralPath $der).Hash }
    finally { Remove-Item -LiteralPath $der -Force }
}

function Assert-ThrowsCode {
    param([Parameter(Mandatory = $true)][scriptblock] $Action, [Parameter(Mandatory = $true)][string] $Code)
    try { & $Action; throw 'FSE2_LOCAL_SELF_TEST_EXPECTED_FAILURE_MISSING' }
    catch {
        if ($_.Exception.Message -notlike "*$Code*") { throw }
    }
}

New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $rootKey = Join-Path $testRoot 'root.key'
    $rootCsr = Join-Path $testRoot 'root.csr'
    $rootCertificate = Join-Path $testRoot 'root.pem'
    $rootExtensions = Join-Path $testRoot 'root.ext'
    $authKey = Join-Path $testRoot 'auth.key'
    $authCsr = Join-Path $testRoot 'auth.csr'
    $authCertificate = Join-Path $testRoot 'auth.pem'
    $authExtensions = Join-Path $testRoot 'auth.ext'
    $signKey = Join-Path $testRoot 'sign.key'
    $signCsr = Join-Path $testRoot 'sign.csr'
    $signCertificate = Join-Path $testRoot 'sign.pem'
    $signExtensions = Join-Path $testRoot 'sign.ext'

    Invoke-OpenSsl @('req', '-newkey', 'rsa:2048', '-nodes', '-sha256',
        '-subj', '/CN=FSE2 Local Self Test Root', '-keyout', $rootKey, '-out', $rootCsr)
    [IO.File]::WriteAllText($rootExtensions,
        "basicConstraints=critical,CA:TRUE`nkeyUsage=critical,keyCertSign,cRLSign`nsubjectKeyIdentifier=hash`n",
        [Text.Encoding]::ASCII)
    Invoke-OpenSsl @('x509', '-req', '-in', $rootCsr, '-signkey', $rootKey, '-days', '2', '-sha256',
        '-extfile', $rootExtensions, '-out', $rootCertificate)
    Invoke-OpenSsl @('req', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', '/CN=FSE2 Local Self Test A1',
        '-keyout', $authKey, '-out', $authCsr)
    [IO.File]::WriteAllText($authExtensions,
        "basicConstraints=critical,CA:FALSE`nkeyUsage=critical,digitalSignature,keyEncipherment`nextendedKeyUsage=clientAuth`n",
        [Text.Encoding]::ASCII)
    Invoke-OpenSsl @('x509', '-req', '-in', $authCsr, '-CA', $rootCertificate, '-CAkey', $rootKey,
        '-CAcreateserial', '-days', '2', '-sha256', '-extfile', $authExtensions, '-out', $authCertificate)
    Invoke-OpenSsl @('req', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', '/CN=FSE2 Local Self Test S1',
        '-keyout', $signKey, '-out', $signCsr)
    [IO.File]::WriteAllText($signExtensions,
        "basicConstraints=critical,CA:FALSE`nkeyUsage=critical,nonRepudiation`n",
        [Text.Encoding]::ASCII)
    Invoke-OpenSsl @('x509', '-req', '-in', $signCsr, '-CA', $rootCertificate, '-CAkey', $rootKey,
        '-CAcreateserial', '-days', '2', '-sha256', '-extfile', $signExtensions, '-out', $signCertificate)
    Invoke-OpenSsl @('verify', '-purpose', 'any', '-trusted', $rootCertificate, $rootCertificate)
    Invoke-OpenSsl @('verify', '-purpose', 'any', '-trusted', $rootCertificate, $authCertificate)
    Invoke-OpenSsl @('verify', '-purpose', 'any', '-trusted', $rootCertificate, $signCertificate)

    $authFingerprint = Get-CertificateFingerprint $authCertificate
    $signFingerprint = Get-CertificateFingerprint $signCertificate
    $rootFingerprint = Get-CertificateFingerprint $rootCertificate
    $arguments = @{
        AuthCertificatePath = $authCertificate
        AuthPrivateKeyPath = $authKey
        SignCertificatePath = $signCertificate
        SignPrivateKeyPath = $signKey
        TrustAnchorPath = $rootCertificate
        ExpectedAuthFingerprintSha256 = $authFingerprint
        ExpectedSignFingerprintSha256 = $signFingerprint
        ExpectedTrustAnchorFingerprintSha256 = $rootFingerprint
        OutputDirectory = $output
        OpenSsl = $OpenSsl
    }

    $preflight = (& $importer @arguments | ConvertFrom-Json)
    if ($preflight.status -ne 'PASS_READ_ONLY_PREFLIGHT' -or $preflight.outputCreated -ne $false -or (Test-Path -LiteralPath $output)) {
        throw 'FSE2_LOCAL_SELF_TEST_PREFLIGHT_FAILED'
    }

    $created = (& $importer @arguments -Execute -Confirm:$false | ConvertFrom-Json)
    if ($created.status -ne 'PASS_CREATED' -or $created.liveFse2Calls -ne 0 -or
        -not (Test-Path -LiteralPath (Join-Path $output 'manifest.json') -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $output 'manifest.json.sha256') -PathType Leaf)) {
        throw 'FSE2_LOCAL_SELF_TEST_CREATE_FAILED'
    }
    $manifest = Get-Content -LiteralPath (Join-Path $output 'manifest.json') -Raw | ConvertFrom-Json
    if (@($manifest.resources).Count -ne 2 -or
        @($manifest.resources | Where-Object { $_.id -eq 'fse2-auth' -and $_.kind -eq 'ClientCertificate' }).Count -ne 1 -or
        @($manifest.resources | Where-Object { $_.id -eq 'fse2-sign' -and $_.kind -eq 'SigningCertificate' }).Count -ne 1) {
        throw 'FSE2_LOCAL_SELF_TEST_MANIFEST_FAILED'
    }
    $passwords = @(
        Get-Content -LiteralPath (Join-Path $output 'material\auth.password') -Raw
        Get-Content -LiteralPath (Join-Path $output 'material\sign.password') -Raw)
    if ($passwords[0] -eq $passwords[1] -or $passwords[0].Length -lt 32 -or $passwords[1].Length -lt 32) {
        throw 'FSE2_LOCAL_SELF_TEST_PASSWORD_SEPARATION_FAILED'
    }
    Invoke-OpenSsl @('pkcs12', '-in', (Join-Path $output 'material\auth.p12'),
        '-passin', ('file:' + (Join-Path $output 'material\auth.password')), '-noout')
    Invoke-OpenSsl @('pkcs12', '-in', (Join-Path $output 'material\sign.p12'),
        '-passin', ('file:' + (Join-Path $output 'material\sign.password')), '-noout')

    $badOutput = Join-Path $testRoot 'bad-output'
    $badArguments = $arguments.Clone()
    $badArguments.OutputDirectory = $badOutput
    $badArguments.ExpectedSignFingerprintSha256 = ('0' * 64)
    Assert-ThrowsCode { & $importer @badArguments } 'FSE2_LOCAL_IMPORT_FINGERPRINT_MISMATCH'
    if (Test-Path -LiteralPath $badOutput) { throw 'FSE2_LOCAL_SELF_TEST_NEGATIVE_OUTPUT_CREATED' }

    if ($ValidateCompose) {
        $labArguments = @{
            Phase = 'Validate'
            ProviderManifestPath = Join-Path $output 'manifest.json'
            MaterialDirectory = Join-Path $output 'material'
        }
        if (-not [string]::IsNullOrWhiteSpace($DotNetPath)) { $labArguments.DotNetPath = $DotNetPath }
        & (Join-Path $PSScriptRoot 'Invoke-Fse2LocalProviderLab.ps1') @labArguments
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_SELF_TEST_COMPOSE_FAILED' }
    }

    if ($StartLab) {
        $labArguments = @{
            ProviderManifestPath = Join-Path $output 'manifest.json'
            MaterialDirectory = Join-Path $output 'material'
        }
        if (-not [string]::IsNullOrWhiteSpace($DotNetPath)) { $labArguments.DotNetPath = $DotNetPath }
        try {
            & (Join-Path $PSScriptRoot 'Invoke-Fse2LocalProviderLab.ps1') @labArguments -Phase Start
            if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_SELF_TEST_START_FAILED' }
        }
        finally {
            & (Join-Path $PSScriptRoot 'Invoke-Fse2LocalProviderLab.ps1') @labArguments -Phase Stop
            if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_SELF_TEST_STOP_FAILED' }
        }
    }

    Write-Host 'FSE2_LOCAL_PKCS12_SELF_TEST_PASS; POSITIVE=2; NEGATIVE=1; LIVE_FSE2_CALLS=0'
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        $resolved = [IO.Path]::GetFullPath($testRoot).TrimEnd('\', '/')
        $expectedPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar + 'fse2-local-pkcs12-self-test-'
        if (-not $resolved.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'FSE2_LOCAL_SELF_TEST_CLEANUP_TARGET_INVALID'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}

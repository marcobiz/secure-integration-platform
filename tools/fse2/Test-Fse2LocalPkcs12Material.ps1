[CmdletBinding()]
param(
    [string] $OpenSsl = 'openssl',
    [string] $DotNetPath,
    [string] $RuntimePrincipal,
    [switch] $ValidateCompose,
    [switch] $StartLab
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $PSScriptRoot 'Fse2PathPolicy.psm1') -Force
$importer = Join-Path $PSScriptRoot 'New-Fse2LocalPkcs12Material.ps1'
$providerProbe = Join-Path $PSScriptRoot 'ProviderProbe\ProviderProbe.csproj'
$runId = [Guid]::NewGuid().ToString('N')
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('fse2-local-pkcs12-self-test-' + $runId)
$output = Join-Path $testRoot 'output'
$m5ArtifactRoot = Join-Path $testRoot 'm5-quickstart'
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
$dotnet = if ([string]::IsNullOrWhiteSpace($DotNetPath)) { Join-Path $root '.dotnet\dotnet.exe' } else { [IO.Path]::GetFullPath($DotNetPath) }
if (-not (Test-Path -LiteralPath $dotnet -PathType Leaf)) {
    if (-not [string]::IsNullOrWhiteSpace($DotNetPath)) { throw 'FSE2_LOCAL_SELF_TEST_DOTNET_INVALID' }
    $dotnet = 'dotnet'
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

function Invoke-Checked {
    param([Parameter(Mandatory = $true)][string] $File, [Parameter(Mandatory = $true)][string[]] $Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw ('FSE2_LOCAL_SELF_TEST_COMMAND_FAILED:' + (Split-Path -Leaf $File)) }
}

function Grant-SyntheticTamperControl {
    param([Parameter(Mandatory = $true)][string] $Path)
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $operatorSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        & icacls $Path /grant:r ('*' + $operatorSid + ':(F)') *> $null
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_SELF_TEST_TAMPER_PERMISSION_FAILED' }
    } else {
        & chmod u+rw -- $Path
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_SELF_TEST_TAMPER_PERMISSION_FAILED' }
    }
}

function Assert-ImporterDenied {
    param(
        [Parameter(Mandatory = $true)][hashtable] $BaseArguments,
        [Parameter(Mandatory = $true)][hashtable] $Overrides,
        [Parameter(Mandatory = $true)][string] $OutputName,
        [Parameter(Mandatory = $true)][string] $Code
    )
    $negative = $BaseArguments.Clone()
    $negative.OutputDirectory = Join-Path $testRoot $OutputName
    foreach ($entry in $Overrides.GetEnumerator()) { $negative[$entry.Key] = $entry.Value }
    Write-Host ('FSE2_LOCAL_SELF_TEST_NEGATIVE=' + $OutputName)
    Assert-ThrowsCode { & $importer @negative } $Code
    if (Test-Path -LiteralPath $negative.OutputDirectory) { throw 'FSE2_LOCAL_SELF_TEST_NEGATIVE_OUTPUT_CREATED' }
}

$testRootPlan = Get-Fse2PathSnapshot -Path $testRoot -Kind OutputDirectory -RepositoryRoot $root -ErrorCodePrefix 'FSE2_LOCAL_SELF_TEST_ROOT'
Assert-Fse2PathSnapshot -Snapshot $testRootPlan | Out-Null
New-Item -ItemType Directory -Path $testRoot | Out-Null
$testRootSnapshot = Get-Fse2PathSnapshot -Path $testRoot -Kind Directory -RepositoryRoot $root -ErrorCodePrefix 'FSE2_LOCAL_SELF_TEST_ROOT'
$testRootMarker = New-Fse2OwnershipMarker -DirectorySnapshot $testRootSnapshot -RunId $runId
$previousContainerRuntimeUid = [Environment]::GetEnvironmentVariable('FSE2_CONTAINER_RUNTIME_UID', 'Process')
$containerRuntimeUidSet = $false
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
        AuthCsrPath = $authCsr
        SignCertificatePath = $signCertificate
        SignPrivateKeyPath = $signKey
        SignCsrPath = $signCsr
        TrustAnchorPath = $rootCertificate
        ExpectedAuthFingerprintSha256 = $authFingerprint
        ExpectedSignFingerprintSha256 = $signFingerprint
        ExpectedTrustAnchorFingerprintSha256 = $rootFingerprint
        OutputDirectory = $output
        RuntimePrincipal = if (-not [string]::IsNullOrWhiteSpace($RuntimePrincipal)) { $RuntimePrincipal } elseif ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        } else { (& id -un | Out-String).Trim() }
        OpenSsl = $OpenSsl
    }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        $containerRuntimeUid = if ([string]$arguments.RuntimePrincipal -match '^uid:(\d+)$') {
            $Matches[1]
        } else { (& id -u -- ([string]$arguments.RuntimePrincipal) | Out-String).Trim() }
        if ($LASTEXITCODE -ne 0 -or $containerRuntimeUid -notmatch '^\d+$' -or $containerRuntimeUid -eq '0') {
            throw 'FSE2_LOCAL_SELF_TEST_CONTAINER_RUNTIME_UID_INVALID'
        }
        [Environment]::SetEnvironmentVariable('FSE2_CONTAINER_RUNTIME_UID', $containerRuntimeUid, 'Process')
        $containerRuntimeUidSet = $true
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
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $runtimeSid = [Security.Principal.SecurityIdentifier]::new([string]$arguments.RuntimePrincipal)
        $outputAcl = Get-Acl -LiteralPath $output
        $rules = @($outputAcl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
        if (-not $outputAcl.AreAccessRulesProtected -or $rules.Count -ne 3 -or
            @($rules | Where-Object { $_.IdentityReference.Value -eq $runtimeSid.Value }).Count -ne 1 -or
            @($rules | Where-Object { $_.IdentityReference.Value -eq $runtimeSid.Value -and
                ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl }).Count -ne 0) {
            throw 'FSE2_LOCAL_SELF_TEST_RUNTIME_ACL_INVALID'
        }
        $runtimeIdentityForAclTest = [pscustomobject]@{ Value = $runtimeSid.Value; IsWindows = $true }
    } else {
        $directoryMode = (& stat -Lc '%a' -- $output | Out-String).Trim()
        $fileMode = (& stat -Lc '%a' -- (Join-Path $output 'manifest.json') | Out-String).Trim()
        if ($directoryMode -ne '550' -or $fileMode -ne '440') { throw 'FSE2_LOCAL_SELF_TEST_RUNTIME_ACL_INVALID' }
        $runtimeIdentityForAclTest = [pscustomobject]@{ Value = $containerRuntimeUid; IsWindows = $false }
    }
    Assert-Fse2ExactRuntimeAcl -Path $output -RuntimeIdentity $runtimeIdentityForAclTest

    $inheritedAclOutput = Join-Path $testRoot 'acl-inheritance-negative'
    New-Item -ItemType Directory -Path $inheritedAclOutput | Out-Null
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { & chmod 0755 -- $inheritedAclOutput }
    Assert-ThrowsCode { Assert-Fse2ExactRuntimeAcl -Path $inheritedAclOutput -RuntimeIdentity $runtimeIdentityForAclTest } `
        'FSE2_LOCAL_IMPORT_ACL_VERIFY_FAILED'
    Write-Host 'FSE2_LOCAL_SELF_TEST_NEGATIVE=acl-inheritance-residual'

    $unexpectedAclOutput = Join-Path $testRoot 'acl-unexpected-ace-negative'
    New-Item -ItemType Directory -Path $unexpectedAclOutput | Out-Null
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        & icacls $unexpectedAclOutput /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' `
            '*S-1-5-32-544:(OI)(CI)(F)' ('*' + $runtimeSid.Value + ':(OI)(CI)(RX)') '*S-1-1-0:(R)' *> $null
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_SELF_TEST_ACL_SETUP_FAILED' }
    } else {
        & chmod 0555 -- $unexpectedAclOutput
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_SELF_TEST_ACL_SETUP_FAILED' }
    }
    Assert-ThrowsCode { Assert-Fse2ExactRuntimeAcl -Path $unexpectedAclOutput -RuntimeIdentity $runtimeIdentityForAclTest } `
        'FSE2_LOCAL_IMPORT_ACL_VERIFY_FAILED'
    Write-Host 'FSE2_LOCAL_SELF_TEST_NEGATIVE=acl-unexpected-ace-or-mode'

    $unverifiableAclOutput = Join-Path $testRoot 'acl-application-impossible-negative'
    Assert-ThrowsCode { Assert-Fse2ExactRuntimeAcl -Path $unverifiableAclOutput -RuntimeIdentity $runtimeIdentityForAclTest } `
        'FSE2_LOCAL_IMPORT_ACL_VERIFY_FAILED'
    if (Test-Path -LiteralPath $unverifiableAclOutput) { throw 'FSE2_LOCAL_SELF_TEST_UNVERIFIABLE_ACL_OUTPUT_CREATED' }
    Write-Host 'FSE2_LOCAL_SELF_TEST_NEGATIVE=acl-application-impossible'
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
    Invoke-Checked $dotnet @('run', '--project', $providerProbe, '--configuration', 'Release', '--',
        (Join-Path $output 'manifest.json'), (Join-Path $output 'material'))

    if ($StartLab) {
        $containerProbe = Join-Path $testRoot 'provider-probe-linux'
        Invoke-Checked $dotnet @('publish', $providerProbe, '--configuration', 'Release', '--no-restore',
            '--output', $containerProbe, '/p:UseAppHost=false')
        $containerProbeUid = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { '1654' } else { $containerRuntimeUid }
        Invoke-Checked 'docker' @('run', '--rm', '--network', 'none', '--user', $containerProbeUid, '--read-only',
            '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m', '-e', 'DOTNET_CLI_HOME=/tmp',
            '--mount', ('type=bind,source=' + (Join-Path $output 'manifest.json') + ',target=/fixture/manifest.json,readonly'),
            '--mount', ('type=bind,source=' + (Join-Path $output 'material') + ',target=/fixture/material,readonly'),
            '--mount', ('type=bind,source=' + $containerProbe + ',target=/probe,readonly'),
            'mcr.microsoft.com/dotnet/runtime:10.0.11@sha256:acad02eb5c4fbf57d15296f9c08d56cd4036e915bdae5b4dd48a06523d452617',
            'dotnet', '/probe/SecureIntegration.Tools.Fse2.ProviderProbe.dll', '/fixture/manifest.json', '/fixture/material')
        Write-Host 'FSE2_LOCAL_PROVIDER_LINUX_CONTAINER_PROBE_PASS; NON_ROOT=1; READ_ONLY=1; LIVE_FSE2_CALLS=0'
    }

    $badOutput = Join-Path $testRoot 'bad-output'
    $badArguments = $arguments.Clone()
    $badArguments.OutputDirectory = $badOutput
    $badArguments.ExpectedSignFingerprintSha256 = ('0' * 64)
    Assert-ThrowsCode { & $importer @badArguments } 'FSE2_LOCAL_IMPORT_FINGERPRINT_MISMATCH'
    if (Test-Path -LiteralPath $badOutput) { throw 'FSE2_LOCAL_SELF_TEST_NEGATIVE_OUTPUT_CREATED' }

    Assert-ImporterDenied $arguments @{ AuthPrivateKeyPath = $signKey } 'auth-key-csr-mismatch' 'FSE2_LOCAL_IMPORT_KEY_CSR_CERTIFICATE_CORRELATION_FAILED'
    Assert-ImporterDenied $arguments @{ AuthPrivateKeyPath = $signKey; AuthCsrPath = $signCsr } 'auth-csr-certificate-mismatch' 'FSE2_LOCAL_IMPORT_KEY_CSR_CERTIFICATE_CORRELATION_FAILED'
    Assert-ImporterDenied $arguments @{ SignPrivateKeyPath = $authKey } 'sign-key-csr-mismatch' 'FSE2_LOCAL_IMPORT_KEY_CSR_CERTIFICATE_CORRELATION_FAILED'
    Assert-ImporterDenied $arguments @{ SignPrivateKeyPath = $authKey; SignCsrPath = $authCsr } 'sign-csr-certificate-mismatch' 'FSE2_LOCAL_IMPORT_KEY_CSR_CERTIFICATE_CORRELATION_FAILED'
    Assert-ImporterDenied $arguments @{
        AuthCertificatePath = $signCertificate; AuthPrivateKeyPath = $signKey; AuthCsrPath = $signCsr
        SignCertificatePath = $authCertificate; SignPrivateKeyPath = $authKey; SignCsrPath = $authCsr
    } 'cross-role-swapped' 'FSE2_LOCAL_IMPORT_FINGERPRINT_MISMATCH'
    Assert-ImporterDenied $arguments @{
        SignCertificatePath = $authCertificate; SignPrivateKeyPath = $authKey; SignCsrPath = $authCsr
    } 'same-identity' 'FSE2_LOCAL_IMPORT_KEY_CSR_CERTIFICATE_CORRELATION_FAILED'

    $badCsrDer = Join-Path $testRoot 'invalid-auth-csr.der'
    $badCsr = Join-Path $testRoot 'invalid-auth.csr'
    Invoke-OpenSsl @('req', '-in', $authCsr, '-outform', 'DER', '-out', $badCsrDer)
    $badCsrBytes = [IO.File]::ReadAllBytes($badCsrDer)
    try {
        $badCsrBytes[$badCsrBytes.Length - 1] = $badCsrBytes[$badCsrBytes.Length - 1] -bxor 1
        $encodedBadCsr = [Convert]::ToBase64String($badCsrBytes, [Base64FormattingOptions]::InsertLineBreaks)
        [IO.File]::WriteAllText($badCsr, "-----BEGIN CERTIFICATE REQUEST-----`n$encodedBadCsr`n-----END CERTIFICATE REQUEST-----`n", [Text.Encoding]::ASCII)
    }
    finally { [Array]::Clear($badCsrBytes, 0, $badCsrBytes.Length) }
    Assert-ImporterDenied $arguments @{ AuthCsrPath = $badCsr } 'invalid-csr-signature' 'FSE2_LOCAL_IMPORT_AUTH_CSR_SIGNATURE_INVALID'
    Assert-ImporterDenied $arguments @{ RuntimePrincipal = 'FSE2-NONEXISTENT-PRINCIPAL-' + $runId } 'runtime-principal-missing' 'FSE2_LOCAL_IMPORT_RUNTIME_PRINCIPAL_INVALID'
    Assert-ImporterDenied $arguments @{ RuntimePrincipal = 'not-a-valid-sid' } 'runtime-principal-malformed' 'FSE2_LOCAL_IMPORT_RUNTIME_PRINCIPAL_INVALID'
    $broadPrincipal = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'S-1-1-0' } else { 'root' }
    Assert-ImporterDenied $arguments @{ RuntimePrincipal = $broadPrincipal } 'runtime-principal-broad' 'FSE2_LOCAL_IMPORT_RUNTIME_PRINCIPAL_INVALID'
    $groupPrincipal = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'S-1-5-32-546' } else { 'adm' }
    Assert-ImporterDenied $arguments @{ RuntimePrincipal = $groupPrincipal } 'runtime-principal-group' 'FSE2_LOCAL_IMPORT_RUNTIME_PRINCIPAL_INVALID'

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
            QuickstartArtifactRoot = $m5ArtifactRoot
        }
        if (-not [string]::IsNullOrWhiteSpace($DotNetPath)) { $labArguments.DotNetPath = $DotNetPath }
        $foreignNetwork = 'fse2-stop-foreign-' + $runId
        $foreignCreated = $false
        try {
            & (Join-Path $PSScriptRoot 'Invoke-Fse2LocalProviderLab.ps1') @labArguments -Phase Start
            if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_SELF_TEST_START_FAILED' }
            Invoke-Checked 'docker' @('network', 'create', '--label', 'com.docker.compose.project=secure-integration-m5-quickstart-foreign', $foreignNetwork)
            $foreignCreated = $true
            $container = @(& docker ps -q --filter 'label=com.docker.compose.project=secure-integration-m5-quickstart' `
                --filter 'label=com.docker.compose.service=gateway')
            if ($LASTEXITCODE -ne 0 -or $container.Count -ne 1) { throw 'FSE2_LOCAL_SELF_TEST_GATEWAY_NOT_FOUND' }
            Invoke-Checked $dotnet @('run', '--project', $providerProbe, '--configuration', 'Release', '--',
                (Join-Path $output 'manifest.json'), (Join-Path $output 'material'))

            $tamperedRoot = Join-Path $output 'material\root.pem'
            Grant-SyntheticTamperControl $tamperedRoot
            [IO.File]::WriteAllText($tamperedRoot, [IO.File]::ReadAllText((Join-Path $output 'material\auth-leaf.pem')), [Text.UTF8Encoding]::new($false))
            Invoke-Checked $dotnet @('run', '--project', $providerProbe, '--configuration', 'Release', '--',
                (Join-Path $output 'manifest.json'), (Join-Path $output 'material'), '--expect-not-ready')
            $gatewayCaSnapshot = Get-Fse2PathSnapshot -Path (Join-Path $m5ArtifactRoot 'raw\certificates\ca.crt') `
                -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_LOCAL_SELF_TEST_GATEWAY_CA' -MaximumBytes 1048576
            $curl = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'curl.exe' } else { 'curl' }
            $curlStatusArguments = @('--silent', '--show-error', '--max-time', '15')
            if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { $curlStatusArguments += '--ssl-no-revoke' }
            $nullOutput = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'NUL' } else { '/dev/null' }
            $curlStatusArguments += @('--cacert', $gatewayCaSnapshot.FullPath, '--output', $nullOutput, '--write-out', '%{http_code}')
            Assert-Fse2PathSnapshot -Snapshot $gatewayCaSnapshot | Out-Null
            $liveStatus = (& $curl @curlStatusArguments 'https://localhost:18443/health/live' | Out-String).Trim()
            if ($LASTEXITCODE -ne 0 -or $liveStatus -cne '200') { throw 'FSE2_LOCAL_SELF_TEST_TAMPER_LIVE_FAILED' }
            Assert-Fse2PathSnapshot -Snapshot $gatewayCaSnapshot | Out-Null
            $readyStatus = (& $curl @curlStatusArguments 'https://localhost:18443/health/ready' | Out-String).Trim()
            if ($LASTEXITCODE -ne 0 -or $readyStatus -cne '503') { throw 'FSE2_LOCAL_SELF_TEST_TAMPER_READINESS_INVALID' }
            Write-Host 'FSE2_LOCAL_TAMPER_READINESS_PASS; LIVE=200; READY=503; SIGNATURES=0; CERTIFICATES=0'
            $manifestForStop = Join-Path $output 'manifest.json'
            $pkcs12ForStop = Join-Path $output 'material\auth.p12'
            Grant-SyntheticTamperControl $manifestForStop
            Grant-SyntheticTamperControl $pkcs12ForStop
            Remove-Item -LiteralPath $manifestForStop -Force
            Remove-Item -LiteralPath $pkcs12ForStop -Force
            $quickstartEnv = Join-Path $m5ArtifactRoot 'raw\m3a.env'
            if (Test-Path -LiteralPath $quickstartEnv) { Remove-Item -LiteralPath $quickstartEnv -Force }
            Write-Host 'FSE2_LOCAL_STOP_NEGATIVE_INPUTS=MANIFEST_DELETED,PKCS12_DELETED,ENV_DELETED,PROVIDER_UNHEALTHY'
        }
        finally {
            & (Join-Path $PSScriptRoot 'Invoke-Fse2LocalProviderLab.ps1') -Phase Stop
            if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_SELF_TEST_STOP_FAILED' }
            if ($foreignCreated) {
                & docker network inspect $foreignNetwork *> $null
                if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_SELF_TEST_FOREIGN_RESOURCE_REMOVED' }
            }
            $partialNetwork = 'fse2-partial-network-' + $runId
            $partialVolume = 'fse2-partial-volume-' + $runId
            $partialNetworkCreated = $false
            $partialVolumeCreated = $false
            try {
                Invoke-Checked 'docker' @('network', 'create', '--label',
                    'com.docker.compose.project=secure-integration-m5-quickstart', $partialNetwork)
                $partialNetworkCreated = $true
                Invoke-Checked 'docker' @('volume', 'create', '--label',
                    'com.docker.compose.project=secure-integration-m5-quickstart', $partialVolume)
                $partialVolumeCreated = $true
                & (Join-Path $PSScriptRoot 'Invoke-Fse2LocalProviderLab.ps1') -Phase Stop
                if ($LASTEXITCODE -ne 0) { throw 'FSE2_LOCAL_SELF_TEST_PARTIAL_START_STOP_FAILED' }
                $partialNetworkCreated = $false
                $partialVolumeCreated = $false
                Write-Host 'FSE2_LOCAL_PARTIAL_START_CLEANUP_PASS; CONTAINERS=0; NETWORKS=0; VOLUMES=0; HELPERS=0'
            }
            finally {
                if ($partialNetworkCreated) { & docker network rm $partialNetwork *> $null }
                if ($partialVolumeCreated) { & docker volume rm $partialVolume *> $null }
                if ($foreignCreated) { Invoke-Checked 'docker' @('network', 'rm', $foreignNetwork) }
            }
        }
    }

    Write-Host 'FSE2_LOCAL_PKCS12_SELF_TEST_PASS; POSITIVE=3; NEGATIVE=15; LIVE_FSE2_CALLS=0'
}
finally {
    if ($containerRuntimeUidSet) {
        [Environment]::SetEnvironmentVariable('FSE2_CONTAINER_RUNTIME_UID', $previousContainerRuntimeUid, 'Process')
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Fse2OwnedDirectory -DirectorySnapshot $testRootSnapshot -MarkerSnapshot $testRootMarker -RunId $runId
    }
}

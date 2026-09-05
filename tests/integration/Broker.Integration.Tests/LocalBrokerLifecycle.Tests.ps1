# Tests the shipped ownership and Stop control flow with a simulated SCM. No service is installed.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot '..\..\..\deploy\windows\Invoke-LocalBroker.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'SCRIPT_PARSE_FAILED' }
foreach ($scriptFile in @('Build-LocalBrokerPackage.ps1', 'Test-LocalBrokerPackage.ps1', 'Test-LocalBrokerWindowsDelivery.ps1')) {
    $path = Join-Path $PSScriptRoot ('..\..\..\eng\' + $scriptFile)
    [void][Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) { throw 'DELIVERY_SCRIPT_PARSE_FAILED' }
}
foreach ($functionName in @('Assert-NoReparse', 'Get-OwnedService', 'Get-ApplicationUserSid', 'Write-Settings')) {
    $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName }, $true)
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
$stopBranch = $ast.Find({ param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$Command -eq ''Stop''' }, $false)
if (-not $stopBranch) { throw 'STOP_CONTROL_FLOW_NOT_FOUND' }
$stop = [ScriptBlock]::Create($stopBranch.Extent.Text)
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('broker-lifecycle-test-' + [guid]::NewGuid().ToString('N'))
$root = Join-Path $fixture 'install'; $data = Join-Path $fixture 'data'; $marker = Join-Path $root 'installation.json'
$name = 'SecureIntegrationBroker.Local.fixture'
$binaryPath = '"' + (Join-Path $root 'broker.exe') + '"'
$script:service = $null; $script:stops = 0
function Get-CimInstance { param($ClassName, $Filter) return $script:service }
function Invoke-ServiceAction { param($Action) if ($Action -cne 'Stop') { throw 'UNEXPECTED_SCM_MUTATION' }; $script:stops++; $script:service.State = 'Stopped' }
function Get-Service { param($Name) return [pscustomobject]@{} | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value { param($State, $Timeout) if ($State -ne 'Stopped') { throw 'UNEXPECTED_WAIT' } } -PassThru }
function Assert([bool] $Condition) { if (-not $Condition) { throw 'LIFECYCLE_ASSERTION_FAILED' } }
function ExpectDenied { param([scriptblock] $Action) try { & $Action | Out-Null } catch { Assert ($_.Exception.Message -like 'LOCAL_BROKER_*'); return }; throw 'OWNERSHIP_WAS_NOT_DENIED' }
try {
    New-Item -ItemType Directory -Path $root, $data -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $data 'preserve.bin'), 'synthetic fixture marker')
    ExpectDenied { Get-OwnedService }
    $record = @{ service = $name; root = $root; data = $data; binaryPath = $binaryPath }
    [IO.File]::WriteAllText($marker, ($record | ConvertTo-Json))
    $owned = Get-OwnedService; $Command = 'Stop'; & $stop | Out-Null
    Assert ($script:stops -eq 0)
    $script:service = [pscustomobject]@{ PathName = $binaryPath; StartName = 'NT SERVICE\' + $name; State = 'Running' }
    $owned = Get-OwnedService; & $stop | Out-Null
    $owned = Get-OwnedService; & $stop | Out-Null
    Assert ($script:stops -eq 1)
    Assert (Test-Path -LiteralPath (Join-Path $data 'preserve.bin'))
    $script:service.PathName = 'foreign.exe'
    ExpectDenied { Get-OwnedService }
    Assert ($script:stops -eq 1)
    $script:service = $null
    $record.data = Join-Path $fixture 'foreign'
    [IO.File]::WriteAllText($marker, ($record | ConvertTo-Json))
    ExpectDenied { Get-OwnedService }
    Assert (Test-Path -LiteralPath (Join-Path $data 'preserve.bin'))
    Write-Output 'STOP_ABSENT_NORMAL_REPEAT_OWNERSHIP=PASS (simulated SCM)'
    $ApplicationUserSid = ''
    ExpectDenied { Get-ApplicationUserSid }
    $ApplicationUserSid = 'S-1-5-32-544'
    ExpectDenied { Get-ApplicationUserSid }
    $ApplicationUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Assert ((Get-ApplicationUserSid) -ceq $ApplicationUserSid)
    Write-Output 'EXPLICIT_APPLICATION_ACCOUNT_SID=PASS'

    # Execute the shipped update branch with simulated process/SCM/copy failure.
    # The real settings write must disable initialization before the first copy.
    $settingsPath = Join-Path $root 'appsettings.json'
    Write-Settings @{ Broker = @{ InitializeDataKeys = $true; InstallationId = 'preserve-id'; Applications = @(@{ AllowedUserSids = @($ApplicationUserSid) }) } }
    $updateBranch = $ast.Find({ param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$Command -eq ''Update''' }, $false)
    Assert ($null -ne $updateBranch)
    function Copy-Published {
        param($Source, $Destination)
        $persisted = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
        Assert (-not $persisted.Broker.InitializeDataKeys)
        throw 'LOCAL_BROKER_COPY_FIXTURE_FAILURE'
    }
    $BrokerPublishDirectory = $root; $brokerDirectory = $root
    # Stop was exercised above; skip only the subprocess invocation of that same
    # branch. Every subsequent settings/copy statement is the shipped code.
    $updateAfterStop = ($updateBranch.Clauses[0].Item2.Statements | Select-Object -Skip 1 | ForEach-Object { $_.Extent.Text }) -join "`n"
    ExpectDenied { & ([ScriptBlock]::Create($updateAfterStop)) }
    $persisted = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    Assert (-not $persisted.Broker.InitializeDataKeys -and $persisted.Broker.InstallationId -ceq 'preserve-id')
    Assert ($persisted.Broker.Applications[0].AllowedUserSids[0] -ceq $ApplicationUserSid)
    Assert (Test-Path -LiteralPath (Join-Path $data 'preserve.bin'))
    Write-Output 'FAILED_UPDATE_DISALLOWS_INITIALIZATION_PRESERVES_STATE=PASS'

    $packageFixture = Join-Path $fixture 'package'
    foreach ($component in @('broker', 'sample')) {
        $componentPath = Join-Path $packageFixture $component
        New-Item -ItemType Directory -Path $componentPath -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $componentPath 'coreclr.dll'), 'synthetic-not-a-runtime')
        [IO.File]::WriteAllText((Join-Path $componentPath 'synthetic.runtimeconfig.json'), '{"runtimeOptions":{"includedFrameworks":[{"name":"Microsoft.NETCore.App","version":"10.0.6"}]}}')
    }
    $packageFiles = @(Get-ChildItem -LiteralPath $packageFixture -Recurse -File | ForEach-Object {
        @{ path = $_.FullName.Substring($packageFixture.Length + 1).Replace('\', '/'); bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    })
    $packageManifest = @{ schemaVersion = 1; product = 'SecureIntegration.LocalBroker'; sourceCommit = ('a' * 40); runtimeIdentifier = 'win-x64'; selfContained = $true; files = $packageFiles }
    [IO.File]::WriteAllText((Join-Path $packageFixture 'package-manifest.json'), ($packageManifest | ConvertTo-Json -Depth 5))
    $validator = Join-Path $PSScriptRoot '..\..\..\eng\Test-LocalBrokerPackage.ps1'
    & $validator -PackageDirectory $packageFixture -ExpectedSourceCommit ('a' * 40) | Out-Null
    $tamper = Join-Path $packageFixture 'broker\coreclr.dll'
    [IO.File]::AppendAllText($tamper, '-tampered')
    $denied = $false
    try { & $validator -PackageDirectory $packageFixture -ExpectedSourceCommit ('a' * 40) | Out-Null }
    catch { $denied = $_.Exception.Message -ceq 'BROKER_PACKAGE_HASH_MISMATCH' }
    Assert $denied
    [IO.File]::WriteAllText($tamper, 'synthetic-not-a-runtime')
    [IO.File]::WriteAllText((Join-Path $packageFixture 'broker\appsettings.json'), '{}')
    $denied = $false
    try { & $validator -PackageDirectory $packageFixture -ExpectedSourceCommit ('a' * 40) | Out-Null }
    catch { $denied = $_.Exception.Message -ceq 'BROKER_PACKAGE_INVENTORY_MISMATCH' }
    Assert $denied
    Write-Output 'PACKAGE_TAMPER_AND_UNLISTED_SETTINGS_DENIED=PASS'

    $deliveryPath = Join-Path $PSScriptRoot '..\..\..\eng\Test-LocalBrokerWindowsDelivery.ps1'
    $deliveryAst = [Management.Automation.Language.Parser]::ParseFile($deliveryPath, [ref]$tokens, [ref]$errors)
    foreach ($functionName in @('StateDigest', 'Get-SyntheticBootstrap', 'Assert-BaselineResume')) {
        $definition = $deliveryAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $functionName }, $true)
        . ([ScriptBlock]::Create($definition.Extent.Text))
    }
    function ExpectDeliveryDenied([scriptblock] $Action, [string] $Code) {
        try { & $Action | Out-Null } catch { Assert ($_.Exception.Message.StartsWith($Code, [StringComparison]::Ordinal)); return }
        throw 'DELIVERY_NEGATIVE_ACCEPTED'
    }
    $root = Join-Path $fixture 'resume'; $data = Join-Path $fixture 'resume-data'
    $marker = Join-Path $root 'installation.json'; $settingsPath = Join-Path $root 'broker\appsettings.json'
    $binaryPath = '"' + (Join-Path $root 'broker\SecureIntegration.Broker.Service.exe') + '" --contentRoot "' + (Join-Path $root 'broker') + '"'
    $BaselineBrokerDirectory = Join-Path $fixture 'baseline\broker'; $BaselineSampleDirectory = Join-Path $fixture 'baseline\sample'
    New-Item -ItemType Directory -Path (Join-Path $data 'keys'), (Join-Path $root 'broker'), (Join-Path $root 'sample'), $BaselineBrokerDirectory, $BaselineSampleDirectory -Force | Out-Null
    foreach ($component in @('broker', 'sample')) {
        $leaf = if ($component -ceq 'broker') { 'SecureIntegration.Broker.Service.exe' } else { 'SecureIntegration.Samples.LocalBroker.exe' }
        [IO.File]::WriteAllText((Join-Path $fixture ('baseline\' + $component + '\' + $leaf)), 'synthetic-binary')
        Copy-Item -LiteralPath (Join-Path $fixture ('baseline\' + $component + '\' + $leaf)) -Destination (Join-Path $root $component)
    }
    $record = @{ service = $name; root = $root; data = $data; binaryPath = $binaryPath; installationId = 'preserved-synthetic-installation' }
    [IO.File]::WriteAllText($marker, ($record | ConvertTo-Json))
    [IO.File]::WriteAllText((Join-Path $data 'keys\z[1].bin'), 'synthetic-wrapped-state')
    [IO.File]::WriteAllText((Join-Path $data 'keys\active.txt'), 'synthetic-version')
    $expectedHashes = foreach ($file in @($marker, (Join-Path $data 'keys\active.txt'), (Join-Path $data 'keys\z[1].bin'))) {
        (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    }
    $retained = StateDigest
    Assert ($retained -ceq ($expectedHashes -join ',') -and $retained.Split(',').Count -eq 3)
    Assert ((StateDigest) -ceq $retained)
    Write-Output 'PS51_STATE_DIGEST_MULTIPLE_LITERAL_PATHS=PASS'

    $installedSample = Join-Path $root 'sample\SecureIntegration.Samples.LocalBroker.exe'
    $settings = @{ Broker = @{ ServiceName = $name; PipeName = $name; InstallationId = $record.installationId; DataDirectory = $data;
        InitializeDataKeys = $false; Gateway = @{ Enabled = $false }; Applications = @(@{
            RegistrationId = 'local-sample'; AllowedUserSids = @($ApplicationUserSid); ExecutablePaths = @($installedSample)
            ExecutableSha256 = @((Get-FileHash -LiteralPath $installedSample -Algorithm SHA256).Hash)
            AllowedOperations = @('ProtectData', 'UnprotectData', 'GetBrokerStatus')
            AllowedDataProtectionContexts = @(@{ Purpose = 'sample'; ContentType = 'text/plain' })
        }) } }
    Write-Settings $settings
    $script:service = [pscustomobject]@{ PathName = $binaryPath; StartName = 'NT SERVICE\' + $name; State = 'Stopped' }
    $BaselineEnvelopeForUpgrade = $false
    $stopsBefore = $script:stops
    Assert-BaselineResume
    Assert ((StateDigest) -ceq $retained -and $script:stops -eq $stopsBefore)
    $script:service.State = 'Running'
    ExpectDeliveryDenied { Assert-BaselineResume } 'DELIVERY_RESUME_REQUIRES_OWNED_STOPPED_BASELINE'
    $BaselineEnvelopeForUpgrade = $true
    Assert-BaselineResume
    $script:service.State = 'Stopped'
    $BaselineEnvelopeForUpgrade = $false
    $script:service.PathName = 'foreign.exe'
    ExpectDenied { Assert-BaselineResume }
    $script:service.PathName = $binaryPath
    [IO.File]::AppendAllText($installedSample, '-different-build')
    ExpectDeliveryDenied { Assert-BaselineResume } 'DELIVERY_BASELINE_FILES_MISMATCH'
    [IO.File]::WriteAllText($installedSample, 'synthetic-binary')
    $settings.Broker.InitializeDataKeys = $true
    Write-Settings $settings
    ExpectDeliveryDenied { Assert-BaselineResume } 'DELIVERY_BASELINE_CONFIGURATION_MISMATCH'
    $settings.Broker.InitializeDataKeys = $false
    $settings.Broker.Applications[0].AllowedUserSids = @('foreign-sid')
    Write-Settings $settings
    ExpectDeliveryDenied { Assert-BaselineResume } 'DELIVERY_BASELINE_CONFIGURATION_MISMATCH'
    Assert ((StateDigest) -ceq $retained -and $script:stops -eq $stopsBefore)
    Write-Output 'BASELINE_RESUME_OWNERSHIP_BUILD_POLICY_STATE=PASS (read-only simulated SCM)'

    $SyntheticBootstrapDirectory = Join-Path $fixture 'synthetic-bootstrap'
    New-Item -ItemType Directory -Path (Join-Path $SyntheticBootstrapDirectory 'certificates') -Force | Out-Null
    $rsa = [Security.Cryptography.RSACng]::new(2048)
    $certificate = $null
    $previousCulture = [Threading.Thread]::CurrentThread.CurrentCulture
    try {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=M3 Synthetic Root fixture', $rsa,
            [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddHours(1))
        [IO.File]::WriteAllBytes((Join-Path $SyntheticBootstrapDirectory 'certificates\ca.crt'), $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        $document = @{ sampleConnector = @{ connectorId = 'sample-secure-service'; state = 'Published' }; activationCodeId = [guid]::NewGuid().ToString('D'); activationCode = 'synthetic-single-use'; expiresAtUtc = [DateTime]::UtcNow.AddMinutes(30).ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
        $documentPath = Join-Path $SyntheticBootstrapDirectory 'provisioning.json'
        [IO.File]::WriteAllText($documentPath, ($document | ConvertTo-Json))
        [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('it-IT')
        $validated = Get-SyntheticBootstrap
        Assert ($validated.Expires -gt [DateTimeOffset]::UtcNow)
        $validated.Certificate.Dispose()
        $goodDirectory = $SyntheticBootstrapDirectory
        $SyntheticBootstrapDirectory += '-missing'
        ExpectDeliveryDenied { Get-SyntheticBootstrap } 'DELIVERY_SYNTHETIC_BOOTSTRAP_INVALID_OR_EXPIRED'
        $SyntheticBootstrapDirectory = $goodDirectory
        $document.expiresAtUtc = '06/09/2026 08:37:08'
        [IO.File]::WriteAllText($documentPath, ($document | ConvertTo-Json))
        ExpectDeliveryDenied { Get-SyntheticBootstrap } 'DELIVERY_SYNTHETIC_BOOTSTRAP_INVALID_OR_EXPIRED'
        $document.expiresAtUtc = '2000-01-01T00:00:00.0000000Z'
        [IO.File]::WriteAllText($documentPath, ($document | ConvertTo-Json))
        ExpectDeliveryDenied { Get-SyntheticBootstrap } 'DELIVERY_SYNTHETIC_BOOTSTRAP_INVALID_OR_EXPIRED'
        Assert ((StateDigest) -ceq $retained -and $script:stops -eq $stopsBefore)
        Write-Output 'PS51_BOOTSTRAP_PREFLIGHT_ISO_CULTURE_PATH_EXPIRY=PASS'
    }
    finally {
        [Threading.Thread]::CurrentThread.CurrentCulture = $previousCulture
        if ($certificate) { $certificate.Dispose() }
        $rsa.Dispose()
    }
}
finally {
    if (([IO.Path]::GetFullPath($fixture)).StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}

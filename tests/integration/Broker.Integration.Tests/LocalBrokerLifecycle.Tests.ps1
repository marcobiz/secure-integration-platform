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
}
finally {
    if (([IO.Path]::GetFullPath($fixture)).StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}

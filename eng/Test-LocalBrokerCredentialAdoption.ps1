# One bounded administrator-assisted standard-account proof. Windows PowerShell 5.1.
[CmdletBinding()]
param(
    [string] $PackageDirectory,
    [string] $EvidenceDirectory,
    [ValidatePattern('^[0-9a-f]{40}$')][string] $ExpectedSourceCommit,
    [ValidatePattern('^credential-[a-z0-9-]{1,25}$')][string] $Instance = 'credential-20260905',
    [ValidatePattern('^BrokerCred[0-9]{4,8}$')][string] $AccountName = 'BrokerCred0905',
    [string] $StandardUserSid,
    [string] $ContinueAccountSid
)
if ($StandardUserSid) { Write-Output 'STANDARD_ACCOUNT_PROOF=ENTERED' }
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue' # Suppress progress, not errors, from first-use module loading.
Set-StrictMode -Version Latest
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$name = 'SecureIntegrationBroker.Local.' + $Instance
$installRoot = Join-Path $env:ProgramFiles ('SecureIntegration\LocalBroker\' + $Instance)
$sample = Join-Path $installRoot 'sample\SecureIntegration.Samples.LocalBroker.exe'
$accountDescription = 'SIP proof ' + $Instance # At most 46 characters; New-LocalUser allows 48.
$accountParameters = @{ Name = $AccountName; Description = $accountDescription }

function New-EphemeralValue {
    $bytes = New-Object byte[] 48
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($bytes); return [Convert]::ToBase64String($bytes) }
    finally { [Array]::Clear($bytes, 0, $bytes.Length); $random.Dispose() }
}
function Get-ChildStderrKind([string] $Value) {
    if ($Value.Length -eq 0) { return 'empty' }
    if ($Value.Length -gt 32768) { return 'oversized' }
    if (-not $Value.StartsWith('#< CLIXML', [StringComparison]::Ordinal)) { return 'other' }
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 32768
    $text = [IO.StringReader]::new($Value.Substring(9).Trim())
    $reader = $null
    try {
        $reader = [Xml.XmlReader]::Create($text, $settings)
        $document = [Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
        if ($document.DocumentElement.LocalName -cne 'Objs' -or
            $document.DocumentElement.NamespaceURI -cne 'http://schemas.microsoft.com/powershell/2004/04') { return 'other' }
        $records = @($document.DocumentElement.ChildNodes | Where-Object { $_ -is [Xml.XmlElement] })
        if ($records.Count -eq 0) { return 'other' }
        foreach ($record in $records) {
            if ($record.LocalName -cne 'Obj' -or $record.GetAttribute('S') -cne 'progress') { return 'other' }
        }
        return 'progress-only-clixml'
    }
    catch { return 'other' }
    finally { if ($reader) { $reader.Dispose() }; $text.Dispose() }
}
function Invoke-Sample([string] $Action, [string] $Envelope, [string] $InputValue, [bool] $ExpectSuccess = $true) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $sample
    $info.Arguments = $Action + ' ' + $name + ' ' + $name + ' local-sample "' + $Envelope + '"'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'CREDENTIAL_GATE_PROCESS_START_FAILED' }
        if ($InputValue) { $process.StandardInput.WriteLine($InputValue) }
        $process.StandardInput.Close()
        $output = $process.StandardOutput.ReadToEndAsync()
        $errorOutput = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(90000)) { $process.Kill(); throw 'CREDENTIAL_GATE_SAMPLE_TIMEOUT' }
        $expected = if ($Action -ceq 'set-credential') { 'CREDENTIAL_SAVED' }
            else { 'CREDENTIAL_LOADED_FOR_APPLICATION (no external authentication performed)' }
        if ($ExpectSuccess) {
            if ($process.ExitCode -ne 0 -or $output.Result.Trim() -cne $expected -or $errorOutput.Result.Length -ne 0) {
                throw 'CREDENTIAL_GATE_SAMPLE_FAILED'
            }
        } elseif ($process.ExitCode -eq 0 -or $output.Result.Length -ne 0 -or $errorOutput.Result.Trim() -cne 'LOCAL_BROKER_SAMPLE_FAILED') {
            throw 'CREDENTIAL_GATE_EXPECTED_SAVE_FAILURE'
        }
    }
    finally { $process.Dispose() }
}

if ($StandardUserSid) {
    # A new Windows logon/process, not impersonation or the filtered administrator token.
    # WindowsIdentity.Groups omits deny-only groups in a filtered token: also query membership.
    $childPhase = 'membership-validation'
    try {
        $adminMember = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -ceq $identity.User.Value }).Count -ne 0
        $childPhase = 'identity-validation'
        if ($identity.User.Value -cne $StandardUserSid -or $adminMember -or $identity.Groups.Value -contains 'S-1-5-32-544' -or
            $identity.Name -ine ($env:COMPUTERNAME + '\' + $AccountName) -or
            $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'CREDENTIAL_GATE_NOT_STANDARD_ACCOUNT' }
        $childPhase = 'profile-path'
        $appData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
        if ([string]::IsNullOrWhiteSpace($appData)) { throw 'CREDENTIAL_GATE_PROFILE_UNAVAILABLE' }
        $envelope = Join-Path $appData ('SecureIntegrationCredentialSample-' + $Instance + '\credential.envelope')
        if ($ContinueAccountSid) {
            if ($ContinueAccountSid -cne $StandardUserSid) { throw 'CREDENTIAL_GATE_NOT_STANDARD_ACCOUNT' }
            # Preserve a possibly successful earlier execution; verify it without replacing it.
            $childPhase = 'prior-ciphertext-use'
            if (Test-Path -LiteralPath $envelope) { Invoke-Sample 'use-credential' $envelope '' }
            $envelope = Join-Path (Split-Path -Parent $envelope) 'credential-continuation.envelope'
            if (Test-Path -LiteralPath $envelope) { throw 'CREDENTIAL_GATE_APPDATA_COLLISION' }
        } elseif (Test-Path -LiteralPath (Split-Path -Parent $envelope)) { throw 'CREDENTIAL_GATE_APPDATA_COLLISION' }
        $childPhase = 'initial-save'
        Invoke-Sample 'set-credential' $envelope (New-EphemeralValue)
        $childPhase = 'initial-new-process-use'
        Invoke-Sample 'use-credential' $envelope ''
        $first = [IO.File]::ReadAllBytes($envelope)
        $childPhase = 'replacement-save'
        Invoke-Sample 'set-credential' $envelope (New-EphemeralValue)
        $childPhase = 'replacement-new-process-use'
        Invoke-Sample 'use-credential' $envelope ''
        $beforeFailure = [IO.File]::ReadAllBytes($envelope)
        if ([Convert]::ToBase64String($first) -ceq [Convert]::ToBase64String($beforeFailure)) { throw 'CREDENTIAL_GATE_REPLACEMENT_MISSING' }
        $childPhase = 'failed-save-preservation'
        $locked = [IO.File]::Open($envelope, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try { Invoke-Sample 'set-credential' $envelope (New-EphemeralValue) $false }
        finally { $locked.Dispose() }
        if ([Convert]::ToBase64String($beforeFailure) -cne [Convert]::ToBase64String([IO.File]::ReadAllBytes($envelope))) {
            throw 'CREDENTIAL_GATE_PREVIOUS_CONFIGURATION_CHANGED'
        }
        $childPhase = 'preserved-new-process-use'
        Invoke-Sample 'use-credential' $envelope ''
        Write-Output 'STANDARD_ACCOUNT_CREDENTIAL_ADOPTION=PASS'
    }
    catch {
        $type = $_.Exception.GetType().Name
        if ($type -cnotin @('RuntimeException', 'ParameterBindingException', 'ParameterBindingValidationException',
            'CommandNotFoundException', 'UnauthorizedAccessException', 'MethodInvocationException')) { $type = 'Other' }
        [Console]::Error.WriteLine('STANDARD_ACCOUNT_CREDENTIAL_ADOPTION=FAILED PHASE=' + $childPhase + ' TYPE=' + $type + ' CATEGORY=' + [string]$_.CategoryInfo.Category)
        exit 1
    }
    # Only ciphertext is left in this task user's private profile. No raw values/evidence.
    exit 0
}

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'CREDENTIAL_GATE_ADMIN_SETUP_REQUIRED' }
if (-not $PackageDirectory -or -not $EvidenceDirectory -or -not $ExpectedSourceCommit) { throw 'CREDENTIAL_GATE_ARGUMENTS_REQUIRED' }
$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
& (Join-Path $PSScriptRoot 'Test-LocalBrokerPackage.ps1') -PackageDirectory $package -ExpectedSourceCommit $ExpectedSourceCommit
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
$data = Join-Path $env:ProgramData ('SecureIntegration\LocalBroker\' + $Instance)
if (Test-Path -LiteralPath $evidence) { throw 'CREDENTIAL_GATE_EXISTING_EVIDENCE_PRESERVED' }
$existingUser = Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue
$existingService = Get-CimInstance Win32_Service -Filter "Name='$name'"
$preservedState = @()
if ($ContinueAccountSid) {
    if (-not $existingUser -or $existingUser.SID.Value -cne $ContinueAccountSid -or $existingUser.Enabled -or
        $existingUser.Description -cne $accountDescription -or -not $existingService -or $existingService.State -cne 'Stopped') {
        throw 'CREDENTIAL_GATE_CONTINUATION_OWNERSHIP_DENIED'
    }
    if (@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -ceq $ContinueAccountSid }).Count -ne 0 -or
        @(Get-LocalGroupMember -SID 'S-1-5-32-545' | Where-Object { $_.SID.Value -ceq $ContinueAccountSid }).Count -ne 1) {
        throw 'CREDENTIAL_GATE_CONTINUATION_MEMBERSHIP_DENIED'
    }
    foreach ($path in @($installRoot, $data, (Join-Path $installRoot 'installation.json'),
        (Join-Path $installRoot 'broker\appsettings.json'), (Join-Path $installRoot 'credential-adoption-proof.ps1'), (Join-Path $data 'keys'))) {
        $cursor = [IO.Path]::GetFullPath($path)
        while ($cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'CREDENTIAL_GATE_REPARSE_DENIED' }
            $parent = Split-Path -Parent $cursor
            if ($parent -eq $cursor) { break }
            $cursor = $parent
        }
    }
    $marker = Get-Content -LiteralPath (Join-Path $installRoot 'installation.json') -Raw | ConvertFrom-Json
    $configuration = (Get-Content -LiteralPath (Join-Path $installRoot 'broker\appsettings.json') -Raw | ConvertFrom-Json).Broker
    $expectedBinary = '"' + (Join-Path $installRoot 'broker\SecureIntegration.Broker.Service.exe') + '" --contentRoot "' + (Join-Path $installRoot 'broker') + '"'
    if ($marker.root -cne $installRoot -or $marker.data -cne $data -or $marker.service -cne $name -or $marker.binaryPath -cne $expectedBinary -or
        $marker.binaryPath -cne $existingService.PathName -or $existingService.StartName -ine ('NT SERVICE\' + $name) -or
        $configuration.InstallationId -cne $marker.installationId -or $configuration.DataDirectory -cne $data -or
        $configuration.ServiceName -cne $name -or $configuration.PipeName -cne $name -or
        $configuration.InitializeDataKeys -or $configuration.Gateway.Enabled -or
        @($configuration.Applications).Count -ne 1 -or $configuration.Applications[0].RegistrationId -cne 'local-sample' -or
        @($configuration.Applications[0].AllowedUserSids).Count -ne 1 -or $configuration.Applications[0].AllowedUserSids[0] -cne $ContinueAccountSid) {
        throw 'CREDENTIAL_GATE_CONTINUATION_CONFIGURATION_DENIED'
    }
    $manifest = Get-Content -LiteralPath (Join-Path $package 'package-manifest.json') -Raw | ConvertFrom-Json
    foreach ($entry in $manifest.files | Where-Object { $_.path -cmatch '^(broker|sample)/' }) {
        $installedFile = Join-Path $installRoot $entry.path
        if ((Get-Item -LiteralPath $installedFile).Attributes -band [IO.FileAttributes]::ReparsePoint -or
            (Get-FileHash -LiteralPath $installedFile -Algorithm SHA256).Hash -cne $entry.sha256) { throw 'CREDENTIAL_GATE_INSTALLED_PACKAGE_MISMATCH' }
    }
    $stateFiles = @((Join-Path $installRoot 'installation.json'), (Join-Path $installRoot 'broker\appsettings.json')) +
        @(Get-ChildItem -LiteralPath (Join-Path $data 'keys') -File | Sort-Object Name | Select-Object -ExpandProperty FullName)
    if ($stateFiles.Count -lt 5) { throw 'CREDENTIAL_GATE_EXISTING_KEYS_REQUIRED' }
    $preservedState = @($stateFiles | ForEach-Object { (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash })
} elseif ($existingUser -or $existingService -or (Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath $data)) {
    throw 'CREDENTIAL_GATE_FOREIGN_OR_PREVIOUS_RESOURCE_PRESERVED'
}
$user = $null
$secret = $null
$installed = $false
$passed = $false
$phase = 'account-parameter-validation'
$failureType = 'none'
$failureCategory = 'none'
$failedChildPhase = 'none'
$failedChildType = 'none'
$failedChildCategory = 'none'
$childExitCode = $null
$childExactPass = $false
$childEntered = $false
$childStderrKind = 'not-observed'
$started = [DateTimeOffset]::UtcNow
$lifecycle = Join-Path $package 'Invoke-LocalBroker.ps1'
try {
    $secret = ConvertTo-SecureString ((New-EphemeralValue) + '-aA1!') -AsPlainText -Force
    if ($ContinueAccountSid) {
        $phase = 'owned-account-login-reset'
        $user = $existingUser
        # Disposable login only; the Broker's virtual-service DPAPI identity is untouched.
        Set-LocalUser -SID $user.SID -Password $secret
        Enable-LocalUser -SID $user.SID
    } else {
        New-LocalUser @accountParameters -Password $secret -WhatIf | Out-Null
        $phase = 'account-create'
        $user = New-LocalUser @accountParameters -Password $secret
        $users = Get-LocalGroup -SID 'S-1-5-32-545'
        Add-LocalGroupMember -Group $users -Member $user
    }
    $phase = 'account-membership'
    if (@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -ceq $user.SID.Value }).Count -ne 0) {
        throw 'CREDENTIAL_GATE_ACCOUNT_IS_ADMINISTRATOR'
    }
    $installed = $true
    if (-not $ContinueAccountSid) {
        $phase = 'service-install'
        & $lifecycle -Command Install -Instance $Instance -ApplicationUserSid $user.SID.Value
    }
    $phase = 'service-start'
    & $lifecycle -Command Start -Instance $Instance
    $phase = 'standard-user-process'
    # The task proof is separate from the product-only archive; child source is admin-owned.
    $childScript = Join-Path $installRoot 'credential-adoption-proof.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $childScript
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $info.Arguments = '-NoProfile -File "' + $childScript + '" -Instance ' + $Instance + ' -AccountName ' + $AccountName + ' -StandardUserSid ' + $user.SID.Value
    if ($ContinueAccountSid) { $info.Arguments += ' -ContinueAccountSid ' + $ContinueAccountSid }
    $info.UserName = $AccountName
    $info.Domain = $env:COMPUTERNAME
    $info.Password = $secret
    $info.LoadUserProfile = $true
    $info.WorkingDirectory = $installRoot
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.EnvironmentVariables.Remove('PSModulePath')
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $info
    try {
        if (-not $child.Start()) { throw 'CREDENTIAL_GATE_LOGON_FAILED' }
        $output = $child.StandardOutput.ReadToEndAsync()
        $errorOutput = $child.StandardError.ReadToEndAsync()
        if (-not $child.WaitForExit(300000)) { $child.Kill(); throw 'CREDENTIAL_GATE_CHILD_TIMEOUT' }
        $childExitCode = $child.ExitCode
        $lines = @($output.Result.Trim() -split '\r?\n')
        $childEntered = $lines.Count -gt 0 -and $lines[0] -ceq 'STANDARD_ACCOUNT_PROOF=ENTERED'
        $childExactPass = $lines.Count -eq 2 -and $childEntered -and $lines[1] -ceq 'STANDARD_ACCOUNT_CREDENTIAL_ADOPTION=PASS'
        $childStderrKind = Get-ChildStderrKind $errorOutput.Result
        if ($childExitCode -ne 0 -or -not $childExactPass -or $childStderrKind -notin @('empty', 'progress-only-clixml')) {
            if ($errorOutput.Result.Trim() -cmatch '^STANDARD_ACCOUNT_CREDENTIAL_ADOPTION=FAILED PHASE=(membership-validation|identity-validation|profile-path|prior-ciphertext-use|initial-save|initial-new-process-use|replacement-save|replacement-new-process-use|failed-save-preservation|preserved-new-process-use) TYPE=([a-zA-Z]+) CATEGORY=([a-zA-Z]+)$') {
                $failedChildPhase = $Matches[1]
                $failedChildType = $Matches[2]
                $failedChildCategory = $Matches[3]
            }
            throw 'CREDENTIAL_GATE_STANDARD_USER_FAILED'
        }
        $passed = $true
        $phase = 'completed'
    }
    finally { $child.Dispose() }
}
catch {
    $type = $_.Exception.GetType().Name
    $failureType = if ($type -cin @('ParameterBindingValidationException', 'InvalidOperationException', 'Win32Exception',
        'UnauthorizedAccessException', 'RuntimeException', 'PSInvalidOperationException')) { $type } else { 'Other' }
    $failureCategory = [string]$_.CategoryInfo.Category
    throw ('CREDENTIAL_GATE_FAILED PHASE=' + $phase + ' CATEGORY=' + $failureCategory + ' TYPE=' + $failureType + ' CHILD_PHASE=' + $failedChildPhase)
}
finally {
    try {
        if ($installed) { & $lifecycle -Command Stop -Instance $Instance }
    }
    finally {
        try {
            if ($user) {
                $owned = Get-LocalUser -SID $user.SID
                if ($owned.Name -cne $AccountName -or $owned.Description -cne $accountDescription) {
                    throw 'CREDENTIAL_GATE_ACCOUNT_OWNERSHIP_UNCERTAIN'
                }
                Disable-LocalUser -SID $user.SID
            }
        }
        finally {
            if ($secret) { $secret.Dispose() }
        }
    }
    if ($ContinueAccountSid) {
        $afterFiles = @((Join-Path $installRoot 'installation.json'), (Join-Path $installRoot 'broker\appsettings.json')) +
            @(Get-ChildItem -LiteralPath (Join-Path $data 'keys') -File | Sort-Object Name | Select-Object -ExpandProperty FullName)
        $afterState = @($afterFiles | ForEach-Object { (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash })
        if (($preservedState -join ',') -cne ($afterState -join ',')) { throw 'CREDENTIAL_GATE_EXISTING_STATE_CHANGED' }
    }
    New-Item -ItemType Directory -Path $evidence | Out-Null
    $result = [ordered]@{
        schemaVersion = 1; sourceCommit = $ExpectedSourceCommit; passed = $passed
        gateScriptSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
        phase = $phase; failureType = $failureType; failureCategory = $failureCategory; failedChildPhase = $failedChildPhase
        failedChildType = $failedChildType; failedChildCategory = $failedChildCategory
        childExitCode = $childExitCode; childExactPass = $childExactPass; childEntered = $childEntered; childStderrKind = $childStderrKind
        existingBrokerStatePreserved = [bool]$ContinueAccountSid
        standardAccountNotInAdministrators = $passed; configureNewExecutionReplace = $passed
        failedSavePreservesPreviousCiphertext = $passed; externalCalls = 0; rawDataRetained = $false
        accountDisabled = [bool]$user; ownedServiceStopped = $installed
        retained = $(if ($user) { 'task-owned disabled account/profile and any protected installation/ciphertext; not an uninstall' } else { 'no task account was created' })
        elapsedSeconds = [int]([DateTimeOffset]::UtcNow - $started).TotalSeconds
    }
    $resultPath = Join-Path $evidence 'result.json'
    [IO.File]::WriteAllText($resultPath, ($result | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(($resultPath + '.sha256'), (Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash, [Text.UTF8Encoding]::new($false))
}
if (-not $passed) { throw 'CREDENTIAL_GATE_FAILED' }
Write-Output 'CREDENTIAL_ADOPTION_GATE=PASS SERVICE=STOPPED ACCOUNT=DISABLED'

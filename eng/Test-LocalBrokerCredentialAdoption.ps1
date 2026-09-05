# One bounded administrator-assisted standard-account proof. Windows PowerShell 5.1.
[CmdletBinding()]
param(
    [string] $PackageDirectory,
    [string] $EvidenceDirectory,
    [ValidatePattern('^[0-9a-f]{40}$')][string] $ExpectedSourceCommit,
    [ValidatePattern('^credential-[a-z0-9-]{1,25}$')][string] $Instance = 'credential-20260905',
    [ValidatePattern('^BrokerCred[0-9]{4,8}$')][string] $AccountName = 'BrokerCred0905',
    [string] $StandardUserSid
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$name = 'SecureIntegrationBroker.Local.' + $Instance
$installRoot = Join-Path $env:ProgramFiles ('SecureIntegration\LocalBroker\' + $Instance)
$sample = Join-Path $installRoot 'sample\SecureIntegration.Samples.LocalBroker.exe'

function New-EphemeralValue {
    $bytes = New-Object byte[] 48
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($bytes); return [Convert]::ToBase64String($bytes) }
    finally { [Array]::Clear($bytes, 0, $bytes.Length); $random.Dispose() }
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
    $adminMember = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -ceq $identity.User.Value }).Count -ne 0
    if ($identity.User.Value -cne $StandardUserSid -or $adminMember -or $identity.Groups.Value -contains 'S-1-5-32-544' -or
        $identity.Name -ine ($env:COMPUTERNAME + '\' + $AccountName) -or
        $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'CREDENTIAL_GATE_NOT_STANDARD_ACCOUNT' }
    $appData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $envelope = Join-Path $appData ('SecureIntegrationCredentialSample-' + $Instance + '\credential.envelope')
    if (Test-Path -LiteralPath (Split-Path -Parent $envelope)) { throw 'CREDENTIAL_GATE_APPDATA_COLLISION' }
    try {
        Invoke-Sample 'set-credential' $envelope (New-EphemeralValue)
        Invoke-Sample 'use-credential' $envelope ''
        $first = [IO.File]::ReadAllBytes($envelope)
        Invoke-Sample 'set-credential' $envelope (New-EphemeralValue)
        Invoke-Sample 'use-credential' $envelope ''
        $beforeFailure = [IO.File]::ReadAllBytes($envelope)
        if ([Convert]::ToBase64String($first) -ceq [Convert]::ToBase64String($beforeFailure)) { throw 'CREDENTIAL_GATE_REPLACEMENT_MISSING' }
        $locked = [IO.File]::Open($envelope, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try { Invoke-Sample 'set-credential' $envelope (New-EphemeralValue) $false }
        finally { $locked.Dispose() }
        if ([Convert]::ToBase64String($beforeFailure) -cne [Convert]::ToBase64String([IO.File]::ReadAllBytes($envelope))) {
            throw 'CREDENTIAL_GATE_PREVIOUS_CONFIGURATION_CHANGED'
        }
        Invoke-Sample 'use-credential' $envelope ''
        Write-Output 'STANDARD_ACCOUNT_CREDENTIAL_ADOPTION=PASS'
    }
    catch { [Console]::Error.WriteLine('STANDARD_ACCOUNT_CREDENTIAL_ADOPTION=FAILED'); exit 1 }
    # Only ciphertext is left in this task user's private profile. No raw values/evidence.
    exit 0
}

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'CREDENTIAL_GATE_ADMIN_SETUP_REQUIRED' }
if (-not $PackageDirectory -or -not $EvidenceDirectory -or -not $ExpectedSourceCommit) { throw 'CREDENTIAL_GATE_ARGUMENTS_REQUIRED' }
$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
& (Join-Path $PSScriptRoot 'Test-LocalBrokerPackage.ps1') -PackageDirectory $package -ExpectedSourceCommit $ExpectedSourceCommit
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
$data = Join-Path $env:ProgramData ('SecureIntegration\LocalBroker\' + $Instance)
if ((Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue) -or (Get-Service -Name $name -ErrorAction SilentlyContinue) -or
    (Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath $data) -or (Test-Path -LiteralPath $evidence)) {
    throw 'CREDENTIAL_GATE_FOREIGN_OR_PREVIOUS_RESOURCE_PRESERVED'
}
$user = $null
$secret = $null
$installed = $false
$passed = $false
$started = [DateTimeOffset]::UtcNow
$lifecycle = Join-Path $package 'Invoke-LocalBroker.ps1'
try {
    $secret = ConvertTo-SecureString ((New-EphemeralValue) + '-aA1!') -AsPlainText -Force
    $user = New-LocalUser -Name $AccountName -Password $secret -Description ('Task-owned Local Broker credential adoption ' + $Instance)
    $users = Get-LocalGroup -SID 'S-1-5-32-545'
    Add-LocalGroupMember -Group $users -Member $user
    if (@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -ceq $user.SID.Value }).Count -ne 0) {
        throw 'CREDENTIAL_GATE_ACCOUNT_IS_ADMINISTRATOR'
    }
    $installed = $true
    & $lifecycle -Command Install -Instance $Instance -ApplicationUserSid $user.SID.Value
    & $lifecycle -Command Start -Instance $Instance
    # The task proof is separate from the product-only archive; child source is admin-owned.
    $childScript = Join-Path $installRoot 'credential-adoption-proof.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $childScript
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $info.Arguments = '-NoProfile -File "' + $childScript + '" -Instance ' + $Instance + ' -AccountName ' + $AccountName + ' -StandardUserSid ' + $user.SID.Value
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
        if ($child.ExitCode -ne 0 -or $output.Result.Trim() -cne 'STANDARD_ACCOUNT_CREDENTIAL_ADOPTION=PASS' -or $errorOutput.Result.Length -ne 0) {
            throw 'CREDENTIAL_GATE_STANDARD_USER_FAILED'
        }
        $passed = $true
    }
    finally { $child.Dispose() }
}
catch { throw 'CREDENTIAL_GATE_FAILED: bounded standard-account setup or invocation failure; no credential output retained.' }
finally {
    try {
        if ($installed) { & $lifecycle -Command Stop -Instance $Instance }
    }
    finally {
        try {
            if ($user) {
                $owned = Get-LocalUser -SID $user.SID
                if ($owned.Name -cne $AccountName -or $owned.Description -cne ('Task-owned Local Broker credential adoption ' + $Instance)) {
                    throw 'CREDENTIAL_GATE_ACCOUNT_OWNERSHIP_UNCERTAIN'
                }
                Disable-LocalUser -SID $user.SID
            }
        }
        finally {
            if ($secret) { $secret.Dispose() }
        }
    }
    New-Item -ItemType Directory -Path $evidence | Out-Null
    $result = [ordered]@{
        schemaVersion = 1; sourceCommit = $ExpectedSourceCommit; passed = $passed
        standardAccountNotInAdministrators = $passed; configureNewExecutionReplace = $passed
        failedSavePreservesPreviousCiphertext = $passed; externalCalls = 0; rawDataRetained = $false
        accountDisabled = [bool]$user; ownedServiceStopped = $installed
        retained = 'task-owned disabled account/profile, stopped service and protected installation/ciphertext; not an uninstall'
        elapsedSeconds = [int]([DateTimeOffset]::UtcNow - $started).TotalSeconds
    }
    $resultPath = Join-Path $evidence 'result.json'
    [IO.File]::WriteAllText($resultPath, ($result | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(($resultPath + '.sha256'), (Get-FileHash -LiteralPath $resultPath -Algorithm SHA256).Hash, [Text.UTF8Encoding]::new($false))
}
if (-not $passed) { throw 'CREDENTIAL_GATE_FAILED' }
Write-Output 'CREDENTIAL_ADOPTION_GATE=PASS SERVICE=STOPPED ACCOUNT=DISABLED'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-LiveMatrixAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'LIVE_MATRIX_REQUIRES_ELEVATION: open Windows PowerShell as Administrator.'
    }
}

function Get-LiveMatrixRepositoryRoot {
    return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
}

function Get-LiveMatrixPaths {
    param([Parameter(Mandatory)] [string] $RunId)

    $root = Join-Path $env:ProgramData 'SecureIntegration\LiveMatrix'
    return [ordered]@{
        Root = $root
        Run = Join-Path $root $RunId
        State = Join-Path (Join-Path $root $RunId) 'state'
        Exchange = Join-Path (Join-Path $root $RunId) 'exchange'
        Raw = Join-Path (Join-Path $root $RunId) 'raw'
        Evidence = Join-Path (Join-Path $root $RunId) 'evidence'
        Install = Join-Path $env:ProgramFiles 'SecureIntegration\LiveMatrix'
        Broker = Join-Path (Join-Path $env:ProgramFiles 'SecureIntegration\LiveMatrix') 'Broker'
        AuthorizedProbe = Join-Path (Join-Path $env:ProgramFiles 'SecureIntegration\LiveMatrix') 'AuthorizedProbe'
        UnauthorizedProbe = Join-Path (Join-Path $env:ProgramFiles 'SecureIntegration\LiveMatrix') 'UnauthorizedProbe'
        BrokerData = Join-Path $env:ProgramData 'SecureIntegration\Broker'
    }
}

function Set-DirectoryAclExact {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string[]] $Sid,
        [ValidateSet('FullControl', 'ReadAndExecute', 'Modify')] [string] $Rights = 'FullControl'
    )

    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $flags = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($value in ($Sid | Select-Object -Unique)) {
        $identifier = [Security.Principal.SecurityIdentifier]::new($value)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($identifier, [Security.AccessControl.FileSystemRights]::$Rights, $flags, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        [void]$security.AddAccessRule($rule)
    }
    [IO.Directory]::SetAccessControl($Path, $security)
}

function Get-WellKnownLiveMatrixSids {
    return [ordered]@{
        System = ([Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null)).Value
        Administrators = ([Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)).Value
    }
}

function Initialize-LiveMatrixLsaRights {
    if ('LiveMatrix.LsaRights' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace LiveMatrix
{
    public static class LsaRights
    {
        private const uint PolicyCreateAccount = 0x00000010;
        private const uint PolicyLookupNames = 0x00000800;
        private const uint StatusObjectNameNotFound = 0xC0000034;

        [StructLayout(LayoutKind.Sequential)]
        private struct LsaObjectAttributes
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LsaUnicodeString
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [DllImport("advapi32.dll", PreserveSig = true)]
        private static extern uint LsaOpenPolicy(IntPtr systemName, ref LsaObjectAttributes attributes, uint desiredAccess, out IntPtr policyHandle);

        [DllImport("advapi32.dll", PreserveSig = true)]
        private static extern uint LsaAddAccountRights(IntPtr policyHandle, byte[] accountSid, LsaUnicodeString[] userRights, uint countOfRights);

        [DllImport("advapi32.dll", PreserveSig = true)]
        private static extern uint LsaRemoveAccountRights(IntPtr policyHandle, byte[] accountSid, bool allRights, LsaUnicodeString[] userRights, uint countOfRights);

        [DllImport("advapi32.dll", PreserveSig = true)]
        private static extern uint LsaEnumerateAccountRights(IntPtr policyHandle, byte[] accountSid, out IntPtr userRights, out uint countOfRights);

        [DllImport("advapi32.dll")]
        private static extern uint LsaNtStatusToWinError(uint status);

        [DllImport("advapi32.dll")]
        private static extern uint LsaClose(IntPtr policyHandle);

        [DllImport("advapi32.dll")]
        private static extern uint LsaFreeMemory(IntPtr buffer);

        public static bool Has(string sid, string right)
        {
            IntPtr policy = OpenPolicy();
            try
            {
                IntPtr rights;
                uint count;
                uint status = LsaEnumerateAccountRights(policy, GetSid(sid), out rights, out count);
                if (status == StatusObjectNameNotFound) { return false; }
                ThrowIfError(status);
                try
                {
                    int size = Marshal.SizeOf(typeof(LsaUnicodeString));
                    for (int index = 0; index < count; index++)
                    {
                        IntPtr current = new IntPtr(rights.ToInt64() + (index * size));
                        LsaUnicodeString value = (LsaUnicodeString)Marshal.PtrToStructure(current, typeof(LsaUnicodeString));
                        string name = Marshal.PtrToStringUni(value.Buffer, value.Length / 2);
                        if (String.Equals(name, right, StringComparison.OrdinalIgnoreCase)) { return true; }
                    }
                    return false;
                }
                finally { LsaFreeMemory(rights); }
            }
            finally { LsaClose(policy); }
        }

        public static void Add(string sid, string right)
        {
            if (Has(sid, right)) { return; }
            IntPtr policy = OpenPolicy();
            LsaUnicodeString value = CreateString(right);
            try { ThrowIfError(LsaAddAccountRights(policy, GetSid(sid), new[] { value }, 1)); }
            finally
            {
                Marshal.FreeHGlobal(value.Buffer);
                LsaClose(policy);
            }
        }

        public static void Remove(string sid, string right)
        {
            if (!Has(sid, right)) { return; }
            IntPtr policy = OpenPolicy();
            LsaUnicodeString value = CreateString(right);
            try { ThrowIfError(LsaRemoveAccountRights(policy, GetSid(sid), false, new[] { value }, 1)); }
            finally
            {
                Marshal.FreeHGlobal(value.Buffer);
                LsaClose(policy);
            }
        }

        private static IntPtr OpenPolicy()
        {
            LsaObjectAttributes attributes = new LsaObjectAttributes();
            attributes.Length = Marshal.SizeOf(typeof(LsaObjectAttributes));
            IntPtr policy;
            ThrowIfError(LsaOpenPolicy(IntPtr.Zero, ref attributes, PolicyLookupNames | PolicyCreateAccount, out policy));
            return policy;
        }

        private static byte[] GetSid(string sid)
        {
            SecurityIdentifier identifier = new SecurityIdentifier(sid);
            byte[] bytes = new byte[identifier.BinaryLength];
            identifier.GetBinaryForm(bytes, 0);
            return bytes;
        }

        private static LsaUnicodeString CreateString(string value)
        {
            LsaUnicodeString result = new LsaUnicodeString();
            result.Buffer = Marshal.StringToHGlobalUni(value);
            result.Length = checked((ushort)(value.Length * 2));
            result.MaximumLength = checked((ushort)((value.Length + 1) * 2));
            return result;
        }

        private static void ThrowIfError(uint status)
        {
            if (status == 0) { return; }
            throw new Win32Exception((int)LsaNtStatusToWinError(status));
        }
    }
}
'@
}

function Test-LiveMatrixBatchLogonRight {
    param([Parameter(Mandatory)] [string] $Sid)
    Initialize-LiveMatrixLsaRights
    return [LiveMatrix.LsaRights]::Has($Sid, 'SeBatchLogonRight')
}

function Grant-LiveMatrixBatchLogonRight {
    param([Parameter(Mandatory)] [string] $Sid)
    Initialize-LiveMatrixLsaRights
    [LiveMatrix.LsaRights]::Add($Sid, 'SeBatchLogonRight')
    if (-not [LiveMatrix.LsaRights]::Has($Sid, 'SeBatchLogonRight')) { throw "LIVE_MATRIX_BATCH_LOGON_GRANT_FAILED: $Sid" }
}

function Revoke-LiveMatrixBatchLogonRight {
    param([Parameter(Mandatory)] [string] $Sid)
    Initialize-LiveMatrixLsaRights
    [LiveMatrix.LsaRights]::Remove($Sid, 'SeBatchLogonRight')
}

function Get-LiveMatrixErrorCode {
    param([Parameter(Mandatory)] [Management.Automation.ErrorRecord] $ErrorRecord)

    if ($ErrorRecord.Exception -is [Management.Automation.CommandNotFoundException]) {
        return 'LIVE_MATRIX_RUNTIME_UNRESOLVED_COMMAND'
    }

    $fullyQualifiedId = [string]$ErrorRecord.FullyQualifiedErrorId
    if ($fullyQualifiedId -match '^(LIVE_MATRIX_[A-Z0-9_]+)') { return $Matches[1] }

    $message = [string]$ErrorRecord.Exception.Message
    if ($message -match '^(LIVE_MATRIX_[A-Z0-9_]+)') { return $Matches[1] }

    return $ErrorRecord.Exception.GetType().Name
}

function Test-LiveMatrixHarnessRuntime {
    param([Parameter(Mandatory)] [string] $RunId)

    $module = Get-Module -Name LiveMatrix.Common | Select-Object -First 1
    if ($null -eq $module) { throw 'LIVE_MATRIX_COMMON_MODULE_NOT_LOADED.' }

    $exported = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $module.ExportedFunctions.Keys) { [void]$exported.Add($name) }

    $moduleTokens = $null
    $moduleErrors = $null
    $moduleAst = [Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$moduleTokens, [ref]$moduleErrors)
    if ($moduleErrors.Count -gt 0) { throw "LIVE_MATRIX_PARSE_ERROR: $($moduleErrors[0].Message)" }
    $moduleFunctions = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($definition in $moduleAst.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        [void]$moduleFunctions.Add($definition.Name)
    }

    $missingExports = @()
    foreach ($required in 'Get-WellKnownLiveMatrixSids', 'Write-LiveMatrixJson', 'Get-LiveMatrixPaths', 'Invoke-LiveMatrixScheduledProcess') {
        if (-not $exported.Contains($required)) { $missingExports += $required }
    }
    if ($missingExports.Count -gt 0) { throw "LIVE_MATRIX_HELPER_NOT_EXPORTED: $($missingExports -join ', ')" }

    $scriptFiles = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File | Sort-Object Name)
    $unresolved = @()
    foreach ($file in $scriptFiles) {
        $tokens = $null
        $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) { throw "LIVE_MATRIX_PARSE_ERROR: $($file.Name): $($errors[0].Message)" }

        $commands = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true)
        foreach ($command in $commands) {
            $name = $command.GetCommandName()
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            if ($moduleFunctions.Contains($name) -and -not $exported.Contains($name)) {
                $unresolved += "$($file.Name):$name"
            }
        }
    }
    if ($unresolved.Count -gt 0) { throw "LIVE_MATRIX_HELPER_NOT_IMPORTED: $($unresolved -join ', ')" }

    $wellKnown = Get-WellKnownLiveMatrixSids
    foreach ($property in 'System', 'Administrators') {
        if ([string]::IsNullOrWhiteSpace([string]$wellKnown[$property])) { throw "LIVE_MATRIX_WELL_KNOWN_SID_MISSING: $property" }
    }

    return [pscustomobject]@{
        runId = $RunId
        overallStatus = 'HarnessValidated'
        preflightPassed = $null
        helperResolutionPassed = $true
        scriptParsePassed = $true
        requiredExportedFunctions = @($exported | Sort-Object)
        checkedScripts = @($scriptFiles.Name)
        checkedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    }
}

function Protect-LiveMatrixCredential {
    param([Parameter(Mandatory)] [pscredential] $Credential, [Parameter(Mandatory)] [string] $Path)

    Add-Type -AssemblyName System.Security
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    try {
        $document = @{ userName = $Credential.UserName; password = $plain } | ConvertTo-Json -Compress
        $bytes = [Text.Encoding]::UTF8.GetBytes($document)
        $protected = [Security.Cryptography.ProtectedData]::Protect($bytes, [Text.Encoding]::UTF8.GetBytes('SecureIntegration.LiveMatrix.Credential.v1'), [Security.Cryptography.DataProtectionScope]::LocalMachine)
        [IO.File]::WriteAllBytes($Path, $protected)
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    finally {
        if ($null -ne $plain) { $plain = $null }
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Unprotect-LiveMatrixCredential {
    param([Parameter(Mandatory)] [string] $Path)

    Add-Type -AssemblyName System.Security
    $protected = [IO.File]::ReadAllBytes($Path)
    $bytes = [Security.Cryptography.ProtectedData]::Unprotect($protected, [Text.Encoding]::UTF8.GetBytes('SecureIntegration.LiveMatrix.Credential.v1'), [Security.Cryptography.DataProtectionScope]::LocalMachine)
    try {
        $document = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
        return [pscredential]::new([string]$document.userName, (ConvertTo-SecureString ([string]$document.password) -AsPlainText -Force))
    }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function New-LiveMatrixPassword {
    $bytes = New-LiveMatrixRandomBytes -Length 30
    return 'Lm1!aA7-' + [Convert]::ToBase64String($bytes).Replace('/', '_').Replace('+', '-').TrimEnd('=')
}

function New-LiveMatrixRandomBytes {
    param([Parameter(Mandatory)] [ValidateRange(1, 4096)] [int] $Length)
    $bytes = New-Object byte[] $Length
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    return $bytes
}

function ConvertTo-LiveMatrixHex {
    param([Parameter(Mandatory)] [byte[]] $Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Ensure-LiveMatrixLocalUser {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $CredentialPath,
        [Parameter(Mandatory)] [ValidateLength(1, 48)] [string] $Description
    )

    $existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $existing -and -not [string]::Equals([string]$existing.Description, $Description, [StringComparison]::Ordinal)) {
        throw "LIVE_MATRIX_USER_COLLISION: local account $Name is not owned by this harness."
    }

    if (Test-Path -LiteralPath $CredentialPath) {
        $credential = Unprotect-LiveMatrixCredential -Path $CredentialPath
    }
    else {
        $credential = [pscredential]::new("$env:COMPUTERNAME\$Name", (ConvertTo-SecureString (New-LiveMatrixPassword) -AsPlainText -Force))
        Protect-LiveMatrixCredential -Credential $credential -Path $CredentialPath
    }

    if ($null -eq $existing) {
        New-LocalUser -Name $Name -Password $credential.Password -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword -Description $Description | Out-Null
    }
    else {
        Set-LocalUser -Name $Name -Password $credential.Password -AccountNeverExpires -PasswordNeverExpires $true -UserMayChangePassword $false
        if (-not $existing.Enabled) { Enable-LocalUser -Name $Name }
    }

    $account = [Security.Principal.NTAccount]::new($env:COMPUTERNAME, $Name)
    $sid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
    return [pscustomobject]@{ Name = $Name; Sid = $sid; Credential = $credential }
}

function Invoke-LiveMatrixScheduledProcess {
    param(
        [Parameter(Mandatory)] [pscredential] $Credential,
        [Parameter(Mandatory)] [string] $Executable,
        [Parameter(Mandatory)] [string] $Command,
        [Parameter(Mandatory)] [string] $InputPath,
        [Parameter(Mandatory)] [string] $OutputPath,
        [int] $TimeoutSeconds = 60,
        [switch] $ExpectFailure
    )

    Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue
    $taskName = 'SecureIntegration-LiveMatrix-' + [guid]::NewGuid().ToString('N')
    $arguments = '--command "{0}" --input "{1}" --output "{2}"' -f $Command, $InputPath, $OutputPath
    $action = New-ScheduledTaskAction -Execute $Executable -Argument $arguments
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -User $Credential.UserName -Password $plainPassword -RunLevel Limited -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        do {
            Start-Sleep -Milliseconds 250
            $info = Get-ScheduledTaskInfo -TaskName $taskName
        } while ($info.LastRunTime.Year -le 1999 -and [DateTime]::UtcNow -lt $deadline)
        do {
            Start-Sleep -Milliseconds 250
            $task = Get-ScheduledTask -TaskName $taskName
        } while ($task.State -eq 'Running' -and [DateTime]::UtcNow -lt $deadline)
        if ($task.State -eq 'Running') { Stop-ScheduledTask -TaskName $taskName; throw "Probe timed out: $Command" }
        $result = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
        if (-not (Test-Path -LiteralPath $OutputPath)) { throw "Probe produced no result: $Command (task result $result)." }
        $report = Get-Content -Raw -LiteralPath $OutputPath | ConvertFrom-Json
        if ($ExpectFailure) {
            if ($result -eq 0 -or $report.passed) { throw "Probe unexpectedly succeeded: $Command" }
        }
        elseif ($result -ne 0 -or -not $report.passed) {
            throw "Probe failed: $Command (task result $result, error $($report.errorCode))."
        }
        return $report
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $plainPassword = $null
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Invoke-ScChecked {
    param([Parameter(Mandatory)] [string[]] $Arguments, [switch] $AllowNonZero)
    $output = & "$env:SystemRoot\System32\sc.exe" @Arguments 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0 -and -not $AllowNonZero) { throw "sc.exe failed ($code): $($Arguments -join ' ')" }
    return [pscustomobject]@{ ExitCode = $code; Output = @($output) }
}

function Wait-LiveMatrixService {
    param([ValidateSet('Running', 'Stopped')] [string] $Status, [int] $TimeoutSeconds = 30)
    $service = Get-Service -Name SecureIntegrationBroker -ErrorAction Stop
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::$Status, [TimeSpan]::FromSeconds($TimeoutSeconds))
    $service.Refresh()
    if ($service.Status.ToString() -ne $Status) { throw "SecureIntegrationBroker did not reach $Status." }
}

function Get-LiveMatrixServiceEvidence {
    $service = Get-CimInstance Win32_Service -Filter "Name='SecureIntegrationBroker'"
    if ($null -eq $service) { throw 'SecureIntegrationBroker is not installed.' }
    $process = if ($service.ProcessId -gt 0) { Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)" } else { $null }
    $owner = if ($null -ne $process) { Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid } else { $null }
    return [pscustomobject]@{
        Name = $service.Name
        State = $service.State
        StartMode = $service.StartMode
        StartName = $service.StartName
        PathName = $service.PathName
        ProcessId = [uint32]$service.ProcessId
        ProcessOwnerSid = if ($null -ne $owner) { [string]$owner.Sid } else { $null }
        ProcessCreationUtc = if ($null -ne $process) { $process.CreationDate.ToUniversalTime().ToString('o') } else { $null }
    }
}

function Assert-LiveMatrixServiceIdentity {
    param([Parameter(Mandatory)] $Evidence)
    $expectedName = 'NT SERVICE\SecureIntegrationBroker'
    $expectedSid = ([Security.Principal.NTAccount]::new($expectedName)).Translate([Security.Principal.SecurityIdentifier]).Value
    if (-not [string]::Equals([string]$Evidence.StartName, $expectedName, [StringComparison]::OrdinalIgnoreCase)) {
        throw "LIVE_MATRIX_WRONG_SERVICE_IDENTITY: StartName is $($Evidence.StartName)."
    }
    if (-not [string]::Equals([string]$Evidence.ProcessOwnerSid, $expectedSid, [StringComparison]::OrdinalIgnoreCase)) {
        throw "LIVE_MATRIX_WRONG_SERVICE_TOKEN: process SID is $($Evidence.ProcessOwnerSid), expected $expectedSid."
    }
    return $expectedSid
}

function Test-FileSystemAclExact {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string[]] $AllowedSid,
        [switch] $RequireProtected
    )

    $item = Get-Item -LiteralPath $Path -Force
    $security = if ($item.PSIsContainer) { [IO.Directory]::GetAccessControl($item.FullName) } else { [IO.File]::GetAccessControl($item.FullName) }
    if ($RequireProtected -and -not $security.AreAccessRulesProtected) { throw "LIVE_MATRIX_ACL_INHERITANCE_ENABLED: $Path" }
    $rules = @($security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $AllowedSid -notcontains $sid) {
            throw "LIVE_MATRIX_ACL_TOO_PERMISSIVE: $Path grants $sid."
        }
    }
    foreach ($expected in $AllowedSid) {
        $matching = @($rules | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -eq $expected })
        if ($matching.Count -eq 0) {
            throw "LIVE_MATRIX_ACL_MISSING_PRINCIPAL: $Path lacks $expected."
        }
        $combinedRights = [int64]0
        foreach ($rule in $matching) { $combinedRights = $combinedRights -bor [int64]$rule.FileSystemRights }
        $requiredRights = [int64][Security.AccessControl.FileSystemRights]::FullControl
        if (($combinedRights -band $requiredRights) -ne $requiredRights) { throw "LIVE_MATRIX_ACL_INSUFFICIENT_RIGHTS: $Path does not grant FullControl to $expected." }
    }
    return [pscustomobject]@{ Path = $item.FullName; Protected = $security.AreAccessRulesProtected; Sddl = $security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All) }
}

function Write-LiveMatrixJson {
    param([Parameter(Mandatory)] $Value, [Parameter(Mandatory)] [string] $Path, [int] $Depth = 12)
    $json = $Value | ConvertTo-Json -Depth $Depth
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}

function Get-LiveMatrixBootTimeUtc {
    return (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
}

Export-ModuleMember -Function Assert-LiveMatrixAdministrator, Get-LiveMatrixRepositoryRoot, Get-LiveMatrixPaths, Set-DirectoryAclExact, Get-WellKnownLiveMatrixSids, Get-LiveMatrixErrorCode, Test-LiveMatrixHarnessRuntime, Test-LiveMatrixBatchLogonRight, Grant-LiveMatrixBatchLogonRight, Revoke-LiveMatrixBatchLogonRight, Protect-LiveMatrixCredential, Unprotect-LiveMatrixCredential, New-LiveMatrixPassword, New-LiveMatrixRandomBytes, ConvertTo-LiveMatrixHex, Ensure-LiveMatrixLocalUser, Invoke-LiveMatrixScheduledProcess, Invoke-ScChecked, Wait-LiveMatrixService, Get-LiveMatrixServiceEvidence, Assert-LiveMatrixServiceIdentity, Test-FileSystemAclExact, Write-LiveMatrixJson, Get-LiveMatrixBootTimeUtc

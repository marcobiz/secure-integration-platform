[CmdletBinding()]
param(
    [ValidateSet('ValidateVm', 'Run', 'Cleanup')]
    [string] $Phase = 'ValidateVm',
    [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{5,39}$')] [string] $RunId,
    [string] $InputDirectory,
    [string] $OutputDirectory = ('C:\SecureEvidence\' + $RunId + '\vm-redacted'),
    [string] $RepositoryRoot = 'C:\Lab\broker-gateway'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'SecureIntegrationBroker'
$installRoot = Join-Path $env:ProgramFiles ('SecureIntegration\M3Split\' + $RunId)
$brokerRoot = Join-Path $installRoot 'Broker'
$legacyRoot = Join-Path $installRoot 'Legacy'
$unauthorizedRoot = Join-Path $installRoot 'UnauthorizedLegacy'
$runRoot = Join-Path $env:ProgramData ('SecureIntegration\M3Split\' + $RunId)
$brokerData = Join-Path $runRoot 'BrokerData'
$exchangeRoot = Join-Path $runRoot 'Exchange'
$statePath = Join-Path $runRoot 'vm-state.json'
$taskPrefix = 'SecureIntegration-M3A-' + $RunId + '-'
$rootThumbprint = $null
$createdUser = $null
$serviceCreated = $false
$ownedUserDescription = 'SIB M3A ' + $RunId

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'M3A_SPLIT_VM_REQUIRES_ELEVATION: open Windows PowerShell 5.1 as Administrator inside the VM.'
    }
}

function Write-JsonFile {
    param([Parameter(Mandatory)] $Value, [Parameter(Mandatory)] [string] $Path)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 16), [Text.UTF8Encoding]::new($false))
}

function Invoke-NativeChecked {
    param([Parameter(Mandatory)] [string] $FilePath, [Parameter(Mandatory)] [string[]] $Arguments)
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) { throw "M3A_SPLIT_VM_NATIVE_FAILED: $FilePath exited with $LASTEXITCODE." }
}

function Invoke-GitVmChecked {
    param(
        [Parameter(Mandatory)] [string[]] $Arguments,
        [Parameter(Mandatory)] [string] $ErrorCode,
        [switch] $CaptureOutput
    )
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $nativeOutput = @(& git.exe @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previousPreference }
    if ($exitCode -ne 0) { throw $ErrorCode }
    if ($CaptureOutput) { return ($nativeOutput -join [Environment]::NewLine) }
}

function New-VmEvidenceArchive {
    param(
        [Parameter(Mandatory)] [string] $Suffix,
        [Parameter(Mandatory)] $Result,
        [switch] $ResultOnly
    )
    $evidenceDirectory = if ($ResultOnly) { $OutputDirectory + '-failure' } else { $OutputDirectory }
    New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
    Write-JsonFile -Path (Join-Path $evidenceDirectory 'RESULT.json') -Value $Result
    $archiveName = $RunId + '-vm-redacted' + $Suffix + '.zip'
    $archivePath = Join-Path (Split-Path -Parent $OutputDirectory) $archiveName
    if (Test-Path -LiteralPath $archivePath) { throw 'M3A_SPLIT_VM_RESULT_ARCHIVE_EXISTS.' }
    Compress-Archive -Path (Join-Path $evidenceDirectory '*') -DestinationPath $archivePath -CompressionLevel Optimal
    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    [IO.File]::WriteAllText(($archivePath + '.sha256'), ($archiveHash + '  ' + $archiveName + [Environment]::NewLine), [Text.Encoding]::ASCII)
    return [pscustomobject]@{ Path = $archivePath; Hash = $archiveHash }
}

function Get-DotnetPath {
    $local = Join-Path $RepositoryRoot '.dotnet\dotnet.exe'
    if (Test-Path -LiteralPath $local) { return $local }
    return (Get-Command dotnet -ErrorAction Stop).Source
}

function Set-InstallAcl {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $ServiceSid,
        [Parameter(Mandatory)] [string] $LegacySid
    )
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $systemSid = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $adminSid = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $serviceIdentifier = [Security.Principal.SecurityIdentifier]::new($ServiceSid)
    $legacyIdentifier = [Security.Principal.SecurityIdentifier]::new($LegacySid)
    [void]$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($systemSid, 'FullControl', $inherit, 'None', 'Allow'))
    [void]$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($adminSid, 'FullControl', $inherit, 'None', 'Allow'))
    [void]$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($serviceIdentifier, 'ReadAndExecute', $inherit, 'None', 'Allow'))
    [void]$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($legacyIdentifier, 'ReadAndExecute', $inherit, 'None', 'Allow'))
    [IO.Directory]::SetAccessControl($Path, $security)
}

function Remove-OwnedM0M1ServiceCollision {
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    if ($null -eq $service) { return }

    $expectedInstall = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'SecureIntegration\LiveMatrix\Broker')).TrimEnd('\') + '\'
    $servicePath = [string]$service.PathName
    if ($servicePath.IndexOf($expectedInstall, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw 'M3A_SPLIT_VM_REFUSE_FOREIGN_SERVICE_COLLISION.'
    }

    $liveMatrixRoot = Join-Path $env:ProgramData 'SecureIntegration\LiveMatrix'
    $ownershipMarker = Join-Path $liveMatrixRoot 'harness-owned-service.marker'
    if (-not (Test-Path -LiteralPath $ownershipMarker)) { throw 'M3A_SPLIT_VM_M0_M1_OWNERSHIP_MARKER_MISSING.' }
    $ownerRunId = [IO.File]::ReadAllText($ownershipMarker).Trim()
    if ($ownerRunId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{5,39}$') { throw 'M3A_SPLIT_VM_M0_M1_OWNER_RUN_ID_INVALID.' }

    $cleanupScript = Join-Path $RepositoryRoot 'tools\live-matrix\Remove-LiveMatrix.ps1'
    if (-not (Test-Path -LiteralPath $cleanupScript)) { throw 'M3A_SPLIT_VM_M0_M1_CLEANUP_MISSING.' }
    & $cleanupScript -RunId $ownerRunId -Confirm:$false
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'M3A_SPLIT_VM_M0_M1_CLEANUP_INCOMPLETE.' }
}

function Invoke-SimulatorTask {
    param(
        [Parameter(Mandatory)] [pscredential] $Credential,
        [Parameter(Mandatory)] [string] $Executable,
        [Parameter(Mandatory)] [string] $OutputPath,
        [Parameter(Mandatory)] [string] $PipeName,
        [Parameter(Mandatory)] [string] $PayloadCanary
    )
    $taskName = $taskPrefix + [Guid]::NewGuid().ToString('N')
    $wrapper = Join-Path $exchangeRoot ($taskName + '.ps1')
    $script = @"
`$ErrorActionPreference = 'Stop'
`$env:M3_BROKER_PIPE_NAME = '$($PipeName.Replace("'", "''"))'
`$env:M3_APPLICATION_REGISTRATION_ID = 'm3-legacy-simulator'
`$env:M3_PAYLOAD_CANARY = '$($PayloadCanary.Replace("'", "''"))'
& '$($Executable.Replace("'", "''"))' --output '$($OutputPath.Replace("'", "''"))'
exit `$LASTEXITCODE
"@
    [IO.File]::WriteAllText($wrapper, $script, [Text.UTF8Encoding]::new($false))
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $wrapper + '"')
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
    $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -User $Credential.UserName -Password $password -RunLevel Limited -Force | Out-Null
        $registered = Get-ScheduledTask -TaskName $taskName
        if ($registered.Principal.RunLevel -ne 'Limited') { throw 'M3A_SPLIT_VM_TASK_NOT_LIMITED.' }
        Start-ScheduledTask -TaskName $taskName
        $deadline = [DateTime]::UtcNow.AddSeconds(90)
        do {
            Start-Sleep -Milliseconds 250
            $task = Get-ScheduledTask -TaskName $taskName
        } while ($task.State -eq 'Running' -and [DateTime]::UtcNow -lt $deadline)
        if ($task.State -eq 'Running') { Stop-ScheduledTask -TaskName $taskName; throw 'M3A_SPLIT_VM_SIMULATOR_TIMEOUT.' }
        $result = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
        if (-not (Test-Path -LiteralPath $OutputPath)) { throw "M3A_SPLIT_VM_SIMULATOR_NO_REPORT: task result $result." }
        return [ordered]@{ taskResult = [int64]$result; runLevel = 'Limited'; user = $Credential.UserName }
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $wrapper -Force -ErrorAction SilentlyContinue
        $password = $null
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Remove-VmResources {
    $state = if (Test-Path -LiteralPath $statePath) { Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } else { $null }
    Get-ScheduledTask -TaskName ($taskPrefix + '*') -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        $path = [string]$service.PathName
        if ($path.IndexOf($installRoot, [StringComparison]::OrdinalIgnoreCase) -lt 0) { throw 'M3A_SPLIT_VM_REFUSE_FOREIGN_SERVICE_REMOVAL.' }
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName | Out-Null
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }
    }
    $userName = if ($null -ne $state) { [string]$state.legacyUser } elseif ($null -ne $createdUser) { [string]$createdUser } else { $null }
    if ($userName) {
        $account = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
        if ($null -ne $account -and [string]$account.Description -eq $ownedUserDescription) {
            Revoke-LiveMatrixBatchLogonRight -Sid $account.Sid.Value
            Remove-LocalUser -Name $userName
        }
    }
    $thumbprint = if ($null -ne $state) { [string]$state.rootThumbprint } else { [string]$rootThumbprint }
    if ($thumbprint) { Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq $thumbprint | Remove-Item -Force }
    foreach ($path in $installRoot, $runRoot) {
        if (Test-Path -LiteralPath $path) {
            $resolved = [IO.Path]::GetFullPath($path)
            if ($resolved.IndexOf(('\SecureIntegration\M3Split\' + $RunId), [StringComparison]::OrdinalIgnoreCase) -lt 0) { throw 'M3A_SPLIT_VM_REFUSE_UNEXPECTED_PATH_REMOVAL.' }
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
    }
    return [ordered]@{
        status = if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -and @(Get-ScheduledTask -TaskName ($taskPrefix + '*') -ErrorAction SilentlyContinue).Count -eq 0) { 'PASS' } else { 'FAIL' }
        remainingServices = @(Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Count
        remainingTasks = @(Get-ScheduledTask -TaskName ($taskPrefix + '*') -ErrorAction SilentlyContinue).Count
        remainingUsers = if ($userName) { @(Get-LocalUser -Name $userName -ErrorAction SilentlyContinue).Count } else { 0 }
    }
}

Assert-Administrator
if ($Phase -eq 'ValidateVm') {
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.Caption.IndexOf('Windows 11', [StringComparison]::OrdinalIgnoreCase) -lt 0) { throw 'M3A_SPLIT_VM_REQUIRES_WINDOWS_11.' }
    if (-not (Test-Path -LiteralPath (Join-Path $RepositoryRoot '.git'))) { throw 'M3A_SPLIT_VM_REPOSITORY_MISSING.' }
    Get-Command git, dotnet, New-LocalUser, New-ScheduledTaskAction -ErrorAction Stop | Out-Null
    [pscustomobject]@{ phase = $Phase; runId = $RunId; status = 'PASS'; hostName = $env:COMPUTERNAME; os = $os.Caption; elevated = $true } | ConvertTo-Json -Compress
    exit 0
}
if ($Phase -eq 'Cleanup') {
    $cleanup = Remove-VmResources
    $cleanup | ConvertTo-Json -Depth 4
    if ($cleanup.status -ne 'PASS') { exit 1 }
    exit 0
}
if ([string]::IsNullOrWhiteSpace($InputDirectory) -or -not (Test-Path -LiteralPath $InputDirectory -PathType Container)) { throw 'M3A_SPLIT_VM_INPUT_REQUIRED.' }
$bootstrapPath = Join-Path $InputDirectory 'bootstrap.json'
$caPath = Join-Path $InputDirectory 'ca.crt'
if (-not (Test-Path -LiteralPath $bootstrapPath) -or -not (Test-Path -LiteralPath $caPath)) { throw 'M3A_SPLIT_VM_INPUT_INCOMPLETE.' }
$bootstrap = Get-Content -LiteralPath $bootstrapPath -Raw | ConvertFrom-Json
if ($bootstrap.runId -ne $RunId -or [string]$bootstrap.candidateCommit -notmatch '^[0-9a-f]{40}$') { throw 'M3A_SPLIT_VM_BOOTSTRAP_INVALID.' }
if ([string]$bootstrap.gatewayBaseAddress -match 'localhost|127\.0\.0\.1|\[::1\]') { throw 'M3A_SPLIT_VM_LOOPBACK_GATEWAY_FORBIDDEN.' }
$gatewayUri = [Uri]$bootstrap.gatewayBaseAddress
if (-not $gatewayUri.IsAbsoluteUri -or $gatewayUri.Scheme -ne 'https') { throw 'M3A_SPLIT_VM_GATEWAY_MUST_BE_HTTPS.' }
$safeRepository = $RepositoryRoot.Replace('\', '/')
$gitPrefix = @('-c', ('safe.directory=' + $safeRepository), '-C', $RepositoryRoot)
$worktree = (Invoke-GitVmChecked -Arguments ($gitPrefix + @('status', '--porcelain')) -ErrorCode 'M3A_SPLIT_VM_GIT_STATUS_FAILED.' -CaptureOutput).Trim()
if ($worktree) { throw 'M3A_SPLIT_VM_WORKTREE_NOT_CLEAN.' }
$candidateCommit = [string]$bootstrap.candidateCommit
$candidatePresent = $true
try { [void](Invoke-GitVmChecked -Arguments ($gitPrefix + @('cat-file', '-e', ($candidateCommit + '^{commit}'))) -ErrorCode 'M3A_SPLIT_VM_COMMIT_MISSING.') }
catch { $candidatePresent = $false }
if (-not $candidatePresent) {
    [void](Invoke-GitVmChecked -Arguments ($gitPrefix + @('fetch', '--prune', 'origin')) -ErrorCode 'M3A_SPLIT_VM_FETCH_FAILED.')
    [void](Invoke-GitVmChecked -Arguments ($gitPrefix + @('cat-file', '-e', ($candidateCommit + '^{commit}'))) -ErrorCode 'M3A_SPLIT_VM_COMMIT_MISSING.')
}
$head = (Invoke-GitVmChecked -Arguments ($gitPrefix + @('rev-parse', 'HEAD')) -ErrorCode 'M3A_SPLIT_VM_HEAD_READ_FAILED.' -CaptureOutput).Trim()
if ($head -ne $candidateCommit) {
    [void](Invoke-GitVmChecked -Arguments ($gitPrefix + @('switch', '--detach', $candidateCommit)) -ErrorCode 'M3A_SPLIT_VM_SWITCH_FAILED.')
    $head = (Invoke-GitVmChecked -Arguments ($gitPrefix + @('rev-parse', 'HEAD')) -ErrorCode 'M3A_SPLIT_VM_HEAD_READ_FAILED.' -CaptureOutput).Trim()
}
if ($head -ne [string]$bootstrap.candidateCommit) { throw 'M3A_SPLIT_VM_HEAD_MISMATCH.' }
[void](Invoke-GitVmChecked -Arguments ($gitPrefix + @('merge-base', '--is-ancestor', 'm2-gateway-baseline-2026-08-04', $head)) -ErrorCode 'M3A_SPLIT_VM_M2_BASELINE_MISSING.')
Remove-OwnedM0M1ServiceCollision
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'M3A_SPLIT_VM_SERVICE_COLLISION.' }
if (Test-Path -LiteralPath $OutputDirectory) { throw 'M3A_SPLIT_VM_OUTPUT_ALREADY_EXISTS.' }

$success = $false
$failure = $null
$manifestBase = $null
try {
New-Item -ItemType Directory -Path $brokerRoot, $legacyRoot, $unauthorizedRoot, $exchangeRoot, $OutputDirectory -Force | Out-Null
$modulePath = Join-Path $RepositoryRoot 'tools\live-matrix\LiveMatrix.Common.psm1'
Import-Module $modulePath -Force -DisableNameChecking
$dotnet = Get-DotnetPath
$brokerProject = Join-Path $RepositoryRoot 'src\Broker\Broker.Service\Broker.Service.csproj'
$legacyProject = Join-Path $RepositoryRoot 'tools\m3\LegacySimulator\LegacySimulator.csproj'
Invoke-NativeChecked -FilePath $dotnet -Arguments @('restore', $brokerProject, '--runtime', 'win-x64', '-p:NuGetLockFilePath=obj\m3-split.win-x64.packages.lock.json')
Invoke-NativeChecked -FilePath $dotnet -Arguments @('restore', $legacyProject, '--runtime', 'win-x64', '-p:NuGetLockFilePath=obj\m3-split.win-x64.packages.lock.json')
Invoke-NativeChecked -FilePath $dotnet -Arguments @('publish', $brokerProject, '-c', 'Release', '--no-restore', '-r', 'win-x64', '--self-contained', 'false', '-o', $brokerRoot)
Invoke-NativeChecked -FilePath $dotnet -Arguments @('publish', $legacyProject, '-c', 'Release', '--no-restore', '-r', 'win-x64', '--self-contained', 'false', '-o', $legacyRoot)
Copy-Item -Path (Join-Path $legacyRoot '*') -Destination $unauthorizedRoot -Recurse -Force
$legacyExecutable = Join-Path $legacyRoot 'SecureIntegration.M3.LegacySimulator.exe'
$unauthorizedExecutable = Join-Path $unauthorizedRoot 'SecureIntegration.M3.LegacySimulator.exe'
$legacyHash = (Get-FileHash -LiteralPath $legacyExecutable -Algorithm SHA256).Hash
$runIdToken = $RunId -replace '[^A-Za-z0-9]', ''
$suffixLength = [Math]::Min(8, $runIdToken.Length)
$userName = 'M3Legacy' + $runIdToken.Substring($runIdToken.Length - $suffixLength, $suffixLength)
$createdUser = $userName
$credentialPath = Join-Path $runRoot 'legacy-user.credential.dpapi'
$legacyUser = Ensure-LiveMatrixLocalUser -Name $userName -CredentialPath $credentialPath -Description $ownedUserDescription
Grant-LiveMatrixBatchLogonRight -Sid $legacyUser.Sid
if (-not (Test-LiveMatrixBatchLogonRight -Sid $legacyUser.Sid)) { throw 'M3A_SPLIT_VM_LEGACY_BATCH_LOGON_RIGHT_MISSING.' }
$adminMembers = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
if ($adminMembers -contains $legacyUser.Sid) { throw 'M3A_SPLIT_VM_LEGACY_USER_IS_ADMIN.' }
$wellKnown = Get-WellKnownLiveMatrixSids
Set-DirectoryAclExact -Path $exchangeRoot -Sid @($wellKnown.System, $wellKnown.Administrators, $legacyUser.Sid) -Rights Modify
$pipeName = 'SecureIntegration.Broker.M3.Split.' + ($RunId -replace '[^A-Za-z0-9.-]', '-')
$configuration = [ordered]@{
    Broker = [ordered]@{
        PipeName = $pipeName; InstallationId = [string]$bootstrap.installationId; DataDirectory = $brokerData
        Gateway = [ordered]@{
            Enabled = $true; BaseAddress = [string]$bootstrap.gatewayBaseAddress; ActivationCodeId = [string]$bootstrap.activationCodeId
            ActivationCodeEnvironmentVariable = 'BROKER_GATEWAY_ACTIVATION_CODE'; CngKeyName = ('SecureIntegration.Broker.M3.Split.' + $RunId)
            BrokerVersion = '3.0.0'; TimeoutSeconds = 45
        }
        Applications = @([ordered]@{
            RegistrationId = 'm3-legacy-simulator'; AllowedUserSids = @($legacyUser.Sid); ExecutablePaths = @($legacyExecutable)
            ExecutableSha256 = @($legacyHash); AllowedPublisherThumbprints = @(); AllowedOperations = @('InvokeGateway'); GatewayGrants = @('m3-vendor:submit')
        })
    }
    Logging = [ordered]@{
        LogLevel = [ordered]@{ Default = 'Information'; Microsoft = 'Warning'; 'Microsoft.Hosting.Lifetime' = 'Information' }
        EventLog = [ordered]@{ LogName = 'Application'; SourceName = 'SecureIntegrationBroker'; LogLevel = [ordered]@{ Default = 'Information' } }
    }
}
Write-JsonFile -Path (Join-Path $brokerRoot 'appsettings.json') -Value $configuration
if (-not [Diagnostics.EventLog]::SourceExists('SecureIntegrationBroker')) { New-EventLog -LogName Application -Source SecureIntegrationBroker }
$serviceExecutable = Join-Path $brokerRoot 'SecureIntegration.Broker.Service.exe'
Invoke-NativeChecked -FilePath 'sc.exe' -Arguments @('create', $serviceName, 'binPath=', ('"' + $serviceExecutable + '"'), 'start=', 'demand', 'obj=', ('NT SERVICE\' + $serviceName))
$serviceCreated = $true
Invoke-NativeChecked -FilePath 'sc.exe' -Arguments @('sidtype', $serviceName, 'unrestricted')
$serviceSid = ([Security.Principal.NTAccount]::new('NT SERVICE\SecureIntegrationBroker')).Translate([Security.Principal.SecurityIdentifier]).Value
Set-InstallAcl -Path $installRoot -ServiceSid $serviceSid -LegacySid $legacyUser.Sid
$installedRoot = Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\LocalMachine\Root
$rootThumbprint = $installedRoot.Thumbprint
$serviceRegistry = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $serviceName
New-ItemProperty -Path $serviceRegistry -Name Environment -PropertyType MultiString -Value @(('BROKER_GATEWAY_ACTIVATION_CODE=' + [string]$bootstrap.activationCode)) -Force | Out-Null
Write-JsonFile -Path $statePath -Value ([ordered]@{ runId = $RunId; legacyUser = $userName; rootThumbprint = $rootThumbprint; installRoot = $installRoot })
$startedAt = Get-Date
    Start-Service -Name $serviceName
    Wait-LiveMatrixService -Status Running -TimeoutSeconds 60
    Start-Sleep -Seconds 2
    $serviceEvidence = Get-LiveMatrixServiceEvidence
    $actualServiceSid = Assert-LiveMatrixServiceIdentity -Evidence $serviceEvidence
    if ($actualServiceSid -ne $serviceSid) { throw 'M3A_SPLIT_VM_SERVICE_SID_MISMATCH.' }
    $dataAcl = Test-FileSystemAclExact -Path $brokerData -AllowedSid @($serviceSid, $wellKnown.System, $wellKnown.Administrators) -RequireProtected
    $installAcl = [IO.Directory]::GetAccessControl($installRoot).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
    $legacyOutput = Join-Path $exchangeRoot 'legacy-simulator.json'
    $positiveTask = Invoke-SimulatorTask -Credential $legacyUser.Credential -Executable $legacyExecutable -OutputPath $legacyOutput -PipeName $pipeName -PayloadCanary ([string]$bootstrap.payloadCanary)
    $legacyReport = Get-Content -LiteralPath $legacyOutput -Raw | ConvertFrom-Json
    if ($positiveTask.taskResult -ne 0 -or -not $legacyReport.passed) { throw 'M3A_SPLIT_VM_P02_FAILED.' }
    Remove-ItemProperty -Path $serviceRegistry -Name Environment -ErrorAction Stop
    Remove-Item -LiteralPath $bootstrapPath -Force
    $unauthorizedOutput = Join-Path $exchangeRoot 'unauthorized-simulator.json'
    $negativeTask = Invoke-SimulatorTask -Credential $legacyUser.Credential -Executable $unauthorizedExecutable -OutputPath $unauthorizedOutput -PipeName $pipeName -PayloadCanary ([string]$bootstrap.payloadCanary)
    $unauthorizedReport = Get-Content -LiteralPath $unauthorizedOutput -Raw | ConvertFrom-Json
    if ($negativeTask.taskResult -eq 0 -or $unauthorizedReport.passed) { throw 'M3A_SPLIT_VM_UNAUTHORIZED_APP_SUCCEEDED.' }
    Start-Sleep -Seconds 2
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'SecureIntegrationBroker'; StartTime = $startedAt } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, Message)
    $eventText = $events | ConvertTo-Json -Depth 5
    if ($eventText -notmatch 'application_not_authorized') { throw 'M3A_SPLIT_VM_UNAUTHORIZED_DENIAL_NOT_AUDITED.' }
    foreach ($content in @((Get-Content -LiteralPath $legacyOutput -Raw), (Get-Content -LiteralPath $unauthorizedOutput -Raw), $eventText)) {
        if ($content.IndexOf([string]$bootstrap.payloadCanary, [StringComparison]::Ordinal) -ge 0 -or $content.IndexOf([string]$bootstrap.activationCode, [StringComparison]::Ordinal) -ge 0) {
            throw 'M3A_SPLIT_VM_CANARY_FOUND.'
        }
    }
    Copy-Item -LiteralPath $legacyOutput -Destination (Join-Path $OutputDirectory 'legacy-simulator.json')
    Write-JsonFile -Path (Join-Path $OutputDirectory 'unauthorized-application.json') -Value ([ordered]@{ scenario = 'M3-N-LOCAL-UNAUTHORIZED'; status = 'PASS'; userSid = $legacyUser.Sid; executableHash = (Get-FileHash -LiteralPath $unauthorizedExecutable -Algorithm SHA256).Hash; reason = 'path-policy-denied' })
    Write-JsonFile -Path (Join-Path $OutputDirectory 'broker-events-redacted.json') -Value $events
    $manifestBase = [ordered]@{
        schemaVersion = 1; environment = 'M3A-SPLIT-VM'; runId = $RunId; commitSha = $head; hostName = $env:COMPUTERNAME
        status = 'PASS'; brokerService = $serviceEvidence; brokerSid = $serviceSid
        legacyIdentity = [ordered]@{ user = $userName; sid = $legacyUser.Sid; standardUser = $true; taskRunLevel = $positiveTask.runLevel; batchLogonRight = $true }
        brokerStorageAclSddl = $dataAcl.Sddl; brokerInstallAclSddl = $installAcl
        scenarios = @(
            [ordered]@{ id = 'M3-P02'; status = 'PASS'; path = 'Legacy Simulator -> SDK -> Windows Service -> HOST Gateway' },
            [ordered]@{ id = 'M3-N06'; status = 'PASS'; path = 'Legacy Simulator -> Broker operation grant denial' },
            [ordered]@{ id = 'M3-N-LOCAL-UNAUTHORIZED'; status = 'PASS'; path = 'same user, unregistered executable path' }
        )
        canaryScan = 'PASS'; directBackendEndpointsDistributed = $false; vendorSecretDistributed = $false
    }
    $success = $true
}
catch {
    $failure = $_
}
finally {
    Remove-Item -LiteralPath $bootstrapPath -Force -ErrorAction SilentlyContinue
    try { $cleanup = Remove-VmResources } catch { $cleanup = [ordered]@{ status = 'FAIL'; remainingServices = -1; remainingTasks = -1; detail = $_.Exception.Message } }
}
if (-not $success -or $cleanup.status -ne 'PASS') {
    $errorCode = if ($null -ne $failure -and [string]$failure.Exception.Message -match '^(M3A_[A-Z0-9_]+)') { $Matches[1] } elseif ($null -ne $failure) { $failure.Exception.GetType().Name } else { 'M3A_SPLIT_VM_CLEANUP_FAILED' }
    $failureResult = [ordered]@{
        schemaVersion = 1
        environment = 'M3A-SPLIT-VM'
        runId = $RunId
        commitSha = $head
        status = 'BLOCKED'
        classification = 'VM_RUN_FAILED'
        errorCode = $errorCode
        cleanup = [ordered]@{
            status = [string]$cleanup.status
            remainingServices = if ($cleanup.Contains('remainingServices')) { [int]$cleanup.remainingServices } else { -1 }
            remainingTasks = if ($cleanup.Contains('remainingTasks')) { [int]$cleanup.remainingTasks } else { -1 }
        }
        completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    }
    [void](New-VmEvidenceArchive -Suffix '-failure' -Result $failureResult -ResultOnly)
    if ($null -ne $failure) { throw $failure }
    throw 'M3A_SPLIT_VM_CLEANUP_FAILED.'
}
$manifestBase['cleanup'] = $cleanup
$manifestBase['completedAtUtc'] = [DateTimeOffset]::UtcNow.ToString('O')
Write-JsonFile -Path (Join-Path $OutputDirectory 'vm-manifest.json') -Value $manifestBase
$successResult = [ordered]@{
    schemaVersion = 1
    environment = 'M3A-SPLIT-VM'
    runId = $RunId
    commitSha = $head
    status = 'PASS'
    classification = 'COMPLETED'
    cleanup = $cleanup
    completedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
}
$archive = New-VmEvidenceArchive -Suffix '' -Result $successResult
[pscustomobject]@{ runId = $RunId; status = 'PASS'; commit = $head; evidence = $archive.Path; sha256 = $archive.Hash; cleanup = $cleanup } | ConvertTo-Json -Depth 7 -Compress

# Windows PowerShell 5.1. Uses published binaries; no SDK is needed on the runtime host.
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Start', 'Stop', 'Update', 'Verify')] [string] $Command = 'Start',
    [ValidatePattern('^[a-zA-Z0-9-]{1,40}$')] [string] $Instance = 'sample',
    [string] $BrokerPublishDirectory = (Join-Path $PSScriptRoot 'broker'),
    [string] $SamplePublishDirectory = (Join-Path $PSScriptRoot 'sample'),
    [string] $ApplicationUserSid
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'LOCAL_BROKER_ADMIN_REQUIRED: service lifecycle requires an elevated Windows PowerShell.'
}
$name = 'SecureIntegrationBroker.Local.' + $Instance
$root = Join-Path $env:ProgramFiles ('SecureIntegration\LocalBroker\' + $Instance)
$data = Join-Path $env:ProgramData ('SecureIntegration\LocalBroker\' + $Instance)
$brokerDirectory = Join-Path $root 'broker'
$sampleDirectory = Join-Path $root 'sample'
$executable = Join-Path $brokerDirectory 'SecureIntegration.Broker.Service.exe'
$sample = Join-Path $sampleDirectory 'SecureIntegration.Samples.LocalBroker.exe'
$binaryPath = '"' + $executable + '" --contentRoot "' + $brokerDirectory + '"'
$marker = Join-Path $root 'installation.json'
$settingsPath = Join-Path $brokerDirectory 'appsettings.json'

function Assert-NoReparse([string] $Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'LOCAL_BROKER_REPARSE_PATH_DENIED'
        }
        $parent = Split-Path -Parent $cursor
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}
function Get-OwnedService {
    Assert-NoReparse $root
    Assert-NoReparse $data
    $service = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if (-not (Test-Path -LiteralPath $marker)) {
        if ($service -or (Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath $data)) { throw 'LOCAL_BROKER_OWNERSHIP_UNCERTAIN: existing resources preserved.' }
        return $null
    }
    Assert-NoReparse $marker
    $record = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
    if ($record.service -cne $name -or $record.root -cne $root -or $record.data -cne $data -or $record.binaryPath -cne $binaryPath) {
        throw 'LOCAL_BROKER_OWNERSHIP_UNCERTAIN: installation marker does not match.'
    }
    if ($service -and ($service.PathName -cne $binaryPath -or $service.StartName -ine ('NT SERVICE\' + $name))) {
        throw 'LOCAL_BROKER_FOREIGN_SERVICE: service preserved.'
    }
    return $service
}
function Invoke-ServiceAction([string] $Action) {
    if ($Action -eq 'Create') {
        # CIM preserves the exact quoted image path under Windows PowerShell 5.1 as well as PowerShell 7.
        $result = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
            Name = $name; DisplayName = $name; PathName = $binaryPath; ServiceType = [byte]16;
            ErrorControl = [byte]1; StartMode = 'Manual'; DesktopInteract = $false; StartName = 'NT SERVICE\' + $name
        }
    }
    else {
        $target = Get-OwnedService
        if (-not $target) { throw 'LOCAL_BROKER_SERVICE_ABSENT' }
        $method = switch ($Action) { 'Start' { 'StartService' }; 'Stop' { 'StopService' }; 'Delete' { 'Delete' }; default { throw 'LOCAL_BROKER_INVALID_ACTION' } }
        $result = Invoke-CimMethod -InputObject $target -MethodName $method
    }
    if ($result.ReturnValue -ne 0) { throw ('LOCAL_BROKER_SERVICE_ACTION_FAILED: ' + $Action + ' result ' + $result.ReturnValue) }
}
function Set-DirectoryRights([string] $Path, [string] $ServiceSid, [bool] $PublicRead) {
    Assert-NoReparse $Path
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544', $ServiceSid)) {
        $rights = if ($PublicRead -and $sid -eq $ServiceSid -and $sid -like 'S-1-5-80-*') { 'ReadAndExecute' } else { 'FullControl' }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), $rights, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    if ($PublicRead) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')) }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Copy-Published([string] $Source, [string] $Destination) {
    if (-not $Source -or -not (Test-Path -LiteralPath $Source -PathType Container)) { throw 'LOCAL_BROKER_PUBLISH_DIRECTORY_REQUIRED' }
    Assert-NoReparse $Source
    Assert-NoReparse $Destination
    $sourceRoot = (Resolve-Path -LiteralPath $Source).Path.TrimEnd('\')
    foreach ($file in Get-ChildItem -LiteralPath $sourceRoot -Recurse -Force) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'LOCAL_BROKER_REPARSE_PATH_DENIED' }
        $relative = $file.FullName.Substring($sourceRoot.Length + 1)
        $target = Join-Path $Destination $relative
        Assert-NoReparse $target
        if ($file.PSIsContainer) { New-Item -ItemType Directory -Path $target -Force | Out-Null }
        elseif ($file.Name -notlike 'appsettings*.json') { Copy-Item -LiteralPath $file.FullName -Destination $target -Force }
    }
}
function Write-Settings($Value) {
    Assert-NoReparse $settingsPath
    [IO.File]::WriteAllText($settingsPath, ($Value | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
}
function Get-ApplicationUserSid {
    if ([string]::IsNullOrWhiteSpace($ApplicationUserSid)) {
        throw 'LOCAL_BROKER_APPLICATION_SID_REQUIRED: pass the SID of the application user, not implicitly the setup administrator.'
    }
    try {
        $sid = [Security.Principal.SecurityIdentifier]::new($ApplicationUserSid)
        if (-not $sid.IsAccountSid()) { throw 'Not an account SID.' }
        $null = $sid.Translate([Security.Principal.NTAccount])
        return $sid.Value
    }
    catch { throw 'LOCAL_BROKER_APPLICATION_SID_INVALID: use an existing Windows account SID.' }
}
function Invoke-Sample([string] $Action, [string] $Envelope, [string] $Application = 'local-sample') {
    & $sample $Action $name $name $Application $Envelope
    if ($LASTEXITCODE -ne 0) { throw 'LOCAL_BROKER_SAMPLE_FAILED: inspect the bounded error code.' }
}

if ($Command -eq 'Verify') {
    # Qualification uses the same installer/lifecycle, not a separate service implementation.
    if ((Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath $data) -or (Get-CimInstance Win32_Service -Filter "Name='$name'")) {
        throw 'LOCAL_BROKER_VERIFY_REQUIRES_FRESH_INSTANCE: choose a new Instance; existing state is preserved.'
    }
    $started = [Diagnostics.Stopwatch]::StartNew()
    $envelope = Join-Path $env:TEMP ($name + '.envelope')
    if (Test-Path -LiteralPath $envelope) { throw 'LOCAL_BROKER_VERIFY_ENVELOPE_COLLISION' }
    try {
        & $PSCommandPath -Command Install -Instance $Instance -BrokerPublishDirectory $BrokerPublishDirectory -SamplePublishDirectory $SamplePublishDirectory -ApplicationUserSid $identity.User.Value
        & $PSCommandPath -Command Start -Instance $Instance
        Invoke-Sample 'protect' $envelope
        Write-Output ('FIRST_PROTECT_MS=' + $started.ElapsedMilliseconds)
        $stateHashes = @(Get-ChildItem -LiteralPath (Join-Path $data 'keys') -File | Sort-Object Name | Get-FileHash -Algorithm SHA256 | Select-Object -ExpandProperty Hash)
        $acl = (Get-Acl -LiteralPath $data).Sddl
        $installationHash = (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash
        & $PSCommandPath -Command Stop -Instance $Instance
        & $PSCommandPath -Command Stop -Instance $Instance
        & $PSCommandPath -Command Start -Instance $Instance
        Invoke-Sample 'verify' $envelope
        Invoke-Sample 'denied' $envelope 'unregistered-app'
        # The same registration from the unstaged executable must fail process/path authorization.
        & (Join-Path $SamplePublishDirectory 'SecureIntegration.Samples.LocalBroker.exe') 'denied' $name $name 'local-sample' '-'
        if ($LASTEXITCODE -ne 0) { throw 'LOCAL_BROKER_UNAUTHORIZED_PROCESS_TEST_FAILED' }
        & $PSCommandPath -Command Update -Instance $Instance -BrokerPublishDirectory $BrokerPublishDirectory -SamplePublishDirectory $SamplePublishDirectory
        Invoke-Sample 'verify' $envelope
        $after = @(Get-ChildItem -LiteralPath (Join-Path $data 'keys') -File | Sort-Object Name | Get-FileHash -Algorithm SHA256 | Select-Object -ExpandProperty Hash)
        if (($stateHashes -join ',') -cne ($after -join ',') -or $acl -cne (Get-Acl -LiteralPath $data).Sddl -or
            $installationHash -cne (Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash) { throw 'LOCAL_BROKER_STATE_CHANGED' }
        Write-Output 'REAL_WINDOWS_SERVICE_RESTART_UPDATE=PASS'
    }
    finally {
        # Only remove the exact owned service registration; retain protected state for same-profile recovery.
        $owned = Get-OwnedService
        if ($owned) {
            & $PSCommandPath -Command Stop -Instance $Instance
            $owned = Get-OwnedService
            if ($owned) { Invoke-ServiceAction 'Delete' }
        }
        Write-Output 'CLEANUP=PERSISTENT_STATE_PRESERVED'
    }
    return
}

$owned = Get-OwnedService
if ($Command -eq 'Stop') {
    if ($owned -and $owned.State -ne 'Stopped') {
        Invoke-ServiceAction 'Stop'
        (Get-Service -Name $name).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    Write-Output 'STOP=COMPLETE DATA=PRESERVED'
    return
}
if ($Command -eq 'Install') {
    if (-not $BrokerPublishDirectory -or -not $SamplePublishDirectory) { throw 'LOCAL_BROKER_PUBLISH_DIRECTORY_REQUIRED' }
    if (-not (Test-Path -LiteralPath (Join-Path $BrokerPublishDirectory 'SecureIntegration.Broker.Service.exe')) -or
        -not (Test-Path -LiteralPath (Join-Path $SamplePublishDirectory 'SecureIntegration.Samples.LocalBroker.exe'))) { throw 'LOCAL_BROKER_PUBLISHED_APPHOST_REQUIRED' }
    if (Test-Path -LiteralPath $marker) {
        $record = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
        if ($owned -and (Test-Path -LiteralPath $settingsPath) -and (Test-Path -LiteralPath $sample) -and (Test-Path -LiteralPath $executable)) {
            Write-Output 'INSTALL=EXISTS NEXT=START_OR_UPDATE'; return
        }
        if ((Test-Path -LiteralPath $data) -and @(Get-ChildItem -LiteralPath $data -Recurse -File).Count -ne 0) {
            throw 'LOCAL_BROKER_PARTIAL_WITH_DATA: preserve and restore the existing installation; initialization is not recovery.'
        }
    }
    else {
        $ApplicationUserSid = Get-ApplicationUserSid
        if ([Diagnostics.EventLog]::SourceExists($name)) { throw 'LOCAL_BROKER_FOREIGN_EVENT_SOURCE: choose a fresh Instance.' }
        # Claim fresh directories before SCM creation, so partial installation is recognizable.
        Set-DirectoryRights $root 'S-1-5-18' $true
        $record = [ordered]@{ service = $name; root = $root; data = $data; binaryPath = $binaryPath; installationId = [guid]::NewGuid().ToString('D') }
        [IO.File]::WriteAllText($marker, ($record | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    }
    $ApplicationUserSid = Get-ApplicationUserSid
    if (-not $owned) { Invoke-ServiceAction 'Create' }
    $serviceSid = ([Security.Principal.NTAccount]::new('NT SERVICE', $name)).Translate([Security.Principal.SecurityIdentifier]).Value
    Set-DirectoryRights $root $serviceSid $true
    Set-DirectoryRights $data $serviceSid $false
    New-Item -ItemType Directory -Path $brokerDirectory, $sampleDirectory -Force | Out-Null
    Copy-Published $BrokerPublishDirectory $brokerDirectory
    Copy-Published $SamplePublishDirectory $sampleDirectory
    $settings = @{ Broker = @{ ServiceName = $name; PipeName = $name; InstallationId = $record.installationId; DataDirectory = $data; InitializeDataKeys = $true; Gateway = @{ Enabled = $false }; Applications = @(@{
        RegistrationId = 'local-sample'; AllowedUserSids = @($ApplicationUserSid); ExecutablePaths = @($sample); ExecutableSha256 = @((Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash); AllowedOperations = @('ProtectData', 'UnprotectData', 'GetBrokerStatus')
        AllowedDataProtectionContexts = @(@{ Purpose = 'sample'; ContentType = 'text/plain' })
    }) } }
    Write-Settings $settings
    if (-not [Diagnostics.EventLog]::SourceExists($name)) { New-EventLog -LogName Application -Source $name }
    Write-Output 'INSTALL=COMPLETE NEXT=START'
    return
}
if (-not $owned) { throw 'LOCAL_BROKER_SERVICE_ABSENT: install a fresh instance or restore the existing installation; do not reinitialize data.' }
if ($Command -eq 'Update') {
    & $PSCommandPath -Command Stop -Instance $Instance
    # A failed copy must never leave first-install initialization enabled.
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    $settings.Broker.InitializeDataKeys = $false
    Write-Settings $settings
    Copy-Published $BrokerPublishDirectory $brokerDirectory
    Copy-Published $SamplePublishDirectory $sampleDirectory
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    $settings.Broker.InitializeDataKeys = $false
    $settings.Broker.Applications[0].ExecutableSha256 = @((Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash)
    Write-Settings $settings
}
if ($owned.State -ne 'Running' -or $Command -eq 'Update') { Invoke-ServiceAction 'Start' }
(Get-Service -Name $name).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
$settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
if ($settings.Broker.InitializeDataKeys) {
    $settings.Broker.InitializeDataKeys = $false
    Write-Settings $settings
}
# SCM readiness is not an application authorization probe. The setup administrator
# need not be authorized to invoke; run the shipped sample under the registered user.
Write-Output 'START=RUNNING NEXT=APPLICATION_STATUS'

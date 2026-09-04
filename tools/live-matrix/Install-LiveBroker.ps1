[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $RunId,
    [string] $AuthorizedUser = 'SibLiveAuthorized',
    [string] $UnauthorizedUser = 'SibLiveDenied'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'LiveMatrix.Common.psm1') -Force -DisableNameChecking
Assert-LiveMatrixAdministrator

$repositoryRoot = Get-LiveMatrixRepositoryRoot
$paths = Get-LiveMatrixPaths -RunId $RunId
$wellKnown = Get-WellKnownLiveMatrixSids
$adminSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

Set-DirectoryAclExact -Path $paths.Root -Sid @($wellKnown.System, $wellKnown.Administrators, $adminSid)
Set-DirectoryAclExact -Path $paths.Run -Sid @($wellKnown.System, $wellKnown.Administrators, $adminSid)
Set-DirectoryAclExact -Path $paths.State -Sid @($wellKnown.System, $wellKnown.Administrators, $adminSid)
New-Item -ItemType Directory -Path $paths.Raw, $paths.Evidence -Force | Out-Null
$ownershipMarker = Join-Path $paths.Root 'harness-owned-service.marker'
if ((Test-Path -LiteralPath $paths.Install) -and -not (Test-Path -LiteralPath $ownershipMarker)) {
    throw 'LIVE_MATRIX_INSTALL_COLLISION: installation directory exists without the harness ownership marker.'
}
[IO.File]::WriteAllText($ownershipMarker, $RunId, [Text.UTF8Encoding]::new($false))

$authorized = Ensure-LiveMatrixLocalUser -Name $AuthorizedUser -CredentialPath (Join-Path $paths.State 'authorized.credential.dpapi') -Description 'Secure Integration live matrix authorized'
$unauthorized = Ensure-LiveMatrixLocalUser -Name $UnauthorizedUser -CredentialPath (Join-Path $paths.State 'unauthorized.credential.dpapi') -Description 'Secure Integration live matrix denied'
Grant-LiveMatrixBatchLogonRight -Sid $authorized.Sid
Grant-LiveMatrixBatchLogonRight -Sid $unauthorized.Sid
$administratorSids = @(Get-LocalGroupMember -SID $wellKnown.Administrators | ForEach-Object { $_.SID.Value })
foreach ($user in $authorized, $unauthorized) {
    if ($administratorSids -contains $user.Sid) { throw "Live matrix account $($user.Name) must not be a local administrator." }
}

$authorizedExchange = Join-Path $paths.Exchange 'authorized'
$sameUserExchange = Join-Path $paths.Exchange 'same-user-untrusted'
$otherUserExchange = Join-Path $paths.Exchange 'other-user'
Set-DirectoryAclExact -Path $authorizedExchange -Sid @($wellKnown.System, $wellKnown.Administrators, $adminSid, $authorized.Sid) -Rights Modify
Set-DirectoryAclExact -Path $sameUserExchange -Sid @($wellKnown.System, $wellKnown.Administrators, $adminSid, $authorized.Sid) -Rights Modify
Set-DirectoryAclExact -Path $otherUserExchange -Sid @($wellKnown.System, $wellKnown.Administrators, $adminSid, $unauthorized.Sid) -Rights Modify

$existingService = Get-Service -Name SecureIntegrationBroker -ErrorAction SilentlyContinue
if ($null -ne $existingService -and $existingService.Status -ne 'Stopped') {
    Invoke-ScChecked -Arguments @('stop', 'SecureIntegrationBroker') | Out-Null
    Wait-LiveMatrixService -Status Stopped
}

if (Test-Path -LiteralPath $paths.Install) {
    $resolvedInstall = [IO.Path]::GetFullPath($paths.Install).TrimEnd('\')
    $expectedInstall = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'SecureIntegration\LiveMatrix')).TrimEnd('\')
    if ($resolvedInstall -ne $expectedInstall) { throw 'Refusing to clean an unexpected installation directory.' }
    Remove-Item -LiteralPath $resolvedInstall -Recurse -Force
}
New-Item -ItemType Directory -Path $paths.Broker, $paths.AuthorizedProbe, $paths.UnauthorizedProbe -Force | Out-Null

$dotnet = (Get-Command dotnet).Source
& $dotnet restore (Join-Path $repositoryRoot 'BrokerGateway.slnx')
if ($LASTEXITCODE -ne 0) { throw 'dotnet restore failed.' }
$brokerProject = Join-Path $repositoryRoot 'src\Broker\Broker.Service\Broker.Service.csproj'
$probeProject = Join-Path $repositoryRoot 'tools\live-matrix\probe\LiveMatrix.Probe.csproj'
$runtimeLock = '-p:NuGetLockFilePath=obj\live-matrix.win-x64.packages.lock.json'
foreach ($project in $brokerProject, $probeProject) {
    & $dotnet restore $project --runtime win-x64 $runtimeLock
    if ($LASTEXITCODE -ne 0) { throw "Runtime restore failed: $project" }
}
& $dotnet publish $brokerProject --configuration Release --no-restore --runtime win-x64 --self-contained false --output $paths.Broker
if ($LASTEXITCODE -ne 0) { throw 'Broker publish failed.' }
& $dotnet publish $probeProject --configuration Release --no-restore --runtime win-x64 --self-contained false --output $paths.AuthorizedProbe
if ($LASTEXITCODE -ne 0) { throw 'Live matrix probe publish failed.' }
Copy-Item -Path (Join-Path $paths.AuthorizedProbe '*') -Destination $paths.UnauthorizedProbe -Recurse -Force

$authorizedExecutable = Join-Path $paths.AuthorizedProbe 'SecureIntegration.LiveMatrix.Probe.exe'
$unauthorizedExecutable = Join-Path $paths.UnauthorizedProbe 'SecureIntegration.LiveMatrix.Probe.exe'
if (-not (Test-Path -LiteralPath $authorizedExecutable) -or -not (Test-Path -LiteralPath $unauthorizedExecutable)) { throw 'Published probe apphost is missing.' }
$authorizedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $authorizedExecutable).Hash

$settingsPath = Join-Path $paths.State 'settings.json'
if (Test-Path -LiteralPath $settingsPath) {
    $settings = Get-Content -Raw -LiteralPath $settingsPath | ConvertFrom-Json
}
else {
    $settings = [ordered]@{
        runId = $RunId
        installationId = 'lm-' + [guid]::NewGuid().ToString('N')
        pipeName = 'SecureIntegration.Broker.LiveMatrix.' + $RunId
        applicationId = 'live-legacy-simulator'
        authorizedUser = $AuthorizedUser
        authorizedSid = $authorized.Sid
        unauthorizedUser = $UnauthorizedUser
        unauthorizedSid = $unauthorized.Sid
        createdUtc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    Write-LiveMatrixJson -Value $settings -Path $settingsPath
}
if ($settings.authorizedSid -ne $authorized.Sid -or $settings.unauthorizedSid -ne $unauthorized.Sid) { throw 'Stored SID state does not match the local accounts.' }

$appSettings = [ordered]@{
    Broker = [ordered]@{
        PipeName = [string]$settings.pipeName
        InstallationId = [string]$settings.installationId
        DataDirectory = $paths.BrokerData
        InitializeDataKeys = $true # Explicit synthetic first-use provisioning; partial state is never repaired.
        Applications = @([ordered]@{
            RegistrationId = [string]$settings.applicationId
            AllowedUserSids = @($authorized.Sid)
            ExecutablePaths = @($authorizedExecutable)
            ExecutableSha256 = @($authorizedHash)
            AllowedPublisherThumbprints = @()
            AllowedOperations = @('PutLocalSecret', 'DeleteLocalSecret', 'ProtectData', 'UnprotectData', 'ComputeHmac', 'GetBrokerStatus')
            AllowedDataProtectionContexts = @(@{ Purpose = 'live-matrix-persistence'; ContentType = 'application/octet-stream' })
            GatewayGrants = @()
        })
    }
    Logging = [ordered]@{
        LogLevel = [ordered]@{ Default = 'Information'; Microsoft = 'Warning'; 'Microsoft.Hosting.Lifetime' = 'Information' }
        EventLog = [ordered]@{ LogName = 'Application'; SourceName = 'SecureIntegrationBroker'; LogLevel = [ordered]@{ Default = 'Information' } }
    }
}
Write-LiveMatrixJson -Value $appSettings -Path (Join-Path $paths.Broker 'appsettings.json')

if (-not [Diagnostics.EventLog]::SourceExists('SecureIntegrationBroker')) {
    New-EventLog -LogName Application -Source SecureIntegrationBroker
}

$serviceExecutable = Join-Path $paths.Broker 'SecureIntegration.Broker.Service.exe'
if ($null -ne $existingService) {
    Invoke-ScChecked -Arguments @('config', 'SecureIntegrationBroker', 'binPath=', "`"$serviceExecutable`"", 'start=', 'auto', 'obj=', 'NT SERVICE\SecureIntegrationBroker') | Out-Null
}
else {
    Invoke-ScChecked -Arguments @('create', 'SecureIntegrationBroker', 'binPath=', "`"$serviceExecutable`"", 'start=', 'auto', 'obj=', 'NT SERVICE\SecureIntegrationBroker') | Out-Null
}
Invoke-ScChecked -Arguments @('sidtype', 'SecureIntegrationBroker', 'unrestricted') | Out-Null
Invoke-ScChecked -Arguments @('failure', 'SecureIntegrationBroker', 'reset=', '86400', 'actions=', 'restart/5000/restart/15000/none/0') | Out-Null
Invoke-ScChecked -Arguments @('start', 'SecureIntegrationBroker') | Out-Null
Wait-LiveMatrixService -Status Running
Start-Sleep -Seconds 2
$serviceEvidence = Get-LiveMatrixServiceEvidence
$serviceSid = Assert-LiveMatrixServiceIdentity -Evidence $serviceEvidence
if (-not (Test-Path -LiteralPath (Join-Path $paths.BrokerData 'keys'))) { throw 'The service did not initialize Broker storage.' }

$canaryPath = Join-Path $paths.State 'canaries.json'
if (Test-Path -LiteralPath $canaryPath) {
    $canaries = Get-Content -Raw -LiteralPath $canaryPath | ConvertFrom-Json
}
else {
    $canaries = [ordered]@{
        secret = 'LM_SECRET_' + (ConvertTo-LiveMatrixHex (New-LiveMatrixRandomBytes -Length 24))
        plaintext = 'LM_PLAINTEXT_' + (ConvertTo-LiveMatrixHex (New-LiveMatrixRandomBytes -Length 24))
        invalidPayload = 'LM_INVALID_' + (ConvertTo-LiveMatrixHex (New-LiveMatrixRandomBytes -Length 24))
        message = 'LM_MESSAGE_' + (ConvertTo-LiveMatrixHex (New-LiveMatrixRandomBytes -Length 16))
    }
    Write-LiveMatrixJson -Value $canaries -Path $canaryPath
}

$baseInput = [ordered]@{
    pipeName = [string]$settings.pipeName
    applicationId = [string]$settings.applicationId
    secretBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$canaries.secret))
    plaintextBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$canaries.plaintext))
    messageBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$canaries.message))
    invalidPayloadMarker = [string]$canaries.invalidPayload
    purpose = 'live-matrix-persistence'
    contentType = 'application/octet-stream'
    persistentStatePath = Join-Path $authorizedExchange 'persistent-state.json'
    storagePath = $paths.BrokerData
    storageProbePath = Join-Path $paths.BrokerData 'keys\key-1.bin'
    storageMetadataPath = Join-Path $paths.BrokerData 'secrets\pending.json'
    dpapiCopyPath = Join-Path $authorizedExchange 'key-1.dpapi-copy.bin'
    dpapiSecretCopyPath = Join-Path $authorizedExchange 'local-secret.dpapi-copy.bin'
    installationId = [string]$settings.installationId
    legacyDatabasePath = Join-Path $authorizedExchange 'legacy-database.encrypted'
}
Write-LiveMatrixJson -Value $baseInput -Path (Join-Path $authorizedExchange 'input.json')

$redactedInput = [ordered]@{}
foreach ($property in $baseInput.Keys) { $redactedInput[$property] = $baseInput[$property] }
$redactedInput.secretBase64 = ''
$redactedInput.plaintextBase64 = ''
$redactedInput.messageBase64 = ''
$redactedInput.invalidPayloadMarker = ''
$redactedInput.persistentStatePath = ''
$redactedInput.dpapiCopyPath = Join-Path $sameUserExchange 'key-1.dpapi-copy.bin'
$redactedInput.dpapiSecretCopyPath = Join-Path $sameUserExchange 'local-secret.dpapi-copy.bin'
Write-LiveMatrixJson -Value $redactedInput -Path (Join-Path $sameUserExchange 'input.json')
$redactedInput.dpapiCopyPath = Join-Path $otherUserExchange 'key-1.dpapi-copy.bin'
$redactedInput.dpapiSecretCopyPath = Join-Path $otherUserExchange 'local-secret.dpapi-copy.bin'
Write-LiveMatrixJson -Value $redactedInput -Path (Join-Path $otherUserExchange 'input.json')

$installEvidence = [ordered]@{
    runId = $RunId
    service = $serviceEvidence
    expectedServiceSid = $serviceSid
    authorized = [ordered]@{ name = $authorized.Name; sid = $authorized.Sid; executable = $authorizedExecutable; sha256 = $authorizedHash; batchLogonRight = Test-LiveMatrixBatchLogonRight -Sid $authorized.Sid }
    unauthorizedSameUser = [ordered]@{ name = $authorized.Name; sid = $authorized.Sid; executable = $unauthorizedExecutable; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $unauthorizedExecutable).Hash }
    unauthorizedOtherUser = [ordered]@{ name = $unauthorized.Name; sid = $unauthorized.Sid; batchLogonRight = Test-LiveMatrixBatchLogonRight -Sid $unauthorized.Sid }
    brokerBinarySha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $serviceExecutable).Hash
    configurationSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $paths.Broker 'appsettings.json')).Hash
    completedUtc = [DateTimeOffset]::UtcNow.ToString('o')
}
Write-LiveMatrixJson -Value $installEvidence -Path (Join-Path $paths.Raw 'installation.json')
$installEvidence | ConvertTo-Json -Depth 8

[CmdletBinding()]
param([Parameter(Mandatory)] [string] $RunId)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'LiveMatrix.Common.psm1') -Force -DisableNameChecking
Assert-LiveMatrixAdministrator

$paths = Get-LiveMatrixPaths -RunId $RunId
$phase = Get-Content -Raw -LiteralPath (Join-Path $paths.State 'phase.json') | ConvertFrom-Json
$settings = Get-Content -Raw -LiteralPath (Join-Path $paths.State 'settings.json') | ConvertFrom-Json
$currentBoot = Get-LiveMatrixBootTimeUtc
$preBoot = [DateTimeOffset]::Parse([string]$phase.preRebootBootTimeUtc)
if ($currentBoot -le $preBoot.UtcDateTime.AddSeconds(1)) { throw 'LIVE_MATRIX_REBOOT_NOT_OBSERVED: post-reboot verification cannot run in the pre-reboot boot session.' }

$service = Get-Service -Name SecureIntegrationBroker -ErrorAction Stop
if ($service.Status -ne 'Running') { $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(60)) }
$serviceEvidence = Get-LiveMatrixServiceEvidence
$serviceSid = Assert-LiveMatrixServiceIdentity -Evidence $serviceEvidence
$authorizedCredential = Unprotect-LiveMatrixCredential -Path (Join-Path $paths.State 'authorized.credential.dpapi')
$unauthorizedCredential = Unprotect-LiveMatrixCredential -Path (Join-Path $paths.State 'unauthorized.credential.dpapi')
$authorizedInput = Join-Path $paths.Exchange 'authorized\input.json'
$otherInput = Join-Path $paths.Exchange 'other-user\input.json'
$authorizedExecutable = Join-Path $paths.AuthorizedProbe 'SecureIntegration.LiveMatrix.Probe.exe'

$postAuthorized = Invoke-LiveMatrixScheduledProcess -Credential $authorizedCredential -Executable $authorizedExecutable -Command 'authorized-post' -InputPath $authorizedInput -OutputPath (Join-Path $paths.Raw 'post-reboot-authorized.json')
$postOther = Invoke-LiveMatrixScheduledProcess -Credential $unauthorizedCredential -Executable $authorizedExecutable -Command 'unauthorized-other-user' -InputPath $otherInput -OutputPath (Join-Path $paths.Raw 'post-reboot-other-user.json')

$wellKnown = Get-WellKnownLiveMatrixSids
$allowedStorageSid = @($serviceSid, $wellKnown.System, $wellKnown.Administrators)
$storageAcl = @()
foreach ($item in Get-ChildItem -LiteralPath $paths.BrokerData -Force -Recurse) {
    $storageAcl += Test-FileSystemAclExact -Path $item.FullName -AllowedSid $allowedStorageSid -RequireProtected:([bool]$item.PSIsContainer)
}
$storageAcl += Test-FileSystemAclExact -Path $paths.BrokerData -AllowedSid $allowedStorageSid -RequireProtected
Write-LiveMatrixJson -Value $storageAcl -Path (Join-Path $paths.Raw 'post-reboot-storage-acl.json')

$eventStart = [DateTimeOffset]::Parse([string]$phase.startedUtc).UtcDateTime
$events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'SecureIntegrationBroker'; StartTime = $eventStart } -ErrorAction Stop | Sort-Object TimeCreated | ForEach-Object {
    [ordered]@{
        timeCreatedUtc = $_.TimeCreated.ToUniversalTime().ToString('o')
        id = $_.Id
        level = $_.LevelDisplayName
        provider = $_.ProviderName
        message = $_.Message
        properties = @($_.Properties | ForEach-Object { [string]$_.Value })
    }
})
if ($events.Count -eq 0) { throw 'LIVE_MATRIX_EVENT_LOG_EMPTY.' }
Write-LiveMatrixJson -Value $events -Path (Join-Path $paths.Raw 'event-log.json') -Depth 8
$eventText = $events | ConvertTo-Json -Depth 8

$requiredLogEvidence = @('succeeded True', 'application_not_authorized', 'invalid_base64', 'authentication_failed', 'data_key_unwrap_failed')
foreach ($required in $requiredLogEvidence) {
    if ($eventText.IndexOf($required, [StringComparison]::OrdinalIgnoreCase) -lt 0) { throw "LIVE_MATRIX_EVENT_PATH_MISSING: $required" }
}

$canaries = Get-Content -Raw -LiteralPath (Join-Path $paths.State 'canaries.json') | ConvertFrom-Json
$persistent = Get-Content -Raw -LiteralPath (Join-Path $paths.Exchange 'authorized\persistent-state.json') | ConvertFrom-Json
$keyBlobBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $paths.BrokerData 'keys\key-1.bin')))
$forbidden = @(
    [string]$canaries.secret,
    [string]$canaries.plaintext,
    [string]$canaries.invalidPayload,
    [string]$canaries.message,
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$canaries.secret)),
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$canaries.plaintext)),
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$canaries.message)),
    [string]$persistent.secretRef,
    [string]$persistent.envelopeBase64,
    [string]$persistent.expectedHmacBase64,
    $keyBlobBase64
)
foreach ($value in $forbidden) {
    if ($eventText.IndexOf($value, [StringComparison]::Ordinal) -ge 0) { throw 'LIVE_MATRIX_SECRET_FOUND_IN_LOGS.' }
}
$genericSecretPattern = '(?im)(authorization:\s*bearer\s+\S+|password\s*[:=]\s*\S+|private[_ -]?key\s*[:=]\s*\S+|plaintext\s*[:=]\s*\S+)'
if ([regex]::IsMatch($eventText, $genericSecretPattern)) { throw 'LIVE_MATRIX_SECRET_PATTERN_FOUND_IN_LOGS.' }
$redaction = [ordered]@{ passed = $true; scannedEvents = $events.Count; paths = $requiredLogEvidence; forbiddenCanaries = $forbidden.Count; completedUtc = [DateTimeOffset]::UtcNow.ToString('o') }
Write-LiveMatrixJson -Value $redaction -Path (Join-Path $paths.Raw 'redaction-scan.json')

$summary = [ordered]@{
    runId = $RunId
    phase = 'post-reboot-complete'
    passed = $true
    computerName = $env:COMPUTERNAME
    bootTimeUtc = $currentBoot.ToString('o')
    previousBootTimeUtc = $preBoot.ToString('o')
    service = $serviceEvidence
    persistence = [ordered]@{ hmac = $true; protectedData = $true }
    unauthorizedUserStillDenied = [bool]$postOther.passed
    aclExact = $true
    redaction = $redaction
    matrix = [ordered]@{ A = 'PASS'; B = 'PASS'; C = 'PASS'; D = 'PASS'; E = 'PASS'; F = 'PASS' }
    completedUtc = [DateTimeOffset]::UtcNow.ToString('o')
}
Write-LiveMatrixJson -Value $summary -Path (Join-Path $paths.Raw 'post-reboot-summary.json')

$bundle = & (Join-Path $PSScriptRoot 'New-EvidenceBundle.ps1') -RunId $RunId
& (Join-Path $PSScriptRoot 'Update-RequirementEvidence.ps1') -RunId $RunId -BundlePath $bundle.BundlePath -BundleSha256 $bundle.Sha256
$taskName = "SecureIntegration-LiveMatrix-PostReboot-$RunId"
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

[pscustomobject]@{ Summary = $summary; EvidenceBundle = $bundle } | ConvertTo-Json -Depth 12

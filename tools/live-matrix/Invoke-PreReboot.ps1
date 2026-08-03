[CmdletBinding()]
param([Parameter(Mandatory)] [string] $RunId)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'LiveMatrix.Common.psm1') -Force -DisableNameChecking
Assert-LiveMatrixAdministrator

$paths = Get-LiveMatrixPaths -RunId $RunId
$settings = Get-Content -Raw -LiteralPath (Join-Path $paths.State 'settings.json') | ConvertFrom-Json
$authorizedCredential = Unprotect-LiveMatrixCredential -Path (Join-Path $paths.State 'authorized.credential.dpapi')
$unauthorizedCredential = Unprotect-LiveMatrixCredential -Path (Join-Path $paths.State 'unauthorized.credential.dpapi')
$authorizedInput = Join-Path $paths.Exchange 'authorized\input.json'
$sameInput = Join-Path $paths.Exchange 'same-user-untrusted\input.json'
$otherInput = Join-Path $paths.Exchange 'other-user\input.json'
$authorizedExecutable = Join-Path $paths.AuthorizedProbe 'SecureIntegration.LiveMatrix.Probe.exe'
$unauthorizedExecutable = Join-Path $paths.UnauthorizedProbe 'SecureIntegration.LiveMatrix.Probe.exe'
$wellKnown = Get-WellKnownLiveMatrixSids

$startedUtc = [DateTimeOffset]::UtcNow
$bootTime = Get-LiveMatrixBootTimeUtc
Write-LiveMatrixJson -Value ([ordered]@{ runId = $RunId; startedUtc = $startedUtc.ToString('o'); preRebootBootTimeUtc = $bootTime.ToString('o') }) -Path (Join-Path $paths.State 'phase.json')

$serviceEvidence = Get-LiveMatrixServiceEvidence
$serviceSid = Assert-LiveMatrixServiceIdentity -Evidence $serviceEvidence
$reports = [ordered]@{}

$reports.authorizedPre = Invoke-LiveMatrixScheduledProcess -Credential $authorizedCredential -Executable $authorizedExecutable -Command 'authorized-pre' -InputPath $authorizedInput -OutputPath (Join-Path $paths.Raw 'authorized-pre.json')

$persistentState = Get-Content -Raw -LiteralPath (Join-Path $paths.Exchange 'authorized\persistent-state.json') | ConvertFrom-Json
$secretMetadataPath = Join-Path $paths.BrokerData ("secrets\$($persistentState.secretRef).json")
if (-not (Test-Path -LiteralPath $secretMetadataPath)) { throw 'Local secret metadata was not persisted.' }
$secretDocument = Get-Content -Raw -LiteralPath $secretMetadataPath | ConvertFrom-Json
foreach ($inputPath in $authorizedInput, $sameInput, $otherInput) {
    $inputDocument = Get-Content -Raw -LiteralPath $inputPath | ConvertFrom-Json
    $inputDocument.storageMetadataPath = $secretMetadataPath
    Write-LiveMatrixJson -Value $inputDocument -Path $inputPath
}

$pipeDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new([string]$reports.authorizedPre.pipeSddl)
if (($pipeDescriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0) {
    throw 'LIVE_MATRIX_PIPE_ACL_INHERITANCE_ENABLED.'
}
$pipeAllowed = @($pipeDescriptor.DiscretionaryAcl | Where-Object { $_.AceType -eq [Security.AccessControl.AceType]::AccessAllowed } | ForEach-Object { $_.SecurityIdentifier.Value } | Select-Object -Unique)
$expectedPipeSid = @($serviceSid, [string]$settings.authorizedSid)
foreach ($sid in $pipeAllowed) { if ($expectedPipeSid -notcontains $sid) { throw "LIVE_MATRIX_PIPE_ACL_TOO_PERMISSIVE: grants $sid." } }
foreach ($sid in $expectedPipeSid) { if ($pipeAllowed -notcontains $sid) { throw "LIVE_MATRIX_PIPE_ACL_MISSING_PRINCIPAL: $sid." } }
$expectedPipeMasks = @{
    $serviceSid = [int][IO.Pipes.PipeAccessRights]::FullControl
    ([string]$settings.authorizedSid) = [int]([IO.Pipes.PipeAccessRights]::ReadWrite -bor [IO.Pipes.PipeAccessRights]::Synchronize)
}
foreach ($ace in $pipeDescriptor.DiscretionaryAcl | Where-Object { $_.AceType -eq [Security.AccessControl.AceType]::AccessAllowed }) {
    $expectedMask = $expectedPipeMasks[$ace.SecurityIdentifier.Value]
    if ($null -eq $expectedMask -or $ace.AccessMask -ne $expectedMask) { throw "LIVE_MATRIX_PIPE_ACL_RIGHTS_MISMATCH: $($ace.SecurityIdentifier.Value) mask $($ace.AccessMask)." }
}

$storageAcl = @()
$allowedStorageSid = @($serviceSid, $wellKnown.System, $wellKnown.Administrators)
foreach ($item in Get-ChildItem -LiteralPath $paths.BrokerData -Force -Recurse) {
    $storageAcl += Test-FileSystemAclExact -Path $item.FullName -AllowedSid $allowedStorageSid -RequireProtected:$item.PSIsContainer
}
$storageAcl += Test-FileSystemAclExact -Path $paths.BrokerData -AllowedSid $allowedStorageSid -RequireProtected
Write-LiveMatrixJson -Value $storageAcl -Path (Join-Path $paths.Raw 'storage-acl.json')
Write-LiveMatrixJson -Value ([ordered]@{ sddl = [string]$reports.authorizedPre.pipeSddl; allowedSids = $pipeAllowed }) -Path (Join-Path $paths.Raw 'pipe-acl.json')

$reports.sameUserPolicy = Invoke-LiveMatrixScheduledProcess -Credential $authorizedCredential -Executable $unauthorizedExecutable -Command 'unauthorized-same-user' -InputPath $sameInput -OutputPath (Join-Path $paths.Raw 'same-user-policy.json')
$reports.sameUserStorage = Invoke-LiveMatrixScheduledProcess -Credential $authorizedCredential -Executable $unauthorizedExecutable -Command 'storage-denied' -InputPath $sameInput -OutputPath (Join-Path $paths.Raw 'same-user-storage.json')
$reports.otherUserPipe = Invoke-LiveMatrixScheduledProcess -Credential $unauthorizedCredential -Executable $authorizedExecutable -Command 'unauthorized-other-user' -InputPath $otherInput -OutputPath (Join-Path $paths.Raw 'other-user-pipe.json')
$reports.otherUserStorage = Invoke-LiveMatrixScheduledProcess -Credential $unauthorizedCredential -Executable $authorizedExecutable -Command 'storage-denied' -InputPath $otherInput -OutputPath (Join-Path $paths.Raw 'other-user-storage.json')

$keyPath = Join-Path $paths.BrokerData 'keys\key-1.bin'
$authorizedDpapiCopy = Join-Path $paths.Exchange 'authorized\key-1.dpapi-copy.bin'
$sameDpapiCopy = Join-Path $paths.Exchange 'same-user-untrusted\key-1.dpapi-copy.bin'
$otherDpapiCopy = Join-Path $paths.Exchange 'other-user\key-1.dpapi-copy.bin'
$authorizedSecretCopy = Join-Path $paths.Exchange 'authorized\local-secret.dpapi-copy.bin'
$sameSecretCopy = Join-Path $paths.Exchange 'same-user-untrusted\local-secret.dpapi-copy.bin'
$otherSecretCopy = Join-Path $paths.Exchange 'other-user\local-secret.dpapi-copy.bin'
Copy-Item -LiteralPath $keyPath -Destination $authorizedDpapiCopy -Force
Copy-Item -LiteralPath $keyPath -Destination $sameDpapiCopy -Force
Copy-Item -LiteralPath $keyPath -Destination $otherDpapiCopy -Force
[IO.File]::WriteAllBytes($authorizedSecretCopy, [Convert]::FromBase64String([string]$secretDocument.protectedValueBase64))
[IO.File]::WriteAllBytes($sameSecretCopy, [Convert]::FromBase64String([string]$secretDocument.protectedValueBase64))
[IO.File]::WriteAllBytes($otherSecretCopy, [Convert]::FromBase64String([string]$secretDocument.protectedValueBase64))
$reports.authorizedDpapiDenied = Invoke-LiveMatrixScheduledProcess -Credential $authorizedCredential -Executable $authorizedExecutable -Command 'dpapi-denied' -InputPath $authorizedInput -OutputPath (Join-Path $paths.Raw 'authorized-dpapi-denied.json')
$reports.sameUserDpapiDenied = Invoke-LiveMatrixScheduledProcess -Credential $authorizedCredential -Executable $unauthorizedExecutable -Command 'dpapi-denied' -InputPath $sameInput -OutputPath (Join-Path $paths.Raw 'same-user-dpapi-denied.json')
$reports.otherUserDpapiDenied = Invoke-LiveMatrixScheduledProcess -Credential $unauthorizedCredential -Executable $authorizedExecutable -Command 'dpapi-denied' -InputPath $otherInput -OutputPath (Join-Path $paths.Raw 'other-user-dpapi-denied.json')

[IO.File]::WriteAllBytes((Join-Path $paths.Exchange 'authorized\legacy-database.encrypted'), [Convert]::FromBase64String([string]$persistentState.envelopeBase64))
$reports.legacyEncryptedDatabase = Invoke-LiveMatrixScheduledProcess -Credential $authorizedCredential -Executable $authorizedExecutable -Command 'read-encrypted-database' -InputPath $authorizedInput -OutputPath (Join-Path $paths.Raw 'legacy-encrypted-database.json')

Invoke-ScChecked -Arguments @('stop', 'SecureIntegrationBroker') | Out-Null
Wait-LiveMatrixService -Status Stopped
Invoke-ScChecked -Arguments @('start', 'SecureIntegrationBroker') | Out-Null
Wait-LiveMatrixService -Status Running
$reports.afterServiceRestart = Invoke-LiveMatrixScheduledProcess -Credential $authorizedCredential -Executable $authorizedExecutable -Command 'authorized-post' -InputPath $authorizedInput -OutputPath (Join-Path $paths.Raw 'after-service-restart.json')

$keyBackup = Join-Path $paths.State 'key-1.pre-tamper.dpapi'
Invoke-ScChecked -Arguments @('stop', 'SecureIntegrationBroker') | Out-Null
Wait-LiveMatrixService -Status Stopped
Copy-Item -LiteralPath $keyPath -Destination $keyBackup -Force
try {
    $tampered = [IO.File]::ReadAllBytes($keyPath)
    if ($tampered.Length -lt 2) { throw 'DPAPI key blob is unexpectedly short.' }
    $tampered[$tampered.Length - 1] = $tampered[$tampered.Length - 1] -bxor 1
    [IO.File]::WriteAllBytes($keyPath, $tampered)
    Invoke-ScChecked -Arguments @('start', 'SecureIntegrationBroker') | Out-Null
    Wait-LiveMatrixService -Status Running
    $reports.tamperedKey = Invoke-LiveMatrixScheduledProcess -Credential $authorizedCredential -Executable $authorizedExecutable -Command 'expected-key-failure' -InputPath $authorizedInput -OutputPath (Join-Path $paths.Raw 'tampered-key.json')
}
finally {
    $service = Get-Service -Name SecureIntegrationBroker -ErrorAction SilentlyContinue
    if ($null -ne $service -and $service.Status -ne 'Stopped') {
        Invoke-ScChecked -Arguments @('stop', 'SecureIntegrationBroker') | Out-Null
        Wait-LiveMatrixService -Status Stopped
    }
    if (Test-Path -LiteralPath $keyBackup) { Copy-Item -LiteralPath $keyBackup -Destination $keyPath -Force }
    Invoke-ScChecked -Arguments @('start', 'SecureIntegrationBroker') | Out-Null
    Wait-LiveMatrixService -Status Running
}
$reports.afterTamperRestore = Invoke-LiveMatrixScheduledProcess -Credential $authorizedCredential -Executable $authorizedExecutable -Command 'authorized-post' -InputPath $authorizedInput -OutputPath (Join-Path $paths.Raw 'after-tamper-restore.json')

$serviceEvidence = Get-LiveMatrixServiceEvidence
[void](Assert-LiveMatrixServiceIdentity -Evidence $serviceEvidence)
$scQc = Invoke-ScChecked -Arguments @('qc', 'SecureIntegrationBroker')
$scSidType = Invoke-ScChecked -Arguments @('qsidtype', 'SecureIntegrationBroker')
Write-LiveMatrixJson -Value ([ordered]@{ qc = $scQc.Output; sidType = $scSidType.Output }) -Path (Join-Path $paths.Raw 'scm-configuration.json')

$summary = [ordered]@{
    runId = $RunId
    phase = 'pre-reboot-complete'
    passed = $true
    startedUtc = $startedUtc.ToString('o')
    completedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    bootTimeUtc = $bootTime.ToString('o')
    service = $serviceEvidence
    pipeAclExact = $true
    storageAclExact = $true
    tests = @($reports.Keys)
}
Write-LiveMatrixJson -Value $summary -Path (Join-Path $paths.Raw 'pre-reboot-summary.json')
$summary | ConvertTo-Json -Depth 8

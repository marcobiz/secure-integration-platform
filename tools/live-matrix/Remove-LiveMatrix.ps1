[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)] [string] $RunId,
    [switch] $PurgeEvidence
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'LiveMatrix.Common.psm1') -Force -DisableNameChecking
Assert-LiveMatrixAdministrator
$paths = Get-LiveMatrixPaths -RunId $RunId
$marker = Join-Path $paths.Root 'harness-owned-service.marker'
if (-not (Test-Path -LiteralPath $marker)) { throw 'Refusing cleanup because the harness ownership marker is missing.' }
if ([IO.File]::ReadAllText($marker).Trim() -ne $RunId) { throw 'Refusing cleanup because this run does not own the current service.' }
$settingsPath = Join-Path $paths.State 'settings.json'
if (Test-Path -LiteralPath $settingsPath) {
    $settings = Get-Content -Raw -LiteralPath $settingsPath | ConvertFrom-Json
    if ([string]$settings.runId -ne $RunId) { throw 'Refusing cleanup because RunId does not match the stored run.' }
}
else {
    $earlyService = Get-Service -Name SecureIntegrationBroker -ErrorAction SilentlyContinue
    $earlyTasks = @(Get-ScheduledTask -TaskName 'SecureIntegration-LiveMatrix-*' -ErrorAction SilentlyContinue)
    $earlyUsers = @(@('SibLiveAuthorized', 'SibLiveDenied') | ForEach-Object { Get-LocalUser -Name $_ -ErrorAction SilentlyContinue })
    $foreignUsers = @($earlyUsers | Where-Object { $_.Description -notlike 'Secure Integration live matrix*' })
    if ($null -ne $earlyService -or $earlyTasks.Count -gt 0 -or $foreignUsers.Count -gt 0 -or (Test-Path -LiteralPath $paths.BrokerData)) {
        throw 'Refusing early-failure cleanup because harness-managed system objects exist without run settings.'
    }
}
if (-not $PSCmdlet.ShouldProcess("live matrix run $RunId", 'Remove service, test accounts, binaries and Broker test storage')) { return }

$service = Get-Service -Name SecureIntegrationBroker -ErrorAction SilentlyContinue
if ($null -ne $service) {
    if ($service.Status -ne 'Stopped') {
        Invoke-ScChecked -Arguments @('stop', 'SecureIntegrationBroker') | Out-Null
        Wait-LiveMatrixService -Status Stopped
    }
    Invoke-ScChecked -Arguments @('delete', 'SecureIntegrationBroker') | Out-Null
}

foreach ($task in Get-ScheduledTask -TaskName 'SecureIntegration-LiveMatrix-*' -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false
}
foreach ($name in 'SibLiveAuthorized', 'SibLiveDenied') {
    $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    if ($null -ne $user -and $user.Description -like 'Secure Integration live matrix*') {
        Revoke-LiveMatrixBatchLogonRight -Sid $user.Sid.Value
        Remove-LocalUser -Name $name
    }
}

foreach ($target in $paths.Install, $paths.BrokerData) {
    if (Test-Path -LiteralPath $target) {
        $full = [IO.Path]::GetFullPath($target)
        if ($full -notlike ([IO.Path]::GetFullPath($env:ProgramFiles) + '*') -and $full -notlike ([IO.Path]::GetFullPath($env:ProgramData) + '*')) { throw "Unsafe cleanup target: $full" }
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}

Remove-Item -LiteralPath $paths.State, $paths.Exchange -Recurse -Force -ErrorAction SilentlyContinue
if ($PurgeEvidence) { Remove-Item -LiteralPath $paths.Run -Recurse -Force -ErrorAction SilentlyContinue }
Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue

[CmdletBinding()]
param(
    [ValidateSet('All', 'Prepare', 'PreReboot', 'PostReboot')]
    [string] $Phase = 'All',
    [string] $RunId,
    [switch] $Reboot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'LiveMatrix.Common.psm1') -Force -DisableNameChecking
Assert-LiveMatrixAdministrator

if ([string]::IsNullOrWhiteSpace($RunId)) { $RunId = 'm0-m1-' + (Get-Date -Format 'yyyyMMdd-HHmmss') }
if ($RunId -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$') { throw 'RunId must contain only letters, digits, dot, underscore and dash (maximum 64 characters).' }
$paths = Get-LiveMatrixPaths -RunId $RunId

try {
    switch ($Phase) {
        'Prepare' {
            & (Join-Path $PSScriptRoot 'Test-Prerequisites.ps1') -RunId $RunId | Out-Host
            & (Join-Path $PSScriptRoot 'Install-LiveBroker.ps1') -RunId $RunId | Out-Host
            break
        }
        'PreReboot' {
            & (Join-Path $PSScriptRoot 'Test-Prerequisites.ps1') -RunId $RunId | Out-Host
            & (Join-Path $PSScriptRoot 'Install-LiveBroker.ps1') -RunId $RunId | Out-Host
            & (Join-Path $PSScriptRoot 'Invoke-PreReboot.ps1') -RunId $RunId | Out-Host
            break
        }
        'PostReboot' {
            & (Join-Path $PSScriptRoot 'Invoke-PostReboot.ps1') -RunId $RunId | Out-Host
            break
        }
        'All' {
            & (Join-Path $PSScriptRoot 'Test-Prerequisites.ps1') -RunId $RunId | Out-Host
            & (Join-Path $PSScriptRoot 'Install-LiveBroker.ps1') -RunId $RunId | Out-Host
            & (Join-Path $PSScriptRoot 'Invoke-PreReboot.ps1') -RunId $RunId | Out-Host

            $taskName = "SecureIntegration-LiveMatrix-PostReboot-$RunId"
            $scriptPath = Join-Path $PSScriptRoot 'Invoke-LiveMatrix.ps1'
            $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Phase PostReboot -RunId "{1}"' -f $scriptPath, $RunId
            $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments
            $trigger = New-ScheduledTaskTrigger -AtStartup
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
            [IO.File]::WriteAllText((Join-Path $paths.Root 'last-run-id.txt'), $RunId, [Text.UTF8Encoding]::new($false))

            if (-not $Reboot) {
                [pscustomobject]@{
                    RunId = $RunId
                    State = 'PRE_REBOOT_PASS_POST_REBOOT_PENDING'
                    ResumeCommand = ".\tools\live-matrix\Invoke-LiveMatrix.ps1 -Phase PostReboot -RunId '$RunId'"
                    ScheduledTask = $taskName
                } | ConvertTo-Json
                break
            }

            Write-Host "Pre-reboot matrix passed. Rebooting VM; scheduled task '$taskName' will execute the post-reboot phase."
            Restart-Computer -Force
        }
    }
}
catch {
    $failure = [ordered]@{
        runId = $RunId
        phase = $Phase
        passed = $false
        errorCode = if ($_.Exception.Message -match '^([A-Z0-9_]+)') { $Matches[1] } else { $_.Exception.GetType().Name }
        failedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    if (Test-Path -LiteralPath $paths.Run) { Write-LiveMatrixJson -Value $failure -Path (Join-Path $paths.Raw "failure-$Phase.json") }
    Write-Error $_
    exit 1
}

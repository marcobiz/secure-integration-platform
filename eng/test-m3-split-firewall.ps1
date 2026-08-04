[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$modulePath = Join-Path $root 'tools\m3\split-host\M3ASplitFirewall.psm1'
$runnerPath = Join-Path $root 'tools\m3\split-host\Invoke-M3ASplitHost.ps1'
Import-Module $modulePath -Force

function Assert-Equal {
    param($Expected, $Actual, [string] $Message)
    if ($Expected -ne $Actual) { throw "$Message Expected '$Expected', got '$Actual'." }
}

function Assert-ThrowsCode {
    param([scriptblock] $Action, [string] $Code)
    try { & $Action; throw "Expected $Code." }
    catch {
        if ([string]$_.Exception.Message -notlike ($Code + '*')) { throw }
    }
}

$firewallProfiles = @(
    [pscustomobject]@{ Name = 'Domain'; Enabled = $false },
    [pscustomobject]@{ Name = 'Private'; Enabled = $false },
    [pscustomobject]@{ Name = 'Public'; Enabled = $false }
)
$dedicated = @([pscustomobject]@{ InterfaceIndex = 46; InterfaceAlias = 'vEthernet (M3A Internal)'; NetworkCategory = 'Private' })
$selection = Resolve-M3AFirewallProfileSelection -InterfaceIndex 46 -ConnectionProfiles $dedicated -FirewallProfiles $firewallProfiles
Assert-Equal 'Private' $selection.ProfileName 'Dedicated interface profile was not resolved.'
Assert-Equal $false $selection.OriginallyEnabled 'Original disabled state was not preserved.'

Assert-ThrowsCode -Code 'M3A_SPLIT_FIREWALL_PROFILE_UNRESOLVED_DEDICATED_SWITCH_REQUIRED.' -Action {
    Resolve-M3AFirewallProfileSelection -InterfaceIndex 46 -ConnectionProfiles @() -FirewallProfiles $firewallProfiles
}
Assert-ThrowsCode -Code 'M3A_SPLIT_FIREWALL_PROFILE_SHARED_DEDICATED_SWITCH_REQUIRED.' -Action {
    Resolve-M3AFirewallProfileSelection -InterfaceIndex 46 -ConnectionProfiles @(
        $dedicated[0],
        [pscustomobject]@{ InterfaceIndex = 20; InterfaceAlias = 'Ethernet'; NetworkCategory = 'Private' }
    ) -FirewallProfiles $firewallProfiles
}

$restored = @(
    [pscustomobject]@{ Name = 'Domain'; Enabled = $false },
    [pscustomobject]@{ Name = 'Private'; Enabled = $false },
    [pscustomobject]@{ Name = 'Public'; Enabled = $false }
)
Assert-Equal $true (Test-M3AFirewallProfileStateRestored -OriginalStates $firewallProfiles -CurrentProfiles $restored) 'Exact rollback state should pass.'
$restored[1].Enabled = $true
Assert-Equal $false (Test-M3AFirewallProfileStateRestored -OriginalStates $firewallProfiles -CurrentProfiles $restored) 'Changed profile state should fail rollback verification.'

$runner = [IO.File]::ReadAllText($runnerPath)
foreach ($required in @(
    'M3A_SPLIT_FIREWALL_PROFILE_NOT_ENFORCING',
    'M3A_SPLIT_FIREWALL_RULE_NOT_ENFORCED',
    'Register-ScheduledTask',
    'Test-M3AFirewallProfileStateRestored',
    'remainingFirewallRollbackTasks',
    'firewallProfileRestored',
    '-InterfaceAlias ([string]$firewallSelection.InterfaceAlias)'
)) {
    if ($runner.IndexOf($required, [StringComparison]::Ordinal) -lt 0) { throw "Missing firewall hardening control: $required" }
}
if ($runner -match '-Profile\s+Any') { throw 'Firewall rule must never use Profile Any.' }

Write-Output 'M3A_SPLIT_FIREWALL_TEST_PASS'

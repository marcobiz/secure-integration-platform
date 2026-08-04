[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$modulePath = Join-Path $root 'tools\m3\split-host\M3ASplitNetwork.psm1'
$runnerPath = Join-Path $root 'tools\m3\split-host\Invoke-M3ASplitHost.ps1'
Import-Module $modulePath -Force

function Assert-Equal {
    param($Expected, $Actual, [string] $Message)
    if ($Expected -ne $Actual) { throw "$Message Expected '$Expected', got '$Actual'." }
}

function Assert-ThrowsCode {
    param([scriptblock] $Action, [string] $Code)
    try { & $Action; throw "Expected $Code." }
    catch { if ([string]$_.Exception.Message -notlike ($Code + '*')) { throw } }
}

Assert-Equal $true (Test-M3AAddressInSubnet 192.168.250.1 192.168.250.0 29) 'HOST address must be inside /29.'
Assert-Equal $false (Test-M3AAddressInSubnet 192.168.250.9 192.168.250.0 29) 'Outside address accepted.'
Assert-ThrowsCode -Code 'M3A_SPLIT_ISOLATED_SUBNET_CONFLICT.' -Action {
    Assert-M3AIsolatedSubnetRecordsAvailable -NetworkAddress 192.168.250.0 -PrefixLength 29 -AddressRecords @([pscustomobject]@{ IPAddress = '192.168.250.4' }) -RouteRecords @() -NatRecords @()
}
Assert-ThrowsCode -Code 'M3A_SPLIT_ISOLATED_SWITCH_NOT_INTERNAL.' -Action {
    Assert-M3AInternalSwitch -Switch ([pscustomobject]@{ Name = 'M3A-Isolated'; SwitchType = 'External' }) -ExpectedName 'M3A-Isolated'
}
foreach ($case in @(
    @{ Gateway = 1; Dns = 0; Forwarding = 'Disabled'; Nat = 0 },
    @{ Gateway = 0; Dns = 1; Forwarding = 'Disabled'; Nat = 0 },
    @{ Gateway = 0; Dns = 0; Forwarding = 'Enabled'; Nat = 0 },
    @{ Gateway = 0; Dns = 0; Forwarding = 'Disabled'; Nat = 1 }
)) {
    Assert-ThrowsCode -Code 'M3A_SPLIT_TEST_ENDPOINT_CONTRACT.' -Action {
        Assert-M3ANetworkEndpointContract -DefaultGatewayCount $case.Gateway -DnsServerCount $case.Dns -Forwarding $case.Forwarding -NatCount $case.Nat -ErrorCode 'M3A_SPLIT_TEST_ENDPOINT_CONTRACT.'
    }
}

$state = [pscustomobject]@{
    switchName = 'M3A-Isolated'; vmNicName = 'M3A-Isolated'
    originalFirewallProfiles = @(
        [pscustomobject]@{ Name = 'Domain'; Enabled = $false },
        [pscustomobject]@{ Name = 'Private'; Enabled = $false },
        [pscustomobject]@{ Name = 'Public'; Enabled = $false }
    )
    tailscale = [pscustomobject]@{ wasEnabled = $true }
}
$profiles = @(
    [pscustomobject]@{ Name = 'Domain'; Enabled = $false },
    [pscustomobject]@{ Name = 'Private'; Enabled = $false },
    [pscustomobject]@{ Name = 'Public'; Enabled = $false }
)
$tailscaleUp = [pscustomobject]@{ Status = 'Up'; AdminStatus = 'Up' }
Assert-Equal $true (Test-M3ANetworkStateRestored $state @() @() $profiles $tailscaleUp) 'Complete rollback rejected.'
Assert-Equal $false (Test-M3ANetworkStateRestored $state @([pscustomobject]@{ Name = 'M3A-Isolated' }) @() $profiles $tailscaleUp) 'Residual switch accepted.'
Assert-Equal $false (Test-M3ANetworkStateRestored $state @() @() $profiles ([pscustomobject]@{ Status = 'Disabled'; AdminStatus = 'Down' })) 'Tailscale restore omission accepted.'
$preDisabledState = [pscustomobject]@{
    switchName = 'M3A-Isolated'; vmNicName = 'M3A-Isolated'
    originalFirewallProfiles = $state.originalFirewallProfiles
    tailscale = [pscustomobject]@{ wasEnabled = $false }
}
Assert-Equal $true (Test-M3ANetworkStateRestored $preDisabledState @() @() $profiles $null) 'Pre-disabled Tailscale cleanup rejected a missing adapter.'
$profiles[1].Enabled = $true
Assert-Equal $false (Test-M3ANetworkStateRestored $state @() @() $profiles $tailscaleUp) 'Firewall rollback omission accepted.'

$runner = [IO.File]::ReadAllText($runnerPath)
$module = [IO.File]::ReadAllText($modulePath)
$runnerCommand = Get-Command $runnerPath
$rollbackParameter = $runnerCommand.Parameters['RollbackTimeoutMinutes']
$rollbackRange = @($rollbackParameter.Attributes | Where-Object { $_ -is [Management.Automation.ValidateRangeAttribute] })
Assert-Equal 1 $rollbackRange.Count 'Rollback timeout range validation missing.'
Assert-Equal 30 $rollbackRange[0].MinRange 'Rollback timeout minimum changed.'
Assert-Equal 180 $rollbackRange[0].MaxRange 'Rollback timeout maximum changed.'
foreach ($required in @(
    'M3A_SPLIT_HOST_ADDRESS_NOT_ASSIGNED_TO_ISOLATED_SWITCH',
    'M3A_SPLIT_VM_EXPOSURE_CONTRACT_FAILED',
    'M3A_SPLIT_GATEWAY_BIND_NOT_RESTRICTED',
    'Disable-M3ATailscaleForIsolation',
    'Get-VM -Id $ExactVmId',
    'Get-VMNetworkAdapter -VM $exactVm -Name $IsolatedVmNicName',
    'Get-VM | Where-Object Id -ne $ExactVmId',
    'New-PSSession -VMId $ExactVmId',
    'remainingNetworkRollbackTasks',
    'isolatedNetworkRestored',
    '[ValidateRange(30, 180)] [int] $RollbackTimeoutMinutes = 30',
    '-RollbackTimeoutMinutes $RollbackTimeoutMinutes',
    '-TimeoutMinutes $RollbackTimeoutMinutes'
)) { if ($runner.IndexOf($required, [StringComparison]::Ordinal) -lt 0) { throw "Missing network enforcement control: $required" } }
foreach ($required in @(
    "New-VMSwitch -Name `$SwitchName -SwitchType Internal",
    'Checkpoint-VM -VM $vm',
    '-DhcpGuard On -RouterGuard On -MacAddressSpoofing Off',
    'M3A_SPLIT_GUEST_ISOLATION_CONTRACT_INVALID',
    'M3A_SPLIT_HOST_ISOLATION_CONTRACT_INVALID',
    'M3A_SPLIT_HOST_TO_VM_LAYER2_CONNECTIVITY_FAILED',
    'M3A_SPLIT_PRIVATE_PROFILE_SHARED_BY_ACTIVE_INTERFACE',
    'Disable-PnpDevice -InstanceId',
    'Enable-PnpDevice -InstanceId',
    'Register-ScheduledTask',
    '[Parameter(Mandatory)] [DateTime] $RollbackAt',
    'rollbackDeadlineUtc',
    'Remove-VMNetworkAdapter',
    'Test-M3ANetworkStateRestored'
)) { if ($module.IndexOf($required, [StringComparison]::Ordinal) -lt 0) { throw "Missing isolated network control: $required" } }
if ($module -match 'New-NetNat|Set-NetIPInterface[^\r\n]+Forwarding\s+Enabled') { throw 'Isolated network must not create NAT or enable forwarding.' }
if ($module -match '(Enable|Disable)-NetAdapter\s+-InterfaceIndex') { throw 'Windows PowerShell 5.1 requires NetAdapter pipeline binding for InterfaceIndex.' }
if (($module + $runner) -match 'Set-NetFirewallProfile[^\r\n]+-Enabled\s+\(\[bool\]') { throw 'Windows PowerShell 5.1 requires the GpoBoolean string value during rollback.' }
if ($module -match 'Set-VMNetworkAdapter[^\r\n]+-StaticMacAddress') { throw 'A running VM NIC must retain its assigned MAC instead of attempting an unsupported static conversion.' }
if ($runner -match 'LocalAddress\s+0\.0\.0\.0|-Profile\s+Any') { throw 'Broad listener or firewall profile accepted.' }
if (($module + $runner) -match 'New-ScheduledTaskTrigger\s+-Once\s+-At\s+\(Get-Date\)\.AddMinutes\(30\)') { throw 'Hard-coded rollback deadline accepted.' }

Write-Output 'M3A_SPLIT_NETWORK_TEST_PASS'

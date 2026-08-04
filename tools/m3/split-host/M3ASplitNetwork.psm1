Set-StrictMode -Version Latest

function Write-M3ANetworkJson {
    param([Parameter(Mandatory)] $Value, [Parameter(Mandatory)] [string] $Path)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
}

function ConvertTo-M3AUInt32Address {
    param([Parameter(Mandatory)] [string] $Address)
    $parsed = [Net.IPAddress]::Parse($Address)
    $bytes = $parsed.GetAddressBytes()
    if ($bytes.Length -ne 4) { throw 'M3A_SPLIT_ISOLATED_IPV4_REQUIRED.' }
    return ([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3]
}

function Test-M3AAddressInSubnet {
    param(
        [Parameter(Mandatory)] [string] $Address,
        [Parameter(Mandatory)] [string] $NetworkAddress,
        [ValidateRange(1, 32)] [int] $PrefixLength
    )
    $hostBits = 32 - $PrefixLength
    $mask = [uint32]([uint64][uint32]::MaxValue - [uint64]([math]::Pow(2, $hostBits) - 1))
    return ((ConvertTo-M3AUInt32Address $Address) -band $mask) -eq ((ConvertTo-M3AUInt32Address $NetworkAddress) -band $mask)
}

function Assert-M3AIsolatedAddressContract {
    param(
        [Parameter(Mandatory)] [string] $NetworkAddress,
        [Parameter(Mandatory)] [string] $HostAddress,
        [Parameter(Mandatory)] [string] $VmAddress,
        [ValidateRange(29, 30)] [int] $PrefixLength
    )
    if ($HostAddress -eq $VmAddress -or -not (Test-M3AAddressInSubnet $HostAddress $NetworkAddress $PrefixLength) -or -not (Test-M3AAddressInSubnet $VmAddress $NetworkAddress $PrefixLength)) {
        throw 'M3A_SPLIT_ISOLATED_ADDRESS_CONTRACT_INVALID.'
    }
    if ($HostAddress -eq $NetworkAddress -or $VmAddress -eq $NetworkAddress) { throw 'M3A_SPLIT_ISOLATED_NETWORK_ADDRESS_USED.' }
}

function Assert-M3AIsolatedSubnetAvailable {
    param(
        [Parameter(Mandatory)] [string] $NetworkAddress,
        [ValidateRange(29, 30)] [int] $PrefixLength
    )
    Assert-M3AIsolatedSubnetRecordsAvailable -NetworkAddress $NetworkAddress -PrefixLength $PrefixLength -AddressRecords @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop) -RouteRecords @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop) -NatRecords @(Get-NetNat -ErrorAction SilentlyContinue)
}

function Assert-M3AIsolatedSubnetRecordsAvailable {
    param(
        [Parameter(Mandatory)] [string] $NetworkAddress,
        [ValidateRange(29, 30)] [int] $PrefixLength,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $AddressRecords,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $RouteRecords,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $NatRecords
    )
    $conflicts = @($AddressRecords | Where-Object { Test-M3AAddressInSubnet ([string]$_.IPAddress) $NetworkAddress $PrefixLength })
    $prefix = "$NetworkAddress/$PrefixLength"
    $conflicts += @($RouteRecords | Where-Object { [string]$_.DestinationPrefix -eq $prefix })
    $conflicts += @($NatRecords | Where-Object { [string]$_.InternalIPInterfaceAddressPrefix -eq $prefix })
    if ($conflicts.Count -ne 0) { throw 'M3A_SPLIT_ISOLATED_SUBNET_CONFLICT.' }
}

function Assert-M3ANetworkEndpointContract {
    param(
        [Parameter(Mandatory)] [int] $DefaultGatewayCount,
        [Parameter(Mandatory)] [int] $DnsServerCount,
        [Parameter(Mandatory)] [string] $Forwarding,
        [Parameter(Mandatory)] [int] $NatCount,
        [Parameter(Mandatory)] [string] $ErrorCode
    )
    if ($DefaultGatewayCount -ne 0 -or $DnsServerCount -ne 0 -or $Forwarding -ne 'Disabled' -or $NatCount -ne 0) { throw $ErrorCode }
}

function Assert-M3AInternalSwitch {
    param([Parameter(Mandatory)] $Switch, [Parameter(Mandatory)] [string] $ExpectedName)
    if ([string]$Switch.Name -ne $ExpectedName -or [string]$Switch.SwitchType -ne 'Internal') {
        throw 'M3A_SPLIT_ISOLATED_SWITCH_NOT_INTERNAL.'
    }
}

function Test-M3ANetworkStateRestored {
    param(
        [Parameter(Mandatory)] $State,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Switches,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $VmAdapters,
        [Parameter(Mandatory)] [object[]] $FirewallProfiles,
        [Parameter(Mandatory)] $TailscaleAdapter
    )
    if (@($Switches | Where-Object { [string]$_.Name -eq [string]$State.switchName }).Count -ne 0) { return $false }
    if (@($VmAdapters | Where-Object { [string]$_.Name -eq [string]$State.vmNicName }).Count -ne 0) { return $false }
    foreach ($original in @($State.originalFirewallProfiles)) {
        $current = @($FirewallProfiles | Where-Object { [string]$_.Name -eq [string]$original.Name })
        if ($current.Count -ne 1 -or [bool]$current[0].Enabled -ne [bool]$original.Enabled) { return $false }
    }
    if ([bool]$State.tailscale.wasEnabled -and ([string]$TailscaleAdapter.Status -ne 'Up' -or [string]$TailscaleAdapter.AdminStatus -ne 'Up')) { return $false }
    return $true
}

function Disable-M3ATailscaleForIsolation {
    param([Parameter(Mandatory)] [string] $StatePath, [Parameter(Mandatory)] [uint32] $DedicatedInterfaceIndex)
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if ([bool]$state.tailscale.present -and [bool]$state.tailscale.wasEnabled) {
        Get-NetAdapter -InterfaceIndex ([uint32]$state.tailscale.interfaceIndex) -ErrorAction Stop | Disable-NetAdapter -Confirm:$false
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(5)
        do {
            $tailscale = Get-NetAdapter -InterfaceIndex ([uint32]$state.tailscale.interfaceIndex) -ErrorAction SilentlyContinue
            if ($null -ne $tailscale -and [string]$tailscale.Status -ne 'Up' -and [string]$tailscale.AdminStatus -ne 'Up') { break }
            Start-Sleep -Milliseconds 500
        } while ([DateTimeOffset]::UtcNow -lt $deadline)
        if ($null -eq $tailscale -or [string]$tailscale.AdminStatus -eq 'Up') {
            if ([string]::IsNullOrWhiteSpace([string]$state.tailscale.pnpDeviceId)) { throw 'M3A_SPLIT_TAILSCALE_PNP_ID_MISSING.' }
            Disable-PnpDevice -InstanceId ([string]$state.tailscale.pnpDeviceId) -Confirm:$false
            $deadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
            do {
                $tailscale = Get-NetAdapter -Name Tailscale -ErrorAction SilentlyContinue
                if ($null -eq $tailscale -or [string]$tailscale.AdminStatus -ne 'Up' -or [string]$tailscale.Status -ne 'Up') { break }
                Start-Sleep -Milliseconds 500
            } while ([DateTimeOffset]::UtcNow -lt $deadline)
            $state.tailscale | Add-Member -NotePropertyName disableMethod -NotePropertyValue 'PnPDevice' -Force
        }
        if ($null -ne $tailscale -and ([string]$tailscale.AdminStatus -eq 'Up' -or [string]$tailscale.Status -eq 'Up')) { throw 'M3A_SPLIT_TAILSCALE_DISABLE_FAILED.' }
        $state.tailscale | Add-Member -NotePropertyName temporarilyDisabled -NotePropertyValue $true -Force
        Write-M3ANetworkJson $state $StatePath
    }

    $upIndices = @(Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty InterfaceIndex)
    $privateProfiles = @(Get-NetConnectionProfile | Where-Object { [string]$_.NetworkCategory -in @('Private', '1') -and $upIndices -contains [uint32]$_.InterfaceIndex })
    if ($privateProfiles.Count -ne 1 -or [uint32]$privateProfiles[0].InterfaceIndex -ne $DedicatedInterfaceIndex) {
        throw 'M3A_SPLIT_PRIVATE_PROFILE_SHARED_BY_ACTIVE_INTERFACE.'
    }
    return [pscustomobject]@{ disabled = [bool]$state.tailscale.wasEnabled; activePrivateInterfaceIndex = [uint32]$privateProfiles[0].InterfaceIndex }
}

function Set-M3ANetworkFirewallRuleState {
    param([Parameter(Mandatory)] [string] $StatePath, [Parameter(Mandatory)] [string] $FirewallRule)
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    $state.firewallRule = $FirewallRule
    Write-M3ANetworkJson $state $StatePath
}

function New-M3ANetworkRollback {
    param(
        [Parameter(Mandatory)] [string] $StatePath,
        [Parameter(Mandatory)] [string] $RollbackPath,
        [Parameter(Mandatory)] [string] $TaskName
    )
    $escapedState = $StatePath.Replace("'", "''")
    $escapedTask = $TaskName.Replace("'", "''")
    $script = @"
`$ErrorActionPreference = 'Continue'
`$state = Get-Content -LiteralPath '$escapedState' -Raw | ConvertFrom-Json
if (`$state.firewallRule) { Get-NetFirewallRule -DisplayName ([string]`$state.firewallRule) -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
foreach (`$profile in @(`$state.originalFirewallProfiles)) { Set-NetFirewallProfile -Name ([string]`$profile.Name) -Enabled ([string]`$profile.Enabled) }
if ([bool]`$state.tailscale.wasEnabled) {
    if (`$state.tailscale.pnpDeviceId) { Enable-PnpDevice -InstanceId ([string]`$state.tailscale.pnpDeviceId) -Confirm:`$false -ErrorAction SilentlyContinue }
    Get-NetAdapter -Name 'Tailscale' -ErrorAction SilentlyContinue | Enable-NetAdapter -Confirm:`$false
}
`$vm = Get-VM -Id ([guid]`$state.vmId) -ErrorAction SilentlyContinue
if (`$null -ne `$vm) {
    Get-VMNetworkAdapter -VM `$vm -Name ([string]`$state.vmNicName) -ErrorAction SilentlyContinue |
        Where-Object { [string]`$_.SwitchName -eq [string]`$state.switchName } |
        Remove-VMNetworkAdapter -Confirm:`$false
}
Get-VMSwitch -Name ([string]`$state.switchName) -ErrorAction SilentlyContinue |
    Where-Object { [string]`$_.SwitchType -eq 'Internal' } |
    Remove-VMSwitch -Force
`$removalDeadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
do { Start-Sleep -Milliseconds 500 } while ((Get-VMSwitch -Name ([string]`$state.switchName) -ErrorAction SilentlyContinue) -and [DateTimeOffset]::UtcNow -lt `$removalDeadline)
Unregister-ScheduledTask -TaskName '$escapedTask' -Confirm:`$false -ErrorAction SilentlyContinue
"@
    [IO.File]::WriteAllText($RollbackPath, $script, [Text.UTF8Encoding]::new($false))
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $RollbackPath + '"')
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(30)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -User SYSTEM -RunLevel Highest -Force | Out-Null
    if ($null -eq (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { throw 'M3A_SPLIT_NETWORK_ROLLBACK_TASK_NOT_REGISTERED.' }
}

function Save-M3ANetworkInventory {
    param([Parameter(Mandatory)] [guid] $VmId, [Parameter(Mandatory)] [string] $Path)
    $vm = Get-VM -Id $VmId -ErrorAction Stop
    $inventory = [ordered]@{
        recordedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
        vm = $vm | Select-Object Name, Id, State, Status, ConfigurationLocation, Path
        switches = @(Get-VMSwitch | Select-Object Name, Id, SwitchType, NetAdapterInterfaceDescription)
        vmAdapters = @(Get-VMNetworkAdapter -VM $vm | Select-Object Name, SwitchName, MacAddress, Status, IPAddresses, DhcpGuard, RouterGuard)
        addresses = @(Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, InterfaceIndex, IPAddress, PrefixLength, PrefixOrigin, SuffixOrigin)
        routes = @(Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix, NextHop, InterfaceAlias, InterfaceIndex, RouteMetric, Protocol, State)
        profiles = @(Get-NetConnectionProfile | Select-Object InterfaceAlias, InterfaceIndex, NetworkCategory, IPv4Connectivity, IPv6Connectivity)
        firewallProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -Name Domain, Private, Public | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
        nat = @(Get-NetNat -ErrorAction SilentlyContinue | Select-Object Name, InternalIPInterfaceAddressPrefix, Active)
        tailscale = Get-NetAdapter -Name Tailscale -ErrorAction SilentlyContinue | Select-Object Name, InterfaceIndex, Status, AdminStatus, InterfaceDescription
    }
    Write-M3ANetworkJson -Value $inventory -Path $Path
    return $inventory
}

function New-M3AIsolatedNetwork {
    param(
        [Parameter(Mandatory)] [guid] $VmId,
        [Parameter(Mandatory)] [Management.Automation.PSCredential] $VmCredential,
        [Parameter(Mandatory)] [string] $SwitchName,
        [Parameter(Mandatory)] [string] $VmNicName,
        [Parameter(Mandatory)] [string] $NetworkAddress,
        [Parameter(Mandatory)] [string] $HostAddress,
        [Parameter(Mandatory)] [string] $VmAddress,
        [ValidateRange(29, 30)] [int] $PrefixLength,
        [Parameter(Mandatory)] [string] $StatePath,
        [Parameter(Mandatory)] [string] $InventoryPath,
        [Parameter(Mandatory)] [string] $RollbackPath,
        [Parameter(Mandatory)] [string] $RollbackTaskName,
        [Parameter(Mandatory)] [string] $CheckpointName
    )
    Assert-M3AIsolatedAddressContract $NetworkAddress $HostAddress $VmAddress $PrefixLength
    Assert-M3AIsolatedSubnetAvailable $NetworkAddress $PrefixLength
    if (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue) { throw 'M3A_SPLIT_ISOLATED_SWITCH_ALREADY_EXISTS.' }
    $vm = Get-VM -Id $VmId -ErrorAction Stop
    if ([string]$vm.State -ne 'Running') { throw 'M3A_SPLIT_VM_NOT_RUNNING.' }
    $management = @(Get-VMNetworkAdapter -VM $vm | Where-Object { [string]$_.SwitchName -eq 'Default Switch' })
    if ($management.Count -lt 1) { throw 'M3A_SPLIT_VM_MANAGEMENT_NIC_MISSING.' }
    if (Get-VMNetworkAdapter -VM $vm -Name $VmNicName -ErrorAction SilentlyContinue) { throw 'M3A_SPLIT_ISOLATED_VM_NIC_ALREADY_EXISTS.' }

    $inventory = Save-M3ANetworkInventory -VmId $VmId -Path $InventoryPath
    $tailscale = Get-NetAdapter -Name Tailscale -ErrorAction SilentlyContinue
    $state = [ordered]@{
        schemaVersion = 1; vmId = [string]$VmId; vmName = [string]$vm.Name
        switchName = $SwitchName; vmNicName = $VmNicName; networkAddress = $NetworkAddress
        hostAddress = $HostAddress; vmAddress = $VmAddress; prefixLength = $PrefixLength
        checkpointName = $CheckpointName; checkpointCreated = $false; switchCreated = $false; vmNicCreated = $false
        firewallRule = $null
        originalFirewallProfiles = @($inventory.firewallProfiles | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Enabled = [bool]$_.Enabled } })
        tailscale = [ordered]@{ present = $null -ne $tailscale; interfaceIndex = if ($tailscale) { [uint32]$tailscale.InterfaceIndex } else { 0 }; pnpDeviceId = if ($tailscale) { [string]$tailscale.PnPDeviceID } else { $null }; wasEnabled = $null -ne $tailscale -and [string]$tailscale.AdminStatus -eq 'Up'; status = if ($tailscale) { [string]$tailscale.Status } else { 'Missing' } }
        rollbackTask = $RollbackTaskName; preparedAtUtc = [DateTimeOffset]::UtcNow.ToString('O')
    }
    Write-M3ANetworkJson $state $StatePath
    New-M3ANetworkRollback -StatePath $StatePath -RollbackPath $RollbackPath -TaskName $RollbackTaskName

    try {
    Checkpoint-VM -VM $vm -SnapshotName $CheckpointName | Out-Null
    $state.checkpointCreated = $true; Write-M3ANetworkJson $state $StatePath
    $switch = New-VMSwitch -Name $SwitchName -SwitchType Internal
    Assert-M3AInternalSwitch $switch $SwitchName
    $state.switchCreated = $true; Write-M3ANetworkJson $state $StatePath

    $hostAdapter = $null
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do {
        $hostAdapter = Get-NetAdapter -Name ('vEthernet (' + $SwitchName + ')') -ErrorAction SilentlyContinue
        if ($null -eq $hostAdapter) { Start-Sleep -Seconds 1 }
    } while ($null -eq $hostAdapter -and [DateTimeOffset]::UtcNow -lt $deadline)
    if ($null -eq $hostAdapter) { throw 'M3A_SPLIT_ISOLATED_HOST_ADAPTER_MISSING.' }
    Set-NetIPInterface -InterfaceIndex $hostAdapter.InterfaceIndex -AddressFamily IPv4 -Dhcp Disabled -Forwarding Disabled -AutomaticMetric Disabled -InterfaceMetric 5000
    Get-NetIPAddress -InterfaceIndex $hostAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
    New-NetIPAddress -InterfaceIndex $hostAdapter.InterfaceIndex -IPAddress $HostAddress -PrefixLength $PrefixLength -AddressFamily IPv4 | Out-Null
    Set-DnsClientServerAddress -InterfaceIndex $hostAdapter.InterfaceIndex -ResetServerAddresses

    Add-VMNetworkAdapter -VM $vm -Name $VmNicName -SwitchName $SwitchName
    $vmNic = Get-VMNetworkAdapter -VM $vm -Name $VmNicName -ErrorAction Stop
    $mac = [string]$vmNic.MacAddress
    Set-VMNetworkAdapter -VMNetworkAdapter $vmNic -DhcpGuard On -RouterGuard On -MacAddressSpoofing Off
    $state.vmNicCreated = $true; $state.vmNicMacAddress = $mac; $state.hostInterfaceIndex = [uint32]$hostAdapter.InterfaceIndex; $state.hostInterfaceAlias = [string]$hostAdapter.Name
    Write-M3ANetworkJson $state $StatePath

    $session = New-PSSession -VMId $VmId -Credential $VmCredential
    try {
        $guest = Invoke-Command -Session $session -ArgumentList $mac, $VmAddress, $PrefixLength -ScriptBlock {
            param($ExpectedMac, $Address, $Prefix)
            $normalized = $ExpectedMac -replace '[:-]', ''
            $deadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
            do {
                $adapter = Get-NetAdapter | Where-Object { ($_.MacAddress -replace '[:-]', '') -eq $normalized } | Select-Object -First 1
                if ($null -eq $adapter) { Start-Sleep -Seconds 2 }
            } while ($null -eq $adapter -and [DateTimeOffset]::UtcNow -lt $deadline)
            if ($null -eq $adapter) { throw 'M3A_SPLIT_GUEST_ISOLATED_ADAPTER_MISSING.' }
            Set-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -Dhcp Disabled -Forwarding Disabled -AutomaticMetric Disabled -InterfaceMetric 5000
            Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
            Get-NetRoute -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object DestinationPrefix -eq '0.0.0.0/0' | Remove-NetRoute -Confirm:$false
            New-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -IPAddress $Address -PrefixLength $Prefix -AddressFamily IPv4 | Out-Null
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ResetServerAddresses
            $profileDeadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
            do {
                $profile = Get-NetConnectionProfile -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
                if ($null -eq $profile) { Start-Sleep -Seconds 1 }
            } while ($null -eq $profile -and [DateTimeOffset]::UtcNow -lt $profileDeadline)
            if ($null -eq $profile) { throw 'M3A_SPLIT_GUEST_CONNECTION_PROFILE_MISSING.' }
            Set-NetConnectionProfile -InterfaceIndex $adapter.InterfaceIndex -NetworkCategory Private
            $defaultRoutes = @(Get-NetRoute -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object DestinationPrefix -eq '0.0.0.0/0')
            $dns = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses)
            $ipInterface = Get-NetIPInterface -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4
            $managementDefault = @(Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -and $_.InterfaceIndex -ne $adapter.InterfaceIndex })
            [pscustomobject]@{
                InterfaceAlias = $adapter.Name; InterfaceIndex = $adapter.InterfaceIndex; MacAddress = $adapter.MacAddress
                DefaultGatewayCount = $defaultRoutes.Count; DnsServerCount = $dns.Count; Forwarding = [string]$ipInterface.Forwarding
                ManagementDefaultRouteCount = $managementDefault.Count
                ManagementInternetReachable = [bool](Test-NetConnection github.com -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue)
            }
        }
    }
    finally { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    $state.guestInterfaceAlias = [string]$guest.InterfaceAlias; $state.guestInterfaceIndex = [uint32]$guest.InterfaceIndex
    Assert-M3ANetworkEndpointContract -DefaultGatewayCount $guest.DefaultGatewayCount -DnsServerCount $guest.DnsServerCount -Forwarding ([string]$guest.Forwarding) -NatCount 0 -ErrorCode 'M3A_SPLIT_GUEST_ISOLATION_CONTRACT_INVALID.'
    if ($guest.ManagementDefaultRouteCount -lt 1 -or -not [bool]$guest.ManagementInternetReachable) { throw 'M3A_SPLIT_VM_MANAGEMENT_CONNECTIVITY_LOST.' }

    $profile = $null
    $profileDeadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do {
        $profile = Get-NetConnectionProfile -InterfaceIndex $hostAdapter.InterfaceIndex -ErrorAction SilentlyContinue
        if ($null -eq $profile) { Start-Sleep -Seconds 1 }
    } while ($null -eq $profile -and [DateTimeOffset]::UtcNow -lt $profileDeadline)
    if ($null -eq $profile) { throw 'M3A_SPLIT_FIREWALL_PROFILE_UNRESOLVED_DEDICATED_SWITCH_REQUIRED.' }
    Set-NetConnectionProfile -InterfaceIndex $hostAdapter.InterfaceIndex -NetworkCategory Private
    $hostDefault = @(Get-NetRoute -InterfaceIndex $hostAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object DestinationPrefix -eq '0.0.0.0/0')
    $hostDns = @(Get-DnsClientServerAddress -InterfaceIndex $hostAdapter.InterfaceIndex -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses)
    $hostIpInterface = Get-NetIPInterface -InterfaceIndex $hostAdapter.InterfaceIndex -AddressFamily IPv4
    $nat = @(Get-NetNat -ErrorAction SilentlyContinue | Where-Object { [string]$_.InternalIPInterfaceAddressPrefix -eq "$NetworkAddress/$PrefixLength" })
    Assert-M3ANetworkEndpointContract -DefaultGatewayCount $hostDefault.Count -DnsServerCount $hostDns.Count -Forwarding ([string]$hostIpInterface.Forwarding) -NatCount $nat.Count -ErrorCode 'M3A_SPLIT_HOST_ISOLATION_CONTRACT_INVALID.'
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $pending = $client.BeginConnect($VmAddress, 9, $null, $null)
        $null = $pending.AsyncWaitHandle.WaitOne(1500)
    }
    catch { }
    finally { $client.Dispose() }
    Start-Sleep -Milliseconds 500
    $neighbor = Get-NetNeighbor -InterfaceIndex $hostAdapter.InterfaceIndex -IPAddress $VmAddress -ErrorAction SilentlyContinue
    $expectedMac = ([string]$mac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    $actualMac = if ($neighbor) { ([string]$neighbor.LinkLayerAddress -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() } else { '' }
    if ($null -eq $neighbor -or [string]$neighbor.State -in @('Unreachable', 'Incomplete') -or $actualMac -ne $expectedMac) { throw 'M3A_SPLIT_HOST_TO_VM_LAYER2_CONNECTIVITY_FAILED.' }
    $state.hostConnectionProfile = 'Private'; $state.hostToVmConnectivity = 'PASS'; $state.vmManagementInternet = 'PASS'
    Write-M3ANetworkJson $state $StatePath
    return [pscustomobject]$state
    }
    catch {
        $networkFailure = $_
        try { Remove-M3AIsolatedNetwork -StatePath $StatePath -RollbackPath $RollbackPath | Out-Null } catch { }
        throw $networkFailure
    }
}

function Remove-M3AIsolatedNetwork {
    param([Parameter(Mandatory)] [string] $StatePath, [Parameter(Mandatory)] [string] $RollbackPath)
    if (-not (Test-Path -LiteralPath $StatePath)) { return $true }
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if ($state.firewallRule) { Get-NetFirewallRule -DisplayName ([string]$state.firewallRule) -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
    foreach ($profile in @($state.originalFirewallProfiles)) { Set-NetFirewallProfile -Name ([string]$profile.Name) -Enabled ([string]$profile.Enabled) }
    if ([bool]$state.tailscale.wasEnabled) {
        if ($state.tailscale.pnpDeviceId) { Enable-PnpDevice -InstanceId ([string]$state.tailscale.pnpDeviceId) -Confirm:$false -ErrorAction SilentlyContinue }
        Get-NetAdapter -Name Tailscale -ErrorAction SilentlyContinue | Enable-NetAdapter -Confirm:$false
        $tailscaleDeadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
        do {
            $tailscaleStatus = Get-NetAdapter -Name Tailscale -ErrorAction SilentlyContinue
            if ($null -ne $tailscaleStatus -and [string]$tailscaleStatus.AdminStatus -eq 'Up' -and [string]$tailscaleStatus.Status -eq 'Up') { break }
            Start-Sleep -Milliseconds 500
        } while ([DateTimeOffset]::UtcNow -lt $tailscaleDeadline)
    }
    $vm = Get-VM -Id ([guid]$state.vmId) -ErrorAction SilentlyContinue
    if ($null -ne $vm) {
        Get-VMNetworkAdapter -VM $vm -Name ([string]$state.vmNicName) -ErrorAction SilentlyContinue | Where-Object { [string]$_.SwitchName -eq [string]$state.switchName } | Remove-VMNetworkAdapter -Confirm:$false
    }
    Get-VMSwitch -Name ([string]$state.switchName) -ErrorAction SilentlyContinue | Where-Object { [string]$_.SwitchType -eq 'Internal' } | Remove-VMSwitch -Force
    $removalDeadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    do {
        $remainingSwitch = Get-VMSwitch -Name ([string]$state.switchName) -ErrorAction SilentlyContinue
        $remainingVmNic = if ($null -ne $vm) { Get-VMNetworkAdapter -VM $vm -Name ([string]$state.vmNicName) -ErrorAction SilentlyContinue } else { $null }
        if ($null -eq $remainingSwitch -and $null -eq $remainingVmNic) { break }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $removalDeadline)
    $switches = @(Get-VMSwitch -ErrorAction SilentlyContinue)
    $adapters = if ($null -ne $vm) { @(Get-VMNetworkAdapter -VM $vm) } else { @() }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -Name Domain,Private,Public | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Enabled = [bool]$_.Enabled } })
    $tailscale = Get-NetAdapter -Name Tailscale -ErrorAction SilentlyContinue
    $restored = Test-M3ANetworkStateRestored $state $switches $adapters $profiles $tailscale
    if ($restored) {
        Unregister-ScheduledTask -TaskName ([string]$state.rollbackTask) -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $RollbackPath -Force -ErrorAction SilentlyContinue
    }
    return $restored
}

Export-ModuleMember -Function Test-M3AAddressInSubnet, Assert-M3AIsolatedAddressContract, Assert-M3AIsolatedSubnetAvailable, Assert-M3AIsolatedSubnetRecordsAvailable, Assert-M3ANetworkEndpointContract, Assert-M3AInternalSwitch, Test-M3ANetworkStateRestored, Disable-M3ATailscaleForIsolation, Set-M3ANetworkFirewallRuleState, Save-M3ANetworkInventory, New-M3AIsolatedNetwork, Remove-M3AIsolatedNetwork

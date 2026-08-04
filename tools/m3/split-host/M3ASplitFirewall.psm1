Set-StrictMode -Version Latest

function ConvertTo-M3AFirewallProfileName {
    param([Parameter(Mandatory)] $NetworkCategory)

    switch ([string]$NetworkCategory) {
        'Public' { return 'Public' }
        '0' { return 'Public' }
        'Private' { return 'Private' }
        '1' { return 'Private' }
        'DomainAuthenticated' { return 'Domain' }
        '2' { return 'Domain' }
        default { throw "M3A_SPLIT_FIREWALL_NETWORK_CATEGORY_UNSUPPORTED: $NetworkCategory." }
    }
}

function Resolve-M3AFirewallProfileSelection {
    param(
        [Parameter(Mandatory)] [uint32] $InterfaceIndex,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $ConnectionProfiles,
        [Parameter(Mandatory)] [object[]] $FirewallProfiles
    )

    $interfaceProfiles = @($ConnectionProfiles | Where-Object { [uint32]$_.InterfaceIndex -eq $InterfaceIndex })
    if ($interfaceProfiles.Count -ne 1) {
        throw 'M3A_SPLIT_FIREWALL_PROFILE_UNRESOLVED_DEDICATED_SWITCH_REQUIRED.'
    }

    $profileName = ConvertTo-M3AFirewallProfileName -NetworkCategory $interfaceProfiles[0].NetworkCategory
    $shared = @($ConnectionProfiles | Where-Object {
        [uint32]$_.InterfaceIndex -ne $InterfaceIndex -and
        (ConvertTo-M3AFirewallProfileName -NetworkCategory $_.NetworkCategory) -eq $profileName
    })
    if ($shared.Count -ne 0) {
        throw 'M3A_SPLIT_FIREWALL_PROFILE_SHARED_DEDICATED_SWITCH_REQUIRED.'
    }

    $firewallProfile = @($FirewallProfiles | Where-Object { [string]$_.Name -eq $profileName })
    if ($firewallProfile.Count -ne 1) {
        throw "M3A_SPLIT_FIREWALL_PROFILE_STATE_UNAVAILABLE: $profileName."
    }

    return [pscustomobject]@{
        InterfaceIndex = $InterfaceIndex
        InterfaceAlias = [string]$interfaceProfiles[0].InterfaceAlias
        NetworkCategory = [string]$interfaceProfiles[0].NetworkCategory
        ProfileName = $profileName
        OriginallyEnabled = [bool]$firewallProfile[0].Enabled
    }
}

function Test-M3AFirewallProfileStateRestored {
    param(
        [Parameter(Mandatory)] [object[]] $OriginalStates,
        [Parameter(Mandatory)] [object[]] $CurrentProfiles
    )

    foreach ($original in $OriginalStates) {
        $current = @($CurrentProfiles | Where-Object { [string]$_.Name -eq [string]$original.Name })
        if ($current.Count -ne 1 -or [bool]$current[0].Enabled -ne [bool]$original.Enabled) { return $false }
    }
    return $true
}

Export-ModuleMember -Function ConvertTo-M3AFirewallProfileName, Resolve-M3AFirewallProfileSelection, Test-M3AFirewallProfileStateRestored

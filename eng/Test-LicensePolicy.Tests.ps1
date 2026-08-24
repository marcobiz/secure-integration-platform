[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'LicensePolicy.psm1') -Force

function Assert-Equal([string] $Name, [object] $Actual, [object] $Expected) {
    if ($Actual -cne $Expected) { throw "$Name expected=$Expected actual=$Actual" }
    Write-Host "$Name PASS"
}

Assert-Equal 'ALPHA_LIC_all_tracked_paths_have_one_policy' (@(Get-RepositoryLicensePolicy 'src/Gateway/Gateway.Api/Program.cs').Count) 1
Assert-Equal 'ALPHA_LIC_apache_override_precedes_default_mpl' (Get-RepositoryLicensePolicy 'sdk/dotnet/Broker.Sdk/Broker.Sdk.csproj').spdxExpression 'Apache-2.0'
Assert-Equal 'ALPHA_LIC_generic_reference_expression_is_exact' (Get-RepositoryLicensePolicy 'docs/connectors/examples/sample.json').spdxExpression 'MPL-2.0 OR Apache-2.0'
Assert-Equal 'ALPHA_LIC_tests_default_to_mpl' (Get-RepositoryLicensePolicy 'tests/unit/Example.Tests/Test.cs').spdxExpression 'MPL-2.0'

$ambiguousRejected = $false
try { Assert-RepositorySpdxExpression 'MPL / Apache' } catch { $ambiguousRejected = $_.Exception.Message -match 'AMBIGUOUS' }
Assert-Equal 'ALPHA_LIC_ambiguous_expression_is_rejected' $ambiguousRejected $true
$aggregateRejectedWithoutContext = $false
try { Assert-RepositorySpdxExpression 'MPL-2.0 AND Apache-2.0' } catch { $aggregateRejectedWithoutContext = $true }
Assert-Equal 'ALPHA_LIC_and_is_aggregate_only' $aggregateRejectedWithoutContext $true
Assert-RepositorySpdxExpression 'MPL-2.0 AND Apache-2.0' -AllowAggregate
Write-Host 'ALPHA_LIC_license_policy_self_tests PASS'

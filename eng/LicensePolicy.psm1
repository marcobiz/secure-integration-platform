Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ApacheExactPaths = @(
    'docs/api/broker-ipc.md',
    'docs/api/gateway-api.md',
    'docs/api/gateway-openapi.yaml',
    'docs/api/runtime-wire-codes.json',
    'docs/connectors/connector-definition.schema.json',
    'docs/connectors/connector-specification.md'
)

function ConvertTo-LicensePolicyPath {
    param([Parameter(Mandatory = $true)][string] $Path)
    $normalized = $Path.Replace('\', '/').TrimStart('./')
    if ([string]::IsNullOrWhiteSpace($normalized) -or $normalized.Contains('//') -or $normalized.StartsWith('../', [StringComparison]::Ordinal)) {
        throw "LICENSE_POLICY_PATH_INVALID: $Path"
    }
    return $normalized
}

function Get-RepositoryLicensePolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string] $Path)

    $normalized = ConvertTo-LicensePolicyPath -Path $Path
    if ($normalized.StartsWith('docs/connectors/examples/', [StringComparison]::Ordinal)) {
        return [pscustomobject]@{ path = $normalized; rule = 'generic-reference'; spdxExpression = 'MPL-2.0 OR Apache-2.0'; precedence = 1 }
    }

    $apacheSubtree = $normalized.StartsWith('sdk/', [StringComparison]::Ordinal) -or
        $normalized.StartsWith('src/Shared/SecureIntegration.Contracts/', [StringComparison]::Ordinal) -or
        $normalized.StartsWith('samples/', [StringComparison]::Ordinal) -or
        $normalized.StartsWith('src/Providers/Synthetic/', [StringComparison]::Ordinal)
    if ($apacheSubtree -or $script:ApacheExactPaths -ccontains $normalized) {
        return [pscustomobject]@{ path = $normalized; rule = 'apache-override'; spdxExpression = 'Apache-2.0'; precedence = 2 }
    }

    return [pscustomobject]@{ path = $normalized; rule = 'repository-default'; spdxExpression = 'MPL-2.0'; precedence = 3 }
}

function Assert-RepositorySpdxExpression {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Expression,
        [switch] $AllowAggregate
    )

    if ($Expression.Contains('MPL / Apache')) { throw 'LICENSE_POLICY_AMBIGUOUS_EXPRESSION' }
    $allowed = @('MPL-2.0', 'Apache-2.0', 'MPL-2.0 OR Apache-2.0')
    if ($AllowAggregate) { $allowed += 'MPL-2.0 AND Apache-2.0' }
    if ($allowed -cnotcontains $Expression) { throw "LICENSE_POLICY_SPDX_EXPRESSION_INVALID: $Expression" }
}

Export-ModuleMember -Function Get-RepositoryLicensePolicy, Assert-RepositorySpdxExpression

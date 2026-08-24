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

function Assert-LicensePolicyGitPathIdentity {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Path,
        [Parameter(Mandatory = $true)][Collections.Generic.HashSet[string]] $TrackedPathSet
    )

    if ([string]::IsNullOrEmpty($Path)) { throw 'LICENSE_POLICY_PATH_EMPTY' }
    foreach ($character in $Path.ToCharArray()) {
        if ([char]::IsControl($character)) { throw 'LICENSE_POLICY_PATH_CONTROL_CHARACTER' }
    }
    if ($Path.StartsWith('/', [StringComparison]::Ordinal) -or $Path.StartsWith('\', [StringComparison]::Ordinal)) {
        throw 'LICENSE_POLICY_PATH_ROOTED'
    }
    if ($Path -cmatch '^[A-Za-z]:') { throw 'LICENSE_POLICY_PATH_DRIVE_QUALIFIED' }
    if ($Path.Contains('\')) { throw 'LICENSE_POLICY_PATH_BACKSLASH' }
    if ($Path.Contains(':')) { throw 'LICENSE_POLICY_PATH_ADS_OR_COLON' }
    if ($Path.EndsWith('/', [StringComparison]::Ordinal)) { throw 'LICENSE_POLICY_PATH_TRAILING_SLASH' }
    if ($Path.Contains('//')) { throw 'LICENSE_POLICY_PATH_EMPTY_SEGMENT' }
    foreach ($segment in $Path.Split('/')) {
        if ($segment -ceq '.' -or $segment -ceq '..') { throw 'LICENSE_POLICY_PATH_TRAVERSAL_SEGMENT' }
    }
    if (-not $TrackedPathSet.Contains($Path)) { throw 'LICENSE_POLICY_PATH_NOT_TRACKED' }
}

function Get-RepositoryLicensePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string] $Path,
        [Parameter(Mandatory = $true)][Collections.Generic.HashSet[string]] $TrackedPathSet
    )

    Assert-LicensePolicyGitPathIdentity -Path $Path -TrackedPathSet $TrackedPathSet
    $explicitMatches = [Collections.Generic.List[object]]::new()
    if ($Path.StartsWith('docs/connectors/examples/', [StringComparison]::Ordinal)) {
        $explicitMatches.Add([pscustomobject]@{ path = $Path; rule = 'generic-reference'; spdxExpression = 'MPL-2.0 OR Apache-2.0'; precedence = 1 })
    }

    $apacheSubtree = $Path.StartsWith('sdk/', [StringComparison]::Ordinal) -or
        $Path.StartsWith('src/Shared/SecureIntegration.Contracts/', [StringComparison]::Ordinal) -or
        $Path.StartsWith('samples/', [StringComparison]::Ordinal) -or
        $Path.StartsWith('src/Providers/Synthetic/', [StringComparison]::Ordinal)
    if ($apacheSubtree -or $script:ApacheExactPaths -ccontains $Path) {
        $explicitMatches.Add([pscustomobject]@{ path = $Path; rule = 'apache-override'; spdxExpression = 'Apache-2.0'; precedence = 2 })
    }

    if ($explicitMatches.Count -gt 1) { throw "LICENSE_POLICY_EXPLICIT_RULE_OVERLAP: $Path" }
    if ($explicitMatches.Count -eq 1) { return $explicitMatches[0] }
    return [pscustomobject]@{ path = $Path; rule = 'repository-default'; spdxExpression = 'MPL-2.0'; precedence = 3 }
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

[CmdletBinding()]
param([string] $SbomDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) '.artifacts\sbom'))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$fixture = Join-Path (Join-Path $root '.artifacts') ("sbom-mode-test-{0}" -f [Guid]::NewGuid().ToString('N'))

try {
    New-Item -ItemType Directory -Path $fixture | Out-Null
    Get-ChildItem -LiteralPath $SbomDirectory -File |
        Where-Object Name -ne 'gateway-container.spdx.json' |
        Copy-Item -Destination $fixture

    $failedClosed = $false
    try {
        & (Join-Path $PSScriptRoot 'validate-sbom.ps1') -SbomDirectory $fixture
    } catch {
        if ($_.Exception.Message -eq 'SBOM_ARTIFACT_MISSING_gateway-container.spdx.json') {
            $failedClosed = $true
        } else {
            throw
        }
    }
    if (-not $failedClosed) { throw 'SBOM_CONTAINER_REQUIREMENT_DID_NOT_FAIL_CLOSED' }

    & (Join-Path $PSScriptRoot 'validate-sbom.ps1') -SbomDirectory $fixture -SkipContainer

    $generalWorkflow = Get-Content -LiteralPath (Join-Path $root '.github\workflows\ci.yml') -Raw
    $m5Workflow = Get-Content -LiteralPath (Join-Path $root '.github\workflows\m5-admin-ui.yml') -Raw
    if ($generalWorkflow -notmatch '(?m)generate-sbom\.ps1\s+-SkipContainer\s*$') { throw 'SBOM_WINDOWS_MODE_NOT_EXPLICIT' }
    if ($m5Workflow -notmatch 'anchore/sbom-action/download-syft@v0') { throw 'SBOM_LINUX_TOOL_NOT_PINNED' }
    if ($m5Workflow -match '(?m)generate-sbom\.ps1[^\r\n]*-SkipContainer') { throw 'SBOM_M5_CONTAINER_GATE_BYPASSED' }

    Write-Host 'SBOM_MODE_REGRESSION_PASS'
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}

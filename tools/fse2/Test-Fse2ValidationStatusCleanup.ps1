[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\\..')).Path
$markerName = '.m5-quickstart-owner'
$markerValue = 'secure-integration-m5-quickstart-artifacts-v1'

function Assert-True {
    param([Parameter(Mandatory = $true)][bool] $Condition)
    if (-not $Condition) { throw 'FSE2_PILOT_CLEANUP_ASSERTION_FAILED' }
}

function Test-PilotStopControlFlow {
    $controlRoot = Join-Path ([IO.Path]::GetTempPath()) ('fse2-pilot-cleanup-test-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $controlRoot | Out-Null
    try {
        # Execute the unchanged cleanup scripts in an isolated source layout. Only
        # process launch and Docker are simulated; filesystem ownership/deletion is real.
        $pilotRepository = Join-Path $controlRoot 'repository'
        foreach ($relative in @('tools\fse2\Invoke-Fse2ValidationStatus.ps1',
            'tools\fse2\Invoke-Fse2LocalProviderLab.ps1', 'tools\fse2\Fse2PathPolicy.psm1',
            'tools\m5\Invoke-M5Quickstart.ps1', 'deploy\m3\docker-compose.m3a.yml',
            'deploy\m5\docker-compose.m5.yml', 'deploy\fse2\docker-compose.fse2-local.yml')) {
            $destination = Join-Path $pilotRepository $relative
            New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $repository $relative) -Destination $destination
        }
        $pilotScript = Join-Path $pilotRepository 'tools\fse2\Invoke-Fse2ValidationStatus.ps1'
        $pilotArtifacts = Join-Path $pilotRepository '.artifacts\m5\fse2-validation-status'
        $pilotCompose = @('deploy\m3\docker-compose.m3a.yml', 'deploy\m5\docker-compose.m5.yml',
            'deploy\fse2\docker-compose.fse2-local.yml') | ForEach-Object { (Join-Path $pilotRepository $_).Replace('\', '/') }
        $pilotProject = 'secure-integration-m5-quickstart'
        $pilotState = @{ Resources = @{}; Delegations = 0; Removals = 0; EnumerationFails = $false }
        function powershell.exe {
            $fileIndex = [Array]::IndexOf($args, '-File')
            Assert-True ($fileIndex -ge 0)
            $child = $args[$fileIndex + 1]
            Assert-True ($child -in @((Join-Path $pilotRepository 'tools\fse2\Invoke-Fse2LocalProviderLab.ps1'),
                (Join-Path $pilotRepository 'tools\m5\Invoke-M5Quickstart.ps1')))
            Assert-True ($args -contains 'Stop')
            Assert-True ($args -contains $pilotArtifacts)
            $pilotState.Delegations++
            $childParameters = @{}
            for ($i = $fileIndex + 2; $i -lt $args.Length; $i += 2) {
                Assert-True ($args[$i] -in @('-Phase', '-QuickstartArtifactRoot', '-ArtifactRoot', '-AdditionalComposeFile'))
                $childParameters[$args[$i].TrimStart('-')] = $args[$i + 1]
            }
            try { & $child @childParameters }
            catch { $global:LASTEXITCODE = 1 }
        }
        function docker {
            $global:LASTEXITCODE = 0
            $kind = if ($args[0] -in @('network', 'volume')) { $args[0] } else { 'container' }
            if ($args[0] -eq 'ps' -or $args[1] -eq 'ls') {
                if ($pilotState.EnumerationFails) { $global:LASTEXITCODE = 1; return }
                Assert-True ($args -contains ('label=com.docker.compose.project=' + $pilotProject))
                foreach ($entry in $pilotState.Resources.GetEnumerator()) {
                    if ($entry.Value.Kind -eq $kind -and
                        (-not ($args -contains 'label=com.docker.compose.service=gateway') -or $entry.Key -eq 'gateway')) { $entry.Key }
                }
            } elseif ($args -contains 'inspect') {
                $id = $args[[Array]::IndexOf($args, 'inspect') + 1]
                $resource = $pilotState.Resources[$id]
                Assert-True ($null -ne $resource)
                if ($args[-1] -eq '{{index .Config.Labels "com.docker.compose.project.config_files"}}') { $resource.Compose }
                else { @{ 'com.docker.compose.project' = $resource.Project } | ConvertTo-Json -Compress }
            } elseif ($args -contains 'rm') {
                Assert-True ($pilotState.Delegations -eq 2)
                Assert-True ($pilotState.Resources.ContainsKey($args[-1]))
                $pilotState.Resources.Remove($args[-1])
                $pilotState.Removals++
            } else { throw 'M5_QUICKSTART_SAFETY_UNEXPECTED_DOCKER_COMMAND' }
        }
        Set-Alias -Name pwsh -Value powershell.exe -Scope Local
        foreach ($scenario in @('partial-bootstrap', 'partial-resources', 'normal', 'foreign-container',
            'unknown-container', 'foreign-artifact', 'missing-marker', 'foreign-network', 'enumeration-failure')) {
            $pilotState.Resources = @{}
            $pilotState.Delegations = 0
            $pilotState.Removals = 0
            $pilotState.EnumerationFails = $scenario -eq 'enumeration-failure'
            New-Item -ItemType Directory -Path (Join-Path $pilotArtifacts 'raw') -Force | Out-Null
            [IO.File]::WriteAllText((Join-Path $pilotArtifacts 'raw\partial.txt'), 'synthetic')
            if ($scenario -ne 'missing-marker') {
                $value = if ($scenario -eq 'foreign-artifact') { 'foreign' } else { $markerValue }
                [IO.File]::WriteAllText((Join-Path $pilotArtifacts $markerName), $value)
            }
            if ($scenario -in @('partial-resources', 'normal', 'foreign-container', 'unknown-container')) {
                $config = if ($scenario -eq 'foreign-container') { 'C:/foreign/compose.yml' }
                    elseif ($scenario -eq 'unknown-container') { '' } else { $pilotCompose[0..1] -join ',' }
                $pilotState.Resources['postgres'] = @{ Kind = 'container'; Project = $pilotProject; Compose = $config }
            }
            if ($scenario -in @('partial-resources', 'normal', 'missing-marker', 'foreign-network')) {
                $networkProject = if ($scenario -eq 'foreign-network') { 'foreign' } else { $pilotProject }
                $pilotState.Resources['network'] = @{ Kind = 'network'; Project = $networkProject }
                $pilotState.Resources['volume'] = @{ Kind = 'volume'; Project = $pilotProject }
            }
            if ($scenario -eq 'normal') {
                $pilotState.Resources['gateway'] = @{ Kind = 'container'; Project = $pilotProject; Compose = $pilotCompose -join ',' }
            }
            $resourceCount = $pilotState.Resources.Count
            $output = @(& $pilotScript -Phase Stop)
            if ($scenario -in @('partial-bootstrap', 'partial-resources', 'normal')) {
                Assert-True ($LASTEXITCODE -eq 0)
                Assert-True ($pilotState.Delegations -eq 2 -and $pilotState.Removals -eq $resourceCount)
                Assert-True ($pilotState.Resources.Count -eq 0 -and -not (Test-Path -LiteralPath $pilotArtifacts))
                $output = @(& $pilotScript -Phase Stop)
                Assert-True ($LASTEXITCODE -eq 0 -and $pilotState.Delegations -eq 4)
                Assert-True (-not (Test-Path -LiteralPath $pilotArtifacts))
            } else {
                Assert-True ($LASTEXITCODE -ne 0)
                $expectedDelegations = if ($scenario -in @('foreign-artifact', 'foreign-network')) { 2 } else { 0 }
                $expectedCode = if ($scenario -in @('foreign-container', 'unknown-container')) { 'FSE2_PILOT_FOREIGN_STACK_DENIED' }
                    elseif ($expectedDelegations -eq 2) { 'FSE2_PILOT_COMMAND_FAILED_SEE_BOUNDED_RESULT' }
                    else { 'FSE2_PILOT_OWNERSHIP_UNVERIFIED' }
                Assert-True ($pilotState.Delegations -eq $expectedDelegations -and $output -contains $expectedCode)
                Assert-True ($pilotState.Resources.Count -eq $resourceCount -and $pilotState.Removals -eq 0)
                Assert-True ((Get-Content -LiteralPath (Join-Path $pilotArtifacts 'raw\partial.txt') -Raw) -ceq 'synthetic')
                # Fixture disposal only, after the actual Stop has demonstrably preserved it.
                Assert-True ($pilotArtifacts -ceq (Join-Path $pilotRepository '.artifacts\m5\fse2-validation-status'))
                Remove-Item -LiteralPath $pilotArtifacts -Recurse -Force
            }
            Write-Host "FSE2_PILOT_CLEANUP_$scenario PASS"
        }
        $pilotState.EnumerationFails = $false
        $pilotState.Resources = @{}
        $pilotState.Delegations = 0
        foreach ($phase in @('Configure', 'Propose', 'Approve', 'Verify', 'Validate-Fhir', 'Validate-Cda',
            'Status-Workflow', 'Status-Trace', 'Audit', 'Restart')) {
            $output = @(& $pilotScript -Phase $phase)
            Assert-True ($LASTEXITCODE -ne 0 -and $output -contains 'FSE2_PILOT_START_REQUIRED')
            Assert-True ($pilotState.Delegations -eq 0)
        }
        Write-Host 'FSE2_PILOT_OTHER_COMMANDS_REQUIRE_GATEWAY PASS'
    }
    finally {
        $control = [IO.Path]::GetFullPath($controlRoot)
        $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $control.StartsWith($tempPrefix, [StringComparison]::Ordinal) -or
            -not ([IO.Path]::GetFileName($control)).StartsWith('fse2-pilot-cleanup-test-', [StringComparison]::Ordinal)) {
            throw 'FSE2_PILOT_TEST_CLEANUP_DENIED'
        }
        if (Test-Path -LiteralPath $control) { Remove-Item -LiteralPath $control -Recurse -Force }
    }
}

try {
    Test-PilotStopControlFlow
    Write-Host 'FSE2_PILOT_CLEANUP_TEST_PASS'
    exit 0
}
catch {
    [Console]::Error.WriteLine('FSE2_PILOT_CLEANUP_TEST_FAILED')
    exit 1
}

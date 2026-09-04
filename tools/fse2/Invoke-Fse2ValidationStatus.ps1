[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Start', 'Configure', 'Propose', 'Approve', 'Verify', 'Validate-Fhir', 'Validate-Cda', 'Status-Workflow', 'Status-Trace', 'Audit', 'Restart', 'Stop')]
    [string] $Phase,
    [string] $ProviderRoot,
    [string] $SettingsPath,
    [string] $Identifier,
    [string] $DotNetPath = 'dotnet'
)

# Windows PowerShell 5.1. Reuses the owned M5/LocalPkcs12 lifecycle and normal APIs.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$artifacts = Join-Path $root '.artifacts\m5\fse2-validation-status'
$binary = Join-Path $root '.artifacts\fse2-pilot-bin'
$project = 'secure-integration-m5-quickstart'
$localProvider = Join-Path $PSScriptRoot 'Invoke-Fse2LocalProviderLab.ps1'
$powershell = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'powershell.exe' } else { 'pwsh' }

function Invoke-Checked {
    param([string] $File, [string[]] $Arguments)
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'FSE2_PILOT_COMMAND_FAILED_SEE_BOUNDED_RESULT' }
}

function Assert-PilotContainerOwnership {
    param([string] $Id, [switch] $AllowBootstrap)
    $files = & docker inspect $Id --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}'
    if ($LASTEXITCODE -ne 0) { throw 'FSE2_PILOT_OWNERSHIP_UNVERIFIED' }
    $expected = @('deploy\m3\docker-compose.m3a.yml', 'deploy\m5\docker-compose.m5.yml', 'deploy\fse2\docker-compose.fse2-local.yml') |
        ForEach-Object { [IO.Path]::GetFullPath((Join-Path $root $_)).Replace('\', '/') }
    $actual = @(([string]$files -split ',') | ForEach-Object { $_.Replace('\', '/') })
    # Start first creates the base M5 stack, then adds the FSE2 overlay to Gateway.
    if ($AllowBootstrap -and $actual.Count -eq 2) { $expected = $expected[0..1] }
    if (@(Compare-Object $expected $actual).Count -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $artifacts '.m5-quickstart-owner'))) {
        throw 'FSE2_PILOT_FOREIGN_STACK_DENIED'
    }
}

function Get-OwnedGateway {
    $containers = @(& docker ps -aq --filter ('label=com.docker.compose.project=' + $project) --filter 'label=com.docker.compose.service=gateway')
    if ($LASTEXITCODE -ne 0 -or $containers.Count -ne 1) { throw 'FSE2_PILOT_START_REQUIRED' }
    $id = [string]$containers[0]
    Assert-PilotContainerOwnership -Id $id
    return $id.Trim()
}

try {
    if ($Phase -eq 'Start') {
        if ([string]::IsNullOrWhiteSpace($ProviderRoot)) { throw 'FSE2_PILOT_PROVIDER_ROOT_REQUIRED' }
        if (-not [IO.Path]::IsPathRooted($DotNetPath)) { $DotNetPath = (Get-Command $DotNetPath -CommandType Application -ErrorAction Stop).Source }
        $existing = @(& docker ps -aq --filter ('label=com.docker.compose.project=' + $project))
        if ($LASTEXITCODE -ne 0 -or $existing.Count -ne 0) { throw 'FSE2_PILOT_STACK_ALREADY_EXISTS_USE_CONFIGURE_OR_STOP' }
        $dirty = & git -C $root status --porcelain --untracked-files=normal
        if ($LASTEXITCODE -ne 0 -or -not [string]::IsNullOrWhiteSpace(($dirty -join ''))) { throw 'FSE2_PILOT_COMMIT_CODE_BEFORE_LIVE' }
        $head = & git -C $root rev-parse HEAD
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_PILOT_HEAD_UNAVAILABLE' }
        Invoke-Checked $DotNetPath @('publish', (Join-Path $PSScriptRoot 'OfficialTestProvisioner\OfficialTestProvisioner.csproj'), '-c', 'Release', '-o', $binary, '-p:RestoreLockedMode=true', '--nologo', '--verbosity', 'quiet')
        Invoke-Checked $powershell @('-NoProfile', '-File', $localProvider, '-Phase', 'Start',
            '-ProviderManifestPath', (Join-Path $ProviderRoot 'manifest.json'), '-MaterialDirectory', (Join-Path $ProviderRoot 'material'),
            '-ConnectorScope', 'fse2-organization-current-spec', '-QuickstartArtifactRoot', $artifacts, '-DotNetPath', $DotNetPath)
        $gateway = Get-OwnedGateway
        $image = & docker inspect $gateway --format '{{.Image}}'
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_PILOT_IMAGE_UNAVAILABLE' }
        $stamp = @{ executedHead = [string]$head; gatewayImage = [string]$image;
            provisionerSha256 = (Get-FileHash -LiteralPath (Join-Path $binary 'SecureIntegration.Tools.Fse2.OfficialTestProvisioner.dll') -Algorithm SHA256).Hash }
        [IO.File]::WriteAllText((Join-Path $artifacts 'fse2-build.json'), ($stamp | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
        Write-Output ($stamp | ConvertTo-Json -Compress)
        Write-Output 'FSE2_PILOT_STARTED; NEXT=Configure; DOCUMENT_DISPATCH=0'
        return
    }

    if ($Phase -eq 'Stop') {
        # A partial Start need not have a Gateway. Keep the checkout boundary before
        # delegating marker/path checks and all deletion to the existing M5 cleanup.
        $containers = @(& docker ps -aq --filter ('label=com.docker.compose.project=' + $project))
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_PILOT_OWNERSHIP_UNVERIFIED' }
        $networks = @(& docker network ls -q --filter ('label=com.docker.compose.project=' + $project))
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_PILOT_OWNERSHIP_UNVERIFIED' }
        $volumes = @(& docker volume ls -q --filter ('label=com.docker.compose.project=' + $project))
        if ($LASTEXITCODE -ne 0) { throw 'FSE2_PILOT_OWNERSHIP_UNVERIFIED' }
        if ($containers.Count + $networks.Count + $volumes.Count -gt 0 -and
            -not (Test-Path -LiteralPath (Join-Path $artifacts '.m5-quickstart-owner') -PathType Leaf)) {
            throw 'FSE2_PILOT_OWNERSHIP_UNVERIFIED'
        }
        foreach ($id in $containers) { Assert-PilotContainerOwnership -Id $id -AllowBootstrap }
        Invoke-Checked $powershell @('-NoProfile', '-File', $localProvider, '-Phase', 'Stop', '-QuickstartArtifactRoot', $artifacts)
        return
    }
    $gateway = Get-OwnedGateway
    if ($Phase -eq 'Restart') {
        Invoke-Checked 'docker' @('restart', $gateway)
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
        do {
            $health = & docker inspect $gateway --format '{{.State.Health.Status}}'
            if ($LASTEXITCODE -ne 0) { throw 'FSE2_PILOT_RESTART_INSPECTION_FAILED' }
            if ([string]$health -eq 'healthy') { Write-Output 'FSE2_PILOT_RESTARTED; NEXT=Status-Workflow; DOCUMENT_DISPATCH=0'; return }
            Start-Sleep -Seconds 2
        } while ([DateTimeOffset]::UtcNow -lt $deadline)
        throw 'FSE2_PILOT_RESTART_NOT_READY'
    }
    if ([string]::IsNullOrWhiteSpace($SettingsPath)) { throw 'FSE2_PILOT_SETTINGS_REQUIRED' }
    Import-Module (Join-Path $PSScriptRoot 'Fse2PathPolicy.psm1') -Force
    $settings = Get-Fse2PathSnapshot -Path $SettingsPath -Kind File -RepositoryRoot $root -ErrorCodePrefix 'FSE2_PILOT_SETTINGS' -MaximumBytes 16384
    $stamp = Get-Content -LiteralPath (Join-Path $artifacts 'fse2-build.json') -Raw | ConvertFrom-Json
    $hash = (Get-FileHash -LiteralPath (Join-Path $binary 'SecureIntegration.Tools.Fse2.OfficialTestProvisioner.dll') -Algorithm SHA256).Hash
    $image = & docker inspect $gateway --format '{{.Image}}'
    if ($LASTEXITCODE -ne 0 -or [string]$image -cne $stamp.gatewayImage -or $hash -cne $stamp.provisionerSha256) { throw 'FSE2_PILOT_EXECUTABLE_DRIFT' }
    $role = switch ($Phase) { 'Propose' { 'editor' }; 'Approve' { 'approver' }; default { 'security-admin' } }
    $arguments = @('run', '--rm', '--network', ('container:' + $gateway), '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
        '--user', '1654', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
        '--mount', ('type=bind,source=' + $binary + ',target=/pilot,readonly'),
        '--mount', ('type=bind,source=' + $artifacts + ',target=/artifacts'),
        '--mount', ('type=bind,source=' + (Join-Path $artifacts 'raw') + ',target=/artifacts/raw,readonly'),
        '--mount', ('type=bind,source=' + $settings.FullPath + ',target=/settings.json,readonly'),
        '--env', 'FSE2_GATEWAY_URL=https://localhost:8443/', '--env', 'FSE2_GATEWAY_CA_FILE=/artifacts/raw/certificates/ca.crt',
        '--env', 'FSE2_PILOT_ARTIFACT_ROOT=/artifacts', '--env', ('FSE2_ADMIN_DEVELOPMENT_USER=' + $role),
        '--entrypoint', 'dotnet', [string]$image, '/pilot/SecureIntegration.Tools.Fse2.OfficialTestProvisioner.dll',
        'pilot', $Phase.ToLowerInvariant(), '/settings.json')
    if (-not [string]::IsNullOrWhiteSpace($Identifier)) { $arguments += $Identifier }
    Assert-Fse2PathSnapshot -Snapshot $settings | Out-Null
    Write-Output ('FSE2_PILOT_EXECUTED_HEAD=' + $stamp.executedHead)
    Invoke-Checked 'docker' $arguments
}
catch {
    # Never render arbitrary exception text (paths, HTTP bodies, credential values).
    $code = [string]$_.Exception.Message
    if ($code -cmatch '^FSE2_[A-Z0-9_]+$') { Write-Output $code }
    else { Write-Output 'FSE2_PILOT_LOCAL_FAILURE_CHECK_PREREQUISITES' }
    exit 1
}

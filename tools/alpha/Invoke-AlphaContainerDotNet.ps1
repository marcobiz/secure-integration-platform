Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$DotNetArguments = @($args | ForEach-Object { [string]$_ })
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$artifactRoot = [IO.Path]::GetFullPath((Join-Path $root '.artifacts\m5\quickstart'))
$artifactMarker = Join-Path $artifactRoot '.m5-quickstart-owner'
$artifactMarkerValue = 'secure-integration-m5-quickstart-artifacts-v1'
$sdkImage = 'mcr.microsoft.com/dotnet/sdk:10.0.302@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0'
$containerGatewayHost = 'host.docker.internal'

function Test-ExactPath {
    param([Parameter(Mandatory = $true)][string] $Actual, [Parameter(Mandatory = $true)][string] $Expected)
    $comparison = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        [StringComparison]::OrdinalIgnoreCase
    }
    else {
        [StringComparison]::Ordinal
    }
    try { $actualFull = [IO.Path]::GetFullPath($Actual) }
    catch { return $false }
    return $actualFull.Equals([IO.Path]::GetFullPath($Expected), $comparison)
}

function Assert-OwnedArtifactRoot {
    if (-not (Test-Path -LiteralPath $artifactRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $artifactMarker -PathType Leaf)) {
        throw 'ALPHA_CONTAINER_DOTNET_ARTIFACT_ROOT_NOT_OWNED'
    }
    $item = Get-Item -LiteralPath $artifactRoot -Force
    $markerItem = Get-Item -LiteralPath $artifactMarker -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($markerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Get-Content -LiteralPath $artifactMarker -Raw) -cne $artifactMarkerValue) {
        throw 'ALPHA_CONTAINER_DOTNET_ARTIFACT_ROOT_NOT_OWNED'
    }
}

function Add-ForwardedEnvironment {
    param([Parameter(Mandatory = $true)][Collections.Generic.List[string]] $Arguments,
        [Parameter(Mandatory = $true)][string[]] $Names)
    foreach ($name in $Names) {
        if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name, 'Process'))) {
            throw 'ALPHA_CONTAINER_DOTNET_ENVIRONMENT_INCOMPLETE'
        }
        $Arguments.Add('--env')
        $Arguments.Add($name)
    }
}

try {
    if ($DotNetArguments.Count -lt 5 -or
        [string]$DotNetArguments[0] -cnotin @('build', 'run') -or
        [string]$DotNetArguments[1] -cne '--project' -or
        [string]$DotNetArguments[3] -cne '--configuration' -or
        [string]$DotNetArguments[4] -cne 'Release') {
        throw 'ALPHA_CONTAINER_DOTNET_ARGUMENTS_INVALID'
    }

    $command = [string]$DotNetArguments[0]
    $projectPath = [string]$DotNetArguments[2]
    $fixtureProject = Join-Path $root 'tools\m3\FixtureGenerator\FixtureGenerator.csproj'
    $securityProject = Join-Path $root 'tools\m3\SecurityDriver\SecurityDriver.csproj'
    $sampleProject = Join-Path $root 'samples\DirectGatewayClient\DirectGatewayClient.csproj'
    $kind = if (Test-ExactPath -Actual $projectPath -Expected $fixtureProject) { 'Fixture' }
    elseif (Test-ExactPath -Actual $projectPath -Expected $securityProject) { 'Security' }
    elseif (Test-ExactPath -Actual $projectPath -Expected $sampleProject) { 'Sample' }
    else { throw 'ALPHA_CONTAINER_DOTNET_PROJECT_DENIED' }

    if ($command -ceq 'build') {
        if ($kind -cne 'Sample' -or $DotNetArguments.Count -ne 5) {
            throw 'ALPHA_CONTAINER_DOTNET_ARGUMENTS_INVALID'
        }
    }
    elseif ($kind -ceq 'Fixture') {
        $expectedRawRoot = Join-Path $artifactRoot 'raw'
        if ($DotNetArguments.Count -ne 7 -or [string]$DotNetArguments[5] -cne '--' -or
            -not (Test-ExactPath -Actual ([string]$DotNetArguments[6]) -Expected $expectedRawRoot)) {
            throw 'ALPHA_CONTAINER_DOTNET_ARGUMENTS_INVALID'
        }
    }
    elseif ($DotNetArguments.Count -ne 5) {
        throw 'ALPHA_CONTAINER_DOTNET_ARGUMENTS_INVALID'
    }

    $containerProject = switch ($kind) {
        'Fixture' { '/src/tools/m3/FixtureGenerator/FixtureGenerator.csproj' }
        'Security' { '/src/tools/m3/SecurityDriver/SecurityDriver.csproj' }
        'Sample' { '/src/samples/DirectGatewayClient/DirectGatewayClient.csproj' }
    }

    $dockerArguments = New-Object 'Collections.Generic.List[string]'
    foreach ($argument in @(
        'run', '--rm', '--pull', 'missing',
        '--user', '1657:1657',
        '--read-only',
        '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges',
        '--pids-limit', '256',
        '--tmpfs', '/tmp:rw,exec,nosuid,size=2g',
        '--add-host', 'host.docker.internal:host-gateway',
        '--mount', ("type=bind,source=$root,target=/src,readonly"),
        '--workdir', '/src',
        '--env', 'DOTNET_CLI_HOME=/tmp/dotnet',
        '--env', 'DOTNET_CLI_TELEMETRY_OPTOUT=1',
        '--env', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1',
        '--env', 'NUGET_PACKAGES=/tmp/nuget')) {
        $dockerArguments.Add($argument)
    }

    if ($command -ceq 'run') {
        Assert-OwnedArtifactRoot
        $dockerArguments.Add('--mount')
        $dockerArguments.Add("type=bind,source=$artifactRoot,target=/artifacts")
    }

    if ($kind -ceq 'Security') {
        foreach ($argument in @(
            '--env', "M3_GATEWAY_BASE_ADDRESS=https://${containerGatewayHost}:18443/",
            '--env', 'M3_GATEWAY_CA_FILE=/artifacts/raw/certificates/ca.crt',
            '--env', 'M3_PROVISIONING_FILE=/artifacts/raw/provisioning.json',
            '--env', 'M3_SECURITY_DRIVER_PFX=/artifacts/raw/certificates/security-driver.pfx',
            '--env', 'M3_SECURITY_OUTPUT=/artifacts/enrollment-status.json',
            '--env', 'M3_SECURITY_SCOPE=smoke')) {
            $dockerArguments.Add($argument)
        }
        Add-ForwardedEnvironment -Arguments $dockerArguments -Names @('M3_CERTIFICATE_PASSWORD')
    }
    elseif ($kind -ceq 'Sample' -and $command -ceq 'run') {
        foreach ($argument in @(
            '--env', "DIRECT_GATEWAY_URL=https://${containerGatewayHost}:18443",
            '--env', 'DIRECT_GATEWAY_CA_FILE=/artifacts/raw/certificates/ca.crt')) {
            $dockerArguments.Add($argument)
        }
        Add-ForwardedEnvironment -Arguments $dockerArguments -Names @(
            'DIRECT_GATEWAY_ACTIVATION_CODE_ID',
            'DIRECT_GATEWAY_ACTIVATION_CODE',
            'DIRECT_GATEWAY_CONNECTOR_ID',
            'DIRECT_GATEWAY_OPERATION_ID',
            'DIRECT_GATEWAY_CORRELATION_ID')
    }

    $dockerArguments.Add($sdkImage)
    $containerCommand = if ($command -ceq 'build') {
        @('dotnet', 'build', $containerProject, '--configuration', 'Release', '--artifacts-path', '/tmp/artifacts')
    }
    else {
        @('dotnet', 'run', '--project', $containerProject, '--configuration', 'Release', '--artifacts-path', '/tmp/artifacts')
    }
    foreach ($argument in $containerCommand) {
        $dockerArguments.Add($argument)
    }
    if ($command -ceq 'build') {
        $dockerArguments.Add('--property:RestoreLockedMode=true')
    }
    elseif ($kind -ceq 'Fixture') {
        foreach ($argument in @('--', '/artifacts/raw', $containerGatewayHost)) { $dockerArguments.Add($argument) }
    }

    & docker @dockerArguments
    $dockerExitCode = $LASTEXITCODE
    if ($dockerExitCode -ne 0) { exit $dockerExitCode }

    if ($kind -ceq 'Fixture') {
        $rawRoot = Join-Path $artifactRoot 'raw'
        $environmentPath = Join-Path $rawRoot 'm3a.env'
        $hostRawRoot = $rawRoot.Replace('\', '/')
        $hostCertificateRoot = (Join-Path $rawRoot 'certificates').Replace('\', '/')
        $environmentLines = [IO.File]::ReadAllLines($environmentPath)
        try {
            for ($index = 0; $index -lt $environmentLines.Length; $index++) {
                if ($environmentLines[$index].StartsWith('M3_RAW_EVIDENCE_DIRECTORY=', [StringComparison]::Ordinal)) {
                    $environmentLines[$index] = 'M3_RAW_EVIDENCE_DIRECTORY=' + $hostRawRoot
                }
                elseif ($environmentLines[$index].StartsWith('M3_CERTIFICATE_DIRECTORY=', [StringComparison]::Ordinal)) {
                    $environmentLines[$index] = 'M3_CERTIFICATE_DIRECTORY=' + $hostCertificateRoot
                }
            }
            [IO.File]::WriteAllLines($environmentPath, $environmentLines, [Text.UTF8Encoding]::new($false))
        }
        finally {
            [Array]::Clear($environmentLines, 0, $environmentLines.Length)
        }
    }
    exit 0
}
catch {
    [Console]::Error.WriteLine('ALPHA_CONTAINER_DOTNET_FAILED')
    exit 1
}

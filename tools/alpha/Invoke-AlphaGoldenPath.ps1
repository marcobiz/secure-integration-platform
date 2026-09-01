[CmdletBinding()]
param(
    [ValidateSet('Validate', 'Run', 'Stop', 'FailureOutputProbe', 'FailureTimeoutProbe', 'FailureOutputLimitProbe', 'DotNetHostMissingProbe', 'DotNetSdkUnavailableProbe')]
    [string] $Phase = 'Run',
    [switch] $SkipBuild,
    [string] $DotNetPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$quickstart = Join-Path $root 'tools\m5\Invoke-M5Quickstart.ps1'
$artifactRoot = Join-Path $root '.artifacts\m5\quickstart'
$rawRoot = Join-Path $artifactRoot 'raw'
$envFile = Join-Path $rawRoot 'm3a.env'
$baseCompose = Join-Path $root 'deploy\m3\docker-compose.m3a.yml'
$overlayCompose = Join-Path $root 'deploy\m5\docker-compose.m5.yml'
$canonicalConnector = Join-Path $root 'docs\connectors\examples\sample-secure-service.connector.json'
$project = 'secure-integration-m5-quickstart'
$useHostDotNet = -not [string]::IsNullOrWhiteSpace($DotNetPath)
$dotnet = if (-not [string]::IsNullOrWhiteSpace($DotNetPath)) {
    [IO.Path]::GetFullPath($DotNetPath)
}
else {
    $null
}
$containerDotNet = Join-Path $PSScriptRoot 'Invoke-AlphaContainerDotNet.ps1'
$powerShellHost = try { (Get-Process -Id $PID -ErrorAction Stop).Path } catch { $null }
if ([string]::IsNullOrWhiteSpace($powerShellHost)) {
    $powerShellHost = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'powershell.exe' } else { 'pwsh' }
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string] $Value)
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $backslashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) { [void]$builder.Append(('\' * $backslashes)); $backslashes = 0 }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) { [void]$builder.Append(('\' * ($backslashes * 2))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Initialize-BoundedProcessCapture {
    if ('AlphaGoldenPath.BoundedProcessCapture' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;

namespace AlphaGoldenPath
{
    public sealed class BoundedProcessResult
    {
        public int ExitCode { get; set; }
        public string StdOut { get; set; }
        public string StdErr { get; set; }
        public bool TimedOut { get; set; }
        public bool OutputLimitExceeded { get; set; }
        public bool TerminationFailed { get; set; }
        public bool CaptureFailed { get; set; }
    }

    internal sealed class CaptureState : IDisposable
    {
        internal readonly object Sync = new object();
        internal readonly MemoryStream StdOut = new MemoryStream();
        internal readonly MemoryStream StdErr = new MemoryStream();
        internal readonly ManualResetEvent OutputLimit = new ManualResetEvent(false);
        internal readonly int Limit;
        internal int Combined;
        internal volatile bool StopRequested;
        internal volatile bool OutputLimitExceeded;
        internal volatile bool CaptureFailed;

        internal CaptureState(int limit) { Limit = limit; }

        public void Dispose()
        {
            StdOut.Dispose();
            StdErr.Dispose();
            OutputLimit.Dispose();
        }
    }

    public static class BoundedProcessCapture
    {
        private static void Pump(Stream source, MemoryStream destination, CaptureState state)
        {
            byte[] buffer = new byte[4096];
            try
            {
                while (!state.StopRequested)
                {
                    int read = source.Read(buffer, 0, buffer.Length);
                    if (read == 0) { return; }
                    lock (state.Sync)
                    {
                        int remaining = state.Limit - state.Combined;
                        if (remaining <= 0)
                        {
                            state.OutputLimitExceeded = true;
                            state.StopRequested = true;
                            state.OutputLimit.Set();
                            return;
                        }
                        int accepted = Math.Min(read, remaining);
                        destination.Write(buffer, 0, accepted);
                        state.Combined += accepted;
                        if (accepted < read)
                        {
                            state.OutputLimitExceeded = true;
                            state.StopRequested = true;
                            state.OutputLimit.Set();
                            return;
                        }
                    }
                }
            }
            catch (IOException)
            {
                if (!state.StopRequested) { state.CaptureFailed = true; }
            }
            catch (ObjectDisposedException)
            {
                if (!state.StopRequested) { state.CaptureFailed = true; }
            }
            catch
            {
                state.CaptureFailed = true;
            }
            finally
            {
                Array.Clear(buffer, 0, buffer.Length);
            }
        }

        private static bool JoinBounded(Thread first, Thread second, int timeoutMilliseconds)
        {
            Stopwatch timer = Stopwatch.StartNew();
            if (!first.Join(timeoutMilliseconds)) { return false; }
            int remaining = Math.Max(0, timeoutMilliseconds - (int)timer.ElapsedMilliseconds);
            return second.Join(remaining);
        }

        private static bool TerminateBounded(Process process, int timeoutMilliseconds)
        {
            try
            {
                if (!process.HasExited)
                {
                    MethodInfo killTree = typeof(Process).GetMethod("Kill", new Type[] { typeof(bool) });
                    if (killTree == null) { process.Kill(); }
                    else { killTree.Invoke(process, new object[] { true }); }
                }
            }
            catch
            {
                try { if (!process.HasExited) { return false; } }
                catch { return false; }
            }
            try { return process.HasExited || process.WaitForExit(timeoutMilliseconds); }
            catch { return false; }
        }

        public static BoundedProcessResult Capture(Process process, int timeoutMilliseconds, int outputLimitBytes, int terminationTimeoutMilliseconds)
        {
            if (timeoutMilliseconds <= 0 || outputLimitBytes <= 0 || terminationTimeoutMilliseconds <= 0)
            {
                throw new ArgumentOutOfRangeException();
            }

            Encoding stdoutEncoding = process.StandardOutput.CurrentEncoding;
            Encoding stderrEncoding = process.StandardError.CurrentEncoding;
            using (CaptureState state = new CaptureState(outputLimitBytes))
            using (ManualResetEvent processExited = new ManualResetEvent(false))
            {
                process.EnableRaisingEvents = true;
                process.Exited += delegate { try { processExited.Set(); } catch (ObjectDisposedException) { } };
                Thread stdoutThread = new Thread(new ThreadStart(delegate { Pump(process.StandardOutput.BaseStream, state.StdOut, state); }));
                Thread stderrThread = new Thread(new ThreadStart(delegate { Pump(process.StandardError.BaseStream, state.StdErr, state); }));
                stdoutThread.IsBackground = true;
                stderrThread.IsBackground = true;
                stdoutThread.Start();
                stderrThread.Start();
                try { if (process.HasExited) { processExited.Set(); } } catch { }

                int signal = WaitHandle.WaitAny(new WaitHandle[] { processExited, state.OutputLimit }, timeoutMilliseconds);
                bool timedOut = signal == WaitHandle.WaitTimeout;
                bool outputLimitExceeded = signal == 1 || state.OutputLimitExceeded;
                bool terminationFailed = false;
                if (timedOut || outputLimitExceeded)
                {
                    state.StopRequested = true;
                    terminationFailed = !TerminateBounded(process, terminationTimeoutMilliseconds);
                }

                if (!JoinBounded(stdoutThread, stderrThread, terminationTimeoutMilliseconds))
                {
                    state.StopRequested = true;
                    terminationFailed = true;
                }
                outputLimitExceeded = outputLimitExceeded || state.OutputLimitExceeded;

                byte[] stdoutBytes;
                byte[] stderrBytes;
                lock (state.Sync)
                {
                    stdoutBytes = state.StdOut.ToArray();
                    stderrBytes = state.StdErr.ToArray();
                }
                try
                {
                    int exitCode = -1;
                    try { if (process.HasExited) { exitCode = process.ExitCode; } } catch { }
                    return new BoundedProcessResult
                    {
                        ExitCode = exitCode,
                        StdOut = stdoutEncoding.GetString(stdoutBytes),
                        StdErr = stderrEncoding.GetString(stderrBytes),
                        TimedOut = timedOut,
                        OutputLimitExceeded = outputLimitExceeded,
                        TerminationFailed = terminationFailed,
                        CaptureFailed = state.CaptureFailed
                    };
                }
                finally
                {
                    Array.Clear(stdoutBytes, 0, stdoutBytes.Length);
                    Array.Clear(stderrBytes, 0, stderrBytes.Length);
                }
            }
        }
    }
}
'@
}

function Get-ChildPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Docker', 'DotNet', 'ContainerDotNet', 'Quickstart', 'FailureProbe', 'TimeoutProbe', 'OutputLimitProbe')]
        [string] $Component
    )
    switch ($Component) {
        'Docker' { return [pscustomobject]@{ TimeoutMilliseconds = 300000; OutputLimitBytes = 1048576; TerminationTimeoutMilliseconds = 5000 } }
        'DotNet' { return [pscustomobject]@{ TimeoutMilliseconds = 600000; OutputLimitBytes = 1048576; TerminationTimeoutMilliseconds = 5000 } }
        'ContainerDotNet' { return [pscustomobject]@{ TimeoutMilliseconds = 600000; OutputLimitBytes = 1048576; TerminationTimeoutMilliseconds = 5000 } }
        'Quickstart' { return [pscustomobject]@{ TimeoutMilliseconds = 1200000; OutputLimitBytes = 262144; TerminationTimeoutMilliseconds = 5000 } }
        'FailureProbe' { return [pscustomobject]@{ TimeoutMilliseconds = 30000; OutputLimitBytes = 65536; TerminationTimeoutMilliseconds = 2000 } }
        'TimeoutProbe' { return [pscustomobject]@{ TimeoutMilliseconds = 750; OutputLimitBytes = 65536; TerminationTimeoutMilliseconds = 2000 } }
        'OutputLimitProbe' { return [pscustomobject]@{ TimeoutMilliseconds = 30000; OutputLimitBytes = 4096; TerminationTimeoutMilliseconds = 2000 } }
    }
}

function Invoke-SanitizedChild {
    param(
        [Parameter(Mandatory = $true)][string] $File,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Docker', 'DotNet', 'ContainerDotNet', 'Quickstart', 'FailureProbe', 'TimeoutProbe', 'OutputLimitProbe')]
        [string] $Component,
        [switch] $AllowFailure
    )
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $File
    $start.WorkingDirectory = $root
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if ($null -ne $start.PSObject.Properties['ArgumentList']) {
        foreach ($argument in $Arguments) { [void]$start.ArgumentList.Add($argument) }
    }
    else {
        $start.Arguments = (($Arguments | ForEach-Object { ConvertTo-NativeArgument -Value ([string]$_) }) -join ' ')
    }
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        try { if (-not $process.Start()) { throw 'start' } }
        catch { throw "ALPHA_GOLDEN_PATH_CHILD_START_FAILED;COMPONENT=$Component" }
        $policy = Get-ChildPolicy -Component $Component
        $capture = [AlphaGoldenPath.BoundedProcessCapture]::Capture(
            $process,
            [int]$policy.TimeoutMilliseconds,
            [int]$policy.OutputLimitBytes,
            [int]$policy.TerminationTimeoutMilliseconds)
        if ($capture.TerminationFailed) { throw "ALPHA_GOLDEN_PATH_CHILD_TERMINATION_FAILED;COMPONENT=$Component" }
        if ($capture.TimedOut) { throw "ALPHA_GOLDEN_PATH_CHILD_TIMEOUT;COMPONENT=$Component" }
        if ($capture.OutputLimitExceeded) { throw "ALPHA_GOLDEN_PATH_CHILD_OUTPUT_LIMIT_EXCEEDED;COMPONENT=$Component" }
        if ($capture.CaptureFailed) { throw "ALPHA_GOLDEN_PATH_CHILD_CAPTURE_FAILED;COMPONENT=$Component" }
        $result = [pscustomobject]@{ ExitCode = $capture.ExitCode; StdOut = $capture.StdOut; StdErr = $capture.StdErr }
        if ($capture.ExitCode -ne 0 -and -not $AllowFailure) {
            $childCode = if ($capture.StdErr -cmatch '(?m)^(M5_QUICKSTART_[A-Z0-9_]+)\r?$') { ';CHILD_CODE=' + $Matches[1] } else { '' }
            $stableExitCode = if ($capture.ExitCode -ge 1 -and $capture.ExitCode -le 65535) { $capture.ExitCode } else { 255 }
            throw "ALPHA_GOLDEN_PATH_CHILD_EXIT_NONZERO;COMPONENT=$Component;EXIT_CODE=$stableExitCode$childCode"
        }
        return $result
    }
    finally { $process.Dispose() }
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string] $File,
        [Parameter(Mandatory = $true)][string[]] $Arguments,
        [Parameter(Mandatory = $true)][ValidateSet('Docker', 'DotNet', 'ContainerDotNet', 'Quickstart')][string] $Component
    )
    return Invoke-SanitizedChild -File $File -Arguments $Arguments -Component $Component
}

function Get-DotNetRequirement {
    $configuration = Get-Content -LiteralPath (Join-Path $root 'global.json') -Raw | ConvertFrom-Json
    $baseline = [string]$configuration.sdk.version
    $rollForward = [string]$configuration.sdk.rollForward
    if ($baseline -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$' -or $rollForward -cnotmatch '^[A-Za-z][A-Za-z0-9]{0,31}$') {
        throw 'ALPHA_GOLDEN_PATH_GLOBAL_JSON_INVALID'
    }
    return [pscustomobject]@{ Baseline = $baseline; RollForward = $rollForward }
}

function Assert-CompatibleDotNetSdk {
    param(
        [Parameter(Mandatory = $true)][string] $File,
        [string[]] $Arguments = @('--version')
    )
    try {
        $result = Invoke-SanitizedChild -File $File -Arguments $Arguments -Component DotNet -AllowFailure
    }
    catch {
        if ([string]$_.Exception.Message -ceq 'ALPHA_GOLDEN_PATH_CHILD_START_FAILED;COMPONENT=DotNet') {
            throw 'ALPHA_GOLDEN_PATH_DOTNET_HOST_NOT_FOUND'
        }
        throw
    }
    if ($result.ExitCode -ne 0) {
        $requirement = Get-DotNetRequirement
        throw "ALPHA_GOLDEN_PATH_DOTNET_SDK_UNAVAILABLE;BASELINE=$($requirement.Baseline);ROLL_FORWARD=$($requirement.RollForward)"
    }
}

function Assert-DockerEngine {
    try {
        $result = Invoke-SanitizedChild -File 'docker' -Arguments @('version') -Component Docker -AllowFailure
    }
    catch {
        if ([string]$_.Exception.Message -ceq 'ALPHA_GOLDEN_PATH_CHILD_START_FAILED;COMPONENT=Docker') {
            throw 'ALPHA_GOLDEN_PATH_DOCKER_UNAVAILABLE'
        }
        throw
    }
    if ($result.ExitCode -ne 0) { throw 'ALPHA_GOLDEN_PATH_DOCKER_UNAVAILABLE' }
}

function Assert-DockerCompose {
    $result = Invoke-SanitizedChild -File 'docker' -Arguments @('compose', 'version') -Component Docker -AllowFailure
    if ($result.ExitCode -ne 0) { throw 'ALPHA_GOLDEN_PATH_DOCKER_COMPOSE_UNAVAILABLE' }
}

function Invoke-ContainerDotNet {
    param([Parameter(Mandatory = $true)][string[]] $Arguments)
    return Invoke-Checked -File $powerShellHost -Arguments (@('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $containerDotNet) + $Arguments) -Component ContainerDotNet
}

function Invoke-Quickstart {
    param([Parameter(Mandatory = $true)][ValidateSet('Start', 'Stop')][string] $RequestedPhase)
    $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $quickstart, '-Phase', $RequestedPhase)
    if ($RequestedPhase -eq 'Start' -and $SkipBuild) { $arguments += '-SkipBuild' }
    if ($RequestedPhase -eq 'Start') {
        if ($useHostDotNet) {
            $arguments += @('-DotNetPath', $dotnet)
        }
        else {
            $arguments += @('-DotNetPath', $containerDotNet)
        }
    }
    return Invoke-Checked -File $powerShellHost -Arguments $arguments -Component Quickstart
}

function Get-ExactProjectResources {
    param([Parameter(Mandatory = $true)][ValidateSet('container', 'network', 'volume')][string] $Kind)
    $arguments = switch ($Kind) {
        'container' { @('ps', '-aq', '--filter', ('label=com.docker.compose.project=' + $project)) }
        'network' { @('network', 'ls', '-q', '--filter', ('label=com.docker.compose.project=' + $project)) }
        'volume' { @('volume', 'ls', '-q', '--filter', ('label=com.docker.compose.project=' + $project)) }
    }
    $result = Invoke-Checked -File 'docker' -Arguments $arguments -Component Docker
    return @($result.StdOut -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
}

function Assert-ZeroProjectResources {
    if (@(Get-ExactProjectResources -Kind container).Count -ne 0 -or
        @(Get-ExactProjectResources -Kind network).Count -ne 0 -or
        @(Get-ExactProjectResources -Kind volume).Count -ne 0) {
        throw 'ALPHA_GOLDEN_PATH_RESIDUAL_PROJECT_RESOURCES'
    }
}

function Read-EnvironmentFile {
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $envFile) {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0) { $values[$line.Substring(0, $separator)] = $line.Substring($separator + 1) }
    }
    return $values
}

function Initialize-ControlHttpClient {
    if ('AlphaGoldenPath.PinnedRootCertificateValidator' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AlphaGoldenPath
{
    public sealed class PinnedRootCertificateValidator : IDisposable
    {
        private X509Certificate2 trustedRoot;

        public PinnedRootCertificateValidator(string caPath)
        {
            trustedRoot = (X509Certificate2)Activator.CreateInstance(
                typeof(X509Certificate2),
                new object[] { caPath });
            Callback = Validate;
        }

        public RemoteCertificateValidationCallback Callback { get; private set; }

        private bool Validate(
            object sender,
            X509Certificate certificate,
            X509Chain peerChain,
            SslPolicyErrors errors)
        {
            if (certificate == null ||
                (errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0 ||
                (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                return false;

            using (X509Certificate2 leaf = (X509Certificate2)Activator.CreateInstance(
                typeof(X509Certificate2),
                new object[] { certificate }))
            using (X509Chain validation = new X509Chain())
            {
                validation.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                validation.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                validation.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                validation.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                validation.ChainPolicy.ExtraStore.Add(trustedRoot);
                if (peerChain != null)
                {
                    foreach (X509ChainElement element in peerChain.ChainElements)
                    {
                        if (!BytesEqual(element.Certificate.RawData, leaf.RawData))
                            validation.ChainPolicy.ExtraStore.Add(element.Certificate);
                    }
                }

                bool built = validation.Build(leaf);
                foreach (X509ChainStatus status in validation.ChainStatus)
                {
                    if (status.Status != X509ChainStatusFlags.NoError &&
                        status.Status != X509ChainStatusFlags.UntrustedRoot)
                        return false;
                }
                if (!built && validation.ChainStatus.Length == 0) return false;
                if (validation.ChainElements.Count < 2) return false;
                X509Certificate2 actualRoot = validation.ChainElements[validation.ChainElements.Count - 1].Certificate;
                return BytesEqual(actualRoot.RawData, trustedRoot.RawData);
            }
        }

        public void Dispose()
        {
            Callback = null;
            if (trustedRoot != null) trustedRoot.Dispose();
            trustedRoot = null;
        }

        private static bool BytesEqual(byte[] left, byte[] right)
        {
            if (left == null || right == null || left.Length != right.Length) return false;
            int difference = 0;
            for (int index = 0; index < left.Length; index++) difference |= left[index] ^ right[index];
            return difference == 0;
        }
    }
}
'@
}

function Invoke-ControlJson {
    param(
        [Parameter(Mandatory = $true)][string] $HostName,
        [Parameter(Mandatory = $true)][int] $Port,
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $HeaderName,
        [Parameter(Mandatory = $true)][string] $HeaderValue,
        [Parameter(Mandatory = $true)][string] $CaPath
    )
    if ($HostName -cnotmatch '^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$' -or
        $Port -lt 1 -or $Port -gt 65535 -or $Path -cnotmatch '^/[^\s\r\n]*$' -or
        $HeaderName -cnotmatch '^[A-Za-z0-9-]{1,64}$' -or $HeaderValue -match '[\r\n]') {
        throw 'ALPHA_GOLDEN_PATH_CONTROL_REQUEST_INVALID'
    }
    Initialize-ControlHttpClient
    $validator = New-Object AlphaGoldenPath.PinnedRootCertificateValidator($CaPath)
    $request = [Net.HttpWebRequest]::Create("https://127.0.0.1:${Port}${Path}")
    $request.Host = "${HostName}:${Port}"
    $request.Method = 'GET'
    $request.Accept = 'application/json'
    $request.AllowAutoRedirect = $false
    $request.KeepAlive = $false
    $request.Proxy = $null
    $request.Timeout = 15000
    $request.ReadWriteTimeout = 15000
    $request.MaximumResponseHeadersLength = 16
    $request.Headers.Add($HeaderName, $HeaderValue)
    $request.ServerCertificateValidationCallback = $validator.Callback
    $webResponse = $null
    $stream = $null
    $body = $null
    try {
        try {
            $webResponse = [Net.HttpWebResponse]$request.GetResponse()
            if ($webResponse.StatusCode -ne [Net.HttpStatusCode]::OK -or
                [string]::IsNullOrWhiteSpace($webResponse.ContentType) -or
                -not $webResponse.ContentType.StartsWith('application/json', [StringComparison]::OrdinalIgnoreCase) -or
                $webResponse.ContentLength -gt 262144) {
                throw 'invalid'
            }
            $stream = $webResponse.GetResponseStream()
            $body = New-Object IO.MemoryStream
            [byte[]]$buffer = New-Object byte[] 4096
            try {
                while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    if ($body.Length + $read -gt 262144) { throw 'invalid' }
                    $body.Write($buffer, 0, $read)
                }
            }
            finally { [Array]::Clear($buffer, 0, $buffer.Length) }
            [byte[]]$response = $body.ToArray()
        }
        catch { throw 'ALPHA_GOLDEN_PATH_CONTROL_REQUEST_FAILED' }
    }
    finally {
        if ($null -ne $body) { $body.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $webResponse) { $webResponse.Dispose() }
        $request.ServerCertificateValidationCallback = $null
        $validator.Dispose()
    }
    try {
        try {
            $strictUtf8 = New-Object Text.UTF8Encoding($false, $true)
            $json = $strictUtf8.GetString($response)
            return $json | ConvertFrom-Json -ErrorAction Stop
        }
        catch { throw 'ALPHA_GOLDEN_PATH_CONTROL_RESPONSE_INVALID' }
        finally { $json = $null }
    }
    finally { if ($null -ne $response) { [Array]::Clear($response, 0, $response.Length) } }
}

function Restart-GatewayAndWait {
    $compose = @('compose', '--project-name', $project, '--env-file', $envFile, '--file', $baseCompose, '--file', $overlayCompose)
    [void](Invoke-Checked -File 'docker' -Arguments ($compose + @('restart', 'gateway')) -Component Docker)
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(2)
    do {
        $containerResult = Invoke-SanitizedChild -File 'docker' -Arguments ($compose + @('ps', '--quiet', 'gateway')) -Component Docker -AllowFailure
        $container = $containerResult.StdOut.Trim()
        if ($containerResult.ExitCode -eq 0 -and $container.Length -gt 0) {
            $healthResult = Invoke-SanitizedChild -File 'docker' -Arguments @('inspect', $container, '--format', '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}') -Component Docker -AllowFailure
            if ($healthResult.ExitCode -eq 0 -and $healthResult.StdOut.Trim() -ceq 'healthy') { return }
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'ALPHA_GOLDEN_PATH_GATEWAY_NOT_READY_AFTER_RESTART'
}

function Get-ReadCount {
    param([Parameter(Mandatory = $true)] $Stats, [Parameter(Mandatory = $true)][string] $Name)
    $property = $Stats.reads.PSObject.Properties[$Name]
    if ($null -eq $property) { return 0L }
    return [long]$property.Value
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][byte[]] $Bytes)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($Bytes)
        try { return ([BitConverter]::ToString($digest)).Replace('-', '') }
        finally { [Array]::Clear($digest, 0, $digest.Length) }
    }
    finally { $sha256.Dispose() }
}

function ConvertTo-CanonicalJson {
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return ConvertTo-Json -InputObject ([string]$Value) -Compress }
    if ($Value -is [bool]) { return $(if ($Value) { 'true' } else { 'false' }) }
    if ($Value -is [Collections.IDictionary]) {
        $parts = foreach ($key in @($Value.Keys | Sort-Object { [string]$_ })) {
            (ConvertTo-Json -InputObject ([string]$key) -Compress) + ':' + (ConvertTo-CanonicalJson -Value $Value[$key])
        }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $parts = foreach ($property in @($Value.PSObject.Properties | Sort-Object Name)) {
            (ConvertTo-Json -InputObject $property.Name -Compress) + ':' + (ConvertTo-CanonicalJson -Value $property.Value)
        }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [Collections.IEnumerable]) {
        $items = foreach ($item in $Value) { ConvertTo-CanonicalJson -Value $item }
        return '[' + ($items -join ',') + ']'
    }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64]) {
        return ([IFormattable]$Value).ToString($null, [Globalization.CultureInfo]::InvariantCulture)
    }
    throw 'ALPHA_GOLDEN_PATH_CANONICAL_JSON_UNSUPPORTED'
}

function Get-CanonicalConnectorMetadata {
    $source = Get-Content -LiteralPath $canonicalConnector -Raw | ConvertFrom-Json
    $canonicalJson = ConvertTo-CanonicalJson -Value $source
    [byte[]]$bytes = [Text.Encoding]::UTF8.GetBytes($canonicalJson)
    try { $checksum = Get-Sha256Hex -Bytes $bytes }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
    $endpoints = @($source.bindings.endpoints | ForEach-Object { [string]$_.name })
    $secrets = @($source.bindings.secrets | Where-Object { [string]$_.kind -ceq 'opaque' } | ForEach-Object { [string]$_.name })
    $certificates = @($source.bindings.secrets | Where-Object { [string]$_.kind -ceq 'clientCertificate' } | ForEach-Object { [string]$_.name })
    return [pscustomobject]@{ Json = $canonicalJson; Checksum = $checksum; Endpoints = $endpoints; Secrets = $secrets; Certificates = $certificates }
}

function Test-ExactStrings {
    param([AllowNull()][object[]] $Actual, [Parameter(Mandatory = $true)][string[]] $Expected)
    if (@($Actual).Count -ne $Expected.Count) { return $false }
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if ([string]$Actual[$index] -cne $Expected[$index]) { return $false }
    }
    return $true
}

function Assert-RedactedText {
    param([Parameter(Mandatory = $true)][string] $Text, [Parameter(Mandatory = $true)][object[]] $Canaries)
    foreach ($canary in $Canaries) {
        $value = [string]$canary.Value
        if ($value.Length -ge 8 -and $Text.IndexOf($value, [StringComparison]::Ordinal) -ge 0) {
            throw 'ALPHA_GOLDEN_PATH_REDACTION_FAILED'
        }
    }
    foreach ($pattern in @(
        '-----BEGIN (?:RSA |EC |)PRIVATE KEY-----',
        '(?i)authorization\s*:\s*\S+',
        '(?i)cookie\s*:\s*\S+',
        '__Host-SecureIntegration\.Admin=[^;\s]+',
        '(?m)^\s+at\s+[A-Za-z0-9_.+`<>]+\(')) {
        if ([regex]::IsMatch($Text, $pattern)) { throw 'ALPHA_GOLDEN_PATH_REDACTION_PATTERN_FAILED' }
    }
}

function Get-StableAlphaFailure {
    param([Parameter(Mandatory = $true)] $Failure)
    $message = [string]$Failure.Exception.Message
    if ($message -ceq 'ALPHA_GOLDEN_PATH_DOTNET_HOST_NOT_FOUND') { return $message }
    if ($message -cmatch '^ALPHA_GOLDEN_PATH_DOTNET_SDK_UNAVAILABLE;BASELINE=[0-9]+\.[0-9]+\.[0-9]+;ROLL_FORWARD=[A-Za-z][A-Za-z0-9]{0,31}$') { return $message }
    if ($message -cmatch '^ALPHA_GOLDEN_PATH_[A-Z0-9_]+(?:;COMPONENT=(?:Docker|DotNet|ContainerDotNet|Quickstart|FailureProbe|TimeoutProbe|OutputLimitProbe)(?:;EXIT_CODE=[0-9]{1,5})?(?:;CHILD_CODE=M5_QUICKSTART_[A-Z0-9_]+)?)?$') {
        return $message
    }
    return 'ALPHA_GOLDEN_PATH_FAILED'
}

try {
    Initialize-BoundedProcessCapture
    if ($Phase -eq 'DotNetHostMissingProbe') {
        $missingHost = Join-Path ([IO.Path]::GetTempPath()) ('alpha-dotnet-host-missing-' + [Guid]::NewGuid().ToString('N') + '.exe')
        Assert-CompatibleDotNetSdk -File $missingHost
        throw 'ALPHA_GOLDEN_PATH_DOTNET_HOST_MISSING_PROBE_DID_NOT_FAIL'
    }
    if ($Phase -eq 'DotNetSdkUnavailableProbe') {
        $sdkProbe = '[Console]::Out.WriteLine("alpha-dotnet-sdk-stdout-canary-7b61d8d2"); [Console]::Error.WriteLine("No compatible SDK under ' + $root + '"); exit 86'
        Assert-CompatibleDotNetSdk -File $powerShellHost -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $sdkProbe)
        throw 'ALPHA_GOLDEN_PATH_DOTNET_SDK_PROBE_DID_NOT_FAIL'
    }
    if ($Phase -eq 'Validate') {
        Assert-DockerEngine
        Assert-DockerCompose
        if ($useHostDotNet) {
            Assert-CompatibleDotNetSdk -File $dotnet
            [void](Invoke-Checked -File $dotnet -Arguments @('restore', (Join-Path $root 'samples\DirectGatewayClient\DirectGatewayClient.csproj'), '--locked-mode') -Component DotNet)
            [void](Invoke-Checked -File $dotnet -Arguments @('build', (Join-Path $root 'samples\DirectGatewayClient\DirectGatewayClient.csproj'), '--configuration', 'Release', '--no-restore') -Component DotNet)
        }
        else {
            [void](Invoke-ContainerDotNet -Arguments @('build', '--project', (Join-Path $root 'samples\DirectGatewayClient\DirectGatewayClient.csproj'), '--configuration', 'Release'))
        }
        Write-Host 'ALPHA_GOLDEN_PATH_VALIDATE_PASS'
        exit 0
    }

    if ($Phase -eq 'Stop') {
        [void](Invoke-Quickstart -RequestedPhase Stop)
        Assert-ZeroProjectResources
        if (Test-Path -LiteralPath $artifactRoot) { throw 'ALPHA_GOLDEN_PATH_ARTIFACT_CLEANUP_FAILED' }
        Write-Host 'ALPHA_GOLDEN_PATH_STOP_PASS; CONTAINERS=0; NETWORKS=0; VOLUMES=0; SYNTHETIC_MATERIAL=0'
        exit 0
    }

    Assert-DockerEngine
    Assert-DockerCompose
    if ($Phase -eq 'Run' -and $useHostDotNet) { Assert-CompatibleDotNetSdk -File $dotnet }
    Assert-ZeroProjectResources
    if (Test-Path -LiteralPath $artifactRoot) { throw 'ALPHA_GOLDEN_PATH_ARTIFACT_ROOT_NOT_CLEAN' }
    $cleanupRequired = $true
    $failure = $null
    $cleanupFailure = $null
    $previousEnvironment = @{}
    $environmentNames = @(
        'DIRECT_GATEWAY_URL',
        'DIRECT_GATEWAY_CA_FILE',
        'DIRECT_GATEWAY_ACTIVATION_CODE_ID',
        'DIRECT_GATEWAY_ACTIVATION_CODE',
        'DIRECT_GATEWAY_CONNECTOR_ID',
        'DIRECT_GATEWAY_OPERATION_ID',
        'DIRECT_GATEWAY_CORRELATION_ID',
        'DOTNET_NOLOGO',
        'DOTNET_CLI_TELEMETRY_OPTOUT',
        'DOTNET_SKIP_FIRST_TIME_EXPERIENCE')
    foreach ($name in $environmentNames) { $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }

    try {
        if ($Phase -in @('FailureOutputProbe', 'FailureTimeoutProbe', 'FailureOutputLimitProbe')) {
            New-Item -ItemType Directory -Path (Join-Path $artifactRoot 'raw') -Force | Out-Null
            [IO.File]::WriteAllText((Join-Path $artifactRoot '.m5-quickstart-owner'), 'secure-integration-m5-quickstart-artifacts-v1', [Text.UTF8Encoding]::new($false))
            $probeSuffix = [Guid]::NewGuid().ToString('N')
            [void](Invoke-Checked -File 'docker' -Arguments @('network', 'create', '--label', ('com.docker.compose.project=' + $project), ('alpha-golden-path-failure-probe-network-' + $probeSuffix)) -Component Docker)
            [void](Invoke-Checked -File 'docker' -Arguments @('volume', 'create', '--label', ('com.docker.compose.project=' + $project), ('alpha-golden-path-failure-probe-volume-' + $probeSuffix)) -Component Docker)
            if ($Phase -eq 'FailureOutputProbe') {
                $probe = @'
[Console]::Out.WriteLine("System.InvalidOperationException: alpha-probe-payload-canary-2f4d68f3")
[Console]::Error.WriteLine("   at Synthetic.Probe.Run() in C:\alpha\probe\Sensitive.cs:line 42")
[Console]::Error.WriteLine("Authorization: Bearer alpha-probe-token-canary-b619f4e8")
[Console]::Error.WriteLine("Host=localhost;Database=probe;Password=alpha-probe-password-canary-c2971a05")
exit 37
'@
                [void](Invoke-SanitizedChild -File $powerShellHost -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $probe) -Component FailureProbe)
                throw 'ALPHA_GOLDEN_PATH_FAILURE_PROBE_DID_NOT_FAIL'
            }
            if ($Phase -eq 'FailureTimeoutProbe') {
                $probe = @'
[Console]::Out.WriteLine("alpha-timeout-probe-canary-a12f8029")
while ($true) { Start-Sleep -Seconds 30 }
'@
                [void](Invoke-SanitizedChild -File $powerShellHost -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $probe) -Component TimeoutProbe)
                throw 'ALPHA_GOLDEN_PATH_TIMEOUT_PROBE_DID_NOT_FAIL'
            }
            $probe = @'
[Console]::Out.Write("alpha-output-limit-probe-canary-33c1b471")
$chunk = "x" * 1024
while ($true) { [Console]::Out.Write($chunk) }
'@
            [void](Invoke-SanitizedChild -File $powerShellHost -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $probe) -Component OutputLimitProbe)
            throw 'ALPHA_GOLDEN_PATH_OUTPUT_LIMIT_PROBE_DID_NOT_FAIL'
        }

        [void](Invoke-Quickstart -RequestedPhase Start)
        $environment = Read-EnvironmentFile
        $provisioning = Get-Content -LiteralPath (Join-Path $rawRoot 'provisioning.json') -Raw | ConvertFrom-Json
        $fixture = Get-Content -LiteralPath (Join-Path $rawRoot 'fixture-public.json') -Raw | ConvertFrom-Json
        foreach ($name in @('directInstallationId', 'directActivationCodeId', 'directActivationCode', 'sampleConnector')) {
            if ($null -eq $provisioning.PSObject.Properties[$name]) { throw 'ALPHA_GOLDEN_PATH_DIRECT_FIXTURE_MISSING' }
        }

        $postgresResult = Invoke-Checked -File 'docker' -Arguments @('ps', '-q', '--filter', ('label=com.docker.compose.project=' + $project), '--filter', 'label=com.docker.compose.service=postgres') -Component Docker
        $postgres = @($postgresResult.StdOut -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
        if ($postgres.Count -ne 1) { throw 'ALPHA_GOLDEN_PATH_POSTGRES_NOT_FOUND' }
        $canonical = Get-CanonicalConnectorMetadata
        $environmentId = [Guid]::ParseExact([string]$provisioning.environmentId, 'D').ToString('D')
        $connectorSql = "SELECT json_build_object('state',v.state,'checksum',encode(v.checksum_sha256,'hex'),'canonicalJson',v.configuration_json::text,'endpoints',ARRAY(SELECT key FROM jsonb_object_keys(b.endpoints_json) key ORDER BY key),'secrets',ARRAY(SELECT key FROM jsonb_object_keys(b.secret_references_json) key ORDER BY key),'certificates',ARRAY(SELECT key FROM jsonb_object_keys(b.certificate_references_json) key ORDER BY key))::text FROM gateway.connector_definition c JOIN gateway.connector_version v ON v.id=c.active_version_id JOIN gateway.connector_binding_bundle_version b ON b.connector_version_id=v.id AND b.environment_id='$environmentId'::uuid AND b.state='active' WHERE c.slug='sample-secure-service' AND v.version='1.0.0' AND v.state='published';"
        $publishedResult = Invoke-Checked -File 'docker' -Arguments @('exec', [string]$postgres[0], 'psql', '-U', 'postgres', '-d', 'broker_gateway_m3', '-Atc', $connectorSql) -Component Docker
        $publishedLines = @($publishedResult.StdOut -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
        if ($publishedLines.Count -ne 1) { throw 'ALPHA_GOLDEN_PATH_CANONICAL_CONNECTOR_MISSING' }
        $published = $publishedLines[0] | ConvertFrom-Json
        $publishedCanonicalJson = ConvertTo-CanonicalJson -Value ([string]$published.canonicalJson | ConvertFrom-Json)
        $metadata = $provisioning.sampleConnector
        if ([string]$published.state -cne 'published' -or [string]$metadata.state -cne 'Published' -or
            ([string]$published.checksum).ToUpperInvariant() -cne $canonical.Checksum -or
            [string]$metadata.checksumSha256 -cne $canonical.Checksum -or
            $publishedCanonicalJson -cne $canonical.Json -or
            -not (Test-ExactStrings -Actual @($published.endpoints) -Expected @($canonical.Endpoints)) -or
            -not (Test-ExactStrings -Actual @($published.secrets) -Expected @($canonical.Secrets)) -or
            -not (Test-ExactStrings -Actual @($published.certificates) -Expected @($canonical.Certificates)) -or
            -not (Test-ExactStrings -Actual @($metadata.endpointBindings) -Expected @($canonical.Endpoints)) -or
            -not (Test-ExactStrings -Actual @($metadata.secretBindings) -Expected @($canonical.Secrets)) -or
            -not (Test-ExactStrings -Actual @($metadata.certificateBindings) -Expected @($canonical.Certificates))) {
            throw 'ALPHA_GOLDEN_PATH_CANONICAL_CONNECTOR_DRIFT'
        }

        $caPath = Join-Path $rawRoot 'certificates\ca.crt'
        $vendorBefore = Invoke-ControlJson -HostName 'vendor.m3.test' -Port 18445 -Path '/m3/stats' -HeaderName 'X-M3-Control-Token' -HeaderValue ([string]$environment.M3_VENDOR_CONTROL_TOKEN) -CaPath $caPath
        $vaultBefore = Invoke-ControlJson -HostName 'vault.m3.test' -Port 18444 -Path '/m3/stats' -HeaderName 'X-M3-Vault-Token' -HeaderValue ([string]$environment.M3_SYNTHETIC_VAULT_TOKEN) -CaPath $caPath
        Restart-GatewayAndWait

        $correlationId = [Guid]::NewGuid()
        $env:DIRECT_GATEWAY_URL = 'https://localhost:18443'
        $env:DIRECT_GATEWAY_CA_FILE = $caPath
        $env:DIRECT_GATEWAY_ACTIVATION_CODE_ID = [string]$provisioning.directActivationCodeId
        $env:DIRECT_GATEWAY_ACTIVATION_CODE = [string]$provisioning.directActivationCode
        $env:DIRECT_GATEWAY_CONNECTOR_ID = 'sample-secure-service'
        $env:DIRECT_GATEWAY_OPERATION_ID = 'submit'
        $env:DIRECT_GATEWAY_CORRELATION_ID = $correlationId.ToString('D')
        $env:DOTNET_NOLOGO = '1'
        $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
        $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
        $sample = if ($useHostDotNet) {
            Invoke-Checked -File $dotnet -Arguments @('run', '--project', (Join-Path $root 'samples\DirectGatewayClient\DirectGatewayClient.csproj'), '--configuration', 'Release') -Component DotNet
        }
        else {
            Invoke-ContainerDotNet -Arguments @('run', '--project', (Join-Path $root 'samples\DirectGatewayClient\DirectGatewayClient.csproj'), '--configuration', 'Release')
        }
        $sampleLines = @($sample.StdOut -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_.StartsWith('{', [StringComparison]::Ordinal) })
        if ($sampleLines.Count -ne 1) { throw 'ALPHA_GOLDEN_PATH_DIRECT_SAMPLE_OUTPUT_INVALID' }
        $sampleResult = $sampleLines[0] | ConvertFrom-Json
        if ($sampleResult.accepted -ne $true -or [string]$sampleResult.vendorReference -cne 'synthetic-order') { throw 'ALPHA_GOLDEN_PATH_DIRECT_SAMPLE_RESPONSE_INVALID' }

        $vendorAfter = Invoke-ControlJson -HostName 'vendor.m3.test' -Port 18445 -Path '/m3/stats' -HeaderName 'X-M3-Control-Token' -HeaderValue ([string]$environment.M3_VENDOR_CONTROL_TOKEN) -CaPath $caPath
        $vaultAfter = Invoke-ControlJson -HostName 'vault.m3.test' -Port 18444 -Path '/m3/stats' -HeaderName 'X-M3-Vault-Token' -HeaderValue ([string]$environment.M3_SYNTHETIC_VAULT_TOKEN) -CaPath $caPath
        $outboundCount = [long]$vendorAfter.accepted - [long]$vendorBefore.accepted
        if ($outboundCount -ne 1 -or $null -eq $vendorAfter.lastAccepted) { throw 'ALPHA_GOLDEN_PATH_OUTBOUND_COUNT_INVALID' }
        [byte[]]$expectedBody = [Text.Encoding]::UTF8.GetBytes('{"message":"direct-gateway-sample"}')
        try { $expectedBodySha256 = Get-Sha256Hex -Bytes $expectedBody }
        finally { [Array]::Clear($expectedBody, 0, $expectedBody.Length) }
        if ([string]$vendorAfter.lastAccepted.method -cne 'POST' -or
            [string]$vendorAfter.lastAccepted.path -cne '/vendor/orders' -or
            [string]$vendorAfter.lastAccepted.contentType -cne 'application/json' -or
            [string]$vendorAfter.lastAccepted.bodySha256 -cne $expectedBodySha256 -or
            [string]$vendorAfter.lastAccepted.clientCertificateSha256 -cne [string]$fixture.vendorClientCertificateSha256) {
            throw 'ALPHA_GOLDEN_PATH_OUTBOUND_METADATA_INVALID'
        }
        $apiKeyReads = (Get-ReadCount -Stats $vaultAfter -Name 'vendor-api-key') - (Get-ReadCount -Stats $vaultBefore -Name 'vendor-api-key')
        $certificateReads = (Get-ReadCount -Stats $vaultAfter -Name 'vendor-client-certificate') - (Get-ReadCount -Stats $vaultBefore -Name 'vendor-client-certificate')
        if ($apiKeyReads -lt 1 -or $certificateReads -lt 1) { throw 'ALPHA_GOLDEN_PATH_SYNTHETIC_PROVIDER_NOT_USED' }

        $sql = "SELECT json_build_object('action',action,'outcome',outcome,'reasonCode',reason_code,'metadata',metadata_redacted)::text FROM gateway.audit_event WHERE correlation_id='$($correlationId.ToString('D'))' AND action='operation.invoke' AND outcome='success';"
        $auditResult = Invoke-Checked -File 'docker' -Arguments @('exec', [string]$postgres[0], 'psql', '-U', 'postgres', '-d', 'broker_gateway_m3', '-Atc', $sql) -Component Docker
        $auditRows = @($auditResult.StdOut -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
        if ($auditRows.Count -ne 1) { throw 'ALPHA_GOLDEN_PATH_AUDIT_INVALID' }
        $auditText = [string]$auditRows[0]
        $audit = $auditText | ConvertFrom-Json
        if ([string]$audit.action -cne 'operation.invoke' -or [string]$audit.outcome -cne 'success') { throw 'ALPHA_GOLDEN_PATH_AUDIT_INVALID' }

        $canaries = @()
        foreach ($name in @('M3_VENDOR_API_KEY','M3_SYNTHETIC_VAULT_TOKEN','M3_VENDOR_CONTROL_TOKEN','M3_POSTGRES_ADMIN_PASSWORD','M3_POSTGRES_RUNTIME_PASSWORD','M3_CERTIFICATE_PASSWORD','M3_ACTIVATION_HMAC_BASE64','M5_POSTGRES_ADMIN_API_PASSWORD')) {
            if ($environment.ContainsKey($name)) { $canaries += [pscustomobject]@{ Name = $name; Value = [string]$environment[$name] } }
        }
        $canaries += [pscustomobject]@{ Name = 'DIRECT_ACTIVATION_CODE'; Value = [string]$provisioning.directActivationCode }
        Assert-RedactedText -Text ($sample.StdOut + $sample.StdErr) -Canaries $canaries
        Assert-RedactedText -Text $auditText -Canaries $canaries
        $composeArguments = @('compose', '--project-name', $project, '--env-file', $envFile, '--file', $baseCompose, '--file', $overlayCompose, 'logs', '--no-color')
        $logs = Invoke-Checked -File 'docker' -Arguments $composeArguments -Component Docker
        Assert-RedactedText -Text ($logs.StdOut + $logs.StdErr) -Canaries $canaries

        Write-Host "ALPHA_GOLDEN_PATH_CONNECTOR_PASS; SOURCE=docs/connectors/examples/sample-secure-service.connector.json; SHA256=$($canonical.Checksum); STATE=PUBLISHED; ENDPOINT=sample-vendor-endpoint; SECRET=sample-vendor-api-key; CERTIFICATE=sample-vendor-client-certificate"
        Write-Host 'ALPHA_GOLDEN_PATH_DIRECT_PASS; CONNECTOR=sample-secure-service; OPERATION=submit; VERSION=1.0.0'
        Write-Host "ALPHA_GOLDEN_PATH_OUTBOUND_PASS; POSITIVE_OUTBOUND_COUNT=$outboundCount; METHOD=POST; PATH=/vendor/orders; CONTENT_TYPE=application/json"
        Write-Host "ALPHA_GOLDEN_PATH_PROVIDER_PASS; API_KEY_READS=$apiKeyReads; CERTIFICATE_READS=$certificateReads"
        Write-Host 'ALPHA_GOLDEN_PATH_RESPONSE_PASS; SANITIZED=YES; AUDIT=METADATA_ONLY; LOGS=REDACTED'
    }
    catch { $failure = $_ }
    finally {
        foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process') }
        if ($cleanupRequired) {
            try { [void](Invoke-Quickstart -RequestedPhase Stop) }
            catch { $cleanupFailure = $_ }
        }
    }

    if ($null -ne $cleanupFailure) { throw 'ALPHA_GOLDEN_PATH_CLEANUP_FAILED' }
    if ($null -ne $failure) { throw $failure }
    Assert-ZeroProjectResources
    if (Test-Path -LiteralPath $artifactRoot) { throw 'ALPHA_GOLDEN_PATH_ARTIFACT_CLEANUP_FAILED' }
    Write-Host 'ALPHA_GOLDEN_PATH_CLEANUP_PASS; CONTAINERS=0; NETWORKS=0; VOLUMES=0; SYNTHETIC_MATERIAL=0'
    Write-Host 'ALPHA_GOLDEN_PATH_PASS'
}
catch {
    [Console]::Error.WriteLine((Get-StableAlphaFailure -Failure $_))
    exit 1
}

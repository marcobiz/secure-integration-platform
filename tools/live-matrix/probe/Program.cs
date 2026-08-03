using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using SecureIntegration.Broker.Sdk;
using SecureIntegration.Contracts;

namespace SecureIntegration.LiveMatrix.Probe;

internal static class Program
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static async Task<int> Main(string[] args)
    {
        Dictionary<string, string> options = ParseArguments(args);
        string? output = options.GetValueOrDefault("output");
        ProbeReport report = new()
        {
            Command = options.GetValueOrDefault("command") ?? string.Empty,
            Identity = CaptureIdentity(),
            StartedUtc = DateTimeOffset.UtcNow,
        };

        try
        {
            switch (report.Command)
            {
                case "authorized-pre":
                    await AuthorizedPreAsync(LoadInput(options), report).ConfigureAwait(false);
                    break;
                case "authorized-post":
                    await AuthorizedPostAsync(LoadInput(options), report).ConfigureAwait(false);
                    break;
                case "expected-key-failure":
                    await ExpectedKeyFailureAsync(LoadInput(options), report).ConfigureAwait(false);
                    break;
                case "read-encrypted-database":
                    ReadEncryptedDatabase(LoadInput(options), report);
                    break;
                case "unauthorized-same-user":
                    await UnauthorizedSameUserAsync(LoadInput(options), report).ConfigureAwait(false);
                    break;
                case "unauthorized-other-user":
                    await UnauthorizedOtherUserAsync(LoadInput(options), report).ConfigureAwait(false);
                    break;
                case "storage-denied":
                    StorageDenied(LoadInput(options), report);
                    break;
                case "dpapi-denied":
                    DpapiDenied(LoadInput(options), report);
                    break;
                default:
                    throw new ProbeFailure("unknown_probe_command");
            }

            report.Passed = report.Assertions.All(static assertion => assertion.Passed);
        }
        catch (Exception exception)
        {
            report.Passed = false;
            report.ErrorCode = RedactedError(exception);
        }
        finally
        {
            report.CompletedUtc = DateTimeOffset.UtcNow;
            if (!string.IsNullOrWhiteSpace(output))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
                await File.WriteAllTextAsync(output, JsonSerializer.Serialize(report, Json)).ConfigureAwait(false);
            }
        }

        return report.Passed ? 0 : 1;
    }

    private static async Task AuthorizedPreAsync(ProbeInput input, ProbeReport report)
    {
        BrokerClient client = Client(input);
        BrokerStatus status = await client.GetStatusAsync().ConfigureAwait(false);
        Assert(report, "A.pipe-connect", !string.IsNullOrWhiteSpace(status.Version), "Broker status returned");

        byte[] secret = Convert.FromBase64String(input.SecretBase64);
        byte[] plaintext = Convert.FromBase64String(input.PlaintextBase64);
        byte[] message = Convert.FromBase64String(input.MessageBase64);
        try
        {
            if (File.Exists(input.PersistentStatePath))
            {
                PersistentState? previous = JsonSerializer.Deserialize<PersistentState>(await File.ReadAllTextAsync(input.PersistentStatePath).ConfigureAwait(false), Json);
                if (previous is not null && !string.IsNullOrWhiteSpace(previous.SecretRef))
                {
                    await client.DeleteLocalSecretAsync(new DeleteLocalSecretRequest { SecretRef = previous.SecretRef }).ConfigureAwait(false);
                }
            }

            LocalSecretReference reference = await client.PutLocalSecretAsync(new PutLocalSecretRequest
            {
                LogicalName = "live-matrix-hmac",
                SecretClass = "Tenant",
                ValueBase64 = input.SecretBase64,
                AllowedOperations = [BrokerOperations.ComputeHmac],
            }).ConfigureAwait(false);
            ComputeHmacResult hmac = await client.ComputeHmacAsync(new ComputeHmacRequest { SecretRef = reference.SecretRef, MessageBase64 = input.MessageBase64 }).ConfigureAwait(false);
            byte[] expectedHmac = HMACSHA256.HashData(secret, message);
            Assert(report, "A.local-secret-hmac", CryptographicOperations.FixedTimeEquals(expectedHmac, Convert.FromBase64String(hmac.DigestBase64)), "HMAC matched local expectation");

            ProtectedDataResult protectedData = await client.ProtectDataAsync(new ProtectDataRequest { Purpose = input.Purpose, ContentType = input.ContentType, PlaintextBase64 = input.PlaintextBase64 }).ConfigureAwait(false);
            UnprotectedDataResult unprotected = await client.UnprotectDataAsync(new UnprotectDataRequest { Purpose = input.Purpose, ContentType = input.ContentType, EnvelopeBase64 = protectedData.EnvelopeBase64 }).ConfigureAwait(false);
            Assert(report, "A.protect-unprotect", CryptographicOperations.FixedTimeEquals(plaintext, Convert.FromBase64String(unprotected.PlaintextBase64)), "Protect/Unprotect round trip matched");

            string deniedCode = await ExpectBrokerErrorAsync(() => client.InvokeGatewayAsync(new InvokeGatewayRequest
            {
                ConnectorId = "not-granted",
                OperationId = "not-granted",
                ContentType = "application/json",
                PayloadBase64 = "e30=",
            })).ConfigureAwait(false);
            Assert(report, "A.only-granted-operations", deniedCode == "operation_not_granted", deniedCode);

            string materialCode = await InvokeUnknownOperationAsync(input, "GetDataKey").ConfigureAwait(false);
            Assert(report, "D.no-key-material-api", materialCode == "operation_not_supported", materialCode);
            string secretCode = await InvokeUnknownOperationAsync(input, "GetSecret").ConfigureAwait(false);
            Assert(report, "D.no-local-secret-api", secretCode == "operation_not_supported", secretCode);

            string invalidCode = await ExpectBrokerErrorAsync(() => client.ProtectDataAsync(new ProtectDataRequest { Purpose = input.Purpose, ContentType = input.ContentType, PlaintextBase64 = input.InvalidPayloadMarker })).ConfigureAwait(false);
            Assert(report, "F.invalid-payload", invalidCode == "invalid_base64", invalidCode);

            byte[] envelope = Convert.FromBase64String(protectedData.EnvelopeBase64);
            envelope[^1] ^= 0x01;
            string cryptoCode = await ExpectBrokerErrorAsync(() => client.UnprotectDataAsync(new UnprotectDataRequest { Purpose = input.Purpose, ContentType = input.ContentType, EnvelopeBase64 = Convert.ToBase64String(envelope) })).ConfigureAwait(false);
            Assert(report, "E.tampered-envelope", cryptoCode == "authentication_failed", cryptoCode);
            Assert(report, "F.crypto-failure", cryptoCode == "authentication_failed", cryptoCode);

            PersistentState state = new()
            {
                SecretRef = reference.SecretRef,
                EnvelopeBase64 = protectedData.EnvelopeBase64,
                ExpectedHmacBase64 = Convert.ToBase64String(expectedHmac),
                PlaintextSha256 = Convert.ToHexString(SHA256.HashData(plaintext)),
            };
            await File.WriteAllTextAsync(input.PersistentStatePath, JsonSerializer.Serialize(state, Json)).ConfigureAwait(false);
            Assert(report, "A.persistence-state-created", File.Exists(input.PersistentStatePath), "Opaque state persisted for restart/reboot verification");
            report.PipeSddl = await CapturePipeSddlAsync(input.PipeName).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(message);
        }
    }

    private static async Task AuthorizedPostAsync(ProbeInput input, ProbeReport report)
    {
        PersistentState state = JsonSerializer.Deserialize<PersistentState>(await File.ReadAllTextAsync(input.PersistentStatePath).ConfigureAwait(false), Json)
            ?? throw new ProbeFailure("persistent_state_invalid");
        BrokerClient client = Client(input);
        _ = await client.GetStatusAsync().ConfigureAwait(false);
        ComputeHmacResult hmac = await client.ComputeHmacAsync(new ComputeHmacRequest { SecretRef = state.SecretRef, MessageBase64 = input.MessageBase64 }).ConfigureAwait(false);
        Assert(report, "E.hmac-after-restart", CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(state.ExpectedHmacBase64), Convert.FromBase64String(hmac.DigestBase64)), "HMAC survived service identity restart/reboot");
        UnprotectedDataResult plaintext = await client.UnprotectDataAsync(new UnprotectDataRequest { Purpose = input.Purpose, ContentType = input.ContentType, EnvelopeBase64 = state.EnvelopeBase64 }).ConfigureAwait(false);
        string hash = Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(plaintext.PlaintextBase64)));
        Assert(report, "E.data-after-restart", string.Equals(hash, state.PlaintextSha256, StringComparison.Ordinal), "Protected data survived service identity restart/reboot");
    }

    private static async Task ExpectedKeyFailureAsync(ProbeInput input, ProbeReport report)
    {
        PersistentState state = JsonSerializer.Deserialize<PersistentState>(await File.ReadAllTextAsync(input.PersistentStatePath).ConfigureAwait(false), Json)
            ?? throw new ProbeFailure("persistent_state_invalid");
        string code = await ExpectBrokerErrorAsync(() => Client(input).UnprotectDataAsync(new UnprotectDataRequest
        {
            Purpose = input.Purpose,
            ContentType = input.ContentType,
            EnvelopeBase64 = state.EnvelopeBase64,
        })).ConfigureAwait(false);
        Assert(report, "E.tampered-key-rejected", code == "data_key_unwrap_failed", code);
        Assert(report, "F.exception-path", code == "data_key_unwrap_failed", code);
    }

    private static void ReadEncryptedDatabase(ProbeInput input, ProbeReport report)
    {
        byte[] bytes = File.ReadAllBytes(input.LegacyDatabasePath);
        Assert(report, "D.encrypted-database-readable", bytes.Length > 32, "Management account read the encrypted test database");
    }

    private static async Task UnauthorizedSameUserAsync(ProbeInput input, ProbeReport report)
    {
        await using NamedPipeClientStream pipe = new(".", input.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
        Assert(report, "B.pipe-acl-allows-registered-sid", pipe.IsConnected, "Same SID reached the pipe ACL");
        Guid correlation = Guid.NewGuid();
        await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(correlation, 0, new HandshakeRequest
        {
            ApplicationRegistrationId = input.ApplicationId,
            ClientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        }), timeout.Token).ConfigureAwait(false);
        IpcFrame? response = await IpcFrameCodec.ReadAsync(pipe, timeout.Token).ConfigureAwait(false);
        Assert(report, "B.process-policy-denied", response is null, "Different executable was rejected before authorization");
    }

    private static async Task UnauthorizedOtherUserAsync(ProbeInput input, ProbeReport report)
    {
        try
        {
            await using NamedPipeClientStream pipe = new(".", input.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(3));
            await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
            Assert(report, "C.pipe-denied", false, "Different SID unexpectedly connected");
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or TimeoutException or OperationCanceledException or IOException)
        {
            Assert(report, "C.pipe-denied", true, "Different SID could not connect");
        }
    }

    private static void StorageDenied(ProbeInput input, ProbeReport report)
    {
        bool directoryDenied = IsAccessDenied(() => _ = Directory.EnumerateFileSystemEntries(input.StoragePath).ToArray());
        bool fileDenied = IsAccessDenied(() => { using FileStream stream = File.OpenRead(input.StorageProbePath); _ = stream.ReadByte(); });
        bool metadataDenied = IsAccessDenied(() => { using FileStream stream = File.OpenRead(input.StorageMetadataPath); _ = stream.ReadByte(); });
        Assert(report, "storage.directory-denied", directoryDenied, "Broker directory enumeration denied");
        Assert(report, "storage.file-denied", fileDenied, "Protected blob read denied");
        Assert(report, "storage.metadata-denied", metadataDenied, "Protected secret metadata read denied");
    }

    private static void DpapiDenied(ProbeInput input, ProbeReport report)
    {
        byte[] wrapped = File.ReadAllBytes(input.DpapiCopyPath);
        byte[] entropy = SHA256.HashData("broker-data-key-v1"u8);
        try
        {
            byte[] plaintext = ProtectedData.Unprotect(wrapped, entropy, DataProtectionScope.CurrentUser);
            CryptographicOperations.ZeroMemory(plaintext);
            Assert(report, "dpapi.current-user-denied", false, "DPAPI unexpectedly unwrapped another identity's blob");
        }
        catch (CryptographicException)
        {
            Assert(report, "dpapi.current-user-denied", true, "DPAPI CurrentUser rejected service-owned blob");
        }

        byte[] protectedSecret = File.ReadAllBytes(input.DpapiSecretCopyPath);
        byte[] secretEntropy = SHA256.HashData(Encoding.UTF8.GetBytes("broker-local-secret-v1\n" + input.InstallationId));
        try
        {
            byte[] plaintext = ProtectedData.Unprotect(protectedSecret, secretEntropy, DataProtectionScope.CurrentUser);
            CryptographicOperations.ZeroMemory(plaintext);
            Assert(report, "dpapi.local-secret-denied", false, "DPAPI unexpectedly unwrapped another identity's local secret");
        }
        catch (CryptographicException)
        {
            Assert(report, "dpapi.local-secret-denied", true, "DPAPI CurrentUser rejected service-owned local secret");
        }
    }

    private static async Task<string> InvokeUnknownOperationAsync(ProbeInput input, string operation)
    {
        await using NamedPipeClientStream pipe = new(".", input.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(10));
        await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
        Guid handshakeId = Guid.NewGuid();
        await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(handshakeId, 0, new HandshakeRequest { ApplicationRegistrationId = input.ApplicationId, ClientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }), timeout.Token).ConfigureAwait(false);
        HandshakeResponse handshake = IpcFrameCodec.Deserialize<HandshakeResponse>((await IpcFrameCodec.ReadAsync(pipe, timeout.Token).ConfigureAwait(false)) ?? throw new ProbeFailure("handshake_closed"));
        Guid requestId = Guid.NewGuid();
        BrokerRequest request = new()
        {
            Operation = operation,
            CorrelationId = requestId,
            ConnectionChallenge = handshake.ServerChallenge,
            RequestNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)),
            DeadlineUtc = DateTimeOffset.UtcNow.AddSeconds(10),
            Body = JsonSerializer.SerializeToElement(new { }, IpcProtocol.JsonOptions),
        };
        await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(requestId, 1, request), timeout.Token).ConfigureAwait(false);
        BrokerResponse response = IpcFrameCodec.Deserialize<BrokerResponse>((await IpcFrameCodec.ReadAsync(pipe, timeout.Token).ConfigureAwait(false)) ?? throw new ProbeFailure("request_closed"));
        return response.Error?.Code ?? "unexpected_success";
    }

    private static async Task<string> CapturePipeSddlAsync(string pipeName)
    {
        await using NamedPipeClientStream pipe = new(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
        uint information = 0x00000001 | 0x00000002 | 0x00000004;
        uint result = GetSecurityInfo(pipe.SafePipeHandle.DangerousGetHandle(), 6, information, out _, out _, out _, out _, out IntPtr descriptor);
        if (result != 0) throw new ProbeFailure("pipe_security_read_failed");
        try
        {
            if (!ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor, 1, information, out IntPtr text, out _)) throw new ProbeFailure("pipe_sddl_conversion_failed");
            try { return Marshal.PtrToStringUni(text) ?? throw new ProbeFailure("pipe_sddl_empty"); }
            finally { _ = LocalFree(text); }
        }
        finally { _ = LocalFree(descriptor); }
    }

    private static bool IsAccessDenied(Action action)
    {
        try { action(); return false; }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException) { return true; }
    }

    private static async Task<string> ExpectBrokerErrorAsync(Func<Task> action)
    {
        try { await action().ConfigureAwait(false); return "unexpected_success"; }
        catch (BrokerClientException exception) { return exception.Code; }
    }

    private static BrokerClient Client(ProbeInput input) => new(new BrokerClientOptions
    {
        PipeName = input.PipeName,
        ApplicationRegistrationId = input.ApplicationId,
        ConnectTimeout = TimeSpan.FromSeconds(5),
        OperationTimeout = TimeSpan.FromSeconds(15),
    });

    private static ProbeInput LoadInput(Dictionary<string, string> options)
    {
        string path = options.GetValueOrDefault("input") ?? throw new ProbeFailure("input_required");
        return JsonSerializer.Deserialize<ProbeInput>(File.ReadAllText(path), Json) ?? throw new ProbeFailure("input_invalid");
    }

    private static Dictionary<string, string> ParseArguments(string[] args)
    {
        Dictionary<string, string> values = new(StringComparer.OrdinalIgnoreCase);
        for (int index = 0; index < args.Length; index += 2)
        {
            if (index + 1 >= args.Length || !args[index].StartsWith("--", StringComparison.Ordinal)) throw new ProbeFailure("invalid_arguments");
            values[args[index][2..]] = args[index + 1];
        }
        return values;
    }

    private static ProcessIdentity CaptureIdentity()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        using Process process = Process.GetCurrentProcess();
        string executable = Environment.ProcessPath ?? string.Empty;
        return new ProcessIdentity
        {
            UserName = identity.Name,
            UserSid = identity.User?.Value ?? string.Empty,
            ProcessId = Environment.ProcessId,
            ProcessStartUtc = process.StartTime.ToUniversalTime(),
            ExecutablePath = executable,
            ExecutableSha256 = File.Exists(executable) ? Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(executable))) : string.Empty,
        };
    }

    private static void Assert(ProbeReport report, string id, bool passed, string detail)
    {
        report.Assertions.Add(new ProbeAssertion { Id = id, Passed = passed, Detail = detail });
        if (!passed) throw new ProbeFailure(id);
    }

    private static string RedactedError(Exception exception) => exception switch
    {
        ProbeFailure failure => failure.Code,
        BrokerClientException broker => broker.Code,
        UnauthorizedAccessException => "access_denied",
        OperationCanceledException => "timeout_or_cancelled",
        CryptographicException => "cryptographic_failure",
        IOException => "io_failure",
        _ => exception.GetType().Name,
    };

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(IntPtr handle, int objectType, uint securityInfo, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr securityDescriptor, uint revision, uint securityInformation, out IntPtr stringSecurityDescriptor, out uint stringLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}

internal sealed class ProbeInput
{
    public string PipeName { get; set; } = string.Empty;
    public string ApplicationId { get; set; } = string.Empty;
    public string SecretBase64 { get; set; } = string.Empty;
    public string PlaintextBase64 { get; set; } = string.Empty;
    public string MessageBase64 { get; set; } = string.Empty;
    public string InvalidPayloadMarker { get; set; } = string.Empty;
    public string Purpose { get; set; } = "live-matrix";
    public string ContentType { get; set; } = "application/octet-stream";
    public string PersistentStatePath { get; set; } = string.Empty;
    public string StoragePath { get; set; } = string.Empty;
    public string StorageProbePath { get; set; } = string.Empty;
    public string StorageMetadataPath { get; set; } = string.Empty;
    public string DpapiCopyPath { get; set; } = string.Empty;
    public string DpapiSecretCopyPath { get; set; } = string.Empty;
    public string InstallationId { get; set; } = string.Empty;
    public string LegacyDatabasePath { get; set; } = string.Empty;
}

internal sealed class PersistentState
{
    public string SecretRef { get; set; } = string.Empty;
    public string EnvelopeBase64 { get; set; } = string.Empty;
    public string ExpectedHmacBase64 { get; set; } = string.Empty;
    public string PlaintextSha256 { get; set; } = string.Empty;
}

internal sealed class ProbeReport
{
    public string Command { get; set; } = string.Empty;
    public ProcessIdentity Identity { get; set; } = new();
    public DateTimeOffset StartedUtc { get; set; }
    public DateTimeOffset CompletedUtc { get; set; }
    public bool Passed { get; set; }
    public string? ErrorCode { get; set; }
    public string? PipeSddl { get; set; }
    public List<ProbeAssertion> Assertions { get; } = [];
}

internal sealed class ProcessIdentity
{
    public string UserName { get; set; } = string.Empty;
    public string UserSid { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public DateTime ProcessStartUtc { get; set; }
    public string ExecutablePath { get; set; } = string.Empty;
    public string ExecutableSha256 { get; set; } = string.Empty;
}

internal sealed class ProbeAssertion
{
    public string Id { get; set; } = string.Empty;
    public bool Passed { get; set; }
    public string Detail { get; set; } = string.Empty;
}

internal sealed class ProbeFailure(string code) : Exception(code)
{
    public string Code { get; } = code;
}

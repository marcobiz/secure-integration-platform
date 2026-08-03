using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using SecureIntegration.Broker.Core;
using SecureIntegration.Broker.Infrastructure.Windows;
using SecureIntegration.Broker.Sdk;
using SecureIntegration.Contracts;
using Xunit;

namespace SecureIntegration.Broker.Integration.Tests;

public sealed class WindowsBrokerIntegrationTests
{
    [Fact]
    public async Task Named_pipe_caller_identity_is_captured_from_the_kernel()
    {
        string name = "SecureIntegration.Identity.Tests." + Guid.NewGuid().ToString("N");
        await using NamedPipeServerStream server = new(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await using NamedPipeClientStream client = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        Task accepting = server.WaitForConnectionAsync(TestContext.Current.CancellationToken);
        await client.ConnectAsync(TestContext.Current.CancellationToken);
        await accepting;
        using CallerIdentity caller = NamedPipeCallerIdentity.Capture(server);
        Assert.Equal((uint)Environment.ProcessId, caller.ProcessId);
        Assert.Equal(Environment.ProcessPath, caller.ExecutablePath, ignoreCase: true);
        Assert.Equal(Process.GetCurrentProcess().StartTime.ToUniversalTime(), caller.ProcessStartTimeUtc.UtcDateTime, TimeSpan.FromSeconds(1));
        Process retainedProcess = Assert.IsType<Process>(typeof(CallerIdentity).GetField("process", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(caller));
        FileStream retainedExecutable = Assert.IsType<FileStream>(typeof(CallerIdentity).GetField("executableFile", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(caller));
        Microsoft.Win32.SafeHandles.SafeProcessHandle retainedHandle = retainedProcess.SafeHandle;
        Microsoft.Win32.SafeHandles.SafeFileHandle retainedFileHandle = retainedExecutable.SafeFileHandle;
        caller.Dispose();
        Assert.True(retainedHandle.IsClosed);
        Assert.True(retainedFileHandle.IsClosed);
    }

    [Fact]
    public void DPAPI_CurrentUser_round_trip_and_ciphertext_is_not_plaintext()
    {
        WindowsDpapiProtectionProvider provider = new();
        byte[] plaintext = "offline-secret-marker"u8.ToArray();
        byte[] protectedValue = provider.Protect(plaintext, "test-entropy"u8.ToArray());
        Assert.False(protectedValue.AsSpan().IndexOf(plaintext) >= 0);
        Assert.Equal(plaintext, provider.Unprotect(protectedValue, "test-entropy"u8.ToArray()));
    }

    [Fact]
    public void Broker_storage_ACL_is_protected_and_has_no_world_grant()
    {
        using TestDirectory temporary = new();
        WindowsStorageSecurity.HardenDirectory(temporary.Path);
        DirectorySecurity security = new DirectoryInfo(temporary.Path).GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
        SecurityIdentifier world = new(WellKnownSidType.WorldSid, null);
        Assert.DoesNotContain(security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>(), rule => rule.IdentityReference == world && rule.AccessControlType == AccessControlType.Allow);
    }

    [Fact]
    public void Named_pipe_ACL_is_protected_and_contains_only_configured_principals()
    {
        using TestDirectory temporary = new();
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        BrokerOptions options = new()
        {
            PipeName = "SecureIntegration.Acl.Tests." + Guid.NewGuid().ToString("N"),
            InstallationId = "acl-test",
            DataDirectory = temporary.Path,
            Applications = [new ApplicationPolicy { RegistrationId = "app", AllowedUserSids = [sid], ExecutablePaths = [Environment.ProcessPath!] }],
        };
        WindowsDpapiProtectionProvider protection = new();
        using FileLocalSecretRepository secrets = new(temporary.Path);
        using FileDataKeyRepository keys = new(temporary.Path, protection);
        BrokerApplicationService application = new(secrets, protection, new AeadDataProtector(keys, options.InstallationId), new NullAudit(), options.InstallationId);
        NamedPipeBrokerServer broker = new(options, new ApplicationAuthorizer(options.Applications), new BrokerRequestDispatcher(application));
        using NamedPipeServerStream pipe = Assert.IsType<NamedPipeServerStream>(typeof(NamedPipeBrokerServer).GetMethod("CreatePipe", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.Invoke(broker, null));
        PipeSecurity security = pipe.GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
        string[] allowed = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().Where(static rule => rule.AccessControlType == AccessControlType.Allow).Select(static rule => rule.IdentityReference.Value).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        Assert.All(allowed, value => Assert.Equal(sid, value, ignoreCase: true));
    }

    [Fact]
    public async Task Service_install_contract_uses_a_virtual_service_account()
    {
        string root = FindRepositoryRoot();
        string script = await File.ReadAllTextAsync(System.IO.Path.Combine(root, "deploy", "windows", "install-service.ps1"), TestContext.Current.CancellationToken);
        Assert.Contains("NT SERVICE\\SecureIntegrationBroker", script, StringComparison.Ordinal);
        Assert.DoesNotContain("LocalSystem", script, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Offline_storage_contains_no_plaintext_and_corruption_is_denied()
    {
        using TestDirectory temporary = new();
        WindowsDpapiProtectionProvider protection = new();
        using FileLocalSecretRepository secrets = new(temporary.Path);
        using FileDataKeyRepository keys = new(temporary.Path, protection);
        BrokerApplicationService service = new(secrets, protection, new AeadDataProtector(keys, "installation-a"), new NullAudit(), "installation-a");
        string reference = await service.PutLocalSecretAsync("app-a", "tenant-key", "Tenant", ["ComputeHmac"], "plaintext-never-at-rest"u8.ToArray(), Guid.NewGuid(), TestContext.Current.CancellationToken);
        string persisted = await File.ReadAllTextAsync(Directory.GetFiles(System.IO.Path.Combine(temporary.Path, "secrets"))[0], TestContext.Current.CancellationToken);
        Assert.DoesNotContain("plaintext-never-at-rest", persisted, StringComparison.Ordinal);

        string keyPath = System.IO.Path.Combine(temporary.Path, "keys", "key-1.bin");
        _ = await keys.GetActiveAsync(TestContext.Current.CancellationToken);
        await File.WriteAllBytesAsync(keyPath, [1, 2, 3], TestContext.Current.CancellationToken);
        BrokerException failure = await Assert.ThrowsAsync<BrokerException>(() => keys.GetAsync(1, TestContext.Current.CancellationToken));
        Assert.Equal("data_key_unwrap_failed", failure.Code);
        Assert.StartsWith("lsr_", reference, StringComparison.Ordinal);

        const string corruptReference = "lsr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        string corruptPath = System.IO.Path.Combine(temporary.Path, "secrets", corruptReference + ".json");
        await File.WriteAllTextAsync(corruptPath, "{\"SecretRef\":\"lsr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"OwnerApplicationId\":\"app-a\",\"LogicalName\":\"x\",\"SecretClass\":\"Tenant\",\"AllowedOperations\":[],\"ProtectedValueBase64\":\"not-base64\"}", TestContext.Current.CancellationToken);
        BrokerException corruptSecret = await Assert.ThrowsAsync<BrokerException>(() => secrets.FindAsync(corruptReference, TestContext.Current.CancellationToken));
        Assert.Equal("local_storage_corrupt", corruptSecret.Code);
    }

    [Fact]
    public async Task AC005_Installation_key_and_ciphertext_differentiation()
    {
        using TestDirectory firstDirectory = new();
        using TestDirectory secondDirectory = new();
        WindowsDpapiProtectionProvider protection = new();
        using FileDataKeyRepository firstKeys = new(firstDirectory.Path, protection);
        using FileDataKeyRepository secondKeys = new(secondDirectory.Path, protection);
        byte[] first = await new AeadDataProtector(firstKeys, "installation-a").ProtectAsync("app", "purpose", "text/plain", [1], TestContext.Current.CancellationToken);
        byte[] second = await new AeadDataProtector(secondKeys, "installation-b").ProtectAsync("app", "purpose", "text/plain", [1], TestContext.Current.CancellationToken);
        Assert.NotEqual((await firstKeys.GetActiveAsync(TestContext.Current.CancellationToken)).Value, (await secondKeys.GetActiveAsync(TestContext.Current.CancellationToken)).Value);
        Assert.NotEqual(first, second);
    }

    [Fact]
    public async Task Repository_reopen_recovers_keys_secrets_and_protected_data_under_same_identity()
    {
        using TestDirectory temporary = new();
        WindowsDpapiProtectionProvider protection = new();
        string secretReference;
        byte[] envelope;
        byte[] expectedHmac = HMACSHA256.HashData("restart-key"u8.ToArray(), "message"u8.ToArray());
        using (FileLocalSecretRepository secrets = new(temporary.Path))
        using (FileDataKeyRepository keys = new(temporary.Path, protection))
        {
            BrokerApplicationService beforeRestart = new(secrets, protection, new AeadDataProtector(keys, "installation-restart"), new NullAudit(), "installation-restart");
            secretReference = await beforeRestart.PutLocalSecretAsync("app-a", "restart-key", "Tenant", ["ComputeHmac"], "restart-key"u8.ToArray(), Guid.NewGuid(), TestContext.Current.CancellationToken);
            envelope = await beforeRestart.ProtectDataAsync("app-a", "restart", "application/json", "persisted-data"u8.ToArray(), TestContext.Current.CancellationToken);
        }

        using (FileLocalSecretRepository secrets = new(temporary.Path))
        using (FileDataKeyRepository keys = new(temporary.Path, protection))
        {
            BrokerApplicationService afterRestart = new(secrets, protection, new AeadDataProtector(keys, "installation-restart"), new NullAudit(), "installation-restart");
            Assert.Equal(expectedHmac, await afterRestart.ComputeHmacAsync("app-a", secretReference, "message"u8.ToArray(), Guid.NewGuid(), TestContext.Current.CancellationToken));
            Assert.Equal("persisted-data"u8.ToArray(), await afterRestart.UnprotectDataAsync("app-a", "restart", "application/json", envelope, TestContext.Current.CancellationToken));
        }
    }

    [Fact]
    public async Task IT_BRK_Authorized_application_uses_pipe_and_unauthorized_hash_is_denied()
    {
        await WithBrokerAsync(async client =>
        {
            ProtectedDataResult protectedData = await client.ProtectDataAsync(new ProtectDataRequest { Purpose = "test", ContentType = "text/plain", PlaintextBase64 = Convert.ToBase64String("hello"u8) }, TestContext.Current.CancellationToken);
            UnprotectedDataResult plaintext = await client.UnprotectDataAsync(new UnprotectDataRequest { Purpose = "test", ContentType = "text/plain", EnvelopeBase64 = protectedData.EnvelopeBase64 }, TestContext.Current.CancellationToken);
            Assert.Equal("hello"u8.ToArray(), Convert.FromBase64String(plaintext.PlaintextBase64));
        });

        await Assert.ThrowsAnyAsync<Exception>(() => WithBrokerAsync(client => client.GetStatusAsync(TestContext.Current.CancellationToken), invalidHash: true));
        await Assert.ThrowsAnyAsync<Exception>(() => WithBrokerAsync(client => client.GetStatusAsync(TestContext.Current.CancellationToken), invalidPublisher: true));
    }

    [Fact]
    public async Task Pipe_supports_concurrent_clients_and_deadline_cancellation()
    {
        await WithBrokerAsync(async client =>
        {
            Task<ProtectedDataResult>[] requests = Enumerable.Range(0, 8).Select(index => client.ProtectDataAsync(new ProtectDataRequest { Purpose = "concurrent-" + index, PlaintextBase64 = Convert.ToBase64String([checked((byte)index)]) }, TestContext.Current.CancellationToken)).ToArray();
            ProtectedDataResult[] results = await Task.WhenAll(requests);
            Assert.Equal(8, results.Length);
        });

        await WithBrokerAsync(async client =>
        {
            BrokerClientException failure = await Assert.ThrowsAsync<BrokerClientException>(() => client.InvokeGatewayAsync(new InvokeGatewayRequest { ConnectorId = "secure-layer-demo", OperationId = "submit", PayloadBase64 = "e30=" }, TestContext.Current.CancellationToken));
            Assert.Equal("deadline_exceeded", failure.Code);
        }, operationTimeout: TimeSpan.FromMilliseconds(100), gateway: new SlowGateway());
    }

    [Fact]
    public async Task Same_connection_multiplexes_requests_and_honors_cancel_frame()
    {
        await WithBrokerAndPipeAsync(async (_, name) =>
        {
            await using NamedPipeClientStream pipe = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(TestContext.Current.CancellationToken);
            Guid handshakeId = Guid.NewGuid();
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(handshakeId, 0, new HandshakeRequest { ApplicationRegistrationId = "test-app", ClientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }), TestContext.Current.CancellationToken);
            HandshakeResponse handshake = IpcFrameCodec.Deserialize<HandshakeResponse>((await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken))!);

            BrokerRequest Request(Guid id, string operation, object body) => new()
            {
                Operation = operation,
                CorrelationId = id,
                ConnectionChallenge = handshake.ServerChallenge,
                RequestNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)),
                DeadlineUtc = DateTimeOffset.UtcNow.AddSeconds(5),
                Body = JsonSerializer.SerializeToElement(body, IpcProtocol.JsonOptions),
            };

            Guid first = Guid.NewGuid();
            Guid second = Guid.NewGuid();
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(first, 1, Request(first, BrokerOperations.GetBrokerStatus, new { })), TestContext.Current.CancellationToken);
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(second, 2, Request(second, BrokerOperations.GetBrokerStatus, new { })), TestContext.Current.CancellationToken);
            HashSet<Guid> responses = [];
            responses.Add(IpcFrameCodec.Deserialize<BrokerResponse>((await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken))!).CorrelationId);
            responses.Add(IpcFrameCodec.Deserialize<BrokerResponse>((await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken))!).CorrelationId);
            Assert.Equal(2, responses.Count);
            Assert.Contains(first, responses);
            Assert.Contains(second, responses);

            Guid slow = Guid.NewGuid();
            InvokeGatewayRequest invoke = new() { ConnectorId = "secure-layer-demo", OperationId = "submit", PayloadBase64 = "e30=" };
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(slow, 3, Request(slow, BrokerOperations.InvokeGateway, invoke)), TestContext.Current.CancellationToken);
            await IpcFrameCodec.WriteAsync(pipe, new IpcFrame(IpcFrameType.Cancel, slow, 4, []), TestContext.Current.CancellationToken);
            BrokerResponse cancelled = IpcFrameCodec.Deserialize<BrokerResponse>((await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken))!);
            Assert.Equal("cancelled", cancelled.Error?.Code);
        }, gateway: new SlowGateway());
    }

    [Fact]
    public async Task Wire_errors_redact_invalid_payload_and_cryptographic_failure()
    {
        CapturingAudit audit = new();
        await WithBrokerAndPipeAsync(async (client, name) =>
        {
            ProtectedDataResult valid = await client.ProtectDataAsync(new ProtectDataRequest { Purpose = "redaction", ContentType = "text/plain", PlaintextBase64 = Convert.ToBase64String("sensitive-plaintext"u8) }, TestContext.Current.CancellationToken);
            byte[] tampered = Convert.FromBase64String(valid.EnvelopeBase64);
            tampered[^1] ^= 1;

            await using NamedPipeClientStream pipe = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(TestContext.Current.CancellationToken);
            Guid handshakeId = Guid.NewGuid();
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(handshakeId, 0, new HandshakeRequest { ApplicationRegistrationId = "test-app", ClientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }), TestContext.Current.CancellationToken);
            HandshakeResponse handshake = IpcFrameCodec.Deserialize<HandshakeResponse>((await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken))!);

            BrokerRequest Request(Guid id, string operation, object body) => new()
            {
                Operation = operation,
                CorrelationId = id,
                ConnectionChallenge = handshake.ServerChallenge,
                RequestNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)),
                DeadlineUtc = DateTimeOffset.UtcNow.AddSeconds(5),
                Body = JsonSerializer.SerializeToElement(body, IpcProtocol.JsonOptions),
            };

            const string invalidSensitiveValue = "sensitive-invalid-base64-value";
            Guid invalidId = Guid.NewGuid();
            ProtectDataRequest invalidBody = new() { Purpose = "redaction", ContentType = "text/plain", PlaintextBase64 = invalidSensitiveValue };
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(invalidId, 1, Request(invalidId, BrokerOperations.ProtectData, invalidBody)), TestContext.Current.CancellationToken);
            IpcFrame invalidFrame = (await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken))!;
            string invalidWire = Encoding.UTF8.GetString(invalidFrame.Body);
            BrokerResponse invalidResponse = IpcFrameCodec.Deserialize<BrokerResponse>(invalidFrame);
            Assert.Equal("invalid_base64", invalidResponse.Error?.Code);
            Assert.DoesNotContain(invalidSensitiveValue, invalidWire, StringComparison.Ordinal);
            Assert.DoesNotContain("FormatException", invalidWire, StringComparison.Ordinal);
            Assert.DoesNotContain("C:\\", invalidWire, StringComparison.OrdinalIgnoreCase);

            Guid cryptoId = Guid.NewGuid();
            UnprotectDataRequest cryptoBody = new() { Purpose = "redaction", ContentType = "text/plain", EnvelopeBase64 = Convert.ToBase64String(tampered) };
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(cryptoId, 2, Request(cryptoId, BrokerOperations.UnprotectData, cryptoBody)), TestContext.Current.CancellationToken);
            IpcFrame cryptoFrame = (await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken))!;
            string cryptoWire = Encoding.UTF8.GetString(cryptoFrame.Body);
            BrokerResponse cryptoResponse = IpcFrameCodec.Deserialize<BrokerResponse>(cryptoFrame);
            Assert.Equal("authentication_failed", cryptoResponse.Error?.Code);
            Assert.DoesNotContain(valid.EnvelopeBase64, cryptoWire, StringComparison.Ordinal);
            Assert.DoesNotContain("CryptographicException", cryptoWire, StringComparison.Ordinal);
        }, audit: audit);
        string auditText = string.Join("\n", audit.Events);
        Assert.DoesNotContain("sensitive", auditText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CryptographicException", auditText, StringComparison.Ordinal);
        Assert.Contains("invalid_base64", auditText, StringComparison.Ordinal);
        Assert.Contains("authentication_failed", auditText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Audit_logging_redacts_normal_and_authentication_denied_paths()
    {
        const string sensitive = "audit-sensitive-local-secret";
        CapturingAudit normalAudit = new();
        await WithBrokerAsync(async client =>
        {
            LocalSecretReference reference = await client.PutLocalSecretAsync(new PutLocalSecretRequest
            {
                LogicalName = "audit-key",
                SecretClass = "Tenant",
                ValueBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(sensitive)),
                AllowedOperations = ["ComputeHmac"],
            }, TestContext.Current.CancellationToken);
            _ = await client.ComputeHmacAsync(new ComputeHmacRequest { SecretRef = reference.SecretRef, MessageBase64 = Convert.ToBase64String("message"u8) }, TestContext.Current.CancellationToken);
        }, audit: normalAudit);
        Assert.DoesNotContain(sensitive, string.Join("\n", normalAudit.Events), StringComparison.Ordinal);

        CapturingAudit deniedAudit = new();
        await Assert.ThrowsAnyAsync<Exception>(() => WithBrokerAsync(client => client.GetStatusAsync(TestContext.Current.CancellationToken), invalidHash: true, audit: deniedAudit));
        string deniedText = string.Join("\n", deniedAudit.Events);
        Assert.Contains("application_not_authorized", deniedText, StringComparison.Ordinal);
        Assert.DoesNotContain(Environment.ProcessPath!, deniedText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(new string('0', 64), deniedText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Handshake_rejects_nonzero_sequence_and_malformed_nonce()
    {
        await WithBrokerAndPipeAsync(async (_, name) =>
        {
            async Task AssertRejectedAsync(ulong sequence, string nonce)
            {
                await using NamedPipeClientStream pipe = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(TestContext.Current.CancellationToken);
                Guid correlation = Guid.NewGuid();
                HandshakeRequest request = new() { ApplicationRegistrationId = "test-app", ClientNonce = nonce };
                await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(correlation, sequence, request), TestContext.Current.CancellationToken);
                Assert.Null(await IpcFrameCodec.ReadAsync(pipe, TestContext.Current.CancellationToken));
            }

            await AssertRejectedAsync(1, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
            await AssertRejectedAsync(0, "not-base64");
        });
    }

    private static async Task WithBrokerAsync(Func<BrokerClient, Task> test, bool invalidHash = false, bool invalidPublisher = false, TimeSpan? operationTimeout = null, IGatewayInvoker? gateway = null, IBrokerAuditSink? audit = null)
        => await WithBrokerAndPipeAsync((client, _) => test(client), invalidHash, invalidPublisher, operationTimeout, gateway, audit);

    private static async Task WithBrokerAndPipeAsync(Func<BrokerClient, string, Task> test, bool invalidHash = false, bool invalidPublisher = false, TimeSpan? operationTimeout = null, IGatewayInvoker? gateway = null, IBrokerAuditSink? audit = null)
    {
        using TestDirectory temporary = new();
        string pipeName = "SecureIntegration.Broker.Tests." + Guid.NewGuid().ToString("N");
        string executable = Environment.ProcessPath ?? throw new InvalidOperationException("The test host path is unavailable.");
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        string hash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(executable, TestContext.Current.CancellationToken)));
        ApplicationPolicy policy = new()
        {
            RegistrationId = "test-app",
            AllowedUserSids = [sid],
            ExecutablePaths = [executable],
            ExecutableSha256 = [invalidHash ? new string('0', 64) : hash],
            AllowedPublisherThumbprints = invalidPublisher ? [new string('0', 40)] : [],
            AllowedOperations = [BrokerOperations.PutLocalSecret, BrokerOperations.DeleteLocalSecret, BrokerOperations.ComputeHmac, BrokerOperations.ProtectData, BrokerOperations.UnprotectData, BrokerOperations.GetBrokerStatus, BrokerOperations.InvokeGateway],
            GatewayGrants = ["secure-layer-demo:submit"],
        };
        BrokerOptions options = new() { PipeName = pipeName, InstallationId = "test-installation", DataDirectory = temporary.Path, Applications = [policy] };
        WindowsDpapiProtectionProvider protection = new();
        using FileLocalSecretRepository secrets = new(temporary.Path);
        using FileDataKeyRepository keys = new(temporary.Path, protection);
        IBrokerAuditSink selectedAudit = audit ?? new NullAudit();
        BrokerApplicationService application = new(secrets, protection, new AeadDataProtector(keys, options.InstallationId), selectedAudit, options.InstallationId, gateway);
        await using NamedPipeBrokerServer server = new(options, new ApplicationAuthorizer(options.Applications), new BrokerRequestDispatcher(application), selectedAudit);
        using CancellationTokenSource stopped = new();
        Task running = server.RunAsync(stopped.Token);
        BrokerClient client = new(new BrokerClientOptions { PipeName = pipeName, ApplicationRegistrationId = policy.RegistrationId, OperationTimeout = operationTimeout ?? TimeSpan.FromSeconds(5) });
        try { await test(client, pipeName); }
        finally
        {
            stopped.Cancel();
            await running;
        }
    }

    private sealed class SlowGateway : IGatewayInvoker
    {
        public async Task<GatewayInvocationResult> InvokeAsync(string applicationId, string connectorId, string operationId, string contentType, byte[] payload, Guid correlationId, CancellationToken cancellationToken)
        {
            await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
            return new GatewayInvocationResult("application/json", [], "1");
        }
    }

    private sealed class NullAudit : IBrokerAuditSink
    {
        public Task WriteAsync(string operation, string applicationId, Guid correlationId, bool succeeded, string? errorCode, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class CapturingAudit : IBrokerAuditSink
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<string> events = new();
        public IReadOnlyCollection<string> Events => events.ToArray();
        public Task WriteAsync(string operation, string applicationId, Guid correlationId, bool succeeded, string? errorCode, CancellationToken cancellationToken)
        {
            events.Enqueue($"operation={operation} application={applicationId} correlation={correlationId:D} succeeded={succeeded} error={errorCode}");
            return Task.CompletedTask;
        }
    }

    private sealed class TestDirectory : IDisposable
    {
        public TestDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "broker-gateway-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }
        public string Path { get; }
        public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true); }
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(System.IO.Path.Combine(directory.FullName, "global.json"))) directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }
}

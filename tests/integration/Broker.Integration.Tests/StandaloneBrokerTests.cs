using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using SecureIntegration.Broker.Core;
using SecureIntegration.Broker.Infrastructure.Windows;
using SecureIntegration.Broker.Sdk;
using SecureIntegration.Contracts;
using Xunit;

namespace SecureIntegration.Broker.Integration.Tests;

public sealed class StandaloneBrokerTests
{
    [Fact]
    public void Broker_process_verification_preparation_executes_the_native_current_process_boundary()
    {
        // This account already owns the test process; no new principal receives access.
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        WindowsProcessSecurity.AllowClientVerification([new ApplicationPolicy { AllowedUserSids = [sid] }]);
    }

    [Fact]
    public void Broker_process_verification_ACL_adds_only_configured_account_query_and_synchronize_and_preserves_denials()
    {
        const string account = "S-1-5-21-10001-10002-10003-1001";
        RawSecurityDescriptor original = new("O:SYG:SYD:(D;;0x1;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)");
        RawAcl originalAcl = original.DiscretionaryAcl!;
        DiscretionaryAcl updated = WindowsProcessSecurity.BuildVerificationAcl(originalAcl, [account, account]);
        CommonAce added = Assert.Single(updated.Cast<GenericAce>().OfType<CommonAce>(), ace => ace.SecurityIdentifier.Value == account);
        Assert.Equal(AceQualifier.AccessAllowed, added.AceQualifier);
        Assert.Equal(0x101000, added.AccessMask);
        Assert.Equal(AceFlags.None, added.AceFlags);
        // No terminate/thread/duplicate-handle/VM/token/control/owner-write grant.
        Assert.Equal(0, added.AccessMask & 0x000F0FFF);
        foreach (GenericAce expected in originalAcl)
            Assert.Contains(updated.Cast<GenericAce>(), actual => expected.Equals(actual));
        Assert.Equal(3, originalAcl.Count);
        Assert.DoesNotContain(updated.Cast<GenericAce>().OfType<CommonAce>(), ace =>
            ace.AceQualifier == AceQualifier.AccessAllowed && ace.SecurityIdentifier.IsWellKnown(WellKnownSidType.WorldSid));
        byte[] once = new byte[updated.BinaryLength];
        updated.GetBinaryForm(once, 0);
        DiscretionaryAcl repeated = WindowsProcessSecurity.BuildVerificationAcl(new RawAcl(once, 0), [account]);
        byte[] twice = new byte[repeated.BinaryLength];
        repeated.GetBinaryForm(twice, 0);
        Assert.Equal(once, twice);
    }

    [Theory]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-32-545")]
    public void Broker_process_verification_never_adds_broad_group_grants(string sid)
    {
        RawSecurityDescriptor original = new("O:SYG:SYD:(A;;GA;;;SY)");
        BrokerException failure = Assert.Throws<BrokerException>(() => WindowsProcessSecurity.BuildVerificationAcl(original.DiscretionaryAcl!, [sid]));
        Assert.Equal("broker_process_security_unavailable", failure.Code);
        Assert.Single(original.DiscretionaryAcl!.Cast<GenericAce>());
    }

    [Theory]
    [InlineData("ProtectData", "other-purpose", "text/plain")]
    [InlineData("UnprotectData", "sample", "application/json")]
    [InlineData("ProtectData", "SAMPLE", "text/plain")]
    public async Task Ungranted_data_context_is_denied_before_decoding_or_key_use(string operation, string purpose, string contentType)
    {
        using KeyDirectory directory = new();
        WindowsDpapiProtectionProvider protection = new();
        using FileDataKeyRepository keys = new(directory.Path, protection);
        using FileLocalSecretRepository secrets = new(directory.Path);
        BrokerRequestDispatcher dispatcher = new(new BrokerApplicationService(secrets, protection, new AeadDataProtector(keys, "install"), new NoAudit(), "install"));
        ApplicationPolicy policy = new()
        {
            AllowedOperations = ["ProtectData", "UnprotectData"],
            AllowedDataProtectionContexts = [new() { Purpose = "sample", ContentType = "text/plain" }]
        };
        BrokerRequest request = new()
        {
            Operation = operation,
            Body = operation == "ProtectData"
                ? System.Text.Json.JsonSerializer.SerializeToElement(new { purpose, contentType, plaintextBase64 = "not-base64!" })
                : System.Text.Json.JsonSerializer.SerializeToElement(new { purpose, contentType, envelopeBase64 = "not-base64!" })
        };
        BrokerException failure = await Assert.ThrowsAsync<BrokerException>(() => dispatcher.DispatchAsync("app", policy, request, TestContext.Current.CancellationToken));
        Assert.Equal("data_context_not_granted", failure.Code);
        Assert.Empty(Directory.GetFiles(directory.Keys));
        request.Body = System.Text.Json.JsonSerializer.SerializeToElement(new { unexpectedField = "synthetic-private-input" });
        BrokerException malformed = await Assert.ThrowsAsync<BrokerException>(() => dispatcher.DispatchAsync("app", policy, request, TestContext.Current.CancellationToken));
        Assert.Equal("invalid_request", malformed.Code);
        Assert.Null(malformed.InnerException);
        Assert.DoesNotContain("synthetic-private-input", malformed.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SDK_binds_pipe_to_the_live_process_instance_and_releases_the_retained_handle()
    {
        using System.Diagnostics.Process other = new()
        {
            StartInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
                Arguments = "-NoProfile -NonInteractive -Command Start-Sleep -Seconds 30",
                UseShellExecute = false, CreateNoWindow = true
            }
        };
        Assert.True(other.Start());
        try
        {
            string name = "Broker.Instance." + Guid.NewGuid().ToString("N");
            using NamedPipeServerStream fake = new(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            SecurityIdentifier owner = WindowsIdentity.GetCurrent().Owner!;
            byte[] sid = new byte[owner.BinaryLength];
            owner.GetBinaryForm(sid, 0);
            using NamedPipeServerIdentity expected = new((uint)other.Id, sid);
            BrokerClient client = new(new BrokerClientOptions { PipeName = name }, () => expected);
            Task accepting = fake.WaitForConnectionAsync(TestContext.Current.CancellationToken);
            Task invocation = client.ProtectDataAsync(new ProtectDataRequest { Purpose = "test", PlaintextBase64 = "c3ludGhldGlj" }, TestContext.Current.CancellationToken);
            await accepting;
            BrokerClientException failure = await Assert.ThrowsAsync<BrokerClientException>(() => invocation);
            Assert.Equal("broker_server_not_authenticated", failure.Code);
            Assert.Equal(0, await fake.ReadAsync(new byte[1], TestContext.Current.CancellationToken));
            using NamedPipeClientStream unopened = new(name);
            Assert.Throws<ObjectDisposedException>(() => expected.Verify(unopened));
        }
        finally { if (!other.HasExited) other.Kill(); await other.WaitForExitAsync(TestContext.Current.CancellationToken); }
    }

    [Fact]
    public async Task Standalone_lifecycle_script_denies_foreign_resources_and_preserves_data_on_repeated_stop()
    {
        string directory = AppContext.BaseDirectory;
        while (!File.Exists(System.IO.Path.Combine(directory, "global.json"))) directory = Directory.GetParent(directory)!.FullName;
        using System.Diagnostics.Process process = new()
        {
            StartInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
            }
        };
        foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-File", System.IO.Path.Combine(directory, "tests", "integration", "Broker.Integration.Tests", "LocalBrokerLifecycle.Tests.ps1") }) process.StartInfo.ArgumentList.Add(argument);
        // A pwsh runner's module path is not Windows PowerShell 5.1's module path.
        process.StartInfo.Environment.Remove("PSModulePath");
        Assert.True(process.Start());
        Task<string> output = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        Task<string> error = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await process.WaitForExitAsync(TestContext.Current.CancellationToken);
        Assert.True(process.ExitCode == 0, await error);
        Assert.Contains("STOP_ABSENT_NORMAL_REPEAT_OWNERSHIP=PASS", await output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SDK_rejects_unregistered_fake_service_before_connecting_or_sending_input()
    {
        string name = "Broker.Fake." + Guid.NewGuid().ToString("N");
        using NamedPipeServerStream fake = new(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        BrokerClient client = new(new BrokerClientOptions { PipeName = name, ServiceName = name, ApplicationRegistrationId = "sample" });
        BrokerClientException failure = await Assert.ThrowsAsync<BrokerClientException>(() => client.ProtectDataAsync(new ProtectDataRequest { Purpose = "test", PlaintextBase64 = "c3ludGhldGlj" }, TestContext.Current.CancellationToken));
        Assert.Equal("broker_server_not_authenticated", failure.Code);
        Assert.False(fake.IsConnected);
    }

    [Fact]
    public async Task SDK_rejects_pipe_with_wrong_owner_before_handshake_or_plaintext()
    {
        string name = "Broker.Owner." + Guid.NewGuid().ToString("N");
        using NamedPipeServerStream fake = new(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        SecurityIdentifier unexpected = new(WellKnownSidType.LocalSystemSid, null);
        byte[] sid = new byte[unexpected.BinaryLength];
        unexpected.GetBinaryForm(sid, 0);
        BrokerClient client = new(new BrokerClientOptions { PipeName = name }, () => new NamedPipeServerIdentity((uint)Environment.ProcessId, sid));
        Task accepting = fake.WaitForConnectionAsync(TestContext.Current.CancellationToken);
        Task invocation = client.ProtectDataAsync(new ProtectDataRequest { Purpose = "test", PlaintextBase64 = "c3ludGhldGlj" }, TestContext.Current.CancellationToken);
        await accepting;
        BrokerClientException failure = await Assert.ThrowsAsync<BrokerClientException>(() => invocation);
        Assert.Equal("broker_server_not_authenticated", failure.Code);
        byte[] received = new byte[1];
        Assert.Equal(0, await fake.ReadAsync(received, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Data_keys_require_explicit_initialization_and_survive_reopen_and_same_profile_restore()
    {
        using KeyDirectory directory = new();
        WindowsDpapiProtectionProvider dpapi = new();
        byte[] envelope;
        using (FileDataKeyRepository keys = new(directory.Path, dpapi))
        {
            BrokerException absent = await Assert.ThrowsAsync<BrokerException>(() => keys.GetActiveAsync(TestContext.Current.CancellationToken));
            Assert.Equal("data_key_store_not_initialized", absent.Code);
            Assert.Empty(Directory.GetFiles(directory.Keys));
            await keys.InitializeAsync(TestContext.Current.CancellationToken);
            envelope = await new AeadDataProtector(keys, "install").ProtectAsync("app", "purpose", "text/plain", [1, 2, 3], TestContext.Current.CancellationToken);
        }
        byte[] backup = await File.ReadAllBytesAsync(directory.Key, TestContext.Current.CancellationToken);
        using (FileDataKeyRepository reopened = new(directory.Path, dpapi))
        {
            await reopened.InitializeAsync(TestContext.Current.CancellationToken);
            byte[] preserved = await File.ReadAllBytesAsync(directory.Key, TestContext.Current.CancellationToken);
            Assert.True(backup.SequenceEqual(preserved));
            byte[] recovered = await new AeadDataProtector(reopened, "install").UnprotectAsync("app", "purpose", "text/plain", envelope, TestContext.Current.CancellationToken);
            Assert.True(recovered.SequenceEqual(new byte[] { 1, 2, 3 }));
            await File.WriteAllBytesAsync(directory.Key, [1, 2, 3], TestContext.Current.CancellationToken);
            BrokerException corrupt = await Assert.ThrowsAsync<BrokerException>(() => reopened.GetActiveAsync(TestContext.Current.CancellationToken));
            Assert.Equal("data_key_unwrap_failed", corrupt.Code);
            await File.WriteAllBytesAsync(directory.Key, backup, TestContext.Current.CancellationToken);
            byte[] restored = await new AeadDataProtector(reopened, "install").UnprotectAsync("app", "purpose", "text/plain", envelope, TestContext.Current.CancellationToken);
            Assert.True(restored.SequenceEqual(new byte[] { 1, 2, 3 }));
        }
    }

    [Theory]
    [InlineData("active.txt", "data_key_store_not_initialized")]
    [InlineData("key-1.bin", "data_key_storage_unavailable")]
    public async Task Lost_key_or_metadata_never_regenerates_or_overwrites_remaining_state(string missing, string expected)
    {
        using KeyDirectory directory = new();
        using FileDataKeyRepository keys = new(directory.Path, new WindowsDpapiProtectionProvider());
        await keys.InitializeAsync(TestContext.Current.CancellationToken);
        File.Delete(System.IO.Path.Combine(directory.Keys, missing));
        Dictionary<string, byte[]> remaining = Directory.GetFiles(directory.Keys).ToDictionary(path => path, File.ReadAllBytes);
        BrokerException failure = await Assert.ThrowsAsync<BrokerException>(() => keys.GetActiveAsync(TestContext.Current.CancellationToken));
        Assert.Equal(expected, failure.Code);
        await Assert.ThrowsAsync<BrokerException>(() => keys.InitializeAsync(TestContext.Current.CancellationToken));
        Assert.Equal(remaining.Count, Directory.GetFiles(directory.Keys).Length);
        Assert.All(remaining, entry => Assert.True(entry.Value.SequenceEqual(File.ReadAllBytes(entry.Key))));
    }

    [Fact]
    public async Task Unreadable_key_and_DPAPI_failure_are_bounded_and_preserve_wrapped_bytes()
    {
        using KeyDirectory directory = new();
        using FileDataKeyRepository keys = new(directory.Path, new WindowsDpapiProtectionProvider());
        await keys.InitializeAsync(TestContext.Current.CancellationToken);
        byte[] before = File.ReadAllBytes(directory.Key);
        using (FileStream locked = File.Open(directory.Key, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            BrokerException lockedFailure = await Assert.ThrowsAsync<BrokerException>(() => keys.GetActiveAsync(TestContext.Current.CancellationToken));
            Assert.Equal("data_key_storage_unavailable", lockedFailure.Code);
        }
        using FileDataKeyRepository unavailableProfile = new(directory.Path, new UnavailableProfile());
        BrokerException failure = await Assert.ThrowsAsync<BrokerException>(() => unavailableProfile.InitializeAsync(TestContext.Current.CancellationToken));
        Assert.Equal("data_key_unwrap_failed", failure.Code);
        Assert.True(before.SequenceEqual(File.ReadAllBytes(directory.Key)));
    }

    [Fact]
    public async Task Interrupted_initialization_and_concurrent_initializers_cannot_replace_a_claimed_store()
    {
        using KeyDirectory directory = new();
        using FileDataKeyRepository first = new(directory.Path, new WindowsDpapiProtectionProvider());
        using FileDataKeyRepository second = new(directory.Path, new WindowsDpapiProtectionProvider());
        async Task Attempt(FileDataKeyRepository keys)
        {
            try { await keys.InitializeAsync(TestContext.Current.CancellationToken); }
            catch (BrokerException failure) { Assert.True(failure.Code is "data_key_initialization_incomplete" or "data_key_initialization_failed"); }
        }
        await Task.WhenAll(Attempt(first), Attempt(second));
        byte[] before = File.ReadAllBytes(directory.Key);
        await second.InitializeAsync(TestContext.Current.CancellationToken);
        Assert.True(before.SequenceEqual(File.ReadAllBytes(directory.Key)));
        File.Delete(directory.Key);
        File.Delete(System.IO.Path.Combine(directory.Keys, "active.txt"));
        BrokerException interrupted = await Assert.ThrowsAsync<BrokerException>(() => first.InitializeAsync(TestContext.Current.CancellationToken));
        Assert.Equal("data_key_initialization_incomplete", interrupted.Code);
        Assert.False(File.Exists(directory.Key));
    }

    private sealed class UnavailableProfile : ILocalProtectionProvider
    {
        public byte[] Protect(byte[] plaintext, byte[] entropy) => throw new InvalidOperationException("Must not generate replacement keys.");
        public byte[] Unprotect(byte[] protectedData, byte[] entropy) => throw new CryptographicException("Synthetic DPAPI profile unavailable");
    }

    private sealed class NoAudit : IBrokerAuditSink
    {
        public Task WriteAsync(string operation, string applicationId, Guid correlationId, bool succeeded, string? errorCode, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class KeyDirectory : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "broker-standalone-tests-" + Guid.NewGuid().ToString("N"));
        public string Keys => System.IO.Path.Combine(Path, "keys");
        public string Key => System.IO.Path.Combine(Keys, "key-1.bin");
        public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path, true); }
    }
}

using System.Reflection;
using System.Security.Cryptography;
using SecureIntegration.Broker.Core;
using Xunit;

namespace SecureIntegration.Broker.Core.Tests;

public sealed class BrokerCoreTests
{
    [Fact]
    public async Task UT_BRK_LocalSecretLifecycle()
    {
        MemorySecrets repository = new();
        BrokerApplicationService service = CreateService(repository, "installation-a");
        byte[] secret = "tenant-key"u8.ToArray();
        string reference = await service.PutLocalSecretAsync("app-a", "signing", "Tenant", ["ComputeHmac"], secret, Guid.NewGuid(), TestContext.Current.CancellationToken);

        Assert.StartsWith("lsr_", reference, StringComparison.Ordinal);
        Assert.NotEqual(secret, repository.Single!.ProtectedValue);
        byte[] digest = await service.ComputeHmacAsync("app-a", reference, "message"u8.ToArray(), Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal(HMACSHA256.HashData(secret, "message"u8.ToArray()), digest);

        await service.DeleteLocalSecretAsync("app-a", reference, Guid.NewGuid(), TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<BrokerException>(() => service.ComputeHmacAsync("app-a", reference, [], Guid.NewGuid(), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Local_secret_delete_is_idempotent_and_cross_application_use_is_denied()
    {
        MemorySecrets repository = new();
        BrokerApplicationService service = CreateService(repository, "installation-a");
        string reference = await service.PutLocalSecretAsync("app-a", "signing", "Session", ["ComputeHmac"], [1, 2, 3], Guid.NewGuid(), TestContext.Current.CancellationToken);
        BrokerException crossApplication = await Assert.ThrowsAsync<BrokerException>(() => service.ComputeHmacAsync("app-b", reference, [4], Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("secret_not_found", crossApplication.Code);
        await service.DeleteLocalSecretAsync("app-a", reference, Guid.NewGuid(), TestContext.Current.CancellationToken);
        await service.DeleteLocalSecretAsync("app-a", reference, Guid.NewGuid(), TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task HMAC_requires_an_explicit_secret_operation_grant()
    {
        BrokerApplicationService service = CreateService(new MemorySecrets(), "installation-a");
        string reference = await service.PutLocalSecretAsync("app-a", "signing", "Tenant", [], [1, 2, 3], Guid.NewGuid(), TestContext.Current.CancellationToken);
        BrokerException denied = await Assert.ThrowsAsync<BrokerException>(() => service.ComputeHmacAsync("app-a", reference, [4], Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("operation_not_granted", denied.Code);
    }

    [Theory]
    [InlineData("Vendor")]
    [InlineData("Operator")]
    public async Task Local_storage_rejects_non_local_secret_classes(string secretClass)
    {
        BrokerApplicationService service = CreateService(new MemorySecrets(), "installation-a");
        BrokerException failure = await Assert.ThrowsAsync<BrokerException>(() => service.PutLocalSecretAsync("app-a", "key", secretClass, [], [1], Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("secret_class_not_permitted", failure.Code);
    }

    [Fact]
    public async Task UT_CRYPTO_AeadRoundTripTamperRotation()
    {
        MemoryKeys keys = new();
        AeadDataProtector protector = new(keys, "installation-a");
        byte[] envelopeV1 = await protector.ProtectAsync("app-a", "cache", "application/json", "payload"u8.ToArray(), TestContext.Current.CancellationToken);
        keys.Rotate();
        byte[] envelopeV2 = await protector.ProtectAsync("app-a", "cache", "application/json", "payload"u8.ToArray(), TestContext.Current.CancellationToken);

        Assert.False(envelopeV1.AsSpan().SequenceEqual(envelopeV2));
        Assert.Equal("payload"u8.ToArray(), await protector.UnprotectAsync("app-a", "cache", "application/json", envelopeV1, TestContext.Current.CancellationToken));
        envelopeV2[^1] ^= 1;
        BrokerException failure = await Assert.ThrowsAsync<BrokerException>(() => protector.UnprotectAsync("app-a", "cache", "application/json", envelopeV2, TestContext.Current.CancellationToken));
        Assert.Equal("authentication_failed", failure.Code);
    }

    [Fact]
    public async Task Installation_and_application_are_authenticated_as_AAD()
    {
        MemoryKeys keys = new();
        AeadDataProtector first = new(keys, "installation-a");
        AeadDataProtector second = new(keys, "installation-b");
        byte[] envelope = await first.ProtectAsync("app-a", "purpose", "text/plain", [1, 2], TestContext.Current.CancellationToken);

        await Assert.ThrowsAsync<BrokerException>(() => first.UnprotectAsync("app-b", "purpose", "text/plain", envelope, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<BrokerException>(() => second.UnprotectAsync("app-a", "purpose", "text/plain", envelope, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void Public_API_has_no_GetSecret_operation()
    {
        string[] methods = typeof(BrokerApplicationService).GetMethods(BindingFlags.Instance | BindingFlags.Public).Select(static method => method.Name).ToArray();
        Assert.DoesNotContain(methods, static name => name.Contains("GetSecret", StringComparison.OrdinalIgnoreCase));
    }

    private static BrokerApplicationService CreateService(MemorySecrets secrets, string installation) =>
        new(secrets, new TestProtection(), new AeadDataProtector(new MemoryKeys(), installation), new NullAudit(), installation);

    private sealed class MemorySecrets : ILocalSecretRepository
    {
        private LocalSecretRecord? record;
        public LocalSecretRecord? Single => record;
        public Task<bool> DeleteAsync(string secretRef, CancellationToken cancellationToken)
        {
            bool found = record?.SecretRef == secretRef;
            record = null;
            return Task.FromResult(found);
        }
        public Task<LocalSecretRecord?> FindAsync(string secretRef, CancellationToken cancellationToken) => Task.FromResult(record?.SecretRef == secretRef ? record : null);
        public Task SaveAsync(LocalSecretRecord value, CancellationToken cancellationToken)
        {
            record = value with { ProtectedValue = value.ProtectedValue.ToArray() };
            return Task.CompletedTask;
        }
    }

    private sealed class MemoryKeys : IDataKeyRepository
    {
        private readonly Dictionary<uint, byte[]> keys = new() { [1] = RandomNumberGenerator.GetBytes(32) };
        private uint active = 1;
        public void Rotate() => keys[++active] = RandomNumberGenerator.GetBytes(32);
        public Task<DataKey> GetActiveAsync(CancellationToken cancellationToken) => Task.FromResult(new DataKey(active, keys[active].ToArray()));
        public Task<DataKey?> GetAsync(uint version, CancellationToken cancellationToken) => Task.FromResult(keys.TryGetValue(version, out byte[]? value) ? new DataKey(version, value.ToArray()) : null);
    }

    private sealed class TestProtection : ILocalProtectionProvider
    {
        public byte[] Protect(byte[] plaintext, byte[] entropy) => plaintext.Select(static value => (byte)(value ^ 0xA5)).ToArray();
        public byte[] Unprotect(byte[] protectedData, byte[] entropy) => Protect(protectedData, entropy);
    }

    private sealed class NullAudit : IBrokerAuditSink
    {
        public Task WriteAsync(string operation, string applicationId, Guid correlationId, bool succeeded, string? errorCode, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}

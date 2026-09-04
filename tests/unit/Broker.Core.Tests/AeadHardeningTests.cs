using System.Buffers.Binary;
using System.Security.Cryptography;
using SecureIntegration.Broker.Core;
using Xunit;

namespace SecureIntegration.Broker.Core.Tests;

public sealed class AeadHardeningTests
{
    [Fact]
    public async Task AEAD_context_delimiters_cannot_reinterpret_application_as_purpose()
    {
        AeadDataProtector protector = new(new StableKeys(), "installation-a");
        BrokerException failure = await Assert.ThrowsAsync<BrokerException>(() => protector.ProtectAsync("app-a", "purpose\nother", "text/plain", [1], TestContext.Current.CancellationToken));
        Assert.Equal("invalid_purpose", failure.Code);
        Assert.Throws<BrokerException>(() => new AeadDataProtector(new StableKeys(), "installation\nother"));
    }

    [Fact]
    public async Task AES_GCM_nonce_is_unique_across_repeated_protection()
    {
        StableKeys keys = new();
        AeadDataProtector protector = new(keys, "installation-a");
        HashSet<string> nonces = [];
        for (int index = 0; index < 512; index++)
        {
            byte[] envelope = await protector.ProtectAsync("app-a", "purpose", "application/json", "same plaintext"u8.ToArray(), TestContext.Current.CancellationToken);
            Assert.True(nonces.Add(Convert.ToHexString(envelope.AsSpan(8, 12))));
        }
    }

    [Theory]
    [InlineData("app-b", "purpose", "application/json")]
    [InlineData("app-a", "other-purpose", "application/json")]
    [InlineData("app-a", "purpose", "text/plain")]
    public async Task AEAD_authenticates_application_purpose_and_content_type(string application, string purpose, string contentType)
    {
        StableKeys keys = new();
        AeadDataProtector protector = new(keys, "installation-a");
        byte[] envelope = await protector.ProtectAsync("app-a", "purpose", "application/json", [1, 2, 3], TestContext.Current.CancellationToken);
        BrokerException failure = await Assert.ThrowsAsync<BrokerException>(() => protector.UnprotectAsync(application, purpose, contentType, envelope, TestContext.Current.CancellationToken));
        Assert.Equal("authentication_failed", failure.Code);
    }

    [Fact]
    public async Task AEAD_rejects_unknown_key_version_without_trying_another_key()
    {
        StableKeys keys = new();
        AeadDataProtector protector = new(keys, "installation-a");
        byte[] envelope = await protector.ProtectAsync("app-a", "purpose", "application/json", [1], TestContext.Current.CancellationToken);
        BinaryPrimitives.WriteUInt32BigEndian(envelope.AsSpan(4, 4), 999);
        BrokerException failure = await Assert.ThrowsAsync<BrokerException>(() => protector.UnprotectAsync("app-a", "purpose", "application/json", envelope, TestContext.Current.CancellationToken));
        Assert.Equal("key_version_not_found", failure.Code);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(35)]
    public async Task AEAD_rejects_malformed_envelope(int length)
    {
        AeadDataProtector protector = new(new StableKeys(), "installation-a");
        BrokerException failure = await Assert.ThrowsAsync<BrokerException>(() => protector.UnprotectAsync("app-a", "purpose", "application/json", new byte[length], TestContext.Current.CancellationToken));
        Assert.Equal("invalid_envelope", failure.Code);
    }

    private sealed class StableKeys : IDataKeyRepository
    {
        private readonly byte[] key = RandomNumberGenerator.GetBytes(32);
        public Task<DataKey> GetActiveAsync(CancellationToken cancellationToken) => Task.FromResult(new DataKey(7, key.ToArray()));
        public Task<DataKey?> GetAsync(uint version, CancellationToken cancellationToken) => Task.FromResult<DataKey?>(version == 7 ? new DataKey(7, key.ToArray()) : null);
    }
}

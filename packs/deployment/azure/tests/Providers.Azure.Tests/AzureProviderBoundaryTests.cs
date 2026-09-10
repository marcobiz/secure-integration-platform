using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Providers.Azure.Tests;

public sealed class AzureProviderBoundaryTests
{
    [Fact]
    public async Task Azure_provider_rejects_reference_for_another_vault_before_using_credential()
    {
        AzureSecretAndCertificateProvider provider = new(new Uri("https://allowed.vault.azure.net/"), new NeverCredential());
        ProviderAccessException denied = await Assert.ThrowsAsync<ProviderAccessException>(() => provider.GetSecretAsync("keyvault://other.vault.azure.net/vendor-key", TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-REFERENCE-DENIED", denied.Code);
    }

    [Fact]
    public async Task Azure_readiness_checks_configured_secret_version_metadata_without_vault_enumeration_or_value_download()
    {
        RecordingSecretClient client = new();
        client.AllowProperties("activation-hmac", "v1", enabled: true);
        AzureSecretAndCertificateProvider provider = new(
            new Uri("https://allowed.vault.azure.net/"),
            client,
            "keyvault://allowed.vault.azure.net/activation-hmac/v1");

        Assert.True(await provider.IsReadyAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, client.VersionPropertiesCalls);
        Assert.Equal(0, client.SecretValueCalls);
        Assert.Equal(0, client.ListCalls);
        Assert.Equal("activation-hmac", client.LastVersionPropertiesRequest);
    }

    [Theory]
    [InlineData(403)]
    [InlineData(404)]
    public async Task Azure_readiness_returns_false_for_denied_or_absent_configured_reference_without_vault_enumeration(int status)
    {
        RecordingSecretClient client = new() { Failure = new RequestFailedException(status, "synthetic") };
        AzureSecretAndCertificateProvider provider = new(
            new Uri("https://allowed.vault.azure.net/"),
            client,
            "keyvault://allowed.vault.azure.net/vendor-api-key");

        Assert.False(await provider.IsReadyAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, client.VersionPropertiesCalls);
        Assert.Equal(0, client.SecretValueCalls);
        Assert.Equal(0, client.ListCalls);
        Assert.Equal("vendor-api-key", client.LastVersionPropertiesRequest);
    }

    [Fact]
    public async Task Azure_readiness_without_configured_reference_is_not_ready_and_does_not_enumerate()
    {
        RecordingSecretClient client = new();
        AzureSecretAndCertificateProvider provider = new(new Uri("https://allowed.vault.azure.net/"), client);

        Assert.False(await provider.IsReadyAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0, client.VersionPropertiesCalls);
        Assert.Equal(0, client.SecretValueCalls);
        Assert.Equal(0, client.ListCalls);
    }

    private sealed class NeverCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new InvalidOperationException("Credential must not be used for a denied reference.");
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new InvalidOperationException("Credential must not be used for a denied reference.");
    }

    private sealed class RecordingSecretClient : SecretClient
    {
        private readonly Dictionary<(string Name, string? Version), bool> properties = new();

        public int VersionPropertiesCalls { get; private set; }
        public int SecretValueCalls { get; private set; }
        public int ListCalls { get; private set; }
        public string? LastVersionPropertiesRequest { get; private set; }
        public RequestFailedException? Failure { get; init; }

        public void AllowProperties(string name, string? version, bool enabled) =>
            properties[(name, version)] = enabled;

        public override Task<Response<KeyVaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default)
        {
            SecretValueCalls++;
            throw new InvalidOperationException("Readiness must not download secret values.");
        }

        public override AsyncPageable<SecretProperties> GetPropertiesOfSecretVersionsAsync(string name, CancellationToken cancellationToken = default)
        {
            VersionPropertiesCalls++;
            LastVersionPropertiesRequest = name;
            if (Failure is not null)
                throw Failure;
            return AsyncPageable<SecretProperties>.FromPages([Page<SecretProperties>.FromValues(
                properties.Where(item => item.Key.Name == name)
                    .Select(item =>
                    {
                        SecretProperties secretProperties = SecretModelFactory.SecretProperties(
                            new Uri($"https://allowed.vault.azure.net/secrets/{item.Key.Name}/{item.Key.Version ?? "current"}"),
                            new Uri("https://allowed.vault.azure.net/"),
                            item.Key.Name,
                            item.Key.Version ?? string.Empty,
                            managed: false,
                            new Uri("https://allowed.vault.azure.net/keys/synthetic"),
                            createdOn: null,
                            updatedOn: null,
                            recoveryLevel: "Recoverable");
                        secretProperties.Enabled = item.Value;
                        return secretProperties;
                    })
                    .ToArray(),
                continuationToken: null,
                response: new EmptyResponse())]);
        }

        public override AsyncPageable<SecretProperties> GetPropertiesOfSecretsAsync(CancellationToken cancellationToken = default)
        {
            ListCalls++;
            throw new InvalidOperationException("Readiness must not enumerate the vault.");
        }
    }

    private sealed class EmptyResponse : Response
    {
        public override int Status => 200;
        public override string ReasonPhrase => "OK";
        public override Stream? ContentStream { get; set; }
        public override string ClientRequestId { get; set; } = string.Empty;
        protected override bool ContainsHeader(string name) => false;
        protected override IEnumerable<HttpHeader> EnumerateHeaders() => [];
        protected override bool TryGetHeader(string name, out string value)
        {
            value = string.Empty;
            return false;
        }
        protected override bool TryGetHeaderValues(string name, out IEnumerable<string> values)
        {
            values = [];
            return false;
        }
        public override void Dispose()
        {
        }
    }
}

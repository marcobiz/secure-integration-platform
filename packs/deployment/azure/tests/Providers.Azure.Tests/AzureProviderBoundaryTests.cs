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

    [Theory]
    [InlineData("v1")]
    [InlineData(null)]
    public async Task Azure_readiness_reads_configured_exact_or_current_reference_without_enumeration(string? version)
    {
        RecordingSecretClient client = new();
        client.AllowSecret("activation-hmac", version);
        AzureSecretAndCertificateProvider provider = new(
            new Uri("https://allowed.vault.azure.net/"),
            client,
            $"keyvault://allowed.vault.azure.net/activation-hmac{(version is null ? string.Empty : $"/{version}")}");

        Assert.True(await provider.IsReadyAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, client.SecretValueCalls);
        Assert.Equal(("activation-hmac", version), client.LastSecretRequest);
        Assert.Equal(TestContext.Current.CancellationToken, client.LastCancellationToken);
        Assert.Equal(0, client.VersionPropertiesCalls);
        Assert.Equal(0, client.ListCalls);
    }

    [Theory]
    [InlineData(403)]
    [InlineData(404)]
    public async Task Azure_readiness_returns_false_when_get_is_denied_or_missing_even_if_list_is_allowed(int status)
    {
        RecordingSecretClient client = new() { Failure = new RequestFailedException(status, "synthetic") };
        client.AllowSecret("activation-hmac", version: null);
        AzureSecretAndCertificateProvider provider = new(
            new Uri("https://allowed.vault.azure.net/"),
            client,
            "keyvault://allowed.vault.azure.net/activation-hmac");

        Assert.False(await provider.IsReadyAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, client.SecretValueCalls);
        Assert.Equal(("activation-hmac", (string?)null), client.LastSecretRequest);
        Assert.Equal(0, client.VersionPropertiesCalls);
        Assert.Equal(0, client.ListCalls);
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

    [Fact]
    public async Task Azure_readiness_preserves_cancellation_without_retry_or_enumeration()
    {
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        RecordingSecretClient client = new();
        client.AllowSecret("activation-hmac", version: null);
        AzureSecretAndCertificateProvider provider = new(
            new Uri("https://allowed.vault.azure.net/"),
            client,
            "keyvault://allowed.vault.azure.net/activation-hmac");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => provider.IsReadyAsync(cancellation.Token));
        Assert.Equal(cancellation.Token, client.LastCancellationToken);
        Assert.Equal(1, client.SecretValueCalls);
        Assert.Equal(0, client.VersionPropertiesCalls);
        Assert.Equal(0, client.ListCalls);
    }

    private sealed class NeverCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new InvalidOperationException("Credential must not be used for a denied reference.");
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new InvalidOperationException("Credential must not be used for a denied reference.");
    }

    private sealed class RecordingSecretClient : SecretClient
    {
        private readonly Dictionary<(string Name, string? Version), KeyVaultSecret> secrets = new();

        public int VersionPropertiesCalls { get; private set; }
        public int SecretValueCalls { get; private set; }
        public int ListCalls { get; private set; }
        public (string Name, string? Version) LastSecretRequest { get; private set; }
        public CancellationToken LastCancellationToken { get; private set; }
        public RequestFailedException? Failure { get; init; }

        public void AllowSecret(string name, string? version) =>
            secrets[(name, version)] = new KeyVaultSecret(name, Guid.NewGuid().ToString("N"));

        public override Task<Response<KeyVaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default)
        {
            SecretValueCalls++;
            LastSecretRequest = (name, version);
            LastCancellationToken = cancellationToken;
            cancellationToken.ThrowIfCancellationRequested();
            if (Failure is not null)
                throw Failure;
            if (!secrets.TryGetValue((name, version), out KeyVaultSecret? secret))
                throw new RequestFailedException(404, "synthetic");
            return Task.FromResult(Response.FromValue(secret, new EmptyResponse()));
        }

        public override AsyncPageable<SecretProperties> GetPropertiesOfSecretVersionsAsync(string name, CancellationToken cancellationToken = default)
        {
            VersionPropertiesCalls++;
            return AsyncPageable<SecretProperties>.FromPages([Page<SecretProperties>.FromValues(
                secrets.Where(item => item.Key.Name == name)
                    .Select(item => item.Value.Properties)
                    .ToArray(),
                continuationToken: null,
                response: new EmptyResponse())]);
        }

        public override AsyncPageable<SecretProperties> GetPropertiesOfSecretsAsync(CancellationToken cancellationToken = default)
        {
            ListCalls++;
            return AsyncPageable<SecretProperties>.FromPages([Page<SecretProperties>.FromValues(
                secrets.Values.Select(secret => secret.Properties).ToArray(),
                continuationToken: null,
                response: new EmptyResponse())]);
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

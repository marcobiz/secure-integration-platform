using Azure.Core;
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

    private sealed class NeverCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new InvalidOperationException("Credential must not be used for a denied reference.");
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new InvalidOperationException("Credential must not be used for a denied reference.");
    }
}

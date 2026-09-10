using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Providers.Azure;

/// <summary>Azure deployment pack factory. This assembly is never referenced by the Core graph.</summary>
public sealed class AzureProviderPackFactory : IProviderPackFactory
{
    private const string ReadinessSecretReferenceSetting = "ReadinessSecretReference";

    /// <inheritdoc />
    public ProviderServices Create(ProviderPackContext context)
    {
        if (context.Endpoint.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(context.Endpoint.UserInfo) || !string.IsNullOrEmpty(context.Endpoint.Query) || !string.IsNullOrEmpty(context.Endpoint.Fragment))
            throw new ProviderAccessException("BGW-PROVIDER-CONFIGURATION-INVALID");
        if (context.Settings.Keys.Any(key => key != ReadinessSecretReferenceSetting))
            throw new ProviderAccessException("BGW-PROVIDER-CONFIGURATION-INVALID");
        TokenCredential credential = string.IsNullOrWhiteSpace(context.ClientIdentity)
            ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
            : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(context.ClientIdentity));
        context.Settings.TryGetValue(ReadinessSecretReferenceSetting, out string? readinessSecretReference);
        AzureSecretAndCertificateProvider provider = new(context.Endpoint, new SecretClient(context.Endpoint, credential), readinessSecretReference);
        return new ProviderServices(provider, provider, provider, provider);
    }
}

/// <summary>Azure Key Vault adapter scoped to one configured vault origin.</summary>
public sealed class AzureSecretAndCertificateProvider :
    ISecretValueProvider, IClientCertificateProvider, IProviderHealthCheck, IProviderCapabilitySource
{
    private readonly Uri vaultUri;
    private readonly SecretClient client;
    private readonly string? readinessSecretReference;

    /// <summary>Creates an adapter for one configured vault origin.</summary>
    public AzureSecretAndCertificateProvider(Uri vaultUri, TokenCredential credential)
        : this(vaultUri, new SecretClient(vaultUri, credential))
    {
    }

    internal AzureSecretAndCertificateProvider(Uri vaultUri, SecretClient client, string? readinessSecretReference = null)
    {
        this.vaultUri = vaultUri;
        this.client = client;
        if (readinessSecretReference is not null)
            _ = Parse(readinessSecretReference);
        this.readinessSecretReference = readinessSecretReference;
    }

    /// <inheritdoc />
    public ProviderCapabilities Capabilities { get; } = new(true, true, false, false);

    /// <inheritdoc />
    public async Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken)
    {
        (string name, string? version) = Parse(logicalReference);
        try
        {
            KeyVaultSecret secret = (await client.GetSecretAsync(name, version, cancellationToken).ConfigureAwait(false)).Value;
            return secret.Value;
        }
        catch (RequestFailedException exception) { throw new ProviderAccessException("BGW-PROVIDER-UNAVAILABLE", true, exception); }
    }

    /// <inheritdoc />
    public async Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken)
    {
        string encoded = await GetSecretAsync(logicalReference, cancellationToken).ConfigureAwait(false);
        try { return X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(encoded), null, X509KeyStorageFlags.EphemeralKeySet); }
        catch (Exception exception) when (exception is FormatException or CryptographicException) { throw new ProviderAccessException("BGW-PROVIDER-CERTIFICATE-INVALID", false, exception); }
    }

    /// <inheritdoc />
    public async Task<bool> IsReadyAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(readinessSecretReference))
            return false;
        (string name, string? version) = Parse(readinessSecretReference);
        try
        {
            await foreach (SecretProperties properties in client.GetPropertiesOfSecretVersionsAsync(name, cancellationToken).ConfigureAwait(false))
            {
                if (version is not null && !string.Equals(properties.Version, version, StringComparison.Ordinal))
                    continue;
                return properties.Enabled != false;
            }
            return false;
        }
        catch (RequestFailedException) { return false; }
    }

    private (string Name, string? Version) Parse(string reference)
    {
        if (!Uri.TryCreate(reference, UriKind.Absolute, out Uri? uri) || uri.Scheme != "keyvault" || !string.Equals(uri.Host, vaultUri.Host, StringComparison.OrdinalIgnoreCase) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new ProviderAccessException("BGW-PROVIDER-REFERENCE-DENIED");
        string[] segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length is < 1 or > 2 || segments.Any(segment => segment.Length > 127 || segment.Any(character => !(char.IsAsciiLetterOrDigit(character) || character == '-'))))
            throw new ProviderAccessException("BGW-PROVIDER-REFERENCE-DENIED");
        return (segments[0], segments.Length == 2 ? segments[1] : null);
    }
}

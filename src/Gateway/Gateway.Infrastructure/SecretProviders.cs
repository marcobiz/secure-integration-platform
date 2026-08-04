using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Retrieves only allowlisted logical references from one configured Azure Key Vault.</summary>
public sealed class AzureKeyVaultSecretProvider(Uri vaultUri, TokenCredential credential) : ISecretProvider
{
    private readonly SecretClient client = new(vaultUri, credential);

    /// <inheritdoc />
    public async Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken)
    {
        (string name, string? version) = Parse(logicalReference);
        KeyVaultSecret secret = (await client.GetSecretAsync(name, version, cancellationToken).ConfigureAwait(false)).Value;
        return secret.Value;
    }

    /// <inheritdoc />
    public async Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken)
    {
        string encoded = await GetSecretAsync(logicalReference, cancellationToken).ConfigureAwait(false);
        try
        {
            return X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(encoded), null, X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException)
        {
            throw new GatewayException("BGW-VAULT-CERTIFICATE-INVALID", 503, true);
        }
    }

    /// <inheritdoc />
    public async Task<bool> IsReadyAsync(CancellationToken cancellationToken)
    {
        try
        {
            await foreach (SecretProperties _ in client.GetPropertiesOfSecretsAsync(cancellationToken).ConfigureAwait(false)) break;
            return true;
        }
        catch (Azure.RequestFailedException) { return false; }
    }

    private (string Name, string? Version) Parse(string reference)
    {
        if (!Uri.TryCreate(reference, UriKind.Absolute, out Uri? uri) || uri.Scheme != "keyvault" || !string.Equals(uri.Host, vaultUri.Host, StringComparison.OrdinalIgnoreCase) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new GatewayException("BGW-VAULT-REFERENCE-DENIED", 500);
        string[] segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length is < 1 or > 2 || segments.Any(segment => segment.Length > 127 || segment.Any(character => !(char.IsAsciiLetterOrDigit(character) || character == '-'))))
            throw new GatewayException("BGW-VAULT-REFERENCE-DENIED", 500);
        return (segments[0], segments.Length == 2 ? segments[1] : null);
    }
}

/// <summary>Non-production secret provider for deterministic tests.</summary>
public sealed class InMemorySecretProvider(IReadOnlyDictionary<string, string> values, IReadOnlyDictionary<string, byte[]>? certificates = null) : ISecretProvider
{
    /// <inheritdoc />
    public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!values.TryGetValue(logicalReference, out string? value)) throw new GatewayException("BGW-VAULT-SECRET-NOT-FOUND", 503, true);
        return Task.FromResult(value);
    }

    /// <inheritdoc />
    public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (certificates is null || !certificates.TryGetValue(logicalReference, out byte[]? value)) throw new GatewayException("BGW-VAULT-SECRET-NOT-FOUND", 503, true);
        return Task.FromResult(X509CertificateLoader.LoadPkcs12(value, null, X509KeyStorageFlags.EphemeralKeySet));
    }

    /// <inheritdoc />
    public Task<bool> IsReadyAsync(CancellationToken cancellationToken) => Task.FromResult(!cancellationToken.IsCancellationRequested);
}

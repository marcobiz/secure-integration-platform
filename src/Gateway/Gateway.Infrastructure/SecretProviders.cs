using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using SecureIntegration.Gateway.Application;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

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

/// <summary>HTTPS-only deterministic M3 Vault client. It is composed by the host only in M3Testing.</summary>
public sealed class SyntheticVaultSecretProvider : ISecretProvider, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow };
    private readonly Uri origin;
    private readonly string accessToken;
    private readonly HttpClient client;

    /// <summary>Creates a fixed-origin provider with a per-run bearer independent of vendor secrets.</summary>
    public SyntheticVaultSecretProvider(Uri origin, string accessToken, HttpMessageHandler? handler = null)
    {
        if (origin.Scheme != Uri.UriSchemeHttps || origin.AbsolutePath != "/" || !string.IsNullOrEmpty(origin.UserInfo) || !string.IsNullOrEmpty(origin.Query) || !string.IsNullOrEmpty(origin.Fragment)) throw new ArgumentException("Synthetic Vault must be an HTTPS origin.", nameof(origin));
        if (string.IsNullOrWhiteSpace(accessToken) || accessToken.Length < 32 || accessToken.Length > 512 || accessToken.Any(character => character is '\r' or '\n')) throw new ArgumentException("Synthetic Vault token is invalid.", nameof(accessToken));
        this.origin = origin;
        this.accessToken = accessToken;
        client = handler is null
            ? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false, AutomaticDecompression = DecompressionMethods.None })
            : new HttpClient(handler, disposeHandler: true);
        client.BaseAddress = origin;
        client.Timeout = TimeSpan.FromSeconds(10);
    }

    /// <inheritdoc />
    public async Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken)
    {
        string name = Parse(logicalReference);
        using HttpRequestMessage request = CreateRequest(HttpMethod.Get, "/v1/secrets/" + Uri.EscapeDataString(name));
        using HttpResponseMessage response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        SecretEnvelope envelope = await ReadEnvelopeAsync(response, cancellationToken).ConfigureAwait(false);
        return envelope.Value;
    }

    /// <inheritdoc />
    public async Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken)
    {
        string encoded = await GetSecretAsync(logicalReference, cancellationToken).ConfigureAwait(false);
        try { return X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(encoded), null, X509KeyStorageFlags.EphemeralKeySet); }
        catch (Exception exception) when (exception is FormatException or CryptographicException) { throw new GatewayException("BGW-VAULT-CERTIFICATE-INVALID", 503, true); }
    }

    /// <inheritdoc />
    public async Task<bool> IsReadyAsync(CancellationToken cancellationToken)
    {
        try
        {
            using HttpRequestMessage request = CreateRequest(HttpMethod.Get, "/health/ready");
            using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            return response.IsSuccessStatusCode;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException) { return false; }
    }

    private HttpRequestMessage CreateRequest(HttpMethod method, string target)
    {
        HttpRequestMessage request = new(method, target);
        request.Headers.TryAddWithoutValidation("X-M3-Vault-Token", accessToken);
        return request;
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        HttpResponseMessage response;
        try { response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false); }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException) { throw new GatewayException("BGW-VAULT-UNAVAILABLE", 503, true); }
        if (!response.IsSuccessStatusCode)
        {
            response.Dispose();
            throw new GatewayException(response.StatusCode == HttpStatusCode.NotFound ? "BGW-VAULT-SECRET-NOT-FOUND" : "BGW-VAULT-UNAVAILABLE", 503, true);
        }
        return response;
    }

    private static async Task<SecretEnvelope> ReadEnvelopeAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength > 4 * 1024 * 1024) throw new GatewayException("BGW-VAULT-RESPONSE-INVALID", 503, true);
        try { return await response.Content.ReadFromJsonAsync<SecretEnvelope>(JsonOptions, cancellationToken).ConfigureAwait(false) ?? throw new JsonException(); }
        catch (JsonException) { throw new GatewayException("BGW-VAULT-RESPONSE-INVALID", 503, true); }
    }

    private string Parse(string reference)
    {
        if (!Uri.TryCreate(reference, UriKind.Absolute, out Uri? uri) || uri.Scheme != "synthetic-vault" || !string.Equals(uri.Host, origin.Host, StringComparison.OrdinalIgnoreCase) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment)) throw new GatewayException("BGW-VAULT-REFERENCE-DENIED", 500);
        string[] segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 1 || segments[0].Length > 127 || segments[0].Any(character => !(char.IsAsciiLetterOrDigit(character) || character == '-'))) throw new GatewayException("BGW-VAULT-REFERENCE-DENIED", 500);
        return segments[0];
    }

    /// <inheritdoc />
    public void Dispose() => client.Dispose();

    private sealed record SecretEnvelope(string Value);
}

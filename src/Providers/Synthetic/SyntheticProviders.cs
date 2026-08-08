using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Providers.Synthetic;

/// <summary>In-memory provider for Development and deterministic tests.</summary>
public sealed class InMemoryProvider :
    ISecretValueProvider, IClientCertificateProvider, ICertificateMetadataProvider, ICertificatePublicMaterialProvider,
    IKeyOperationProvider, IProviderHealthCheck, IProviderCapabilitySource
{
    private readonly IReadOnlyDictionary<string, string> values;
    private readonly IReadOnlyDictionary<string, byte[]>? encodedCertificates;
    private readonly IReadOnlyDictionary<string, X509Certificate2>? certificateHandles;
    private readonly IReadOnlyDictionary<string, X509Certificate2>? signingKeyHandles;
    private readonly IReadOnlyDictionary<string, IReadOnlyList<X509Certificate2>>? certificateChains;

    /// <summary>Creates a synthetic provider from runtime-only values and certificate handles.</summary>
    public InMemoryProvider(
        IReadOnlyDictionary<string, string> values,
        IReadOnlyDictionary<string, byte[]>? certificates = null,
        IReadOnlyDictionary<string, X509Certificate2>? certificateHandles = null,
        IReadOnlyDictionary<string, X509Certificate2>? signingKeyHandles = null,
        IReadOnlyDictionary<string, IReadOnlyList<X509Certificate2>>? certificateChains = null)
    {
        this.values = values;
        encodedCertificates = certificates;
        this.certificateHandles = certificateHandles;
        this.signingKeyHandles = signingKeyHandles;
        this.certificateChains = certificateChains;
        bool hasCertificates = certificates is not null || certificateHandles is not null;
        Capabilities = new(true, hasCertificates, signingKeyHandles is not null, false, hasCertificates || signingKeyHandles is not null);
    }

    /// <inheritdoc />
    public ProviderCapabilities Capabilities { get; }

    /// <inheritdoc />
    public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!values.TryGetValue(logicalReference, out string? value)) throw new ProviderAccessException("BGW-PROVIDER-SECRET-NOT-FOUND", true);
        return Task.FromResult(value);
    }

    /// <inheritdoc />
    public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (certificateHandles is not null && certificateHandles.TryGetValue(logicalReference, out X509Certificate2? handle))
            return Task.FromResult(new X509Certificate2(handle));
        if (encodedCertificates is null || !encodedCertificates.TryGetValue(logicalReference, out byte[]? value)) throw new ProviderAccessException("BGW-PROVIDER-SECRET-NOT-FOUND", true);
        return Task.FromResult(LoadCertificate(value));
    }

    /// <inheritdoc />
    public async Task<ProviderCertificatePublicMetadata> GetPublicMetadataAsync(string logicalReference, CancellationToken cancellationToken)
    {
        using X509Certificate2 certificate = await GetClientCertificateAsync(logicalReference, cancellationToken).ConfigureAwait(false);
        return PublicMetadata(certificate);
    }

    /// <inheritdoc />
    public Task<ProviderCertificatePublicMaterial> GetPublicMaterialAsync(string logicalReference, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        X509Certificate2? certificate = null;
        bool disposeCertificate = false;
        try
        {
            if (signingKeyHandles is not null && signingKeyHandles.TryGetValue(logicalReference, out X509Certificate2? signingCertificate))
            {
                certificate = signingCertificate;
            }
            else if (certificateHandles is not null && certificateHandles.TryGetValue(logicalReference, out X509Certificate2? clientCertificate))
            {
                certificate = clientCertificate;
            }
            else if (encodedCertificates is not null && encodedCertificates.TryGetValue(logicalReference, out byte[]? encodedCertificate))
            {
                certificate = LoadCertificate(encodedCertificate);
                disposeCertificate = true;
            }
            else
            {
                throw new ProviderAccessException("BGW-PROVIDER-CERTIFICATE-NOT-FOUND");
            }

            ReadOnlyMemory<byte>[] chain = certificateChains is not null && certificateChains.TryGetValue(logicalReference, out IReadOnlyList<X509Certificate2>? configuredChain)
                ? configuredChain.Select(value => (ReadOnlyMemory<byte>)value.RawData).ToArray()
                : [];
            return Task.FromResult(new ProviderCertificatePublicMaterial(certificate.RawData, chain, PublicMetadata(certificate)));
        }
        finally
        {
            if (disposeCertificate) certificate?.Dispose();
        }
    }

    /// <inheritdoc />
    public Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!string.Equals(algorithm, "RS256", StringComparison.Ordinal) || digest.Length != 32)
            throw new ProviderAccessException("BGW-PROVIDER-SIGNING-ALGORITHM-DENIED");
        if (signingKeyHandles is null || !signingKeyHandles.TryGetValue(logicalReference, out X509Certificate2? certificate))
            throw new ProviderAccessException("BGW-PROVIDER-SIGNING-KEY-NOT-FOUND");
        using RSA? rsa = certificate.GetRSAPrivateKey();
        if (rsa is null) throw new ProviderAccessException("BGW-PROVIDER-SIGNING-KEY-INVALID");
        return Task.FromResult(rsa.SignHash(digest.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    /// <inheritdoc />
    public Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (signingKeyHandles is null || !signingKeyHandles.TryGetValue(logicalReference, out X509Certificate2? certificate))
            throw new ProviderAccessException("BGW-PROVIDER-SIGNING-KEY-NOT-FOUND");
        using RSA? rsa = certificate.GetRSAPublicKey();
        if (rsa is null) throw new ProviderAccessException("BGW-PROVIDER-SIGNING-KEY-INVALID");
        return Task.FromResult(new ProviderSigningKeyPublicMetadata(
            Convert.ToHexString(SHA256.HashData(certificate.RawData)), certificate.NotBefore.ToUniversalTime(), certificate.NotAfter.ToUniversalTime(),
            "RSA", rsa.KeySize, certificate.SerialNumber, rsa.ExportSubjectPublicKeyInfo()));
    }

    /// <inheritdoc />
    public Task<bool> IsReadyAsync(CancellationToken cancellationToken) => Task.FromResult(!cancellationToken.IsCancellationRequested);

    internal static X509Certificate2 LoadCertificate(byte[] encoded)
    {
        try { return X509CertificateLoader.LoadPkcs12(encoded, null, X509KeyStorageFlags.EphemeralKeySet); }
        catch (CryptographicException exception) { throw new ProviderAccessException("BGW-PROVIDER-CERTIFICATE-INVALID", false, exception); }
    }

    internal static ProviderCertificatePublicMetadata PublicMetadata(X509Certificate2 certificate)
    {
        using RSA? rsa = certificate.GetRSAPublicKey();
        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        int keySize = rsa?.KeySize ?? ecdsa?.KeySize ?? certificate.PublicKey.EncodedKeyValue.RawData.Length * 8;
        string algorithm = rsa is not null ? "RSA" : ecdsa is not null ? "ECDSA" : certificate.PublicKey.Oid.Value ?? "unknown";
        IReadOnlyList<string>? enhancedKeyUsages = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault()?.EnhancedKeyUsages.Cast<Oid>().Select(value => value.Value ?? string.Empty).ToArray();
        X509KeyUsageFlags? keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault()?.KeyUsages;
        return new(Convert.ToHexString(SHA256.HashData(certificate.RawData)), certificate.Subject, certificate.Issuer, certificate.NotBefore.ToUniversalTime(), certificate.NotAfter.ToUniversalTime(), algorithm, keySize, certificate.SerialNumber, enhancedKeyUsages, keyUsage);
    }
}

/// <summary>HTTPS-only deterministic provider used by local and CI environments.</summary>
public sealed class SyntheticProvider : ISecretValueProvider, IClientCertificateProvider, ICertificateMetadataProvider,
    ICertificatePublicMaterialProvider, IProviderHealthCheck, IProviderCapabilitySource, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow };
    private readonly Uri origin;
    private readonly string accessToken;
    private readonly HttpClient client;

    /// <summary>Creates a fixed-origin provider with a per-run bearer independent of vendor credentials.</summary>
    public SyntheticProvider(Uri origin, string accessToken, HttpMessageHandler? handler = null)
    {
        if (origin.Scheme != Uri.UriSchemeHttps || origin.AbsolutePath != "/" || !string.IsNullOrEmpty(origin.UserInfo) || !string.IsNullOrEmpty(origin.Query) || !string.IsNullOrEmpty(origin.Fragment)) throw new ArgumentException("Synthetic provider must be an HTTPS origin.", nameof(origin));
        if (string.IsNullOrWhiteSpace(accessToken) || accessToken.Length is < 32 or > 512 || accessToken.Any(character => character is '\r' or '\n')) throw new ArgumentException("Synthetic provider token is invalid.", nameof(accessToken));
        this.origin = origin;
        this.accessToken = accessToken;
        client = handler is null
            ? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false, AutomaticDecompression = DecompressionMethods.None })
            : new HttpClient(handler, disposeHandler: true);
        client.BaseAddress = origin;
        client.Timeout = TimeSpan.FromSeconds(10);
    }

    /// <inheritdoc />
    public ProviderCapabilities Capabilities { get; } = new(true, true, false, false, true);

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
        try { return InMemoryProvider.LoadCertificate(Convert.FromBase64String(encoded)); }
        catch (FormatException exception) { throw new ProviderAccessException("BGW-PROVIDER-CERTIFICATE-INVALID", false, exception); }
    }

    /// <inheritdoc />
    public async Task<ProviderCertificatePublicMetadata> GetPublicMetadataAsync(string logicalReference, CancellationToken cancellationToken)
    {
        using X509Certificate2 certificate = await GetClientCertificateAsync(logicalReference, cancellationToken).ConfigureAwait(false);
        return InMemoryProvider.PublicMetadata(certificate);
    }

    /// <inheritdoc />
    public async Task<ProviderCertificatePublicMaterial> GetPublicMaterialAsync(string logicalReference, CancellationToken cancellationToken)
    {
        using X509Certificate2 certificate = await GetClientCertificateAsync(logicalReference, cancellationToken).ConfigureAwait(false);
        return new ProviderCertificatePublicMaterial(certificate.RawData, [], InMemoryProvider.PublicMetadata(certificate));
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
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException) { throw new ProviderAccessException("BGW-PROVIDER-UNAVAILABLE", true, exception); }
        if (!response.IsSuccessStatusCode)
        {
            response.Dispose();
            throw new ProviderAccessException(response.StatusCode == HttpStatusCode.NotFound ? "BGW-PROVIDER-SECRET-NOT-FOUND" : "BGW-PROVIDER-UNAVAILABLE", true);
        }
        return response;
    }

    private static async Task<SecretEnvelope> ReadEnvelopeAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength > 4 * 1024 * 1024) throw new ProviderAccessException("BGW-PROVIDER-RESPONSE-INVALID", true);
        try { return await response.Content.ReadFromJsonAsync<SecretEnvelope>(JsonOptions, cancellationToken).ConfigureAwait(false) ?? throw new JsonException(); }
        catch (JsonException exception) { throw new ProviderAccessException("BGW-PROVIDER-RESPONSE-INVALID", true, exception); }
    }

    private string Parse(string reference)
    {
        if (!Uri.TryCreate(reference, UriKind.Absolute, out Uri? uri) || uri.Scheme != "synthetic-vault" || !string.Equals(uri.Host, origin.Host, StringComparison.OrdinalIgnoreCase) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment)) throw new ProviderAccessException("BGW-PROVIDER-REFERENCE-DENIED");
        string[] segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 1 || segments[0].Length > 127 || segments[0].Any(character => !(char.IsAsciiLetterOrDigit(character) || character == '-'))) throw new ProviderAccessException("BGW-PROVIDER-REFERENCE-DENIED");
        return segments[0];
    }

    /// <inheritdoc />
    public void Dispose() => client.Dispose();

    private sealed record SecretEnvelope(string Value);
}

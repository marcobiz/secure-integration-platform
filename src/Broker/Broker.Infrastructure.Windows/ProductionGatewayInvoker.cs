using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecureIntegration.Broker.Core;
using SecureIntegration.Contracts;

namespace SecureIntegration.Broker.Infrastructure.Windows;

/// <summary>
/// Production Installation client: owns a non-exportable CNG P-256 key, enrolls with
/// proof-of-possession and signs every bounded BGW1 request. It never accepts a Tenant,
/// destination URI or secret reference from the IPC caller.
/// </summary>
public sealed class ProductionGatewayInvoker : IGatewayInvoker, IDisposable
{
    private const string ThumbprintFileName = "gateway-installation-certificate.thumbprint";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
    private readonly GatewayInstallationOptions options;
    private readonly string dataDirectory;
    private readonly Uri gatewayOrigin;
    private readonly SemaphoreSlim enrollmentLock = new(1, 1);
    private readonly HttpClient bootstrapClient;
    private HttpClient? authenticatedClient;
    private X509Certificate2? installationCertificate;
    private bool enrolled;

    /// <summary>Creates a fail-closed client for one fixed Gateway origin.</summary>
    public ProductionGatewayInvoker(GatewayInstallationOptions options, string dataDirectory)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.dataDirectory = dataDirectory ?? throw new ArgumentNullException(nameof(dataDirectory));
        if (!options.Enabled) throw new ArgumentException("Gateway installation client is not enabled.", nameof(options));
        if (!Uri.TryCreate(options.BaseAddress, UriKind.Absolute, out Uri? parsed) || parsed.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(parsed.UserInfo) || !string.IsNullOrEmpty(parsed.Query) || !string.IsNullOrEmpty(parsed.Fragment))
            throw new ArgumentException("Gateway BaseAddress must be an HTTPS origin without credentials, query or fragment.", nameof(options));
        if (parsed.AbsolutePath != "/") throw new ArgumentException("Gateway BaseAddress must not contain a path.", nameof(options));
        if (!Guid.TryParse(options.ActivationCodeId, out _) || options.TimeoutSeconds is < 1 or > 120 || string.IsNullOrWhiteSpace(options.CngKeyName) || options.CngKeyName.Length > 200 || !Version.TryParse(options.BrokerVersion, out _))
            throw new ArgumentException("Gateway Installation configuration is invalid.", nameof(options));
        gatewayOrigin = parsed;
        bootstrapClient = CreateClient(null);
    }

    /// <inheritdoc />
    public async Task<GatewayInvocationResult> InvokeAsync(string applicationId, string connectorId, string operationId, string contentType, byte[] payload, Guid correlationId, CancellationToken cancellationToken)
    {
        _ = applicationId; // local authorization is completed before this boundary.
        if (!IsIdentifier(connectorId) || !IsIdentifier(operationId) || correlationId == Guid.Empty) throw new BrokerException("gateway_request_invalid", "validation");
        if (payload.LongLength > IpcProtocol.MaxPayloadBytes) throw new BrokerException("payload_too_large", "validation");
        if (string.IsNullOrWhiteSpace(contentType) || contentType.Length > 200 || contentType.Any(character => character is '\r' or '\n')) throw new BrokerException("gateway_request_invalid", "validation");

        await EnsureEnrolledAsync(cancellationToken).ConfigureAwait(false);
        string target = $"/v1/connectors/{Uri.EscapeDataString(connectorId)}/operations/{Uri.EscapeDataString(operationId)}:invoke";
        InvokeRequest envelope = new("1.0", new Payload(contentType, "base64", Convert.ToBase64String(payload)), correlationId);
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
        using HttpRequestMessage request = CreateSignedRequest(HttpMethod.Post, target, body, installationCertificate!);
        request.Headers.TryAddWithoutValidation("traceparent", CreateTraceParent());
        using HttpResponseMessage response = await SendAsync(authenticatedClient!, request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw MapGatewayFailure(response.StatusCode);
        byte[] responseBody = await ReadBoundedAsync(response, cancellationToken).ConfigureAwait(false);
        InvokeResponse result;
        try { result = JsonSerializer.Deserialize<InvokeResponse>(responseBody, JsonOptions) ?? throw new JsonException(); }
        catch (JsonException exception) { throw new BrokerException("gateway_response_invalid", "gateway", false, exception); }
        if (result.CorrelationId != correlationId || result.Result.Encoding != "base64") throw new BrokerException("gateway_response_invalid", "gateway");
        byte[] decoded;
        try { decoded = Convert.FromBase64String(result.Result.Data); }
        catch (FormatException exception) { throw new BrokerException("gateway_response_invalid", "gateway", false, exception); }
        if (decoded.LongLength > IpcProtocol.MaxPayloadBytes) throw new BrokerException("gateway_response_too_large", "gateway");
        return new GatewayInvocationResult(result.Result.ContentType, decoded, result.ConnectorVersion);
    }

    internal async Task EnsureEnrolledAsync(CancellationToken cancellationToken)
    {
        if (enrolled) return;
        await enrollmentLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (enrolled) return;
            installationCertificate = LoadOrCreateCertificate();
            authenticatedClient = CreateClient(installationCertificate);
            if (await IsRegisteredAsync(cancellationToken).ConfigureAwait(false))
            {
                enrolled = true;
                return;
            }

            string? activationCode = Environment.GetEnvironmentVariable(options.ActivationCodeEnvironmentVariable, EnvironmentVariableTarget.Process);
            if (string.IsNullOrWhiteSpace(activationCode)) throw new BrokerException("gateway_enrollment_required", "gateway");
            Guid activationCodeId = Guid.Parse(options.ActivationCodeId);
            using ECDsa privateKey = installationCertificate.GetECDsaPrivateKey() ?? throw new BrokerException("gateway_credential_unavailable", "gateway");
            string publicKey = Convert.ToBase64String(privateKey.ExportSubjectPublicKeyInfo());
            ChallengeResponse challenge = await PostAsync<ChallengeRequest, ChallengeResponse>(bootstrapClient, "/v1/enrollments/challenges", new ChallengeRequest(activationCodeId, publicKey), cancellationToken).ConfigureAwait(false);
            byte[] proofBytes = Encoding.UTF8.GetBytes(FormattableString.Invariant($"BGW-ENROLL1\n{challenge.ChallengeId:D}\n{challenge.Challenge}\n{activationCodeId:D}"));
            string signature = Base64UrlEncode(privateKey.SignData(proofBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            ActivationRequest activation = new(challenge.ChallengeId, activationCode, Convert.ToBase64String(installationCertificate.RawData), signature, options.BrokerVersion);
            _ = await PostAsync<ActivationRequest, EnrollmentResult>(bootstrapClient, "/v1/enrollments:activate", activation, cancellationToken).ConfigureAwait(false);
            Environment.SetEnvironmentVariable(options.ActivationCodeEnvironmentVariable, null, EnvironmentVariableTarget.Process);
            enrolled = true;
        }
        finally { enrollmentLock.Release(); }
    }

    private async Task<bool> IsRegisteredAsync(CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = CreateSignedRequest(HttpMethod.Get, "/v1/broker-policy", [], installationCertificate!);
        using HttpResponseMessage response = await SendAsync(authenticatedClient!, request, cancellationToken).ConfigureAwait(false);
        return response.IsSuccessStatusCode ? true : response.StatusCode == HttpStatusCode.Unauthorized ? false : throw MapGatewayFailure(response.StatusCode);
    }

    internal X509Certificate2 LoadOrCreateCertificate()
    {
        Directory.CreateDirectory(dataDirectory);
        string markerPath = Path.Combine(dataDirectory, ThumbprintFileName);
        if (File.Exists(markerPath))
        {
            string thumbprint = File.ReadAllText(markerPath, Encoding.ASCII).Trim();
            using X509Store store = new(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2? existing = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false).OfType<X509Certificate2>().FirstOrDefault(certificate => certificate.HasPrivateKey);
            if (existing is null) throw new BrokerException("gateway_credential_unavailable", "gateway");
            return new X509Certificate2(existing);
        }

        CngKeyCreationParameters parameters = new()
        {
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = CngKeyCreationOptions.None,
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider
        };
        using CngKey key = CngKey.Exists(options.CngKeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider)
            ? CngKey.Open(options.CngKeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider)
            : CngKey.Create(CngAlgorithm.ECDsaP256, options.CngKeyName, parameters);
        using ECDsaCng ecdsa = new(key);
        CertificateRequest request = new($"CN=SecureIntegration Installation {options.ActivationCodeId}", ecdsa, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        OidCollection eku = [new Oid("1.3.6.1.5.5.7.3.2")];
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
        X509Certificate2 created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(90));
        using (X509Store store = new(StoreName.My, StoreLocation.CurrentUser))
        {
            store.Open(OpenFlags.ReadWrite);
            store.Add(created);
        }
        File.WriteAllText(markerPath, created.Thumbprint, Encoding.ASCII);
        return created;
    }

    private HttpClient CreateClient(X509Certificate2? certificate)
    {
        HttpClientHandler handler = new()
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            AutomaticDecompression = DecompressionMethods.None
        };
        if (certificate is not null) handler.ClientCertificates.Add(certificate);
        return new HttpClient(handler) { BaseAddress = gatewayOrigin, Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds) };
    }

    private static HttpRequestMessage CreateSignedRequest(HttpMethod method, string target, byte[] body, X509Certificate2 certificate)
    {
        string timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'", CultureInfo.InvariantCulture);
        string nonce = Base64UrlEncode(RandomNumberGenerator.GetBytes(16));
        string contentHash = Base64UrlEncode(SHA256.HashData(body));
        string signingInput = string.Join('\n', "BGW1", method.Method.ToUpperInvariant(), target, timestamp, nonce, contentHash);
        using ECDsa key = certificate.GetECDsaPrivateKey() ?? throw new BrokerException("gateway_credential_unavailable", "gateway");
        string signature = Base64UrlEncode(key.SignData(Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        HttpRequestMessage request = new(method, target);
        request.Headers.TryAddWithoutValidation("X-BG-Timestamp", timestamp);
        request.Headers.TryAddWithoutValidation("X-BG-Nonce", nonce);
        request.Headers.TryAddWithoutValidation("X-BG-Content-SHA256", contentHash);
        request.Headers.TryAddWithoutValidation("X-BG-Signature", signature);
        if (body.Length != 0) request.Content = new ByteArrayContent(body) { Headers = { ContentType = new("application/json") } };
        return request;
    }

    private static async Task<TResponse> PostAsync<TRequest, TResponse>(HttpClient client, string target, TRequest value, CancellationToken cancellationToken)
    {
        using ByteArrayContent content = new(JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions));
        content.Headers.ContentType = new("application/json");
        using HttpResponseMessage response = await client.PostAsync(target, content, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw MapGatewayFailure(response.StatusCode);
        byte[] body = await ReadBoundedAsync(response, cancellationToken).ConfigureAwait(false);
        try { return JsonSerializer.Deserialize<TResponse>(body, JsonOptions) ?? throw new JsonException(); }
        catch (JsonException exception) { throw new BrokerException("gateway_response_invalid", "gateway", false, exception); }
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try { return await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false); }
        catch (HttpRequestException exception) { throw new BrokerException("gateway_transport_failed", "gateway", true, exception); }
        catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested) { throw new BrokerException("gateway_timeout", "gateway", true, exception); }
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength > IpcProtocol.MaxPayloadBytes) throw new BrokerException("gateway_response_too_large", "gateway");
        await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using MemoryStream output = new();
        byte[] buffer = new byte[81920];
        while (true)
        {
            int read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (output.Length + read > IpcProtocol.MaxPayloadBytes) throw new BrokerException("gateway_response_too_large", "gateway");
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private static BrokerException MapGatewayFailure(HttpStatusCode statusCode) => statusCode switch
    {
        HttpStatusCode.Unauthorized => new("gateway_authentication_denied", "gateway"),
        HttpStatusCode.Forbidden => new("gateway_authorization_denied", "gateway"),
        HttpStatusCode.NotFound => new("gateway_operation_not_found", "gateway"),
        HttpStatusCode.Conflict => new("gateway_conflict", "gateway"),
        HttpStatusCode.TooManyRequests => new("gateway_throttled", "gateway", true),
        _ when (int)statusCode >= 500 => new("gateway_unavailable", "gateway", true),
        _ => new("gateway_request_rejected", "gateway")
    };

    private static string Base64UrlEncode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static string CreateTraceParent() => FormattableString.Invariant($"00-{ActivityTraceId.CreateRandom()}-{ActivitySpanId.CreateRandom()}-01");
    private static bool IsIdentifier(string value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 100 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    /// <inheritdoc />
    public void Dispose()
    {
        authenticatedClient?.Dispose();
        bootstrapClient.Dispose();
        installationCertificate?.Dispose();
        enrollmentLock.Dispose();
    }

    private sealed record ChallengeRequest(Guid ActivationCodeId, string PublicKeySpki);
    private sealed record ChallengeResponse(Guid ChallengeId, string Challenge, DateTimeOffset ExpiresAt);
    private sealed record ActivationRequest(Guid ChallengeId, string ActivationCode, string ClientCertificate, string ProofSignature, string BrokerVersion);
    private sealed record EnrollmentResult(Guid InstallationId, Guid TenantId, Guid ApplicationId, DateTimeOffset CredentialExpiresAt, DateTimeOffset RenewalStartsAt);
    private sealed record Payload(string ContentType, string Encoding, string Data);
    private sealed record InvokeRequest(string ProtocolVersion, Payload Payload, Guid CorrelationId);
    private sealed record InvokeResponse(Guid CorrelationId, string ConnectorVersion, Payload Result);
}

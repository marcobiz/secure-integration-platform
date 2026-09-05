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
/// Production Installation client: owns non-exportable CNG P-256 keys, enrolls with
/// proof-of-possession, renews the same Installation and signs every bounded BGW1 request.
/// It never accepts a Tenant, destination URI or secret reference from the IPC caller.
/// </summary>
public sealed class ProductionGatewayInvoker : IGatewayInvoker, IDisposable
{
    private const string ThumbprintFileName = "gateway-installation-certificate.thumbprint";
    private const string StateFileName = "gateway-installation-state.json";
    private const int StateFormatVersion = 1;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };
    private readonly GatewayInstallationOptions options;
    private readonly string dataDirectory;
    private readonly Uri gatewayOrigin;
    private readonly SemaphoreSlim lifecycleLock = new(1, 1);
    private readonly Func<X509Certificate2?, HttpMessageHandler> handlerFactory;
    private readonly TimeProvider timeProvider;
    private readonly HttpClient bootstrapClient;
    private readonly List<GatewaySession> retainedSessions = [];
    private GatewaySession? activeSession;
    private GatewaySession? pendingSession;
    private GatewayInstallationState? state;
    private bool initialized;
    private bool disposed;

    /// <summary>Creates a fail-closed client for one fixed Gateway origin.</summary>
    public ProductionGatewayInvoker(GatewayInstallationOptions options, string dataDirectory)
        : this(options, dataDirectory, CreateDefaultHandler, TimeProvider.System)
    {
    }

    internal ProductionGatewayInvoker(
        GatewayInstallationOptions options,
        string dataDirectory,
        Func<X509Certificate2?, HttpMessageHandler> handlerFactory,
        TimeProvider timeProvider)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.dataDirectory = dataDirectory ?? throw new ArgumentNullException(nameof(dataDirectory));
        this.handlerFactory = handlerFactory ?? throw new ArgumentNullException(nameof(handlerFactory));
        this.timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
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

        GatewaySession session = await GetReadySessionAsync(cancellationToken).ConfigureAwait(false);
        string target = $"/v1/connectors/{Uri.EscapeDataString(connectorId)}/operations/{Uri.EscapeDataString(operationId)}:invoke";
        InvokeRequest envelope = new("1.0", new Payload(contentType, "base64", Convert.ToBase64String(payload)), correlationId);
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
        using HttpRequestMessage request = CreateSignedRequest(HttpMethod.Post, target, body, session.Certificate);
        request.Headers.TryAddWithoutValidation("traceparent", CreateTraceParent());
        using HttpResponseMessage response = await SendAsync(session.Client, request, "gateway_outcome_ambiguous", cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw MapGatewayFailure(response.StatusCode, "gateway_outcome_ambiguous");
        byte[] responseBody = await ReadBoundedAsync(response, "gateway_outcome_ambiguous", cancellationToken).ConfigureAwait(false);
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

    internal async Task EnsureEnrolledAsync(CancellationToken cancellationToken) =>
        _ = await GetReadySessionAsync(cancellationToken).ConfigureAwait(false);

    private async Task<GatewaySession> GetReadySessionAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        await lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!initialized) await InitializeAsync(cancellationToken).ConfigureAwait(false);
            if (state!.Pending is not null) await ReconcilePendingRenewalAsync(cancellationToken).ConfigureAwait(false);
            if (timeProvider.GetUtcNow() >= state.RenewalStartsAt) await BeginRenewalAsync(cancellationToken).ConfigureAwait(false);
            return activeSession!;
        }
        finally { lifecycleLock.Release(); }
    }

    private async Task InitializeAsync(CancellationToken cancellationToken)
    {
        state ??= ReadState();
        if (activeSession is null)
        {
            X509Certificate2 certificate = state is null
                ? LoadOrCreateCertificate()
                : LoadOwnedCertificate(state.CurrentCertificateThumbprint, state.CurrentKeyName);
            activeSession = new GatewaySession(certificate, CreateClient(certificate));
        }

        if (state?.Pending is not null) await ReconcilePendingRenewalAsync(cancellationToken).ConfigureAwait(false);

        BrokerPolicy? policy = await GetPolicyAsync(activeSession, cancellationToken).ConfigureAwait(false);
        if (policy is null)
        {
            if (state is not null) throw new BrokerException("gateway_credential_rejected", "gateway");
            await EnrollAsync(activeSession, cancellationToken).ConfigureAwait(false);
            policy = await GetPolicyAsync(activeSession, cancellationToken).ConfigureAwait(false)
                ?? throw new BrokerException("gateway_enrollment_outcome_ambiguous", "gateway");
        }

        ValidatePolicy(policy, activeSession.Certificate);
        if (state is null)
        {
            state = new GatewayInstallationState(
                StateFormatVersion,
                policy.InstallationId,
                activeSession.Certificate.Thumbprint,
                KeyName(activeSession.Certificate),
                policy.CredentialId,
                policy.CredentialExpiresAt,
                policy.RenewalStartsAt,
                null);
            WriteState(state);
        }
        else
        {
            ValidatePolicyMatchesState(policy, state);
            GatewayInstallationState refreshed = state with
            {
                CredentialExpiresAt = policy.CredentialExpiresAt,
                RenewalStartsAt = policy.RenewalStartsAt
            };
            if (refreshed != state)
            {
                WriteState(refreshed);
                state = refreshed;
            }
        }

        Environment.SetEnvironmentVariable(options.ActivationCodeEnvironmentVariable, null, EnvironmentVariableTarget.Process);
        initialized = true;
    }

    private async Task EnrollAsync(GatewaySession session, CancellationToken cancellationToken)
    {
        string? activationCode = Environment.GetEnvironmentVariable(options.ActivationCodeEnvironmentVariable, EnvironmentVariableTarget.Process);
        if (string.IsNullOrWhiteSpace(activationCode)) throw new BrokerException("gateway_enrollment_required", "gateway");
        Guid activationCodeId = Guid.Parse(options.ActivationCodeId);
        using ECDsa privateKey = session.Certificate.GetECDsaPrivateKey() ?? throw new BrokerException("gateway_credential_unavailable", "gateway");
        string publicKey = Convert.ToBase64String(privateKey.ExportSubjectPublicKeyInfo());
        ChallengeResponse challenge = await PostJsonAsync<ChallengeRequest, ChallengeResponse>(
            bootstrapClient,
            "/v1/enrollments/challenges",
            new ChallengeRequest(activationCodeId, publicKey),
            ambiguityCode: null,
            cancellationToken).ConfigureAwait(false);
        byte[] proofBytes = Encoding.UTF8.GetBytes(FormattableString.Invariant($"BGW-ENROLL1\n{challenge.ChallengeId:D}\n{challenge.Challenge}\n{activationCodeId:D}"));
        string signature = Base64UrlEncode(privateKey.SignData(proofBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        ActivationRequest activation = new(challenge.ChallengeId, activationCode, Convert.ToBase64String(session.Certificate.RawData), signature, options.BrokerVersion);
        _ = await PostJsonAsync<ActivationRequest, EnrollmentResult>(
            bootstrapClient,
            "/v1/enrollments:activate",
            activation,
            "gateway_enrollment_outcome_ambiguous",
            cancellationToken).ConfigureAwait(false);
    }

    private async Task BeginRenewalAsync(CancellationToken cancellationToken)
    {
        BrokerPolicy? currentPolicy = await GetPolicyAsync(activeSession!, cancellationToken).ConfigureAwait(false);
        if (currentPolicy is null) throw new BrokerException("gateway_credential_rejected", "gateway");
        ValidatePolicy(currentPolicy, activeSession!.Certificate);
        ValidatePolicyMatchesState(currentPolicy, state!);
        if (timeProvider.GetUtcNow() < currentPolicy.RenewalStartsAt) return;

        if (state!.Pending is null)
        {
            string keyName = RenewalKeyName(currentPolicy.CredentialId);
            X509Certificate2 replacement = LoadOrCreateOwnedCertificate(keyName);
            PendingRenewal pending = new(replacement.Thumbprint, keyName);
            try
            {
                GatewayInstallationState withPending = state with { Pending = pending };
                WriteState(withPending);
                state = withPending;
                pendingSession = new GatewaySession(replacement, CreateClient(replacement));
            }
            catch
            {
                replacement.Dispose();
                throw;
            }
        }

        await SendRenewalAndPromoteAsync(currentPolicy, cancellationToken).ConfigureAwait(false);
    }

    private async Task ReconcilePendingRenewalAsync(CancellationToken cancellationToken)
    {
        PendingRenewal pending = state!.Pending!;
        pendingSession ??= CreateSession(pending.CertificateThumbprint, pending.KeyName);
        BrokerPolicy? pendingPolicy = await GetPolicyAsync(pendingSession, cancellationToken).ConfigureAwait(false);
        if (pendingPolicy is not null)
        {
            ValidatePolicy(pendingPolicy, pendingSession.Certificate);
            ValidateSameInstallation(pendingPolicy, state);
            PromotePending(pendingPolicy);
            return;
        }

        BrokerPolicy? currentPolicy = await GetPolicyAsync(activeSession!, cancellationToken).ConfigureAwait(false);
        if (currentPolicy is null) throw new BrokerException("gateway_renewal_state_unresolved", "gateway");
        ValidatePolicy(currentPolicy, activeSession!.Certificate);
        ValidatePolicyMatchesState(currentPolicy, state);
        if (timeProvider.GetUtcNow() < currentPolicy.RenewalStartsAt)
            throw new BrokerException("gateway_renewal_state_unresolved", "gateway");
        await SendRenewalAndPromoteAsync(currentPolicy, cancellationToken).ConfigureAwait(false);
    }

    private async Task SendRenewalAndPromoteAsync(BrokerPolicy currentPolicy, CancellationToken cancellationToken)
    {
        PendingRenewal pending = state!.Pending!;
        pendingSession ??= CreateSession(pending.CertificateThumbprint, pending.KeyName);
        using ECDsa replacementKey = pendingSession.Certificate.GetECDsaPrivateKey() ?? throw new BrokerException("gateway_credential_unavailable", "gateway");
        byte[] spkiHash = SHA256.HashData(replacementKey.ExportSubjectPublicKeyInfo());
        byte[] proof = Encoding.UTF8.GetBytes(FormattableString.Invariant($"BGW-RENEW1\n{currentPolicy.InstallationId:D}\n{currentPolicy.CredentialId:D}\n{Base64UrlEncode(spkiHash)}"));
        string signature = Base64UrlEncode(replacementKey.SignData(proof, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        RenewalRequest renewal = new(Convert.ToBase64String(pendingSession.Certificate.RawData), signature);
        EnrollmentResult result = await PostSignedAsync<RenewalRequest, EnrollmentResult>(
            activeSession!,
            "/v1/enrollments:renew",
            renewal,
            "gateway_renewal_outcome_ambiguous",
            cancellationToken).ConfigureAwait(false);
        if (result.InstallationId != state.InstallationId)
            throw new BrokerException("gateway_renewal_response_invalid", "gateway");

        BrokerPolicy? pendingPolicy = await GetPolicyAsync(pendingSession, cancellationToken).ConfigureAwait(false);
        if (pendingPolicy is null) throw new BrokerException("gateway_renewal_outcome_ambiguous", "gateway");
        ValidatePolicy(pendingPolicy, pendingSession.Certificate);
        ValidateSameInstallation(pendingPolicy, state);
        if (pendingPolicy.CredentialExpiresAt != result.CredentialExpiresAt || pendingPolicy.RenewalStartsAt != result.RenewalStartsAt)
            throw new BrokerException("gateway_renewal_response_invalid", "gateway");
        PromotePending(pendingPolicy);
    }

    private void PromotePending(BrokerPolicy policy)
    {
        PendingRenewal pending = state!.Pending!;
        GatewayInstallationState promoted = state with
        {
            CurrentCertificateThumbprint = pending.CertificateThumbprint,
            CurrentKeyName = pending.KeyName,
            CredentialId = policy.CredentialId,
            CredentialExpiresAt = policy.CredentialExpiresAt,
            RenewalStartsAt = policy.RenewalStartsAt,
            Pending = null
        };
        WriteThumbprint(pending.CertificateThumbprint);
        WriteState(promoted);
        retainedSessions.Add(activeSession!);
        activeSession = pendingSession!;
        pendingSession = null;
        state = promoted;
    }

    private async Task<BrokerPolicy?> GetPolicyAsync(GatewaySession session, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = CreateSignedRequest(HttpMethod.Get, "/v1/broker-policy", [], session.Certificate);
        using HttpResponseMessage response = await SendAsync(session.Client, request, ambiguityCode: null, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.Unauthorized) return null;
        if (!response.IsSuccessStatusCode) throw MapGatewayFailure(response.StatusCode);
        byte[] body = await ReadBoundedAsync(response, ambiguityCode: null, cancellationToken).ConfigureAwait(false);
        try { return JsonSerializer.Deserialize<BrokerPolicy>(body, JsonOptions) ?? throw new JsonException(); }
        catch (JsonException exception) { throw new BrokerException("gateway_policy_invalid", "gateway", false, exception); }
    }

    internal X509Certificate2 LoadOrCreateCertificate()
    {
        GatewayInstallationState? persisted = ReadState();
        if (persisted is not null) return LoadOwnedCertificate(persisted.CurrentCertificateThumbprint, persisted.CurrentKeyName);

        string markerPath = Path.Combine(dataDirectory, ThumbprintFileName);
        Directory.CreateDirectory(dataDirectory);
        if (File.Exists(markerPath)) return LoadOwnedCertificate(ReadThumbprint(markerPath), options.CngKeyName);
        if (CngKey.Exists(options.CngKeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider))
            throw new BrokerException("gateway_credential_state_unavailable", "gateway");

        X509Certificate2 created = CreateOwnedCertificate(options.CngKeyName);
        try { WriteThumbprint(created.Thumbprint); }
        catch
        {
            created.Dispose();
            throw;
        }
        return created;
    }

    private X509Certificate2 LoadOrCreateOwnedCertificate(string keyName)
    {
        using X509Store store = new(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        foreach (X509Certificate2 candidate in store.Certificates)
        {
            if (IsOwnedCertificate(candidate, keyName)) return new X509Certificate2(candidate);
        }
        return CreateOwnedCertificate(keyName);
    }

    private X509Certificate2 CreateOwnedCertificate(string keyName)
    {
        CngKeyCreationParameters parameters = new()
        {
            ExportPolicy = CngExportPolicies.None,
            KeyCreationOptions = CngKeyCreationOptions.None,
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider
        };
        using CngKey key = CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider)
            ? CngKey.Open(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider)
            : CngKey.Create(CngAlgorithm.ECDsaP256, keyName, parameters);
        using ECDsaCng ecdsa = new(key);
        CertificateRequest request = new(ExpectedSubject, ecdsa, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        OidCollection eku = [new Oid("1.3.6.1.5.5.7.3.2")];
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
        DateTimeOffset now = timeProvider.GetUtcNow();
        X509Certificate2 created = request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(90));
        using (X509Store store = new(StoreName.My, StoreLocation.CurrentUser))
        {
            store.Open(OpenFlags.ReadWrite);
            store.Add(created);
        }
        return created;
    }

    private X509Certificate2 LoadOwnedCertificate(string thumbprint, string keyName)
    {
        ValidateThumbprint(thumbprint);
        if (!IsOwnedKeyName(keyName)) throw new BrokerException("gateway_credential_state_invalid", "gateway");
        using X509Store store = new(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        X509Certificate2? existing = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
            .OfType<X509Certificate2>()
            .FirstOrDefault(certificate => IsOwnedCertificate(certificate, keyName));
        if (existing is null) throw new BrokerException("gateway_credential_unavailable", "gateway");
        return new X509Certificate2(existing);
    }

    private bool IsOwnedCertificate(X509Certificate2 certificate, string keyName)
    {
        if (!certificate.HasPrivateKey || !string.Equals(certificate.Subject, ExpectedSubject, StringComparison.Ordinal)) return false;
        bool clientAuth = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .Any(extension => extension.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2"));
        if (!clientAuth) return false;
        try
        {
            using ECDsa? key = certificate.GetECDsaPrivateKey();
            return key is ECDsaCng cng && cng.KeySize == 256 &&
                cng.Key.Provider == CngProvider.MicrosoftSoftwareKeyStorageProvider &&
                cng.Key.ExportPolicy == CngExportPolicies.None &&
                string.Equals(cng.Key.KeyName, keyName, StringComparison.Ordinal);
        }
        catch (CryptographicException) { return false; }
    }

    private GatewaySession CreateSession(string thumbprint, string keyName)
    {
        X509Certificate2 certificate = LoadOwnedCertificate(thumbprint, keyName);
        return new GatewaySession(certificate, CreateClient(certificate));
    }

    private GatewayInstallationState? ReadState()
    {
        string path = Path.Combine(dataDirectory, StateFileName);
        if (!File.Exists(path)) return null;
        try
        {
            if (new FileInfo(path).Length is <= 0 or > 16_384) throw new JsonException();
            GatewayInstallationState value = JsonSerializer.Deserialize<GatewayInstallationState>(File.ReadAllBytes(path), JsonOptions) ?? throw new JsonException();
            ValidateState(value);
            string marker = ReadThumbprint(Path.Combine(dataDirectory, ThumbprintFileName));
            if (!string.Equals(marker, value.CurrentCertificateThumbprint, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(marker, value.Pending?.CertificateThumbprint, StringComparison.OrdinalIgnoreCase))
                throw new JsonException();
            return value;
        }
        catch (BrokerException) { throw; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new BrokerException("gateway_credential_state_unavailable", "gateway", false, exception);
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException)
        {
            throw new BrokerException("gateway_credential_state_invalid", "gateway", false, exception);
        }
    }

    private void ValidateState(GatewayInstallationState value)
    {
        ValidateThumbprint(value.CurrentCertificateThumbprint);
        if (value.FormatVersion != StateFormatVersion || value.InstallationId == Guid.Empty || value.CredentialId == Guid.Empty ||
            !IsOwnedKeyName(value.CurrentKeyName) || value.RenewalStartsAt >= value.CredentialExpiresAt)
            throw new BrokerException("gateway_credential_state_invalid", "gateway");
        if (value.Pending is not null)
        {
            ValidateThumbprint(value.Pending.CertificateThumbprint);
            if (!string.Equals(value.Pending.KeyName, RenewalKeyName(value.CredentialId), StringComparison.Ordinal) ||
                string.Equals(value.Pending.CertificateThumbprint, value.CurrentCertificateThumbprint, StringComparison.OrdinalIgnoreCase))
                throw new BrokerException("gateway_credential_state_invalid", "gateway");
        }
    }

    private void WriteState(GatewayInstallationState value)
    {
        ValidateState(value);
        AtomicWrite(Path.Combine(dataDirectory, StateFileName), JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions), "gateway_credential_state_unavailable");
    }

    private void WriteThumbprint(string thumbprint)
    {
        ValidateThumbprint(thumbprint);
        AtomicWrite(Path.Combine(dataDirectory, ThumbprintFileName), Encoding.ASCII.GetBytes(thumbprint), "gateway_credential_state_unavailable");
    }

    private static void AtomicWrite(string path, byte[] bytes, string errorCode)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (FileStream file = new(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                file.Write(bytes);
                file.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new BrokerException(errorCode, "gateway", false, exception);
        }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static string ReadThumbprint(string path)
    {
        try
        {
            if (!File.Exists(path) || new FileInfo(path).Length is <= 0 or > 128) throw new BrokerException("gateway_credential_state_unavailable", "gateway");
            string thumbprint = File.ReadAllText(path, Encoding.ASCII).Trim();
            ValidateThumbprint(thumbprint);
            return thumbprint;
        }
        catch (BrokerException) { throw; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new BrokerException("gateway_credential_state_unavailable", "gateway", false, exception);
        }
    }

    private static void ValidateThumbprint(string value)
    {
        if (value.Length != 40 || value.Any(character => !char.IsAsciiHexDigit(character)))
            throw new BrokerException("gateway_credential_state_invalid", "gateway");
    }

    private static void ValidatePolicy(BrokerPolicy policy, X509Certificate2 certificate)
    {
        if (policy.InstallationId == Guid.Empty || policy.CredentialId == Guid.Empty ||
            policy.ProtocolMajor != 1 || policy.ProtocolMinor != 0 || policy.Revoked || policy.RenewalStartsAt >= policy.CredentialExpiresAt ||
            policy.CredentialExpiresAt != certificate.NotAfter.ToUniversalTime())
            throw new BrokerException("gateway_policy_invalid", "gateway");
    }

    private static void ValidatePolicyMatchesState(BrokerPolicy policy, GatewayInstallationState value)
    {
        ValidateSameInstallation(policy, value);
        if (policy.CredentialId != value.CredentialId)
            throw new BrokerException("gateway_credential_state_mismatch", "gateway");
    }

    private static void ValidateSameInstallation(BrokerPolicy policy, GatewayInstallationState value)
    {
        if (policy.InstallationId != value.InstallationId)
            throw new BrokerException("gateway_credential_state_mismatch", "gateway");
    }

    private string RenewalKeyName(Guid credentialId)
    {
        string suffix = ".renewal." + credentialId.ToString("N");
        string prefix = options.CngKeyName[..Math.Min(options.CngKeyName.Length, 200 - suffix.Length)];
        return prefix + suffix;
    }

    private bool IsOwnedKeyName(string keyName)
    {
        if (string.Equals(keyName, options.CngKeyName, StringComparison.Ordinal)) return true;
        string suffixPrefix = options.CngKeyName[..Math.Min(options.CngKeyName.Length, 200 - 41)] + ".renewal.";
        return keyName.Length == suffixPrefix.Length + 32 && keyName.StartsWith(suffixPrefix, StringComparison.Ordinal) && keyName[suffixPrefix.Length..].All(char.IsAsciiHexDigit);
    }

    private string ExpectedSubject => $"CN=SecureIntegration Installation {options.ActivationCodeId}";

    private HttpClient CreateClient(X509Certificate2? certificate) => new(handlerFactory(certificate))
    {
        BaseAddress = gatewayOrigin,
        Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds)
    };

    private static HttpMessageHandler CreateDefaultHandler(X509Certificate2? certificate)
    {
        HttpClientHandler handler = new()
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            AutomaticDecompression = DecompressionMethods.None
        };
        if (certificate is not null) handler.ClientCertificates.Add(certificate);
        return handler;
    }

    private HttpRequestMessage CreateSignedRequest(HttpMethod method, string target, byte[] body, X509Certificate2 certificate)
    {
        string timestamp = timeProvider.GetUtcNow().ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'", CultureInfo.InvariantCulture);
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

    private static async Task<TResponse> PostJsonAsync<TRequest, TResponse>(HttpClient client, string target, TRequest value, string? ambiguityCode, CancellationToken cancellationToken)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        using HttpRequestMessage request = new(HttpMethod.Post, target) { Content = new ByteArrayContent(body) };
        request.Content.Headers.ContentType = new("application/json");
        return await SendAndDeserializeAsync<TResponse>(client, request, ambiguityCode, cancellationToken).ConfigureAwait(false);
    }

    private async Task<TResponse> PostSignedAsync<TRequest, TResponse>(GatewaySession session, string target, TRequest value, string ambiguityCode, CancellationToken cancellationToken)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        using HttpRequestMessage request = CreateSignedRequest(HttpMethod.Post, target, body, session.Certificate);
        return await SendAndDeserializeAsync<TResponse>(session.Client, request, ambiguityCode, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<TResponse> SendAndDeserializeAsync<TResponse>(HttpClient client, HttpRequestMessage request, string? ambiguityCode, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(client, request, ambiguityCode, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw MapGatewayFailure(response.StatusCode, ambiguityCode);
        byte[] body = await ReadBoundedAsync(response, ambiguityCode, cancellationToken).ConfigureAwait(false);
        try { return JsonSerializer.Deserialize<TResponse>(body, JsonOptions) ?? throw new JsonException(); }
        catch (JsonException exception) { throw new BrokerException("gateway_response_invalid", "gateway", false, exception); }
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, HttpRequestMessage request, string? ambiguityCode, CancellationToken cancellationToken)
    {
        try { return await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false); }
        catch (HttpRequestException exception)
        {
            // ConnectionError can occur after the remote effect; it does not identify the dispatch phase.
            bool knownPreDispatch = exception.HttpRequestError is HttpRequestError.NameResolutionError or HttpRequestError.SecureConnectionError;
            if (ambiguityCode is not null && !knownPreDispatch) throw new BrokerException(ambiguityCode, "gateway", false, exception);
            throw new BrokerException("gateway_transport_failed", "gateway", true, exception);
        }
        catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw ambiguityCode is null
                ? new BrokerException("gateway_timeout", "gateway", true, exception)
                : new BrokerException(ambiguityCode, "gateway", false, exception);
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpResponseMessage response, string? ambiguityCode, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength > IpcProtocol.MaxPayloadBytes) throw new BrokerException("gateway_response_too_large", "gateway");
        try
        {
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
        catch (BrokerException) { throw; }
        catch (Exception exception) when (exception is HttpRequestException or IOException || exception is TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            throw ambiguityCode is null
                ? new BrokerException("gateway_transport_failed", "gateway", true, exception)
                : new BrokerException(ambiguityCode, "gateway", false, exception);
        }
    }

    private static BrokerException MapGatewayFailure(HttpStatusCode statusCode, string? ambiguityCode = null) => statusCode switch
    {
        HttpStatusCode.Unauthorized => new("gateway_authentication_denied", "gateway"),
        HttpStatusCode.Forbidden => new("gateway_authorization_denied", "gateway"),
        HttpStatusCode.NotFound => new("gateway_operation_not_found", "gateway"),
        HttpStatusCode.Conflict => new("gateway_conflict", "gateway"),
        HttpStatusCode.TooManyRequests => new("gateway_throttled", "gateway", true),
        _ when (int)statusCode >= 500 && ambiguityCode is not null => new(ambiguityCode, "gateway"),
        _ when (int)statusCode >= 500 => new("gateway_unavailable", "gateway", true),
        _ => new("gateway_request_rejected", "gateway")
    };

    private static string KeyName(X509Certificate2 certificate)
    {
        using ECDsa? key = certificate.GetECDsaPrivateKey();
        return key is ECDsaCng cng && !string.IsNullOrWhiteSpace(cng.Key.KeyName)
            ? cng.Key.KeyName
            : throw new BrokerException("gateway_credential_unavailable", "gateway");
    }

    private static string Base64UrlEncode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static string CreateTraceParent() => FormattableString.Invariant($"00-{ActivityTraceId.CreateRandom()}-{ActivitySpanId.CreateRandom()}-01");
    private static bool IsIdentifier(string value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 100 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    /// <inheritdoc />
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        activeSession?.Dispose();
        pendingSession?.Dispose();
        foreach (GatewaySession session in retainedSessions) session.Dispose();
        bootstrapClient.Dispose();
        lifecycleLock.Dispose();
    }

    private sealed class GatewaySession(X509Certificate2 certificate, HttpClient client) : IDisposable
    {
        internal X509Certificate2 Certificate { get; } = certificate;
        internal HttpClient Client { get; } = client;
        public void Dispose()
        {
            Client.Dispose();
            Certificate.Dispose();
        }
    }

    private sealed record GatewayInstallationState(
        int FormatVersion,
        Guid InstallationId,
        string CurrentCertificateThumbprint,
        string CurrentKeyName,
        Guid CredentialId,
        DateTimeOffset CredentialExpiresAt,
        DateTimeOffset RenewalStartsAt,
        PendingRenewal? Pending);
    private sealed record PendingRenewal(string CertificateThumbprint, string KeyName);
    private sealed record ChallengeRequest(Guid ActivationCodeId, string PublicKeySpki);
    private sealed record ChallengeResponse(Guid ChallengeId, string Challenge, DateTimeOffset ExpiresAt);
    private sealed record ActivationRequest(Guid ChallengeId, string ActivationCode, string ClientCertificate, string ProofSignature, string BrokerVersion);
    private sealed record RenewalRequest(string NewClientCertificate, string ProofSignature);
    private sealed record EnrollmentResult(Guid InstallationId, Guid TenantId, Guid ApplicationId, DateTimeOffset CredentialExpiresAt, DateTimeOffset RenewalStartsAt);
    private sealed record BrokerPolicy(string MinimumBrokerVersion, int ProtocolMajor, int ProtocolMinor, bool Revoked, Guid InstallationId, Guid CredentialId, DateTimeOffset CredentialExpiresAt, DateTimeOffset RenewalStartsAt);
    private sealed record Payload(string ContentType, string Encoding, string Data);
    private sealed record InvokeRequest(string ProtocolVersion, Payload Payload, Guid CorrelationId);
    private sealed record InvokeResponse(Guid CorrelationId, string ConnectorVersion, Payload Result);
}

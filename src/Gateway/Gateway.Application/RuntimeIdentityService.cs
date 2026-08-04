using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Application;

/// <summary>Verifies ClientAuth registry binding and the signed BGW1 runtime envelope.</summary>
public sealed class RuntimeIdentityService(IGatewayRegistry registry, IGatewayClock clock)
{
    private static readonly TimeSpan TimestampTolerance = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan NonceLifetime = TimeSpan.FromMinutes(10);

    /// <summary>Authenticates a certificate-bound and signed request and consumes its nonce.</summary>
    public async Task<AuthenticatedInstallation> AuthenticateAsync(X509Certificate2? presentedCertificate, string method, string rawPathAndQuery, RuntimeSignatureHeaders headers, ReadOnlyMemory<byte> body, Guid correlationId, CancellationToken cancellationToken)
    {
        if (presentedCertificate is null) throw new GatewayException("BGW-AUTHN-CERTIFICATE-REQUIRED", 401);
        byte[] certificateHash = SHA256.HashData(presentedCertificate.RawData);
        RegisteredInstallationIdentity identity = await registry.FindIdentityByCertificateAsync(certificateHash, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-AUTHN-CREDENTIAL-UNKNOWN", 401);
        DateTimeOffset now = clock.UtcNow;
        if (identity.TenantStatus != TenantStatus.Active || identity.ApplicationStatus != ApplicationStatus.Active || identity.InstallationStatus != InstallationStatus.Active || identity.CredentialStatus is not (CredentialStatus.Active or CredentialStatus.Overlap)) throw new GatewayException("BGW-INSTALLATION-REVOKED", 403);
        if (identity.CredentialNotBefore > now || identity.CredentialNotAfter <= now) throw new GatewayException("BGW-INSTALLATION-CREDENTIAL-EXPIRED", 403);
        string[] timestampFormats = ["yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'"];
        if (!DateTimeOffset.TryParseExact(headers.Timestamp, timestampFormats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset timestamp) || (timestamp - now).Duration() > TimestampTolerance) throw new GatewayException("BGW-AUTHN-TIMESTAMP", 401);
        byte[] nonce;
        byte[] signature;
        byte[] suppliedContentHash;
        try
        {
            nonce = Base64Url.Decode(headers.Nonce);
            signature = Base64Url.Decode(headers.Signature);
            suppliedContentHash = Base64Url.Decode(headers.ContentSha256);
        }
        catch (FormatException) { throw new GatewayException("BGW-AUTHN-SIGNATURE-FORMAT", 401); }
        if (nonce.Length != 16) throw new GatewayException("BGW-AUTHN-NONCE", 401);
        byte[] actualContentHash = SHA256.HashData(body.Span);
        if (suppliedContentHash.Length != actualContentHash.Length || !CryptographicOperations.FixedTimeEquals(suppliedContentHash, actualContentHash)) throw new GatewayException("BGW-AUTHN-CONTENT-DIGEST", 401);
        string normalizedTarget = ValidateRawTarget(rawPathAndQuery);
        string signingInput = string.Join('\n', "BGW1", method.ToUpperInvariant(), normalizedTarget, headers.Timestamp, headers.Nonce, headers.ContentSha256);
        using X509Certificate2 registeredCertificate = X509CertificateLoader.LoadCertificate(identity.CertificateDer);
        using ECDsa? publicKey = registeredCertificate.GetECDsaPublicKey();
        if (publicKey is null || !publicKey.VerifyData(Encoding.UTF8.GetBytes(signingInput), signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new GatewayException("BGW-AUTHN-SIGNATURE", 401);
        if (!await registry.TryStoreNonceAsync(identity.InstallationId, SHA256.HashData(nonce), now.Add(NonceLifetime), cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-AUTHN-REPLAY", 401);
        await registry.AppendAuditAsync(new GatewayAuditEvent(Guid.NewGuid(), now, identity.TenantId, "installation", identity.InstallationId.ToString("D"), "runtime.authenticate", "credential", identity.CredentialId.ToString("D"), correlationId, "success", "BGW-AUTHN-OK", new Dictionary<string, string> { ["method"] = method.ToUpperInvariant() }), cancellationToken).ConfigureAwait(false);
        return new AuthenticatedInstallation(identity, correlationId);
    }

    /// <summary>Builds the canonical BGW1 request signing input.</summary>
    public static string BuildSigningInput(string method, string rawPathAndQuery, string timestamp, string nonce, string contentSha256) => string.Join('\n', "BGW1", method.ToUpperInvariant(), ValidateRawTarget(rawPathAndQuery), timestamp, nonce, contentSha256);

    private static string ValidateRawTarget(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value[0] != '/' || value.Contains('#') || value.Contains("//", StringComparison.Ordinal) || value.Contains('\\') || value.Contains("/../", StringComparison.Ordinal) || value.EndsWith("/..", StringComparison.Ordinal) || value.Contains("/./", StringComparison.Ordinal) || value.EndsWith("/.", StringComparison.Ordinal)) throw new GatewayException("BGW-PROTOCOL-TARGET", 400);
        string lower = value.ToLowerInvariant();
        if (lower.Contains("%2f", StringComparison.Ordinal) || lower.Contains("%5c", StringComparison.Ordinal) || lower.Contains("%2e", StringComparison.Ordinal)) throw new GatewayException("BGW-PROTOCOL-TARGET", 400);
        int queryIndex = value.IndexOf('?');
        if (queryIndex >= 0)
        {
            HashSet<string> names = new(StringComparer.Ordinal);
            foreach (string item in value[(queryIndex + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                string name = item.Split('=', 2)[0];
                if (string.IsNullOrEmpty(name) || !names.Add(name)) throw new GatewayException("BGW-PROTOCOL-QUERY", 400);
            }
        }
        return value;
    }
}

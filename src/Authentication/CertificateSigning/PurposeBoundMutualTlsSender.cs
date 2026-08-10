using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Authentication.CertificateSigning;

/// <summary>Metadata-only result from one purpose-bound outbound mTLS dispatch.</summary>
public sealed record MutualTlsAuthenticatedResponse(
    MutualTlsTransportResponse Response,
    ClientCertificateHealth CertificateHealth,
    string CertificateVersion,
    long CatalogRevision);

/// <summary>
/// Owns certificate resolution, last-moment authorization and transport attachment inside one
/// outbound dispatch. No certificate handle is returned to the connector.
/// </summary>
public sealed class PurposeBoundMutualTlsSender(
    IAuthenticationPolicySource policySource,
    IAuthenticationResourceBindingResolver bindingResolver,
    IClientCertificateProvider? certificates,
    ICertificateMetadataProvider? certificateMetadata,
    IAuthenticationHostResolver hostResolver,
    IPurposeBoundMutualTlsTransport transport,
    IAuthenticationClock clock,
    IAuthenticationPrivateDestinationAllowance? privateDestinationAllowance = null)
{
    private const string ClientAuthenticationEku = "1.3.6.1.5.5.7.3.2";

    /// <summary>
    /// Sends one request using only the current server-owned policy and certificate binding.
    /// Policy and binding are revalidated immediately before DNS resolution and dispatch.
    /// </summary>
    public async Task<MutualTlsAuthenticatedResponse> SendAsync(
        AuthenticationExecutionContext context,
        string policyId,
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(policyId);
        ArgumentNullException.ThrowIfNull(request);
        BindingPolicy.ValidateContext(context);
        if (certificates is null || certificateMetadata is null)
            throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-CAPABILITY-UNAVAILABLE");

        ServerOwnedMutualTlsPolicySnapshot policy = await ResolvePolicyAsync(context, policyId, cancellationToken).ConfigureAwait(false);
        ValidateRequest(policy, request);
        BoundAuthenticationResource resource = await ResolveBindingAsync(context, policy, cancellationToken).ConfigureAwait(false);

        ProviderCertificatePublicMetadata metadata;
        try
        {
            metadata = await certificateMetadata.GetPublicMetadataAsync(resource.ProviderReference, cancellationToken).ConfigureAwait(false)
                ?? throw new ProviderAccessException("BGW-PROVIDER-METADATA-INVALID");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (ProviderAccessException exception) { throw ProviderFailure("BGW-AUTH-MTLS-METADATA-UNAVAILABLE", exception.Retryable); }
        catch (Exception) { throw ProviderFailure("BGW-AUTH-MTLS-METADATA-UNAVAILABLE"); }
        try { ValidateMetadata(resource.PublicMetadata, metadata, policy, clock.UtcNow); }
        catch (AuthenticationPrimitiveException) { throw; }
        catch (Exception) { throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-CERTIFICATE-DENIED"); }

        X509Certificate2 certificate;
        try
        {
            certificate = await certificates.GetClientCertificateAsync(resource.ProviderReference, cancellationToken).ConfigureAwait(false)
                ?? throw new ProviderAccessException("BGW-PROVIDER-CERTIFICATE-INVALID");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (ProviderAccessException exception) { throw ProviderFailure("BGW-AUTH-MTLS-CERTIFICATE-UNAVAILABLE", exception.Retryable); }
        catch (Exception) { throw ProviderFailure("BGW-AUTH-MTLS-CERTIFICATE-UNAVAILABLE"); }

        using (certificate)
        {
            ValidateCertificate(certificate, resource.PublicMetadata, metadata, policy, clock.UtcNow);

            // Close the rotation/disable window before any DNS or transport activity. The caller
            // never receives a reusable authorization or certificate handle.
            ServerOwnedMutualTlsPolicySnapshot currentPolicy = await ResolvePolicyAsync(context, policyId, cancellationToken).ConfigureAwait(false);
            BoundAuthenticationResource currentResource = await ResolveBindingAsync(context, currentPolicy, cancellationToken).ConfigureAwait(false);
            if (!SameAuthorization(policy, currentPolicy, resource, currentResource))
                throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-AUTHORIZATION-STALE");
            ValidateRequest(currentPolicy, request);

            IPAddress[] addresses = await hostResolver.ResolveAsync(currentPolicy.Endpoint.DnsSafeHost, cancellationToken).ConfigureAwait(false);
            if (addresses.Length == 0 || addresses.Any(address => IsForbiddenAddress(address) && privateDestinationAllowance?.IsAllowed(currentPolicy.Endpoint.DnsSafeHost, address) != true))
                throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-DESTINATION-DENIED");

            // DNS resolution is asynchronous and therefore another policy/publication transition
            // window. Re-resolve exact authority after DNS and before the transport side effect.
            ServerOwnedMutualTlsPolicySnapshot finalPolicy = await ResolvePolicyAsync(context, policyId, cancellationToken).ConfigureAwait(false);
            BoundAuthenticationResource finalResource = await ResolveBindingAsync(context, finalPolicy, cancellationToken).ConfigureAwait(false);
            if (!SameAuthorization(currentPolicy, finalPolicy, currentResource, finalResource))
                throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-AUTHORIZATION-STALE");
            ValidateRequest(finalPolicy, request);

            ClientCertificateHealth health = certificate.NotAfter.ToUniversalTime() <= clock.UtcNow.Add(finalPolicy.NearExpiryWarningWindow)
                ? ClientCertificateHealth.NearExpiry
                : ClientCertificateHealth.Healthy;
            MutualTlsCertificateLease certificateLease = new(certificate);
            MutualTlsTransportResponse response = await transport.SendAsync(
                request,
                addresses,
                certificateLease,
                finalPolicy.Timeout,
                finalPolicy.MaximumResponseBytes,
                cancellationToken).ConfigureAwait(false);
            return new(response, health, metadata.Version, finalResource.CatalogRevision);
        }
    }

    private async Task<ServerOwnedMutualTlsPolicySnapshot> ResolvePolicyAsync(AuthenticationExecutionContext context, string policyId, CancellationToken cancellationToken)
    {
        ServerOwnedMutualTlsPolicySnapshot policy = await policySource.ResolveMutualTlsAsync(context, policyId, cancellationToken).ConfigureAwait(false)
            ?? throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-POLICY-DENIED");
        BindingPolicy.ValidateMutualTlsPolicy(context, policyId, policy);
        return policy;
    }

    private async Task<BoundAuthenticationResource> ResolveBindingAsync(AuthenticationExecutionContext context, ServerOwnedMutualTlsPolicySnapshot policy, CancellationToken cancellationToken)
    {
        BoundAuthenticationResource resource = await bindingResolver.ResolveAsync(context, policy.LogicalCertificateBindingId, AuthenticationResourcePurpose.MutualTlsClientAuthentication, cancellationToken).ConfigureAwait(false)
            ?? throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-BOUNDARY");
        BindingPolicy.ValidateBinding(context, resource, policy.LogicalCertificateBindingId, AuthenticationResourcePurpose.MutualTlsClientAuthentication);
        BindingPolicy.ValidateExactPolicyBinding(resource, policy.PolicyRevision, policy.PolicyChecksumSha256, policy.CatalogRevision, policy.CatalogChecksumSha256, policy.ResourceVersion);
        return resource;
    }

    private static void ValidateRequest(ServerOwnedMutualTlsPolicySnapshot policy, HttpRequestMessage request)
    {
        if (request.RequestUri is null || request.RequestUri != policy.Endpoint || !string.Equals(request.Method.Method, policy.HttpMethod, StringComparison.Ordinal))
            throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-REQUEST-BOUNDARY");
    }

    private static void ValidateMetadata(BoundResourcePublicMetadata expected, ProviderCertificatePublicMetadata actual, ServerOwnedMutualTlsPolicySnapshot policy, DateTimeOffset now)
    {
        BindingPolicy.MatchMetadata(expected, actual.FingerprintSha256, actual.NotBefore, actual.NotAfter, actual.KeyAlgorithm, actual.PublicKeySize, actual.Version);
        if (actual.NotBefore > now || actual.NotAfter <= now ||
            (string.Equals(actual.KeyAlgorithm, "RSA", StringComparison.Ordinal) && actual.PublicKeySize < policy.MinimumRsaKeySize) ||
            (string.Equals(actual.KeyAlgorithm, "ECDSA", StringComparison.Ordinal) && actual.PublicKeySize < policy.MinimumEcdsaKeySize) ||
            (!string.Equals(actual.KeyAlgorithm, "RSA", StringComparison.Ordinal) && !string.Equals(actual.KeyAlgorithm, "ECDSA", StringComparison.Ordinal)) ||
            actual.EnhancedKeyUsages is null || !actual.EnhancedKeyUsages.Contains(ClientAuthenticationEku, StringComparer.Ordinal) ||
            actual.KeyUsage is null || (actual.KeyUsage.Value & X509KeyUsageFlags.DigitalSignature) == 0)
            throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-CERTIFICATE-DENIED");
    }

    private static void ValidateCertificate(X509Certificate2 certificate, BoundResourcePublicMetadata expected, ProviderCertificatePublicMetadata metadata, ServerOwnedMutualTlsPolicySnapshot policy, DateTimeOffset now)
    {
        try
        {
            string fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
            if (!certificate.HasPrivateKey || !FixedHexEquals(fingerprint, expected.FingerprintSha256) || !FixedHexEquals(fingerprint, metadata.FingerprintSha256) ||
                certificate.NotBefore.ToUniversalTime() > now || certificate.NotAfter.ToUniversalTime() <= now)
                throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-CERTIFICATE-DENIED");

            using RSA? rsa = certificate.GetRSAPublicKey();
            using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
            byte[] spki = rsa?.ExportSubjectPublicKeyInfo() ?? ecdsa?.ExportSubjectPublicKeyInfo() ?? [];
            string algorithm = rsa is not null ? "RSA" : ecdsa is not null ? "ECDSA" : "unknown";
            int keySize = rsa?.KeySize ?? ecdsa?.KeySize ?? 0;
            if (spki.Length == 0 || !FixedHexEquals(Convert.ToHexString(SHA256.HashData(spki)), expected.SubjectPublicKeyInfoSha256) ||
                !string.Equals(algorithm, metadata.KeyAlgorithm, StringComparison.Ordinal) || keySize != metadata.PublicKeySize ||
                (rsa is not null && rsa.KeySize < policy.MinimumRsaKeySize) || (ecdsa is not null && ecdsa.KeySize < policy.MinimumEcdsaKeySize))
                throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-CERTIFICATE-DENIED");

            X509EnhancedKeyUsageExtension? eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
            X509KeyUsageExtension? keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
            if (eku is null || !eku.EnhancedKeyUsages.Cast<Oid>().Any(value => string.Equals(value.Value, ClientAuthenticationEku, StringComparison.Ordinal)) ||
                keyUsage is null || (keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0)
                throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-CERTIFICATE-PURPOSE");
        }
        catch (AuthenticationPrimitiveException) { throw; }
        catch (Exception) { throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-CERTIFICATE-DENIED"); }
    }

    private static bool SameAuthorization(
        ServerOwnedMutualTlsPolicySnapshot expectedPolicy,
        ServerOwnedMutualTlsPolicySnapshot actualPolicy,
        BoundAuthenticationResource expectedResource,
        BoundAuthenticationResource actualResource) =>
        expectedPolicy.PolicyRevision == actualPolicy.PolicyRevision &&
        FixedHexEquals(expectedPolicy.PolicyChecksumSha256, actualPolicy.PolicyChecksumSha256) &&
        expectedResource.CatalogRevision == actualResource.CatalogRevision &&
        FixedHexEquals(expectedResource.CatalogChecksumSha256, actualResource.CatalogChecksumSha256) &&
        string.Equals(expectedResource.ProviderReference, actualResource.ProviderReference, StringComparison.Ordinal) &&
        string.Equals(expectedResource.PublicMetadata.Version, actualResource.PublicMetadata.Version, StringComparison.Ordinal) &&
        FixedHexEquals(expectedResource.PublicMetadata.FingerprintSha256, actualResource.PublicMetadata.FingerprintSha256) &&
        FixedHexEquals(expectedResource.PublicMetadata.SubjectPublicKeyInfoSha256, actualResource.PublicMetadata.SubjectPublicKeyInfoSha256);

    private static bool FixedHexEquals(string left, string right) => BindingPolicy.IsSha256(left) && BindingPolicy.IsSha256(right) &&
        CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));

    private static AuthenticationPrimitiveException ProviderFailure(string code, bool retryable = false) => new(code, retryable);

    private static bool IsForbiddenAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return true;
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && (address.GetAddressBytes()[0] & 0xfe) == 0xfc) return true;
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            byte[] bytes = address.GetAddressBytes();
            return bytes[0] is 0 or 10 or 127 || bytes[0] >= 224 || (bytes[0] == 169 && bytes[1] == 254) ||
                (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) || (bytes[0] == 192 && bytes[1] == 168) ||
                (bytes[0] == 100 && bytes[1] is >= 64 and <= 127);
        }
        return address.IsIPv4MappedToIPv6 && IsForbiddenAddress(address.MapToIPv4());
    }
}

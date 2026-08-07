using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Authentication.CertificateSigning;

/// <summary>Resolves and validates an outbound mTLS certificate for one exact approved purpose.</summary>
public sealed class PurposeBoundClientCertificateResolver(
    IAuthenticationResourceBindingResolver bindingResolver,
    IClientCertificateProvider? certificates,
    ICertificateMetadataProvider? certificateMetadata,
    IAuthenticationClock clock)
{
    private const string ClientAuthenticationEku = "1.3.6.1.5.5.7.3.2";

    /// <summary>Returns one ephemeral provider-backed certificate handle after all binding and public metadata checks pass.</summary>
    public async Task<ResolvedClientCertificate> ResolveClientCertificateAsync(
        AuthenticationExecutionContext context,
        MutualTlsClientProfile profile,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(profile);
        BindingPolicy.ValidateContext(context);
        ValidateProfile(context, profile);
        if (certificates is null || certificateMetadata is null)
            throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-CAPABILITY-UNAVAILABLE");

        BoundAuthenticationResource resource = await bindingResolver.ResolveAsync(context, profile.LogicalCertificateBindingId, AuthenticationResourcePurpose.MutualTlsClientAuthentication, cancellationToken).ConfigureAwait(false)
            ?? throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-BOUNDARY");
        BindingPolicy.ValidateBinding(context, resource, profile.LogicalCertificateBindingId, AuthenticationResourcePurpose.MutualTlsClientAuthentication);

        ProviderCertificatePublicMetadata metadata;
        try { metadata = await certificateMetadata.GetPublicMetadataAsync(resource.ProviderReference, cancellationToken).ConfigureAwait(false) ?? throw new ProviderAccessException("BGW-PROVIDER-METADATA-INVALID"); }
        catch (ProviderAccessException exception) { throw ProviderFailure("BGW-AUTH-MTLS-METADATA-UNAVAILABLE", exception); }
        ValidateMetadata(resource.PublicMetadata, metadata, profile, clock.UtcNow);

        X509Certificate2 certificate;
        try { certificate = await certificates.GetClientCertificateAsync(resource.ProviderReference, cancellationToken).ConfigureAwait(false) ?? throw new ProviderAccessException("BGW-PROVIDER-CERTIFICATE-INVALID"); }
        catch (ProviderAccessException exception) { throw ProviderFailure("BGW-AUTH-MTLS-CERTIFICATE-UNAVAILABLE", exception); }
        try
        {
            ValidateCertificate(certificate, metadata, profile, clock.UtcNow);
            ClientCertificateHealth health = certificate.NotAfter.ToUniversalTime() <= clock.UtcNow.Add(profile.NearExpiryWarningWindow)
                ? ClientCertificateHealth.NearExpiry
                : ClientCertificateHealth.Healthy;
            return new ResolvedClientCertificate(certificate, health, metadata.FingerprintSha256, metadata.Version, resource.CatalogRevision);
        }
        catch
        {
            certificate.Dispose();
            throw;
        }
    }

    private static void ValidateProfile(AuthenticationExecutionContext context, MutualTlsClientProfile profile)
    {
        if (!BindingPolicy.IsIdentifier(profile.ProfileId) || !string.Equals(profile.ProfileId, context.ProfileId, StringComparison.Ordinal) ||
            !BindingPolicy.IsIdentifier(profile.LogicalCertificateBindingId) || profile.NearExpiryWarningWindow < TimeSpan.Zero ||
            profile.NearExpiryWarningWindow > TimeSpan.FromDays(90) || profile.MinimumRsaKeySize < 2048 || profile.MinimumRsaKeySize > 16384 ||
            profile.MinimumEcdsaKeySize < 256 || profile.MinimumEcdsaKeySize > 1024)
            throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-PROFILE");
    }

    private static void ValidateMetadata(BoundResourcePublicMetadata expected, ProviderCertificatePublicMetadata actual, MutualTlsClientProfile profile, DateTimeOffset now)
    {
        BindingPolicy.MatchMetadata(expected, actual.FingerprintSha256, actual.NotBefore, actual.NotAfter, actual.KeyAlgorithm, actual.PublicKeySize, actual.Version);
        if (actual.NotBefore > now || actual.NotAfter <= now ||
            (string.Equals(actual.KeyAlgorithm, "RSA", StringComparison.Ordinal) && actual.PublicKeySize < profile.MinimumRsaKeySize) ||
            (string.Equals(actual.KeyAlgorithm, "ECDSA", StringComparison.Ordinal) && actual.PublicKeySize < profile.MinimumEcdsaKeySize) ||
            (!string.Equals(actual.KeyAlgorithm, "RSA", StringComparison.Ordinal) && !string.Equals(actual.KeyAlgorithm, "ECDSA", StringComparison.Ordinal)) ||
            actual.EnhancedKeyUsages is null || !actual.EnhancedKeyUsages.Contains(ClientAuthenticationEku, StringComparer.Ordinal) ||
            actual.KeyUsage is null || (actual.KeyUsage.Value & X509KeyUsageFlags.DigitalSignature) == 0)
            throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-CERTIFICATE-DENIED");
    }

    private static void ValidateCertificate(X509Certificate2 certificate, ProviderCertificatePublicMetadata metadata, MutualTlsClientProfile profile, DateTimeOffset now)
    {
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
        if (!certificate.HasPrivateKey || !string.Equals(fingerprint, metadata.FingerprintSha256, StringComparison.OrdinalIgnoreCase) ||
            certificate.NotBefore.ToUniversalTime() > now || certificate.NotAfter.ToUniversalTime() <= now)
            throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-CERTIFICATE-DENIED");

        using RSA? rsa = certificate.GetRSAPublicKey();
        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        if ((rsa is null && ecdsa is null) || (rsa is not null && rsa.KeySize < profile.MinimumRsaKeySize) || (ecdsa is not null && ecdsa.KeySize < profile.MinimumEcdsaKeySize))
            throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-CERTIFICATE-DENIED");

        X509EnhancedKeyUsageExtension? eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
        X509KeyUsageExtension? keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        if (eku is null || !eku.EnhancedKeyUsages.Cast<Oid>().Any(value => string.Equals(value.Value, ClientAuthenticationEku, StringComparison.Ordinal)) ||
            keyUsage is null || (keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0)
            throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-CERTIFICATE-PURPOSE");
    }

    private static AuthenticationPrimitiveException ProviderFailure(string code, ProviderAccessException exception) => new(code, exception.Retryable);
}

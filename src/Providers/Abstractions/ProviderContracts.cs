using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SecureIntegration.Providers.Abstractions;

/// <summary>Retrieves secret values for server-side use only.</summary>
public interface ISecretValueProvider
{
    /// <summary>Returns the value addressed by an allowlisted logical reference.</summary>
    Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken);
}

/// <summary>Retrieves outbound client certificates without exposing them to callers outside the runtime.</summary>
public interface IClientCertificateProvider
{
    /// <summary>Loads an ephemeral client certificate for one logical reference.</summary>
    Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken);
}

/// <summary>Reads only public certificate metadata for review and policy decisions.</summary>
public interface ICertificateMetadataProvider
{
    /// <summary>Returns public metadata without exporting private key material.</summary>
    Task<ProviderCertificatePublicMetadata> GetPublicMetadataAsync(string logicalReference, CancellationToken cancellationToken);
}

/// <summary>
/// Retrieves only the public DER certificate material for an allowlisted logical reference.
/// The capability never returns a private key, PKCS#12 payload, password, credential or locator.
/// </summary>
public interface ICertificatePublicMaterialProvider
{
    /// <summary>Returns the leaf certificate and its optional issuer chain, leaf first.</summary>
    Task<ProviderCertificatePublicMaterial> GetPublicMaterialAsync(string logicalReference, CancellationToken cancellationToken);
}

/// <summary>Defensively copied public X.509 material for one exact provider resource revision.</summary>
public sealed class ProviderCertificatePublicMaterial
{
    /// <summary>Creates a public-only leaf and optional issuer chain snapshot.</summary>
    public ProviderCertificatePublicMaterial(
        ReadOnlyMemory<byte> leafCertificateDer,
        IReadOnlyList<ReadOnlyMemory<byte>> certificateChainDer,
        ProviderCertificatePublicMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(certificateChainDer);
        ArgumentNullException.ThrowIfNull(metadata);
        LeafCertificateDer = leafCertificateDer.ToArray();
        CertificateChainDer = certificateChainDer.Select(value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
        Metadata = metadata;
        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(LeafCertificateDer.Span);
        using RSA? rsa = certificate.GetRSAPublicKey();
        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        byte[] subjectPublicKeyInfo = rsa?.ExportSubjectPublicKeyInfo() ?? ecdsa?.ExportSubjectPublicKeyInfo()
            ?? throw new CryptographicException("BGW-PROVIDER-CERTIFICATE-PUBLIC-KEY-INVALID");
        SubjectPublicKeyInfoSha256 = Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo));
    }

    /// <summary>DER-encoded leaf certificate.</summary>
    public ReadOnlyMemory<byte> LeafCertificateDer { get; }
    /// <summary>Optional DER-encoded issuers in certification order, excluding the leaf.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> CertificateChainDer { get; }
    /// <summary>Public identity metadata for the same leaf and provider resource revision.</summary>
    public ProviderCertificatePublicMetadata Metadata { get; }
    /// <summary>SHA-256 of the leaf SubjectPublicKeyInfo, derived from the returned DER.</summary>
    public string SubjectPublicKeyInfoSha256 { get; }
}

/// <summary>Provider-neutral public certificate metadata.</summary>
public sealed record ProviderCertificatePublicMetadata(
    string FingerprintSha256,
    string Subject,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string KeyAlgorithm,
    int PublicKeySize,
    string Version,
    IReadOnlyList<string>? EnhancedKeyUsages = null,
    X509KeyUsageFlags? KeyUsage = null);

/// <summary>Public metadata for a provider-owned signing key. SubjectPublicKeyInfo never contains private material.</summary>
public sealed record ProviderSigningKeyPublicMetadata(
    string FingerprintSha256,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string KeyAlgorithm,
    int PublicKeySize,
    string Version,
    byte[] SubjectPublicKeyInfo);

/// <summary>Uses a provider-owned signing key and exposes only its public verification metadata.</summary>
public interface IKeyOperationProvider
{
    /// <summary>Signs a digest with the referenced key and algorithm.</summary>
    Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken);
    /// <summary>Returns public metadata used to bind and verify a provider-side signing operation.</summary>
    Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken);
}

/// <summary>Compatibility name for the narrow signing/key-use capability.</summary>
public interface ISigningKeyProvider : IKeyOperationProvider { }

/// <summary>Computes a MAC without exporting provider-owned key material.</summary>
public interface IMacProvider
{
    /// <summary>Computes a MAC with the referenced key and algorithm.</summary>
    Task<byte[]> ComputeMacAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> data, CancellationToken cancellationToken);
}

/// <summary>Reports readiness of a configured provider boundary.</summary>
public interface IProviderHealthCheck
{
    /// <summary>Returns false when the provider cannot safely serve configured capabilities.</summary>
    Task<bool> IsReadyAsync(CancellationToken cancellationToken);
}

/// <summary>Describes only the capabilities exposed by a provider pack.</summary>
public interface IProviderCapabilitySource
{
    /// <summary>Immutable capability declaration.</summary>
    ProviderCapabilities Capabilities { get; }
}

/// <summary>Provider capabilities; absent capabilities are never inferred or emulated.</summary>
public sealed record ProviderCapabilities(
    bool SecretValues,
    bool ClientCertificates,
    bool SigningKeys,
    bool Mac,
    bool CertificatePublicMaterial = false);

/// <summary>Provider-neutral configuration passed to an optional deployment pack.</summary>
public sealed record ProviderPackContext(Uri Endpoint, string? ClientIdentity, IReadOnlyDictionary<string, string> Settings);

/// <summary>Capability instances returned by a deployment pack factory.</summary>
public sealed record ProviderServices(
    ISecretValueProvider SecretValues,
    IClientCertificateProvider ClientCertificates,
    IProviderHealthCheck Health,
    IProviderCapabilitySource CapabilitySource,
    IKeyOperationProvider? SigningKeys = null,
    IMacProvider? Mac = null,
    ICertificateMetadataProvider? CertificateMetadata = null,
    ICertificatePublicMaterialProvider? CertificatePublicMaterial = null);

/// <summary>Composition seam implemented by deployment-specific packs.</summary>
public interface IProviderPackFactory
{
    /// <summary>Creates provider capabilities from explicit, provider-neutral settings.</summary>
    ProviderServices Create(ProviderPackContext context);
}

/// <summary>Sanitized provider failure propagated across the pack boundary.</summary>
public sealed class ProviderAccessException(string code, bool retryable = false, Exception? innerException = null) : Exception(code, innerException)
{
    /// <summary>Stable non-secret error code.</summary>
    public string Code { get; } = code;
    /// <summary>Whether a bounded runtime retry may be safe.</summary>
    public bool Retryable { get; } = retryable;
}

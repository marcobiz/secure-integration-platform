using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;

namespace SecureIntegration.Authentication.CertificateSigning.Tests;

internal sealed class FixedClock(DateTimeOffset now) : IAuthenticationClock
{
    public DateTimeOffset UtcNow { get; set; } = now;
}

internal sealed class MutableBindingResolver(BoundAuthenticationResource current) : IAuthenticationResourceBindingResolver
{
    public BoundAuthenticationResource Current { get; set; } = current;
    public int Calls { get; private set; }

    public Task<BoundAuthenticationResource> ResolveAsync(AuthenticationExecutionContext context, string logicalBindingId, AuthenticationResourcePurpose purpose, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls++;
        return Task.FromResult(Current);
    }
}

internal sealed class TrackingKeyProvider(IKeyOperationProvider inner) : IKeyOperationProvider
{
    public List<string> MetadataReferences { get; } = [];
    public List<(string Reference, string Algorithm)> Signatures { get; } = [];

    public Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken)
    {
        MetadataReferences.Add(logicalReference);
        return inner.GetSigningKeyMetadataAsync(logicalReference, cancellationToken);
    }

    public Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken)
    {
        Signatures.Add((logicalReference, algorithm));
        return inner.SignDigestAsync(logicalReference, algorithm, digest, cancellationToken);
    }
}

internal sealed class TrackingCertificateProvider(InMemoryProvider inner) : IClientCertificateProvider, ICertificateMetadataProvider
{
    public List<string> MetadataReferences { get; } = [];
    public List<string> CertificateReferences { get; } = [];

    public Task<ProviderCertificatePublicMetadata> GetPublicMetadataAsync(string logicalReference, CancellationToken cancellationToken)
    {
        MetadataReferences.Add(logicalReference);
        return inner.GetPublicMetadataAsync(logicalReference, cancellationToken);
    }

    public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken)
    {
        CertificateReferences.Add(logicalReference);
        return inner.GetClientCertificateAsync(logicalReference, cancellationToken);
    }
}

internal sealed class FixedIdentifierSource(string identifier) : IJwtIdentifierSource
{
    public string Create() => identifier;
}

internal static class AuthenticationTestData
{
    internal const string ConnectorId = "synthetic-healthcare";
    internal const string OperationId = "submit";
    internal const string JwtProfileId = "synthetic-rs256";
    internal const string MutualTlsProfileId = "synthetic-mtls";
    internal const string JwtBindingId = "jwt-signing-certificate";
    internal const string MutualTlsBindingId = "outbound-client-certificate";

    internal static AuthenticationExecutionContext Context(string profileId, Uri? endpoint = null) => new(
        Guid.Parse("11111111-1111-1111-1111-111111111111"),
        Guid.Parse("22222222-2222-2222-2222-222222222222"),
        Guid.Parse("33333333-3333-3333-3333-333333333333"),
        Guid.Parse("44444444-4444-4444-4444-444444444444"),
        Guid.Parse("55555555-5555-5555-5555-555555555555"),
        ConnectorId,
        OperationId,
        profileId,
        endpoint ?? new Uri("https://synthetic.example.test/api"),
        Guid.Parse("66666666-6666-6666-6666-666666666666"));

    internal static Rs256JwtProfile JwtProfile(TimeSpan? lifetime = null) => new(
        JwtProfileId,
        "https://issuer.example.test",
        "https://audience.example.test",
        JwtSubjectPolicy.Installation,
        null,
        new HashSet<string>(StringComparer.Ordinal) { "role", "payload_sha256" },
        lifetime ?? TimeSpan.FromMinutes(5),
        TimeSpan.FromSeconds(30),
        JwtBindingId);

    internal static MutualTlsClientProfile MutualTlsProfile(TimeSpan? warning = null) => new(
        MutualTlsProfileId,
        MutualTlsBindingId,
        warning ?? TimeSpan.FromDays(7));

    internal static BoundAuthenticationResource SigningBinding(AuthenticationExecutionContext context, X509Certificate2 certificate, string providerReference, long revision = 1, AuthenticationResourceStatus status = AuthenticationResourceStatus.Active, AuthenticationResourcePurpose purpose = AuthenticationResourcePurpose.JwtSigning) =>
        Binding(context, certificate, providerReference, JwtBindingId, purpose, revision, status);

    internal static BoundAuthenticationResource MutualTlsBinding(AuthenticationExecutionContext context, X509Certificate2 certificate, string providerReference, long revision = 1, AuthenticationResourceStatus status = AuthenticationResourceStatus.Active, AuthenticationResourcePurpose purpose = AuthenticationResourcePurpose.MutualTlsClientAuthentication) =>
        Binding(context, certificate, providerReference, MutualTlsBindingId, purpose, revision, status);

    internal static BoundResourcePublicMetadata Metadata(X509Certificate2 certificate)
    {
        using RSA? rsa = certificate.GetRSAPublicKey();
        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        return new(
            Convert.ToHexString(SHA256.HashData(certificate.RawData)),
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            rsa is not null ? "RSA" : ecdsa is not null ? "ECDSA" : "unknown",
            rsa?.KeySize ?? ecdsa?.KeySize ?? 0,
            certificate.SerialNumber);
    }

    internal static InMemoryProvider Provider(SyntheticAuthenticationMaterial material) => new(
        new Dictionary<string, string>(),
        certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
        {
            ["mtls-r1"] = material.ClientCertificateRevision1,
            ["mtls-r2"] = material.ClientCertificateRevision2,
            ["mtls-expired"] = material.ExpiredClientCertificate,
            ["mtls-near"] = material.NearExpiryClientCertificate,
            ["mtls-wrong-purpose"] = material.WrongPurposeCertificate
        },
        signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
        {
            ["sign-r1"] = material.SigningKeyRevision1,
            ["sign-r2"] = material.SigningKeyRevision2
        });

    private static BoundAuthenticationResource Binding(AuthenticationExecutionContext context, X509Certificate2 certificate, string providerReference, string logicalBinding, AuthenticationResourcePurpose purpose, long revision, AuthenticationResourceStatus status) => new(
        logicalBinding,
        purpose,
        status,
        context.ConnectorVersionId,
        context.ConnectorId,
        context.OperationId,
        context.ProfileId,
        context.EnvironmentId,
        context.Endpoint,
        revision,
        new string(revision % 2 == 0 ? 'B' : 'A', 64),
        providerReference,
        Metadata(certificate));
}

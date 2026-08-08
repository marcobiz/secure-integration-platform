using System.Net;
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
    public Func<int, BoundAuthenticationResource>? OnResolve { get; set; }
    public int Calls { get; private set; }

    public Task<BoundAuthenticationResource> ResolveAsync(AuthenticationExecutionContext context, string logicalBindingId, AuthenticationResourcePurpose purpose, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls++;
        return Task.FromResult(OnResolve?.Invoke(Calls) ?? Current);
    }
}

internal sealed class MutablePolicySource(
    ServerOwnedRs256PolicySnapshot rs256,
    ServerOwnedMutualTlsPolicySnapshot mutualTls) : IAuthenticationPolicySource
{
    public ServerOwnedRs256PolicySnapshot Rs256 { get; set; } = rs256;
    public ServerOwnedMutualTlsPolicySnapshot MutualTls { get; set; } = mutualTls;
    public int Rs256Calls { get; private set; }
    public int MutualTlsCalls { get; private set; }

    public Task<ServerOwnedRs256PolicySnapshot> ResolveRs256Async(AuthenticationExecutionContext context, string policyId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Rs256Calls++;
        return Task.FromResult(Rs256);
    }

    public Task<ServerOwnedMutualTlsPolicySnapshot> ResolveMutualTlsAsync(AuthenticationExecutionContext context, string policyId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        MutualTlsCalls++;
        return Task.FromResult(MutualTls);
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

internal sealed class TrackingPublicMaterialProvider(ICertificatePublicMaterialProvider inner) : ICertificatePublicMaterialProvider
{
    public List<string> References { get; } = [];

    public Task<ProviderCertificatePublicMaterial> GetPublicMaterialAsync(string logicalReference, CancellationToken cancellationToken)
    {
        References.Add(logicalReference);
        return inner.GetPublicMaterialAsync(logicalReference, cancellationToken);
    }
}

internal sealed class TrackingCertificateProvider(IClientCertificateProvider certificates, ICertificateMetadataProvider metadata) : IClientCertificateProvider, ICertificateMetadataProvider
{
    public TrackingCertificateProvider(InMemoryProvider provider) : this(provider, provider) { }

    public List<string> MetadataReferences { get; } = [];
    public List<string> CertificateReferences { get; } = [];

    public Task<ProviderCertificatePublicMetadata> GetPublicMetadataAsync(string logicalReference, CancellationToken cancellationToken)
    {
        MetadataReferences.Add(logicalReference);
        return metadata.GetPublicMetadataAsync(logicalReference, cancellationToken);
    }

    public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken)
    {
        CertificateReferences.Add(logicalReference);
        return certificates.GetClientCertificateAsync(logicalReference, cancellationToken);
    }
}

internal sealed class FixedIdentifierSource(string identifier) : IJwtIdentifierSource
{
    public string Create() => identifier;
}

internal sealed class StaticHostResolver(params IPAddress[] addresses) : IAuthenticationHostResolver
{
    public int Calls { get; private set; }

    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Calls++;
        return Task.FromResult(addresses);
    }
}

internal sealed class LoopbackAllowance : IAuthenticationPrivateDestinationAllowance
{
    public bool IsAllowed(string host, IPAddress address) => string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) && IPAddress.IsLoopback(address);
}

internal static class AuthenticationTestData
{
    internal const string ConnectorId = "synthetic-connector";
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

    internal static ServerOwnedRs256PolicySnapshot JwtPolicy(
        AuthenticationExecutionContext context,
        X509Certificate2 certificate,
        long revision = 1,
        string? issuer = null,
        string? audience = null,
        JwtSubjectPolicy subjectPolicy = JwtSubjectPolicy.Installation,
        string? fixedSubject = null,
        IReadOnlySet<string>? allowedClaims = null,
        TimeSpan? lifetime = null,
        JwtCertificateHeaderMode certificateHeaderMode = JwtCertificateHeaderMode.None,
        JwtTemporalClaimMode temporalClaimMode = JwtTemporalClaimMode.IssuedAtNotBeforeExpiration,
        IReadOnlyList<JwtTrustedClaimBinding>? trustedClaims = null) => ServerOwnedRs256PolicySnapshot.Create(
            JwtProfileId,
            revision,
            context.ConnectorVersionId,
            context.ConnectorId,
            context.OperationId,
            context.EnvironmentId,
            context.Endpoint,
            issuer ?? "https://issuer.example.test",
            audience ?? "https://audience.example.test",
            subjectPolicy,
            fixedSubject,
            allowedClaims ?? new HashSet<string>(StringComparer.Ordinal) { "role", "payload_sha256" },
            lifetime ?? TimeSpan.FromMinutes(5),
            TimeSpan.FromSeconds(30),
            JwtBindingId,
            certificate.SerialNumber,
            revision,
            CatalogChecksum(revision),
            certificateHeaderMode: certificateHeaderMode,
            temporalClaimMode: temporalClaimMode,
            trustedClaims: trustedClaims);

    internal static ServerOwnedMutualTlsPolicySnapshot MutualTlsPolicy(
        AuthenticationExecutionContext context,
        X509Certificate2 certificate,
        long revision = 1,
        TimeSpan? warning = null) => ServerOwnedMutualTlsPolicySnapshot.Create(
            MutualTlsProfileId,
            revision,
            context.ConnectorVersionId,
            context.ConnectorId,
            context.OperationId,
            context.EnvironmentId,
            context.Endpoint,
            "GET",
            MutualTlsBindingId,
            certificate.SerialNumber,
            revision,
            CatalogChecksum(revision),
            warning ?? TimeSpan.FromDays(7),
            TimeSpan.FromSeconds(10),
            4096);

    internal static MutablePolicySource Policies(AuthenticationExecutionContext context, X509Certificate2 signingCertificate, X509Certificate2 mutualTlsCertificate) =>
        new(JwtPolicy(context with { ProfileId = JwtProfileId }, signingCertificate), MutualTlsPolicy(context with { ProfileId = MutualTlsProfileId }, mutualTlsCertificate));

    internal static BoundAuthenticationResource SigningBinding(AuthenticationExecutionContext context, X509Certificate2 certificate, string providerReference, ServerOwnedRs256PolicySnapshot policy, AuthenticationResourceStatus status = AuthenticationResourceStatus.Active, AuthenticationResourcePurpose purpose = AuthenticationResourcePurpose.JwtSigning) =>
        Binding(context, certificate, providerReference, JwtBindingId, purpose, policy.PolicyRevision, policy.PolicyChecksumSha256, policy.CatalogRevision, policy.CatalogChecksumSha256, status);

    internal static BoundAuthenticationResource MutualTlsBinding(AuthenticationExecutionContext context, X509Certificate2 certificate, string providerReference, ServerOwnedMutualTlsPolicySnapshot policy, AuthenticationResourceStatus status = AuthenticationResourceStatus.Active, AuthenticationResourcePurpose purpose = AuthenticationResourcePurpose.MutualTlsClientAuthentication) =>
        Binding(context, certificate, providerReference, MutualTlsBindingId, purpose, policy.PolicyRevision, policy.PolicyChecksumSha256, policy.CatalogRevision, policy.CatalogChecksumSha256, status);

    internal static BoundResourcePublicMetadata Metadata(X509Certificate2 certificate)
    {
        using RSA? rsa = certificate.GetRSAPublicKey();
        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        byte[] spki = rsa?.ExportSubjectPublicKeyInfo() ?? ecdsa?.ExportSubjectPublicKeyInfo() ?? [];
        return new(
            Convert.ToHexString(SHA256.HashData(certificate.RawData)),
            Convert.ToHexString(SHA256.HashData(spki)),
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
            ["sign-r2"] = material.SigningKeyRevision2,
            ["sign-expired"] = material.ExpiredSigningCertificate
        },
        certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal)
        {
            ["sign-r1"] = [material.RootCertificate],
            ["sign-r2"] = [material.RootCertificate],
            ["sign-expired"] = [material.RootCertificate]
        });

    private static BoundAuthenticationResource Binding(
        AuthenticationExecutionContext context,
        X509Certificate2 certificate,
        string providerReference,
        string logicalBinding,
        AuthenticationResourcePurpose purpose,
        long policyRevision,
        string policyChecksum,
        long catalogRevision,
        string catalogChecksum,
        AuthenticationResourceStatus status) => new(
            logicalBinding,
            purpose,
            status,
            context.ConnectorVersionId,
            context.ConnectorId,
            context.OperationId,
            context.ProfileId,
            policyRevision,
            policyChecksum,
            context.EnvironmentId,
            context.Endpoint,
            catalogRevision,
            catalogChecksum,
            providerReference,
            Metadata(certificate));

    private static string CatalogChecksum(long revision) => new(revision % 2 == 0 ? 'B' : 'A', 64);
}

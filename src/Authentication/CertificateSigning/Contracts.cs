using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace SecureIntegration.Authentication.CertificateSigning;

/// <summary>Immutable server-derived scope for one outbound authentication operation.</summary>
public sealed record AuthenticationExecutionContext(
    Guid TenantId,
    Guid InstallationId,
    Guid ApplicationId,
    Guid EnvironmentId,
    Guid ConnectorVersionId,
    string ConnectorId,
    string OperationId,
    string ProfileId,
    Uri Endpoint,
    Guid CorrelationId);

/// <summary>Distinct uses that cannot be substituted even when backed by the same provider.</summary>
public enum AuthenticationResourcePurpose
{
    /// <summary>RS256 JWT signing only.</summary>
    JwtSigning,
    /// <summary>Outbound TLS client authentication only.</summary>
    MutualTlsClientAuthentication
}

/// <summary>Current server-owned resource state.</summary>
public enum AuthenticationResourceStatus
{
    /// <summary>The exact catalog revision is usable.</summary>
    Active,
    /// <summary>The resource is denied before provider or network access.</summary>
    Disabled
}

/// <summary>Approved public metadata frozen into a resource binding.</summary>
public sealed record BoundResourcePublicMetadata(
    string FingerprintSha256,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string KeyAlgorithm,
    int PublicKeySize,
    string Version);

/// <summary>
/// Server-owned resolution result. ProviderReference is produced only by the protected resolver;
/// it is never an input to SignJwt or ResolveClientCertificate.
/// </summary>
public sealed record BoundAuthenticationResource(
    string LogicalBindingId,
    AuthenticationResourcePurpose Purpose,
    AuthenticationResourceStatus Status,
    Guid ConnectorVersionId,
    string ConnectorId,
    string OperationId,
    string ProfileId,
    Guid EnvironmentId,
    Uri Endpoint,
    long CatalogRevision,
    string CatalogChecksumSha256,
    string ProviderReference,
    BoundResourcePublicMetadata PublicMetadata);

/// <summary>Resolves only approved, immutable authentication bindings from server-owned state.</summary>
public interface IAuthenticationResourceBindingResolver
{
    /// <summary>Resolves an exact logical binding and purpose within the server-derived execution context.</summary>
    Task<BoundAuthenticationResource> ResolveAsync(
        AuthenticationExecutionContext context,
        string logicalBindingId,
        AuthenticationResourcePurpose purpose,
        CancellationToken cancellationToken);
}

/// <summary>UTC clock used by validity and JWT lifetime policy.</summary>
public interface IAuthenticationClock
{
    /// <summary>Current UTC time.</summary>
    DateTimeOffset UtcNow { get; }
}

/// <summary>System UTC clock.</summary>
public sealed class SystemAuthenticationClock : IAuthenticationClock
{
    /// <inheritdoc />
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

/// <summary>Stable sanitized primitive failure.</summary>
public sealed class AuthenticationPrimitiveException : Exception
{
    /// <summary>Creates a failure containing only a stable metadata-safe code.</summary>
    public AuthenticationPrimitiveException(string code, bool retryable = false)
        : base(code)
    {
        Code = code;
        Retryable = retryable;
    }

    /// <summary>Stable non-secret error code.</summary>
    public string Code { get; }
    /// <summary>Whether an explicitly idempotent caller may retry.</summary>
    public bool Retryable { get; }
}

/// <summary>Server-derived source for the JWT subject.</summary>
public enum JwtSubjectPolicy
{
    /// <summary>Use the authenticated Installation identifier.</summary>
    Installation,
    /// <summary>Use the authenticated Application identifier.</summary>
    Application,
    /// <summary>Use a fixed value compiled into the profile.</summary>
    Fixed
}

/// <summary>Immutable RS256 policy. Algorithm and key binding are not caller inputs.</summary>
public sealed record Rs256JwtProfile(
    string ProfileId,
    string Issuer,
    string Audience,
    JwtSubjectPolicy SubjectPolicy,
    string? FixedSubject,
    IReadOnlySet<string> AllowedClaims,
    TimeSpan Lifetime,
    TimeSpan AllowedClockSkew,
    string LogicalKeyBindingId,
    int MinimumRsaKeySize = 2048);

/// <summary>One server-derived, profile-allowlisted claim.</summary>
public sealed record JwtBoundClaim(string Name, JsonElement Value);

/// <summary>Stores only a digest of a generated JWT identifier until expiry.</summary>
public interface IJwtReplayStore
{
    /// <summary>Reserves one identifier digest exactly once.</summary>
    Task<bool> TryReserveAsync(ReadOnlyMemory<byte> identifierSha256, DateTimeOffset expiresAt, CancellationToken cancellationToken);
}

/// <summary>Generates unpredictable JWT identifiers.</summary>
public interface IJwtIdentifierSource
{
    /// <summary>Creates a new opaque identifier.</summary>
    string Create();
}

/// <summary>Fixed outbound mTLS policy.</summary>
public sealed record MutualTlsClientProfile(
    string ProfileId,
    string LogicalCertificateBindingId,
    TimeSpan NearExpiryWarningWindow,
    int MinimumRsaKeySize = 2048,
    int MinimumEcdsaKeySize = 256);

/// <summary>Non-blocking public health classification for a valid mTLS certificate.</summary>
public enum ClientCertificateHealth
{
    /// <summary>Valid outside the configured warning window.</summary>
    Healthy,
    /// <summary>Valid but inside the configured warning window.</summary>
    NearExpiry
}

/// <summary>Validated certificate handle and metadata for one outbound channel.</summary>
public sealed class ResolvedClientCertificate : IDisposable
{
    internal ResolvedClientCertificate(X509Certificate2 certificate, ClientCertificateHealth health, string fingerprintSha256, string version, long catalogRevision)
    {
        Certificate = certificate;
        Health = health;
        FingerprintSha256 = fingerprintSha256;
        Version = version;
        CatalogRevision = catalogRevision;
    }

    /// <summary>Ephemeral provider-backed certificate handle; never serialize or return it to a client.</summary>
    public X509Certificate2 Certificate { get; }
    /// <summary>Public health state.</summary>
    public ClientCertificateHealth Health { get; }
    /// <summary>Approved public fingerprint.</summary>
    public string FingerprintSha256 { get; }
    /// <summary>Provider resource version.</summary>
    public string Version { get; }
    /// <summary>Approved catalog revision used for the channel.</summary>
    public long CatalogRevision { get; }

    /// <inheritdoc />
    public void Dispose() => Certificate.Dispose();
}

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
    string SubjectPublicKeyInfoSha256,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string KeyAlgorithm,
    int PublicKeySize,
    string Version);

/// <summary>
/// Server-owned resolution result. ProviderReference is produced only by the protected resolver;
/// it is never an input to a connector-facing signing or mTLS operation.
/// </summary>
public sealed record BoundAuthenticationResource(
    string LogicalBindingId,
    AuthenticationResourcePurpose Purpose,
    AuthenticationResourceStatus Status,
    Guid ConnectorVersionId,
    string ConnectorId,
    string OperationId,
    string ProfileId,
    long PolicyRevision,
    string PolicyChecksumSha256,
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

/// <summary>Server-owned source for approved authentication policies.</summary>
public interface IAuthenticationPolicySource
{
    /// <summary>Resolves the approved RS256 policy for one Published operation.</summary>
    Task<ServerOwnedRs256PolicySnapshot> ResolveRs256Async(
        AuthenticationExecutionContext context,
        string policyId,
        CancellationToken cancellationToken);

    /// <summary>Resolves the approved outbound mTLS policy for one Published operation.</summary>
    Task<ServerOwnedMutualTlsPolicySnapshot> ResolveMutualTlsAsync(
        AuthenticationExecutionContext context,
        string policyId,
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
    /// <summary>Use a fixed value compiled into the approved policy.</summary>
    Fixed
}

/// <summary>Immutable server-owned RS256 policy snapshot for an exact Published operation.</summary>
public sealed class ServerOwnedRs256PolicySnapshot
{
    private ServerOwnedRs256PolicySnapshot(
        string policyId,
        long policyRevision,
        Guid connectorVersionId,
        string connectorId,
        string operationId,
        Guid environmentId,
        Uri endpoint,
        string issuer,
        string audience,
        JwtSubjectPolicy subjectPolicy,
        string? fixedSubject,
        IReadOnlySet<string> allowedClaims,
        TimeSpan lifetime,
        TimeSpan allowedClockSkew,
        string logicalKeyBindingId,
        string resourceVersion,
        long catalogRevision,
        string catalogChecksumSha256,
        int minimumRsaKeySize)
    {
        PolicyId = policyId;
        PolicyRevision = policyRevision;
        ConnectorVersionId = connectorVersionId;
        ConnectorId = connectorId;
        OperationId = operationId;
        EnvironmentId = environmentId;
        Endpoint = endpoint;
        Issuer = issuer;
        Audience = audience;
        SubjectPolicy = subjectPolicy;
        FixedSubject = fixedSubject;
        AllowedClaims = new HashSet<string>(allowedClaims, StringComparer.Ordinal);
        Lifetime = lifetime;
        AllowedClockSkew = allowedClockSkew;
        LogicalKeyBindingId = logicalKeyBindingId;
        ResourceVersion = resourceVersion;
        CatalogRevision = catalogRevision;
        CatalogChecksumSha256 = catalogChecksumSha256;
        MinimumRsaKeySize = minimumRsaKeySize;
        PolicyChecksumSha256 = AuthenticationPolicyDigest.Rs256(this);
    }

    /// <summary>Creates a policy snapshot for use by the protected server-side policy catalogue.</summary>
    public static ServerOwnedRs256PolicySnapshot Create(
        string policyId,
        long policyRevision,
        Guid connectorVersionId,
        string connectorId,
        string operationId,
        Guid environmentId,
        Uri endpoint,
        string issuer,
        string audience,
        JwtSubjectPolicy subjectPolicy,
        string? fixedSubject,
        IReadOnlySet<string> allowedClaims,
        TimeSpan lifetime,
        TimeSpan allowedClockSkew,
        string logicalKeyBindingId,
        string resourceVersion,
        long catalogRevision,
        string catalogChecksumSha256,
        int minimumRsaKeySize = 2048) => new(
            policyId, policyRevision, connectorVersionId, connectorId, operationId, environmentId, endpoint,
            issuer, audience, subjectPolicy, fixedSubject, allowedClaims, lifetime, allowedClockSkew,
            logicalKeyBindingId, resourceVersion, catalogRevision, catalogChecksumSha256, minimumRsaKeySize);

    /// <summary>Logical approved policy identifier.</summary>
    public string PolicyId { get; }
    /// <summary>Immutable policy revision.</summary>
    public long PolicyRevision { get; }
    /// <summary>Digest over all security-relevant policy fields.</summary>
    public string PolicyChecksumSha256 { get; }
    /// <summary>Published ConnectorVersion identity.</summary>
    public Guid ConnectorVersionId { get; }
    /// <summary>Connector identity.</summary>
    public string ConnectorId { get; }
    /// <summary>Invoked operation identity.</summary>
    public string OperationId { get; }
    /// <summary>Server-derived Environment identity.</summary>
    public Guid EnvironmentId { get; }
    /// <summary>Approved outbound endpoint.</summary>
    public Uri Endpoint { get; }
    /// <summary>Approved issuer.</summary>
    public string Issuer { get; }
    /// <summary>Approved audience.</summary>
    public string Audience { get; }
    /// <summary>Approved subject derivation.</summary>
    public JwtSubjectPolicy SubjectPolicy { get; }
    /// <summary>Approved fixed subject when applicable.</summary>
    public string? FixedSubject { get; }
    /// <summary>Approved business-claim names.</summary>
    public IReadOnlySet<string> AllowedClaims { get; }
    /// <summary>Approved token lifetime.</summary>
    public TimeSpan Lifetime { get; }
    /// <summary>Approved clock skew.</summary>
    public TimeSpan AllowedClockSkew { get; }
    /// <summary>Logical key binding resolved only by the runtime.</summary>
    public string LogicalKeyBindingId { get; }
    /// <summary>Exact approved resource revision.</summary>
    public string ResourceVersion { get; }
    /// <summary>Exact approved resource-catalog revision.</summary>
    public long CatalogRevision { get; }
    /// <summary>Exact approved resource-catalog checksum.</summary>
    public string CatalogChecksumSha256 { get; }
    /// <summary>Minimum accepted RSA strength.</summary>
    public int MinimumRsaKeySize { get; }
}

/// <summary>Immutable server-owned mTLS policy snapshot for an exact Published operation.</summary>
public sealed class ServerOwnedMutualTlsPolicySnapshot
{
    private ServerOwnedMutualTlsPolicySnapshot(
        string policyId,
        long policyRevision,
        Guid connectorVersionId,
        string connectorId,
        string operationId,
        Guid environmentId,
        Uri endpoint,
        string httpMethod,
        string logicalCertificateBindingId,
        string resourceVersion,
        long catalogRevision,
        string catalogChecksumSha256,
        TimeSpan nearExpiryWarningWindow,
        TimeSpan timeout,
        long maximumResponseBytes,
        int minimumRsaKeySize,
        int minimumEcdsaKeySize)
    {
        PolicyId = policyId;
        PolicyRevision = policyRevision;
        ConnectorVersionId = connectorVersionId;
        ConnectorId = connectorId;
        OperationId = operationId;
        EnvironmentId = environmentId;
        Endpoint = endpoint;
        HttpMethod = httpMethod;
        LogicalCertificateBindingId = logicalCertificateBindingId;
        ResourceVersion = resourceVersion;
        CatalogRevision = catalogRevision;
        CatalogChecksumSha256 = catalogChecksumSha256;
        NearExpiryWarningWindow = nearExpiryWarningWindow;
        Timeout = timeout;
        MaximumResponseBytes = maximumResponseBytes;
        MinimumRsaKeySize = minimumRsaKeySize;
        MinimumEcdsaKeySize = minimumEcdsaKeySize;
        PolicyChecksumSha256 = AuthenticationPolicyDigest.MutualTls(this);
    }

    /// <summary>Creates a policy snapshot for use by the protected server-side policy catalogue.</summary>
    public static ServerOwnedMutualTlsPolicySnapshot Create(
        string policyId,
        long policyRevision,
        Guid connectorVersionId,
        string connectorId,
        string operationId,
        Guid environmentId,
        Uri endpoint,
        string httpMethod,
        string logicalCertificateBindingId,
        string resourceVersion,
        long catalogRevision,
        string catalogChecksumSha256,
        TimeSpan nearExpiryWarningWindow,
        TimeSpan timeout,
        long maximumResponseBytes,
        int minimumRsaKeySize = 2048,
        int minimumEcdsaKeySize = 256) => new(
            policyId, policyRevision, connectorVersionId, connectorId, operationId, environmentId, endpoint,
            httpMethod, logicalCertificateBindingId, resourceVersion, catalogRevision, catalogChecksumSha256,
            nearExpiryWarningWindow, timeout, maximumResponseBytes, minimumRsaKeySize, minimumEcdsaKeySize);

    /// <summary>Logical approved policy identifier.</summary>
    public string PolicyId { get; }
    /// <summary>Immutable policy revision.</summary>
    public long PolicyRevision { get; }
    /// <summary>Digest over all security-relevant policy fields.</summary>
    public string PolicyChecksumSha256 { get; }
    /// <summary>Published ConnectorVersion identity.</summary>
    public Guid ConnectorVersionId { get; }
    /// <summary>Connector identity.</summary>
    public string ConnectorId { get; }
    /// <summary>Invoked operation identity.</summary>
    public string OperationId { get; }
    /// <summary>Server-derived Environment identity.</summary>
    public Guid EnvironmentId { get; }
    /// <summary>Approved outbound endpoint.</summary>
    public Uri Endpoint { get; }
    /// <summary>Approved outbound HTTP method.</summary>
    public string HttpMethod { get; }
    /// <summary>Logical certificate binding resolved only by the runtime.</summary>
    public string LogicalCertificateBindingId { get; }
    /// <summary>Exact approved resource revision.</summary>
    public string ResourceVersion { get; }
    /// <summary>Exact approved resource-catalog revision.</summary>
    public long CatalogRevision { get; }
    /// <summary>Exact approved resource-catalog checksum.</summary>
    public string CatalogChecksumSha256 { get; }
    /// <summary>Non-blocking warning window.</summary>
    public TimeSpan NearExpiryWarningWindow { get; }
    /// <summary>Server-owned dispatch timeout.</summary>
    public TimeSpan Timeout { get; }
    /// <summary>Server-owned maximum response size.</summary>
    public long MaximumResponseBytes { get; }
    /// <summary>Minimum accepted RSA strength.</summary>
    public int MinimumRsaKeySize { get; }
    /// <summary>Minimum accepted ECDSA strength.</summary>
    public int MinimumEcdsaKeySize { get; }
}

/// <summary>One profile-allowlisted business claim.</summary>
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

/// <summary>Non-blocking public health classification for a valid mTLS certificate.</summary>
public enum ClientCertificateHealth
{
    /// <summary>Valid outside the configured warning window.</summary>
    Healthy,
    /// <summary>Valid but inside the configured warning window.</summary>
    NearExpiry
}

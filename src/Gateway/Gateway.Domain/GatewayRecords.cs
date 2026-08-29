namespace SecureIntegration.Gateway.Domain;

/// <summary>Lifecycle state of a Tenant.</summary>
public enum TenantStatus
{
    /// <summary>Tenant may use the service.</summary>
    Active,
    /// <summary>Tenant access is temporarily denied.</summary>
    Suspended,
    /// <summary>Tenant is permanently out of service.</summary>
    Retired
}

/// <summary>Lifecycle state of an Application.</summary>
public enum ApplicationStatus
{
    /// <summary>Application may be provisioned.</summary>
    Active,
    /// <summary>Application provisioning is suspended.</summary>
    Suspended,
    /// <summary>Application is permanently retired.</summary>
    Retired
}

/// <summary>Lifecycle state of an Installation.</summary>
public enum InstallationStatus
{
    /// <summary>Installation is awaiting enrollment.</summary>
    Pending,
    /// <summary>Installation may authenticate.</summary>
    Active,
    /// <summary>Installation is temporarily disabled.</summary>
    Suspended,
    /// <summary>Installation trust was revoked.</summary>
    Revoked,
    /// <summary>Installation was permanently retired.</summary>
    Retired
}

/// <summary>Origin of a machine identity authenticated by the Gateway.</summary>
public enum InstallationKind
{
    /// <summary>A Local Broker installed as a Windows Service.</summary>
    Broker,
    /// <summary>An authorized application that authenticates directly to the Gateway.</summary>
    Direct
}

/// <summary>Lifecycle state of an Installation credential.</summary>
public enum CredentialStatus
{
    /// <summary>Credential is not active yet.</summary>
    Pending,
    /// <summary>Credential is the current credential.</summary>
    Active,
    /// <summary>Credential remains valid during controlled renewal overlap.</summary>
    Overlap,
    /// <summary>Credential was explicitly revoked.</summary>
    Revoked,
    /// <summary>Credential has expired.</summary>
    Expired
}

/// <summary>A customer security boundary.</summary>
public sealed record TenantRecord(Guid Id, string Code, string DisplayName, TenantStatus Status, DateTimeOffset CreatedAt, long RowVersion = 1);

/// <summary>A product authorized to own Installations.</summary>
public sealed record ApplicationRecord(Guid Id, string Code, string DisplayName, ApplicationStatus Status, string MinimumBrokerVersion, string? MaximumBrokerVersion, DateTimeOffset CreatedAt, long RowVersion = 1);

/// <summary>An isolated deployment environment.</summary>
public sealed record GatewayEnvironmentRecord(Guid Id, string Code, string DisplayName, bool ProductionControls);

/// <summary>One machine identity bound immutably to Tenant/Application/Environment.</summary>
public sealed record InstallationRecord(
    Guid Id,
    Guid TenantId,
    Guid ApplicationId,
    Guid EnvironmentId,
    InstallationStatus Status,
    string? BrokerVersion,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastSeenAt = null,
    DateTimeOffset? RevokedAt = null,
    string? RevocationReason = null,
    InstallationKind InstallationKind = InstallationKind.Broker,
    string? ClientVersion = null,
    DateTimeOffset? UpdatedAt = null,
    InstallationCredentialPublicMetadata? Credential = null);

/// <summary>Public credential metadata safe for administrative display.</summary>
public sealed record InstallationCredentialPublicMetadata(
    Guid CredentialId,
    CredentialStatus Status,
    string CertificateSha256,
    string SpkiSha256,
    string SerialNumber,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter);

/// <summary>A registered ClientAuth credential. Certificate bytes contain public material only.</summary>
public sealed record InstallationCredentialRecord(
    Guid Id,
    Guid InstallationId,
    byte[] CertificateSha256,
    byte[] SpkiSha256,
    byte[] CertificateDer,
    string SerialNumber,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    CredentialStatus Status,
    DateTimeOffset CreatedAt,
    Guid? ReplacedById = null,
    DateTimeOffset? RevokedAt = null);

/// <summary>One-time activation material stored only as an HMAC.</summary>
public sealed record ActivationCodeRecord(
    Guid Id,
    Guid InstallationId,
    byte[] CodeHmac,
    DateTimeOffset ExpiresAt,
    DateTimeOffset CreatedAt,
    string CreatedBy,
    short AttemptCount = 0,
    DateTimeOffset? UsedAt = null);

/// <summary>Server-side operation grant scoped to the authenticated Installation and Tenant.</summary>
public sealed record InstallationGrantRecord(
    Guid Id,
    Guid InstallationId,
    Guid TenantId,
    string ConnectorId,
    string OperationId,
    bool Enabled,
    DateTimeOffset ValidFrom,
    DateTimeOffset? ValidUntil = null);

/// <summary>Identity derived from a registered credential; never from request fields.</summary>
public sealed record RegisteredInstallationIdentity(
    Guid InstallationId,
    Guid TenantId,
    Guid ApplicationId,
    Guid EnvironmentId,
    TenantStatus TenantStatus,
    ApplicationStatus ApplicationStatus,
    InstallationStatus InstallationStatus,
    Guid CredentialId,
    CredentialStatus CredentialStatus,
    byte[] CertificateDer,
    DateTimeOffset CredentialNotBefore,
    DateTimeOffset CredentialNotAfter,
    string MinimumBrokerVersion,
    string? MaximumBrokerVersion,
    InstallationKind InstallationKind = InstallationKind.Broker,
    string? ClientVersion = null);

/// <summary>Closed phase for one metadata-only external failure.</summary>
[System.Text.Json.Serialization.JsonConverter(typeof(System.Text.Json.Serialization.JsonStringEnumConverter<GatewayAuditFailurePhase>))]
public enum GatewayAuditFailurePhase
{
    /// <summary>No usable address was resolved.</summary>
    [System.Text.Json.Serialization.JsonStringEnumMemberName("DNS_FAILURE")]
    DnsFailure,
    /// <summary>No approved address accepted a connection.</summary>
    [System.Text.Json.Serialization.JsonStringEnumMemberName("TCP_CONNECT_FAILURE")]
    TcpConnectFailure,
    /// <summary>The upstream server certificate was not accepted.</summary>
    [System.Text.Json.Serialization.JsonStringEnumMemberName("TLS_SERVER_VALIDATION_FAILURE")]
    TlsServerValidationFailure,
    /// <summary>Mutual-TLS client authentication did not complete.</summary>
    [System.Text.Json.Serialization.JsonStringEnumMemberName("MTLS_CLIENT_AUTH_FAILURE")]
    MutualTlsClientAuthenticationFailure,
    /// <summary>The bounded operation deadline elapsed.</summary>
    [System.Text.Json.Serialization.JsonStringEnumMemberName("TIMEOUT")]
    Timeout,
    /// <summary>A different transport failure occurred.</summary>
    [System.Text.Json.Serialization.JsonStringEnumMemberName("TRANSPORT_FAILURE_OTHER")]
    TransportFailureOther,
    /// <summary>A bounded upstream HTTP response was received.</summary>
    [System.Text.Json.Serialization.JsonStringEnumMemberName("UPSTREAM_HTTP_RESPONSE")]
    UpstreamHttpResponse,
    /// <summary>A received upstream response could not be mapped locally.</summary>
    [System.Text.Json.Serialization.JsonStringEnumMemberName("LOCAL_RESPONSE_MAPPING_FAILURE")]
    LocalResponseMappingFailure
}

/// <summary>Closed HTTP category that does not expose an upstream reason phrase.</summary>
[System.Text.Json.Serialization.JsonConverter(typeof(System.Text.Json.Serialization.JsonStringEnumConverter<GatewayAuditStatusCategory>))]
public enum GatewayAuditStatusCategory
{
    /// <summary>No upstream HTTP response was received.</summary>
    [System.Text.Json.Serialization.JsonStringEnumMemberName("NO_UPSTREAM_RESPONSE")]
    NoUpstreamResponse,
    /// <summary>HTTP 1xx.</summary>
    [System.Text.Json.Serialization.JsonStringEnumMemberName("INFORMATIONAL")]
    Informational,
    /// <summary>HTTP 2xx.</summary>
    [System.Text.Json.Serialization.JsonStringEnumMemberName("SUCCESS")]
    Success,
    /// <summary>HTTP 3xx.</summary>
    [System.Text.Json.Serialization.JsonStringEnumMemberName("REDIRECTION")]
    Redirection,
    /// <summary>HTTP 4xx.</summary>
    [System.Text.Json.Serialization.JsonStringEnumMemberName("CLIENT_ERROR")]
    ClientError,
    /// <summary>HTTP 5xx.</summary>
    [System.Text.Json.Serialization.JsonStringEnumMemberName("SERVER_ERROR")]
    ServerError
}

/// <summary>Closed metadata-only external failure diagnostics persisted with one audit event.</summary>
public sealed class GatewayAuditFailureDiagnostics
{
    private GatewayAuditFailureDiagnostics(
        GatewayAuditFailurePhase failurePhase,
        int? upstreamStatus,
        GatewayAuditStatusCategory statusCategory,
        string? safeUpstreamCode,
        string? localSafeCode)
    {
        if (!Enum.IsDefined(failurePhase)) throw new ArgumentOutOfRangeException(nameof(failurePhase));
        if (!Enum.IsDefined(statusCategory)) throw new ArgumentOutOfRangeException(nameof(statusCategory));
        if (upstreamStatus is not null && upstreamStatus is < 100 or > 599)
            throw new ArgumentOutOfRangeException(nameof(upstreamStatus));
        if (statusCategory != Category(upstreamStatus))
            throw new ArgumentException("Audit status category does not match the bounded upstream status.", nameof(statusCategory));
        if (!IsSafeCode(safeUpstreamCode)) throw new ArgumentException("Safe upstream code is invalid.", nameof(safeUpstreamCode));
        if (!IsSafeCode(localSafeCode)) throw new ArgumentException("Local safe code is invalid.", nameof(localSafeCode));

        bool transport = failurePhase is GatewayAuditFailurePhase.DnsFailure or
            GatewayAuditFailurePhase.TcpConnectFailure or GatewayAuditFailurePhase.TlsServerValidationFailure or
            GatewayAuditFailurePhase.MutualTlsClientAuthenticationFailure or GatewayAuditFailurePhase.Timeout or
            GatewayAuditFailurePhase.TransportFailureOther;
        if (transport && (upstreamStatus is not null || safeUpstreamCode is not null || localSafeCode is not null))
            throw new ArgumentException("Transport diagnostics cannot contain upstream or local response fields.");
        if (!transport && upstreamStatus is null)
            throw new ArgumentException("Response diagnostics require a bounded upstream status.", nameof(upstreamStatus));
        if (failurePhase == GatewayAuditFailurePhase.UpstreamHttpResponse && localSafeCode is not null)
            throw new ArgumentException("Upstream HTTP diagnostics cannot contain a local safe code.", nameof(localSafeCode));
        if (failurePhase == GatewayAuditFailurePhase.LocalResponseMappingFailure && localSafeCode is null)
            throw new ArgumentException("Local response mapping diagnostics require a local safe code.", nameof(localSafeCode));

        FailurePhase = failurePhase;
        UpstreamStatus = upstreamStatus;
        StatusCategory = statusCategory;
        SafeUpstreamCode = safeUpstreamCode;
        LocalSafeCode = localSafeCode;
    }

    /// <summary>Closed failure phase.</summary>
    public GatewayAuditFailurePhase FailurePhase { get; }
    /// <summary>Bounded HTTP status, or null when no response arrived.</summary>
    public int? UpstreamStatus { get; }
    /// <summary>Closed category derived only from the bounded status.</summary>
    public GatewayAuditStatusCategory StatusCategory { get; }
    /// <summary>Optional code selected by the vertical's frozen upstream allowlist.</summary>
    public string? SafeUpstreamCode { get; }
    /// <summary>Optional code selected by the vertical's frozen local allowlist.</summary>
    public string? LocalSafeCode { get; }

    /// <summary>Creates one validated closed diagnostics value, including persistence read-back.</summary>
    public static GatewayAuditFailureDiagnostics Create(
        GatewayAuditFailurePhase failurePhase,
        int? upstreamStatus,
        GatewayAuditStatusCategory statusCategory,
        string? safeUpstreamCode,
        string? localSafeCode) =>
        new(failurePhase, upstreamStatus, statusCategory, safeUpstreamCode, localSafeCode);

    /// <summary>Derives the closed category from a bounded HTTP status.</summary>
    public static GatewayAuditStatusCategory Category(int? statusCode) => statusCode switch
    {
        null => GatewayAuditStatusCategory.NoUpstreamResponse,
        >= 100 and <= 199 => GatewayAuditStatusCategory.Informational,
        >= 200 and <= 299 => GatewayAuditStatusCategory.Success,
        >= 300 and <= 399 => GatewayAuditStatusCategory.Redirection,
        >= 400 and <= 499 => GatewayAuditStatusCategory.ClientError,
        >= 500 and <= 599 => GatewayAuditStatusCategory.ServerError,
        _ => throw new ArgumentOutOfRangeException(nameof(statusCode))
    };

    private static bool IsSafeCode(string? value) => value is null ||
        value is { Length: >= 1 and <= 96 } &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
}

/// <summary>Metadata-only audit event.</summary>
public sealed record GatewayAuditEvent(
    Guid Id,
    DateTimeOffset OccurredAt,
    Guid? TenantId,
    string ActorType,
    string ActorId,
    string Action,
    string TargetType,
    string TargetId,
    Guid CorrelationId,
    string Outcome,
    string ReasonCode,
    IReadOnlyDictionary<string, string> Metadata,
    GatewayAuditFailureDiagnostics? FailureDiagnostics = null);

/// <summary>Lifecycle state of one immutable Connector definition version.</summary>
public enum ConnectorVersionState
{
    /// <summary>The definition can still be replaced by its author.</summary>
    Draft,
    /// <summary>The definition passed schema and semantic validation.</summary>
    Validated,
    /// <summary>The definition is the only version eligible for runtime use.</summary>
    Published,
    /// <summary>The definition was published previously and may be used as a rollback target.</summary>
    Superseded,
    /// <summary>The definition is permanently unavailable to runtime and rollback.</summary>
    Retired
}

/// <summary>Immutable JSON and lifecycle metadata for one Connector version.</summary>
public sealed record ConnectorVersionRecord(
    Guid Id,
    Guid ConnectorId,
    string ConnectorSlug,
    string Version,
    string SchemaVersion,
    ConnectorVersionState State,
    string CanonicalJson,
    byte[] ChecksumSha256,
    string CreatedBy,
    DateTimeOffset CreatedAt,
    long RowVersion,
    DateTimeOffset? ValidatedAt = null,
    DateTimeOffset? PublishedAt = null,
    DateTimeOffset? RetiredAt = null);

/// <summary>Lifecycle of one immutable, server-owned Connector binding bundle revision.</summary>
public enum ConnectorBindingState
{
    /// <summary>Awaiting checksum-bound four-eyes approval and publication.</summary>
    Draft,
    /// <summary>Referenced by an approved Published Connector version.</summary>
    Active,
    /// <summary>Permanently unavailable for new runtime resolution.</summary>
    Retired
}

/// <summary>Kind of provider-owned material referenced by a Connector binding.</summary>
public enum ProviderResourceType
{
    /// <summary>A secret value retrieved only by the Gateway runtime.</summary>
    Secret,
    /// <summary>A client certificate whose private key remains provider-owned.</summary>
    ClientCertificate
}

/// <summary>Lifecycle of one server-owned provider resource catalog revision.</summary>
public enum ProviderResourceStatus
{
    /// <summary>The catalog revision may be selected by a new binding.</summary>
    Active,
    /// <summary>The catalog revision is unavailable for new approvals and runtime resolution.</summary>
    Disabled
}

/// <summary>Structured logical reference accepted at the Connector administration boundary.</summary>
public sealed record ProviderResourceReference(
    string ProviderId,
    string ResourceId,
    ProviderResourceType ResourceType,
    string? Version = null,
    long? PublicMetadataRevision = null);

/// <summary>Public certificate metadata safe to show to an approver.</summary>
public sealed record CertificatePublicMetadata(
    string FingerprintSha256,
    string Subject,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string KeyAlgorithm,
    int PublicKeySize,
    string Version,
    string? SubjectPublicKeyInfoSha256 = null,
    string? SubjectCommonName = null);

/// <summary>Immutable server-owned provider catalog revision. ProviderReference is internal and never returned by Admin APIs.</summary>
public sealed record ProviderResourceCatalogRecord(
    Guid Id,
    string ProviderId,
    string ProviderDisplayName,
    string ProviderType,
    string ResourceId,
    ProviderResourceType ResourceType,
    string DisplayName,
    Guid EnvironmentId,
    string ConnectorScope,
    string OperationScope,
    string ProviderReference,
    ProviderResourceStatus Status,
    string? Version,
    long Revision,
    long? PublicMetadataRevision,
    CertificatePublicMetadata? CertificateMetadata,
    string ChecksumSha256,
    DateTimeOffset CreatedAt);

/// <summary>Non-secret immutable catalog snapshot stored in a Connector binding revision.</summary>
public sealed record ProviderResourceBinding(
    string ProviderId,
    string ProviderDisplayName,
    string ProviderType,
    string ResourceId,
    ProviderResourceType ResourceType,
    string DisplayName,
    Guid EnvironmentId,
    string ConnectorScope,
    string OperationScope,
    string? Version,
    long CatalogRevision,
    long? PublicMetadataRevision,
    CertificatePublicMetadata? CertificateMetadata,
    string CatalogChecksumSha256);

/// <summary>Server-owned immutable endpoint, secret and certificate binding revisions in one Environment.</summary>
public sealed record ConnectorBindingSet(
    Guid Id,
    Guid ConnectorId,
    Guid ConnectorVersionId,
    Guid EnvironmentId,
    IReadOnlyDictionary<string, Uri> Endpoints,
    IReadOnlyDictionary<string, ProviderResourceBinding> SecretResources,
    IReadOnlyDictionary<string, ProviderResourceBinding> CertificateResources,
    long Revision,
    string ChecksumSha256,
    ConnectorBindingState State,
    DateTimeOffset UpdatedAt,
    string UpdatedBy);

/// <summary>Authenticated scope required to resolve protected provider locators at runtime.</summary>
public sealed record PublishedConnectorAccessContext(Guid InstallationId, Guid TenantId, Guid ApplicationId, string OperationId);

/// <summary>Small stamp checked before a cached runtime definition may be reused.</summary>
public sealed record PublishedConnectorStamp(
    Guid VersionId,
    long PublicationRevision,
    long BindingRevision,
    string BindingChecksumSha256,
    string ResourceStampSha256);

/// <summary>Published immutable definition and its server-side Environment bindings.</summary>
public sealed record PublishedConnectorSnapshot(
    ConnectorVersionRecord Version,
    ConnectorBindingSet Bindings,
    PublishedConnectorStamp Stamp,
    IReadOnlyDictionary<string, string> SecretProviderReferences,
    IReadOnlyDictionary<string, string> CertificateProviderReferences);

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
public sealed record TenantRecord(Guid Id, string Code, string DisplayName, TenantStatus Status, DateTimeOffset CreatedAt);

/// <summary>A product authorized to own Installations.</summary>
public sealed record ApplicationRecord(Guid Id, string Code, string DisplayName, ApplicationStatus Status, string MinimumBrokerVersion, string? MaximumBrokerVersion, DateTimeOffset CreatedAt);

/// <summary>An isolated deployment environment.</summary>
public sealed record GatewayEnvironmentRecord(Guid Id, string Code, string DisplayName, bool ProductionControls);

/// <summary>One installed Broker identity bound immutably to Tenant/Application/Environment.</summary>
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
    string? RevocationReason = null);

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
    string? MaximumBrokerVersion);

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
    IReadOnlyDictionary<string, string> Metadata);

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

/// <summary>Server-owned immutable endpoint, secret and certificate binding revisions in one Environment.</summary>
public sealed record ConnectorBindingSet(
    Guid Id,
    Guid ConnectorId,
    Guid ConnectorVersionId,
    Guid EnvironmentId,
    IReadOnlyDictionary<string, Uri> Endpoints,
    IReadOnlyDictionary<string, string> SecretReferences,
    IReadOnlyDictionary<string, string> CertificateReferences,
    long Revision,
    string ChecksumSha256,
    ConnectorBindingState State,
    DateTimeOffset UpdatedAt,
    string UpdatedBy);

/// <summary>Small stamp checked before a cached runtime definition may be reused.</summary>
public sealed record PublishedConnectorStamp(Guid VersionId, long PublicationRevision, long BindingRevision, string BindingChecksumSha256);

/// <summary>Published immutable definition and its server-side Environment bindings.</summary>
public sealed record PublishedConnectorSnapshot(ConnectorVersionRecord Version, ConnectorBindingSet Bindings, PublishedConnectorStamp Stamp);

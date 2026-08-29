using System.Text.Json.Serialization;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Api;

/// <summary>Development-only selection of one fixed synthetic user.</summary>
public sealed record DevelopmentLoginRequest(string UserName);

/// <summary>Creates a tenant without accepting security-sensitive configuration.</summary>
public sealed record CreateTenantRequest(string Code, string DisplayName);
/// <summary>Updates mutable Tenant display metadata.</summary>
public sealed record UpdateTenantRequest(string DisplayName);

/// <summary>Creates an application and its Broker compatibility bounds.</summary>
public sealed record CreateApplicationRequest(string Code, string DisplayName, string MinimumBrokerVersion, string? MaximumBrokerVersion);
/// <summary>Updates mutable Application display and Broker compatibility metadata.</summary>
public sealed record UpdateApplicationRequest(string DisplayName, string MinimumBrokerVersion, string? MaximumBrokerVersion);

/// <summary>Creates a pending installation under existing server-side resources.</summary>
public sealed record CreateInstallationRequest(Guid TenantId, Guid ApplicationId, Guid EnvironmentId, SecureIntegration.Gateway.Domain.InstallationKind InstallationKind = SecureIntegration.Gateway.Domain.InstallationKind.Broker);

/// <summary>Immediately revokes an installation.</summary>
public sealed record RevokeInstallationRequest(string Reason);

/// <summary>Creates one deny-by-default operation grant.</summary>
public sealed record CreateGrantRequest(Guid TenantId, Guid InstallationId, string ConnectorId, string OperationId, DateTimeOffset? ValidUntil);

/// <summary>Explicit closed failure diagnostics. No generic metadata or upstream content is present.</summary>
public sealed record SafeFailureDiagnosticsResource(
    GatewayAuditFailurePhase FailurePhase,
    int? UpstreamStatus,
    GatewayAuditStatusCategory StatusCategory,
    string? SafeUpstreamCode,
    string? LocalSafeCode);

/// <summary>Redacted audit projection. Bounded failure diagnostics are omitted unless server-side RBAC authorizes them.</summary>
public sealed record AdminAuditEventResource(
    Guid Id,
    DateTimeOffset OccurredAt,
    string Action,
    string TargetType,
    string TargetId,
    Guid CorrelationId,
    string Outcome,
    string ReasonCode,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] SafeFailureDiagnosticsResource? FailureDiagnostics);

/// <summary>Redacted approval resource with canonical hexadecimal digests.</summary>
public sealed record ConnectorApprovalResource(Guid Id, Guid ConnectorVersionId, string ChecksumSha256, string BindingDigestSha256, Guid RequestedBy, Guid? ApprovedBy, Guid? RejectedBy, string Status, DateTimeOffset RequestedAt);

/// <summary>Safe logical provider resource metadata exposed to Connector administrators.</summary>
public sealed record ProviderResourceBindingResource(string ProviderId, string ResourceId, string ResourceType, string DisplayName, string? Version, long CatalogRevision, long? PublicMetadataRevision, string CatalogChecksumSha256);

/// <summary>Read-only provider resource catalog projection; physical provider references and values are absent.</summary>
public sealed record ProviderResourceCatalogResource(Guid Id, string ProviderId, string ProviderDisplayName, string ProviderType, string ResourceId, string ResourceType, string DisplayName, Guid EnvironmentId, string ConnectorScope, string OperationScope, string Status, string? Version, long Revision, long? PublicMetadataRevision, SecureIntegration.Gateway.Domain.CertificatePublicMetadata? CertificateMetadata, string ChecksumSha256);

/// <summary>Binding approval resource exposing logical catalog identities and one-way component checksums, never physical provider references.</summary>
public sealed record ConnectorBindingResource(Guid Id, Guid ConnectorId, Guid ConnectorVersionId, Guid EnvironmentId,
    IReadOnlyDictionary<string, string> Endpoints, IReadOnlyDictionary<string, ProviderResourceBindingResource> SecretResources, IReadOnlyDictionary<string, ProviderResourceBindingResource> CertificateResources,
    string EndpointChecksumSha256, string SecretChecksumSha256, string CertificateChecksumSha256,
    long Revision, string ChecksumSha256, string State, DateTimeOffset UpdatedAt, string UpdatedBy);

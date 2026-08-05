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
public sealed record CreateInstallationRequest(Guid TenantId, Guid ApplicationId, Guid EnvironmentId);

/// <summary>Immediately revokes an installation.</summary>
public sealed record RevokeInstallationRequest(string Reason);

/// <summary>Creates one deny-by-default operation grant.</summary>
public sealed record CreateGrantRequest(Guid TenantId, Guid InstallationId, string ConnectorId, string OperationId, DateTimeOffset? ValidUntil);

/// <summary>Redacted approval resource with canonical hexadecimal digests.</summary>
public sealed record ConnectorApprovalResource(Guid Id, Guid ConnectorVersionId, string ChecksumSha256, string BindingDigestSha256, Guid RequestedBy, Guid? ApprovedBy, Guid? RejectedBy, string Status, DateTimeOffset RequestedAt);

/// <summary>Binding approval resource exposing logical names and one-way component checksums, never provider references.</summary>
public sealed record ConnectorBindingResource(Guid Id, Guid ConnectorId, Guid ConnectorVersionId, Guid EnvironmentId,
    IReadOnlyDictionary<string, string> Endpoints, IReadOnlyDictionary<string, string> SecretReferences, IReadOnlyDictionary<string, string> CertificateReferences,
    string EndpointChecksumSha256, string SecretChecksumSha256, string CertificateChecksumSha256,
    long Revision, string ChecksumSha256, string State, DateTimeOffset UpdatedAt, string UpdatedBy);

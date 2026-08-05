namespace SecureIntegration.Gateway.Api;

/// <summary>Development-only selection of one fixed synthetic user.</summary>
public sealed record DevelopmentLoginRequest(string UserName);

/// <summary>Creates a tenant without accepting security-sensitive configuration.</summary>
public sealed record CreateTenantRequest(string Code, string DisplayName);

/// <summary>Creates an application and its Broker compatibility bounds.</summary>
public sealed record CreateApplicationRequest(string Code, string DisplayName, string MinimumBrokerVersion, string? MaximumBrokerVersion);

/// <summary>Creates a pending installation under existing server-side resources.</summary>
public sealed record CreateInstallationRequest(Guid TenantId, Guid ApplicationId, Guid EnvironmentId);

/// <summary>Immediately revokes an installation.</summary>
public sealed record RevokeInstallationRequest(string Reason);

/// <summary>Creates one deny-by-default operation grant.</summary>
public sealed record CreateGrantRequest(Guid TenantId, Guid InstallationId, string ConnectorId, string OperationId, DateTimeOffset? ValidUntil);

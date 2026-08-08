using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Application;

/// <summary>Opaque proof that Core authorized one authenticated principal for one Connector operation.</summary>
public sealed class AuthorizedGatewayInvocation
{
    internal AuthorizedGatewayInvocation(GatewayClientPrincipal principal, string connectorId, string operationId)
    {
        Principal = principal;
        ConnectorId = connectorId;
        OperationId = operationId;
    }

    /// <summary>Authenticated server-derived principal.</summary>
    public GatewayClientPrincipal Principal { get; }
    /// <summary>Authorized Connector ID.</summary>
    public string ConnectorId { get; }
    /// <summary>Authorized operation ID.</summary>
    public string OperationId { get; }
}

/// <summary>Provider-neutral Core boundary that produces an opaque authorized invocation.</summary>
public interface IGatewayInvocationAuthorizer
{
    /// <summary>Checks current principal state and the exact operation grant.</summary>
    Task<AuthorizedGatewayInvocation> AuthorizeAsync(GatewayClientPrincipal principal, string connectorId, string operationId, CancellationToken cancellationToken);
}

/// <summary>Core implementation over the authenticated principal and Gateway grant registry.</summary>
public sealed class GatewayInvocationAuthorizer : IGatewayInvocationAuthorizer
{
    private readonly Func<Guid, Guid, string, string, DateTimeOffset, CancellationToken, Task<bool>> grants;
    private readonly IGatewayClock clock;

    /// <summary>Creates the Core authorizer used after inbound authentication.</summary>
    public GatewayInvocationAuthorizer(IGatewayRegistry registry, IGatewayClock clock)
        : this(registry.IsGrantedAsync, clock)
    {
    }

    internal GatewayInvocationAuthorizer(
        Func<Guid, Guid, string, string, DateTimeOffset, CancellationToken, Task<bool>> grants,
        IGatewayClock clock)
    {
        this.grants = grants;
        this.clock = clock;
    }

    /// <inheritdoc />
    public async Task<AuthorizedGatewayInvocation> AuthorizeAsync(GatewayClientPrincipal principal, string connectorId, string operationId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectorId);
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        RegisteredInstallationIdentity identity = principal.Identity;
        if (identity.TenantStatus is not TenantStatus.Active || identity.ApplicationStatus is not ApplicationStatus.Active ||
            identity.InstallationStatus is not InstallationStatus.Active ||
            identity.CredentialStatus is not (CredentialStatus.Active or CredentialStatus.Overlap) ||
            identity.CredentialNotBefore > clock.UtcNow || identity.CredentialNotAfter <= clock.UtcNow ||
            !await grants(identity.InstallationId, identity.TenantId, connectorId, operationId, clock.UtcNow, cancellationToken).ConfigureAwait(false))
            throw new GatewayException("BGW-AUTHZ-OPERATION-DENIED", 403);

        return new AuthorizedGatewayInvocation(principal, connectorId, operationId);
    }
}

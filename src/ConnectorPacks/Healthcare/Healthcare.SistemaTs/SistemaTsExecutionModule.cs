using System.Collections.Frozen;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.ConnectorPacks.Healthcare.SistemaTs;

/// <summary>Registers the compiled Sistema TS ePrescription strategy and typed session adapters.</summary>
public sealed class SistemaTsExecutionModule : IConnectorExecutionModule
{
    /// <summary>Exact deployment module identifier.</summary>
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("healthcare-sistema-ts");

    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar)
    {
        ArgumentNullException.ThrowIfNull(registrar);
        registrar.AddStrategy<SistemaTsExecutionStrategy>();
        registrar.AddTypedSessionHandshakeRequestAdapter<SistemaTsCreateSessionRequestAdapter>();
        registrar.AddTypedSessionHandshakeResponseAdapter<SistemaTsCreateSessionResponseAdapter>();
        registrar.AddExternalSessionValidationAdapter<SistemaTsCheckTokenAdapter>();
    }
}

/// <summary>Connector-first execution strategy for the frozen national Sistema TS contracts.</summary>
public sealed class SistemaTsExecutionStrategy : IConnectorExecutionStrategy
{
    private static readonly IReadOnlySet<GatewayAuthenticationKind> AuthenticationKinds =
        new[] { GatewayAuthenticationKind.Basic }
            .ToFrozenSet();

    /// <summary>Exact Published strategy selector.</summary>
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("healthcare-sistema-ts-eprescription");

    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => AuthenticationKinds;

    /// <inheritdoc />
    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(
        AuthorizedConnectorExecution execution,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        SistemaTsPublishedOperation published = SistemaTsPublishedOperation.Read(execution);
        if (published.OperationId == SistemaTsOperationCatalog.SessionCreate.OperationId)
        {
            RequireAuthentication(execution, GatewayAuthenticationKind.Basic);
            return await execution.Capabilities.ExecuteTypedSessionHandshakeAsync(cancellationToken).ConfigureAwait(false);
        }

        throw new InvalidOperationException(
            "Sistema TS business dispatch is unavailable until the qualified typed composed-body capability is present.");
    }

    private static void RequireAuthentication(AuthorizedConnectorExecution execution, GatewayAuthenticationKind expected)
    {
        if (execution.AuthenticationKind != expected)
            throw new InvalidOperationException("Sistema TS Published authentication kind is incompatible with the operation.");
    }
}

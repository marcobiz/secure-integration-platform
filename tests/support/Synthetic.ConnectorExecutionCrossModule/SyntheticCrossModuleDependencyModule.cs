using System.Collections.Frozen;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Synthetic.ConnectorExecutionDependencyModule;

namespace SecureIntegration.Synthetic.ConnectorExecutionCrossModule;

/// <summary>Startup-negative module whose strategy requests a service owned and registered by another module.</summary>
public sealed class SyntheticCrossModuleDependencyModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-cross-module");

    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar) =>
        registrar.AddStrategy<SyntheticCrossModuleDependencyStrategy>();
}

/// <summary>Invalid strategy constructor crossing the module assembly boundary.</summary>
public sealed class SyntheticCrossModuleDependencyStrategy(
    ISyntheticDependencyOwnerService dependency) : IConnectorExecutionStrategy
{
    private static readonly FrozenSet<GatewayAuthenticationKind> AuthenticationKinds =
        new[] { GatewayAuthenticationKind.None }.ToFrozenSet();

    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("invalid-cross-module");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => AuthenticationKinds;
    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        throw new InvalidOperationException(dependency.GetType().Name);
}

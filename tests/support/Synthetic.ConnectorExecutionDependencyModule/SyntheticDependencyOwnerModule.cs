using System.Collections.Frozen;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Synthetic.ConnectorExecutionDependencyModule;

/// <summary>Service contract owned exclusively by the synthetic dependency-owner module.</summary>
public interface ISyntheticDependencyOwnerService;

/// <summary>Module-owned service used to prove cross-module constructor injection is denied.</summary>
public sealed class SyntheticDependencyOwnerService : ISyntheticDependencyOwnerService;

/// <summary>Valid owner module that explicitly registers its own service and strategy.</summary>
public sealed class SyntheticDependencyOwnerModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-dependency-owner");

    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar)
    {
        registrar.AddSingleton<ISyntheticDependencyOwnerService, SyntheticDependencyOwnerService>();
        registrar.AddStrategy<SyntheticDependencyOwnerStrategy>();
    }
}

/// <summary>Valid module-owned strategy required by the startup module contract.</summary>
public sealed class SyntheticDependencyOwnerStrategy(ISyntheticDependencyOwnerService service) : IConnectorExecutionStrategy
{
    private static readonly FrozenSet<GatewayAuthenticationKind> AuthenticationKinds =
        new[] { GatewayAuthenticationKind.None }.ToFrozenSet();

    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-dependency-owner");

    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => AuthenticationKinds;

    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
    {
        _ = service;
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new QualifiedGatewayExecutionResult(200, "application/json", "{}"u8.ToArray()));
    }
}

using System.Collections.Frozen;
using System.Text.Json;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Synthetic.ConnectorExecutionModule;

/// <summary>Neutral external qualification module using only supported public execution contracts.</summary>
public sealed class SyntheticExecutionModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-execution");

    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar)
    {
        registrar.AddSingleton<SyntheticExecutionResultWriter>();
        registrar.AddStrategy<SyntheticEchoExecutionStrategy>();
        registrar.AddStrategy<SyntheticThrowingExecutionStrategy>();
        registrar.AddStrategy<SyntheticFakeCancellationExecutionStrategy>();
        registrar.AddStrategy<SyntheticForgedGatewayFailureStrategy>();
        registrar.AddStrategy<SyntheticCapabilityBridgeExecutionStrategy>();
        registrar.AddStrategy<SyntheticRetainedBridgeExecutionStrategy>();
    }
}

/// <summary>Qualification-only module that deliberately registers a duplicate key.</summary>
public sealed class SyntheticDuplicateExecutionModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-duplicate-execution");

    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar)
    {
        registrar.AddSingleton<SyntheticExecutionResultWriter>();
        registrar.AddStrategy<SyntheticEchoExecutionStrategy>();
        registrar.AddStrategy<DuplicateSyntheticEchoExecutionStrategy>();
    }
}

/// <summary>Echoes safe authorized context and the immutable payload snapshot.</summary>
public sealed class SyntheticEchoExecutionStrategy(SyntheticExecutionResultWriter writer) : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-echo");

    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;

    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        writer.WriteAsync(execution, cancellationToken);
}

/// <summary>Second type with the same key, used to prove deterministic startup rejection.</summary>
public sealed class DuplicateSyntheticEchoExecutionStrategy(SyntheticExecutionResultWriter writer) : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-echo");

    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;

    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        writer.WriteAsync(execution, cancellationToken);
}

/// <summary>Throws a diagnostic canary to qualify the generic extension failure boundary.</summary>
public sealed class SyntheticThrowingExecutionStrategy : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-throw");

    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;

    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("synthetic-extension-diagnostic-canary");
}

/// <summary>Throws cancellation from an unrelated token to prove it cannot spoof caller cancellation.</summary>
public sealed class SyntheticFakeCancellationExecutionStrategy : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-fake-cancel");

    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.OpaqueSessionHttp;

    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        throw new OperationCanceledException("synthetic-fake-cancellation-canary", new CancellationToken(canceled: true));
}

/// <summary>Attempts to forge a privileged Core error classification from an external strategy.</summary>
public sealed class SyntheticForgedGatewayFailureStrategy : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-forged-error");

    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;

    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-STALE", 503, true);
}

/// <summary>Delegates only the current authorized invocation to existing server-owned capabilities.</summary>
public sealed class SyntheticCapabilityBridgeExecutionStrategy : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-capability-bridge");

    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.CapabilityBridge;

    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        execution.OperationId switch
        {
            "session-bootstrap" => execution.Capabilities.ExecuteTypedSessionHandshakeAsync(cancellationToken),
            "session-business" => execution.Capabilities.ExecuteComposedSoapAsync(cancellationToken),
            _ => throw new InvalidOperationException("Synthetic capability bridge received an unsupported operation.")
        };
}

/// <summary>Retains one bridge to prove it cannot be replayed from a later invocation.</summary>
public sealed class SyntheticRetainedBridgeExecutionStrategy : IConnectorExecutionStrategy
{
    private IAuthorizedConnectorCapabilityBridge? retained;

    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-retained-bridge");

    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;

    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
    {
        if (string.Equals(execution.OperationId, "retain-bridge", StringComparison.Ordinal))
        {
            retained = execution.Capabilities;
            return Task.FromResult(new QualifiedGatewayExecutionResult(200, "application/json", "{}"u8.ToArray()));
        }
        return (retained ?? execution.Capabilities).ExecuteComposedSoapAsync(cancellationToken);
    }
}

/// <summary>Startup-negative module whose strategy requests the ambient service provider.</summary>
public sealed class SyntheticServiceProviderDependencyModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-service-provider");
    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar) =>
        registrar.AddStrategy<SyntheticServiceProviderDependencyStrategy>();
}

/// <summary>Startup-negative module whose strategy requests all other strategies.</summary>
public sealed class SyntheticStrategyCollectionDependencyModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-strategy-collection");
    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar) =>
        registrar.AddStrategy<SyntheticStrategyCollectionDependencyStrategy>();
}

/// <summary>Startup-negative module that hides a service-provider dependency one level down.</summary>
public sealed class SyntheticRecursiveDependencyModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-recursive-dependency");
    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar)
    {
        registrar.AddSingleton<SyntheticRecursiveDependency>();
        registrar.AddStrategy<SyntheticRecursiveDependencyStrategy>();
    }
}

/// <summary>Invalid strategy constructor used only by startup-denial evidence.</summary>
public sealed class SyntheticServiceProviderDependencyStrategy(IServiceProvider services) : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("invalid-service-provider");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;
    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        throw new InvalidOperationException(services.GetType().Name);
}

/// <summary>Invalid strategy-collection constructor used only by startup-denial evidence.</summary>
public sealed class SyntheticStrategyCollectionDependencyStrategy(
    IEnumerable<IConnectorExecutionStrategy> strategies) : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("invalid-strategy-collection");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;
    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        throw new InvalidOperationException(strategies.Count().ToString(System.Globalization.CultureInfo.InvariantCulture));
}

/// <summary>Invalid nested dependency requesting the ambient provider.</summary>
public sealed class SyntheticRecursiveDependency(IServiceProvider services)
{
    /// <inheritdoc />
    public override string ToString() => services.GetType().Name;
}

/// <summary>Strategy whose module-owned helper recursively reaches a forbidden host dependency.</summary>
public sealed class SyntheticRecursiveDependencyStrategy(
    SyntheticRecursiveDependency dependency) : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("invalid-recursive-dependency");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;
    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        throw new InvalidOperationException(dependency.ToString());
}

/// <summary>Startup-negative module containing an explicit module-owned constructor cycle.</summary>
public sealed class SyntheticConstructorCycleModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-constructor-cycle");

    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar)
    {
        registrar.AddSingleton<SyntheticCycleA>();
        registrar.AddSingleton<SyntheticCycleB>();
        registrar.AddStrategy<SyntheticConstructorCycleStrategy>();
    }
}

/// <summary>First node in the synthetic constructor cycle.</summary>
public sealed class SyntheticCycleA(SyntheticCycleB dependency)
{
    /// <inheritdoc />
    public override string ToString() => dependency.GetType().Name;
}

/// <summary>Second node in the synthetic constructor cycle.</summary>
public sealed class SyntheticCycleB(SyntheticCycleA dependency)
{
    /// <inheritdoc />
    public override string ToString() => dependency.GetType().Name;
}

/// <summary>Strategy reaching the explicit cycle through a module-owned service.</summary>
public sealed class SyntheticConstructorCycleStrategy(SyntheticCycleA dependency) : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("invalid-constructor-cycle");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;
    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        throw new InvalidOperationException(dependency.ToString());
}

/// <summary>Module-owned formatter resolved through constructor injection without a service locator.</summary>
public sealed class SyntheticExecutionResultWriter
{
    private readonly JsonSerializerOptions webJson = new(JsonSerializerDefaults.Web);

    /// <summary>Creates one bounded neutral qualification response.</summary>
    public async Task<QualifiedGatewayExecutionResult> WriteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
    {
        await using Stream payload = execution.OpenPayloadStream();
        byte[] body = new byte[execution.PayloadLength];
        await payload.ReadExactlyAsync(body, cancellationToken).ConfigureAwait(false);
        byte[] response = JsonSerializer.SerializeToUtf8Bytes(new
        {
            execution.TenantId,
            execution.ApplicationId,
            execution.InstallationId,
            execution.EnvironmentId,
            execution.ConnectorId,
            execution.ConnectorVersion,
            execution.OperationId,
            execution.CorrelationId,
            authenticationKind = execution.AuthenticationKind.ToString(),
            executionStrategyKey = execution.ExecutionStrategyKey.Value,
            execution.RequestContentType,
            payloadBase64 = Convert.ToBase64String(body)
        }, webJson);
        return new(200, "application/json", response);
    }
}

internal static class SyntheticAuthenticationKinds
{
    internal static readonly FrozenSet<GatewayAuthenticationKind> None =
        new[] { GatewayAuthenticationKind.None }.ToFrozenSet();
    internal static readonly FrozenSet<GatewayAuthenticationKind> OpaqueSessionHttp =
        new[] { GatewayAuthenticationKind.OpaqueSessionHttp }.ToFrozenSet();
    internal static readonly FrozenSet<GatewayAuthenticationKind> CapabilityBridge = new[]
    {
        GatewayAuthenticationKind.None,
        GatewayAuthenticationKind.Basic,
        GatewayAuthenticationKind.SoapBasicOpaqueSession
    }.ToFrozenSet();
}

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
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        writer.WriteAsync(execution, cancellationToken);
}

/// <summary>Second type with the same key, used to prove deterministic startup rejection.</summary>
public sealed class DuplicateSyntheticEchoExecutionStrategy(SyntheticExecutionResultWriter writer) : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-echo");

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
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("synthetic-extension-diagnostic-canary");
}

/// <summary>Throws cancellation from an unrelated token to prove it cannot spoof caller cancellation.</summary>
public sealed class SyntheticFakeCancellationExecutionStrategy : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-fake-cancel");

    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        throw new OperationCanceledException("synthetic-fake-cancellation-canary", new CancellationToken(canceled: true));
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

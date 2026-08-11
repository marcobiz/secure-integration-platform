using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Providers.Abstractions;

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
        registrar.AddStrategy<SyntheticSignedMutualTlsExecutionStrategy>();
        registrar.AddStrategy<SyntheticDualSlotExecutionStrategy>();
        registrar.AddStrategy<SyntheticUnknownSigningSlotExecutionStrategy>();
        registrar.AddStrategy<SyntheticRepeatedSigningSlotExecutionStrategy>();
        registrar.AddStrategy<SyntheticMissingRequiredSigningSlotExecutionStrategy>();
        registrar.AddStrategy<SyntheticDeniedSigningClaimExecutionStrategy>();
        registrar.AddStrategy<SyntheticRetainedSigningBridgeExecutionStrategy>();
        registrar.AddStrategy<SyntheticFireAndForgetSigningExecutionStrategy>();
        registrar.AddStrategy<SyntheticFireAndForgetRestrictedTransportExecutionStrategy>();
        registrar.AddTypedSessionHandshakeRequestAdapter<SyntheticExternalTypedSessionRequestAdapter>();
        registrar.AddTypedSessionHandshakeResponseAdapter<SyntheticExternalTypedSessionResponseAdapter>();
        registrar.AddExternalSessionValidationAdapter<SyntheticExternalSessionValidationAdapter>();
        registrar.AddTypedComposedSoapRequestAdapter<SyntheticExternalTypedComposedSoapRequestAdapter>();
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

/// <summary>Neutral proof strategy using only the invocation-bound signing and restricted-transport bridge.</summary>
public sealed class SyntheticSignedMutualTlsExecutionStrategy : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-signed-mtls");

    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.MutualTls;

    /// <inheritdoc />
    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
    {
        using Stream configuration = execution.OpenPublishedExtensionConfiguration().OpenJsonStream();
        using JsonDocument document = await JsonDocument.ParseAsync(configuration, cancellationToken: cancellationToken).ConfigureAwait(false);
        JsonElement root = document.RootElement;
        string claimName = root.GetProperty("claimName").GetString()!;
        JsonElement claimValue = root.GetProperty("claimValue").Clone();
        string bodyValue = root.GetProperty("body").GetString()!;
        AuthorizedConnectorSignedToken token = await execution.Capabilities.CreateSignedTokenAsync(
            new Dictionary<string, JsonElement>(StringComparer.Ordinal) { [claimName] = claimValue },
            cancellationToken).ConfigureAwait(false);
        return await execution.Capabilities.ExecuteRestrictedTransportAsync(
            new AuthorizedConnectorRestrictedTransportRequest(Encoding.UTF8.GetBytes(bodyValue), token),
            cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// Neutral external proof that requests two exact Published slots while Core owns both signing
/// policies and their outbound projections.
/// </summary>
public sealed class SyntheticDualSlotExecutionStrategy : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-dual-slot");

    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.MutualTls;

    /// <inheritdoc />
    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(
        AuthorizedConnectorExecution execution,
        CancellationToken cancellationToken)
    {
        using Stream configuration = execution.OpenPublishedExtensionConfiguration().OpenJsonStream();
        using JsonDocument document = await JsonDocument.ParseAsync(configuration, cancellationToken: cancellationToken).ConfigureAwait(false);
        JsonElement root = document.RootElement;
        string claimName = root.GetProperty("claimName").GetString()!;
        JsonElement claimValue = root.GetProperty("claimValue").Clone();
        string bodyValue = root.GetProperty("body").GetString()!;
        IReadOnlyDictionary<string, JsonElement> claims = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            [claimName] = claimValue
        };
        _ = await execution.Capabilities.CreateSignedTokenAsync(
            ConnectorSigningSlotKey.Parse("primary"), claims, cancellationToken).ConfigureAwait(false);
        _ = await execution.Capabilities.CreateSignedTokenAsync(
            ConnectorSigningSlotKey.Parse("secondary"), claims, cancellationToken).ConfigureAwait(false);
        return await execution.Capabilities.ExecuteRestrictedTransportAsync(
            new AuthorizedConnectorRestrictedTransportRequest(Encoding.UTF8.GetBytes(bodyValue)),
            cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>Requests a slot absent from the exact Published operation.</summary>
public sealed class SyntheticUnknownSigningSlotExecutionStrategy : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-unknown-slot");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.MutualTls;
    /// <inheritdoc />
    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
    {
        _ = await execution.Capabilities.CreateSignedTokenAsync(
            ConnectorSigningSlotKey.Parse("unknown"),
            new Dictionary<string, JsonElement>(StringComparer.Ordinal),
            cancellationToken).ConfigureAwait(false);
        throw new InvalidOperationException("Unknown signing slot unexpectedly succeeded.");
    }
}

/// <summary>Requests the same authorized slot twice to prove one-shot consumption.</summary>
public sealed class SyntheticRepeatedSigningSlotExecutionStrategy : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-repeat-slot");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.MutualTls;
    /// <inheritdoc />
    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
    {
        ConnectorSigningSlotKey primary = ConnectorSigningSlotKey.Parse("primary");
        _ = await execution.Capabilities.CreateSignedTokenAsync(
            primary, new Dictionary<string, JsonElement>(StringComparer.Ordinal), cancellationToken).ConfigureAwait(false);
        _ = await execution.Capabilities.CreateSignedTokenAsync(
            primary, new Dictionary<string, JsonElement>(StringComparer.Ordinal), cancellationToken).ConfigureAwait(false);
        throw new InvalidOperationException("Repeated signing slot unexpectedly succeeded.");
    }
}

/// <summary>Attempts transport without generating every Published-required slot.</summary>
public sealed class SyntheticMissingRequiredSigningSlotExecutionStrategy : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-missing-slot");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.MutualTls;
    /// <inheritdoc />
    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
    {
        _ = await execution.Capabilities.CreateSignedTokenAsync(
            ConnectorSigningSlotKey.Parse("primary"),
            new Dictionary<string, JsonElement>(StringComparer.Ordinal),
            cancellationToken).ConfigureAwait(false);
        return await execution.Capabilities.ExecuteRestrictedTransportAsync(
            new AuthorizedConnectorRestrictedTransportRequest("synthetic-body"u8.ToArray()),
            cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>Negative strategy proving that a module cannot expand a Published claim allowlist.</summary>
public sealed class SyntheticDeniedSigningClaimExecutionStrategy : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-denied-signing-claim");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.MutualTls;
    /// <inheritdoc />
    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
    {
        _ = await execution.Capabilities.CreateSignedTokenAsync(
            ConnectorSigningSlotKey.Parse("primary"),
            new Dictionary<string, JsonElement>(StringComparer.Ordinal)
            {
                ["not-allowlisted"] = JsonSerializer.SerializeToElement("denied")
            }, cancellationToken).ConfigureAwait(false);
        throw new InvalidOperationException("Denied signing unexpectedly succeeded.");
    }
}

/// <summary>Retains a signing bridge to prove it cannot be used from a later invocation scope.</summary>
public sealed class SyntheticRetainedSigningBridgeExecutionStrategy : IConnectorExecutionStrategy
{
    private IAuthorizedConnectorCapabilityBridge? retained;

    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-retained-signing");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;
    /// <inheritdoc />
    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
    {
        if (string.Equals(execution.OperationId, "retain-signing", StringComparison.Ordinal))
        {
            retained = execution.Capabilities;
            return new(200, "application/json", "{}"u8.ToArray());
        }
        _ = await (retained ?? execution.Capabilities).CreateSignedTokenAsync(
            new Dictionary<string, JsonElement>(StringComparer.Ordinal), cancellationToken).ConfigureAwait(false);
        return new(200, "application/json", "{}"u8.ToArray());
    }
}

/// <summary>Starts signing without awaiting it, to qualify the host-owned capability lifetime.</summary>
public sealed class SyntheticFireAndForgetSigningExecutionStrategy : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-fire-forget-signing");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;
    /// <inheritdoc />
    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
    {
        Task<AuthorizedConnectorSignedToken> abandoned = execution.Capabilities.CreateSignedTokenAsync(
            new Dictionary<string, JsonElement>(StringComparer.Ordinal), CancellationToken.None);
        SyntheticCapabilityLifetimeProbe.Retain(abandoned);
        await SyntheticCapabilityLifetimeProbe.WaitUntilCapabilityStartedAsync(cancellationToken).ConfigureAwait(false);
        return new(200, "application/json", "{}"u8.ToArray());
    }
}

/// <summary>Starts restricted transport without awaiting it, to qualify close-before-dispatch cancellation.</summary>
public sealed class SyntheticFireAndForgetRestrictedTransportExecutionStrategy : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-fire-forget-transport");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;
    /// <inheritdoc />
    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
    {
        AuthorizedConnectorSignedToken token = await execution.Capabilities.CreateSignedTokenAsync(
            new Dictionary<string, JsonElement>(StringComparer.Ordinal), cancellationToken).ConfigureAwait(false);
        Task<QualifiedGatewayExecutionResult> abandoned = execution.Capabilities.ExecuteRestrictedTransportAsync(
            new AuthorizedConnectorRestrictedTransportRequest("synthetic-body"u8.ToArray(), token), CancellationToken.None);
        SyntheticCapabilityLifetimeProbe.Retain(abandoned);
        await SyntheticCapabilityLifetimeProbe.WaitUntilCapabilityStartedAsync(cancellationToken).ConfigureAwait(false);
        return new(200, "application/json", "{}"u8.ToArray());
    }
}

/// <summary>Deterministic cross-assembly coordination used only by capability lifetime qualification.</summary>
public static class SyntheticCapabilityLifetimeProbe
{
    private static TaskCompletionSource<bool> started = NewSignal();
    private static Task? retained;

    /// <summary>Resets the isolated qualification probe before one test invocation.</summary>
    public static void Reset()
    {
        Volatile.Write(ref retained, null);
        Volatile.Write(ref started, NewSignal());
    }

    /// <summary>Signals that the host dispatcher is paused before its privileged effect.</summary>
    public static void SignalCapabilityStarted() => Volatile.Read(ref started).TrySetResult(true);

    /// <summary>Waits without polling until the host dispatcher reaches its deterministic gate.</summary>
    public static Task WaitUntilCapabilityStartedAsync(CancellationToken cancellationToken) =>
        Volatile.Read(ref started).Task.WaitAsync(cancellationToken);

    /// <summary>Records the deliberately abandoned task so the test can prove host drainage.</summary>
    public static void Retain(Task operation) => Volatile.Write(ref retained, operation);

    /// <summary>Returns whether the deliberately abandoned task was completed by host scope closure.</summary>
    public static bool RetainedOperationCompleted => Volatile.Read(ref retained)?.IsCompleted == true;

    private static TaskCompletionSource<bool> NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

/// <summary>External strategy that forwards adversarial claim collections through only the public bridge.</summary>
public sealed class SyntheticAdversarialClaimsExecutionStrategy : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("synthetic-adversarial-claims");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;
    /// <inheritdoc />
    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
    {
        _ = await execution.Capabilities.CreateSignedTokenAsync(
            SyntheticClaimBoundsProbe.Claims, cancellationToken).ConfigureAwait(false);
        return new(200, "application/json", "{}"u8.ToArray());
    }
}

/// <summary>Qualification-only holder that does not enumerate or copy the configured claim collection.</summary>
public static class SyntheticClaimBoundsProbe
{
    private static IReadOnlyDictionary<string, JsonElement> claims =
        new Dictionary<string, JsonElement>(StringComparer.Ordinal);

    /// <summary>Supplies a module-controlled collection without pre-enumerating it.</summary>
    public static void Configure(IReadOnlyDictionary<string, JsonElement> values) => Volatile.Write(ref claims, values);

    /// <summary>Returns the exact configured collection to the public bridge.</summary>
    public static IReadOnlyDictionary<string, JsonElement> Claims => Volatile.Read(ref claims);
}

/// <summary>Startup-negative module that attempts duplicate adapter implementation registration.</summary>
public sealed class SyntheticDuplicateAdapterModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-duplicate-adapter");
    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar)
    {
        registrar.AddTypedSessionHandshakeRequestAdapter<SyntheticExternalTypedSessionRequestAdapter>();
        registrar.AddTypedSessionHandshakeRequestAdapter<SyntheticExternalTypedSessionRequestAdapter>();
    }
}

/// <summary>Startup-negative module that attempts to register a non-module adapter type.</summary>
public sealed class SyntheticWrongModuleAdapterModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-wrong-module-adapter");
    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar) =>
        registrar.AddTypedSessionHandshakeRequestAdapter<ITypedSessionHandshakeRequestAdapter>();
}

/// <summary>Startup-negative module that duplicates the composed request adapter category.</summary>
public sealed class SyntheticDuplicateComposedRequestAdapterModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-duplicate-composed-adapter");
    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar)
    {
        registrar.AddTypedComposedSoapRequestAdapter<SyntheticExternalTypedComposedSoapRequestAdapter>();
        registrar.AddTypedComposedSoapRequestAdapter<SyntheticExternalTypedComposedSoapRequestAdapter>();
    }
}

/// <summary>Startup-negative module that attempts a non-module composed adapter registration.</summary>
public sealed class SyntheticWrongModuleComposedRequestAdapterModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-wrong-composed-adapter");
    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar) =>
        registrar.AddTypedComposedSoapRequestAdapter<ITypedComposedSoapRequestAdapter>();
}

/// <summary>Startup-negative module that requests direct provider and transport authorities.</summary>
public sealed class SyntheticForbiddenAuthorityDependencyModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-forbidden-authority");
    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar)
    {
        registrar.AddStrategy<SyntheticSecretProviderDependencyStrategy>();
        registrar.AddStrategy<SyntheticKeyProviderDependencyStrategy>();
        registrar.AddStrategy<SyntheticTransportDependencyStrategy>();
    }
}

/// <summary>Startup-negative module requesting direct secret-provider authority.</summary>
public sealed class SyntheticSecretProviderDependencyModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-secret-provider");
    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar) =>
        registrar.AddStrategy<SyntheticSecretProviderDependencyStrategy>();
}

/// <summary>Startup-negative module requesting direct signing-provider authority.</summary>
public sealed class SyntheticKeyProviderDependencyModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-key-provider");
    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar) =>
        registrar.AddStrategy<SyntheticKeyProviderDependencyStrategy>();
}

/// <summary>Startup-negative module requesting direct restricted-transport authority.</summary>
public sealed class SyntheticTransportDependencyModule : IConnectorExecutionModule
{
    /// <inheritdoc />
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("synthetic-transport-provider");
    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar) =>
        registrar.AddStrategy<SyntheticTransportDependencyStrategy>();
}

/// <summary>Invalid direct secret-provider dependency.</summary>
public sealed class SyntheticSecretProviderDependencyStrategy(ISecretValueProvider provider) : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("invalid-secret-provider");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;
    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        throw new InvalidOperationException(provider.GetType().Name);
}

/// <summary>Invalid direct signing-provider dependency.</summary>
public sealed class SyntheticKeyProviderDependencyStrategy(IKeyOperationProvider provider) : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("invalid-key-provider");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;
    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        throw new InvalidOperationException(provider.GetType().Name);
}

/// <summary>Invalid direct restricted-transport dependency.</summary>
public sealed class SyntheticTransportDependencyStrategy(IRestrictedTransport transport) : IConnectorExecutionStrategy
{
    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("invalid-restricted-transport");
    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => SyntheticAuthenticationKinds.None;
    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        throw new InvalidOperationException(transport.GetType().Name);
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

internal static class SyntheticExternalTypedSessionProtocol
{
    internal const string Namespace = "urn:synthetic:typed-session";
    internal static readonly FrozenSet<string> RequiredInputs =
        new[] { "organization-code" }.ToFrozenSet(StringComparer.Ordinal);
}

internal static class SyntheticExternalTypedComposedSoapProtocol
{
    internal const string Namespace = "urn:synthetic:session";
    internal static readonly FrozenSet<string> RequiredInputs =
        new[] { "organization-code" }.ToFrozenSet(StringComparer.Ordinal);
}

/// <summary>External no-IVT adapter for one neutral typed composed-SOAP business request.</summary>
public sealed class SyntheticExternalTypedComposedSoapRequestAdapter : ITypedComposedSoapRequestAdapter
{
    /// <inheritdoc />
    public string AdapterId => "external-business-request";
    /// <inheritdoc />
    public string AdapterType => "external-compiled-business-request";
    /// <inheritdoc />
    public IReadOnlySet<string> RequiredServerOwnedInputs => SyntheticExternalTypedComposedSoapProtocol.RequiredInputs;

    /// <inheritdoc />
    public void WriteRequest(XmlWriter writer, TypedComposedSoapRequestContext context)
    {
        Stream retainedPayload = context.OpenBusinessPayloadStream();
        SyntheticTypedComposedSoapRequestProbe.Retain(context, retainedPayload);
        SyntheticBindingInputLifetimeProbe.Retain(context.ServerOwnedInputs);
        using Stream first = context.OpenBusinessPayloadStream();
        using Stream second = context.OpenBusinessPayloadStream();
        XDocument firstDocument = ReadBusinessPayload(first);
        XDocument secondDocument = ReadBusinessPayload(second);
        XElement root = firstDocument.Root ?? throw new XmlException();
        if (secondDocument.Root?.Name != root.Name) throw new XmlException();
        XName payloadName = XName.Get("Payload", "urn:synthetic:business-input");
        XElement payloadElement = root.Elements(payloadName).Single();
        if (root.Elements().Any(value => value.Name != payloadName &&
            value.Name != XName.Get("OrganizationCode", "urn:synthetic:business-input")))
            throw new XmlException();
        string payload = payloadElement.Value;
        if (payload.Length > 4_096) throw new XmlException();
        if (string.Equals(payload, "adapter-throws-canary", StringComparison.Ordinal))
            throw new InvalidOperationException("synthetic-typed-composed-adapter-canary");
        if (string.Equals(payload, "adapter-fake-cancellation", StringComparison.Ordinal))
            throw new OperationCanceledException("synthetic-typed-composed-fake-cancellation", new CancellationToken(canceled: true));
        if (string.Equals(payload, "binding-oracle-xml-lang", StringComparison.Ordinal))
        {
            writer.WriteStartAttribute("xml", "lang", "http://www.w3.org/XML/1998/namespace");
            context.ServerOwnedInputs.WriteRequiredXmlValue("organization-code");
            writer.WriteEndAttribute();
            SyntheticBindingInputStateOracleProbe.RecordXmlLang(
                string.Equals(writer.XmlLang, "core-owned<&organization", StringComparison.Ordinal));
            throw new InvalidOperationException("synthetic-binding-oracle-must-not-complete");
        }
        if (string.Equals(payload, "binding-oracle-namespace", StringComparison.Ordinal))
        {
            writer.WriteStartAttribute("xmlns", "probe", "http://www.w3.org/2000/xmlns/");
            context.ServerOwnedInputs.WriteRequiredXmlValue("organization-code");
            writer.WriteEndAttribute();
            SyntheticBindingInputStateOracleProbe.RecordNamespace(
                string.Equals(writer.LookupPrefix("core-owned<&organization"), "probe", StringComparison.Ordinal));
            throw new InvalidOperationException("synthetic-binding-oracle-must-not-complete");
        }

        writer.WriteElementString("op", "Payload", SyntheticExternalTypedComposedSoapProtocol.Namespace, payload);
        writer.WriteStartElement("op", "OrganizationCode", SyntheticExternalTypedComposedSoapProtocol.Namespace);
        context.ServerOwnedInputs.WriteRequiredXmlValue("organization-code");
        writer.WriteEndElement();

        static XDocument ReadBusinessPayload(Stream stream)
        {
            XmlReaderSettings settings = new()
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersFromEntities = 0,
                MaxCharactersInDocument = 32_768
            };
            using XmlReader reader = XmlReader.Create(stream, settings);
            XDocument document = XDocument.Load(reader, LoadOptions.None);
            XElement root = document.Root ?? throw new XmlException();
            if (root.Name != XName.Get("BusinessPayload", "urn:synthetic:business-input") ||
                root.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration))
                throw new XmlException();
            return document;
        }
    }
}

/// <summary>External no-IVT probe for XML writer state that must never observe binding plaintext.</summary>
public static class SyntheticBindingInputStateOracleProbe
{
    private static int xmlLangSucceeded;
    private static int namespaceSucceeded;

    /// <summary>Clears qualification-only boolean observations without retaining any value.</summary>
    public static void Reset()
    {
        Volatile.Write(ref xmlLangSucceeded, 0);
        Volatile.Write(ref namespaceSucceeded, 0);
    }

    /// <summary>Records only whether the reserved XML attribute exposed the known synthetic value.</summary>
    public static void RecordXmlLang(bool succeeded) => Volatile.Write(ref xmlLangSucceeded, succeeded ? 1 : 0);

    /// <summary>Records only whether namespace lookup confirmed the known synthetic value.</summary>
    public static void RecordNamespace(bool succeeded) => Volatile.Write(ref namespaceSucceeded, succeeded ? 1 : 0);

    /// <summary>Whether any adapter-visible writer-state oracle succeeded.</summary>
    public static bool AnySucceeded => Volatile.Read(ref xmlLangSucceeded) != 0 || Volatile.Read(ref namespaceSucceeded) != 0;
}

/// <summary>External probes for callback lifetime and read-only repeatable business payload views.</summary>
public static class SyntheticTypedComposedSoapRequestProbe
{
    private static TypedComposedSoapRequestContext? retained;
    private static Stream? retainedPayload;

    /// <summary>Clears qualification-only retained state.</summary>
    public static void Reset()
    {
        Volatile.Write(ref retained, null);
        Interlocked.Exchange(ref retainedPayload, null)?.Dispose();
    }

    /// <summary>Retains only to prove callback-scoped context denial and payload clearing.</summary>
    public static void Retain(TypedComposedSoapRequestContext context, Stream payload)
    {
        Volatile.Write(ref retained, context);
        Interlocked.Exchange(ref retainedPayload, payload)?.Dispose();
    }

    /// <summary>Returns true only when the retained stream is cleared and the context cannot reopen it.</summary>
    public static bool RetainedPayloadViewIsClearedAndContextIsDenied()
    {
        TypedComposedSoapRequestContext context = Volatile.Read(ref retained)
            ?? throw new InvalidOperationException("Synthetic typed composed request context was not retained.");
        Stream payload = Interlocked.Exchange(ref retainedPayload, null)
            ?? throw new InvalidOperationException("Synthetic typed composed payload stream was not retained.");
        byte[] observed = new byte[context.BusinessPayloadLength];
        try
        {
            payload.Position = 0;
            int count = payload.ReadAtLeast(observed, observed.Length, throwOnEndOfStream: false);
            if (count != observed.Length || observed.Any(value => value != 0)) return false;
            try
            {
                using Stream _ = context.OpenBusinessPayloadStream();
                return false;
            }
            catch
            {
                return true;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(observed);
            payload.Dispose();
        }
    }
}

/// <summary>Externally registered neutral request adapter with one server-owned input.</summary>
public sealed class SyntheticExternalTypedSessionRequestAdapter : ITypedSessionHandshakeRequestAdapter
{
    /// <inheritdoc />
    public string AdapterId => "external-create-session-request";
    /// <inheritdoc />
    public string AdapterType => "external-compiled-request";
    /// <inheritdoc />
    public IReadOnlySet<string> RequiredServerOwnedInputs => SyntheticExternalTypedSessionProtocol.RequiredInputs;

    /// <inheritdoc />
    public void WriteRequest(XmlWriter writer, TypedSessionHandshakeRequestContext context)
    {
        SyntheticBindingInputLifetimeProbe.Retain(context.ServerOwnedInputs);
        using StringWriter alternateBuffer = new(System.Globalization.CultureInfo.InvariantCulture);
        using (XmlWriter alternateWriter = XmlWriter.Create(alternateBuffer, new XmlWriterSettings { OmitXmlDeclaration = true }))
            alternateWriter.Flush();
        SyntheticBindingInputLifetimeProbe.RecordAlternateWriter(alternateBuffer.ToString());
        writer.WriteStartElement("s", "ClientContext", SyntheticExternalTypedSessionProtocol.Namespace);
        writer.WriteStartElement("s", "Identity", SyntheticExternalTypedSessionProtocol.Namespace);
        writer.WriteElementString("s", "Tenant", SyntheticExternalTypedSessionProtocol.Namespace, context.TenantId.ToString("D"));
        writer.WriteElementString("s", "Installation", SyntheticExternalTypedSessionProtocol.Namespace, context.InstallationId.ToString("D"));
        writer.WriteElementString("s", "Application", SyntheticExternalTypedSessionProtocol.Namespace, context.ApplicationId.ToString("D"));
        writer.WriteEndElement();
        writer.WriteStartElement("s", "OrganizationCode", SyntheticExternalTypedSessionProtocol.Namespace);
        context.ServerOwnedInputs.WriteRequiredXmlValue("organization-code");
        writer.WriteEndElement();
        writer.WriteStartElement("s", "Policy", SyntheticExternalTypedSessionProtocol.Namespace);
        writer.WriteElementString("s", "Profile", SyntheticExternalTypedSessionProtocol.Namespace, context.ProfileId);
        writer.WriteElementString("s", "PublishedChecksum", SyntheticExternalTypedSessionProtocol.Namespace, context.PublishedPolicyChecksum);
        writer.WriteEndElement();
        writer.WriteEndElement();
    }
}

/// <summary>External no-IVT probe proving writer redirection is absent and retained views fail closed.</summary>
public static class SyntheticBindingInputLifetimeProbe
{
    private static AuthorizedConnectorBindingInputs? retained;
    private static string alternateWriterOutput = string.Empty;

    /// <summary>Clears qualification-only retained state.</summary>
    public static void Reset()
    {
        Volatile.Write(ref retained, null);
        Volatile.Write(ref alternateWriterOutput, string.Empty);
    }

    /// <summary>Records the view solely so a later external call can attempt reuse.</summary>
    public static void Retain(AuthorizedConnectorBindingInputs inputs) => Volatile.Write(ref retained, inputs);

    /// <summary>Records the module-owned writer output without receiving a server-owned value.</summary>
    public static void RecordAlternateWriter(string output) => Volatile.Write(ref alternateWriterOutput, output);

    /// <summary>Module-owned alternate sink content.</summary>
    public static string AlternateWriterOutput => Volatile.Read(ref alternateWriterOutput);

    /// <summary>Attempts a post-callback write; true means the retained view denied it.</summary>
    public static bool RetainedWriteIsDenied()
    {
        AuthorizedConnectorBindingInputs inputs = Volatile.Read(ref retained)
            ?? throw new InvalidOperationException("Synthetic binding-input view was not retained.");
        try
        {
            inputs.WriteRequiredXmlValue("organization-code");
            return false;
        }
        catch
        {
            return true;
        }
    }
}

/// <summary>Externally registered neutral response adapter.</summary>
public sealed class SyntheticExternalTypedSessionResponseAdapter : ITypedSessionHandshakeResponseAdapter
{
    /// <inheritdoc />
    public string AdapterId => "external-create-session-response";
    /// <inheritdoc />
    public string AdapterType => "external-compiled-response";

    /// <inheritdoc />
    public TypedSessionHandshakeAdapterOutcome ReadResponse(XmlReader payload, TypedSessionHandshakeResponseContext context)
    {
        payload.ReadStartElement("CreateSessionResponse", SyntheticExternalTypedSessionProtocol.Namespace);
        payload.ReadStartElement("Result", SyntheticExternalTypedSessionProtocol.Namespace);
        string status = payload.ReadElementContentAsString("Status", SyntheticExternalTypedSessionProtocol.Namespace);
        TypedSessionHandshakeAdapterOutcome outcome;
        if (string.Equals(status, "issued", StringComparison.Ordinal))
        {
            payload.ReadStartElement("Session", SyntheticExternalTypedSessionProtocol.Namespace);
            string value = payload.ReadElementContentAsString("Value", SyntheticExternalTypedSessionProtocol.Namespace);
            var expiry = XmlConvert.ToDateTime(
                payload.ReadElementContentAsString("ExpiresAt", SyntheticExternalTypedSessionProtocol.Namespace),
                XmlDateTimeSerializationMode.RoundtripKind);
            payload.ReadEndElement();
            outcome = TypedSessionHandshakeAdapterOutcome.Issued(value, expiry);
        }
        else if (string.Equals(status, "external_admission_required", StringComparison.Ordinal))
        {
            payload.ReadStartElement("Admission", SyntheticExternalTypedSessionProtocol.Namespace);
            if (!string.Equals(payload.ReadElementContentAsString("Provenance", SyntheticExternalTypedSessionProtocol.Namespace), "interactive_handoff", StringComparison.Ordinal))
                throw new XmlException();
            payload.ReadEndElement();
            outcome = TypedSessionHandshakeAdapterOutcome.ExternalAdmissionRequired();
        }
        else if (string.Equals(status, "rejected", StringComparison.Ordinal))
        {
            outcome = TypedSessionHandshakeAdapterOutcome.Rejected(TypedSessionHandshakeRejection.Rejected);
        }
        else throw new XmlException();
        payload.ReadEndElement();
        payload.ReadEndElement();
        return outcome;
    }
}

/// <summary>Externally registered neutral admission validator with one server-owned input.</summary>
public sealed class SyntheticExternalSessionValidationAdapter : ITypedExternalSessionValidationAdapter
{
    /// <inheritdoc />
    public string AdapterId => "external-session-validator";
    /// <inheritdoc />
    public string AdapterType => "external-compiled-validator";
    /// <inheritdoc />
    public IReadOnlySet<string> RequiredServerOwnedInputs => SyntheticExternalTypedSessionProtocol.RequiredInputs;

    /// <inheritdoc />
    public void WriteValidationRequest(XmlWriter writer, ExternalSessionValidationRequestContext context)
    {
        writer.WriteStartElement("s", "Candidate", SyntheticExternalTypedSessionProtocol.Namespace);
        writer.WriteElementString("s", "Provenance", SyntheticExternalTypedSessionProtocol.Namespace, "interactive_handoff");
        writer.WriteStartElement("s", "OrganizationCode", SyntheticExternalTypedSessionProtocol.Namespace);
        context.ServerOwnedInputs.WriteRequiredXmlValue("organization-code");
        writer.WriteEndElement();
        writer.WriteElementString("s", "OpaqueValue", SyntheticExternalTypedSessionProtocol.Namespace, Encoding.UTF8.GetString(context.SensitiveCandidate.Span));
        writer.WriteEndElement();
    }

    /// <inheritdoc />
    public ExternalSessionValidationResult ReadValidationResponse(XmlReader payload, ExternalSessionValidationResponseContext context)
    {
        payload.ReadStartElement("ValidateSessionResponse", SyntheticExternalTypedSessionProtocol.Namespace);
        payload.ReadStartElement("Validation", SyntheticExternalTypedSessionProtocol.Namespace);
        string status = payload.ReadElementContentAsString("Status", SyntheticExternalTypedSessionProtocol.Namespace);
        if (string.Equals(status, "rejected", StringComparison.Ordinal))
        {
            payload.ReadEndElement();
            payload.ReadEndElement();
            return ExternalSessionValidationResult.Invalid(ExternalSessionValidationStatus.Rejected);
        }
        if (!string.Equals(status, "valid", StringComparison.Ordinal)) throw new XmlException();
        var expiry = XmlConvert.ToDateTime(
            payload.ReadElementContentAsString("ExpiresAt", SyntheticExternalTypedSessionProtocol.Namespace),
            XmlDateTimeSerializationMode.RoundtripKind);
        payload.ReadEndElement();
        payload.ReadEndElement();
        return ExternalSessionValidationResult.Valid(expiry);
    }
}

internal static class SyntheticAuthenticationKinds
{
    internal static readonly FrozenSet<GatewayAuthenticationKind> None =
        new[] { GatewayAuthenticationKind.None }.ToFrozenSet();
    internal static readonly FrozenSet<GatewayAuthenticationKind> OpaqueSessionHttp =
        new[] { GatewayAuthenticationKind.OpaqueSessionHttp }.ToFrozenSet();
    internal static readonly FrozenSet<GatewayAuthenticationKind> MutualTls =
        new[] { GatewayAuthenticationKind.MutualTls }.ToFrozenSet();
    internal static readonly FrozenSet<GatewayAuthenticationKind> CapabilityBridge = new[]
    {
        GatewayAuthenticationKind.None,
        GatewayAuthenticationKind.Basic,
        GatewayAuthenticationKind.SoapBasicOpaqueSession
    }.ToFrozenSet();
}

using System.Collections.Frozen;
using System.Text;
using System.Text.Json;
using System.Xml;
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
        registrar.AddStrategy<SyntheticDeniedSigningClaimExecutionStrategy>();
        registrar.AddStrategy<SyntheticRetainedSigningBridgeExecutionStrategy>();
        registrar.AddTypedSessionHandshakeRequestAdapter<SyntheticExternalTypedSessionRequestAdapter>();
        registrar.AddTypedSessionHandshakeResponseAdapter<SyntheticExternalTypedSessionResponseAdapter>();
        registrar.AddExternalSessionValidationAdapter<SyntheticExternalSessionValidationAdapter>();
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
        writer.WriteStartElement("s", "ClientContext", SyntheticExternalTypedSessionProtocol.Namespace);
        writer.WriteStartElement("s", "Identity", SyntheticExternalTypedSessionProtocol.Namespace);
        writer.WriteElementString("s", "Tenant", SyntheticExternalTypedSessionProtocol.Namespace, context.TenantId.ToString("D"));
        writer.WriteElementString("s", "Installation", SyntheticExternalTypedSessionProtocol.Namespace, context.InstallationId.ToString("D"));
        writer.WriteElementString("s", "Application", SyntheticExternalTypedSessionProtocol.Namespace, context.ApplicationId.ToString("D"));
        writer.WriteEndElement();
        writer.WriteStartElement("s", "OrganizationCode", SyntheticExternalTypedSessionProtocol.Namespace);
        context.ServerOwnedInputs.WriteRequiredXmlValue(writer, "organization-code");
        writer.WriteEndElement();
        writer.WriteStartElement("s", "Policy", SyntheticExternalTypedSessionProtocol.Namespace);
        writer.WriteElementString("s", "Profile", SyntheticExternalTypedSessionProtocol.Namespace, context.ProfileId);
        writer.WriteElementString("s", "PublishedChecksum", SyntheticExternalTypedSessionProtocol.Namespace, context.PublishedPolicyChecksum);
        writer.WriteEndElement();
        writer.WriteEndElement();
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
        context.ServerOwnedInputs.WriteRequiredXmlValue(writer, "organization-code");
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

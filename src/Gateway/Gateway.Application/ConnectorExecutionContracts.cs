using System.Collections.Frozen;

namespace SecureIntegration.Gateway.Application;

/// <summary>Canonical server-owned identifier selecting one trusted Connector execution strategy.</summary>
public sealed record ConnectorExecutionStrategyKey
{
    /// <summary>Maximum canonical key length.</summary>
    public const int MaximumLength = 64;

    private ConnectorExecutionStrategyKey(string value) => Value = value;

    /// <summary>Lower-case canonical key value.</summary>
    public string Value { get; }

    /// <summary>Validates an exact lower-case ASCII execution strategy key.</summary>
    public static ConnectorExecutionStrategyKey Parse(string value)
    {
        if (!ConnectorExecutionIdentifier.IsValid(value, MaximumLength))
            throw new ArgumentException("Invalid Connector execution strategy key.", nameof(value));
        return new(value);
    }

    /// <summary>Attempts to validate an exact lower-case ASCII execution strategy key.</summary>
    public static bool TryParse(string? value, out ConnectorExecutionStrategyKey? key)
    {
        if (!ConnectorExecutionIdentifier.IsValid(value, MaximumLength))
        {
            key = null;
            return false;
        }
        key = new(value!);
        return true;
    }

    /// <inheritdoc />
    public override string ToString() => Value;
}

/// <summary>Canonical deployment-owned identifier for one explicitly configured execution module.</summary>
public sealed record ConnectorExecutionModuleId
{
    /// <summary>Maximum canonical module identifier length.</summary>
    public const int MaximumLength = 64;

    private ConnectorExecutionModuleId(string value) => Value = value;

    /// <summary>Lower-case canonical module identifier.</summary>
    public string Value { get; }

    /// <summary>Validates an exact lower-case ASCII module identifier.</summary>
    public static ConnectorExecutionModuleId Parse(string value)
    {
        if (!ConnectorExecutionIdentifier.IsValid(value, MaximumLength))
            throw new ArgumentException("Invalid Connector execution module identifier.", nameof(value));
        return new(value);
    }

    /// <inheritdoc />
    public override string ToString() => Value;
}

/// <summary>
/// Non-forgeable proof that Core authenticated a caller, checked its grant and resolved one exact
/// Published Connector operation. Only the authenticated Gateway runtime can construct it.
/// </summary>
public sealed class AuthorizedConnectorExecution
{
    private readonly byte[] payload;
    private readonly AuthorizedConnectorCapabilityBridge capabilities;

    internal AuthorizedConnectorExecution(
        AuthorizedGatewayInvocation invocation,
        GatewayOperationDefinition operation,
        ConnectorExecutionStrategyKey executionStrategyKey,
        ReadOnlySpan<byte> payload,
        IAuthorizedConnectorCapabilityDispatcher? capabilityDispatcher = null,
        AuthorizedPublishedExecutionStamp? publishedAuthority = null)
    {
        Invocation = invocation;
        Operation = operation;
        ExecutionStrategyKey = executionStrategyKey;
        this.payload = payload.ToArray();
        this.publishedAuthority = publishedAuthority;
        capabilities = new(this, capabilityDispatcher);
    }

    /// <summary>Authenticated server-derived Tenant identity.</summary>
    public Guid TenantId => Invocation.Principal.TenantId;
    /// <summary>Authenticated server-derived Application identity.</summary>
    public Guid ApplicationId => Invocation.Principal.ApplicationId;
    /// <summary>Authenticated server-derived Installation identity.</summary>
    public Guid InstallationId => Invocation.Principal.InstallationId;
    /// <summary>Server-derived Environment identity.</summary>
    public Guid EnvironmentId => Invocation.Principal.Identity.EnvironmentId;
    /// <summary>Authorized Connector identifier.</summary>
    public string ConnectorId => Invocation.ConnectorId;
    /// <summary>Authorized operation identifier.</summary>
    public string OperationId => Invocation.OperationId;
    /// <summary>Published Connector version selected by Core.</summary>
    public string ConnectorVersion => Operation.Version;
    /// <summary>Authenticated correlation identifier.</summary>
    public Guid CorrelationId => Invocation.Principal.CorrelationId;
    /// <summary>Published outbound authentication semantics, distinct from execution selection.</summary>
    public GatewayAuthenticationKind AuthenticationKind => Operation.Authentication;
    /// <summary>Exact Published or legacy-compatible server-derived execution strategy key.</summary>
    public ConnectorExecutionStrategyKey ExecutionStrategyKey { get; }
    /// <summary>Published request media type associated with the authorized payload.</summary>
    public string RequestContentType => Operation.RequestContentType;
    /// <summary>Bounded authorized payload length.</summary>
    public int PayloadLength => payload.Length;
    /// <summary>
    /// Narrow, invocation-bound access to existing server-owned Connector capabilities. The bridge
    /// accepts no identity, endpoint, credential, profile or provider selector.
    /// </summary>
    public IAuthorizedConnectorCapabilityBridge Capabilities => capabilities;

    /// <summary>Opens an independent read-only view over the immutable authorized payload snapshot.</summary>
    public Stream OpenPayloadStream() => new MemoryStream(payload, writable: false);

    internal AuthorizedGatewayInvocation Invocation { get; }
    internal GatewayOperationDefinition Operation { get; }
    internal ReadOnlyMemory<byte> Payload => payload;
    internal AuthorizedPublishedExecutionStamp PublishedAuthority => publishedAuthority ??
        throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-STALE", 503, true);

    private readonly AuthorizedPublishedExecutionStamp? publishedAuthority;

    internal IDisposable EnterCapabilityScope() => capabilities.EnterExecutionScope();

    internal bool Owns(AuthorizedConnectorCapabilityFailureException exception) =>
        ReferenceEquals(capabilities, exception.Authority);

    private sealed class AuthorizedConnectorCapabilityBridge(
        AuthorizedConnectorExecution execution,
        IAuthorizedConnectorCapabilityDispatcher? dispatcher) : IAuthorizedConnectorCapabilityBridge
    {
        private static readonly AsyncLocal<AuthorizedConnectorCapabilityBridge?> Current = new();
        private int active;
        private int consumed;

        public Task<QualifiedGatewayExecutionResult> ExecuteTypedSessionHandshakeAsync(CancellationToken cancellationToken) =>
            InvokeAsync(static (value, handoff, token) => value.ExecuteTypedSessionHandshakeAsync(handoff, token), cancellationToken);

        public Task<QualifiedGatewayExecutionResult> ExecuteComposedSoapAsync(CancellationToken cancellationToken) =>
            InvokeAsync(static (value, handoff, token) => value.ExecuteComposedSoapAsync(handoff, token), cancellationToken);

        internal IDisposable EnterExecutionScope()
        {
            if (Interlocked.CompareExchange(ref active, 1, 0) != 0)
                throw new InvalidOperationException("Authorized Connector capability scope is already active.");
            AuthorizedConnectorCapabilityBridge? previous = Current.Value;
            Current.Value = this;
            return new ExecutionScope(this, previous);
        }

        private async Task<QualifiedGatewayExecutionResult> InvokeAsync(
            Func<IAuthorizedConnectorCapabilityDispatcher, AuthorizedConnectorExecution, CancellationToken, Task<QualifiedGatewayExecutionResult>> invoke,
            CancellationToken cancellationToken)
        {
            if (Volatile.Read(ref active) != 1 || !ReferenceEquals(Current.Value, this) ||
                Interlocked.CompareExchange(ref consumed, 1, 0) != 0 || dispatcher is null)
                throw Failure(new GatewayException("BGW-EGRESS-AUTHENTICATION", 409));

            try
            {
                return await invoke(dispatcher, execution, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancellationToken);
            }
            catch (GatewayException exception)
            {
                throw Failure(exception);
            }
            catch (AuthorizedConnectorCapabilityFailureException)
            {
                throw;
            }
            catch (Exception)
            {
                throw Failure(new GatewayException("BGW-EGRESS-UPSTREAM-REJECTED", 502));
            }
        }

        private AuthorizedConnectorCapabilityFailureException Failure(GatewayException failure) => new(this, failure);

        private sealed class ExecutionScope(
            AuthorizedConnectorCapabilityBridge owner,
            AuthorizedConnectorCapabilityBridge? previous) : IDisposable
        {
            private int disposed;

            public void Dispose()
            {
                if (Interlocked.Exchange(ref disposed, 1) != 0) return;
                Current.Value = previous;
                Volatile.Write(ref owner.active, 0);
            }
        }
    }
}

/// <summary>
/// Invocation-bound bridge to the two existing qualified server capabilities required by compiled
/// Connector runtimes. It is not a provider, transport, catalog or service-resolution facade.
/// </summary>
public interface IAuthorizedConnectorCapabilityBridge
{
    /// <summary>Executes the current Published operation as its typed session handshake.</summary>
    Task<QualifiedGatewayExecutionResult> ExecuteTypedSessionHandshakeAsync(CancellationToken cancellationToken);
    /// <summary>Executes the current Published operation through the composed SOAP capability.</summary>
    Task<QualifiedGatewayExecutionResult> ExecuteComposedSoapAsync(CancellationToken cancellationToken);
}

/// <summary>One exact deployment-registered execution strategy.</summary>
public interface IConnectorExecutionStrategy
{
    /// <summary>Canonical key owned exclusively by this strategy registration.</summary>
    ConnectorExecutionStrategyKey Key { get; }
    /// <summary>
    /// Closed outbound authentication kinds this strategy implements. Core snapshots and validates
    /// this metadata at startup and checks it before calling the strategy.
    /// </summary>
    IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds { get; }
    /// <summary>Executes only an already authenticated, granted and Published-resolved handoff.</summary>
    Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken);
}

/// <summary>Restricted registration surface exposed to a trusted execution module at startup.</summary>
public interface IConnectorExecutionStrategyRegistrar
{
    /// <summary>Registers one module-owned singleton service using constructor injection.</summary>
    void AddSingleton<TService>() where TService : class;
    /// <summary>Registers one module-owned singleton service implementation using constructor injection.</summary>
    void AddSingleton<TService, TImplementation>()
        where TService : class
        where TImplementation : class, TService;
    /// <summary>Registers one module-owned execution strategy using constructor injection.</summary>
    void AddStrategy<TStrategy>() where TStrategy : class, IConnectorExecutionStrategy;
}

/// <summary>Explicit startup-only module that registers known execution strategies and their own services.</summary>
public interface IConnectorExecutionModule
{
    /// <summary>Stable deployment-owned module identity.</summary>
    ConnectorExecutionModuleId Id { get; }
    /// <summary>Registers only module-owned services and execution strategies.</summary>
    void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar);
}

internal static class ConnectorExecutionIdentifier
{
    internal static bool IsValid(string? value, int maximumLength) =>
        value is { Length: > 0 } && value.Length <= maximumLength &&
        value[0] is >= 'a' and <= 'z' &&
        value[^1] is (>= 'a' and <= 'z') or (>= '0' and <= '9') &&
        value.All(character => character is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_' or '.');
}

internal static class ConnectorExecutionStrategyKeys
{
    internal static readonly ConnectorExecutionStrategyKey DefaultHttp = ConnectorExecutionStrategyKey.Parse("default-http");
    internal static readonly ConnectorExecutionStrategyKey OpaqueSessionHttp = ConnectorExecutionStrategyKey.Parse("opaque-session-http");
    internal static readonly ConnectorExecutionStrategyKey ComposedSoap = ConnectorExecutionStrategyKey.Parse("composed-soap");
    internal static readonly ConnectorExecutionStrategyKey OAuthAuthorizationCode = ConnectorExecutionStrategyKey.Parse("oauth-authorization-code");
    internal static readonly ConnectorExecutionStrategyKey OAuthClientCredentials = ConnectorExecutionStrategyKey.Parse("oauth-client-credentials");

    internal static ConnectorExecutionStrategyKey Legacy(GatewayAuthenticationKind authentication) => authentication switch
    {
        GatewayAuthenticationKind.None or GatewayAuthenticationKind.Basic or GatewayAuthenticationKind.ApiKey or
        GatewayAuthenticationKind.MutualTls or GatewayAuthenticationKind.ApiKeyAndMutualTls => DefaultHttp,
        GatewayAuthenticationKind.OAuthAuthorizationCode => OAuthAuthorizationCode,
        GatewayAuthenticationKind.OAuthClientCredentials => OAuthClientCredentials,
        GatewayAuthenticationKind.OpaqueSessionHttp => OpaqueSessionHttp,
        GatewayAuthenticationKind.SoapBasicOpaqueSession => ComposedSoap,
        _ => throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409)
    };

    internal static ConnectorExecutionStrategyKey Resolve(GatewayOperationDefinition operation) =>
        operation.ExecutionStrategy ?? Legacy(operation.Authentication);

    internal static ConnectorExecutionStrategyKey Resolve(System.Text.Json.JsonElement operation)
    {
        if (operation.TryGetProperty("executionStrategy", out System.Text.Json.JsonElement explicitKey))
            return ConnectorExecutionStrategyKey.Parse(explicitKey.GetString()!);
        string authentication = operation.GetProperty("authentication").GetProperty("kind").GetString()!;
        return authentication switch
        {
            "none" or "basic" or "apiKey" or "mtls" or "apiKeyAndMtls" => DefaultHttp,
            "oauthAuthorizationCode" => OAuthAuthorizationCode,
            "oauthClientCredentials" => OAuthClientCredentials,
            "opaqueSessionHttp" => OpaqueSessionHttp,
            "soapBasicOpaqueSession" => ComposedSoap,
            _ => throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-CORRUPT", 503)
        };
    }
}

internal sealed class ConnectorExecutionStrategyRegistry
{
    internal const int MaximumStrategies = 256;
    private readonly Dictionary<ConnectorExecutionStrategyKey, ConnectorExecutionStrategyRegistration> strategies;

    internal ConnectorExecutionStrategyRegistry(IEnumerable<IConnectorExecutionStrategy> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        Dictionary<ConnectorExecutionStrategyKey, ConnectorExecutionStrategyRegistration> registered = [];
        foreach (IConnectorExecutionStrategy strategy in values)
        {
            ConnectorExecutionStrategyKey key;
            FrozenSet<GatewayAuthenticationKind> supported;
            try
            {
                if (strategy is null)
                    throw new InvalidOperationException();
                key = strategy.Key ?? throw new InvalidOperationException();
                IReadOnlySet<GatewayAuthenticationKind> advertised = strategy.SupportedAuthenticationKinds
                    ?? throw new InvalidOperationException();
                GatewayAuthenticationKind[] declared = advertised.ToArray();
                if (declared.Length is < 1 || declared.Length > Enum.GetValues<GatewayAuthenticationKind>().Length ||
                    declared.Any(value => !Enum.IsDefined(value)))
                    throw new InvalidOperationException();
                supported = declared.ToFrozenSet();
                if (supported.Count != declared.Length)
                    throw new InvalidOperationException();
            }
            catch (Exception)
            {
                throw new InvalidOperationException("Connector execution strategy registration or authentication compatibility is invalid.");
            }
            if (registered.Count >= MaximumStrategies)
                throw new InvalidOperationException("Connector execution strategy registry is full.");
            if (!registered.TryAdd(key, new(strategy, supported, strategy is ICoreConnectorExecutionStrategy)))
                throw new InvalidOperationException("Duplicate Connector execution strategy key.");
        }
        strategies = registered;
    }

    internal ConnectorExecutionStrategyRegistration Required(
        ConnectorExecutionStrategyKey key,
        GatewayAuthenticationKind authenticationKind)
    {
        if (!strategies.TryGetValue(key, out ConnectorExecutionStrategyRegistration? registration) ||
            !registration.SupportedAuthenticationKinds.Contains(authenticationKind))
            throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
        return registration;
    }
}

internal sealed record ConnectorExecutionStrategyRegistration(
    IConnectorExecutionStrategy Strategy,
    IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds,
    bool PreservesCoreFailures);

/// <summary>Implemented only by built-in Core strategies through existing friend boundaries.</summary>
internal interface ICoreConnectorExecutionStrategy;

/// <summary>Internal composition contract implemented by the existing qualified capability pack.</summary>
internal interface IAuthorizedConnectorCapabilityDispatcher
{
    Task<QualifiedGatewayExecutionResult> ExecuteTypedSessionHandshakeAsync(
        AuthorizedConnectorExecution execution,
        CancellationToken cancellationToken);

    Task<QualifiedGatewayExecutionResult> ExecuteComposedSoapAsync(
        AuthorizedConnectorExecution execution,
        CancellationToken cancellationToken);
}

internal sealed class AuthorizedConnectorCapabilityFailureException(
    object authority,
    GatewayException failure) : Exception("Authorized Connector capability failed.")
{
    internal object Authority { get; } = authority;
    internal GatewayException Failure { get; } = failure;
}

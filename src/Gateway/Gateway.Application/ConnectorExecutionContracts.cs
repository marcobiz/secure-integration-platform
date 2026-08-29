using System.Collections.Frozen;
using System.Text.Json;
using SecureIntegration.Security;

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

/// <summary>
/// Canonical server-owned identifier selecting one complete Published signing authority. Naming a
/// slot does not create authority; Core exact-matches it against the current operation.
/// </summary>
public sealed record ConnectorSigningSlotKey
{
    /// <summary>Maximum canonical slot-key length.</summary>
    public const int MaximumLength = 64;

    private ConnectorSigningSlotKey(string value) => Value = value;

    /// <summary>Lower-case canonical slot-key value.</summary>
    public string Value { get; }

    /// <summary>Validates an exact lower-case ASCII signing slot key.</summary>
    public static ConnectorSigningSlotKey Parse(string value)
    {
        if (!ConnectorExecutionIdentifier.IsValid(value, MaximumLength))
            throw new ArgumentException("Invalid Connector signing slot key.", nameof(value));
        return new(value);
    }

    /// <summary>Attempts to validate an exact lower-case ASCII signing slot key.</summary>
    public static bool TryParse(string? value, out ConnectorSigningSlotKey? key)
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
    private AuthorizedRestrictedTransportResponseMode restrictedTransportResponseMode;

    internal AuthorizedConnectorExecution(
        AuthorizedGatewayInvocation invocation,
        GatewayOperationDefinition operation,
        ConnectorExecutionStrategyKey executionStrategyKey,
        ReadOnlySpan<byte> payload,
        IAuthorizedConnectorCapabilityDispatcher? capabilityDispatcher = null,
        AuthorizedPublishedExecutionStamp? publishedAuthority = null,
        AuthorizedPublishedExtensionConfiguration? extensionConfiguration = null)
    {
        Invocation = invocation;
        Operation = operation;
        ExecutionStrategyKey = executionStrategyKey;
        this.payload = payload.ToArray();
        this.publishedAuthority = publishedAuthority;
        this.extensionConfiguration = extensionConfiguration?.Copy() ?? AuthorizedPublishedExtensionConfiguration.Empty();
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

    /// <summary>
    /// Opens the immutable bounded extension configuration copied from the exact Published
    /// operation initially authorized by Core. No store handle or authority stamp is returned.
    /// </summary>
    public AuthorizedPublishedExtensionConfiguration OpenPublishedExtensionConfiguration() => extensionConfiguration.Copy();

    /// <summary>Opens an independent read-only view over the immutable authorized payload snapshot.</summary>
    public Stream OpenPayloadStream() => new MemoryStream(payload, writable: false);

    internal AuthorizedGatewayInvocation Invocation { get; }
    internal GatewayOperationDefinition Operation { get; }
    internal ReadOnlyMemory<byte> Payload => payload;
    internal AuthorizedRestrictedTransportResponseMode RestrictedTransportResponseMode => restrictedTransportResponseMode;
    internal AuthorizedPublishedExecutionStamp PublishedAuthority => publishedAuthority ??
        throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-STALE", 503, true);

    private readonly AuthorizedPublishedExecutionStamp? publishedAuthority;
    private readonly AuthorizedPublishedExtensionConfiguration extensionConfiguration;

    internal AuthorizedConnectorCapabilityScope EnterCapabilityScope(CancellationToken invocationCancellation) =>
        capabilities.EnterExecutionScope(invocationCancellation);

    internal bool Owns(AuthorizedConnectorCapabilityFailureException exception) =>
        ReferenceEquals(capabilities, exception.Authority);

    internal void AuthorizeRestrictedTransportResponseMode(AuthorizedRestrictedTransportResponseMode mode)
    {
        if (!Enum.IsDefined(mode) || restrictedTransportResponseMode != AuthorizedRestrictedTransportResponseMode.SuccessOnly)
            throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
        restrictedTransportResponseMode = mode;
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable",
        Justification = "The private bridge is externally retained for denial tests; its host-owned scope deterministically cancels, drains and disposes all owned sources without exposing IDisposable authority.")]
    private sealed class AuthorizedConnectorCapabilityBridge(
        AuthorizedConnectorExecution execution,
        IAuthorizedConnectorCapabilityDispatcher? dispatcher) : IAuthorizedConnectorCapabilityBridge
    {
        private static readonly AsyncLocal<AuthorizedConnectorCapabilityBridge?> Current = new();
        private readonly object synchronization = new();
        private readonly List<TrackedCapabilityOperation> operations = [];
        private readonly HashSet<ConnectorSigningSlotKey> consumedSigningSlots = [];
        private readonly Dictionary<ConnectorSigningSlotKey, AuthorizedConnectorSignedToken> signedTokens = [];
        private CancellationToken invocationCancellation;
        private CancellationTokenSource? lifetimeCancellation;
        private int state;
        private int consumedCapabilities;
        private int signingAttempts;
        private QualifiedGatewayExecutionResult? restrictedTransportResult;

        private const int TypedSessionHandshakeCapability = 1;
        private const int ComposedSoapCapability = 2;
        private const int RestrictedTransportCapability = 4;

        public Task<QualifiedGatewayExecutionResult> ExecuteTypedSessionHandshakeAsync(CancellationToken cancellationToken) =>
            StartOperation(TypedSessionHandshakeCapability,
                static (value, handoff, token) => value.ExecuteTypedSessionHandshakeAsync(handoff, token), cancellationToken);

        public Task<QualifiedGatewayExecutionResult> ExecuteComposedSoapAsync(CancellationToken cancellationToken) =>
            StartOperation(ComposedSoapCapability,
                static (value, handoff, token) => value.ExecuteComposedSoapAsync(handoff, token), cancellationToken);

        public Task<AuthorizedConnectorSignedToken> CreateSignedTokenAsync(
            IReadOnlyDictionary<string, JsonElement> claims,
            CancellationToken cancellationToken) =>
            CreateSignedTokenAsync(ConnectorSigningSlotKeys.Legacy, claims, cancellationToken);

        public Task<AuthorizedConnectorSignedToken> CreateSignedTokenAsync(
            ConnectorSigningSlotKey signingSlot,
            IReadOnlyDictionary<string, JsonElement> claims,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(signingSlot);
            return StartSigningOperation(signingSlot, async (value, handoff, token) =>
            {
                IReadOnlyDictionary<string, JsonElement> snapshot;
                try { snapshot = BoundedJwtClaimSnapshot.Create(claims); }
                catch (Exception exception) when (exception is BoundedJwtClaimValidationException or ArgumentException or InvalidOperationException or JsonException or OverflowException)
                {
                    throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
                }
                string compactToken = await value.CreateSignedTokenAsync(handoff, signingSlot, snapshot, token).ConfigureAwait(false);
                AuthorizedConnectorSignedToken result = new(this, signingSlot, compactToken);
                lock (synchronization)
                {
                    if (!signedTokens.TryAdd(signingSlot, result))
                        throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
                }
                return result;
            }, cancellationToken);
        }

        public Task<QualifiedGatewayExecutionResult> ExecuteRestrictedTransportAsync(
            AuthorizedConnectorRestrictedTransportRequest request,
            CancellationToken cancellationToken) =>
            StartOperation(RestrictedTransportCapability, async (value, handoff, token) =>
            {
                ArgumentNullException.ThrowIfNull(request);
                IReadOnlyDictionary<ConnectorSigningSlotKey, AuthorizedConnectorSignedToken> snapshot;
                lock (synchronization)
                {
                    if (request.SignedToken is not null &&
                        (!request.SignedToken.IsOwnedBy(this) ||
                         !signedTokens.TryGetValue(request.SignedToken.SigningSlot, out AuthorizedConnectorSignedToken? expected) ||
                         !ReferenceEquals(expected, request.SignedToken)))
                        throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
                    snapshot = signedTokens.ToDictionary(value => value.Key, value => value.Value);
                }
                QualifiedGatewayExecutionResult result = await value.ExecuteRestrictedTransportAsync(
                    handoff, request, snapshot, token).ConfigureAwait(false);
                lock (synchronization) restrictedTransportResult = result;
                return result;
            }, cancellationToken);

        public void RejectRestrictedTransportResponse(QualifiedGatewayExecutionResult response, string? safeProblemCode)
        {
            bool validCode = safeProblemCode is null || safeProblemCode is { Length: >= 1 and <= 96 } &&
                safeProblemCode.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
            lock (synchronization)
            {
                if (state != 1 || !ReferenceEquals(Current.Value, this) ||
                    execution.RestrictedTransportResponseMode != AuthorizedRestrictedTransportResponseMode.BoundedProblemDetails ||
                    !ReferenceEquals(restrictedTransportResult, response) || response.StatusCode is >= 200 and < 300 || !validCode)
                    throw Failure(new GatewayException("BGW-EGRESS-AUTHENTICATION", 409));
            }
            bool retryable = execution.Operation.Idempotent && execution.Operation.MaximumRetries > 0 &&
                response.StatusCode is 429 or 502 or 503 or 504;
            throw Failure(new GatewayException(
                "BGW-EGRESS-UPSTREAM-REJECTED",
                502,
                retryable,
                SafeUpstreamFailureDiagnostics.HttpResponse(response.StatusCode, safeProblemCode)));
        }

        public void RejectRestrictedTransportResponseMapping(
            QualifiedGatewayExecutionResult response,
            string localSafeCode,
            string? safeUpstreamCode = null)
        {
            bool validLocalCode = localSafeCode is { Length: >= 1 and <= 96 } &&
                localSafeCode.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
            bool validUpstreamCode = safeUpstreamCode is null || safeUpstreamCode is { Length: >= 1 and <= 96 } &&
                safeUpstreamCode.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
            lock (synchronization)
            {
                if (state != 1 || !ReferenceEquals(Current.Value, this) ||
                    execution.RestrictedTransportResponseMode != AuthorizedRestrictedTransportResponseMode.BoundedProblemDetails ||
                    !ReferenceEquals(restrictedTransportResult, response) || response.StatusCode is not (>= 200 and < 300) ||
                    !validLocalCode || !validUpstreamCode)
                    throw Failure(new GatewayException("BGW-EGRESS-AUTHENTICATION", 409));
            }
            throw Failure(new GatewayException(
                "BGW-EGRESS-UPSTREAM-REJECTED",
                502,
                false,
                SafeUpstreamFailureDiagnostics.LocalResponseMapping(response.StatusCode, localSafeCode, safeUpstreamCode)));
        }

        internal AuthorizedConnectorCapabilityScope EnterExecutionScope(CancellationToken actualInvocationCancellation)
        {
            lock (synchronization)
            {
                if (state != 0)
                    throw new InvalidOperationException("Authorized Connector capability scope is already active.");
                invocationCancellation = actualInvocationCancellation;
                lifetimeCancellation = new CancellationTokenSource();
                state = 1;
                AuthorizedConnectorCapabilityBridge? previous = Current.Value;
                Current.Value = this;
                return new AuthorizedConnectorCapabilityScope(() =>
                {
                    Current.Value = previous;
                    return CloseExecutionScopeAsync();
                });
            }
        }

        private Task<TResult> StartOperation<TResult>(
            int capability,
            Func<IAuthorizedConnectorCapabilityDispatcher, AuthorizedConnectorExecution, CancellationToken, Task<TResult>> invoke,
            CancellationToken cancellationToken)
        {
            TrackedCapabilityOperation operation = BeginOperation(capability, cancellationToken);
            Task<TResult> task = InvokeTrackedAsync(operation, invoke, cancellationToken);
            operation.Attach(task);
            return task;
        }

        private Task<TResult> StartSigningOperation<TResult>(
            ConnectorSigningSlotKey signingSlot,
            Func<IAuthorizedConnectorCapabilityDispatcher, AuthorizedConnectorExecution, CancellationToken, Task<TResult>> invoke,
            CancellationToken cancellationToken)
        {
            TrackedCapabilityOperation operation = BeginSigningOperation(signingSlot, cancellationToken);
            Task<TResult> task = InvokeTrackedAsync(operation, invoke, cancellationToken);
            operation.Attach(task);
            return task;
        }

        private TrackedCapabilityOperation BeginOperation(int capability, CancellationToken methodCancellation)
        {
            lock (synchronization)
            {
                if (state != 1 || !ReferenceEquals(Current.Value, this) || dispatcher is null ||
                    (consumedCapabilities & capability) != 0 || lifetimeCancellation is null)
                    throw Failure(new GatewayException("BGW-EGRESS-AUTHENTICATION", 409));

                consumedCapabilities |= capability;
                CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
                    invocationCancellation,
                    lifetimeCancellation.Token,
                    methodCancellation);
                TrackedCapabilityOperation operation = new(linked);
                operations.Add(operation);
                return operation;
            }
        }

        private TrackedCapabilityOperation BeginSigningOperation(
            ConnectorSigningSlotKey signingSlot,
            CancellationToken methodCancellation)
        {
            lock (synchronization)
            {
                if (state != 1 || !ReferenceEquals(Current.Value, this) || dispatcher is null ||
                    lifetimeCancellation is null || signingAttempts >= AuthorizedSigningSlots.MaximumSlots ||
                    !consumedSigningSlots.Add(signingSlot))
                    throw Failure(new GatewayException("BGW-EGRESS-AUTHENTICATION", 409));

                signingAttempts++;
                CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(
                    invocationCancellation,
                    lifetimeCancellation.Token,
                    methodCancellation);
                TrackedCapabilityOperation operation = new(linked);
                operations.Add(operation);
                return operation;
            }
        }

        private async Task<TResult> InvokeTrackedAsync<TResult>(
            TrackedCapabilityOperation operation,
            Func<IAuthorizedConnectorCapabilityDispatcher, AuthorizedConnectorExecution, CancellationToken, Task<TResult>> invoke,
            CancellationToken methodCancellation)
        {
            try
            {
                return await invoke(dispatcher!, execution, operation.CancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (invocationCancellation.IsCancellationRequested)
            {
                throw new OperationCanceledException(invocationCancellation);
            }
            catch (OperationCanceledException) when (methodCancellation.IsCancellationRequested)
            {
                throw new OperationCanceledException(methodCancellation);
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

        private async Task<AuthorizedConnectorCapabilityScopeCloseResult> CloseExecutionScopeAsync()
        {
            TrackedCapabilityOperation[] tracked;
            CancellationTokenSource? lifetime;
            bool hadInFlight;
            lock (synchronization)
            {
                if (state != 1)
                    return new(false);
                state = 2;
                tracked = operations.ToArray();
                hadInFlight = tracked.Any(value => !value.IsCompleted);
                lifetime = lifetimeCancellation;
            }

            try { lifetime?.Cancel(); }
            catch (AggregateException) { }

            foreach (TrackedCapabilityOperation operation in tracked)
            {
                try
                {
                    Task task = await operation.AttachedTask.ConfigureAwait(false);
                    await task.ConfigureAwait(false);
                }
                catch (Exception) { }
                finally { operation.Dispose(); }
            }

            lifetime?.Dispose();
            lock (synchronization)
            {
                lifetimeCancellation = null;
                state = 3;
            }
            return new(hadInFlight);
        }

        private AuthorizedConnectorCapabilityFailureException Failure(GatewayException failure) => new(this, failure);

        private sealed class TrackedCapabilityOperation(CancellationTokenSource cancellation) : IDisposable
        {
            private readonly TaskCompletionSource<Task> attached = new(TaskCreationOptions.RunContinuationsAsynchronously);
            private Task? task;

            internal CancellationToken CancellationToken => cancellation.Token;
            internal Task<Task> AttachedTask => attached.Task;
            internal bool IsCompleted => Volatile.Read(ref task)?.IsCompleted == true;

            internal void Attach(Task value)
            {
                if (Interlocked.CompareExchange(ref task, value, null) is not null)
                    throw new InvalidOperationException("Authorized Connector capability task was already attached.");
                attached.TrySetResult(value);
            }

            public void Dispose() => cancellation.Dispose();
        }
    }
}

internal readonly record struct AuthorizedConnectorCapabilityScopeCloseResult(bool HadInFlightOperations);

internal sealed class AuthorizedConnectorCapabilityScope(
    Func<Task<AuthorizedConnectorCapabilityScopeCloseResult>> close)
{
    private readonly object synchronization = new();
    private Task<AuthorizedConnectorCapabilityScopeCloseResult>? closeTask;

    internal Task<AuthorizedConnectorCapabilityScopeCloseResult> CloseAsync()
    {
        lock (synchronization)
            return closeTask ??= close();
    }
}

internal static class BoundedJwtClaimSnapshot
{
    internal static IReadOnlyDictionary<string, JsonElement> Create(IReadOnlyDictionary<string, JsonElement> claims)
    {
        ArgumentNullException.ThrowIfNull(claims);
        Dictionary<string, JsonElement> snapshot = new(StringComparer.Ordinal);
        int actualCount = 0;
        int aggregateCharacters = 0;
        foreach ((string name, JsonElement value) in claims)
        {
            BoundedJwtClaimValidation.ValidateNext(name, value, ref actualCount, ref aggregateCharacters);
            if (!snapshot.TryAdd(name, value.Clone()))
                throw new BoundedJwtClaimValidationException(BoundedJwtClaimFailure.Name);
        }
        return snapshot;
    }
}

/// <summary>
/// Invocation-bound bridge to the qualified server capabilities required by compiled
/// Connector runtimes. It is not a provider, transport, catalog or service-resolution facade.
/// </summary>
public interface IAuthorizedConnectorCapabilityBridge
{
    /// <summary>Executes the current Published operation as its typed session handshake.</summary>
    Task<QualifiedGatewayExecutionResult> ExecuteTypedSessionHandshakeAsync(CancellationToken cancellationToken);
    /// <summary>Executes the current Published operation through the composed SOAP capability.</summary>
    Task<QualifiedGatewayExecutionResult> ExecuteComposedSoapAsync(CancellationToken cancellationToken);
    /// <summary>
    /// Creates one bounded RS256 token using only the current Published signing policy and its
    /// allowlisted scalar claims. No policy, key, provider, algorithm or purpose selector exists.
    /// </summary>
    Task<AuthorizedConnectorSignedToken> CreateSignedTokenAsync(
        IReadOnlyDictionary<string, JsonElement> claims,
        CancellationToken cancellationToken);
    /// <summary>
    /// Creates at most one bounded RS256 token for one exact Published signing slot. The slot is a
    /// selector for pre-approved authority, never a key, provider, algorithm or purpose selector.
    /// </summary>
    Task<AuthorizedConnectorSignedToken> CreateSignedTokenAsync(
        ConnectorSigningSlotKey signingSlot,
        IReadOnlyDictionary<string, JsonElement> claims,
        CancellationToken cancellationToken);
    /// <summary>
    /// Sends one bounded body to the exact current Published endpoint with the exact server-owned
    /// mTLS identity and the signed token produced by this same invocation.
    /// </summary>
    Task<QualifiedGatewayExecutionResult> ExecuteRestrictedTransportAsync(
        AuthorizedConnectorRestrictedTransportRequest request,
        CancellationToken cancellationToken);
    /// <summary>
    /// Rejects the exact non-success result returned by this invocation after connector-local safe
    /// problem mapping. No body, title, detail, endpoint or arbitrary metadata can be supplied.
    /// </summary>
    void RejectRestrictedTransportResponse(QualifiedGatewayExecutionResult response, string? safeProblemCode);
    /// <summary>Rejects only the exact successful bounded response that the current vertical could not map safely.</summary>
    void RejectRestrictedTransportResponseMapping(QualifiedGatewayExecutionResult response, string localSafeCode, string? safeUpstreamCode = null);
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
    /// <summary>Registers one module-owned implementation of the existing typed-session request adapter contract.</summary>
    void AddTypedSessionHandshakeRequestAdapter<TAdapter>() where TAdapter : class;
    /// <summary>Registers one module-owned implementation of the existing typed-session response adapter contract.</summary>
    void AddTypedSessionHandshakeResponseAdapter<TAdapter>() where TAdapter : class;
    /// <summary>Registers one module-owned implementation of the existing external-session validator contract.</summary>
    void AddExternalSessionValidationAdapter<TAdapter>() where TAdapter : class;
    /// <summary>Registers one module-owned composed-SOAP business request adapter.</summary>
    void AddTypedComposedSoapRequestAdapter<TAdapter>() where TAdapter : class;
    /// <summary>Registers one module-owned bounded Published-operation expectation provider.</summary>
    void AddAuthorizedPublishedOperationExpectationProvider<TProvider>()
        where TProvider : class, IAuthorizedPublishedOperationExpectationProvider;
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

internal static class ConnectorSigningSlotKeys
{
    internal static readonly ConnectorSigningSlotKey Legacy = ConnectorSigningSlotKey.Parse("legacy");
}

internal static class AuthorizedSigningSlots
{
    internal const int MaximumSlots = 4;
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

internal sealed class AuthorizedPublishedOperationExpectationProviderRegistry
{
    private const int MaximumProviders = 64;
    private readonly FrozenDictionary<ConnectorExecutionStrategyKey, IAuthorizedPublishedOperationExpectationProvider> providers;

    internal AuthorizedPublishedOperationExpectationProviderRegistry(
        IEnumerable<IAuthorizedPublishedOperationExpectationProvider>? values)
    {
        Dictionary<ConnectorExecutionStrategyKey, IAuthorizedPublishedOperationExpectationProvider> registered = [];
        int providerCount = 0;
        foreach (IAuthorizedPublishedOperationExpectationProvider provider in values ?? [])
        {
            if (provider is null || ++providerCount > MaximumProviders)
                throw new InvalidOperationException("Published operation expectation provider registry is invalid or full.");
            IReadOnlySet<ConnectorExecutionStrategyKey> advertised = provider.SupportedExecutionStrategies ??
                throw new InvalidOperationException("Published operation expectation provider strategy set is missing.");
            int strategyCount = 0;
            HashSet<ConnectorExecutionStrategyKey> snapshot = [];
            foreach (ConnectorExecutionStrategyKey key in advertised)
            {
                if (key is null || ++strategyCount > ConnectorExecutionStrategyRegistry.MaximumStrategies || !snapshot.Add(key))
                    throw new InvalidOperationException("Published operation expectation provider strategy set is invalid.");
            }
            if (snapshot.Count == 0)
                throw new InvalidOperationException("Published operation expectation provider strategy set is empty.");
            foreach (ConnectorExecutionStrategyKey key in snapshot)
                if (!registered.TryAdd(key, provider))
                    throw new InvalidOperationException("Duplicate Published operation expectation provider strategy key.");
        }
        providers = registered.ToFrozenDictionary();
    }

    internal IAuthorizedPublishedOperationExpectationProvider Required(ConnectorExecutionStrategyKey key) =>
        providers.TryGetValue(key, out IAuthorizedPublishedOperationExpectationProvider? provider)
            ? provider
            : throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
}

/// <summary>Implemented only by built-in Core strategies through existing friend boundaries.</summary>
internal interface ICoreConnectorExecutionStrategy;

/// <summary>Internal composition contract implemented by the existing qualified capability pack.</summary>
internal interface IAuthorizedConnectorCapabilityDispatcher
{
    Task ValidatePublishedOperationExpectationsAsync(
        AuthorizedConnectorExecution execution,
        AuthorizedPublishedOperationExpectations expectations,
        CancellationToken cancellationToken);

    Task<QualifiedGatewayExecutionResult> ExecuteTypedSessionHandshakeAsync(
        AuthorizedConnectorExecution execution,
        CancellationToken cancellationToken);

    Task<QualifiedGatewayExecutionResult> ExecuteComposedSoapAsync(
        AuthorizedConnectorExecution execution,
        CancellationToken cancellationToken);

    Task<string> CreateSignedTokenAsync(
        AuthorizedConnectorExecution execution,
        ConnectorSigningSlotKey signingSlot,
        IReadOnlyDictionary<string, JsonElement> claims,
        CancellationToken cancellationToken);

    Task<QualifiedGatewayExecutionResult> ExecuteRestrictedTransportAsync(
        AuthorizedConnectorExecution execution,
        AuthorizedConnectorRestrictedTransportRequest request,
        IReadOnlyDictionary<ConnectorSigningSlotKey, AuthorizedConnectorSignedToken> signedTokens,
        CancellationToken cancellationToken);
}

internal interface IAuthorizedVerticalCapabilityRuntime
{
    Task ValidatePublishedOperationExpectationsAsync(
        AuthorizedConnectorExecution execution,
        AuthorizedPublishedOperationExpectations expectations,
        CancellationToken cancellationToken);

    Task<string> CreateSignedTokenAsync(
        AuthorizedConnectorExecution execution,
        ConnectorSigningSlotKey signingSlot,
        IReadOnlyDictionary<string, JsonElement> claims,
        CancellationToken cancellationToken);

    Task<QualifiedGatewayExecutionResult> ExecuteRestrictedTransportAsync(
        AuthorizedConnectorExecution execution,
        AuthorizedConnectorRestrictedTransportRequest request,
        IReadOnlyDictionary<ConnectorSigningSlotKey, AuthorizedConnectorSignedToken> signedTokens,
        CancellationToken cancellationToken);
}

internal sealed class AuthorizedConnectorCapabilityFailureException(
    object authority,
    GatewayException failure) : Exception("Authorized Connector capability failed.")
{
    internal object Authority { get; } = authority;
    internal GatewayException Failure { get; } = failure;
}

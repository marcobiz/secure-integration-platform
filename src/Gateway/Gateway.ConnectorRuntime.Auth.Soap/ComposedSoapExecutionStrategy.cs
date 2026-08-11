using System.Collections.Frozen;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>Production strategy for Basic + typed SOAP metadata + opaque-session dispatch.</summary>
public sealed class ComposedSoapExecutionStrategy : IConnectorExecutionStrategy, ICoreConnectorExecutionStrategy
{
    private static readonly FrozenSet<GatewayAuthenticationKind> AuthenticationKinds =
        new[] { GatewayAuthenticationKind.SoapBasicOpaqueSession }.ToFrozenSet();
    private readonly PublishedComposedSoapAuthorityResolver authority;
    private readonly TypedComposedSoapRequestComposer requestComposer;
    private readonly ComposedSoapAuthenticatedClient client;

    /// <summary>Creates the production strategy over the real Published store and restricted SOAP transport.</summary>
    public ComposedSoapExecutionStrategy(
        IConnectorConfigurationStore store,
        ISecretValueProvider secrets,
        OpaqueSessionLeaseProvider sessions,
        IHostResolver resolver,
        IRestrictedTransport transport,
        IGatewayClock clock,
        IPrivateDestinationAllowance? privateDestinationAllowance = null,
        IEnumerable<ITypedComposedSoapRequestAdapter>? requestAdapters = null)
        : this(store, secrets, sessions, resolver, transport, clock, privateDestinationAllowance,
            new TypedComposedSoapRequestAdapterRegistry(requestAdapters ?? []), null)
    {
    }

    internal ComposedSoapExecutionStrategy(
        IConnectorConfigurationStore store,
        ISecretValueProvider secrets,
        OpaqueSessionLeaseProvider sessions,
        IHostResolver resolver,
        IRestrictedTransport transport,
        IGatewayClock clock,
        IPrivateDestinationAllowance? privateDestinationAllowance,
        Func<CancellationToken, Task>? beforeFinalAuthorization)
        : this(store, secrets, sessions, resolver, transport, clock, privateDestinationAllowance,
            new TypedComposedSoapRequestAdapterRegistry([]), beforeFinalAuthorization)
    {
    }

    internal ComposedSoapExecutionStrategy(
        IConnectorConfigurationStore store,
        ISecretValueProvider secrets,
        OpaqueSessionLeaseProvider sessions,
        IHostResolver resolver,
        IRestrictedTransport transport,
        IGatewayClock clock,
        IPrivateDestinationAllowance? privateDestinationAllowance,
        IEnumerable<ITypedComposedSoapRequestAdapter> requestAdapters,
        Func<CancellationToken, Task>? beforeFinalAuthorization)
        : this(store, secrets, sessions, resolver, transport, clock, privateDestinationAllowance,
            new TypedComposedSoapRequestAdapterRegistry(requestAdapters), beforeFinalAuthorization)
    {
    }

    private ComposedSoapExecutionStrategy(
        IConnectorConfigurationStore store,
        ISecretValueProvider secrets,
        OpaqueSessionLeaseProvider sessions,
        IHostResolver resolver,
        IRestrictedTransport transport,
        IGatewayClock clock,
        IPrivateDestinationAllowance? privateDestinationAllowance,
        TypedComposedSoapRequestAdapterRegistry requestAdapters,
        Func<CancellationToken, Task>? beforeFinalAuthorization)
    {
        ISecretValueProvider secretProvider = secrets ?? throw new ArgumentNullException(nameof(secrets));
        authority = new(store ?? throw new ArgumentNullException(nameof(store)), clock ?? throw new ArgumentNullException(nameof(clock)), requestAdapters);
        requestComposer = new(secretProvider);
        client = new(secretProvider, sessions ?? throw new ArgumentNullException(nameof(sessions)),
            resolver ?? throw new ArgumentNullException(nameof(resolver)), transport ?? throw new ArgumentNullException(nameof(transport)), clock,
            privateDestinationAllowance, beforeFinalAuthorization);
    }

    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("composed-soap");

    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => AuthenticationKinds;

    /// <inheritdoc />
    public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
        ExecuteCoreAsync(execution, requireSelectedKey: true, cancellationToken);

    internal Task<QualifiedGatewayExecutionResult> ExecuteAuthorizedCapabilityAsync(
        AuthorizedConnectorExecution execution,
        CancellationToken cancellationToken) =>
        ExecuteCoreAsync(execution, requireSelectedKey: false, cancellationToken);

    private async Task<QualifiedGatewayExecutionResult> ExecuteCoreAsync(
        AuthorizedConnectorExecution execution,
        bool requireSelectedKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        GatewayOperationDefinition operation = execution.Operation;
        if (operation.Authentication != GatewayAuthenticationKind.SoapBasicOpaqueSession ||
            (requireSelectedKey && execution.ExecutionStrategyKey != Key) ||
            operation.Method != HttpMethod.Post || string.IsNullOrWhiteSpace(operation.AuthenticationPolicyId) ||
            string.IsNullOrWhiteSpace(operation.SessionProfileId))
            throw AuthenticationFailure();

        try
        {
            OpaqueSessionAuthorizedInvocation invocation = new(execution.Invocation.Principal, execution.ConnectorId, execution.OperationId);
            ComposedSoapResolvedExecutionContext resolved = requireSelectedKey
                ? await authority.ResolveAsync(invocation, new(operation.AuthenticationPolicyId), cancellationToken).ConfigureAwait(false)
                : await authority.ResolveAuthorizedAsync(invocation, new(operation.AuthenticationPolicyId), execution.PublishedAuthority, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(resolved.State.SessionAuthority.ConnectorVersion, operation.Version, StringComparison.Ordinal) ||
                !string.Equals(resolved.State.SessionAuthority.ProfileId, operation.SessionProfileId, StringComparison.Ordinal))
                throw AuthenticationFailure();
            using TypedComposedSoapRequestSnapshot? typedRequest = await requestComposer.ComposeAsync(
                resolved, execution.Payload, cancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte> exactEnvelope = typedRequest?.Bytes ?? execution.Payload;
            ComposedSoapHttpResponse response = await client.SendAuthorizedAsync(resolved, exactEnvelope, cancellationToken).ConfigureAwait(false);
            return new(response.StatusCode, response.ContentType, response.Body);
        }
        catch (OperationCanceledException) { throw; }
        catch (GatewayException) { throw; }
        catch (SoapAuthException exception)
        {
            throw exception.Code switch
            {
                "SOAP-EGRESS-DESTINATION-DENIED" => new GatewayException("BGW-EGRESS-DESTINATION-DENIED", 403),
                "SOAP-AUTHORITY-STALE" when !requireSelectedKey => new GatewayException("BGW-CONNECTOR-CONFIGURATION-STALE", 503, true),
                "SOAP-RESPONSE-TOO-LARGE" => new GatewayException("BGW-EGRESS-RESPONSE-TOO-LARGE", 502),
                "SOAP-TRANSPORT-FAILED" or "SOAP-TIMEOUT" => new GatewayException("BGW-EGRESS-UPSTREAM-REJECTED", 502),
                "SOAP-TYPED-COMPOSED-BINDING-INPUT-UNAVAILABLE" => new GatewayException("BGW-EGRESS-UPSTREAM-REJECTED", 502),
                "SOAP-REQUEST-INVALID" or "SOAP-XML-INVALID" or "SOAP-REQUEST-TOO-LARGE" or
                "SOAP-TYPED-COMPOSED-REQUEST-REJECTED" => new GatewayException("BGW-PROTOCOL-PAYLOAD", 400),
                _ => AuthenticationFailure()
            };
        }
        catch (Exception) { throw AuthenticationFailure(); }
    }

    private static GatewayException AuthenticationFailure() => new("BGW-EGRESS-AUTHENTICATION", 409);
}

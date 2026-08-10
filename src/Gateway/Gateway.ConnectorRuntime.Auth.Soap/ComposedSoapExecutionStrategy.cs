using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>Production strategy for Basic + typed SOAP metadata + opaque-session dispatch.</summary>
public sealed class ComposedSoapExecutionStrategy : IConnectorExecutionStrategy
{
    private readonly PublishedComposedSoapAuthorityResolver authority;
    private readonly ComposedSoapAuthenticatedClient client;

    /// <summary>Creates the production strategy over the real Published store and restricted SOAP transport.</summary>
    public ComposedSoapExecutionStrategy(
        IConnectorConfigurationStore store,
        ISecretValueProvider secrets,
        OpaqueSessionLeaseProvider sessions,
        IHostResolver resolver,
        IRestrictedTransport transport,
        IGatewayClock clock,
        IPrivateDestinationAllowance? privateDestinationAllowance = null)
        : this(store, secrets, sessions, resolver, transport, clock, privateDestinationAllowance, null)
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
    {
        authority = new(store ?? throw new ArgumentNullException(nameof(store)), clock ?? throw new ArgumentNullException(nameof(clock)));
        client = new(secrets ?? throw new ArgumentNullException(nameof(secrets)), sessions ?? throw new ArgumentNullException(nameof(sessions)),
            resolver ?? throw new ArgumentNullException(nameof(resolver)), transport ?? throw new ArgumentNullException(nameof(transport)), clock,
            privateDestinationAllowance, beforeFinalAuthorization);
    }

    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("composed-soap");

    /// <inheritdoc />
    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        GatewayOperationDefinition operation = execution.Operation;
        if (operation.Authentication != GatewayAuthenticationKind.SoapBasicOpaqueSession || execution.ExecutionStrategyKey != Key ||
            operation.Method != HttpMethod.Post || string.IsNullOrWhiteSpace(operation.AuthenticationPolicyId) ||
            string.IsNullOrWhiteSpace(operation.SessionProfileId))
            throw AuthenticationFailure();

        try
        {
            OpaqueSessionAuthorizedInvocation invocation = new(execution.Invocation.Principal, execution.ConnectorId, execution.OperationId);
            ComposedSoapResolvedExecutionContext resolved = await authority.ResolveAsync(invocation, new(operation.AuthenticationPolicyId), cancellationToken).ConfigureAwait(false);
            if (!string.Equals(resolved.State.SessionAuthority.ConnectorVersion, operation.Version, StringComparison.Ordinal) ||
                !string.Equals(resolved.State.SessionAuthority.ProfileId, operation.SessionProfileId, StringComparison.Ordinal))
                throw AuthenticationFailure();
            ComposedSoapHttpResponse response = await client.SendAuthorizedAsync(resolved, execution.Payload, cancellationToken).ConfigureAwait(false);
            return new(response.StatusCode, response.ContentType, response.Body);
        }
        catch (OperationCanceledException) { throw; }
        catch (GatewayException) { throw; }
        catch (SoapAuthException exception)
        {
            throw exception.Code switch
            {
                "SOAP-EGRESS-DESTINATION-DENIED" => new GatewayException("BGW-EGRESS-DESTINATION-DENIED", 403),
                "SOAP-RESPONSE-TOO-LARGE" => new GatewayException("BGW-EGRESS-RESPONSE-TOO-LARGE", 502),
                "SOAP-TRANSPORT-FAILED" or "SOAP-TIMEOUT" => new GatewayException("BGW-EGRESS-UPSTREAM-REJECTED", 502),
                "SOAP-REQUEST-INVALID" or "SOAP-XML-INVALID" => new GatewayException("BGW-PROTOCOL-PAYLOAD", 400),
                _ => AuthenticationFailure()
            };
        }
        catch (Exception) { throw AuthenticationFailure(); }
    }

    private static GatewayException AuthenticationFailure() => new("BGW-EGRESS-AUTHENTICATION", 409);
}

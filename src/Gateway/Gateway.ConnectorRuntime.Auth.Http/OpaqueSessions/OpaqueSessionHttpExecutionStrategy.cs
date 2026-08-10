using System.Collections.Frozen;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;

/// <summary>Production strategy for the qualified generic opaque-session HTTP capability.</summary>
public sealed class OpaqueSessionHttpExecutionStrategy : IConnectorExecutionStrategy, ICoreConnectorExecutionStrategy
{
    private static readonly FrozenSet<GatewayAuthenticationKind> AuthenticationKinds =
        new[] { GatewayAuthenticationKind.OpaqueSessionHttp }.ToFrozenSet();
    private readonly PublishedOpaqueSessionAuthorityResolver authority;
    private readonly OpaqueSessionHttpClient client;

    /// <summary>Creates the production strategy over the real Published store and restricted transport.</summary>
    public OpaqueSessionHttpExecutionStrategy(
        IConnectorConfigurationStore store,
        OpaqueSessionLeaseProvider sessions,
        IHostResolver resolver,
        IRestrictedTransport transport,
        IGatewayClock clock,
        IPrivateDestinationAllowance? privateDestinationAllowance = null)
    {
        authority = new(store ?? throw new ArgumentNullException(nameof(store)), clock ?? throw new ArgumentNullException(nameof(clock)));
        client = new(sessions ?? throw new ArgumentNullException(nameof(sessions)), resolver ?? throw new ArgumentNullException(nameof(resolver)),
            transport ?? throw new ArgumentNullException(nameof(transport)), clock, privateDestinationAllowance);
    }

    /// <inheritdoc />
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("opaque-session-http");

    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => AuthenticationKinds;

    /// <inheritdoc />
    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        GatewayOperationDefinition operation = execution.Operation;
        if (operation.Authentication != GatewayAuthenticationKind.OpaqueSessionHttp || execution.ExecutionStrategyKey != Key ||
            string.IsNullOrWhiteSpace(operation.AuthenticationPolicyId) || string.IsNullOrWhiteSpace(operation.SessionProfileId))
            throw AuthenticationFailure();

        try
        {
            OpaqueSessionAuthorizedInvocation invocation = new(execution.Invocation.Principal, execution.ConnectorId, execution.OperationId);
            OpaqueSessionResolvedExecutionContext resolved = await authority.ResolveAsync(invocation, new(operation.AuthenticationPolicyId), cancellationToken).ConfigureAwait(false);
            if (!string.Equals(resolved.State.ConnectorVersion, operation.Version, StringComparison.Ordinal) ||
                !string.Equals(resolved.State.ProfileId, operation.SessionProfileId, StringComparison.Ordinal))
                throw AuthenticationFailure();
            OpaqueSessionHttpResponse response = await client.SendAuthorizedAsync(resolved, execution.Payload, cancellationToken).ConfigureAwait(false);
            return new(response.StatusCode, response.ContentType, response.Body);
        }
        catch (OperationCanceledException) { throw; }
        catch (GatewayException) { throw; }
        catch (OpaqueSessionAuthException exception)
        {
            throw exception.Code switch
            {
                "SESSION-HTTP-EGRESS-DESTINATION-DENIED" => new GatewayException("BGW-EGRESS-DESTINATION-DENIED", 403),
                "SESSION-HTTP-REQUEST-INVALID" => new GatewayException("BGW-PROTOCOL-PAYLOAD", 400),
                "SESSION-HTTP-TRANSPORT-FAILED" or "SESSION-HTTP-TIMEOUT" => new GatewayException("BGW-EGRESS-UPSTREAM-REJECTED", 502),
                _ => AuthenticationFailure()
            };
        }
        catch (Exception) { throw AuthenticationFailure(); }
    }

    private static GatewayException AuthenticationFailure() => new("BGW-EGRESS-AUTHENTICATION", 409);
}

using System.Collections.Frozen;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.ConnectorPacks.Healthcare.SistemaTs;

/// <summary>Registers the compiled Sistema TS ePrescription strategy and typed session adapters.</summary>
public sealed class SistemaTsExecutionModule : IConnectorExecutionModule
{
    /// <summary>Exact deployment module identifier.</summary>
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("healthcare-sistema-ts");

    /// <inheritdoc />
    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar)
    {
        ArgumentNullException.ThrowIfNull(registrar);
        registrar.AddStrategy<SistemaTsExecutionStrategy>();
        registrar.AddTypedSessionHandshakeRequestAdapter<SistemaTsCreateSessionRequestAdapter>();
        registrar.AddTypedSessionHandshakeResponseAdapter<SistemaTsCreateSessionResponseAdapter>();
        registrar.AddExternalSessionValidationAdapter<SistemaTsCheckTokenAdapter>();
    }
}

/// <summary>Connector-first execution strategy for the frozen national Sistema TS contracts.</summary>
public sealed class SistemaTsExecutionStrategy : IConnectorExecutionStrategy
{
    private static readonly IReadOnlySet<GatewayAuthenticationKind> AuthenticationKinds =
        new[] { GatewayAuthenticationKind.Basic, GatewayAuthenticationKind.SoapBasicOpaqueSession }
            .ToFrozenSet();

    /// <summary>Exact Published strategy selector.</summary>
    public ConnectorExecutionStrategyKey Key => ConnectorExecutionStrategyKey.Parse("healthcare-sistema-ts-eprescription");

    /// <inheritdoc />
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => AuthenticationKinds;

    /// <inheritdoc />
    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(
        AuthorizedConnectorExecution execution,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        SistemaTsPublishedOperation published = SistemaTsPublishedOperation.Read(execution);
        if (published.OperationId == SistemaTsOperationCatalog.SessionCreate.OperationId)
        {
            RequireAuthentication(execution, GatewayAuthenticationKind.Basic);
            return await execution.Capabilities.ExecuteTypedSessionHandshakeAsync(cancellationToken).ConfigureAwait(false);
        }

        RequireAuthentication(execution, GatewayAuthenticationKind.SoapBasicOpaqueSession);
        if (!execution.RequestContentType.StartsWith("text/xml", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Sistema TS requires the frozen SOAP 1.1 media type.");
        SistemaTsBusinessOperation operation = SistemaTsOperationCatalog.Required(published.OperationId);
        using Stream request = execution.OpenPayloadStream();
        byte[] requestBytes = await SistemaTsBoundedContent.ReadAsync(request, execution.PayloadLength, cancellationToken).ConfigureAwait(false);
        SistemaTsBusinessXml.ValidateRequest(operation, requestBytes);

        QualifiedGatewayExecutionResult result = await execution.Capabilities
            .ExecuteComposedSoapAsync(cancellationToken)
            .ConfigureAwait(false);
        SistemaTsBusinessXml.ValidateResponse(operation, result.Body);
        return result;
    }

    private static void RequireAuthentication(AuthorizedConnectorExecution execution, GatewayAuthenticationKind expected)
    {
        if (execution.AuthenticationKind != expected)
            throw new InvalidOperationException("Sistema TS Published authentication kind is incompatible with the operation.");
    }
}

using System.Text.Json;
using System.Text.Json.Serialization;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>
/// Internal adapter from the provider-neutral invocation bridge to the two already-qualified SOAP
/// capabilities. All authority remains in the current Published invocation and existing runtimes.
/// </summary>
internal sealed class AuthorizedConnectorCapabilityDispatcher(
    TypedSessionHandshakeRuntime handshakes,
    ComposedSoapExecutionStrategy composedSoap) : IAuthorizedConnectorCapabilityDispatcher
{
    private static readonly JsonSerializerOptions ResultJson = CreateResultJson();

    public async Task<QualifiedGatewayExecutionResult> ExecuteTypedSessionHandshakeAsync(
        AuthorizedConnectorExecution execution,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        TypedSessionHandshakeResult result = await handshakes.AcquireAuthorizedAsync(
            execution.Invocation,
            cancellationToken).ConfigureAwait(false);
        return new(200, "application/json", JsonSerializer.SerializeToUtf8Bytes(result, ResultJson));
    }

    public Task<QualifiedGatewayExecutionResult> ExecuteComposedSoapAsync(
        AuthorizedConnectorExecution execution,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        return composedSoap.ExecuteAuthorizedCapabilityAsync(execution, cancellationToken);
    }

    private static JsonSerializerOptions CreateResultJson()
    {
        JsonSerializerOptions options = new(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}

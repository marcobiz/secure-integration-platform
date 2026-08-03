using System.Net.Http.Headers;
using SecureIntegration.Broker.Core;

namespace SecureIntegration.Broker.Infrastructure.Windows;

/// <summary>Calls only a configured Gateway base address and never accepts a client-controlled URL.</summary>
public sealed class FixedGatewayHttpInvoker : IGatewayInvoker
{
    private readonly HttpClient client;

    /// <summary>Creates an invoker using a centrally configured HTTP client.</summary>
    public FixedGatewayHttpInvoker(HttpClient client)
    {
        this.client = client ?? throw new ArgumentNullException(nameof(client));
        if (client.BaseAddress is null || client.BaseAddress.Scheme != Uri.UriSchemeHttps) throw new ArgumentException("Gateway BaseAddress must use HTTPS.", nameof(client));
    }

    /// <inheritdoc />
    public async Task<GatewayInvocationResult> InvokeAsync(string applicationId, string connectorId, string operationId, string contentType, byte[] payload, Guid correlationId, CancellationToken cancellationToken)
    {
        if (payload.Length > SecureIntegration.Contracts.IpcProtocol.MaxPayloadBytes) throw new BrokerException("payload_too_large", "validation");
        string relative = $"runtime/connectors/{Uri.EscapeDataString(connectorId)}/operations/{Uri.EscapeDataString(operationId)}:invoke";
        using HttpRequestMessage request = new(HttpMethod.Post, relative);
        request.Headers.TryAddWithoutValidation("X-Correlation-Id", correlationId.ToString("D"));
        request.Headers.TryAddWithoutValidation("X-Application-Id", applicationId);
        request.Content = new ByteArrayContent(payload);
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException exception)
        {
            throw new BrokerException("gateway_transport_failed", "gateway", true, exception);
        }

        using (response)
        {
        if (!response.IsSuccessStatusCode) throw new BrokerException("gateway_invocation_failed", "gateway", (int)response.StatusCode >= 500);
        byte[] responsePayload = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        if (responsePayload.Length > SecureIntegration.Contracts.IpcProtocol.MaxPayloadBytes) throw new BrokerException("gateway_response_too_large", "gateway");
        string responseContentType = response.Content.Headers.ContentType?.ToString() ?? "application/octet-stream";
        string connectorVersion = response.Headers.TryGetValues("X-Connector-Version", out IEnumerable<string>? values) ? values.FirstOrDefault() ?? "unknown" : "unknown";
        return new GatewayInvocationResult(responseContentType, responsePayload, connectorVersion);
        }
    }
}

using System.Security.Cryptography;
using System.Text.Json;

namespace SecureIntegration.Samples.DirectGatewayClient;

/// <summary>Public invoke payload accepted by the Gateway runtime.</summary>
public sealed record GatewayPayload(string ContentType, string Encoding, string Data);

/// <summary>Public invoke request used by the Direct .NET golden path.</summary>
public sealed record InvokeRequest(
    string ProtocolVersion,
    GatewayPayload Payload,
    Guid CorrelationId,
    string? IdempotencyKey = null,
    JsonElement? OperatorContext = null,
    IReadOnlyDictionary<string, JsonElement>? Metadata = null,
    IReadOnlyDictionary<string, JsonElement>? Extensions = null);

/// <summary>Sanitized public HTTP 200 invoke response.</summary>
public sealed record InvokeResponse(Guid CorrelationId, string ConnectorVersion, GatewayPayload Result);

/// <summary>Canonical synthetic connector result carried inside <see cref="InvokeResponse.Result"/>.</summary>
public sealed record SyntheticSubmitResponse(bool Accepted, string VendorReference);

/// <summary>Decodes the documented canonical synthetic success without exposing a raw provider response.</summary>
public static class InvokeSuccessContract
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    /// <summary>Decodes and deserializes the bounded application result returned by the canonical connector.</summary>
    public static SyntheticSubmitResponse DeserializeSyntheticSubmit(InvokeResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (!response.Result.ContentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Gateway returned an unsupported result content type.");
        if (!string.Equals(response.Result.Encoding, "base64", StringComparison.Ordinal))
            throw new InvalidOperationException("Gateway returned an unsupported result encoding.");

        byte[] bytes;
        try { bytes = Convert.FromBase64String(response.Result.Data); }
        catch (FormatException exception) { throw new InvalidOperationException("Gateway returned invalid result data.", exception); }
        try
        {
            return JsonSerializer.Deserialize<SyntheticSubmitResponse>(bytes, WebJson)
                ?? throw new InvalidOperationException("Gateway returned no application result.");
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException("Gateway returned an invalid application result.", exception);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}

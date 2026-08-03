using System.Text.Json;

namespace SecureIntegration.Contracts;

/// <summary>Stable Local Broker operation names.</summary>
public static class BrokerOperations
{
    /// <summary>Stores a local secret.</summary>
    public const string PutLocalSecret = nameof(PutLocalSecret);

    /// <summary>Deletes a local secret.</summary>
    public const string DeleteLocalSecret = nameof(DeleteLocalSecret);

    /// <summary>Protects local data.</summary>
    public const string ProtectData = nameof(ProtectData);

    /// <summary>Unprotects local data.</summary>
    public const string UnprotectData = nameof(UnprotectData);

    /// <summary>Computes a scoped HMAC.</summary>
    public const string ComputeHmac = nameof(ComputeHmac);

    /// <summary>Invokes one configured Gateway operation.</summary>
    public const string InvokeGateway = nameof(InvokeGateway);

    /// <summary>Gets redacted Broker status.</summary>
    public const string GetBrokerStatus = nameof(GetBrokerStatus);
}

/// <summary>Handshake request sent by an SDK client.</summary>
public sealed class HandshakeRequest
{
    /// <summary>Message discriminator.</summary>
    public string Message { get; set; } = "HandshakeRequest";

    /// <summary>Supported version range.</summary>
    public ProtocolVersionRange Supported { get; set; } = new();

    /// <summary>Registered Application identifier.</summary>
    public string ApplicationRegistrationId { get; set; } = string.Empty;

    /// <summary>Random client nonce.</summary>
    public string ClientNonce { get; set; } = string.Empty;
}

/// <summary>Handshake response from the Local Broker.</summary>
public sealed class HandshakeResponse
{
    /// <summary>Message discriminator.</summary>
    public string Message { get; set; } = "HandshakeResponse";

    /// <summary>Selected version.</summary>
    public ProtocolVersion Selected { get; set; } = new();

    /// <summary>Opaque connection ID.</summary>
    public Guid ConnectionId { get; set; }

    /// <summary>Challenge echoed by every request.</summary>
    public string ServerChallenge { get; set; } = string.Empty;

    /// <summary>Negotiated hard limits.</summary>
    public ProtocolLimits Limits { get; set; } = new();
}

/// <summary>A supported protocol range.</summary>
public sealed class ProtocolVersionRange
{
    /// <summary>Required major.</summary>
    public int Major { get; set; } = IpcProtocol.Major;

    /// <summary>Minimum minor.</summary>
    public int MinMinor { get; set; }

    /// <summary>Maximum minor.</summary>
    public int MaxMinor { get; set; } = IpcProtocol.Minor;
}

/// <summary>A selected protocol version.</summary>
public sealed class ProtocolVersion
{
    /// <summary>Major version.</summary>
    public int Major { get; set; } = IpcProtocol.Major;

    /// <summary>Minor version.</summary>
    public int Minor { get; set; } = IpcProtocol.Minor;
}

/// <summary>Negotiated protocol limits.</summary>
public sealed class ProtocolLimits
{
    /// <summary>Maximum control bytes.</summary>
    public int ControlBytes { get; set; } = IpcProtocol.MaxControlBytes;

    /// <summary>Maximum standard payload bytes.</summary>
    public int PayloadBytes { get; set; } = IpcProtocol.MaxPayloadBytes;

    /// <summary>Maximum streamed payload bytes.</summary>
    public int StreamBytes { get; set; } = IpcProtocol.MaxStreamBytes;
}

/// <summary>Generic operation request.</summary>
public sealed class BrokerRequest
{
    /// <summary>Message discriminator.</summary>
    public string Message { get; set; } = "Request";

    /// <summary>Stable operation name.</summary>
    public string Operation { get; set; } = string.Empty;

    /// <summary>Semantic protocol version.</summary>
    public string ProtocolVersion { get; set; } = "1.0";

    /// <summary>Correlation ID.</summary>
    public Guid CorrelationId { get; set; }

    /// <summary>Connection challenge.</summary>
    public string ConnectionChallenge { get; set; } = string.Empty;

    /// <summary>Per-request nonce.</summary>
    public string RequestNonce { get; set; } = string.Empty;

    /// <summary>UTC deadline.</summary>
    public DateTimeOffset DeadlineUtc { get; set; }

    /// <summary>Typed operation body represented as JSON.</summary>
    public JsonElement Body { get; set; }
}

/// <summary>Generic operation response.</summary>
public sealed class BrokerResponse
{
    /// <summary>Message discriminator.</summary>
    public string Message { get; set; } = "Response";

    /// <summary>Correlation ID.</summary>
    public Guid CorrelationId { get; set; }

    /// <summary>Whether the operation succeeded.</summary>
    public bool Success { get; set; }

    /// <summary>Operation result when successful.</summary>
    public JsonElement? Result { get; set; }

    /// <summary>Redacted error when unsuccessful.</summary>
    public BrokerError? Error { get; set; }
}

/// <summary>Stable, redacted Broker error.</summary>
public sealed class BrokerError
{
    /// <summary>Machine-readable error code.</summary>
    public string Code { get; set; } = string.Empty;

    /// <summary>Error category.</summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>Whether retry can be considered.</summary>
    public bool Retryable { get; set; }
}

/// <summary>PutLocalSecret input.</summary>
public sealed class PutLocalSecretRequest
{
    /// <summary>Non-secret logical name.</summary>
    public string LogicalName { get; set; } = string.Empty;

    /// <summary>Tenant or Session. Vendor and Operator are rejected.</summary>
    public string SecretClass { get; set; } = string.Empty;

    /// <summary>Base64-encoded secret bytes.</summary>
    public string ValueBase64 { get; set; } = string.Empty;

    /// <summary>Allowed cryptographic uses.</summary>
    public string[] AllowedOperations { get; set; } = Array.Empty<string>();
}

/// <summary>Opaque local secret reference.</summary>
public sealed class LocalSecretReference
{
    /// <summary>Opaque reference.</summary>
    public string SecretRef { get; set; } = string.Empty;
}

/// <summary>DeleteLocalSecret input.</summary>
public sealed class DeleteLocalSecretRequest
{
    /// <summary>Opaque reference.</summary>
    public string SecretRef { get; set; } = string.Empty;
}

/// <summary>ProtectData input.</summary>
public sealed class ProtectDataRequest
{
    /// <summary>Application-defined purpose constrained to 128 characters.</summary>
    public string Purpose { get; set; } = string.Empty;

    /// <summary>Content type authenticated as AAD.</summary>
    public string ContentType { get; set; } = "application/octet-stream";

    /// <summary>Base64-encoded plaintext.</summary>
    public string PlaintextBase64 { get; set; } = string.Empty;
}

/// <summary>Protected data result.</summary>
public sealed class ProtectedDataResult
{
    /// <summary>Base64-encoded versioned AEAD envelope.</summary>
    public string EnvelopeBase64 { get; set; } = string.Empty;
}

/// <summary>UnprotectData input.</summary>
public sealed class UnprotectDataRequest
{
    /// <summary>Expected purpose.</summary>
    public string Purpose { get; set; } = string.Empty;

    /// <summary>Expected content type.</summary>
    public string ContentType { get; set; } = "application/octet-stream";

    /// <summary>Base64-encoded versioned AEAD envelope.</summary>
    public string EnvelopeBase64 { get; set; } = string.Empty;
}

/// <summary>Unprotected data result.</summary>
public sealed class UnprotectedDataResult
{
    /// <summary>Base64-encoded plaintext.</summary>
    public string PlaintextBase64 { get; set; } = string.Empty;
}

/// <summary>ComputeHmac input.</summary>
public sealed class ComputeHmacRequest
{
    /// <summary>Opaque local secret reference.</summary>
    public string SecretRef { get; set; } = string.Empty;

    /// <summary>Base64-encoded message.</summary>
    public string MessageBase64 { get; set; } = string.Empty;
}

/// <summary>ComputeHmac result.</summary>
public sealed class ComputeHmacResult
{
    /// <summary>Base64-encoded digest.</summary>
    public string DigestBase64 { get; set; } = string.Empty;
}

/// <summary>Gateway invocation input.</summary>
public sealed class InvokeGatewayRequest
{
    /// <summary>Configured Connector ID.</summary>
    public string ConnectorId { get; set; } = string.Empty;

    /// <summary>Configured operation ID.</summary>
    public string OperationId { get; set; } = string.Empty;

    /// <summary>Payload content type.</summary>
    public string ContentType { get; set; } = "application/json";

    /// <summary>Base64-encoded payload.</summary>
    public string PayloadBase64 { get; set; } = string.Empty;
}

/// <summary>Gateway invocation result.</summary>
public sealed class InvokeGatewayResult
{
    /// <summary>Result content type.</summary>
    public string ContentType { get; set; } = "application/json";

    /// <summary>Base64-encoded result payload.</summary>
    public string PayloadBase64 { get; set; } = string.Empty;

    /// <summary>Connector version selected by the harness/Gateway.</summary>
    public string ConnectorVersion { get; set; } = string.Empty;
}

/// <summary>Redacted Local Broker status.</summary>
public sealed class BrokerStatus
{
    /// <summary>Service status.</summary>
    public string Status { get; set; } = "healthy";

    /// <summary>Broker assembly version.</summary>
    public string Version { get; set; } = string.Empty;

    /// <summary>IPC protocol version.</summary>
    public string ProtocolVersion { get; set; } = "1.0";

    /// <summary>Whether a Gateway invoker is configured.</summary>
    public bool GatewayConfigured { get; set; }
}


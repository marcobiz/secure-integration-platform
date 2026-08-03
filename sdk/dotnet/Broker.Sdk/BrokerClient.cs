using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text.Json;
using SecureIntegration.Contracts;

namespace SecureIntegration.Broker.Sdk;

/// <summary>Options for the thin Local Broker SDK.</summary>
public sealed class BrokerClientOptions
{
    /// <summary>Named Pipe name.</summary>
    public string PipeName { get; set; } = "SecureIntegration.Broker.v1";
    /// <summary>Registered Application identifier.</summary>
    public string ApplicationRegistrationId { get; set; } = string.Empty;
    /// <summary>Connection timeout.</summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(5);
    /// <summary>Default operation timeout.</summary>
    public TimeSpan OperationTimeout { get; set; } = TimeSpan.FromSeconds(30);
}

/// <summary>Redacted exception returned by the Local Broker.</summary>
public sealed class BrokerClientException : Exception
{
    /// <summary>Creates an SDK exception from a wire error.</summary>
    public BrokerClientException(string code, string category, bool retryable) : base(code)
    {
        Code = code;
        Category = category;
        Retryable = retryable;
    }
    /// <summary>Machine-readable code.</summary>
    public string Code { get; }
    /// <summary>Error category.</summary>
    public string Category { get; }
    /// <summary>Whether retry can be considered.</summary>
    public bool Retryable { get; }
}

/// <summary>Thin asynchronous client for the versioned Local Broker Named Pipe protocol.</summary>
public sealed class BrokerClient
{
    private readonly BrokerClientOptions options;

    /// <summary>Creates a client.</summary>
    public BrokerClient(BrokerClientOptions options) => this.options = options ?? throw new ArgumentNullException(nameof(options));

    /// <summary>Stores a permitted local secret and returns an opaque reference.</summary>
    public Task<LocalSecretReference> PutLocalSecretAsync(PutLocalSecretRequest request, CancellationToken cancellationToken = default) => InvokeAsync<PutLocalSecretRequest, LocalSecretReference>(BrokerOperations.PutLocalSecret, request, cancellationToken);
    /// <summary>Deletes a local secret.</summary>
    public Task DeleteLocalSecretAsync(DeleteLocalSecretRequest request, CancellationToken cancellationToken = default) => InvokeNoResultAsync(BrokerOperations.DeleteLocalSecret, request, cancellationToken);
    /// <summary>Protects local data.</summary>
    public Task<ProtectedDataResult> ProtectDataAsync(ProtectDataRequest request, CancellationToken cancellationToken = default) => InvokeAsync<ProtectDataRequest, ProtectedDataResult>(BrokerOperations.ProtectData, request, cancellationToken);
    /// <summary>Unprotects local data.</summary>
    public Task<UnprotectedDataResult> UnprotectDataAsync(UnprotectDataRequest request, CancellationToken cancellationToken = default) => InvokeAsync<UnprotectDataRequest, UnprotectedDataResult>(BrokerOperations.UnprotectData, request, cancellationToken);
    /// <summary>Computes an HMAC without retrieving its key.</summary>
    public Task<ComputeHmacResult> ComputeHmacAsync(ComputeHmacRequest request, CancellationToken cancellationToken = default) => InvokeAsync<ComputeHmacRequest, ComputeHmacResult>(BrokerOperations.ComputeHmac, request, cancellationToken);
    /// <summary>Invokes one configured Gateway operation.</summary>
    public Task<InvokeGatewayResult> InvokeGatewayAsync(InvokeGatewayRequest request, CancellationToken cancellationToken = default) => InvokeAsync<InvokeGatewayRequest, InvokeGatewayResult>(BrokerOperations.InvokeGateway, request, cancellationToken);
    /// <summary>Gets redacted Broker status.</summary>
    public Task<BrokerStatus> GetStatusAsync(CancellationToken cancellationToken = default) => InvokeAsync<object, BrokerStatus>(BrokerOperations.GetBrokerStatus, new { }, cancellationToken);

    private async Task InvokeNoResultAsync<TRequest>(string operation, TRequest body, CancellationToken cancellationToken) =>
        _ = await InvokeAsync<TRequest, JsonElement>(operation, body, cancellationToken).ConfigureAwait(false);

    private async Task<TResponse> InvokeAsync<TRequest, TResponse>(string operation, TRequest body, CancellationToken cancellationToken)
    {
        using CancellationTokenSource connectionDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectionDeadline.CancelAfter(options.ConnectTimeout);
        using NamedPipeClientStream pipe = new(".", options.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.WriteThrough);
        await pipe.ConnectAsync(connectionDeadline.Token).ConfigureAwait(false);
        Guid handshakeCorrelation = Guid.NewGuid();
        HandshakeRequest handshake = new()
        {
            ApplicationRegistrationId = options.ApplicationRegistrationId,
            ClientNonce = Convert.ToBase64String(RandomBytes(32)),
        };
        await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(handshakeCorrelation, 0, handshake), cancellationToken).ConfigureAwait(false);
        IpcFrame handshakeFrame = await IpcFrameCodec.ReadAsync(pipe, cancellationToken).ConfigureAwait(false) ?? throw new EndOfStreamException("Broker closed during handshake.");
        HandshakeResponse handshakeResponse = IpcFrameCodec.Deserialize<HandshakeResponse>(handshakeFrame);

        Guid correlationId = Guid.NewGuid();
        BrokerRequest request = new()
        {
            Operation = operation,
            CorrelationId = correlationId,
            ConnectionChallenge = handshakeResponse.ServerChallenge,
            RequestNonce = Convert.ToBase64String(RandomBytes(24)),
            DeadlineUtc = DateTimeOffset.UtcNow.Add(options.OperationTimeout),
            Body = JsonSerializer.SerializeToElement(body, IpcProtocol.JsonOptions),
        };
        await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(correlationId, 1, request), cancellationToken).ConfigureAwait(false);
        IpcFrame responseFrame = await IpcFrameCodec.ReadAsync(pipe, cancellationToken).ConfigureAwait(false) ?? throw new EndOfStreamException("Broker closed before responding.");
        BrokerResponse response = IpcFrameCodec.Deserialize<BrokerResponse>(responseFrame);
        if (!response.Success)
        {
            BrokerError error = response.Error ?? new BrokerError { Code = "broker_error", Category = "protocol" };
            throw new BrokerClientException(error.Code, error.Category, error.Retryable);
        }

        if (response.Result is null) throw new InvalidDataException("Broker success response has no result.");
        return response.Result.Value.Deserialize<TResponse>(IpcProtocol.JsonOptions) ?? throw new InvalidDataException("Broker result was null.");
    }

    private static byte[] RandomBytes(int length)
    {
        byte[] value = new byte[length];
        using RandomNumberGenerator generator = RandomNumberGenerator.Create();
        generator.GetBytes(value);
        return value;
    }
}

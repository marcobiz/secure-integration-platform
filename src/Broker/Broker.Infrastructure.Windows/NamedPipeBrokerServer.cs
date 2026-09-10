using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using SecureIntegration.Broker.Core;
using SecureIntegration.Contracts;

namespace SecureIntegration.Broker.Infrastructure.Windows;

/// <summary>Versioned, authenticated Named Pipe host for the Local Broker.</summary>
public sealed class NamedPipeBrokerServer : IAsyncDisposable
{
    private const int DefaultMaximumPipeInstances = 32;
    private static readonly TimeSpan DefaultStalledTransferTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan AcceptFailureBackoff = TimeSpan.FromMilliseconds(100);

    private readonly BrokerOptions options;
    private readonly ApplicationAuthorizer authorizer;
    private readonly BrokerRequestDispatcher dispatcher;
    private readonly IBrokerAuditSink audit;
    private readonly TimeSpan stalledTransferTimeout;
    private readonly int maximumPipeInstances;
    private readonly SemaphoreSlim connectionSlots;
    private readonly CancellationTokenSource disposeCancellation = new();
    private readonly ConcurrentDictionary<int, Task> clients = new();
    private int clientNumber;
    private bool disposed;

    /// <summary>Creates the server.</summary>
    public NamedPipeBrokerServer(BrokerOptions options, ApplicationAuthorizer authorizer, BrokerRequestDispatcher dispatcher, IBrokerAuditSink audit)
        : this(options, authorizer, dispatcher, audit, DefaultStalledTransferTimeout, DefaultMaximumPipeInstances)
    {
    }

    internal NamedPipeBrokerServer(BrokerOptions options, ApplicationAuthorizer authorizer, BrokerRequestDispatcher dispatcher, IBrokerAuditSink audit, TimeSpan stalledTransferTimeout, int maximumPipeInstances)
    {
        this.options = options;
        this.authorizer = authorizer;
        this.dispatcher = dispatcher;
        this.audit = audit ?? throw new ArgumentNullException(nameof(audit));
        if (stalledTransferTimeout <= TimeSpan.Zero || stalledTransferTimeout > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(stalledTransferTimeout));
        if (maximumPipeInstances is < 1 or > 254)
            throw new ArgumentOutOfRangeException(nameof(maximumPipeInstances));
        this.stalledTransferTimeout = stalledTransferTimeout;
        this.maximumPipeInstances = maximumPipeInstances;
        connectionSlots = new SemaphoreSlim(maximumPipeInstances, maximumPipeInstances);
    }

    /// <summary>Accepts connections until cancellation.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using CancellationTokenSource serverCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, disposeCancellation.Token);
        CancellationToken token = serverCancellation.Token;
        while (!token.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            bool slotAcquired = false;
            try
            {
                await connectionSlots.WaitAsync(token).ConfigureAwait(false);
                slotAcquired = true;
                pipe = CreatePipe();
                await pipe.WaitForConnectionAsync(token).ConfigureAwait(false);
                int number = Interlocked.Increment(ref clientNumber);
                Task task = HandleClientAsync(pipe, token);
                clients[number] = task;
                _ = task.ContinueWith(
                    completed =>
                    {
                        clients.TryRemove(number, out _);
                        _ = connectionSlots.Release();
                    },
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
                pipe = null;
                slotAcquired = false;
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                pipe?.Dispose();
                if (slotAcquired) _ = connectionSlots.Release();
                break;
            }
            catch (IOException)
            {
                pipe?.Dispose();
                if (slotAcquired) _ = connectionSlots.Release();
                try { await Task.Delay(AcceptFailureBackoff, token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
            }
            finally
            {
                pipe?.Dispose();
            }
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (disposed) return;
        disposed = true;
        await disposeCancellation.CancelAsync().ConfigureAwait(false);
        try { await Task.WhenAll(clients.Values).ConfigureAwait(false); }
        finally
        {
            disposeCancellation.Dispose();
            connectionSlots.Dispose();
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken serverCancellation)
    {
        await using (pipe.ConfigureAwait(false))
        {
            string auditApplicationId = "unidentified";
            Guid auditCorrelationId = Guid.Empty;
            try
            {
                IpcFrame handshakeFrame = await WithStalledTransferDeadlineAsync(pipe, token => IpcFrameCodec.ReadAsync(pipe, token), serverCancellation).ConfigureAwait(false) ?? throw new EndOfStreamException();
                HandshakeRequest handshake = IpcFrameCodec.Deserialize<HandshakeRequest>(handshakeFrame);
                auditApplicationId = SafeAuditIdentifier(handshake.ApplicationRegistrationId);
                auditCorrelationId = handshakeFrame.CorrelationId;
                using CallerIdentity caller = NamedPipeCallerIdentity.Capture(pipe);
                if (handshakeFrame.Type != IpcFrameType.Control || handshakeFrame.Sequence != 0 || handshakeFrame.CorrelationId == Guid.Empty || handshake.Message != "HandshakeRequest" || handshake.Supported.Major != IpcProtocol.Major || handshake.Supported.MinMinor > IpcProtocol.Minor || handshake.Supported.MaxMinor < IpcProtocol.Minor || !ValidNonce(handshake.ClientNonce, 16, 64))
                {
                    throw new BrokerException("protocol_version_not_supported", "protocol");
                }

                ApplicationPolicy policy = authorizer.AuthorizeApplication(handshake.ApplicationRegistrationId, caller);
                string challenge = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                HandshakeResponse response = new() { ConnectionId = Guid.NewGuid(), ServerChallenge = challenge };
                await WriteFrameAsync(pipe, IpcFrameCodec.JsonFrame(handshakeFrame.CorrelationId, 0, response), serverCancellation).ConfigureAwait(false);
                HashSet<string> nonces = new(StringComparer.Ordinal);
                ConcurrentDictionary<Guid, RequestCancellation> activeCancellations = new();
                List<Task> activeTasks = [];
                using SemaphoreSlim writeLock = new(1, 1);
                try
                {
                    ulong expectedSequence = 1;
                    while (!serverCancellation.IsCancellationRequested && pipe.IsConnected)
                    {
                        IpcFrame? frame = await IpcFrameCodec.ReadAsync(pipe, stalledTransferTimeout, serverCancellation).ConfigureAwait(false);
                        if (frame is null) break;
                        if (frame.Sequence != expectedSequence++) throw new BrokerException("invalid_sequence", "protocol");
                        if (frame.Type == IpcFrameType.Cancel)
                        {
                            if (activeCancellations.TryGetValue(frame.CorrelationId, out RequestCancellation? target)) target.CancelByClient();
                            continue;
                        }

                        BrokerRequest request = IpcFrameCodec.Deserialize<BrokerRequest>(frame);
                        if (request.CorrelationId == Guid.Empty || request.CorrelationId != frame.CorrelationId || request.ProtocolVersion != "1.0" || request.ConnectionChallenge != challenge || request.DeadlineUtc <= DateTimeOffset.UtcNow || request.DeadlineUtc > DateTimeOffset.UtcNow.AddMinutes(1) || !ValidNonce(request.RequestNonce, 16, 64) || nonces.Count >= 1024 || !nonces.Add(request.RequestNonce))
                        {
                            throw new BrokerException("invalid_request_context", "protocol");
                        }

                        if (activeCancellations.Count >= 16)
                        {
                            activeTasks.Add(WriteResponseAsync(pipe, frame, Failure(request.CorrelationId, new BrokerException("concurrency_limit_exceeded", "capacity", true)), writeLock, serverCancellation));
                            continue;
                        }

                        RequestCancellation requestCancellation = new(request.DeadlineUtc - DateTimeOffset.UtcNow, serverCancellation);
                        if (!activeCancellations.TryAdd(request.CorrelationId, requestCancellation))
                        {
                            requestCancellation.Dispose();
                            throw new BrokerException("duplicate_correlation_id", "protocol");
                        }

                        activeTasks.Add(ExecuteRequestAsync(pipe, frame, request, handshake.ApplicationRegistrationId, policy, requestCancellation, activeCancellations, writeLock, serverCancellation));
                        activeTasks.RemoveAll(static task => task.IsCompletedSuccessfully);
                    }
                }
                finally
                {
                    foreach (RequestCancellation active in activeCancellations.Values) active.CancelForShutdown();
                    await Task.WhenAll(activeTasks).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (serverCancellation.IsCancellationRequested)
            {
            }
            catch (Exception exception) when (exception is IOException or EndOfStreamException or InvalidDataException or TimeoutException or BrokerException or ObjectDisposedException or UnauthorizedAccessException)
            {
                // Connection-level failures deliberately close the pipe without echoing sensitive context.
                string errorCode = exception is BrokerException brokerException ? brokerException.Code : "connection_rejected";
                await audit.WriteAsync("Connection", auditApplicationId, auditCorrelationId, false, errorCode, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    private static BrokerResponse Failure(Guid correlationId, BrokerException exception) => new()
    {
        CorrelationId = correlationId,
        Success = false,
        Error = new BrokerError { Code = exception.Code, Category = exception.Category, Retryable = exception.Retryable },
    };

    private static bool ValidNonce(string value, int minimumBytes, int maximumBytes)
    {
        try
        {
            byte[] bytes = Convert.FromBase64String(value);
            return bytes.Length >= minimumBytes && bytes.Length <= maximumBytes;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private async Task ExecuteRequestAsync(
        NamedPipeServerStream pipe,
        IpcFrame frame,
        BrokerRequest request,
        string applicationId,
        ApplicationPolicy policy,
        RequestCancellation requestCancellation,
        ConcurrentDictionary<Guid, RequestCancellation> activeCancellations,
        SemaphoreSlim writeLock,
        CancellationToken connectionCancellation)
    {
        BrokerResponse response;
        try
        {
            response = new BrokerResponse { CorrelationId = request.CorrelationId, Success = true, Result = await dispatcher.DispatchAsync(applicationId, policy, request, requestCancellation.Token).ConfigureAwait(false) };
        }
        catch (BrokerException exception)
        {
            response = Failure(request.CorrelationId, exception);
        }
        catch (OperationCanceledException)
        {
            bool deadlineExpired = !requestCancellation.CancelledByClient && !connectionCancellation.IsCancellationRequested;
            response = Failure(request.CorrelationId, new BrokerException(deadlineExpired ? "deadline_exceeded" : "cancelled", deadlineExpired ? "timeout" : "cancelled", deadlineExpired));
        }

        await audit.WriteAsync(SafeAuditIdentifier(request.Operation), SafeAuditIdentifier(applicationId), request.CorrelationId, response.Success, response.Error?.Code, CancellationToken.None).ConfigureAwait(false);

        try
        {
            await WriteResponseAsync(pipe, frame, response, writeLock, connectionCancellation).ConfigureAwait(false);
        }
        finally
        {
            _ = activeCancellations.TryRemove(request.CorrelationId, out _);
            requestCancellation.Dispose();
        }
    }

    private async Task WriteResponseAsync(NamedPipeServerStream pipe, IpcFrame requestFrame, BrokerResponse response, SemaphoreSlim writeLock, CancellationToken cancellationToken)
    {
        await writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteFrameAsync(pipe, IpcFrameCodec.JsonFrame(requestFrame.CorrelationId, requestFrame.Sequence, response), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            writeLock.Release();
        }
    }

    private async Task WriteFrameAsync(NamedPipeServerStream pipe, IpcFrame frame, CancellationToken cancellationToken) =>
        await WithStalledTransferDeadlineAsync(pipe, token => IpcFrameCodec.WriteAsync(pipe, frame, token), cancellationToken).ConfigureAwait(false);

    private async Task<T> WithStalledTransferDeadlineAsync<T>(NamedPipeServerStream pipe, Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken)
    {
        using CancellationTokenSource transferCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        transferCancellation.CancelAfter(stalledTransferTimeout);
        using CancellationTokenRegistration registration = transferCancellation.Token.Register(static state => ((PipeStream)state!).Dispose(), pipe);
        try
        {
            return await operation(transferCancellation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (transferCancellation.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new BrokerException("ipc_transfer_timeout", "timeout", true);
        }
        catch (ObjectDisposedException) when (transferCancellation.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new BrokerException("ipc_transfer_timeout", "timeout", true);
        }
        catch (IOException) when (transferCancellation.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw new BrokerException("ipc_transfer_timeout", "timeout", true);
        }
    }

    private async Task WithStalledTransferDeadlineAsync(NamedPipeServerStream pipe, Func<CancellationToken, Task> operation, CancellationToken cancellationToken) =>
        await WithStalledTransferDeadlineAsync<object?>(pipe, async token =>
        {
            await operation(token).ConfigureAwait(false);
            return null;
        }, cancellationToken).ConfigureAwait(false);

    private sealed class RequestCancellation : IDisposable
    {
        private readonly CancellationTokenSource source;
        private int cancelledByClient;

        public RequestCancellation(TimeSpan deadline, CancellationToken connectionCancellation)
        {
            source = CancellationTokenSource.CreateLinkedTokenSource(connectionCancellation);
            source.CancelAfter(deadline);
        }

        public CancellationToken Token => source.Token;
        public bool CancelledByClient => Volatile.Read(ref cancelledByClient) != 0;
        public void CancelByClient()
        {
            Interlocked.Exchange(ref cancelledByClient, 1);
            source.Cancel();
        }

        public void CancelForShutdown() => source.Cancel();
        public void Dispose() => source.Dispose();
    }

    private static string SafeAuditIdentifier(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128 || value.Any(static character => !char.IsAsciiLetterOrDigit(character) && character is not '.' and not '-' and not '_')) return "invalid";
        return value;
    }

    private NamedPipeServerStream CreatePipe()
    {
        PipeSecurity security = new();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        SecurityIdentifier serviceSid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("The service identity has no SID.");
        security.AddAccessRule(new PipeAccessRule(serviceSid, PipeAccessRights.FullControl, AccessControlType.Allow));
        foreach (string sidValue in options.Applications.SelectMany(static application => application.AllowedUserSids).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sidValue), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        }

        return NamedPipeServerStreamAcl.Create(
            options.PipeName,
            PipeDirection.InOut,
            maximumPipeInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            0,
            0,
            security);
    }
}

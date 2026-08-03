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
    private readonly BrokerOptions options;
    private readonly ApplicationAuthorizer authorizer;
    private readonly BrokerRequestDispatcher dispatcher;
    private readonly ConcurrentDictionary<int, Task> clients = new();
    private int clientNumber;
    private bool disposed;

    /// <summary>Creates the server.</summary>
    public NamedPipeBrokerServer(BrokerOptions options, ApplicationAuthorizer authorizer, BrokerRequestDispatcher dispatcher)
    {
        this.options = options;
        this.authorizer = authorizer;
        this.dispatcher = dispatcher;
    }

    /// <summary>Accepts connections until cancellation.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = CreatePipe();
            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                int number = Interlocked.Increment(ref clientNumber);
                Task task = HandleClientAsync(pipe, cancellationToken);
                clients[number] = task;
                _ = task.ContinueWith(
                    completed => clients.TryRemove(number, out _),
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
                pipe = null;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                pipe?.Dispose();
                break;
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
        await Task.WhenAll(clients.Values).ConfigureAwait(false);
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken serverCancellation)
    {
        await using (pipe.ConfigureAwait(false))
        {
            try
            {
                IpcFrame handshakeFrame = await IpcFrameCodec.ReadAsync(pipe, serverCancellation).ConfigureAwait(false) ?? throw new EndOfStreamException();
                HandshakeRequest handshake = IpcFrameCodec.Deserialize<HandshakeRequest>(handshakeFrame);
                using CallerIdentity caller = NamedPipeCallerIdentity.Capture(pipe);
                if (handshake.Message != "HandshakeRequest" || handshake.Supported.Major != IpcProtocol.Major || handshake.Supported.MinMinor > IpcProtocol.Minor || handshake.Supported.MaxMinor < IpcProtocol.Minor)
                {
                    throw new BrokerException("protocol_version_not_supported", "protocol");
                }

                ApplicationPolicy policy = authorizer.AuthorizeApplication(handshake.ApplicationRegistrationId, caller);
                string challenge = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                HandshakeResponse response = new() { ConnectionId = Guid.NewGuid(), ServerChallenge = challenge };
                await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(handshakeFrame.CorrelationId, 0, response), serverCancellation).ConfigureAwait(false);
                HashSet<string> nonces = new(StringComparer.Ordinal);
                ConcurrentDictionary<Guid, CancellationTokenSource> activeCancellations = new();
                List<Task> activeTasks = [];
                using SemaphoreSlim writeLock = new(1, 1);
                ulong expectedSequence = 1;
                while (!serverCancellation.IsCancellationRequested && pipe.IsConnected)
                {
                    IpcFrame? frame = await IpcFrameCodec.ReadAsync(pipe, serverCancellation).ConfigureAwait(false);
                    if (frame is null) break;
                    if (frame.Sequence != expectedSequence++) throw new BrokerException("invalid_sequence", "protocol");
                    if (frame.Type == IpcFrameType.Cancel)
                    {
                        if (activeCancellations.TryGetValue(frame.CorrelationId, out CancellationTokenSource? target)) target.Cancel();
                        continue;
                    }

                    BrokerRequest request = IpcFrameCodec.Deserialize<BrokerRequest>(frame);
                    if (request.CorrelationId != frame.CorrelationId || request.ConnectionChallenge != challenge || request.DeadlineUtc <= DateTimeOffset.UtcNow || request.DeadlineUtc > DateTimeOffset.UtcNow.AddMinutes(1) || string.IsNullOrWhiteSpace(request.RequestNonce) || nonces.Count >= 1024 || !nonces.Add(request.RequestNonce))
                    {
                        throw new BrokerException("invalid_request_context", "protocol");
                    }

                    if (activeCancellations.Count >= 16)
                    {
                        activeTasks.Add(WriteResponseAsync(pipe, frame, Failure(request.CorrelationId, new BrokerException("concurrency_limit_exceeded", "capacity", true)), writeLock, serverCancellation));
                        continue;
                    }

                    CancellationTokenSource requestCancellation = CancellationTokenSource.CreateLinkedTokenSource(serverCancellation);
                    requestCancellation.CancelAfter(request.DeadlineUtc - DateTimeOffset.UtcNow);
                    if (!activeCancellations.TryAdd(request.CorrelationId, requestCancellation))
                    {
                        requestCancellation.Dispose();
                        throw new BrokerException("duplicate_correlation_id", "protocol");
                    }

                    activeTasks.Add(ExecuteRequestAsync(pipe, frame, request, handshake.ApplicationRegistrationId, policy, requestCancellation, activeCancellations, writeLock, serverCancellation));
                    activeTasks.RemoveAll(static task => task.IsCompletedSuccessfully);
                }

                foreach (CancellationTokenSource active in activeCancellations.Values) active.Cancel();
                await Task.WhenAll(activeTasks).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is IOException or EndOfStreamException or BrokerException or UnauthorizedAccessException)
            {
                // Connection-level failures deliberately close the pipe without echoing sensitive context.
            }
        }
    }

    private static BrokerResponse Failure(Guid correlationId, BrokerException exception) => new()
    {
        CorrelationId = correlationId,
        Success = false,
        Error = new BrokerError { Code = exception.Code, Category = exception.Category, Retryable = exception.Retryable },
    };

    private async Task ExecuteRequestAsync(
        NamedPipeServerStream pipe,
        IpcFrame frame,
        BrokerRequest request,
        string applicationId,
        ApplicationPolicy policy,
        CancellationTokenSource requestCancellation,
        ConcurrentDictionary<Guid, CancellationTokenSource> activeCancellations,
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
            bool deadlineExpired = DateTimeOffset.UtcNow >= request.DeadlineUtc;
            response = Failure(request.CorrelationId, new BrokerException(deadlineExpired ? "deadline_exceeded" : "cancelled", deadlineExpired ? "timeout" : "cancelled", deadlineExpired));
        }
        finally
        {
            _ = activeCancellations.TryRemove(request.CorrelationId, out _);
            requestCancellation.Dispose();
        }

        await WriteResponseAsync(pipe, frame, response, writeLock, connectionCancellation).ConfigureAwait(false);
    }

    private static async Task WriteResponseAsync(NamedPipeServerStream pipe, IpcFrame requestFrame, BrokerResponse response, SemaphoreSlim writeLock, CancellationToken cancellationToken)
    {
        await writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(requestFrame.CorrelationId, requestFrame.Sequence, response), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            writeLock.Release();
        }
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
            32,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            0,
            0,
            security);
    }
}

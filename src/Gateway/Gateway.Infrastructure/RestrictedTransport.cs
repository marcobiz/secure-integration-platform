using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Hardened one-request transport: no proxy, cookies, redirects or unbounded buffering.</summary>
public sealed class SystemRestrictedTransport(X509Certificate2Collection? customTrustRoots = null, string? pinnedServerCertificateSha256 = null) : IRestrictedTransport
{
    private const int MaximumProblemDetailsBytes = 16 * 1024;

    /// <inheritdoc />
    public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken) =>
        SendCoreAsync(request, approvedAddresses, clientCertificate, timeout, maximumResponseBytes, preserveNonSuccessResponse: false, classifyTransportFailures: false, cancellationToken);

    /// <inheritdoc />
    public Task<ExternalResponse> SendProblemDetailsAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken) =>
        SendCoreAsync(request, approvedAddresses, clientCertificate, timeout, maximumResponseBytes, preserveNonSuccessResponse: true, classifyTransportFailures: true, cancellationToken);

    /// <inheritdoc />
    public Task<ExternalResponse> SendSoapAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken) =>
        SendCoreAsync(request, approvedAddresses, null, timeout, maximumResponseBytes, preserveNonSuccessResponse: true, classifyTransportFailures: false, cancellationToken);

    private async Task<ExternalResponse> SendCoreAsync(
        HttpRequestMessage request,
        IReadOnlyList<IPAddress> approvedAddresses,
        X509Certificate2? clientCertificate,
        TimeSpan timeout,
        long maximumResponseBytes,
        bool preserveNonSuccessResponse,
        bool classifyTransportFailures,
        CancellationToken cancellationToken)
    {
        string expectedHost = request.RequestUri?.DnsSafeHost ?? throw new GatewayException("BGW-EGRESS-DESTINATION-DENIED", 500);
        SslClientAuthenticationOptions sslOptions = new() { EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 };
        int tcpConnected = 0;
        int serverCertificateAccepted = 0;
        int serverCertificateRejected = 0;
        int clientCertificateSelected = 0;
        if (customTrustRoots is { Count: > 0 })
        {
            X509Certificate2Collection trustedRoots = new(customTrustRoots);
            sslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
            {
                bool accepted = false;
                if (certificate is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                {
                    Interlocked.Exchange(ref serverCertificateRejected, 1);
                    return false;
                }
                using X509Certificate2 leaf = certificate as X509Certificate2 ?? new X509Certificate2(certificate);
                if (pinnedServerCertificateSha256 is not null)
                {
                    byte[] expected;
                    try { expected = Convert.FromHexString(pinnedServerCertificateSha256); }
                    catch (FormatException)
                    {
                        Interlocked.Exchange(ref serverCertificateRejected, 1);
                        return false;
                    }
                    accepted = expected.Length == 32 && CryptographicOperations.FixedTimeEquals(expected, SHA256.HashData(leaf.RawData));
                }
                else
                {
                    using X509Chain chain = new();
                    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    chain.ChainPolicy.CustomTrustStore.AddRange(trustedRoots);
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                    chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                    accepted = chain.Build(leaf);
                }
                if (accepted) Interlocked.Exchange(ref serverCertificateAccepted, 1);
                else Interlocked.Exchange(ref serverCertificateRejected, 1);
                return accepted;
            };
        }
        else if (classifyTransportFailures)
        {
            sslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
            {
                bool accepted = certificate is not null && errors == SslPolicyErrors.None;
                if (accepted) Interlocked.Exchange(ref serverCertificateAccepted, 1);
                else Interlocked.Exchange(ref serverCertificateRejected, 1);
                return accepted;
            };
        }
        using SocketsHttpHandler handler = new()
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = timeout,
            SslOptions = sslOptions,
            ConnectCallback = async (context, token) =>
            {
                if (!string.Equals(context.DnsEndPoint.Host, expectedHost, StringComparison.OrdinalIgnoreCase)) throw new GatewayException("BGW-EGRESS-DESTINATION-DENIED", 403);
                Exception? last = null;
                foreach (IPAddress address in approvedAddresses)
                {
                    Socket socket = new(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), token).ConfigureAwait(false);
                        Interlocked.Exchange(ref tcpConnected, 1);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (Exception exception) when (exception is SocketException or OperationCanceledException)
                    {
                        last = exception;
                        socket.Dispose();
                        if (exception is OperationCanceledException) throw;
                    }
                }
                throw new HttpRequestException("No approved destination address was reachable.", last);
            }
        };
        if (clientCertificate is not null)
        {
            handler.SslOptions.ClientCertificates = [clientCertificate];
            handler.SslOptions.LocalCertificateSelectionCallback = (_, _, _, _, _) =>
            {
                Interlocked.Exchange(ref clientCertificateSelected, 1);
                return clientCertificate;
            };
        }
        using HttpClient client = new(handler) { Timeout = Timeout.InfiniteTimeSpan };
        using CancellationTokenSource effectiveDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        effectiveDeadline.CancelAfter(timeout);
        CancellationToken effectiveToken = effectiveDeadline.Token;
        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, effectiveToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (Exception exception) when (classifyTransportFailures &&
            exception is OperationCanceledException or TimeoutException or HttpRequestException or AuthenticationException or IOException)
        {
            throw ClassifiedFailure(
                exception,
                effectiveDeadline.IsCancellationRequested,
                tcpConnected,
                serverCertificateAccepted,
                serverCertificateRejected,
                clientCertificateSelected);
        }
        using (response)
        {
        if ((int)response.StatusCode is >= 300 and < 400) throw new GatewayException("BGW-EGRESS-REDIRECT-DENIED", 502);
        bool nonSuccess = (int)response.StatusCode is < 200 or >= 300;
        if (!preserveNonSuccessResponse && nonSuccess) throw new GatewayException("BGW-EGRESS-UPSTREAM-REJECTED", 502);
        long retainedBodyLimit = classifyTransportFailures && nonSuccess
            ? Math.Min(maximumResponseBytes, MaximumProblemDetailsBytes)
            : maximumResponseBytes;
        if (response.Content.Headers.ContentLength > retainedBodyLimit)
        {
            if (classifyTransportFailures && nonSuccess)
                return new ExternalResponse((int)response.StatusCode, response.Content.Headers.ContentType?.ToString() ?? "application/octet-stream", []);
            throw new GatewayException("BGW-EGRESS-RESPONSE-TOO-LARGE", 502);
        }
        try
        {
            await using Stream input = await response.Content.ReadAsStreamAsync(effectiveToken).ConfigureAwait(false);
            using MemoryStream output = new();
            byte[] buffer = new byte[81920];
            while (true)
            {
                int read = await input.ReadAsync(buffer, effectiveToken).ConfigureAwait(false);
                if (read == 0) break;
                if (output.Length + read > retainedBodyLimit)
                {
                    if (classifyTransportFailures && nonSuccess)
                        return new ExternalResponse((int)response.StatusCode, response.Content.Headers.ContentType?.ToString() ?? "application/octet-stream", []);
                    throw new GatewayException("BGW-EGRESS-RESPONSE-TOO-LARGE", 502);
                }
                output.Write(buffer, 0, read);
            }
            return new ExternalResponse((int)response.StatusCode, response.Content.Headers.ContentType?.ToString() ?? "application/octet-stream", output.ToArray());
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (Exception exception) when (classifyTransportFailures &&
            exception is OperationCanceledException or TimeoutException or HttpRequestException or AuthenticationException or IOException)
        {
            throw ClassifiedFailure(
                exception,
                effectiveDeadline.IsCancellationRequested,
                tcpConnected,
                serverCertificateAccepted,
                serverCertificateRejected,
                clientCertificateSelected);
        }
        }
    }

    private static RestrictedTransportFailureException ClassifiedFailure(
        Exception exception,
        bool deadlineElapsed,
        int tcpConnected,
        int serverCertificateAccepted,
        int serverCertificateRejected,
        int clientCertificateSelected)
    {
        RestrictedTransportFailurePhase phase = exception is OperationCanceledException or TimeoutException || deadlineElapsed
            ? RestrictedTransportFailurePhase.Timeout
            : tcpConnected == 0
                ? RestrictedTransportFailurePhase.TcpConnectFailure
                : serverCertificateRejected != 0
                    ? RestrictedTransportFailurePhase.TlsServerValidationFailure
                    : serverCertificateAccepted != 0 && clientCertificateSelected != 0
                        ? RestrictedTransportFailurePhase.MutualTlsClientAuthenticationFailure
                        : RestrictedTransportFailurePhase.TransportFailureOther;
        return new(phase);
    }
}

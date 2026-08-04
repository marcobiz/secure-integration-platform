using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Hardened one-request transport: no proxy, cookies, redirects or unbounded buffering.</summary>
public sealed class SystemRestrictedTransport : IRestrictedTransport
{
    /// <inheritdoc />
    public async Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
    {
        string expectedHost = request.RequestUri?.DnsSafeHost ?? throw new GatewayException("BGW-EGRESS-DESTINATION-DENIED", 500);
        using SocketsHttpHandler handler = new()
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = timeout,
            SslOptions = new SslClientAuthenticationOptions { EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 },
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
        if (clientCertificate is not null) handler.SslOptions.ClientCertificates = [clientCertificate];
        using HttpClient client = new(handler) { Timeout = timeout };
        using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if ((int)response.StatusCode is >= 300 and < 400) throw new GatewayException("BGW-EGRESS-REDIRECT-DENIED", 502);
        if ((int)response.StatusCode is < 200 or >= 300) throw new GatewayException("BGW-EGRESS-UPSTREAM-REJECTED", 502);
        if (response.Content.Headers.ContentLength > maximumResponseBytes) throw new GatewayException("BGW-EGRESS-RESPONSE-TOO-LARGE", 502);
        await using Stream input = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using MemoryStream output = new();
        byte[] buffer = new byte[81920];
        while (true)
        {
            int read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (output.Length + read > maximumResponseBytes) throw new GatewayException("BGW-EGRESS-RESPONSE-TOO-LARGE", 502);
            output.Write(buffer, 0, read);
        }
        return new ExternalResponse((int)response.StatusCode, response.Content.Headers.ContentType?.ToString() ?? "application/octet-stream", output.ToArray());
    }
}

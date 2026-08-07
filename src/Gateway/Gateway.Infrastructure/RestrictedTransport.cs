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
    /// <inheritdoc />
    public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken) =>
        SendCoreAsync(request, approvedAddresses, clientCertificate, timeout, maximumResponseBytes, preserveSoapFault: false, cancellationToken);

    /// <inheritdoc />
    public Task<ExternalResponse> SendSoapAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken) =>
        SendCoreAsync(request, approvedAddresses, null, timeout, maximumResponseBytes, preserveSoapFault: true, cancellationToken);

    private async Task<ExternalResponse> SendCoreAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, bool preserveSoapFault, CancellationToken cancellationToken)
    {
        string expectedHost = request.RequestUri?.DnsSafeHost ?? throw new GatewayException("BGW-EGRESS-DESTINATION-DENIED", 500);
        SslClientAuthenticationOptions sslOptions = new() { EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 };
        if (customTrustRoots is { Count: > 0 })
        {
            X509Certificate2Collection trustedRoots = new(customTrustRoots);
            sslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
            {
                if (certificate is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
                using X509Certificate2 leaf = certificate as X509Certificate2 ?? new X509Certificate2(certificate);
                if (pinnedServerCertificateSha256 is not null)
                {
                    byte[] expected;
                    try { expected = Convert.FromHexString(pinnedServerCertificateSha256); }
                    catch (FormatException) { return false; }
                    return expected.Length == 32 && CryptographicOperations.FixedTimeEquals(expected, SHA256.HashData(leaf.RawData));
                }
                using X509Chain chain = new();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.AddRange(trustedRoots);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                return chain.Build(leaf);
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
            handler.SslOptions.LocalCertificateSelectionCallback = (_, _, _, _, _) => clientCertificate;
        }
        using HttpClient client = new(handler) { Timeout = Timeout.InfiniteTimeSpan };
        using CancellationTokenSource effectiveDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        effectiveDeadline.CancelAfter(timeout);
        CancellationToken effectiveToken = effectiveDeadline.Token;
        using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, effectiveToken).ConfigureAwait(false);
        if ((int)response.StatusCode is >= 300 and < 400) throw new GatewayException("BGW-EGRESS-REDIRECT-DENIED", 502);
        if (!preserveSoapFault && ((int)response.StatusCode is < 200 or >= 300)) throw new GatewayException("BGW-EGRESS-UPSTREAM-REJECTED", 502);
        if (response.Content.Headers.ContentLength > maximumResponseBytes) throw new GatewayException("BGW-EGRESS-RESPONSE-TOO-LARGE", 502);
        await using Stream input = await response.Content.ReadAsStreamAsync(effectiveToken).ConfigureAwait(false);
        using MemoryStream output = new();
        byte[] buffer = new byte[81920];
        while (true)
        {
            int read = await input.ReadAsync(buffer, effectiveToken).ConfigureAwait(false);
            if (read == 0) break;
            if (output.Length + read > maximumResponseBytes) throw new GatewayException("BGW-EGRESS-RESPONSE-TOO-LARGE", 502);
            output.Write(buffer, 0, read);
        }
        return new ExternalResponse((int)response.StatusCode, response.Content.Headers.ContentType?.ToString() ?? "application/octet-stream", output.ToArray());
    }
}

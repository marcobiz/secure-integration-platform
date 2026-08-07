using System.Net;
using SecureIntegration.Authentication.CertificateSigning;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Adapts the Gateway DNS boundary to the certificate-signing primitive.</summary>
public sealed class AuthenticationHostResolverAdapter(IHostResolver inner) : IAuthenticationHostResolver
{
    /// <inheritdoc />
    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => inner.ResolveAsync(host, cancellationToken);
}

/// <summary>Adapts the Gateway restricted transport without exposing the certificate to Connectors.</summary>
public sealed class PurposeBoundMutualTlsTransportAdapter(IRestrictedTransport inner) : IPurposeBoundMutualTlsTransport
{
    /// <inheritdoc />
    public async Task<MutualTlsTransportResponse> SendAsync(
        HttpRequestMessage request,
        IReadOnlyList<IPAddress> approvedAddresses,
        MutualTlsCertificateLease certificateLease,
        TimeSpan timeout,
        long maximumResponseBytes,
        CancellationToken cancellationToken)
    {
        ExternalResponse response = await inner.SendAsync(
            request,
            approvedAddresses,
            certificateLease.TakeCertificate(),
            timeout,
            maximumResponseBytes,
            cancellationToken).ConfigureAwait(false);
        return new(response.StatusCode, response.ContentType, response.Body);
    }
}

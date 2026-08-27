using System.Net;
using System.Security.Cryptography.X509Certificates;
using SecureIntegration.Authentication.CertificateSigning;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Adapts the Gateway DNS boundary to the certificate-signing primitive.</summary>
public sealed class AuthenticationHostResolverAdapter(IHostResolver inner, bool classifyFailures = false) : IAuthenticationHostResolver
{
    /// <inheritdoc />
    public async Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        try
        {
            return await inner.ResolveAsync(host, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (classifyFailures && exception is OperationCanceledException or TimeoutException)
        {
            throw new RestrictedTransportFailureException(RestrictedTransportFailurePhase.Timeout);
        }
        catch (Exception) when (classifyFailures)
        {
            throw new RestrictedTransportFailureException(RestrictedTransportFailurePhase.DnsFailure);
        }
    }
}

/// <summary>Adapts the Gateway restricted transport without exposing the certificate to Connectors.</summary>
public sealed class PurposeBoundMutualTlsTransportAdapter(IRestrictedTransport inner, bool preserveProblemDetails = false) : IPurposeBoundMutualTlsTransport
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
        X509Certificate2 certificate = certificateLease.TakeCertificate();
        ExternalResponse response = preserveProblemDetails
            ? await inner.SendProblemDetailsAsync(request, approvedAddresses, certificate, timeout, maximumResponseBytes, cancellationToken).ConfigureAwait(false)
            : await inner.SendAsync(request, approvedAddresses, certificate, timeout, maximumResponseBytes, cancellationToken).ConfigureAwait(false);
        return new(response.StatusCode, response.ContentType, response.Body);
    }
}

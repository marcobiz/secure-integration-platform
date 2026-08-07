using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace SecureIntegration.Authentication.CertificateSigning;

/// <summary>Resolves destination addresses for the exact server-owned endpoint.</summary>
public interface IAuthenticationHostResolver
{
    /// <summary>Resolves all addresses used by the restricted transport.</summary>
    Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken);
}

/// <summary>Optional narrow exception for an explicitly approved private test destination.</summary>
public interface IAuthenticationPrivateDestinationAllowance
{
    /// <summary>Returns true only for an explicitly server-approved host and address.</summary>
    bool IsAllowed(string host, IPAddress address);
}

/// <summary>Bounded response from the restricted one-shot mTLS transport.</summary>
public sealed record MutualTlsTransportResponse(int StatusCode, string ContentType, byte[] Body);

/// <summary>
/// Opaque, one-shot certificate authorization. It cannot be constructed by a Connector and
/// exposes no certificate or private material through its public API.
/// </summary>
public sealed class MutualTlsCertificateLease
{
    private X509Certificate2? certificate;

    internal MutualTlsCertificateLease(X509Certificate2 certificate) => this.certificate = certificate;

    internal X509Certificate2 TakeCertificate() =>
        Interlocked.Exchange(ref certificate, null) ?? throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-LEASE-CONSUMED");
}

/// <summary>Restricted transport seam whose certificate lease is opaque to Connector code.</summary>
public interface IPurposeBoundMutualTlsTransport
{
    /// <summary>Sends one bounded request using an internally authorized certificate lease.</summary>
    Task<MutualTlsTransportResponse> SendAsync(
        HttpRequestMessage request,
        IReadOnlyList<IPAddress> approvedAddresses,
        MutualTlsCertificateLease certificateLease,
        TimeSpan timeout,
        long maximumResponseBytes,
        CancellationToken cancellationToken);
}

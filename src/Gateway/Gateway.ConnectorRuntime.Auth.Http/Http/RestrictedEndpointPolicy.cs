using System.Net;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.Http;

/// <summary>Applies the Gateway SSRF and DNS policy to server-owned authentication endpoints.</summary>
public sealed class RestrictedEndpointPolicy(IHostResolver resolver, IPrivateDestinationAllowance? privateDestinationAllowance = null)
{
    /// <summary>Validates HTTPS shape and resolves the exact approved address set used by restricted transport.</summary>
    public async Task<IReadOnlyList<IPAddress>> ResolveAsync(Uri endpoint, CancellationToken cancellationToken)
    {
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(endpoint.UserInfo) || !string.IsNullOrEmpty(endpoint.Fragment))
            throw new GatewayException("BGW-EGRESS-DESTINATION-DENIED", 403);
        IPAddress[] addresses = await resolver.ResolveAsync(endpoint.DnsSafeHost, cancellationToken).ConfigureAwait(false);
        if (addresses.Length == 0 || addresses.Any(address => IsForbiddenAddress(address) && privateDestinationAllowance?.IsAllowed(endpoint.DnsSafeHost, address) != true))
            throw new GatewayException("BGW-EGRESS-DESTINATION-DENIED", 403);
        return addresses;
    }

    private static bool IsForbiddenAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return true;
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && (address.GetAddressBytes()[0] & 0xfe) == 0xfc) return true;
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            byte[] bytes = address.GetAddressBytes();
            return bytes[0] is 0 or 10 or 127 || bytes[0] >= 224 || (bytes[0] == 169 && bytes[1] == 254) || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) || (bytes[0] == 192 && bytes[1] == 168) || (bytes[0] == 100 && bytes[1] is >= 64 and <= 127);
        }
        return address.IsIPv4MappedToIPv6 && IsForbiddenAddress(address.MapToIPv4());
    }
}

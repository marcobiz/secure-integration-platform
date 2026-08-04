using System.Collections.Concurrent;
using System.Net;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>System UTC clock.</summary>
public sealed class SystemGatewayClock : IGatewayClock
{
    /// <inheritdoc />
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

/// <summary>Single-node challenge store allowed by ADR-0008 for the initial enrollment boundary.</summary>
public sealed class InMemoryEnrollmentChallengeStore : IEnrollmentChallengeStore
{
    private readonly ConcurrentDictionary<Guid, EnrollmentChallenge> challenges = new();

    /// <inheritdoc />
    public EnrollmentChallenge Create(Guid activationCodeId, byte[] publicKeySpki, DateTimeOffset now, TimeSpan lifetime)
    {
        byte[] challengeBytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        EnrollmentChallenge challenge = new(Guid.NewGuid(), activationCodeId, challengeBytes, publicKeySpki.ToArray(), now.Add(lifetime));
        if (!challenges.TryAdd(challenge.Id, challenge)) throw new InvalidOperationException("Cannot allocate enrollment challenge.");
        return challenge;
    }

    /// <inheritdoc />
    public EnrollmentChallenge? Consume(Guid challengeId, DateTimeOffset now)
    {
        if (!challenges.TryRemove(challengeId, out EnrollmentChallenge? challenge) || challenge.ExpiresAt <= now) return null;
        return challenge;
    }
}

/// <summary>System DNS resolver.</summary>
public sealed class SystemHostResolver : IHostResolver
{
    /// <inheritdoc />
    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Dns.GetHostAddressesAsync(host, cancellationToken);
}

/// <summary>Exact-host/CIDR exception used only for the isolated M3 synthetic network.</summary>
public sealed class M3PrivateDestinationAllowance : IPrivateDestinationAllowance
{
    private readonly string allowedHost;
    private readonly IPAddress network;
    private readonly int prefixLength;

    /// <summary>Validates one private IPv4 network; loopback and link-local remain forbidden.</summary>
    public M3PrivateDestinationAllowance(string host, string cidr)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > 253 || IPAddress.TryParse(host, out _)) throw new ArgumentException("M3 mock host must be a DNS name.", nameof(host));
        string[] parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out IPAddress? parsed) || parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || !int.TryParse(parts[1], out prefixLength) || prefixLength is < 24 or > 32) throw new ArgumentException("M3 mock CIDR must be an IPv4 /24 or narrower network.", nameof(cidr));
        allowedHost = host;
        network = parsed;
        if (!IsPrivate(parsed)) throw new ArgumentException("M3 mock CIDR must be private.", nameof(cidr));
    }

    /// <inheritdoc />
    public bool IsAllowed(string host, IPAddress address)
    {
        if (!string.Equals(host, allowedHost, StringComparison.OrdinalIgnoreCase) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || IPAddress.IsLoopback(address)) return false;
        byte[] value = address.GetAddressBytes();
        if (value[0] == 169 && value[1] == 254) return false;
        uint mask = prefixLength == 0 ? 0 : uint.MaxValue << (32 - prefixLength);
        return (ToUInt32(value) & mask) == (ToUInt32(network.GetAddressBytes()) & mask);
    }

    private static bool IsPrivate(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();
        return bytes[0] == 10 || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) || (bytes[0] == 192 && bytes[1] == 168);
    }

    private static uint ToUInt32(byte[] bytes) => ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
}

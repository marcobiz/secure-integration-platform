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

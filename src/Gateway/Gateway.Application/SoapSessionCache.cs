using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace SecureIntegration.Gateway.Application;

internal sealed class SoapSessionCache
{
    private readonly ConcurrentDictionary<string, StoredSession> sessions = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<SoapSessionCacheKey, string> currentSessions = new();
    private readonly ConcurrentDictionary<string, StoredInteraction> interactions = new(StringComparer.Ordinal);

    public OpaqueSoapSessionReference Store(SoapSessionCacheKey key, string upstreamSession, DateTimeOffset expiresAt)
    {
        string reference = NewReference();
        string digest = Digest(reference);
        StoredSession stored = new(key, reference, upstreamSession, expiresAt);
        if (!sessions.TryAdd(digest, stored)) throw new SoapAuthException("SOAP-SESSION-COLLISION");
        if (currentSessions.TryGetValue(key, out string? priorDigest)) sessions.TryRemove(priorDigest, out _);
        currentSessions[key] = digest;
        return new OpaqueSoapSessionReference(reference);
    }

    public (OpaqueSoapSessionReference Reference, string UpstreamSession)? ResolveCurrent(SoapSessionCacheKey key, DateTimeOffset now)
    {
        if (!currentSessions.TryGetValue(key, out string? digest) || !sessions.TryGetValue(digest, out StoredSession? stored)) return null;
        if (stored.ExpiresAt <= now)
        {
            InvalidateDigest(key, digest);
            return null;
        }
        return (new OpaqueSoapSessionReference(stored.Reference), stored.UpstreamSession);
    }

    public string? Resolve(SoapSessionCacheKey key, OpaqueSoapSessionReference reference, DateTimeOffset now)
    {
        ValidateReference(reference.Value);
        string digest = Digest(reference.Value);
        if (!sessions.TryGetValue(digest, out StoredSession? stored) || stored.Key != key || stored.ExpiresAt <= now)
        {
            if (stored?.ExpiresAt <= now) InvalidateDigest(stored.Key, digest);
            return null;
        }
        return stored.UpstreamSession;
    }

    public void Invalidate(SoapSessionCacheKey key, OpaqueSoapSessionReference? reference = null)
    {
        if (reference is not null)
        {
            ValidateReference(reference.Value);
            string digest = Digest(reference.Value);
            if (sessions.TryGetValue(digest, out StoredSession? stored) && stored.Key == key) InvalidateDigest(key, digest);
            return;
        }
        if (currentSessions.TryRemove(key, out string? current)) sessions.TryRemove(current, out _);
    }

    public SoapInteractiveChallenge StoreInteraction(SoapSessionCacheKey key, string upstreamChallenge, DateTimeOffset expiresAt)
    {
        string reference = NewReference();
        if (!interactions.TryAdd(Digest(reference), new StoredInteraction(key, upstreamChallenge, expiresAt))) throw new SoapAuthException("SOAP-INTERACTION-COLLISION");
        return new SoapInteractiveChallenge(reference, upstreamChallenge, expiresAt);
    }

    public string ConsumeInteraction(SoapSessionCacheKey key, string interactionReference, DateTimeOffset now)
    {
        ValidateReference(interactionReference);
        string digest = Digest(interactionReference);
        if (!interactions.TryGetValue(digest, out StoredInteraction? stored) || stored.Key != key || stored.ExpiresAt <= now)
        {
            if (stored?.ExpiresAt <= now) interactions.TryRemove(digest, out _);
            throw new SoapAuthException("SOAP-INTERACTION-INVALID");
        }
        if (!((ICollection<KeyValuePair<string, StoredInteraction>>)interactions).Remove(new(digest, stored))) throw new SoapAuthException("SOAP-INTERACTION-INVALID");
        return stored.UpstreamChallenge;
    }

    private void InvalidateDigest(SoapSessionCacheKey key, string digest)
    {
        sessions.TryRemove(digest, out _);
        currentSessions.TryGetValue(key, out string? current);
        if (string.Equals(current, digest, StringComparison.Ordinal)) currentSessions.TryRemove(key, out _);
    }

    private static string NewReference() => Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
    private static string Digest(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static void ValidateReference(string value)
    {
        if (value.Length is < 40 or > 64 || value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_')))
            throw new SoapAuthException("SOAP-OPAQUE-REFERENCE-INVALID");
    }

    private sealed record StoredSession(SoapSessionCacheKey Key, string Reference, string UpstreamSession, DateTimeOffset ExpiresAt);
    private sealed record StoredInteraction(SoapSessionCacheKey Key, string UpstreamChallenge, DateTimeOffset ExpiresAt);
}

internal sealed record SoapSessionCacheKey(
    Guid TenantId,
    Guid InstallationId,
    Guid ApplicationId,
    Guid EnvironmentId,
    string ConnectorId,
    string ConnectorVersion,
    long EndpointRevision,
    long CredentialRevision,
    string ProfileId);

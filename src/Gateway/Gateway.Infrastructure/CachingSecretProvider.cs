using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Short-lived in-process cache that never exposes cached values outside the secret boundary.</summary>
public sealed class CachingSecretValueProvider(ISecretValueProvider inner, TimeSpan lifetime, TimeProvider? timeProvider = null) : ISecretValueProvider
{
    // Small hot credential set; eviction reloads through the provider, never rejects a new reference.
    private const int MaximumEntries = 256;
    private readonly Dictionary<string, CacheEntry> entries = new(StringComparer.Ordinal);
    private readonly object cacheLock = new();
    // Fixed stripes bound synchronization too. Hash collisions may serialize refreshes, not cache hits.
    // Gates live with this cache and are never removed/disposed while a waiter may retain one.
    private readonly SemaphoreSlim[] refreshLocks = Enumerable.Range(0, 64).Select(_ => new SemaphoreSlim(1, 1)).ToArray();
    private readonly TimeProvider time = timeProvider ?? TimeProvider.System;

    /// <inheritdoc />
    public async Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken)
    {
        if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromMinutes(15)) throw new InvalidOperationException("Secret cache lifetime must be between zero and fifteen minutes.");
        if (FindFresh(logicalReference) is { } cached) return cached.Value;
        SemaphoreSlim gate = refreshLocks[(uint)StringComparer.Ordinal.GetHashCode(logicalReference) % (uint)refreshLocks.Length];
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (FindFresh(logicalReference) is { } refreshed) return refreshed.Value;
            DateTimeOffset readStartedAt = time.GetUtcNow();
            string value = await inner.GetSecretAsync(logicalReference, cancellationToken).ConfigureAwait(false);
            lock (cacheLock)
            {
                RemoveExpired();
                if (!entries.ContainsKey(logicalReference) && entries.Count >= MaximumEntries)
                    entries.Remove(entries.MinBy(item => item.Value.ExpiresAt).Key);
                entries[logicalReference] = new(value, readStartedAt.Add(lifetime));
            }
            return value;
        }
        finally { gate.Release(); }
    }

    private CacheEntry? FindFresh(string logicalReference)
    {
        lock (cacheLock)
        {
            if (entries.TryGetValue(logicalReference, out CacheEntry? entry) && entry.ExpiresAt > time.GetUtcNow()) return entry;
            RemoveExpired();
            return null;
        }
    }

    // Lazy cleanup drops references on a miss/admission; it does not promise timed erasure of strings.
    private void RemoveExpired()
    {
        DateTimeOffset now = time.GetUtcNow();
        foreach (string key in entries.Where(item => item.Value.ExpiresAt <= now).Select(item => item.Key).ToArray()) entries.Remove(key);
    }

    private sealed record CacheEntry(string Value, DateTimeOffset ExpiresAt);
}

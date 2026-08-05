using System.Collections.Concurrent;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Short-lived in-process cache that never exposes cached values outside the secret boundary.</summary>
public sealed class CachingSecretValueProvider(ISecretValueProvider inner, TimeSpan lifetime, TimeProvider? timeProvider = null) : ISecretValueProvider
{
    private readonly ConcurrentDictionary<string, CacheEntry> entries = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, SemaphoreSlim> locks = new(StringComparer.Ordinal);
    private readonly TimeProvider time = timeProvider ?? TimeProvider.System;

    /// <inheritdoc />
    public async Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken)
    {
        if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromMinutes(15)) throw new InvalidOperationException("Secret cache lifetime must be between zero and fifteen minutes.");
        DateTimeOffset now = time.GetUtcNow();
        if (entries.TryGetValue(logicalReference, out CacheEntry? cached) && cached.ExpiresAt > now) return cached.Value;
        SemaphoreSlim gate = locks.GetOrAdd(logicalReference, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            now = time.GetUtcNow();
            if (entries.TryGetValue(logicalReference, out cached) && cached.ExpiresAt > now) return cached.Value;
            string value = await inner.GetSecretAsync(logicalReference, cancellationToken).ConfigureAwait(false);
            entries[logicalReference] = new(value, now.Add(lifetime));
            return value;
        }
        finally { gate.Release(); }
    }

    private sealed record CacheEntry(string Value, DateTimeOffset ExpiresAt);
}

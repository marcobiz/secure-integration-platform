using System.Collections;
using System.Reflection;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class SecretCacheRetentionTests
{
    [Fact]
    public async Task Secret_cache_bounds_distinct_references_and_releases_expired_entries_on_activity()
    {
        FakeTime time = new();
        int calls = 0;
        DelegateProvider provider = new((reference, _) => Task.FromResult(reference + Interlocked.Increment(ref calls)));
        CachingSecretValueProvider cache = new(provider, TimeSpan.FromMinutes(5), time);
        string first = await cache.GetSecretAsync("first", TestContext.Current.CancellationToken);
        Assert.Equal(first, await cache.GetSecretAsync("first", TestContext.Current.CancellationToken));
        for (int index = 0; index < 300; index++)
        {
            time.Now = time.Now.AddMilliseconds(1);
            _ = await cache.GetSecretAsync("reference-" + index, TestContext.Current.CancellationToken);
        }
        Assert.Equal(256, Entries(cache).Count);
        Assert.NotEqual(first, await cache.GetSecretAsync("first", TestContext.Current.CancellationToken));
        Assert.Equal(302, calls);
        time.Now = time.Now.AddMinutes(6);
        _ = await cache.GetSecretAsync("fresh", TestContext.Current.CancellationToken);
        Assert.Single(Entries(cache));
        Assert.Equal(64, Assert.IsType<SemaphoreSlim[]>(typeof(CachingSecretValueProvider).GetField("refreshLocks", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(cache)).Length);
    }

    [Fact]
    public async Task Secret_cache_deduplicates_concurrent_refresh_without_blocking_another_stripe()
    {
        TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int calls = 0;
        DelegateProvider provider = new(async (reference, cancellation) =>
        {
            Interlocked.Increment(ref calls);
            if (reference == "slow") await release.Task.WaitAsync(cancellation);
            return "synthetic-" + reference;
        });
        CachingSecretValueProvider cache = new(provider, TimeSpan.FromMinutes(5));
        Task<string>[] sameKey = Enumerable.Range(0, 8).Select(_ => cache.GetSecretAsync("slow", TestContext.Current.CancellationToken)).ToArray();
        string other = Enumerable.Range(0, 1000).Select(index => "other-" + index).First(value =>
            (uint)StringComparer.Ordinal.GetHashCode(value) % 64 != (uint)StringComparer.Ordinal.GetHashCode("slow") % 64);
        try
        {
            using CancellationTokenSource cancelledWaiter = new();
            Task<string> waiting = cache.GetSecretAsync("slow", cancelledWaiter.Token);
            cancelledWaiter.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
            Assert.Equal("synthetic-" + other, await cache.GetSecretAsync(other, TestContext.Current.CancellationToken).WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));
            Assert.Equal(2, calls);
        }
        finally { release.TrySetResult(); }
        Assert.All(await Task.WhenAll(sameKey), value => Assert.Equal("synthetic-slow", value));
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task Secret_cache_preserves_pre_provider_expiry_and_releases_gate_after_failure()
    {
        FakeTime time = new();
        int calls = 0;
        DelegateProvider provider = new((_, _) =>
        {
            if (++calls == 1) throw new InvalidOperationException("synthetic failure");
            time.Now = time.Now.AddMinutes(6);
            return Task.FromResult("synthetic-value-" + calls);
        });
        CachingSecretValueProvider cache = new(provider, TimeSpan.FromMinutes(5), time);
        await Assert.ThrowsAsync<InvalidOperationException>(() => cache.GetSecretAsync("key", TestContext.Current.CancellationToken));
        Assert.Equal("synthetic-value-2", await cache.GetSecretAsync("key", TestContext.Current.CancellationToken));
        Assert.Equal("synthetic-value-3", await cache.GetSecretAsync("key", TestContext.Current.CancellationToken));
    }

    // Retention is private state: inspect it without adding a production diagnostics API for the test.
    private static IDictionary Entries(CachingSecretValueProvider cache) =>
        Assert.IsAssignableFrom<IDictionary>(typeof(CachingSecretValueProvider).GetField("entries", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(cache));

    private sealed class FakeTime : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 9, 6, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class DelegateProvider(Func<string, CancellationToken, Task<string>> get) : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) => get(logicalReference, cancellationToken);
    }
}

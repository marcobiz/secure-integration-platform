using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OAuth;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.Http;

/// <summary>Lifecycle state for a bounded transport-neutral interactive challenge.</summary>
public enum InteractiveChallengeState
{
    /// <summary>The challenge may be completed once.</summary>
    Pending,
    /// <summary>The completion handler accepted the bounded artifact.</summary>
    Completed,
    /// <summary>The absolute lifetime elapsed.</summary>
    Expired,
    /// <summary>The challenge was invalidated.</summary>
    Invalidated
}

/// <summary>Opaque challenge that may be presented by a trusted UX adapter.</summary>
public sealed class InteractiveChallenge
{
    internal InteractiveChallenge(string opaqueInteractionReference, string opaqueChallenge, Guid correlationId, DateTimeOffset expiresAt, InteractiveChallengeState state)
    {
        OpaqueInteractionReference = opaqueInteractionReference;
        OpaqueChallenge = opaqueChallenge;
        CorrelationId = correlationId;
        ExpiresAt = expiresAt;
        State = state;
    }
    /// <summary>Opaque one-time interaction reference.</summary>
    [JsonIgnore] public string OpaqueInteractionReference { get; }
    /// <summary>Opaque challenge value presented out of band.</summary>
    [JsonIgnore] public string OpaqueChallenge { get; }
    /// <summary>Original authenticated invocation correlation.</summary>
    public Guid CorrelationId { get; }
    /// <summary>Absolute expiry.</summary>
    public DateTimeOffset ExpiresAt { get; }
    /// <summary>State at issuance.</summary>
    public InteractiveChallengeState State { get; }
    /// <inheritdoc />
    public override string ToString() => $"InteractiveChallenge(CorrelationId={CorrelationId:D}, ExpiresAt={ExpiresAt:O}, State={State})";
}

/// <summary>Server-side profile bounds for one characterized interactive challenge.</summary>
public sealed class InteractiveChallengeProfile
{
    /// <summary>Creates server-owned bounds for a characterized challenge.</summary>
    public InteractiveChallengeProfile(string profileId, TimeSpan lifetime, int maximumCompletionArtifactBytes)
    {
        ProfileId = profileId;
        Lifetime = lifetime;
        MaximumCompletionArtifactBytes = maximumCompletionArtifactBytes;
        Validate();
    }
    /// <summary>Logical profile identifier.</summary>
    public string ProfileId { get; }
    /// <summary>Maximum challenge lifetime.</summary>
    public TimeSpan Lifetime { get; }
    /// <summary>Maximum accepted completion artifact size.</summary>
    public int MaximumCompletionArtifactBytes { get; }
    internal void Validate()
    {
        if (!OAuthValidation.Identifier(ProfileId) || Lifetime < TimeSpan.FromMinutes(1) || Lifetime > TimeSpan.FromMinutes(30) || MaximumCompletionArtifactBytes is < 1 or > 4096)
            throw OAuthFailures.Configuration();
    }
    /// <inheritdoc />
    public override string ToString() => $"InteractiveChallengeProfile(ProfileId={ProfileId})";
}

/// <summary>Server-owned completion callback; presentation transports never implement this capability.</summary>
public interface IInteractiveChallengeCompletionHandler
{
    /// <summary>Consumes one bounded sensitive artifact without returning it to the caller.</summary>
    Task CompleteAsync(OAuthResolvedExecutionContext context, string profileId, ReadOnlyMemory<byte> artifact, CancellationToken cancellationToken);
}

/// <summary>Bounded in-memory AP-02 challenge store with expiry and single-completion enforcement.</summary>
public sealed class InteractiveChallengeStore
{
    private readonly object sync = new();
    private readonly Dictionary<string, Entry> entries = new(StringComparer.Ordinal);
    private readonly int capacity;
    private readonly IGatewayClock clock;

    /// <summary>Creates a bounded challenge store. No completion artifact is retained.</summary>
    public InteractiveChallengeStore(int capacity, IGatewayClock clock)
    {
        if (capacity is < 1 or > 100_000) throw new ArgumentOutOfRangeException(nameof(capacity));
        this.capacity = capacity;
        this.clock = clock;
    }

    /// <summary>Issues an opaque reference and challenge correlated to the immutable execution context.</summary>
    public InteractiveChallenge Request(OAuthResolvedExecutionContext resolvedContext, InteractiveChallengeProfile profile)
    {
        ArgumentNullException.ThrowIfNull(resolvedContext);
        OutboundAuthContext context = resolvedContext.Authority;
        profile.Validate();
        if (context.Deadline <= clock.UtcNow) throw OAuthFailures.Rejected();
        string reference = OpaqueValue();
        string challenge = OpaqueValue();
        DateTimeOffset expiresAt = Min(clock.UtcNow + profile.Lifetime, context.Deadline);
        lock (sync)
        {
            PruneExpired();
            EnsureCapacity();
            entries.Add(reference, new(context, profile.ProfileId, Hash(challenge), expiresAt, InteractiveChallengeState.Pending, clock.UtcNow));
        }
        return new(reference, challenge, context.CorrelationId, expiresAt, InteractiveChallengeState.Pending);
    }

    /// <summary>Returns metadata-only state for presentation polling.</summary>
    public InteractiveChallengeState Poll(OAuthResolvedExecutionContext resolvedContext, string opaqueInteractionReference)
    {
        ArgumentNullException.ThrowIfNull(resolvedContext);
        OutboundAuthContext context = resolvedContext.Authority;
        lock (sync)
        {
            if (!entries.TryGetValue(opaqueInteractionReference, out Entry? entry) || entry.ContextKey != ContextKey(context) || entry.CorrelationId != context.CorrelationId) throw OAuthFailures.Rejected();
            if (entry.ExpiresAt <= clock.UtcNow && entry.State == InteractiveChallengeState.Pending) entry.State = InteractiveChallengeState.Expired;
            entry.LastAccess = clock.UtcNow;
            return entry.State;
        }
    }

    /// <summary>Completes once through a server-owned handler; replay and cross-context use fail closed.</summary>
    public async Task CompleteAsync(OAuthResolvedExecutionContext resolvedContext, InteractiveChallengeProfile profile, string opaqueInteractionReference, string opaqueChallenge, ReadOnlyMemory<byte> completionArtifact, IInteractiveChallengeCompletionHandler handler, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolvedContext);
        OutboundAuthContext context = resolvedContext.Authority;
        profile.Validate();
        if (completionArtifact.Length is < 1 || completionArtifact.Length > profile.MaximumCompletionArtifactBytes) throw OAuthFailures.Rejected();
        Entry entry;
        lock (sync)
        {
            if (!entries.TryGetValue(opaqueInteractionReference, out entry!) || entry.ContextKey != ContextKey(context) || entry.CorrelationId != context.CorrelationId || !string.Equals(entry.ProfileId, profile.ProfileId, StringComparison.Ordinal) || entry.State != InteractiveChallengeState.Pending)
                throw OAuthFailures.Rejected();
            if (entry.ExpiresAt <= clock.UtcNow)
            {
                entry.State = InteractiveChallengeState.Expired;
                throw OAuthFailures.Rejected();
            }
            byte[] candidate = Hash(opaqueChallenge);
            bool accepted = CryptographicOperations.FixedTimeEquals(entry.ChallengeHash, candidate);
            CryptographicOperations.ZeroMemory(candidate);
            if (!accepted) throw OAuthFailures.Rejected();
            entry.State = InteractiveChallengeState.Invalidated; // reserve before side effects
        }
        try
        {
            await handler.CompleteAsync(resolvedContext, profile.ProfileId, completionArtifact, cancellationToken).ConfigureAwait(false);
            lock (sync) entry.State = InteractiveChallengeState.Completed;
        }
        catch
        {
            lock (sync) entry.State = InteractiveChallengeState.Invalidated;
            throw;
        }
    }

    /// <summary>Invalidates a matching challenge immediately.</summary>
    public void Invalidate(OAuthResolvedExecutionContext resolvedContext, string opaqueInteractionReference)
    {
        ArgumentNullException.ThrowIfNull(resolvedContext);
        OutboundAuthContext context = resolvedContext.Authority;
        lock (sync)
            if (entries.TryGetValue(opaqueInteractionReference, out Entry? entry) && entry.ContextKey == ContextKey(context) && entry.CorrelationId == context.CorrelationId) entry.State = InteractiveChallengeState.Invalidated;
    }

    private void PruneExpired()
    {
        foreach ((string key, Entry entry) in entries.Where(value => value.Value.ExpiresAt <= clock.UtcNow).ToArray())
        {
            CryptographicOperations.ZeroMemory(entry.ChallengeHash);
            entries.Remove(key);
        }
    }

    private void EnsureCapacity()
    {
        if (entries.Count < capacity) return;
        KeyValuePair<string, Entry> oldest = entries.MinBy(value => value.Value.LastAccess);
        CryptographicOperations.ZeroMemory(oldest.Value.ChallengeHash);
        entries.Remove(oldest.Key);
    }

    private static string OpaqueValue() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Hash(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));
    private static DateTimeOffset Min(DateTimeOffset left, DateTimeOffset right) => left <= right ? left : right;
    private static string ContextKey(OutboundAuthContext context) => string.Join('\n', context.TenantId, context.InstallationId, context.ApplicationId, context.EnvironmentId, context.ConnectorVersionId,
        context.ConnectorId, context.ConnectorVersion, context.OperationId, context.AuthBindingRevision, context.EndpointRevision, context.SecretRevision, context.ResourceStamp);

    private sealed class Entry(OutboundAuthContext context, string profileId, byte[] challengeHash, DateTimeOffset expiresAt, InteractiveChallengeState state, DateTimeOffset lastAccess)
    {
        internal string ContextKey { get; } = InteractiveChallengeStore.ContextKey(context);
        internal Guid CorrelationId { get; } = context.CorrelationId;
        internal string ProfileId { get; } = profileId;
        internal byte[] ChallengeHash { get; } = challengeHash;
        internal DateTimeOffset ExpiresAt { get; } = expiresAt;
        internal InteractiveChallengeState State { get; set; } = state;
        internal DateTimeOffset LastAccess { get; set; } = lastAccess;
    }
}

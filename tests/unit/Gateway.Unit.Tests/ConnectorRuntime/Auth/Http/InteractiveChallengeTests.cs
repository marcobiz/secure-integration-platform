using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.Http;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OAuth;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests.ConnectorRuntime.Auth.Http;

public sealed class InteractiveChallengeTests
{
    [Fact]
    public async Task M6_UT_Challenge_is_transport_neutral_correlated_single_use_and_artifact_is_not_retained()
    {
        MutableClock clock = new(DateTimeOffset.UtcNow);
        InteractiveChallengeStore store = new(2, clock);
        OAuthResolvedExecutionContext context = Context(clock);
        InteractiveChallengeProfile profile = new("wave1.interaction", TimeSpan.FromMinutes(5), 64);
        CapturingHandler handler = new();
        InteractiveChallenge challenge = store.Request(context, profile);

        Assert.Equal(context.CorrelationId, challenge.CorrelationId);
        Assert.Equal(InteractiveChallengeState.Pending, store.Poll(context, challenge.OpaqueInteractionReference));
        byte[] artifact = Encoding.UTF8.GetBytes("synthetic-completion");
        await store.CompleteAsync(context, profile, challenge.OpaqueInteractionReference, challenge.OpaqueChallenge, artifact, handler, TestContext.Current.CancellationToken);
        Assert.Equal(InteractiveChallengeState.Completed, store.Poll(context, challenge.OpaqueInteractionReference));
        Assert.Equal(artifact, handler.Observed);
        await Assert.ThrowsAsync<GatewayException>(() => store.CompleteAsync(context, profile, challenge.OpaqueInteractionReference, challenge.OpaqueChallenge, artifact, handler, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M6_UT_Challenge_expiry_wrong_context_wrong_challenge_and_capacity_fail_closed()
    {
        MutableClock clock = new(DateTimeOffset.UtcNow);
        InteractiveChallengeStore store = new(1, clock);
        Guid tenant = Guid.NewGuid();
        Guid correlation = Guid.NewGuid();
        OAuthResolvedExecutionContext context = Context(clock, tenant, correlation);
        InteractiveChallengeProfile profile = new("wave1.interaction", TimeSpan.FromMinutes(1), 32);
        InteractiveChallenge expired = store.Request(context, profile);
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(InteractiveChallengeState.Expired, store.Poll(context, expired.OpaqueInteractionReference));
        await Assert.ThrowsAsync<GatewayException>(() => store.CompleteAsync(context, profile, expired.OpaqueInteractionReference, expired.OpaqueChallenge, new byte[] { 1 }, new CapturingHandler(), TestContext.Current.CancellationToken));

        clock.Advance(TimeSpan.FromMinutes(-2));
        InteractiveChallenge first = store.Request(context, profile);
        InteractiveChallenge second = store.Request(context, profile);
        Assert.Throws<GatewayException>(() => store.Poll(context, first.OpaqueInteractionReference));
        Assert.Throws<GatewayException>(() => store.Poll(Context(clock, Guid.NewGuid(), correlation), second.OpaqueInteractionReference));
        await Assert.ThrowsAsync<GatewayException>(() => store.CompleteAsync(context, profile, second.OpaqueInteractionReference, second.OpaqueChallenge + "x", new byte[] { 1 }, new CapturingHandler(), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M6_UT_Challenge_completion_requires_original_correlation_and_diagnostics_are_redacted()
    {
        MutableClock clock = new(DateTimeOffset.UtcNow);
        InteractiveChallengeStore store = new(2, clock);
        Guid tenant = Guid.NewGuid();
        OAuthResolvedExecutionContext correlationA = Context(clock, tenant, Guid.NewGuid());
        OAuthResolvedExecutionContext correlationB = Context(clock, tenant, Guid.NewGuid());
        InteractiveChallengeProfile profile = new("wave1.interaction", TimeSpan.FromMinutes(5), 32);
        InteractiveChallenge challenge = store.Request(correlationA, profile);

        await Assert.ThrowsAsync<GatewayException>(() => store.CompleteAsync(correlationB, profile, challenge.OpaqueInteractionReference, challenge.OpaqueChallenge, new byte[] { 1 }, new CapturingHandler(), TestContext.Current.CancellationToken));
        Assert.Equal(InteractiveChallengeState.Pending, store.Poll(correlationA, challenge.OpaqueInteractionReference));
        string diagnostic = challenge + JsonSerializer.Serialize(challenge);
        Assert.DoesNotContain(challenge.OpaqueChallenge, diagnostic, StringComparison.Ordinal);
        Assert.DoesNotContain(challenge.OpaqueInteractionReference, diagnostic, StringComparison.Ordinal);
    }

    private static OAuthResolvedExecutionContext Context(IGatewayClock clock, Guid? tenant = null, Guid? correlation = null)
    {
        OutboundAuthContext authority = new(tenant ?? Guid.NewGuid(), Guid.Parse("10000000-0000-0000-0000-000000000001"), Guid.Parse("20000000-0000-0000-0000-000000000002"),
            Guid.Parse("30000000-0000-0000-0000-000000000003"), Guid.Parse("40000000-0000-0000-0000-000000000004"), "connector", "1.0.0", "operation", 1, 1, 1, "stamp",
            correlation ?? Guid.NewGuid(), clock.UtcNow.AddMinutes(30));
        OAuthAuthorizationCodeProfile oauth = new("wave1.interaction", new Uri("https://authorize.invalid/authorize"), new Uri("https://token.invalid/token"),
            new Uri("https://client.invalid/callback"), "client", ["scope"], null, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(5), 4096, TimeSpan.Zero, true);
        return new(authority, oauth, new ScopedOAuthSecretCapability(new FixedSecretProvider(), "exact"), new Uri("https://resource.invalid/operation"), HttpMethod.Post,
            "application/json", TimeSpan.FromSeconds(5), 4096, _ => Task.CompletedTask);
    }

    private sealed class MutableClock(DateTimeOffset now) : IGatewayClock
    {
        public DateTimeOffset UtcNow { get; private set; } = now;
        internal void Advance(TimeSpan value) => UtcNow += value;
    }

    private sealed class FixedSecretProvider : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) => Task.FromResult("synthetic");
    }

    private sealed class CapturingHandler : IInteractiveChallengeCompletionHandler
    {
        internal byte[]? Observed { get; private set; }
        public Task CompleteAsync(OAuthResolvedExecutionContext context, string profileId, ReadOnlyMemory<byte> artifact, CancellationToken cancellationToken)
        {
            Observed = artifact.ToArray();
            return Task.CompletedTask;
        }
    }
}

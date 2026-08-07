using System.Text;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.Http;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OAuth;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests.ConnectorRuntime.Auth.Http;

public sealed class InteractiveChallengeTests
{
    [Fact]
    public async Task M6_UT_Challenge_is_transport_neutral_correlated_single_use_and_artifact_is_not_retained()
    {
        MutableClock clock = new(DateTimeOffset.UtcNow);
        InteractiveChallengeStore store = new(2, clock);
        OutboundAuthContext context = Context(clock);
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
        OutboundAuthContext context = Context(clock);
        InteractiveChallengeProfile profile = new("wave1.interaction", TimeSpan.FromMinutes(1), 32);
        InteractiveChallenge expired = store.Request(context, profile);
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(InteractiveChallengeState.Expired, store.Poll(context, expired.OpaqueInteractionReference));
        await Assert.ThrowsAsync<GatewayException>(() => store.CompleteAsync(context, profile, expired.OpaqueInteractionReference, expired.OpaqueChallenge, new byte[] { 1 }, new CapturingHandler(), TestContext.Current.CancellationToken));

        clock.Advance(TimeSpan.FromMinutes(-2));
        InteractiveChallenge first = store.Request(context, profile);
        InteractiveChallenge second = store.Request(context, profile);
        Assert.Throws<GatewayException>(() => store.Poll(context, first.OpaqueInteractionReference));
        OutboundAuthContext otherTenant = context with { TenantId = Guid.NewGuid() };
        Assert.Throws<GatewayException>(() => store.Poll(otherTenant, second.OpaqueInteractionReference));
        await Assert.ThrowsAsync<GatewayException>(() => store.CompleteAsync(context, profile, second.OpaqueInteractionReference, second.OpaqueChallenge + "x", new byte[] { 1 }, new CapturingHandler(), TestContext.Current.CancellationToken));
    }

    private static OutboundAuthContext Context(IGatewayClock clock) => new(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "connector", "1.0.0", "operation", 1, 1, 1, "stamp", Guid.NewGuid(), clock.UtcNow.AddMinutes(30));

    private sealed class MutableClock(DateTimeOffset now) : IGatewayClock
    {
        public DateTimeOffset UtcNow { get; private set; } = now;
        internal void Advance(TimeSpan value) => UtcNow += value;
    }

    private sealed class CapturingHandler : IInteractiveChallengeCompletionHandler
    {
        internal byte[]? Observed { get; private set; }
        public Task CompleteAsync(OutboundAuthContext context, string profileId, ReadOnlyMemory<byte> artifact, CancellationToken cancellationToken)
        {
            Observed = artifact.ToArray();
            return Task.CompletedTask;
        }
    }
}

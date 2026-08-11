using System.Collections;
using System.Collections.Frozen;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Synthetic.ConnectorExecutionModule;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

public sealed class CapabilityLifetimeRemediationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Wave1_SEC_external_no_IVT_fire_and_forget_capability_is_cancelled_drained_and_rejected_before_effect(bool signing)
    {
        SyntheticCapabilityLifetimeProbe.Reset();
        BlockingCapabilityDispatcher dispatcher = new(signing);
        IConnectorExecutionStrategy strategy = signing
            ? new SyntheticFireAndForgetSigningExecutionStrategy()
            : new SyntheticFireAndForgetRestrictedTransportExecutionStrategy();
        CapabilityRuntimeFixture fixture = await CapabilityRuntimeFixture.CreateAsync(strategy.Key, strategy, dispatcher);

        GatewayException failure = await Assert.ThrowsAsync<GatewayException>(() => fixture.InvokeAsync(TestContext.Current.CancellationToken));

        Assert.Equal("BGW-EGRESS-UPSTREAM-REJECTED", failure.Code);
        Assert.Equal(502, failure.StatusCode);
        Assert.False(failure.Retryable);
        Assert.Equal(failure.Code, failure.Message);
        Assert.Null(failure.InnerException);
        Assert.Equal(1, dispatcher.GatedCalls);
        Assert.Equal(0, dispatcher.PrivilegedEffects);
        Assert.Equal(0, fixture.Transport.Calls);
        Assert.True(dispatcher.LifetimeCancellationObserved);
        Assert.True(SyntheticCapabilityLifetimeProbe.RetainedOperationCompleted);
        Assert.DoesNotContain(fixture.Registry.SnapshotAuditEvents(), value =>
            value.Action == "operation.invoke" && value.Outcome == "success");
    }

    [Fact]
    public async Task Wave1_SEC_module_claims_are_incrementally_bounded_before_clone_or_signer_effect()
    {
        List<(string Name, IReadOnlyDictionary<string, JsonElement> Claims, string? Canary)> cases =
        [
            ("dishonest-count", new DishonestCountClaims(33), null),
            ("max-plus-one", Claims(33, static index => JsonSerializer.SerializeToElement(index)), null),
            ("overlong-name", new Dictionary<string, JsonElement>(StringComparer.Ordinal)
                { [new string('n', 65)] = JsonSerializer.SerializeToElement("value") }, null),
            ("oversized-string", new Dictionary<string, JsonElement>(StringComparer.Ordinal)
                { ["value"] = JsonSerializer.SerializeToElement(new string('x', 1_025) + "oversized-claim-canary") }, "oversized-claim-canary"),
            ("oversized-aggregate", Claims(32, static index => ParseNumber(4_096, index)), null),
            ("disallowed-kind", new Dictionary<string, JsonElement>(StringComparer.Ordinal)
                { ["value"] = JsonSerializer.SerializeToElement(new { nested = true }) }, null),
            ("excessive-depth", new Dictionary<string, JsonElement>(StringComparer.Ordinal)
                { ["value"] = DeepObject(64) }, null)
        ];

        foreach ((string name, IReadOnlyDictionary<string, JsonElement> claims, string? canary) in cases)
        {
            SyntheticClaimBoundsProbe.Configure(claims);
            RecordingCapabilityDispatcher dispatcher = new();
            SyntheticAdversarialClaimsExecutionStrategy strategy = new();
            CapabilityRuntimeFixture fixture = await CapabilityRuntimeFixture.CreateAsync(strategy.Key, strategy, dispatcher);

            GatewayException failure = await Assert.ThrowsAsync<GatewayException>(() => fixture.InvokeAsync(TestContext.Current.CancellationToken));

            Assert.Equal("BGW-EGRESS-AUTHENTICATION", failure.Code);
            Assert.Equal(409, failure.StatusCode);
            Assert.Equal(0, dispatcher.SigningCalls);
            Assert.DoesNotContain(fixture.Registry.SnapshotAuditEvents(), value => value.Action == "operation.invoke" && value.Outcome == "success");
            if (canary is not null) Assert.DoesNotContain(canary, failure.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain(name, failure.ToString(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Wave1_SEC_signing_slots_are_one_shot_independent_and_attempts_are_bounded()
    {
        RecordingCapabilityDispatcher dualDispatcher = new();
        SlotSequenceStrategy dual = new("synthetic-dual-once", ["primary", "secondary"]);
        CapabilityRuntimeFixture dualFixture = await CapabilityRuntimeFixture.CreateAsync(dual.Key, dual, dualDispatcher);

        _ = await dualFixture.InvokeAsync(TestContext.Current.CancellationToken);

        Assert.Equal(["primary", "secondary"], dualDispatcher.SigningSlots);

        RecordingCapabilityDispatcher repeatedDispatcher = new();
        SlotSequenceStrategy repeated = new("synthetic-repeat-slot", ["primary", "primary"]);
        CapabilityRuntimeFixture repeatedFixture = await CapabilityRuntimeFixture.CreateAsync(repeated.Key, repeated, repeatedDispatcher);
        GatewayException repeatedFailure = await Assert.ThrowsAsync<GatewayException>(() =>
            repeatedFixture.InvokeAsync(TestContext.Current.CancellationToken));

        Assert.Equal("BGW-EGRESS-AUTHENTICATION", repeatedFailure.Code);
        Assert.Equal(["primary"], repeatedDispatcher.SigningSlots);

        RecordingCapabilityDispatcher boundedDispatcher = new();
        SlotSequenceStrategy bounded = new("synthetic-slot-bound", ["primary", "secondary", "tertiary", "quaternary", "fifth"]);
        CapabilityRuntimeFixture boundedFixture = await CapabilityRuntimeFixture.CreateAsync(bounded.Key, bounded, boundedDispatcher);
        GatewayException boundedFailure = await Assert.ThrowsAsync<GatewayException>(() =>
            boundedFixture.InvokeAsync(TestContext.Current.CancellationToken));

        Assert.Equal("BGW-EGRESS-AUTHENTICATION", boundedFailure.Code);
        Assert.Equal(["primary", "secondary", "tertiary", "quaternary"], boundedDispatcher.SigningSlots);
    }

    [Fact]
    public async Task Wave1_SEC_signed_token_is_denied_post_close_and_across_invocations_before_transport()
    {
        RecordingCapabilityDispatcher dispatcher = new();
        RetainedSlotTokenStrategy strategy = new();
        CapabilityRuntimeFixture fixture = await CapabilityRuntimeFixture.CreateAsync(strategy.Key, strategy, dispatcher);

        _ = await fixture.InvokeAsync(TestContext.Current.CancellationToken);
        Assert.NotNull(strategy.RetainedBridge);
        Assert.NotNull(strategy.RetainedToken);
        _ = await Assert.ThrowsAsync<AuthorizedConnectorCapabilityFailureException>(() => strategy.RetainedBridge.CreateSignedTokenAsync(
            ConnectorSigningSlotKey.Parse("secondary"),
            new Dictionary<string, JsonElement>(StringComparer.Ordinal),
            TestContext.Current.CancellationToken));
        _ = await Assert.ThrowsAsync<AuthorizedConnectorCapabilityFailureException>(() => strategy.RetainedBridge.ExecuteRestrictedTransportAsync(
            new AuthorizedConnectorRestrictedTransportRequest("synthetic-body"u8.ToArray(), strategy.RetainedToken),
            TestContext.Current.CancellationToken));

        GatewayException crossInvocation = await Assert.ThrowsAsync<GatewayException>(() =>
            fixture.InvokeAsync(TestContext.Current.CancellationToken));

        Assert.Equal("BGW-EGRESS-AUTHENTICATION", crossInvocation.Code);
        Assert.Equal(1, dispatcher.SigningCalls);
        Assert.Equal(0, dispatcher.TransportCalls);
    }

    private static Dictionary<string, JsonElement> Claims(int count, Func<int, JsonElement> value) =>
        Enumerable.Range(0, count).ToDictionary(index => $"claim-{index:D2}", value, StringComparer.Ordinal);

    private static JsonElement ParseNumber(int length, int suffix)
    {
        string number = "1" + new string((char)('0' + suffix % 10), length - 1);
        using JsonDocument document = JsonDocument.Parse(number);
        return document.RootElement.Clone();
    }

    private static JsonElement DeepObject(int depth)
    {
        string json = new string('[', depth) + "0" + new string(']', depth);
        using JsonDocument document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = depth + 1 });
        return document.RootElement.Clone();
    }

    private sealed class DishonestCountClaims(int actualCount) : IReadOnlyDictionary<string, JsonElement>
    {
        public int Count => 1;
        public IEnumerable<string> Keys => this.Select(value => value.Key);
        public IEnumerable<JsonElement> Values => this.Select(value => value.Value);
        public JsonElement this[string key] => JsonSerializer.SerializeToElement(key);
        public bool ContainsKey(string key) => false;
        public bool TryGetValue(string key, out JsonElement value) { value = default; return false; }
        public IEnumerator<KeyValuePair<string, JsonElement>> GetEnumerator()
        {
            for (int index = 0; index < actualCount; index++)
                yield return new($"claim-{index:D2}", JsonSerializer.SerializeToElement(index));
        }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private sealed class BlockingCapabilityDispatcher(bool signing) : IAuthorizedConnectorCapabilityDispatcher
    {
        private int gatedCalls;
        private int privilegedEffects;
        private int lifetimeCancellationObserved;
        internal int GatedCalls => Volatile.Read(ref gatedCalls);
        internal int PrivilegedEffects => Volatile.Read(ref privilegedEffects);
        internal bool LifetimeCancellationObserved => Volatile.Read(ref lifetimeCancellationObserved) == 1;

        public Task<QualifiedGatewayExecutionResult> ExecuteTypedSessionHandshakeAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
            throw new InvalidOperationException();
        public Task<QualifiedGatewayExecutionResult> ExecuteComposedSoapAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
            throw new InvalidOperationException();

        public Task<string> CreateSignedTokenAsync(AuthorizedConnectorExecution execution, ConnectorSigningSlotKey signingSlot, IReadOnlyDictionary<string, JsonElement> claims, CancellationToken cancellationToken) =>
            signing ? GateAsync("synthetic-token", cancellationToken) : Task.FromResult("synthetic-token");

        public Task<QualifiedGatewayExecutionResult> ExecuteRestrictedTransportAsync(
            AuthorizedConnectorExecution execution,
            AuthorizedConnectorRestrictedTransportRequest request,
            IReadOnlyDictionary<ConnectorSigningSlotKey, AuthorizedConnectorSignedToken> signedTokens,
            CancellationToken cancellationToken) =>
            signing ? throw new InvalidOperationException() : GateAsync(new QualifiedGatewayExecutionResult(200, "application/json", "{}"u8.ToArray()), cancellationToken);

        private async Task<T> GateAsync<T>(T result, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref gatedCalls);
            SyntheticCapabilityLifetimeProbe.SignalCapabilityStarted();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                Interlocked.Exchange(ref lifetimeCancellationObserved, 1);
                throw new InvalidOperationException("synthetic-abandoned-provider-canary");
            }
            Interlocked.Increment(ref privilegedEffects);
            return result;
        }
    }

    private sealed class RecordingCapabilityDispatcher : IAuthorizedConnectorCapabilityDispatcher
    {
        private int signingCalls;
        private int transportCalls;
        private readonly List<string> signingSlots = [];
        internal int SigningCalls => Volatile.Read(ref signingCalls);
        internal int TransportCalls => Volatile.Read(ref transportCalls);
        internal string[] SigningSlots
        {
            get { lock (signingSlots) return signingSlots.ToArray(); }
        }
        public Task<QualifiedGatewayExecutionResult> ExecuteTypedSessionHandshakeAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) => throw new InvalidOperationException();
        public Task<QualifiedGatewayExecutionResult> ExecuteComposedSoapAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) => throw new InvalidOperationException();
        public Task<string> CreateSignedTokenAsync(AuthorizedConnectorExecution execution, ConnectorSigningSlotKey signingSlot, IReadOnlyDictionary<string, JsonElement> claims, CancellationToken cancellationToken)
        {
            int call = Interlocked.Increment(ref signingCalls);
            lock (signingSlots) signingSlots.Add(signingSlot.Value);
            return Task.FromResult($"synthetic-token-{call}");
        }
        public Task<QualifiedGatewayExecutionResult> ExecuteRestrictedTransportAsync(AuthorizedConnectorExecution execution, AuthorizedConnectorRestrictedTransportRequest request, IReadOnlyDictionary<ConnectorSigningSlotKey, AuthorizedConnectorSignedToken> signedTokens, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref transportCalls);
            return Task.FromResult(new QualifiedGatewayExecutionResult(200, "application/json", "{}"u8.ToArray()));
        }
    }

    private sealed class SlotSequenceStrategy(string key, IReadOnlyList<string> slots) : IConnectorExecutionStrategy
    {
        public ConnectorExecutionStrategyKey Key { get; } = ConnectorExecutionStrategyKey.Parse(key);
        public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds { get; } =
            new[] { GatewayAuthenticationKind.None }.ToFrozenSet();

        public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(
            AuthorizedConnectorExecution execution,
            CancellationToken cancellationToken)
        {
            foreach (string slot in slots)
                _ = await execution.Capabilities.CreateSignedTokenAsync(
                    ConnectorSigningSlotKey.Parse(slot),
                    new Dictionary<string, JsonElement>(StringComparer.Ordinal),
                    cancellationToken).ConfigureAwait(false);
            return new(200, "application/json", "{}"u8.ToArray());
        }
    }

    private sealed class RetainedSlotTokenStrategy : IConnectorExecutionStrategy
    {
        private int calls;
        public ConnectorExecutionStrategyKey Key { get; } = ConnectorExecutionStrategyKey.Parse("synthetic-retained-slot-token");
        public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds { get; } =
            new[] { GatewayAuthenticationKind.None }.ToFrozenSet();
        internal IAuthorizedConnectorCapabilityBridge RetainedBridge { get; private set; } = null!;
        internal AuthorizedConnectorSignedToken RetainedToken { get; private set; } = null!;

        public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(
            AuthorizedConnectorExecution execution,
            CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                RetainedBridge = execution.Capabilities;
                RetainedToken = await execution.Capabilities.CreateSignedTokenAsync(
                    new Dictionary<string, JsonElement>(StringComparer.Ordinal),
                    cancellationToken).ConfigureAwait(false);
                return new(200, "application/json", "{}"u8.ToArray());
            }
            return await execution.Capabilities.ExecuteRestrictedTransportAsync(
                new AuthorizedConnectorRestrictedTransportRequest("synthetic-body"u8.ToArray(), RetainedToken),
                cancellationToken).ConfigureAwait(false);
        }
    }

    private sealed class CapabilityRuntimeFixture(
        RestrictedEgressService runtime,
        GatewayClientPrincipal principal,
        GatewayInvokeRequest request,
        InMemoryGatewayRegistry registry,
        NeverTransport transport)
    {
        private const string ConnectorId = "capability-lifetime";
        private const string OperationId = "invoke";
        internal InMemoryGatewayRegistry Registry => registry;
        internal NeverTransport Transport => transport;

        internal Task<GatewayInvokeResponse> InvokeAsync(CancellationToken cancellationToken) =>
            runtime.InvokeAsync(principal, ConnectorId, OperationId, request, cancellationToken);

        internal static async Task<CapabilityRuntimeFixture> CreateAsync(
            ConnectorExecutionStrategyKey strategyKey,
            IConnectorExecutionStrategy strategy,
            IAuthorizedConnectorCapabilityDispatcher dispatcher)
        {
            FixedClock clock = new();
            InMemoryGatewayRegistry registry = new(clock);
            Guid tenant = Guid.NewGuid();
            Guid application = Guid.NewGuid();
            Guid environment = Guid.NewGuid();
            Guid installation = Guid.NewGuid();
            await registry.AddTenantAsync(new(tenant, "capability", "Capability", TenantStatus.Active, clock.UtcNow), TestContext.Current.CancellationToken);
            await registry.AddApplicationAsync(new(application, "capability", "Capability", ApplicationStatus.Active, "3.0.0", null, clock.UtcNow), TestContext.Current.CancellationToken);
            await registry.AddEnvironmentAsync(new(environment, "capability", "Capability", false), TestContext.Current.CancellationToken);
            await registry.AddInstallationAsync(new(installation, tenant, application, environment, InstallationStatus.Active, "3.0.0", clock.UtcNow), TestContext.Current.CancellationToken);
            await registry.AddGrantAsync(new(Guid.NewGuid(), installation, tenant, ConnectorId, OperationId, true, clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
            GatewayOperationDefinition operation = new(ConnectorId, OperationId, "1.0.0", new("https://upstream.example.test/invoke"), HttpMethod.Post,
                "application/json", GatewayAuthenticationKind.None, null, null, null, null, null, 5_000, 4_096, 4_096, false, 0, null, null, strategyKey);
            GatewayOperationCatalog catalog = new([operation]);
            GatewayInvokeRequest request = new("1.0", new("application/json", "utf8", "{}"), Guid.NewGuid());
            RegisteredInstallationIdentity identity = new(installation, tenant, application, environment,
                TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active, Guid.NewGuid(), CredentialStatus.Active,
                [1, 2, 3], clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddHours(1), "3.0.0", null);
            GatewayClientPrincipal principal = new(identity, request.CorrelationId);
            NeverTransport transport = new();
            RestrictedEgressService runtime = new(registry, catalog, new NeverSecrets(), new NeverCertificates(), new PublicResolver(),
                transport, clock, null, [strategy], dispatcher);
            return new(runtime, principal, request, registry, transport);
        }
    }

    private sealed class FixedClock : IGatewayClock
    {
        public DateTimeOffset UtcNow { get; } = new(2026, 8, 11, 12, 0, 0, TimeSpan.Zero);
    }

    private sealed class NeverSecrets : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) => throw new InvalidOperationException();
    }

    private sealed class NeverCertificates : IClientCertificateProvider
    {
        public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken) => throw new InvalidOperationException();
    }

    private sealed class PublicResolver : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { IPAddress.Parse("8.8.8.8") });
    }

    private sealed class NeverTransport : IRestrictedTransport
    {
        private int calls;
        internal int Calls => Volatile.Read(ref calls);

        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate,
            TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref calls);
            throw new InvalidOperationException();
        }
    }
}

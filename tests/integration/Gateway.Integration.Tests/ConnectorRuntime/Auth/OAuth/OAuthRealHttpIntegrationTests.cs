using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.Http;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OAuth;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.M6.SyntheticOAuthServer;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests.ConnectorRuntime.Auth.OAuth;

public sealed class OAuthRealHttpIntegrationTests
{
    [Fact]
    public async Task M6_IT_OAuth_real_HTTPS_authorization_bearer_cache_refresh_and_redaction()
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5));
        (OAuthAuthorizationChallenge challenge, string code, string state) = await fixture.AuthorizeAsync();
        OAuthTokenSessionReference session = await fixture.Client.CompleteAuthorizationAsync(fixture.Resolved, challenge.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken);

        ExternalResponse accepted = await fixture.Client.SendAuthenticatedAsync(fixture.Resolved, session, ReadOnlyMemory<byte>.Empty, TestContext.Current.CancellationToken);
        Assert.Equal(200, accepted.StatusCode);
        Assert.Equal(1, fixture.Server.ResourceRequestCount);
        Assert.Equal(1, fixture.Client.CachedSessionCount);

        fixture.Clock.Advance(TimeSpan.FromMinutes(6));
        Assert.Equal(200, (await fixture.Client.SendAuthenticatedAsync(fixture.Resolved, session, ReadOnlyMemory<byte>.Empty, TestContext.Current.CancellationToken)).StatusCode);
        Assert.Equal(2, fixture.Server.TokenRequestCount);
        Assert.Equal(2, fixture.Server.ResourceRequestCount);

        string auditText = JsonSerializer.Serialize(fixture.Audit.Records);
        Assert.DoesNotContain(code, auditText, StringComparison.Ordinal);
        Assert.DoesNotContain(state, auditText, StringComparison.Ordinal);
        Assert.All(fixture.Audit.Records, record => Assert.Equal(fixture.Resolved.CorrelationId, record.CorrelationId));
    }

    [Theory]
    [InlineData("invalid-response", "BGW-EGRESS-AUTHENTICATION")]
    [InlineData("wrong-content-type", "BGW-EGRESS-AUTHENTICATION")]
    [InlineData("expired-token", "BGW-EGRESS-AUTHENTICATION")]
    [InlineData("malicious-redirect", "BGW-EGRESS-REDIRECT-DENIED")]
    public async Task M6_IT_OAuth_invalid_token_responses_and_redirect_fail_sanitized(string mode, string expectedCode)
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5), expirySkew: TimeSpan.FromSeconds(2));
        (OAuthAuthorizationChallenge challenge, string code, string state) = await fixture.AuthorizeAsync(mode: mode);
        GatewayException error = await Assert.ThrowsAsync<GatewayException>(() => fixture.Client.CompleteAuthorizationAsync(fixture.Resolved, challenge.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken));
        Assert.Equal(expectedCode, error.Code);
        Assert.DoesNotContain(code, error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(state, error.ToString(), StringComparison.Ordinal);
        Assert.Equal(OAuthAuthorizationState.Failed, fixture.Client.PollAuthorization(fixture.Resolved, challenge.OpaqueAttemptReference));
    }

    [Fact]
    public async Task M6_IT_OAuth_state_replay_expired_code_and_snapshot_rotation_fail_closed()
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5));
        (OAuthAuthorizationChallenge mismatch, string mismatchCode, string mismatchState) = await fixture.AuthorizeAsync();
        await Assert.ThrowsAsync<GatewayException>(() => fixture.Client.CompleteAuthorizationAsync(fixture.Resolved, mismatch.OpaqueAttemptReference, mismatchCode, mismatchState + "x", TestContext.Current.CancellationToken));
        Assert.Equal(OAuthAuthorizationState.Failed, fixture.Client.PollAuthorization(fixture.Resolved, mismatch.OpaqueAttemptReference));

        (OAuthAuthorizationChallenge expired, string expiredCode, string expiredState) = await fixture.AuthorizeAsync(mode: "expired-code");
        await Assert.ThrowsAsync<GatewayException>(() => fixture.Client.CompleteAuthorizationAsync(fixture.Resolved, expired.OpaqueAttemptReference, expiredCode, expiredState, TestContext.Current.CancellationToken));

        (OAuthAuthorizationChallenge completed, string code, string state) = await fixture.AuthorizeAsync();
        OAuthTokenSessionReference session = await fixture.Client.CompleteAuthorizationAsync(fixture.Resolved, completed.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<GatewayException>(() => fixture.Client.CompleteAuthorizationAsync(fixture.Resolved, completed.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken));

        fixture.RotateSnapshot();
        await Assert.ThrowsAsync<GatewayException>(() => fixture.Client.SendAuthenticatedAsync(fixture.Resolved, session, ReadOnlyMemory<byte>.Empty, TestContext.Current.CancellationToken));
        Assert.Equal(0, fixture.Server.ResourceRequestCount);
    }

    [Fact]
    public async Task M6_IT_OAuth_SSRF_endpoint_manipulation_and_disabled_secret_never_reach_transport()
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5));
        RecordingTransport transport = new();
        OAuthAuthorizationCodeClient client = fixture.NewClient(new FixedResolver(IPAddress.Parse("169.254.169.254")), transport);
        await Assert.ThrowsAsync<GatewayException>(() => client.BeginAuthorizationAsync(fixture.Resolved, TestContext.Current.CancellationToken));
        Assert.Equal(0, transport.Calls);

        fixture.Secret.Throw = true;
        OAuthAuthorizationCodeClient disabledClient = fixture.NewClient(new FixedResolver(IPAddress.Loopback), transport);
        (OAuthAuthorizationChallenge challenge, string code, string state) = await fixture.AuthorizeAsync(disabledClient);
        GatewayException error = await Assert.ThrowsAsync<GatewayException>(() => disabledClient.CompleteAuthorizationAsync(fixture.Resolved, challenge.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-EGRESS-AUTHENTICATION", error.Code);
        Assert.Equal(0, transport.Calls);
    }

    [Fact]
    public async Task M6_IT_OAuth_cache_is_bounded_and_refresh_is_single_flight()
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5));
        CapturingAudit audit = new();
        OAuthAuthorizationCodeClient client = fixture.NewClient(new FixedResolver(IPAddress.Loopback), fixture.RestrictedTransport, audit, tokenCapacity: 1);
        OAuthResolvedExecutionContext firstContext = await fixture.ResolveAsync();
        (OAuthAuthorizationChallenge firstChallenge, string firstCode, string firstState) = await fixture.AuthorizeAsync(client, firstContext);
        OAuthTokenSessionReference first = await client.CompleteAuthorizationAsync(firstContext, firstChallenge.OpaqueAttemptReference, firstCode, firstState, TestContext.Current.CancellationToken);
        OAuthResolvedExecutionContext secondContext = await fixture.ResolveAsync(Guid.NewGuid());
        (OAuthAuthorizationChallenge secondChallenge, string secondCode, string secondState) = await fixture.AuthorizeAsync(client, secondContext);
        OAuthTokenSessionReference second = await client.CompleteAuthorizationAsync(secondContext, secondChallenge.OpaqueAttemptReference, secondCode, secondState, TestContext.Current.CancellationToken);
        Assert.Equal(1, client.CachedSessionCount);
        await Assert.ThrowsAsync<GatewayException>(() => client.SendAuthenticatedAsync(firstContext, first, ReadOnlyMemory<byte>.Empty, TestContext.Current.CancellationToken));

        fixture.Clock.Advance(TimeSpan.FromMinutes(6));
        ExternalResponse[] results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => client.SendAuthenticatedAsync(secondContext, second, ReadOnlyMemory<byte>.Empty, TestContext.Current.CancellationToken)));
        Assert.All(results, result => Assert.Equal(200, result.StatusCode));
        Assert.Single(audit.Records, record => record.Action == "oauth.token.refresh" && record.Outcome == "success");
    }

    [Theory]
    [InlineData("profile")]
    [InlineData("token-endpoint")]
    [InlineData("client-secret-reference")]
    [InlineData("scope-audience")]
    public async Task M6_IT_OAuth_Published_authority_rejects_profile_endpoint_secret_and_scope_substitution_before_provider_use(string substitution)
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5));
        if (substitution == "profile")
        {
            await Assert.ThrowsAsync<GatewayException>(() => fixture.ResolveAsync(profileId: "attacker.profile"));
            Assert.Equal(0, fixture.Secret.Calls);
            Assert.Equal(0, fixture.Server.TokenRequestCount);
            return;
        }

        OAuthResolvedExecutionContext original = await fixture.ResolveAsync();
        (OAuthAuthorizationChallenge challenge, string code, string state) = await fixture.AuthorizeAsync(fixture.Client, original);
        fixture.SubstituteSnapshot(substitution);
        await Assert.ThrowsAsync<GatewayException>(() => fixture.Client.CompleteAuthorizationAsync(original, challenge.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken));
        Assert.Equal(0, fixture.Secret.Calls);
        Assert.Equal(0, fixture.Server.TokenRequestCount);
    }

    [Fact]
    public async Task M6_IT_OAuth_completion_and_poll_require_original_correlation_but_session_cache_does_not()
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5));
        OAuthResolvedExecutionContext correlationA = await fixture.ResolveAsync(Guid.NewGuid());
        OAuthResolvedExecutionContext correlationB = await fixture.ResolveAsync(Guid.NewGuid());
        (OAuthAuthorizationChallenge challenge, string code, string state) = await fixture.AuthorizeAsync(fixture.Client, correlationA);

        await Assert.ThrowsAsync<GatewayException>(() => fixture.Client.CompleteAuthorizationAsync(correlationB, challenge.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken));
        Assert.Throws<GatewayException>(() => fixture.Client.PollAuthorization(correlationB, challenge.OpaqueAttemptReference));
        OAuthTokenSessionReference session = await fixture.Client.CompleteAuthorizationAsync(correlationA, challenge.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken);
        Assert.Equal(200, (await fixture.Client.SendAuthenticatedAsync(correlationB, session, ReadOnlyMemory<byte>.Empty, TestContext.Current.CancellationToken)).StatusCode);
    }

    [Fact]
    public async Task M6_IT_OAuth_bearer_is_destination_bound_and_attacker_server_receives_zero_requests()
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5));
        await using Fixture attacker = await Fixture.CreateAsync(TimeSpan.FromMinutes(5));
        (OAuthAuthorizationChallenge challenge, string code, string state) = await fixture.AuthorizeAsync();
        OAuthTokenSessionReference session = await fixture.Client.CompleteAuthorizationAsync(fixture.Resolved, challenge.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken);

        Assert.Equal(200, (await fixture.Client.SendAuthenticatedAsync(fixture.Resolved, session, ReadOnlyMemory<byte>.Empty, TestContext.Current.CancellationToken)).StatusCode);
        Assert.Equal(1, fixture.Server.ResourceRequestCount);
        Assert.Equal(0, attacker.Server.ResourceRequestCount);
        Assert.DoesNotContain(typeof(OAuthAuthorizationCodeClient).GetMethods().Where(method => method.IsPublic).SelectMany(method => method.GetParameters()), parameter => parameter.ParameterType == typeof(HttpRequestMessage));
    }

    [Fact]
    public async Task M6_IT_OAuth_refresh_result_is_tombstoned_when_snapshot_rotates_during_await()
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5));
        BlockingTransport blocking = new(fixture.RestrictedTransport);
        OAuthAuthorizationCodeClient client = fixture.NewClient(new FixedResolver(IPAddress.Loopback), blocking);
        OAuthResolvedExecutionContext context = await fixture.ResolveAsync();
        (OAuthAuthorizationChallenge challenge, string code, string state) = await fixture.AuthorizeAsync(client, context);
        OAuthTokenSessionReference session = await client.CompleteAuthorizationAsync(context, challenge.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken);
        fixture.Clock.Advance(TimeSpan.FromMinutes(6));
        blocking.BlockNextSend();

        Task<ExternalResponse> stale = client.SendAuthenticatedAsync(context, session, ReadOnlyMemory<byte>.Empty, TestContext.Current.CancellationToken);
        await blocking.WaitUntilBlockedAsync();
        fixture.RotateSnapshot();
        client.InvalidateConnector(context.ConnectorId);
        blocking.Release();

        await Assert.ThrowsAsync<GatewayException>(() => stale);
        Assert.Equal(0, fixture.Server.ResourceRequestCount);
        Assert.Equal(0, client.CachedSessionCount);
    }

    [Theory]
    [InlineData("?state=first&state=last")]
    [InlineData("?safe=1&%73tate=last")]
    [InlineData("?client_id=first&safe=1")]
    [InlineData("?code_challenge_method=S256")]
    public void M6_UT_OAuth_authorization_endpoint_rejects_reserved_parameter_smuggling(string query)
    {
        Assert.Throws<GatewayException>(() => new OAuthAuthorizationCodeProfile("wave1.synthetic", new Uri("https://authorize.invalid/authorize" + query), new Uri("https://token.invalid/token"),
            new Uri("https://client.invalid/callback"), "client", ["scope"], "audience", TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(5), 4096, TimeSpan.Zero, true));
    }

    [Fact]
    public async Task M6_IT_OAuth_authorization_endpoint_is_user_agent_navigation_not_server_side_fetch()
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5));
        OAuthAuthorizationChallenge challenge = await fixture.Client.BeginAuthorizationAsync(fixture.Resolved, TestContext.Current.CancellationToken);
        Assert.Equal("external-user-agent-navigation", challenge.PresentationKind);
        Assert.Equal(0, fixture.Server.AuthorizationRequestCount);
        Assert.Equal(0, fixture.Server.TokenRequestCount);
        Assert.Equal(0, fixture.Server.ResourceRequestCount);
    }

    [Fact]
    public async Task M6_IT_OAuth_diagnostics_ToString_JSON_exceptions_and_assertion_rendering_are_redacted()
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5));
        (OAuthAuthorizationChallenge challenge, string code, string state) = await fixture.AuthorizeAsync();
        OAuthTokenSessionReference session = await fixture.Client.CompleteAuthorizationAsync(fixture.Resolved, challenge.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken);
        SyntheticOAuthServerOptions options = fixture.Options;
        string rendered = string.Join('\n', challenge.ToString(), JsonSerializer.Serialize(challenge), session.ToString(), JsonSerializer.Serialize(session), options.ToString(), JsonSerializer.Serialize(options), fixture.Resolved.ToString(), JsonSerializer.Serialize(fixture.Resolved));
        Xunit.Sdk.EqualException assertion = Assert.Throws<Xunit.Sdk.EqualException>(() => Assert.Equal(challenge, new OAuthAuthorizationChallenge("different-reference", new Uri("https://client.invalid/?state=different-state"), challenge.CorrelationId, challenge.ExpiresAt)));
        rendered += assertion.ToString();

        foreach (string sensitive in new[] { challenge.OpaqueAttemptReference, code, state, session.Value, options.ClientSecret })
            Assert.DoesNotContain(sensitive, rendered, StringComparison.Ordinal);
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly X509Certificate2 root;
        private readonly X509Certificate2 leaf;
        private readonly Guid tenantId = Guid.NewGuid();
        private readonly Guid installationId = Guid.NewGuid();
        private readonly Guid applicationId = Guid.NewGuid();
        private readonly Guid environmentId = Guid.NewGuid();
        private readonly Guid connectorId = Guid.NewGuid();
        private readonly Guid versionId = Guid.NewGuid();
        private readonly SystemRestrictedTransport transport;

        private Fixture(SyntheticOAuthServerInstance server, SyntheticOAuthServerOptions options, X509Certificate2 root, X509Certificate2 leaf, MutableClock clock, TimeSpan expirySkew, MutableSecretProvider secret)
        {
            Server = server;
            Options = options;
            this.root = root;
            this.leaf = leaf;
            Clock = clock;
            Secret = secret;
            Audit = new CapturingAudit();
            transport = new(new X509Certificate2Collection(root));
            Snapshot = CreateSnapshot(expirySkew);
            Resolver = new((_, _, _, _) => Task.FromResult<PublishedConnectorSnapshot?>(Snapshot), Secret, Clock);
            Resolved = ResolveAsync().GetAwaiter().GetResult();
            Client = NewClient(new FixedResolver(IPAddress.Loopback), transport, Audit);
        }

        internal SyntheticOAuthServerInstance Server { get; }
        internal SyntheticOAuthServerOptions Options { get; }
        internal MutableClock Clock { get; }
        internal MutableSecretProvider Secret { get; }
        internal CapturingAudit Audit { get; }
        internal PublishedConnectorSnapshot Snapshot { get; private set; }
        internal PublishedOAuthAuthorityResolver Resolver { get; }
        internal OAuthResolvedExecutionContext Resolved { get; }
        internal OAuthAuthorizationCodeClient Client { get; }
        internal IRestrictedTransport RestrictedTransport => transport;

        internal static async Task<Fixture> CreateAsync(TimeSpan tokenLifetime, TimeSpan? expirySkew = null)
        {
            (X509Certificate2 root, X509Certificate2 leaf) = Certificates();
            string clientId = "synthetic-" + Guid.NewGuid().ToString("N");
            string secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
            SyntheticOAuthServerOptions options = new(clientId, secret, new Uri("https://client.invalid/oauth/callback"), "scope.synthetic", "audience.synthetic", TimeSpan.FromMinutes(2), tokenLifetime);
            SyntheticOAuthServerInstance server = await SyntheticOAuthServerHost.StartAsync(options, leaf, TestContext.Current.CancellationToken);
            return new(server, options, root, leaf, new MutableClock(DateTimeOffset.UtcNow), expirySkew ?? TimeSpan.FromSeconds(30), new MutableSecretProvider(secret));
        }

        internal OAuthAuthorizationCodeClient NewClient(IHostResolver resolver, IRestrictedTransport selectedTransport, IOutboundAuthAuditSink? audit = null, int tokenCapacity = 2) =>
            new(8, tokenCapacity, new RestrictedEndpointPolicy(resolver, new LoopbackAllowance()), selectedTransport, Clock, audit);

        internal async Task<OAuthResolvedExecutionContext> ResolveAsync(Guid? correlationId = null, string profileId = "wave1.synthetic") =>
            await Resolver.ResolveAsync(new OAuthAuthorizedInvocation(Principal(correlationId ?? Guid.NewGuid()), "synthetic-oauth", "invoke"), new OAuthAuthorityRequest(profileId), TestContext.Current.CancellationToken);

        internal async Task<(OAuthAuthorizationChallenge Challenge, string Code, string State)> AuthorizeAsync(OAuthAuthorizationCodeClient? client = null, OAuthResolvedExecutionContext? context = null, string? mode = null)
        {
            OAuthAuthorizationChallenge challenge = await (client ?? Client).BeginAuthorizationAsync(context ?? Resolved, TestContext.Current.CancellationToken);
            Uri uri = challenge.AuthorizationUri;
            if (mode is not null) uri = new Uri(uri.AbsoluteUri + "&synthetic_mode=" + Uri.EscapeDataString(mode));
            using HttpClientHandler handler = new() { AllowAutoRedirect = false, ServerCertificateCustomValidationCallback = (_, certificate, _, _) => certificate is not null && certificate.GetCertHashString(HashAlgorithmName.SHA256) == leaf.GetCertHashString(HashAlgorithmName.SHA256) };
            using HttpClient browser = new(handler);
            using HttpResponseMessage response = await browser.GetAsync(uri, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Dictionary<string, Microsoft.Extensions.Primitives.StringValues> callback = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
            return (challenge, callback["code"].ToString(), callback["state"].ToString());
        }

        internal void RotateSnapshot()
        {
            ConnectorBindingSet bindings = Snapshot.Bindings with { Revision = Snapshot.Bindings.Revision + 1, ChecksumSha256 = "binding-rotated" };
            Snapshot = Snapshot with { Bindings = bindings, Stamp = Snapshot.Stamp with { BindingRevision = bindings.Revision, BindingChecksumSha256 = bindings.ChecksumSha256, ResourceStampSha256 = "resource-rotated" } };
        }

        internal void SubstituteSnapshot(string substitution)
        {
            if (substitution == "client-secret-reference")
            {
                Snapshot = Snapshot with { SecretProviderReferences = new Dictionary<string, string>(StringComparer.Ordinal) { ["oauth-client-secret"] = "attacker-secret-reference" } };
                return;
            }
            using JsonDocument source = JsonDocument.Parse(Snapshot.Version.CanonicalJson);
            JsonElement rootElement = source.RootElement;
            string json = Snapshot.Version.CanonicalJson;
            if (substitution == "token-endpoint")
            {
                Dictionary<string, Uri> endpoints = Snapshot.Bindings.Endpoints.ToDictionary(value => value.Key, value => value.Value, StringComparer.Ordinal);
                endpoints["oauth-token"] = new Uri("https://attacker.example/token");
                Snapshot = Snapshot with { Bindings = Snapshot.Bindings with { Endpoints = endpoints } };
                return;
            }
            if (substitution == "scope-audience")
            {
                json = json.Replace("scope.synthetic", "scope.attacker", StringComparison.Ordinal).Replace("audience.synthetic", "audience.attacker", StringComparison.Ordinal);
                Snapshot = Snapshot with { Version = Snapshot.Version with { CanonicalJson = json } };
            }
        }

        private GatewayClientPrincipal Principal(Guid correlationId)
        {
            RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
                Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], Clock.UtcNow.AddMinutes(-1), Clock.UtcNow.AddHours(1), "1.0.0", null);
            return new(identity, correlationId);
        }

        private PublishedConnectorSnapshot CreateSnapshot(TimeSpan expirySkew)
        {
            var definition = new
            {
                connectorId = "synthetic-oauth",
                version = "1.0.0",
                operations = new[]
                {
                    new
                    {
                        operationId = "invoke",
                        endpointBinding = "protected-resource",
                        path = "/resource",
                        method = "GET",
                        timeoutMs = 5000,
                        authentication = new
                        {
                            kind = "oauthAuthorizationCode",
                            profileId = "wave1.synthetic",
                            authorizationEndpointBinding = "oauth-authorization",
                            tokenEndpointBinding = "oauth-token",
                            clientId = Options.ClientId,
                            secretBinding = "oauth-client-secret",
                            scopes = new[] { "scope.synthetic" },
                            audience = "audience.synthetic",
                            redirectUri = Options.RedirectUri.AbsoluteUri,
                            authorizationLifetimeSeconds = 300,
                            tokenRequestTimeoutMilliseconds = 5000,
                            maximumTokenResponseBytes = 16384,
                            expirySkewSeconds = (int)expirySkew.TotalSeconds,
                            allowRefresh = true
                        },
                        request = new { contentType = "application/json", maximumBytes = 4096 },
                        response = new { maximumBytes = 4096 }
                    }
                }
            };
            ConnectorVersionRecord version = new(versionId, connectorId, "synthetic-oauth", "1.0.0", "m6-test", ConnectorVersionState.Published, JsonSerializer.Serialize(definition), SHA256.HashData("definition"u8), "test", Clock.UtcNow, 1, Clock.UtcNow, Clock.UtcNow);
            ProviderResourceBinding resource = new("synthetic", "Synthetic", "Synthetic", "oauth-secret", ProviderResourceType.Secret, "OAuth client secret", environmentId,
                "synthetic-oauth", "invoke", "per-run", 11, null, null, "catalog-checksum");
            Dictionary<string, Uri> endpoints = new(StringComparer.Ordinal)
            {
                ["oauth-authorization"] = new Uri(Server.BaseAddress, "/authorize"),
                ["oauth-token"] = new Uri(Server.BaseAddress, "/token"),
                ["protected-resource"] = Server.BaseAddress
            };
            ConnectorBindingSet bindings = new(Guid.NewGuid(), connectorId, versionId, environmentId, endpoints,
                new Dictionary<string, ProviderResourceBinding>(StringComparer.Ordinal) { ["oauth-client-secret"] = resource },
                new Dictionary<string, ProviderResourceBinding>(StringComparer.Ordinal), 7, "binding-checksum", ConnectorBindingState.Active, Clock.UtcNow, "test");
            PublishedConnectorStamp stamp = new(versionId, 3, 7, "binding-checksum", "resource-stamp-11");
            return new(version, bindings, stamp, new Dictionary<string, string>(StringComparer.Ordinal) { ["oauth-client-secret"] = "exact-provider-reference" }, new Dictionary<string, string>());
        }

        public async ValueTask DisposeAsync()
        {
            await Server.DisposeAsync();
            leaf.Dispose();
            root.Dispose();
        }
    }

    private sealed class MutableClock(DateTimeOffset now) : IGatewayClock
    {
        public DateTimeOffset UtcNow { get; private set; } = now;
        internal void Advance(TimeSpan value) => UtcNow += value;
    }

    private sealed class FixedResolver(IPAddress address) : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { address });
    }

    private sealed class LoopbackAllowance : IPrivateDestinationAllowance
    {
        public bool IsAllowed(string host, IPAddress address) => address.Equals(IPAddress.Loopback) && host is "127.0.0.1" or "localhost";
    }

    private sealed class MutableSecretProvider(string value) : ISecretValueProvider
    {
        internal int Calls { get; private set; }
        internal bool Throw { get; set; }
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken)
        {
            Calls++;
            if (Throw) throw new ProviderAccessException("SYNTHETIC-DISABLED");
            Assert.Equal("exact-provider-reference", logicalReference);
            return Task.FromResult(value);
        }
    }

    private sealed class RecordingTransport : IRestrictedTransport
    {
        internal int Calls { get; private set; }
        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            Calls++;
            throw new InvalidOperationException("Transport must not be reached.");
        }
    }

    private sealed class BlockingTransport(IRestrictedTransport inner) : IRestrictedTransport
    {
        private TaskCompletionSource started = NewSignal();
        private TaskCompletionSource release = NewSignal();
        private volatile bool block;
        internal void BlockNextSend() => block = true;
        internal Task WaitUntilBlockedAsync() => started.Task;
        internal void Release() => release.TrySetResult();
        public async Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            if (block)
            {
                block = false;
                started.TrySetResult();
                await release.Task.WaitAsync(cancellationToken);
            }
            return await inner.SendAsync(request, approvedAddresses, clientCertificate, timeout, maximumResponseBytes, cancellationToken);
        }
        private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private sealed class CapturingAudit : IOutboundAuthAuditSink
    {
        internal List<OutboundAuthAuditRecord> Records { get; } = [];
        public Task WriteAsync(OutboundAuthAuditRecord record, CancellationToken cancellationToken) { lock (Records) Records.Add(record); return Task.CompletedTask; }
    }

    private static (X509Certificate2 Root, X509Certificate2 Leaf) Certificates()
    {
        using RSA leafKey = RSA.Create(2048);
        CertificateRequest request = new("CN=localhost", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], true));
        SubjectAlternativeNameBuilder san = new();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        using X509Certificate2 created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddHours(6));
        X509Certificate2 leaf = X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);
        return (X509CertificateLoader.LoadCertificate(leaf.RawData), leaf);
    }
}

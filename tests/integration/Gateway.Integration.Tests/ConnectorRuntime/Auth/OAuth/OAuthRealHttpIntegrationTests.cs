using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.WebUtilities;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.Http;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OAuth;
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
        OAuthTokenSessionReference session = await fixture.Client.CompleteAuthorizationAsync(fixture.Context, fixture.Profile, challenge.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken);

        using HttpRequestMessage first = new(HttpMethod.Get, new Uri(fixture.Server.BaseAddress, "/resource"));
        await fixture.Client.ApplyBearerAsync(fixture.Context, fixture.Profile, session, first, TestContext.Current.CancellationToken);
        ExternalResponse accepted = await fixture.SendResourceAsync(first);
        Assert.Equal(200, accepted.StatusCode);
        Assert.Equal(1, fixture.Client.CachedSessionCount);

        fixture.Clock.Advance(TimeSpan.FromMinutes(6));
        using HttpRequestMessage refreshed = new(HttpMethod.Get, new Uri(fixture.Server.BaseAddress, "/resource"));
        await fixture.Client.ApplyBearerAsync(fixture.Context, fixture.Profile, session, refreshed, TestContext.Current.CancellationToken);
        Assert.NotEqual(first.Headers.Authorization?.Parameter, refreshed.Headers.Authorization?.Parameter);
        Assert.Equal(200, (await fixture.SendResourceAsync(refreshed)).StatusCode);

        string auditText = System.Text.Json.JsonSerializer.Serialize(fixture.Audit.Records);
        Assert.DoesNotContain(code, auditText, StringComparison.Ordinal);
        Assert.DoesNotContain(state, auditText, StringComparison.Ordinal);
        Assert.DoesNotContain(first.Headers.Authorization!.Parameter!, auditText, StringComparison.Ordinal);
        Assert.All(fixture.Audit.Records, record => Assert.Equal(fixture.Context.CorrelationId, record.CorrelationId));
    }

    [Theory]
    [InlineData("invalid-response", "BGW-EGRESS-AUTHENTICATION")]
    [InlineData("wrong-content-type", "BGW-EGRESS-AUTHENTICATION")]
    [InlineData("expired-token", "BGW-EGRESS-AUTHENTICATION")]
    [InlineData("malicious-redirect", "BGW-EGRESS-REDIRECT-DENIED")]
    public async Task M6_IT_OAuth_invalid_token_responses_and_redirect_fail_sanitized(string mode, string expectedCode)
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5), expirySkew: TimeSpan.FromSeconds(2));
        (OAuthAuthorizationChallenge challenge, string code, string state) = await fixture.AuthorizeAsync(mode);
        GatewayException error = await Assert.ThrowsAsync<GatewayException>(() => fixture.Client.CompleteAuthorizationAsync(fixture.Context, fixture.Profile, challenge.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken));
        Assert.Equal(expectedCode, error.Code);
        Assert.DoesNotContain(code, error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(state, error.ToString(), StringComparison.Ordinal);
        Assert.Equal(OAuthAuthorizationState.Failed, fixture.Client.PollAuthorization(fixture.Context, fixture.Profile, challenge.OpaqueAttemptReference));
    }

    [Fact]
    public async Task M6_IT_OAuth_state_replay_expired_code_scope_and_secret_rotation_fail_closed()
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5));
        (OAuthAuthorizationChallenge mismatch, string mismatchCode, string mismatchState) = await fixture.AuthorizeAsync();
        await Assert.ThrowsAsync<GatewayException>(() => fixture.Client.CompleteAuthorizationAsync(fixture.Context, fixture.Profile, mismatch.OpaqueAttemptReference, mismatchCode, mismatchState + "x", TestContext.Current.CancellationToken));
        Assert.Equal(OAuthAuthorizationState.Failed, fixture.Client.PollAuthorization(fixture.Context, fixture.Profile, mismatch.OpaqueAttemptReference));

        (OAuthAuthorizationChallenge expired, string expiredCode, string expiredState) = await fixture.AuthorizeAsync("expired-code");
        await Assert.ThrowsAsync<GatewayException>(() => fixture.Client.CompleteAuthorizationAsync(fixture.Context, fixture.Profile, expired.OpaqueAttemptReference, expiredCode, expiredState, TestContext.Current.CancellationToken));

        (OAuthAuthorizationChallenge completed, string code, string state) = await fixture.AuthorizeAsync();
        OAuthTokenSessionReference session = await fixture.Client.CompleteAuthorizationAsync(fixture.Context, fixture.Profile, completed.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<GatewayException>(() => fixture.Client.CompleteAuthorizationAsync(fixture.Context, fixture.Profile, completed.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken));
        var (replayAttempt, _, replayState) = await fixture.AuthorizeAsync();
        await Assert.ThrowsAsync<GatewayException>(() => fixture.Client.CompleteAuthorizationAsync(fixture.Context, fixture.Profile, replayAttempt.OpaqueAttemptReference, code, replayState, TestContext.Current.CancellationToken));

        OAuthAuthorizationCodeProfile changedScope = fixture.ProfileWithScopes("scope.synthetic", "scope.unapproved");
        using HttpRequestMessage scopeRequest = new(HttpMethod.Get, new Uri(fixture.Server.BaseAddress, "/resource"));
        await Assert.ThrowsAsync<GatewayException>(() => fixture.Client.ApplyBearerAsync(fixture.Context, changedScope, session, scopeRequest, TestContext.Current.CancellationToken));
        Assert.Equal(0, fixture.Client.CachedSessionCount);

        (OAuthAuthorizationChallenge rotationChallenge, string rotationCode, string rotationState) = await fixture.AuthorizeAsync();
        OAuthTokenSessionReference rotationSession = await fixture.Client.CompleteAuthorizationAsync(fixture.Context, fixture.Profile, rotationChallenge.OpaqueAttemptReference, rotationCode, rotationState, TestContext.Current.CancellationToken);
        OutboundAuthContext rotated = fixture.Context with { SecretRevision = fixture.Context.SecretRevision + 1, ResourceStamp = "stamp-rotated" };
        using HttpRequestMessage rotatedRequest = new(HttpMethod.Get, new Uri(fixture.Server.BaseAddress, "/resource"));
        await Assert.ThrowsAsync<GatewayException>(() => fixture.Client.ApplyBearerAsync(rotated, fixture.Profile, rotationSession, rotatedRequest, TestContext.Current.CancellationToken));
        Assert.Equal(0, fixture.Client.CachedSessionCount);
    }

    [Fact]
    public async Task M6_IT_OAuth_SSRF_endpoint_manipulation_and_disabled_secret_never_reach_transport()
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5));
        RecordingTransport transport = new();
        OAuthAuthorizationCodeClient client = fixture.NewClient(new FixedResolver(IPAddress.Parse("169.254.169.254")), transport, fixture.Secrets);
        await Assert.ThrowsAsync<GatewayException>(() => client.BeginAuthorizationAsync(fixture.Context, fixture.Profile, TestContext.Current.CancellationToken));
        Assert.Equal(0, transport.Calls);

        ThrowingSecretProvider disabled = new();
        OAuthAuthorizationCodeClient disabledClient = fixture.NewClient(new FixedResolver(IPAddress.Loopback), transport, disabled);
        (OAuthAuthorizationChallenge challenge, string code, string state) = await fixture.AuthorizeAsync(disabledClient);
        GatewayException error = await Assert.ThrowsAsync<GatewayException>(() => disabledClient.CompleteAuthorizationAsync(fixture.Context, fixture.Profile, challenge.OpaqueAttemptReference, code, state, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-EGRESS-AUTHENTICATION", error.Code);
        Assert.Equal(0, transport.Calls);
    }

    [Fact]
    public async Task M6_IT_OAuth_cache_is_bounded_and_refresh_is_single_flight()
    {
        await using Fixture fixture = await Fixture.CreateAsync(TimeSpan.FromMinutes(5));
        CapturingAudit audit = new();
        OAuthAuthorizationCodeClient client = fixture.NewClient(new FixedResolver(IPAddress.Loopback), fixture.RestrictedTransport, fixture.Secrets, audit, tokenCapacity: 1);
        (OAuthAuthorizationChallenge firstChallenge, string firstCode, string firstState) = await fixture.AuthorizeAsync(client);
        OAuthTokenSessionReference first = await client.CompleteAuthorizationAsync(fixture.Context, fixture.Profile, firstChallenge.OpaqueAttemptReference, firstCode, firstState, TestContext.Current.CancellationToken);
        (OAuthAuthorizationChallenge secondChallenge, string secondCode, string secondState) = await fixture.AuthorizeAsync(client);
        OAuthTokenSessionReference second = await client.CompleteAuthorizationAsync(fixture.Context, fixture.Profile, secondChallenge.OpaqueAttemptReference, secondCode, secondState, TestContext.Current.CancellationToken);
        Assert.Equal(1, client.CachedSessionCount);
        using HttpRequestMessage evicted = new(HttpMethod.Get, new Uri(fixture.Server.BaseAddress, "/resource"));
        await Assert.ThrowsAsync<GatewayException>(() => client.ApplyBearerAsync(fixture.Context, fixture.Profile, first, evicted, TestContext.Current.CancellationToken));

        fixture.Clock.Advance(TimeSpan.FromMinutes(6));
        HttpRequestMessage[] requests = Enumerable.Range(0, 8).Select(_ => new HttpRequestMessage(HttpMethod.Get, new Uri(fixture.Server.BaseAddress, "/resource"))).ToArray();
        try
        {
            await Task.WhenAll(requests.Select(request => client.ApplyBearerAsync(fixture.Context, fixture.Profile, second, request, TestContext.Current.CancellationToken)));
            Assert.Single(audit.Records, record => record.Action == "oauth.token.refresh" && record.Outcome == "success");
            Assert.Single(requests.Select(request => request.Headers.Authorization?.Parameter).Distinct(StringComparer.Ordinal));
        }
        finally { foreach (HttpRequestMessage request in requests) request.Dispose(); }
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly X509Certificate2 root;
        private readonly X509Certificate2 leaf;
        private readonly SystemRestrictedTransport transport;

        private Fixture(SyntheticOAuthServerInstance server, X509Certificate2 root, X509Certificate2 leaf, string clientId, MutableClock clock, TimeSpan expirySkew, string secret)
        {
            Server = server;
            this.root = root;
            this.leaf = leaf;
            Clock = clock;
            Secrets = new FixedSecretProvider(secret);
            Audit = new CapturingAudit();
            transport = new(new X509Certificate2Collection(root));
            Profile = CreateProfile(["scope.synthetic"], clientId, expirySkew);
            Context = new(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "synthetic-oauth", "1.0.0", "invoke", 3, 7, 11, "resource-stamp-11", Guid.NewGuid(), clock.UtcNow.AddHours(1));
            Client = NewClient(new FixedResolver(IPAddress.Loopback), transport, Secrets, Audit);
        }

        internal SyntheticOAuthServerInstance Server { get; }
        internal MutableClock Clock { get; }
        internal ISecretValueProvider Secrets { get; }
        internal CapturingAudit Audit { get; }
        internal OAuthAuthorizationCodeProfile Profile { get; }
        internal OutboundAuthContext Context { get; }
        internal OAuthAuthorizationCodeClient Client { get; }
        internal IRestrictedTransport RestrictedTransport => transport;

        internal static async Task<Fixture> CreateAsync(TimeSpan tokenLifetime, TimeSpan? expirySkew = null)
        {
            (X509Certificate2 root, X509Certificate2 leaf) = Certificates();
            string clientId = "synthetic-" + Guid.NewGuid().ToString("N");
            string secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
            SyntheticOAuthServerOptions options = new(clientId, secret, new Uri("https://client.invalid/oauth/callback"), "scope.synthetic", "audience.synthetic", TimeSpan.FromMinutes(2), tokenLifetime);
            SyntheticOAuthServerInstance server = await SyntheticOAuthServerHost.StartAsync(options, leaf, TestContext.Current.CancellationToken);
            return new(server, root, leaf, clientId, new MutableClock(DateTimeOffset.UtcNow), expirySkew ?? TimeSpan.FromSeconds(30), secret);
        }

        internal OAuthAuthorizationCodeClient NewClient(IHostResolver resolver, IRestrictedTransport selectedTransport, ISecretValueProvider secretProvider, IOutboundAuthAuditSink? audit = null, int tokenCapacity = 2) =>
            new(8, tokenCapacity, secretProvider, new RestrictedEndpointPolicy(resolver, new LoopbackAllowance()), selectedTransport, Clock, audit);

        internal OAuthAuthorizationCodeProfile ProfileWithScopes(params string[] scopes) => CreateProfile(scopes, Profile.ClientId, Profile.ExpirySkew);

        internal async Task<(OAuthAuthorizationChallenge Challenge, string Code, string State)> AuthorizeAsync(string? mode = null) => await AuthorizeAsync(Client, mode);

        internal async Task<(OAuthAuthorizationChallenge Challenge, string Code, string State)> AuthorizeAsync(OAuthAuthorizationCodeClient client, string? mode = null)
        {
            OAuthAuthorizationChallenge challenge = await client.BeginAuthorizationAsync(Context, Profile, TestContext.Current.CancellationToken);
            Uri uri = challenge.AuthorizationUri;
            if (mode is not null) uri = new Uri(uri.AbsoluteUri + "&synthetic_mode=" + Uri.EscapeDataString(mode));
            using HttpClientHandler handler = new() { AllowAutoRedirect = false, ServerCertificateCustomValidationCallback = (_, certificate, _, _) => certificate is not null && certificate.GetCertHashString(HashAlgorithmName.SHA256) == leaf.GetCertHashString(HashAlgorithmName.SHA256) };
            using HttpClient browser = new(handler);
            using HttpResponseMessage response = await browser.GetAsync(uri, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Dictionary<string, Microsoft.Extensions.Primitives.StringValues> callback = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
            return (challenge, callback["code"].ToString(), callback["state"].ToString());
        }

        internal async Task<ExternalResponse> SendResourceAsync(HttpRequestMessage request)
        {
            IReadOnlyList<IPAddress> addresses = await new RestrictedEndpointPolicy(new FixedResolver(IPAddress.Loopback), new LoopbackAllowance()).ResolveAsync(request.RequestUri!, TestContext.Current.CancellationToken);
            return await transport.SendAsync(request, addresses, null, TimeSpan.FromSeconds(5), 4096, TestContext.Current.CancellationToken);
        }

        private OAuthAuthorizationCodeProfile CreateProfile(IEnumerable<string> scopes, string clientId, TimeSpan expirySkew) => new("wave1.synthetic", new Uri(Server.BaseAddress, "/authorize"), new Uri(Server.BaseAddress, "/token"), new Uri("https://client.invalid/oauth/callback"), clientId, "logical-client-secret", scopes, "audience.synthetic", TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(5), 16 * 1024, expirySkew, true);

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

    private sealed class FixedSecretProvider(string value) : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) => Task.FromResult(value);
    }

    private sealed class ThrowingSecretProvider : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) => throw new ProviderAccessException("SYNTHETIC-DISABLED");
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

    private sealed class CapturingAudit : IOutboundAuthAuditSink
    {
        internal List<OutboundAuthAuditRecord> Records { get; } = [];
        public Task WriteAsync(OutboundAuthAuditRecord record, CancellationToken cancellationToken) { Records.Add(record); return Task.CompletedTask; }
    }

    private static (X509Certificate2 Root, X509Certificate2 Leaf) Certificates()
    {
        using RSA leafKey = RSA.Create(2048);
        CertificateRequest leafRequest = new("CN=localhost", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        OidCollection eku = [new Oid("1.3.6.1.5.5.7.3.1")];
        leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
        SubjectAlternativeNameBuilder san = new();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        leafRequest.CertificateExtensions.Add(san.Build());
        using X509Certificate2 created = leafRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddHours(6));
        X509Certificate2 leaf = X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);
        X509Certificate2 root = X509CertificateLoader.LoadCertificate(leaf.RawData);
        return (root, leaf);
    }
}

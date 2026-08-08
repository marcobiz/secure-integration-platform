using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.M6.SyntheticOpaqueSessionServer;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests.ConnectorRuntime.Auth.Soap;

public sealed class OpaqueSessionHttpRealIntegrationTests
{
    private const string UpstreamSession = "synthetic-opaque-session-reference";

    [Fact]
    public async Task Wave1_IT_published_authority_projects_exactly_one_header_over_real_restricted_HTTPS()
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticOpaqueSessionServerInstance server = await SyntheticOpaqueSessionServerHost.StartAsync(
            new("X-Session-Reference", UpstreamSession, TimeSpan.FromSeconds(2)), certificates.Server, TestContext.Current.CancellationToken);
        await using RealProjectionFixture fixture = await RealProjectionFixture.CreateAsync(server.Endpoint, certificates, new LoopbackAllowance());

        OpaqueSessionHttpResponse response = await fixture.SendAsync("{}"u8.ToArray());

        Assert.Equal(200, response.StatusCode);
        Assert.Equal(1, server.Counters.Requests);
        Assert.Equal(1, server.Counters.Accepted);
        Assert.Equal(0, server.Counters.Missing + server.Counters.Wrong + server.Counters.Duplicate);
    }

    [Fact]
    public async Task Wave1_IT_real_HTTPS_delayed_response_honors_timeout_and_uses_generic_exception()
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticOpaqueSessionServerInstance server = await SyntheticOpaqueSessionServerHost.StartAsync(
            new("X-Session-Reference", UpstreamSession, TimeSpan.FromSeconds(2)), certificates.Server, TestContext.Current.CancellationToken);
        await using RealProjectionFixture fixture = await RealProjectionFixture.CreateAsync(new Uri(server.Endpoint, "/delayed"), certificates, new LoopbackAllowance(), timeout: TimeSpan.FromMilliseconds(150));

        OpaqueSessionAuthException timeout = await Assert.ThrowsAsync<OpaqueSessionAuthException>(() => fixture.SendAsync("{}"u8.ToArray()));

        Assert.Equal("SESSION-HTTP-TIMEOUT", timeout.Code);
        Assert.DoesNotContain(UpstreamSession, timeout.ToString(), StringComparison.Ordinal);
        Assert.Equal(1, server.Counters.Requests);
    }

    [Theory]
    [InlineData("rotate")]
    [InlineData("disable")]
    public async Task Wave1_IT_real_HTTPS_final_rotate_or_disable_race_sends_zero_network_requests(string mutation)
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticOpaqueSessionServerInstance server = await SyntheticOpaqueSessionServerHost.StartAsync(
            new("X-Session-Reference", UpstreamSession, TimeSpan.FromSeconds(2)), certificates.Server, TestContext.Current.CancellationToken);
        TaskCompletionSource entered = NewSignal();
        TaskCompletionSource release = NewSignal();
        async Task Hook(CancellationToken cancellationToken)
        {
            entered.TrySetResult();
            await release.Task.WaitAsync(cancellationToken);
        }
        await using RealProjectionFixture fixture = await RealProjectionFixture.CreateAsync(server.Endpoint, certificates, new LoopbackAllowance(), beforeFinalAuthorization: Hook);

        Task<OpaqueSessionHttpResponse> pending = fixture.SendAsync(new byte[1024 * 1024]);
        await entered.Task;
        if (mutation == "rotate") fixture.Snapshots.RotateCredential();
        else fixture.Snapshots.FailClosed = true;
        release.TrySetResult();

        _ = await Assert.ThrowsAsync<OpaqueSessionAuthException>(() => pending);
        Assert.Equal(0, server.Counters.Requests);
    }

    [Fact]
    public async Task Wave1_IT_attacker_destination_is_denied_before_real_HTTPS_network_dispatch()
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticOpaqueSessionServerInstance server = await SyntheticOpaqueSessionServerHost.StartAsync(
            new("X-Session-Reference", UpstreamSession, TimeSpan.FromSeconds(2)), certificates.Server, TestContext.Current.CancellationToken);
        await using RealProjectionFixture fixture = await RealProjectionFixture.CreateAsync(server.Endpoint, certificates, allowance: null);

        OpaqueSessionAuthException denied = await Assert.ThrowsAsync<OpaqueSessionAuthException>(() => fixture.SendAsync("{}"u8.ToArray()));

        Assert.Equal("SESSION-HTTP-EGRESS-DESTINATION-DENIED", denied.Code);
        Assert.Equal(0, server.Counters.Requests);
    }

    private sealed class RealProjectionFixture : IAsyncDisposable
    {
        private readonly Guid tenantId = Guid.NewGuid();
        private readonly Guid installationId = Guid.NewGuid();
        private readonly Guid applicationId = Guid.NewGuid();
        private readonly Guid environmentId = Guid.NewGuid();
        private readonly Guid versionId = Guid.NewGuid();
        private readonly Guid connectorId = Guid.NewGuid();
        private readonly SystemGatewayClock clock = new();
        private readonly CompositeTransport transport;
        private readonly SoapSessionClient soap;
        private readonly OpaqueSessionHttpClient http;
        private readonly PublishedOpaqueSessionAuthorityResolver authority;
        private readonly OpaqueSessionReference session;

        private RealProjectionFixture(Uri endpoint, CertificateFixture certificates, IPrivateDestinationAllowance? allowance, TimeSpan timeout, Func<CancellationToken, Task>? beforeFinalAuthorization)
        {
            SystemRestrictedTransport restricted = new(new X509Certificate2Collection(certificates.Root), Convert.ToHexString(SHA256.HashData(certificates.Server.RawData)));
            transport = new(restricted);
            Snapshots = new(CreateSnapshot(endpoint, timeout));
            soap = new(new FixedSecrets(), new LoopbackResolver(), transport, clock, new MatchingStampProvider(), new LoopbackAllowance());
            http = new(soap.OpaqueSessionLeases, new LoopbackResolver(), transport, clock, allowance, beforeFinalAuthorization);
            authority = new(Snapshots.ResolveAsync, clock);
            session = AcquireAsync().GetAwaiter().GetResult();
        }

        internal MutableSnapshotSource Snapshots { get; }

        internal static Task<RealProjectionFixture> CreateAsync(Uri endpoint, CertificateFixture certificates, IPrivateDestinationAllowance? allowance,
            TimeSpan? timeout = null, Func<CancellationToken, Task>? beforeFinalAuthorization = null) =>
            Task.FromResult(new RealProjectionFixture(endpoint, certificates, allowance, timeout ?? TimeSpan.FromSeconds(2), beforeFinalAuthorization));

        internal async Task<OpaqueSessionHttpResponse> SendAsync(byte[] body)
        {
            RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
                Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddHours(1), "1.0.0", null);
            OpaqueSessionResolvedExecutionContext resolved = await authority.ResolveAsync(new(new GatewayClientPrincipal(identity, Guid.NewGuid()), "synthetic-session", "operation-a"),
                new("session-header"), TestContext.Current.CancellationToken);
            return await http.SendAsync(resolved, body, session, TestContext.Current.CancellationToken);
        }

        private async Task<OpaqueSessionReference> AcquireAsync()
        {
            ConnectorAuthExecutionContext context = new(tenantId, installationId, applicationId, environmentId, "synthetic-session", "1.0.0", "operation-a", 7, 7, 11,
                "opaque-session", Guid.NewGuid(), clock.UtcNow.AddMinutes(2));
            OpaqueSoapSessionReference acquired = await soap.AcquireSessionAsync(context, new(new Uri("https://127.0.0.1/session-login"), 7), Profile(), TestContext.Current.CancellationToken);
            return acquired.ToOpaqueSessionReference();
        }

        private PublishedConnectorSnapshot CreateSnapshot(Uri endpoint, TimeSpan timeout)
        {
            Uri baseEndpoint = new(endpoint.GetLeftPart(UriPartial.Authority));
            string path = endpoint.PathAndQuery;
            var definition = new
            {
                connectorId = "synthetic-session",
                version = "1.0.0",
                operations = new[]
                {
                    new
                    {
                        operationId = "operation-a",
                        endpointBinding = "service",
                        path,
                        method = "POST",
                        timeoutMs = (int)timeout.TotalMilliseconds,
                        authentication = new
                        {
                            kind = "opaqueSessionHttp",
                            policyId = "session-header",
                            sessionProfileId = "opaque-session",
                            secretBinding = "session-credential",
                            headerName = "X-Session-Reference",
                            valueFormat = "rawOpaqueValue"
                        },
                        request = new { contentType = "application/json", maximumBytes = 2 * 1024 * 1024 },
                        response = new { maximumBytes = 4096 }
                    }
                }
            };
            string canonical = JsonSerializer.Serialize(definition);
            ConnectorVersionRecord version = new(versionId, connectorId, "synthetic-session", "1.0.0", "wave1-test", ConnectorVersionState.Published,
                canonical, SHA256.HashData(Encoding.UTF8.GetBytes(canonical)), "test", clock.UtcNow, 1, clock.UtcNow, clock.UtcNow);
            ProviderResourceBinding resource = new("synthetic", "Synthetic", "Synthetic", "session-secret", ProviderResourceType.Secret, "Session credential", environmentId,
                "synthetic-session", "operation-a", "per-run", 11, null, null, "catalog-checksum");
            ConnectorBindingSet bindings = new(Guid.NewGuid(), connectorId, versionId, environmentId,
                new Dictionary<string, Uri>(StringComparer.Ordinal) { ["service"] = baseEndpoint },
                new Dictionary<string, ProviderResourceBinding>(StringComparer.Ordinal) { ["session-credential"] = resource },
                new Dictionary<string, ProviderResourceBinding>(StringComparer.Ordinal), 7, "binding-checksum", ConnectorBindingState.Active, clock.UtcNow, "test");
            return new(version, bindings, new(versionId, 3, 7, "binding-checksum", "resource-stamp-11"), new Dictionary<string, string>(), new Dictionary<string, string>());
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class MutableSnapshotSource(PublishedConnectorSnapshot snapshot)
    {
        internal PublishedConnectorSnapshot Snapshot { get; private set; } = snapshot;
        internal bool FailClosed { get; set; }

        internal Task<PublishedConnectorSnapshot?> ResolveAsync(string connectorId, Guid environmentId, PublishedConnectorAccessContext access, CancellationToken cancellationToken)
        {
            if (FailClosed) throw new InvalidOperationException("disabled");
            return Task.FromResult<PublishedConnectorSnapshot?>(Snapshot);
        }

        internal void RotateCredential()
        {
            ProviderResourceBinding resource = Snapshot.Bindings.SecretResources["session-credential"] with { CatalogRevision = 12, CatalogChecksumSha256 = "rotated" };
            Snapshot = Snapshot with
            {
                Bindings = Snapshot.Bindings with { SecretResources = new Dictionary<string, ProviderResourceBinding> { ["session-credential"] = resource } },
                Stamp = Snapshot.Stamp with { ResourceStampSha256 = "resource-stamp-12" }
            };
        }
    }

    private static SoapSessionProfile Profile()
    {
        const string ns = "urn:synthetic:session";
        SoapOperationProfile login = new("login", SoapEnvelopeVersion.Soap11, "urn:synthetic:login", new("Login", ns), new("LoginResponse", ns));
        SoapOperationProfile business = new("operation-a", SoapEnvelopeVersion.Soap11, "urn:synthetic:business", new("Business", ns), new("BusinessResponse", ns));
        return new("opaque-session", new("username", "password"), login, new("SessionId", ns), new("Session", ns), [business], TimeSpan.FromHours(1), []);
    }

    private sealed class CompositeTransport(IRestrictedTransport restricted) : IRestrictedTransport
    {
        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken) =>
            restricted.SendAsync(request, approvedAddresses, clientCertificate, timeout, maximumResponseBytes, cancellationToken);

        public Task<ExternalResponse> SendSoapAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            string response = $"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><s:LoginResponse xmlns:s=\"urn:synthetic:session\"><s:SessionId>{UpstreamSession}</s:SessionId></s:LoginResponse></soap:Body></soap:Envelope>";
            return Task.FromResult(new ExternalResponse(200, "text/xml; charset=utf-8", Encoding.UTF8.GetBytes(response)));
        }
    }

    private sealed class FixedSecrets : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string providerReference, CancellationToken cancellationToken) => Task.FromResult("synthetic");
    }

    private sealed class LoopbackResolver : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { IPAddress.Loopback });
    }

    private sealed class LoopbackAllowance : IPrivateDestinationAllowance
    {
        public bool IsAllowed(string host, IPAddress address) => IPAddress.IsLoopback(address);
    }

    private sealed class MatchingStampProvider : ISoapSessionResourceStampProvider
    {
        public Task<SoapSessionResourceStamp?> GetCurrentAsync(ConnectorAuthExecutionContext context, CancellationToken cancellationToken) =>
            Task.FromResult<SoapSessionResourceStamp?>(new(context.CredentialRevision, SoapCredentialResourceStatus.Active, context.BindingRevision, context.EndpointRevision));
    }

    private sealed class CertificateFixture(X509Certificate2 root, X509Certificate2 server) : IDisposable
    {
        public X509Certificate2 Root { get; } = root;
        public X509Certificate2 Server { get; } = server;

        public static CertificateFixture Create()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            using RSA rootKey = RSA.Create(2048);
            CertificateRequest rootRequest = new("CN=Synthetic Session Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            X509Certificate2 root = rootRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
            using RSA serverKey = RSA.Create(2048);
            CertificateRequest serverRequest = new("CN=127.0.0.1", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true));
            SubjectAlternativeNameBuilder san = new();
            san.AddIpAddress(IPAddress.Loopback);
            serverRequest.CertificateExtensions.Add(san.Build());
            using X509Certificate2 publicServer = serverRequest.Create(root, now.AddMinutes(-1), now.AddMinutes(30), RandomNumberGenerator.GetBytes(16));
            using X509Certificate2 serverWithKey = publicServer.CopyWithPrivateKey(serverKey);
            X509Certificate2 server = X509CertificateLoader.LoadPkcs12(serverWithKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
            return new(root, server);
        }

        public void Dispose() { Server.Dispose(); Root.Dispose(); }
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

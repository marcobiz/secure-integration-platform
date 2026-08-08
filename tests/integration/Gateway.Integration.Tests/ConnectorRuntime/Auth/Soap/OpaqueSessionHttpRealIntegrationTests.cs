using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.M6.SyntheticOpaqueSessionServer;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests.ConnectorRuntime.Auth.Soap;

public sealed class OpaqueSessionHttpRealIntegrationTests
{
    private const string UpstreamSession = "synthetic-opaque-session-reference";

    [Fact]
    public async Task Wave1_IT_real_HTTPS_projects_exactly_one_destination_bound_header_through_restricted_transport()
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticOpaqueSessionServerInstance server = await SyntheticOpaqueSessionServerHost.StartAsync(
            new("X-Session-Reference", UpstreamSession, TimeSpan.FromSeconds(2)), certificates.Server, TestContext.Current.CancellationToken);
        SystemRestrictedTransport restricted = new(new X509Certificate2Collection(certificates.Root), Convert.ToHexString(SHA256.HashData(certificates.Server.RawData)));
        CompositeTransport transport = new(restricted);
        SystemGatewayClock clock = new();
        ConnectorAuthExecutionContext context = Context(clock);
        FixedPolicySource policies = new(Policy(context, server.Endpoint));
        SoapSessionClient client = new(new FixedSecrets(), new LoopbackResolver(), transport, clock, new MatchingStampProvider(), new LoopbackAllowance(), policies);
        OpaqueSoapSessionReference session = await client.AcquireSessionAsync(context, new(new Uri("https://127.0.0.1/session-login"), 7), Profile(), TestContext.Current.CancellationToken);

        OpaqueSessionHttpResponse response = await client.SendWithOpaqueSessionAsync(context, "session-header", Encoding.UTF8.GetBytes("{}"), session, TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal(1, server.Counters.Requests);
        Assert.Equal(1, server.Counters.Accepted);
        Assert.Equal(0, server.Counters.Missing + server.Counters.Wrong + server.Counters.Duplicate);
    }

    [Fact]
    public async Task Wave1_IT_real_HTTPS_delayed_response_honors_timeout_and_remains_sanitized()
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticOpaqueSessionServerInstance server = await SyntheticOpaqueSessionServerHost.StartAsync(
            new("X-Session-Reference", UpstreamSession, TimeSpan.FromSeconds(2)), certificates.Server, TestContext.Current.CancellationToken);
        Uri delayed = new(server.Endpoint, "/delayed");
        SystemRestrictedTransport restricted = new(new X509Certificate2Collection(certificates.Root), Convert.ToHexString(SHA256.HashData(certificates.Server.RawData)));
        SystemGatewayClock clock = new();
        ConnectorAuthExecutionContext context = Context(clock);
        FixedPolicySource policies = new(Policy(context, delayed, TimeSpan.FromMilliseconds(150)));
        SoapSessionClient client = new(new FixedSecrets(), new LoopbackResolver(), new CompositeTransport(restricted), clock, new MatchingStampProvider(), new LoopbackAllowance(), policies);
        OpaqueSoapSessionReference session = await client.AcquireSessionAsync(context, new(new Uri("https://127.0.0.1/session-login"), 7), Profile(), TestContext.Current.CancellationToken);

        SoapAuthException timeout = await Assert.ThrowsAsync<SoapAuthException>(() => client.SendWithOpaqueSessionAsync(context, "session-header", Encoding.UTF8.GetBytes("{}"), session, TestContext.Current.CancellationToken));

        Assert.Equal("SESSION-HTTP-TIMEOUT", timeout.Code);
        Assert.DoesNotContain(UpstreamSession, timeout.ToString(), StringComparison.Ordinal);
        Assert.Equal(1, server.Counters.Requests);
    }

    private static ConnectorAuthExecutionContext Context(SystemGatewayClock clock) => new(
        Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "synthetic-session", "1.0.0", "operation-a", 5, 7, 11, "opaque-session", Guid.NewGuid(), clock.UtcNow.AddMinutes(2), "resource-stamp");

    private static ServerOwnedOpaqueSessionHttpPolicySnapshot Policy(ConnectorAuthExecutionContext context, Uri endpoint, TimeSpan? timeout = null) =>
        ServerOwnedOpaqueSessionHttpPolicySnapshot.Create("session-header", context.ConnectorId, context.ConnectorVersion, context.OperationId, context.SessionProfileId, context.EnvironmentId,
            endpoint, HttpMethod.Post, "application/json", context.BindingRevision, context.EndpointRevision, context.CredentialRevision, "resource-stamp",
            "X-Session-Reference", OpaqueSessionHttpHeaderValueFormat.RawOpaqueValue, null, timeout ?? TimeSpan.FromSeconds(2), 1024, 1024);

    private static SoapSessionProfile Profile()
    {
        const string ns = "urn:synthetic:session";
        SoapOperationProfile login = new("login", SoapEnvelopeVersion.Soap11, "urn:synthetic:login", new("Login", ns), new("LoginResponse", ns));
        SoapOperationProfile business = new("operation-a", SoapEnvelopeVersion.Soap11, "urn:synthetic:business", new("Business", ns), new("BusinessResponse", ns));
        return new("opaque-session", new("username", "password"), login, new("SessionId", ns), new("Session", ns), [business], TimeSpan.FromHours(1), []);
    }

    private sealed class FixedPolicySource(ServerOwnedOpaqueSessionHttpPolicySnapshot policy) : IOpaqueSessionHttpPolicySource
    {
        public Task<ServerOwnedOpaqueSessionHttpPolicySnapshot> ResolveAsync(ConnectorAuthExecutionContext context, string policyId, CancellationToken cancellationToken) => Task.FromResult(policy);
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
            Task.FromResult<SoapSessionResourceStamp?>(new(context.CredentialRevision, SoapCredentialResourceStatus.Active, context.BindingRevision, context.EndpointRevision, context.ResourceStamp));
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
}

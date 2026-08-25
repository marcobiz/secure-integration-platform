using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Http;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.M6.SyntheticSoapServer;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests.ConnectorRuntime.Auth.Soap;

public sealed class SoapRealHttpIntegrationTests
{
    private const string OperationNamespace = "urn:synthetic:session";
    private const string FaultNamespace = "urn:synthetic:fault";

    [Theory]
    [InlineData(SoapEnvelopeVersion.Soap11)]
    [InlineData(SoapEnvelopeVersion.Soap12)]
    public async Task M6_IT_SOAP_real_HTTPS_Basic_login_business_logout_and_expiry_reacquisition(SoapEnvelopeVersion version)
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticSoapServerInstance server = await SyntheticSoapServerHost.StartAsync(
            new("synthetic-user", "synthetic-password", false, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(2)), certificates.Server, TestContext.Current.CancellationToken);
        SoapSessionClient client = CreateClient(certificates.Root, certificates.Server, server.Endpoint);
        SoapSessionProfile profile = Profile(version, timeoutMilliseconds: 2_000, maximumResponseBytes: 32_768);
        SystemGatewayClock clock = new();
        ConnectorAuthExecutionContext context = Context(clock);
        SoapEndpointBinding endpoint = new(server.Endpoint, 4);

        OpaqueSoapSessionReference session = await client.AcquireSessionAsync(context, endpoint, profile, TestContext.Current.CancellationToken);
        SoapBusinessResult result = await client.InvokeAsync(context, endpoint, profile, new Dictionary<string, string> { ["payload"] = "normal" }, session, TestContext.Current.CancellationToken);
        Assert.Equal("accepted", result.Values["result"]);
        SoapBusinessResult reacquired = await client.InvokeAsync(context, endpoint, profile, new Dictionary<string, string> { ["payload"] = "expire-once" }, null, TestContext.Current.CancellationToken);
        Assert.Equal("accepted", reacquired.Values["result"]);
        Assert.Equal(2, server.Counters.Login);
        Assert.Equal(3, server.Counters.Business);

        OpaqueSoapSessionReference current = await client.AcquireSessionAsync(context, endpoint, profile, TestContext.Current.CancellationToken);
        await client.LogoutAsync(context, endpoint, profile, current, TestContext.Current.CancellationToken);
        Assert.Equal(1, server.Counters.Logout);
        SoapAuthException invalidated = await Assert.ThrowsAsync<SoapAuthException>(() => client.InvokeAsync(context, endpoint, profile, new Dictionary<string, string> { ["payload"] = "normal" }, current, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-SESSION-INVALID", invalidated.Code);
    }

    [Fact]
    public async Task M6_IT_SOAP_real_HTTPS_interactive_challenge_completion_is_transport_neutral()
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticSoapServerInstance server = await SyntheticSoapServerHost.StartAsync(
            new("synthetic-user", "synthetic-password", true, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(2)), certificates.Server, TestContext.Current.CancellationToken);
        SoapSessionClient client = CreateClient(certificates.Root, certificates.Server, server.Endpoint);
        SoapSessionProfile profile = Profile(SoapEnvelopeVersion.Soap12, 2_000, 32_768);
        SystemGatewayClock clock = new();
        ConnectorAuthExecutionContext context = Context(clock);
        SoapEndpointBinding endpoint = new(server.Endpoint, 4);

        SoapInteractionRequiredException challenge = await Assert.ThrowsAsync<SoapInteractionRequiredException>(() => client.AcquireSessionAsync(context, endpoint, profile, TestContext.Current.CancellationToken));
        OpaqueSoapSessionReference session = await client.CompleteInteractiveChallengeAsync(context, endpoint, profile, challenge.Challenge.InteractionReference, "123456", TestContext.Current.CancellationToken);
        SoapBusinessResult result = await client.InvokeAsync(context, endpoint, profile, new Dictionary<string, string> { ["payload"] = "normal" }, session, TestContext.Current.CancellationToken);
        Assert.Equal("accepted", result.Values["result"]);
        Assert.Equal(1, server.Counters.Login);
        Assert.Equal(1, server.Counters.Challenge);
        Assert.Equal(1, server.Counters.Business);
    }

    [Fact]
    public async Task M6_IT_SOAP_real_HTTPS_fault_malformed_oversize_timeout_cancellation_action_and_content_type_are_enforced()
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticSoapServerInstance server = await SyntheticSoapServerHost.StartAsync(
            new("synthetic-user", "synthetic-password", false, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(2)), certificates.Server, TestContext.Current.CancellationToken);
        SoapSessionClient client = CreateClient(certificates.Root, certificates.Server, server.Endpoint);
        SoapSessionProfile profile = Profile(SoapEnvelopeVersion.Soap11, timeoutMilliseconds: 10_000, maximumResponseBytes: 4_096);
        SystemGatewayClock clock = new();
        ConnectorAuthExecutionContext context = Context(clock);
        SoapEndpointBinding endpoint = new(server.Endpoint, 4);
        OpaqueSoapSessionReference session = await client.AcquireSessionAsync(context, endpoint, profile, TestContext.Current.CancellationToken);

        SoapFaultException fault = await Assert.ThrowsAsync<SoapFaultException>(() => client.InvokeAsync(context, endpoint, profile, new Dictionary<string, string> { ["payload"] = "fault" }, session, TestContext.Current.CancellationToken));
        Assert.Equal(SoapFaultCategory.Business, fault.Category);
        SoapAuthException malformed = await Assert.ThrowsAsync<SoapAuthException>(() => client.InvokeAsync(context, endpoint, profile, new Dictionary<string, string> { ["payload"] = "malformed" }, session, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-XML-MALFORMED", malformed.Code);
        SoapAuthException oversized = await Assert.ThrowsAsync<SoapAuthException>(() => client.InvokeAsync(context, endpoint, profile, new Dictionary<string, string> { ["payload"] = "oversize" }, session, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-RESPONSE-TOO-LARGE", oversized.Code);
        SoapSessionProfile timeoutProfile = Profile(SoapEnvelopeVersion.Soap11, timeoutMilliseconds: 150, maximumResponseBytes: 4_096);
        SoapAuthException timeout = await Assert.ThrowsAsync<SoapAuthException>(() => client.InvokeAsync(context, endpoint, timeoutProfile, new Dictionary<string, string> { ["payload"] = "timeout" }, session, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-TIMEOUT", timeout.Code);

        using CancellationTokenSource cancellation = new(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.InvokeAsync(context, endpoint, profile, new Dictionary<string, string> { ["payload"] = "timeout" }, session, cancellation.Token));

        SystemRestrictedTransport transport = new(new X509Certificate2Collection(certificates.Root), Convert.ToHexString(SHA256.HashData(certificates.Server.RawData)));
        IPAddress[] addresses = [IPAddress.Loopback];
        byte[] envelope = Encoding.UTF8.GetBytes($"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><op:Login xmlns:op=\"{OperationNamespace}\"/></soap:Body></soap:Envelope>");
        using HttpRequestMessage wrongAction = RawRequest(server.Endpoint, envelope, "text/xml; charset=utf-8", "\"urn:synthetic:Wrong\"");
        ExternalResponse actionResponse = await transport.SendSoapAsync(wrongAction, addresses, TimeSpan.FromSeconds(2), 4_096, TestContext.Current.CancellationToken);
        Assert.Equal(StatusCodes.Status415UnsupportedMediaType, actionResponse.StatusCode);
        using HttpRequestMessage wrongContentType = RawRequest(server.Endpoint, envelope, "application/json", "\"urn:synthetic:Login\"");
        ExternalResponse contentTypeResponse = await transport.SendSoapAsync(wrongContentType, addresses, TimeSpan.FromSeconds(2), 4_096, TestContext.Current.CancellationToken);
        Assert.Equal(StatusCodes.Status415UnsupportedMediaType, contentTypeResponse.StatusCode);
    }

    [Fact]
    public async Task M6_IT_SOAP_real_HTTPS_timeout_covers_headers_flushed_then_stalled_response_body()
    {
        const int SetupTimeoutMilliseconds = 10_000;
        const int StalledBodyTimeoutMilliseconds = 250;

        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticSoapServerInstance server = await SyntheticSoapServerHost.StartAsync(
            new("synthetic-user", "synthetic-password", false, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(2)), certificates.Server, TestContext.Current.CancellationToken);
        SoapSessionClient client = CreateClient(certificates.Root, certificates.Server, server.Endpoint);
        SystemGatewayClock clock = new();
        ConnectorAuthExecutionContext context = Context(clock);
        SoapEndpointBinding endpoint = new(server.Endpoint, 4);
        SoapSessionProfile loginProfile = Profile(SoapEnvelopeVersion.Soap11, timeoutMilliseconds: SetupTimeoutMilliseconds, maximumResponseBytes: 4_096);
        OpaqueSoapSessionReference session = await client.AcquireSessionAsync(context, endpoint, loginProfile, TestContext.Current.CancellationToken);
        SoapSessionProfile stalledBodyProfile = Profile(SoapEnvelopeVersion.Soap11, timeoutMilliseconds: StalledBodyTimeoutMilliseconds, maximumResponseBytes: 4_096);

        Task<SoapBusinessResult> invocation = client.InvokeAsync(context, endpoint, stalledBodyProfile, new Dictionary<string, string> { ["payload"] = "body-stalled" }, session, TestContext.Current.CancellationToken);
        using CancellationTokenSource observationDeadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        observationDeadline.CancelAfter(TimeSpan.FromSeconds(10));
        await server.Counters.WaitForBodyHeadersFlushedAsync(observationDeadline.Token);
        SoapAuthException timeout = await Assert.ThrowsAsync<SoapAuthException>(() => invocation);
        Assert.Equal("SOAP-TIMEOUT", timeout.Code);
        Assert.Equal(1, server.Counters.Business);
    }

    private static HttpRequestMessage RawRequest(Uri endpoint, byte[] envelope, string contentType, string action)
    {
        HttpRequestMessage request = new(HttpMethod.Post, endpoint);
        request.Content = new ByteArrayContent(envelope);
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        request.Headers.TryAddWithoutValidation("SOAPAction", action);
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes("synthetic-user:synthetic-password")));
        return request;
    }

    private static SoapSessionClient CreateClient(X509Certificate2 root, X509Certificate2 server, Uri endpoint) => new(
        new FixedSecrets(), new FixedResolver(), new SystemRestrictedTransport(new X509Certificate2Collection(root), Convert.ToHexString(SHA256.HashData(server.RawData))), new SystemGatewayClock(), new MatchingStampProvider(), new LoopbackAllowance(endpoint.DnsSafeHost));

    private static ConnectorAuthExecutionContext Context(SystemGatewayClock clock) => new(
        Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "synthetic-soap", "1.0.0", "business", 3, 4, 9, "basic-session", Guid.NewGuid(), clock.UtcNow.AddMinutes(2));

    private static SoapSessionProfile Profile(SoapEnvelopeVersion version, int timeoutMilliseconds, long maximumResponseBytes)
    {
        SoapOperationProfile login = new("login", version, "urn:synthetic:Login", new("Login", OperationNamespace), new("LoginResponse", OperationNamespace), timeoutMilliseconds: timeoutMilliseconds, maximumResponseBytes: maximumResponseBytes);
        SoapOperationProfile complete = new("complete", version, "urn:synthetic:CompleteChallenge", new("CompleteChallenge", OperationNamespace), new("CompleteChallengeResponse", OperationNamespace),
            [new("challengeState", new("Challenge", OperationNamespace), 128), new("artifact", new("Artifact", OperationNamespace), 16)], timeoutMilliseconds: timeoutMilliseconds, maximumResponseBytes: maximumResponseBytes);
        SoapOperationProfile business = new("business", version, "urn:synthetic:BusinessOperation", new("BusinessOperation", OperationNamespace), new("BusinessOperationResponse", OperationNamespace),
            [new("payload", new("Payload", OperationNamespace), 4096)], [new("result", new("Result", OperationNamespace), 4096)], timeoutMilliseconds, maximumResponseBytes: maximumResponseBytes, retryAfterSessionReacquisition: true);
        SoapOperationProfile logout = new("logout", version, "urn:synthetic:Logout", new("Logout", OperationNamespace), new("LogoutResponse", OperationNamespace), timeoutMilliseconds: timeoutMilliseconds, maximumResponseBytes: maximumResponseBytes);
        return new("basic-session", new("provider/username", "provider/password"), login, new("SessionId", OperationNamespace), new("Session", OperationNamespace), [business], TimeSpan.FromHours(16),
            [new(new("SessionExpired", FaultNamespace), SoapFaultCategory.SessionExpired), new(new("InvalidSession", FaultNamespace), SoapFaultCategory.InvalidSession), new(new("BusinessRejected", FaultNamespace), SoapFaultCategory.Business), new(new("AuthenticationDenied", FaultNamespace), SoapFaultCategory.AuthenticationDenied)],
            new("Challenge", OperationNamespace), complete, "artifact", "challengeState", TimeSpan.FromMinutes(5), logout);
    }

    private sealed class FixedSecrets : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) => Task.FromResult(logicalReference.Contains("username", StringComparison.Ordinal) ? "synthetic-user" : "synthetic-password");
    }

    private sealed class FixedResolver : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { IPAddress.Loopback });
    }

    private sealed class MatchingStampProvider : ISoapSessionResourceStampProvider
    {
        public Task<SoapSessionResourceStamp?> GetCurrentAsync(ConnectorAuthExecutionContext context, CancellationToken cancellationToken) =>
            Task.FromResult<SoapSessionResourceStamp?>(new(context.CredentialRevision, SoapCredentialResourceStatus.Active, context.BindingRevision, context.EndpointRevision));
    }

    private sealed class LoopbackAllowance(string host) : IPrivateDestinationAllowance
    {
        public bool IsAllowed(string candidateHost, IPAddress address) => string.Equals(host, candidateHost, StringComparison.OrdinalIgnoreCase) && IPAddress.IsLoopback(address);
    }

    private sealed class CertificateFixture(X509Certificate2 root, X509Certificate2 server) : IDisposable
    {
        public X509Certificate2 Root { get; } = root;
        public X509Certificate2 Server { get; } = server;

        public static CertificateFixture Create()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            using RSA rootKey = RSA.Create(2048);
            CertificateRequest rootRequest = new("CN=Synthetic SOAP Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            X509Certificate2 root = rootRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));

            using RSA serverKey = RSA.Create(2048);
            CertificateRequest serverRequest = new("CN=127.0.0.1", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            OidCollection eku = new() { new Oid("1.3.6.1.5.5.7.3.1") };
            serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
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

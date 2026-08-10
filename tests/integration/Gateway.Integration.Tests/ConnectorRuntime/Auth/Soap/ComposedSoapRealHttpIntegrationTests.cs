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
using SecureIntegration.M6.SyntheticSoapServer;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests.ConnectorRuntime.Auth.Soap;

public sealed class ComposedSoapRealHttpIntegrationTests
{
    [Theory]
    [InlineData(SoapEnvelopeVersion.Soap11)]
    [InlineData(SoapEnvelopeVersion.Soap12)]
    public async Task Wave1_IT_composed_Basic_session_SOAPAction_and_body_use_one_real_restricted_HTTPS_dispatch(SoapEnvelopeVersion version)
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticSoapServerInstance server = await StartServerAsync(certificates);
        await using RealComposedFixture fixture = await RealComposedFixture.CreateAsync(server.Endpoint, certificates, version);

        ComposedSoapHttpResponse response = await fixture.SendAsync("accepted", TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal(1, server.Counters.Composed);
        Assert.Equal(1, server.Counters.ComposedAccepted);
        Assert.Equal(1, fixture.Transport.ComposedDispatches);
        Assert.Equal(0, fixture.Transport.GenericDispatches);
        SoapDecodedResponse parsed = SoapXmlBoundary.ParseResponse(fixture.ResponseProfile(), new(response.StatusCode, response.ContentType, response.Body), null, null,
            new Dictionary<(string, string), SoapFaultCategory>(), TestContext.Current.CancellationToken);
        Assert.Equal("accepted", parsed.Values["result"]);
    }

    [Fact]
    public async Task Wave1_IT_HTTP500_SOAP_Fault_reaches_hardened_parser_and_malformed_Fault_is_denied()
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticSoapServerInstance server = await StartServerAsync(certificates);
        await using RealComposedFixture fixture = await RealComposedFixture.CreateAsync(server.Endpoint, certificates, SoapEnvelopeVersion.Soap11);

        ComposedSoapHttpResponse faultResponse = await fixture.SendAsync("fault", TestContext.Current.CancellationToken);

        Assert.Equal(500, faultResponse.StatusCode);
        SoapFaultException fault = Assert.Throws<SoapFaultException>(() => SoapXmlBoundary.ParseResponse(fixture.ResponseProfile(),
            new(faultResponse.StatusCode, faultResponse.ContentType, faultResponse.Body), null, null,
            new Dictionary<(string, string), SoapFaultCategory> { [("BusinessRejected", "urn:synthetic:fault")] = SoapFaultCategory.Business }, TestContext.Current.CancellationToken));
        Assert.Equal(SoapFaultCategory.Business, fault.Category);

        ComposedSoapHttpResponse malformed = await fixture.SendAsync("malformed-fault", TestContext.Current.CancellationToken);
        Assert.Equal(500, malformed.StatusCode);
        Assert.Equal("SOAP-FAULT-STRUCTURE", Assert.Throws<SoapAuthException>(() => SoapXmlBoundary.ParseResponse(fixture.ResponseProfile(),
            new(malformed.StatusCode, malformed.ContentType, malformed.Body), null, null,
            new Dictionary<(string, string), SoapFaultCategory>(), TestContext.Current.CancellationToken)).Code);
        Assert.Equal(2, server.Counters.ComposedAccepted);
    }

    [Fact]
    public async Task Wave1_IT_wrong_Basic_is_observed_only_by_the_intended_real_HTTPS_destination()
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticSoapServerInstance server = await StartServerAsync(certificates);
        await using RealComposedFixture fixture = await RealComposedFixture.CreateAsync(server.Endpoint, certificates, SoapEnvelopeVersion.Soap11, wrongBasic: true);

        ComposedSoapHttpResponse response = await fixture.SendAsync("accepted", TestContext.Current.CancellationToken);

        Assert.Equal(401, response.StatusCode);
        Assert.Equal(1, server.Counters.Composed);
        Assert.Equal(1, server.Counters.BasicRejected);
        Assert.Equal(0, server.Counters.ComposedAccepted);
    }

    [Theory]
    [InlineData("basic")]
    [InlineData("session")]
    [InlineData("endpoint")]
    [InlineData("action")]
    public async Task Wave1_IT_final_composed_authority_races_send_zero_real_network_requests(string mutation)
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticSoapServerInstance server = await StartServerAsync(certificates);
        TaskCompletionSource entered = Signal();
        TaskCompletionSource release = Signal();
        async Task Hook(CancellationToken cancellationToken)
        {
            entered.TrySetResult();
            await release.Task.WaitAsync(cancellationToken);
        }
        await using RealComposedFixture fixture = await RealComposedFixture.CreateAsync(server.Endpoint, certificates, SoapEnvelopeVersion.Soap11, beforeFinalAuthorization: Hook);

        Task<ComposedSoapHttpResponse> pending = fixture.SendAsync("accepted", TestContext.Current.CancellationToken);
        await entered.Task;
        if (mutation == "basic") fixture.Snapshots.RotateBasic();
        else if (mutation == "session") fixture.InvalidateSession();
        else if (mutation == "endpoint") fixture.Snapshots.Endpoint = new("https://changed.synthetic.example");
        else fixture.Snapshots.Action = "urn:synthetic:changed";
        release.TrySetResult();

        _ = await Assert.ThrowsAsync<SoapAuthException>(() => pending);
        Assert.Equal(0, server.Counters.Composed);
        Assert.Equal(0, fixture.Transport.ComposedDispatches);
    }

    [Fact]
    public async Task Wave1_IT_real_HTTPS_composed_product_deadline_maps_to_timeout_and_dispatches_once()
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticSoapServerInstance timeoutServer = await StartServerAsync(certificates);
        await using RealComposedFixture timeout = await RealComposedFixture.CreateAsync(timeoutServer.Endpoint, certificates, SoapEnvelopeVersion.Soap11, timeout: TimeSpan.FromMilliseconds(150));

        SoapAuthException timeoutFailure = await Assert.ThrowsAsync<SoapAuthException>(() => timeout.SendAsync("timeout", TestContext.Current.CancellationToken));

        Assert.Equal("SOAP-TIMEOUT", timeoutFailure.Code);
        Assert.DoesNotContain(RealComposedFixture.Password, timeoutFailure.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(RealComposedFixture.UpstreamSession, timeoutFailure.ToString(), StringComparison.Ordinal);
        Assert.Equal(1, timeout.Transport.ComposedDispatches);
        Assert.Equal(0, timeout.Transport.GenericDispatches);
    }

    [Fact]
    public async Task Wave1_IT_real_HTTPS_composed_response_stall_after_request_observed_honors_timeout_and_dispatches_once()
    {
        // Five seconds gives loopback connect, TLS, request upload and full Kestrel validation a
        // reliable CI budget. The separate twenty-second watchdog guards only the test awaits and
        // is never passed to the production invocation as caller cancellation.
        TimeSpan productTimeout = TimeSpan.FromSeconds(5);
        TimeSpan outerWatchdogTimeout = TimeSpan.FromSeconds(20);
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticSoapServerInstance server = await StartServerAsync(certificates);
        await using RealComposedFixture fixture = await RealComposedFixture.CreateAsync(
            server.Endpoint, certificates, SoapEnvelopeVersion.Soap11, timeout: productTimeout);
        using CancellationTokenSource callerCancellation = new();
        using CancellationTokenSource outerWatchdog = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        outerWatchdog.CancelAfter(outerWatchdogTimeout);

        Task<ComposedSoapHttpResponse> pending = fixture.SendAsync("response-stalled", callerCancellation.Token);
        await server.Counters.WaitForComposedAcceptedAsync(outerWatchdog.Token);

        Assert.Equal(1, server.Counters.Composed);
        Assert.Equal(1, server.Counters.ComposedAccepted);
        Assert.Equal(1, fixture.Transport.ComposedDispatches);
        Assert.Equal(0, fixture.Transport.GenericDispatches);
        Assert.False(pending.IsCompleted);

        // The synthetic response remains gated. Only the finite timeout supplied through the real
        // composed client and SystemRestrictedTransport is allowed to terminate this invocation.
        SoapAuthException timeoutFailure = await Assert.ThrowsAsync<SoapAuthException>(() => pending.WaitAsync(outerWatchdog.Token));

        Assert.Equal("SOAP-TIMEOUT", timeoutFailure.Code);
        Assert.False(callerCancellation.IsCancellationRequested);
        Assert.False(outerWatchdog.IsCancellationRequested);
        Assert.DoesNotContain(RealComposedFixture.Password, timeoutFailure.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(RealComposedFixture.UpstreamSession, timeoutFailure.ToString(), StringComparison.Ordinal);
        Assert.Equal(1, server.Counters.Composed);
        Assert.Equal(1, server.Counters.ComposedAccepted);
        Assert.Equal(1, fixture.Transport.ComposedDispatches);
    }

    [Fact]
    public async Task Wave1_IT_real_HTTPS_composed_caller_cancellation_remains_distinct_and_dispatches_once()
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        await using SyntheticSoapServerInstance cancellationServer = await StartServerAsync(certificates);
        await using RealComposedFixture caller = await RealComposedFixture.CreateAsync(cancellationServer.Endpoint, certificates, SoapEnvelopeVersion.Soap11);
        using CancellationTokenSource cancellation = new();

        Task<ComposedSoapHttpResponse> pending = caller.SendAsync("response-stalled", cancellation.Token);
        await cancellationServer.Counters.WaitForComposedAcceptedAsync(TestContext.Current.CancellationToken);

        Assert.Equal(1, cancellationServer.Counters.Composed);
        Assert.Equal(1, cancellationServer.Counters.ComposedAccepted);
        Assert.Equal(1, caller.Transport.ComposedDispatches);
        Assert.Equal(0, caller.Transport.GenericDispatches);
        Assert.False(pending.IsCompleted);

        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);

        Assert.Equal(1, cancellationServer.Counters.Composed);
        Assert.Equal(1, cancellationServer.Counters.ComposedAccepted);
        Assert.Equal(1, caller.Transport.ComposedDispatches);
    }

    private static Task<SyntheticSoapServerInstance> StartServerAsync(CertificateFixture certificates) => SyntheticSoapServerHost.StartAsync(
        new(RealComposedFixture.Username, RealComposedFixture.Password, false, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(2))
        {
            OpaqueSessionHeaderName = "X-Session-Reference",
            OpaqueSessionValue = RealComposedFixture.UpstreamSession
        }, certificates.Server, TestContext.Current.CancellationToken);

    private sealed class RealComposedFixture : IAsyncDisposable
    {
        internal const string Username = "synthetic-user";
        internal const string Password = "synthetic-password";
        internal const string UpstreamSession = "opaque-session-value";
        internal const string Action = "urn:synthetic:BusinessOperation";
        private static readonly Uri SessionEndpoint = new("https://127.0.0.1/session-login");
        private readonly Guid tenantId = Guid.NewGuid();
        private readonly Guid installationId = Guid.NewGuid();
        private readonly Guid applicationId = Guid.NewGuid();
        private readonly Guid environmentId = Guid.NewGuid();
        private readonly SoapEnvelopeVersion version;
        private readonly SystemGatewayClock clock = new();
        private readonly SoapSessionClient soap;
        private readonly ComposedSoapAuthenticatedClient client;
        private readonly PublishedComposedSoapAuthorityResolver authority;
        private readonly OpaqueSessionReference session;

        private RealComposedFixture(Uri endpoint, CertificateFixture certificates, SoapEnvelopeVersion version, bool wrongBasic, TimeSpan timeout,
            Func<CancellationToken, Task>? beforeFinalAuthorization)
        {
            this.version = version;
            SystemRestrictedTransport restricted = new(new X509Certificate2Collection(certificates.Root), Convert.ToHexString(SHA256.HashData(certificates.Server.RawData)));
            Transport = new(restricted);
            Secrets = new(wrongBasic);
            Snapshots = new(environmentId, endpoint, version, timeout, clock);
            soap = new(Secrets, new LoopbackResolver(), Transport, clock, new MatchingStampProvider(), new LoopbackAllowance());
            client = new(Secrets, soap.OpaqueSessionLeases, new LoopbackResolver(), Transport, clock, new LoopbackAllowance(), beforeFinalAuthorization);
            authority = new(Snapshots.ResolveAsync, clock);
            session = AcquireSessionAsync().GetAwaiter().GetResult();
        }

        internal RoutingTransport Transport { get; }
        internal RealSecrets Secrets { get; }
        internal MutableSnapshots Snapshots { get; }

        internal static Task<RealComposedFixture> CreateAsync(Uri endpoint, CertificateFixture certificates, SoapEnvelopeVersion version, bool wrongBasic = false,
            TimeSpan? timeout = null, Func<CancellationToken, Task>? beforeFinalAuthorization = null) =>
            Task.FromResult(new RealComposedFixture(endpoint, certificates, version, wrongBasic, timeout ?? TimeSpan.FromSeconds(2), beforeFinalAuthorization));

        internal async Task<ComposedSoapHttpResponse> SendAsync(string payload, CancellationToken cancellationToken)
        {
            RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
                Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddHours(1), "1.0.0", null);
            ComposedSoapResolvedExecutionContext resolved = await authority.ResolveAsync(new(new GatewayClientPrincipal(identity, Guid.NewGuid()), "synthetic-composed", "business"),
                new("composed-policy"), cancellationToken);
            return await client.SendAsync(resolved, Envelope(payload), session, cancellationToken);
        }

        internal SoapOperationProfile ResponseProfile() => new("business", version, Action, new("BusinessOperation", "urn:synthetic:session"),
            new("BusinessOperationResponse", "urn:synthetic:session"), responseFields: [new("result", new("Result", "urn:synthetic:session"))]);

        internal void InvalidateSession() => soap.InvalidateSession(SessionContext(), new(SessionEndpoint, 7), SessionProfile(), new(session.Value));

        private byte[] Envelope(string payload)
        {
            string envelopeNamespace = SoapXmlBoundary.EnvelopeNamespace(version);
            return Encoding.UTF8.GetBytes($"<soap:Envelope xmlns:soap=\"{envelopeNamespace}\"><soap:Body><op:BusinessOperation xmlns:op=\"urn:synthetic:session\"><op:Payload>{WebUtility.HtmlEncode(payload)}</op:Payload></op:BusinessOperation></soap:Body></soap:Envelope>");
        }

        private async Task<OpaqueSessionReference> AcquireSessionAsync()
        {
            OpaqueSoapSessionReference acquired = await soap.AcquireSessionAsync(SessionContext(), new(SessionEndpoint, 7), SessionProfile(), TestContext.Current.CancellationToken);
            return acquired.ToOpaqueSessionReference();
        }

        private ConnectorAuthExecutionContext SessionContext() => new(tenantId, installationId, applicationId, environmentId, "synthetic-composed", "1.0.0", "business", 7, 7, 11,
            "opaque-session", Guid.NewGuid(), clock.UtcNow.AddMinutes(5));

        private static SoapSessionProfile SessionProfile()
        {
            SoapOperationProfile login = new("login", SoapEnvelopeVersion.Soap11, "urn:synthetic:Login", new("Login", "urn:synthetic:session"), new("LoginResponse", "urn:synthetic:session"));
            SoapOperationProfile business = new("business", SoapEnvelopeVersion.Soap11, Action, new("BusinessOperation", "urn:synthetic:session"), new("BusinessOperationResponse", "urn:synthetic:session"));
            return new("opaque-session", new("login-user-ref", "login-password-ref"), login, new("SessionId", "urn:synthetic:session"), new("Session", "urn:synthetic:session"), [business], TimeSpan.FromHours(1), []);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class MutableSnapshots(Guid environmentId, Uri endpoint, SoapEnvelopeVersion version, TimeSpan timeout, IGatewayClock clock)
    {
        private readonly Guid versionId = Guid.NewGuid();
        private readonly Guid connectorId = Guid.NewGuid();
        private readonly Guid bindingId = Guid.NewGuid();
        internal Uri Endpoint { get; set; } = new(endpoint.GetLeftPart(UriPartial.Authority));
        internal string Action { get; set; } = RealComposedFixture.Action;
        internal long UsernameRevision { get; private set; } = 21;

        internal Task<PublishedConnectorSnapshot?> ResolveAsync(string connector, Guid environment, PublishedConnectorAccessContext access, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<PublishedConnectorSnapshot?>(Create());
        }

        internal void RotateBasic() => UsernameRevision++;

        private PublishedConnectorSnapshot Create()
        {
            string canonical = JsonSerializer.Serialize(new
            {
                connectorId = "synthetic-composed",
                version = "1.0.0",
                operations = new[]
                {
                    new
                    {
                        operationId = "business",
                        endpointBinding = "service",
                        path = "/composed",
                        method = "POST",
                        timeoutMs = (int)timeout.TotalMilliseconds,
                        authentication = new
                        {
                            kind = "soapBasicOpaqueSession",
                            policyId = "composed-policy",
                            sessionProfileId = "opaque-session",
                            usernameBinding = "basic-username",
                            passwordBinding = "basic-password",
                            secretBinding = "session-credential",
                            headerName = "X-Session-Reference",
                            valueFormat = "rawOpaqueValue",
                            soapHttp = new { version = version == SoapEnvelopeVersion.Soap11 ? "1.1" : "1.2", action = Action }
                        },
                        request = new { contentType = version == SoapEnvelopeVersion.Soap11 ? "text/xml" : "application/soap+xml", maximumBytes = 1_048_576 },
                        response = new { maximumBytes = 1_048_576 }
                    }
                }
            });
            ConnectorVersionRecord connectorVersion = new(versionId, connectorId, "synthetic-composed", "1.0.0", "wave1-test", ConnectorVersionState.Published,
                canonical, SHA256.HashData(Encoding.UTF8.GetBytes(canonical)), "test", clock.UtcNow, 1, clock.UtcNow, clock.UtcNow);
            Dictionary<string, ProviderResourceBinding> resources = new(StringComparer.Ordinal)
            {
                ["basic-username"] = Resource("basic-username", UsernameRevision),
                ["basic-password"] = Resource("basic-password", 22),
                ["session-credential"] = Resource("session-credential", 11)
            };
            ConnectorBindingSet bindings = new(bindingId, connectorId, versionId, environmentId,
                new Dictionary<string, Uri>(StringComparer.Ordinal) { ["service"] = Endpoint }, resources, new Dictionary<string, ProviderResourceBinding>(), 7,
                "binding-checksum", ConnectorBindingState.Active, clock.UtcNow, "test");
            return new(connectorVersion, bindings, new(versionId, 3, 7, "binding-checksum", "resource-" + UsernameRevision),
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["basic-username"] = "basic-username-ref-" + UsernameRevision,
                    ["basic-password"] = "basic-password-ref",
                    ["session-credential"] = "session-resource-ref"
                }, new Dictionary<string, string>());
        }

        private ProviderResourceBinding Resource(string id, long revision) => new("synthetic", "Synthetic", "Synthetic", id, ProviderResourceType.Secret, id, environmentId,
            "synthetic-composed", "business", "per-run", revision, null, null, "catalog-" + revision);
    }

    private sealed class RoutingTransport(IRestrictedTransport restricted) : IRestrictedTransport
    {
        private int genericDispatches;
        private int composedDispatches;

        internal int GenericDispatches => Volatile.Read(ref genericDispatches);
        internal int ComposedDispatches => Volatile.Read(ref composedDispatches);

        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout,
            long maximumResponseBytes, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref genericDispatches);
            throw new InvalidOperationException("Composed SOAP must not use generic SendAsync.");
        }

        public Task<ExternalResponse> SendSoapAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            if (request.RequestUri?.AbsolutePath == "/session-login")
            {
                string response = $"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><s:LoginResponse xmlns:s=\"urn:synthetic:session\"><s:SessionId>{RealComposedFixture.UpstreamSession}</s:SessionId></s:LoginResponse></soap:Body></soap:Envelope>";
                return Task.FromResult(new ExternalResponse(200, "text/xml; charset=utf-8", Encoding.UTF8.GetBytes(response)));
            }
            Interlocked.Increment(ref composedDispatches);
            return restricted.SendSoapAsync(request, approvedAddresses, timeout, maximumResponseBytes, cancellationToken);
        }
    }

    private sealed class RealSecrets(bool wrongBasic) : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string providerReference, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(providerReference switch
            {
                "basic-username-ref-21" => wrongBasic ? "wrong-user" : RealComposedFixture.Username,
                "basic-password-ref" => RealComposedFixture.Password,
                _ => "synthetic-login"
            });
        }
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
        internal X509Certificate2 Root { get; } = root;
        internal X509Certificate2 Server { get; } = server;

        internal static CertificateFixture Create()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            using RSA rootKey = RSA.Create(2048);
            CertificateRequest rootRequest = new("CN=Synthetic Composed SOAP Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
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

        public void Dispose()
        {
            Server.Dispose();
            Root.Dispose();
        }
    }

    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

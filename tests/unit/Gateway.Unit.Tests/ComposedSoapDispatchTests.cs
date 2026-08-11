using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class ComposedSoapDispatchTests
{
    private static readonly string[] AllowedRaceFailures = ["SOAP-AUTHORITY-STALE", "SOAP-AUTHORITY-REJECTED", "SOAP-SESSION-INVALID", "SOAP-SESSION-STALE"];
    private static readonly string[] ResolverParameterNames = ["invocation", "request", "cancellationToken"];

    [Theory]
    [InlineData(SoapEnvelopeVersion.Soap11, "text/xml", true)]
    [InlineData(SoapEnvelopeVersion.Soap12, "application/soap+xml", false)]
    public async Task Wave1_UT_composed_authority_applies_Basic_typed_SOAP_and_opaque_session_once(
        SoapEnvelopeVersion version,
        string mediaType,
        bool hasSoapAction)
    {
        ComposedFixture fixture = new(version);
        OpaqueSessionReference session = await fixture.AcquireSessionAsync();
        ComposedSoapResolvedExecutionContext authority = await fixture.ResolveAsync();

        ComposedSoapHttpResponse response = await fixture.Client.SendAsync(authority, fixture.Envelope(), session, TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal(1, fixture.Transport.ComposedDispatches);
        Assert.Equal("Basic", fixture.Transport.AuthorizationScheme);
        Assert.Equal(Convert.ToBase64String(Encoding.UTF8.GetBytes(ComposedFixture.Username + ":" + ComposedFixture.Password)), fixture.Transport.AuthorizationParameter);
        Assert.Equal(ComposedFixture.UpstreamSession, fixture.Transport.SessionHeader);
        Assert.Equal(mediaType, fixture.Transport.ContentType);
        Assert.Equal(hasSoapAction ? '"' + ComposedFixture.Action + '"' : null, fixture.Transport.SoapAction);
        Assert.Equal(hasSoapAction ? null : ComposedFixture.Action, fixture.Transport.ContentTypeAction);
        Assert.Equal(3, fixture.Snapshots.Calls);
        Assert.DoesNotContain(ComposedFixture.UpstreamSession, JsonSerializer.Serialize(authority), StringComparison.Ordinal);
        Assert.DoesNotContain(ComposedFixture.Password, authority.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Authorization")]
    [InlineData("SOAPAction")]
    [InlineData("Content-Type")]
    [InlineData("traceparent")]
    [InlineData("X-Forwarded-For")]
    [InlineData("Bad Header")]
    [InlineData("X-Bad\r\nInjected")]
    public async Task Wave1_SEC_composed_session_header_cannot_collide_or_inject(string headerName)
    {
        ComposedFixture fixture = new();
        fixture.Snapshots.HeaderName = headerName;

        SoapAuthException failure = await Assert.ThrowsAsync<SoapAuthException>(() => fixture.ResolveAsync());

        Assert.Equal("SOAP-HTTP-POLICY-VIOLATION", failure.Code);
        Assert.Equal(0, fixture.Transport.ComposedDispatches);
    }

    [Fact]
    public async Task Wave1_SEC_composed_request_rejects_version_content_policy_and_authority_substitution_before_network()
    {
        ComposedFixture mismatch = new(SoapEnvelopeVersion.Soap11);
        OpaqueSessionReference mismatchSession = await mismatch.AcquireSessionAsync();
        ComposedSoapResolvedExecutionContext mismatchAuthority = await mismatch.ResolveAsync();
        SoapAuthException version = await Assert.ThrowsAsync<SoapAuthException>(() => mismatch.Client.SendAsync(
            mismatchAuthority, mismatch.Envelope(SoapEnvelopeVersion.Soap12), mismatchSession, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-ENVELOPE-NAMESPACE", version.Code);
        Assert.Equal(0, mismatch.Transport.ComposedDispatches);

        ComposedFixture contentType = new();
        contentType.Snapshots.RequestContentType = "application/json";
        Assert.Equal("SOAP-HTTP-METADATA-INVALID", (await Assert.ThrowsAsync<SoapAuthException>(() => contentType.ResolveAsync())).Code);

        ComposedFixture method = new();
        method.Snapshots.Method = "PUT";
        Assert.Equal("SOAP-AUTHORITY-REJECTED", (await Assert.ThrowsAsync<SoapAuthException>(() => method.ResolveAsync())).Code);

        ComposedFixture wrongPolicy = new();
        Assert.Equal("SOAP-AUTHORITY-REJECTED", (await Assert.ThrowsAsync<SoapAuthException>(() => wrongPolicy.ResolveAsync("other-policy"))).Code);

        ComposedFixture missingBasic = new();
        missingBasic.Snapshots.RemoveUsernameProviderReference = true;
        Assert.Equal("SOAP-AUTHORITY-REJECTED", (await Assert.ThrowsAsync<SoapAuthException>(() => missingBasic.ResolveAsync())).Code);

        ComposedFixture injectedAction = new();
        injectedAction.Snapshots.Action = "urn:synthetic:business\r\nInjected: true";
        Assert.Equal("SOAP-HTTP-METADATA-INVALID", (await Assert.ThrowsAsync<SoapAuthException>(() => injectedAction.ResolveAsync())).Code);

        Assert.Equal(0, contentType.Transport.ComposedDispatches + method.Transport.ComposedDispatches + wrongPolicy.Transport.ComposedDispatches + missingBasic.Transport.ComposedDispatches + injectedAction.Transport.ComposedDispatches);
    }

    [Fact]
    public async Task Wave1_SEC_missing_session_and_duplicate_SOAP_metadata_fail_before_network()
    {
        ComposedFixture fixture = new();
        OpaqueSessionReference session = await fixture.AcquireSessionAsync();
        ComposedSoapResolvedExecutionContext authority = await fixture.ResolveAsync();

        await Assert.ThrowsAsync<ArgumentNullException>(() => fixture.Client.SendAsync(authority, fixture.Envelope(), null!, TestContext.Current.CancellationToken));
        Assert.Equal(0, fixture.Transport.ComposedDispatches);

        SoapHttpRequestMetadata metadata = new(SoapEnvelopeVersion.Soap11, ComposedFixture.Action);
        using HttpRequestMessage request = new(HttpMethod.Post, "https://soap.synthetic.example");
        metadata.Apply(request, fixture.Envelope());
        Assert.Equal("SOAP-HTTP-POLICY-VIOLATION", Assert.Throws<SoapAuthException>(() => metadata.Apply(request, fixture.Envelope())).Code);
        Assert.Single(request.Headers.GetValues("SOAPAction"));
        Assert.NotNull(session);
    }

    [Theory]
    [InlineData("basic-rotate")]
    [InlineData("session-rotate")]
    [InlineData("endpoint")]
    [InlineData("endpoint-revision")]
    [InlineData("action")]
    [InlineData("disable")]
    public async Task Wave1_SEC_composed_final_revalidation_races_send_zero_network(string mutation)
    {
        TaskCompletionSource entered = Signal();
        TaskCompletionSource release = Signal();
        async Task Hook(CancellationToken cancellationToken)
        {
            entered.TrySetResult();
            await release.Task.WaitAsync(cancellationToken);
        }

        ComposedFixture fixture = new(beforeFinalAuthorization: Hook);
        OpaqueSessionReference session = await fixture.AcquireSessionAsync();
        ComposedSoapResolvedExecutionContext authority = await fixture.ResolveAsync();
        Task<ComposedSoapHttpResponse> pending = fixture.Client.SendAsync(authority, fixture.Envelope(), session, TestContext.Current.CancellationToken);
        await entered.Task;

        if (mutation == "basic-rotate") fixture.Snapshots.RotateBasic();
        else if (mutation == "session-rotate") fixture.InvalidateSession(session);
        else if (mutation == "endpoint") fixture.Snapshots.Endpoint = new("https://changed.synthetic.example");
        else if (mutation == "endpoint-revision") fixture.Snapshots.BindingRevision++;
        else if (mutation == "action") fixture.Snapshots.Action = "urn:synthetic:changed";
        else fixture.Snapshots.FailClosed = true;
        release.TrySetResult();

        SoapAuthException failure = await Assert.ThrowsAsync<SoapAuthException>(() => pending);
        Assert.Contains(failure.Code, AllowedRaceFailures);
        Assert.Equal(0, fixture.Transport.ComposedDispatches);
        Assert.Null(fixture.Transport.SessionHeader);
    }

    [Fact]
    public async Task Wave1_UT_SendSoapAsync_preserves_HTTP500_for_strict_Fault_parser()
    {
        ComposedFixture fixture = new();
        fixture.Transport.Response = new(500, "text/xml; charset=utf-8", Encoding.UTF8.GetBytes(
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><soap:Fault xmlns:f=\"urn:synthetic:fault\"><faultcode>f:BusinessRejected</faultcode><faultstring>synthetic</faultstring></soap:Fault></soap:Body></soap:Envelope>"));
        OpaqueSessionReference session = await fixture.AcquireSessionAsync();
        ComposedSoapResolvedExecutionContext authority = await fixture.ResolveAsync();

        ComposedSoapHttpResponse response = await fixture.Client.SendAsync(authority, fixture.Envelope(), session, TestContext.Current.CancellationToken);

        Assert.Equal(500, response.StatusCode);
        SoapFaultException fault = Assert.Throws<SoapFaultException>(() => SoapXmlBoundary.ParseResponse(
            fixture.ResponseProfile(), new ExternalResponse(response.StatusCode, response.ContentType, response.Body), null, null,
            new Dictionary<(string, string), SoapFaultCategory> { [("BusinessRejected", "urn:synthetic:fault")] = SoapFaultCategory.Business }, TestContext.Current.CancellationToken));
        Assert.Equal(SoapFaultCategory.Business, fault.Category);

        fixture.Transport.Response = new(500, "text/xml; charset=utf-8", Encoding.UTF8.GetBytes(
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><soap:Fault xmlns:f=\"urn:synthetic:fault\"><faultcode>f:BusinessRejected</faultcode><faultcode>f:Other</faultcode><faultstring>synthetic</faultstring></soap:Fault></soap:Body></soap:Envelope>"));
        response = await fixture.Client.SendAsync(authority, fixture.Envelope(), session, TestContext.Current.CancellationToken);
        Assert.Equal("SOAP-FAULT-STRUCTURE", Assert.Throws<SoapAuthException>(() => SoapXmlBoundary.ParseResponse(
            fixture.ResponseProfile(), new ExternalResponse(response.StatusCode, response.ContentType, response.Body), null, null,
            new Dictionary<(string, string), SoapFaultCategory>(), TestContext.Current.CancellationToken)).Code);
    }

    [Fact]
    public async Task Wave1_SEC_composed_SSRF_timeout_cancellation_and_diagnostics_are_closed()
    {
        ComposedFixture ssrf = new(resolver: new FixedResolver(IPAddress.Loopback));
        OpaqueSessionReference ssrfSession = await ssrf.AcquireSessionAsync();
        ComposedSoapResolvedExecutionContext ssrfAuthority = await ssrf.ResolveAsync();
        Assert.Equal("SOAP-EGRESS-DESTINATION-DENIED", (await Assert.ThrowsAsync<SoapAuthException>(() => ssrf.Client.SendAsync(ssrfAuthority, ssrf.Envelope(), ssrfSession, TestContext.Current.CancellationToken))).Code);
        Assert.Equal(0, ssrf.Transport.ComposedDispatches);

        ComposedFixture timeout = new();
        timeout.Transport.CancelDispatch = true;
        OpaqueSessionReference timeoutSession = await timeout.AcquireSessionAsync();
        ComposedSoapResolvedExecutionContext timeoutAuthority = await timeout.ResolveAsync();
        SoapAuthException timeoutFailure = await Assert.ThrowsAsync<SoapAuthException>(() => timeout.Client.SendAsync(timeoutAuthority, timeout.Envelope(), timeoutSession, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-TIMEOUT", timeoutFailure.Code);
        Assert.DoesNotContain(ComposedFixture.Password, timeoutFailure.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(ComposedFixture.UpstreamSession, timeoutFailure.ToString(), StringComparison.Ordinal);

        ComposedFixture caller = new();
        OpaqueSessionReference callerSession = await caller.AcquireSessionAsync();
        ComposedSoapResolvedExecutionContext callerAuthority = await caller.ResolveAsync();
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => caller.Client.SendAsync(callerAuthority, caller.Envelope(), callerSession, cancellation.Token));
    }

    [Fact]
    public async Task Wave1_SEC_typed_composed_adapter_preserves_only_the_actually_cancelled_caller_token()
    {
        ComposedFixture fixture = new();
        ComposedSoapResolvedExecutionContext resolved = await fixture.ResolveAsync();
        using CancellationTokenSource callerCancellation = new();
        CancelingTypedComposedRequestAdapter adapter = new(callerCancellation);
        TypedComposedSoapRequestAuthority typed = new(
            adapter,
            new SoapElementRule("BusinessOperation", "urn:synthetic:operation"),
            [],
            32_768,
            "typed-cancellation-fingerprint");
        ComposedSoapAuthorityState state = resolved.State with { TypedRequest = typed };
        AuthorizedConnectorBindingInputs inputs = new(new Dictionary<string, string>(StringComparer.Ordinal));

        try
        {
            OperationCanceledException failure = Assert.ThrowsAny<OperationCanceledException>(() =>
                TypedComposedSoapRequestXmlBoundary.Serialize(
                    state,
                    "<BusinessPayload/>"u8.ToArray(),
                    inputs,
                    callerCancellation.Token));

            Assert.Equal(callerCancellation.Token, failure.CancellationToken);
            Assert.DoesNotContain("typed-cancellation-canary", failure.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            inputs.Clear();
        }
    }

    [Fact]
    public void Wave1_CT_composed_public_surface_has_no_authority_or_header_override()
    {
        Assert.False(typeof(ServerBoundBasicAuthentication).IsPublic);
        Assert.False(typeof(ResolvedBasicCredentialBinding).IsPublic);
        Assert.Empty(typeof(ResolvedBasicCredentialBinding).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(typeof(ComposedSoapAuthenticatedClient).Assembly.GetExportedTypes(), type => type.Name.Contains("BasicAuthentication", StringComparison.Ordinal));
        Assert.Empty(typeof(SoapHttpRequestMetadata).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(ComposedSoapResolvedExecutionContext).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        MethodInfo dispatch = Assert.Single(typeof(ComposedSoapAuthenticatedClient).GetMethods(), method => method.Name == nameof(ComposedSoapAuthenticatedClient.SendAsync));
        Assert.DoesNotContain(dispatch.GetParameters(), parameter => parameter.ParameterType == typeof(HttpRequestMessage));
        Assert.DoesNotContain(dispatch.GetParameters().Select(parameter => parameter.Name!), name =>
            name.Contains("endpoint", StringComparison.OrdinalIgnoreCase) || name.Contains("header", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("action", StringComparison.OrdinalIgnoreCase) || name.Contains("contentType", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("version", StringComparison.OrdinalIgnoreCase) || name.Contains("credential", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("revision", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(ResolverParameterNames, typeof(PublishedComposedSoapAuthorityResolver).GetMethod(nameof(PublishedComposedSoapAuthorityResolver.ResolveAsync))!
            .GetParameters().Select(parameter => parameter.Name).ToArray());
    }

    private sealed class ComposedFixture
    {
        internal const string Username = "synthetic-user";
        internal const string Password = "synthetic-password";
        internal const string UpstreamSession = "opaque-session-value";
        internal const string Action = "urn:synthetic:business";
        private static readonly Uri SessionEndpoint = new("https://session.synthetic.example/login");
        private readonly Guid tenantId = Guid.NewGuid();
        private readonly Guid installationId = Guid.NewGuid();
        private readonly Guid applicationId = Guid.NewGuid();
        private readonly Guid environmentId = Guid.NewGuid();
        private readonly SoapEnvelopeVersion version;
        private readonly SoapSessionClient soap;

        internal ComposedFixture(
            SoapEnvelopeVersion version = SoapEnvelopeVersion.Soap11,
            IHostResolver? resolver = null,
            Func<CancellationToken, Task>? beforeFinalAuthorization = null)
        {
            this.version = version;
            Clock = new();
            Transport = new(version);
            Secrets = new();
            Snapshots = new(environmentId, version, Clock);
            soap = new(Secrets, new FixedResolver(IPAddress.Parse("8.8.8.8")), Transport, Clock, new MatchingStampProvider());
            Client = new(Secrets, soap.OpaqueSessionLeases, resolver ?? new FixedResolver(IPAddress.Parse("8.8.8.8")), Transport, Clock, null, beforeFinalAuthorization);
            Authority = new(Snapshots.ResolveAsync, Clock);
        }

        internal MutableClock Clock { get; }
        internal RecordingSecrets Secrets { get; }
        internal RecordingTransport Transport { get; }
        internal MutableSnapshots Snapshots { get; }
        internal ComposedSoapAuthenticatedClient Client { get; }
        internal PublishedComposedSoapAuthorityResolver Authority { get; }

        internal async Task<OpaqueSessionReference> AcquireSessionAsync()
        {
            OpaqueSoapSessionReference reference = await soap.AcquireSessionAsync(SessionContext(), new(SessionEndpoint, 7), SessionProfile(), TestContext.Current.CancellationToken);
            return reference.ToOpaqueSessionReference();
        }

        internal Task<ComposedSoapResolvedExecutionContext> ResolveAsync(string policyId = "composed-policy")
        {
            RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
                Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], Clock.UtcNow.AddMinutes(-1), Clock.UtcNow.AddHours(1), "1.0.0", null);
            return Authority.ResolveAsync(new(new GatewayClientPrincipal(identity, Guid.NewGuid()), "synthetic-composed", "business"), new(policyId), TestContext.Current.CancellationToken);
        }

        internal byte[] Envelope(SoapEnvelopeVersion? overrideVersion = null)
        {
            string ns = SoapXmlBoundary.EnvelopeNamespace(overrideVersion ?? version);
            return Encoding.UTF8.GetBytes($"<soap:Envelope xmlns:soap=\"{ns}\"><soap:Body><op:Business xmlns:op=\"urn:synthetic:operation\"><op:Payload>input</op:Payload></op:Business></soap:Body></soap:Envelope>");
        }

        internal SoapOperationProfile ResponseProfile() => new("business", version, Action, new("Business", "urn:synthetic:operation"), new("BusinessResponse", "urn:synthetic:operation"),
            responseFields: [new("result", new("Result", "urn:synthetic:operation"))]);

        internal void InvalidateSession(OpaqueSessionReference session) => soap.InvalidateSession(SessionContext(), new(SessionEndpoint, 7), SessionProfile(), new(session.Value));

        private ConnectorAuthExecutionContext SessionContext() => new(tenantId, installationId, applicationId, environmentId, "synthetic-composed", "1.0.0", "business", 7, 7, 11,
            "opaque-session", Guid.NewGuid(), Clock.UtcNow.AddMinutes(5));

        private static SoapSessionProfile SessionProfile()
        {
            SoapOperationProfile login = new("login", SoapEnvelopeVersion.Soap11, "urn:synthetic:login", new("Login", "urn:synthetic:session"), new("LoginResponse", "urn:synthetic:session"));
            SoapOperationProfile business = new("business", SoapEnvelopeVersion.Soap11, Action, new("Business", "urn:synthetic:operation"), new("BusinessResponse", "urn:synthetic:operation"));
            return new("opaque-session", new("login-user-ref", "login-password-ref"), login, new("SessionId", "urn:synthetic:session"), new("Session", "urn:synthetic:session"), [business], TimeSpan.FromHours(1), []);
        }
    }

    private sealed class MutableSnapshots(Guid environmentId, SoapEnvelopeVersion version, MutableClock clock)
    {
        private readonly Guid versionId = Guid.NewGuid();
        private readonly Guid connectorId = Guid.NewGuid();
        private readonly Guid bindingId = Guid.NewGuid();
        internal int Calls { get; private set; }
        internal bool FailClosed { get; set; }
        internal bool RemoveUsernameProviderReference { get; set; }
        internal string HeaderName { get; set; } = "X-Session-Reference";
        internal string Method { get; set; } = "POST";
        internal string RequestContentType { get; set; } = version == SoapEnvelopeVersion.Soap11 ? "text/xml" : "application/soap+xml";
        internal string Action { get; set; } = ComposedFixture.Action;
        internal Uri Endpoint { get; set; } = new("https://api.synthetic.example");
        internal long BindingRevision { get; set; } = 7;
        internal long UsernameRevision { get; set; } = 21;

        internal Task<PublishedConnectorSnapshot?> ResolveAsync(string connector, Guid environment, PublishedConnectorAccessContext access, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            if (FailClosed) throw new InvalidOperationException("synthetic disabled canary");
            return Task.FromResult<PublishedConnectorSnapshot?>(Create());
        }

        internal void RotateBasic() => UsernameRevision++;

        private PublishedConnectorSnapshot Create()
        {
            Dictionary<string, object?> authentication = new(StringComparer.Ordinal)
            {
                ["kind"] = "soapBasicOpaqueSession",
                ["policyId"] = "composed-policy",
                ["sessionProfileId"] = "opaque-session",
                ["usernameBinding"] = "basic-username",
                ["passwordBinding"] = "basic-password",
                ["secretBinding"] = "session-credential",
                ["headerName"] = HeaderName,
                ["valueFormat"] = "rawOpaqueValue",
                ["soapHttp"] = new { version = version == SoapEnvelopeVersion.Soap11 ? "1.1" : "1.2", action = Action }
            };
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
                        path = "/service",
                        method = Method,
                        timeoutMs = 5_000,
                        authentication,
                        request = new { contentType = RequestContentType, maximumBytes = 1_048_576 },
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
                new Dictionary<string, Uri>(StringComparer.Ordinal) { ["service"] = Endpoint }, resources,
                new Dictionary<string, ProviderResourceBinding>(StringComparer.Ordinal), BindingRevision, "binding-" + BindingRevision, ConnectorBindingState.Active, clock.UtcNow, "test");
            Dictionary<string, string> references = new(StringComparer.Ordinal)
            {
                ["basic-username"] = "basic-username-ref-" + UsernameRevision,
                ["basic-password"] = "basic-password-ref",
                ["session-credential"] = "session-resource-ref"
            };
            if (RemoveUsernameProviderReference) references.Remove("basic-username");
            return new(connectorVersion, bindings, new(versionId, 3, BindingRevision, bindings.ChecksumSha256, $"resource-{UsernameRevision}-22-11"), references,
                new Dictionary<string, string>(StringComparer.Ordinal));
        }

        private ProviderResourceBinding Resource(string resourceId, long revision) => new("synthetic", "Synthetic", "Synthetic", resourceId, ProviderResourceType.Secret,
            resourceId, environmentId, "synthetic-composed", "business", "per-run", revision, null, null, "catalog-" + revision);
    }

    private sealed class RecordingSecrets : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string providerReference, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(providerReference switch
            {
                "basic-username-ref-21" => ComposedFixture.Username,
                "basic-password-ref" => ComposedFixture.Password,
                _ => "synthetic-session-login"
            });
        }
    }

    private sealed class CancelingTypedComposedRequestAdapter(CancellationTokenSource callerCancellation) : ITypedComposedSoapRequestAdapter
    {
        public string AdapterId => "canceling-request";
        public string AdapterType => "synthetic-canceling-request";

        public void WriteRequest(XmlWriter writer, TypedComposedSoapRequestContext context)
        {
            callerCancellation.Cancel();
            throw new OperationCanceledException("typed-cancellation-canary", new CancellationToken(canceled: true));
        }
    }

    private sealed class RecordingTransport(SoapEnvelopeVersion version) : IRestrictedTransport
    {
        internal int ComposedDispatches { get; private set; }
        internal string? AuthorizationScheme { get; private set; }
        internal string? AuthorizationParameter { get; private set; }
        internal string? SessionHeader { get; private set; }
        internal string? SoapAction { get; private set; }
        internal string? ContentType { get; private set; }
        internal string? ContentTypeAction { get; private set; }
        internal bool CancelDispatch { get; set; }
        internal ExternalResponse Response { get; set; } = Success(version);

        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, System.Security.Cryptography.X509Certificates.X509Certificate2? clientCertificate,
            TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken) => throw new InvalidOperationException("Generic SendAsync must not be used by composed SOAP dispatch.");

        public Task<ExternalResponse> SendSoapAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            if (request.RequestUri?.Host == "session.synthetic.example")
            {
                string login = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><s:LoginResponse xmlns:s=\"urn:synthetic:session\"><s:SessionId>" + ComposedFixture.UpstreamSession + "</s:SessionId></s:LoginResponse></soap:Body></soap:Envelope>";
                return Task.FromResult(new ExternalResponse(200, "text/xml; charset=utf-8", Encoding.UTF8.GetBytes(login)));
            }
            ComposedDispatches++;
            AuthorizationScheme = request.Headers.Authorization?.Scheme;
            AuthorizationParameter = request.Headers.Authorization?.Parameter;
            SessionHeader = request.Headers.TryGetValues("X-Session-Reference", out IEnumerable<string>? sessions) ? sessions.SingleOrDefault() : null;
            SoapAction = request.Headers.TryGetValues("SOAPAction", out IEnumerable<string>? actions) ? actions.SingleOrDefault() : null;
            ContentType = request.Content?.Headers.ContentType?.MediaType;
            ContentTypeAction = request.Content?.Headers.ContentType?.Parameters.SingleOrDefault(parameter => string.Equals(parameter.Name, "action", StringComparison.OrdinalIgnoreCase))?.Value?.Trim('"');
            if (CancelDispatch) return Task.FromException<ExternalResponse>(new OperationCanceledException(cancellationToken));
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Response);
        }

        private static ExternalResponse Success(SoapEnvelopeVersion version)
        {
            string ns = SoapXmlBoundary.EnvelopeNamespace(version);
            string response = $"<soap:Envelope xmlns:soap=\"{ns}\"><soap:Body><op:BusinessResponse xmlns:op=\"urn:synthetic:operation\"><op:Result>accepted</op:Result></op:BusinessResponse></soap:Body></soap:Envelope>";
            return new(200, version == SoapEnvelopeVersion.Soap11 ? "text/xml; charset=utf-8" : "application/soap+xml; charset=utf-8", Encoding.UTF8.GetBytes(response));
        }
    }

    private sealed class MutableClock : IGatewayClock
    {
        public DateTimeOffset UtcNow { get; set; } = DateTimeOffset.UtcNow;
    }

    private sealed class FixedResolver(IPAddress address) : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new[] { address });
        }
    }

    private sealed class MatchingStampProvider : ISoapSessionResourceStampProvider
    {
        public Task<SoapSessionResourceStamp?> GetCurrentAsync(ConnectorAuthExecutionContext context, CancellationToken cancellationToken) =>
            Task.FromResult<SoapSessionResourceStamp?>(new(context.CredentialRevision, SoapCredentialResourceStatus.Active, context.BindingRevision, context.EndpointRevision));
    }

    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

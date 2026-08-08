using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class OpaqueSessionHttpProjectionTests
{
    private static readonly Uri SessionEndpoint = new("https://session.synthetic.example/service");
    private static readonly Uri HttpBaseEndpoint = new("https://api.synthetic.example");
    private static readonly string[] PolicySelectorParameterNames = ["policyId"];

    [Theory]
    [InlineData(OpaqueSessionHttpHeaderValueFormat.RawOpaqueValue, null, "opaque-session-value")]
    [InlineData(OpaqueSessionHttpHeaderValueFormat.FixedSchemeAndOpaqueValue, "Session", "Session opaque-session-value")]
    public async Task Wave1_UT_published_authority_projects_once_only_during_restricted_dispatch(
        OpaqueSessionHttpHeaderValueFormat format, string? scheme, string expectedHeader)
    {
        ProjectionFixture fixture = new(format, scheme);
        OpaqueSessionReference session = await fixture.AcquireAsync("operation-a");
        OpaqueSessionResolvedExecutionContext authority = await fixture.ResolveAsync("operation-a");

        OpaqueSessionHttpResponse response = await fixture.HttpClient.SendAsync(authority, Encoding.UTF8.GetBytes("business-input"), session, TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("accepted", Encoding.UTF8.GetString(response.Body));
        Assert.Equal(expectedHeader, fixture.Transport.ProjectedHeader);
        Assert.Equal(1, fixture.Transport.HttpDispatchCount);
        Assert.Equal(new Uri(HttpBaseEndpoint, "/resource"), fixture.Transport.RequestUri);
        Assert.Equal(3, fixture.Snapshots.Calls);
        Assert.DoesNotContain("opaque-session-value", session.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Authorization")]
    [InlineData("Host")]
    [InlineData("Content-Length")]
    [InlineData("Transfer-Encoding")]
    [InlineData("Connection")]
    [InlineData("Cookie")]
    [InlineData("Set-Cookie")]
    [InlineData("Proxy-Authorization")]
    [InlineData("Proxy-Authenticate")]
    [InlineData("Forwarded")]
    [InlineData("Via")]
    [InlineData("X-Correlation-ID")]
    [InlineData("TRACEPARENT")]
    [InlineData("TraceParent")]
    [InlineData("traceparent")]
    [InlineData("TRACESTATE")]
    [InlineData("Baggage")]
    [InlineData("X-Forwarded-For")]
    [InlineData("x-forwarded-for")]
    [InlineData("X-FORWARDED-PROTO")]
    [InlineData(" traceparent")]
    [InlineData("traceparent ")]
    [InlineData("trace\tparent")]
    [InlineData("Bad Header")]
    [InlineData("X-Bad\r\nInjected")]
    [InlineData("X-Bad\0Header")]
    public void Wave1_UT_header_name_normalization_cannot_bypass_infrastructure_denylist(string headerName)
    {
        OpaqueSessionAuthException failure = Assert.Throws<OpaqueSessionAuthException>(() => new HttpRequestHeaderOpaqueSessionPlacement(headerName, OpaqueSessionHttpHeaderValueFormat.RawOpaqueValue, null));
        Assert.Equal("SESSION-HTTP-HEADER-FORBIDDEN", failure.Code);
    }

    [Fact]
    public async Task Wave1_SEC_stale_version_endpoint_substitution_operation_and_generation_fail_before_network()
    {
        ProjectionFixture fixture = new();
        OpaqueSessionReference session = await fixture.AcquireAsync("operation-a");
        OpaqueSessionResolvedExecutionContext authority = await fixture.ResolveAsync("operation-a");

        fixture.Snapshots.Snapshot = fixture.Snapshots.Snapshot with
        {
            Version = fixture.Snapshots.Snapshot.Version with { Version = "2.0.0" }
        };
        Assert.Equal("SESSION-HTTP-AUTHORITY-STALE", (await Assert.ThrowsAsync<OpaqueSessionAuthException>(() => fixture.HttpClient.SendAsync(authority, ReadOnlyMemory<byte>.Empty, session, TestContext.Current.CancellationToken))).Code);

        fixture = new();
        session = await fixture.AcquireAsync("operation-a");
        authority = await fixture.ResolveAsync("operation-a");
        Dictionary<string, Uri> endpoints = new(fixture.Snapshots.Snapshot.Bindings.Endpoints, StringComparer.Ordinal) { ["service"] = new("https://attacker.example") };
        fixture.Snapshots.Snapshot = fixture.Snapshots.Snapshot with { Bindings = fixture.Snapshots.Snapshot.Bindings with { Endpoints = endpoints } };
        Assert.Equal("SESSION-HTTP-AUTHORITY-STALE", (await Assert.ThrowsAsync<OpaqueSessionAuthException>(() => fixture.HttpClient.SendAsync(authority, ReadOnlyMemory<byte>.Empty, session, TestContext.Current.CancellationToken))).Code);

        ProjectionFixture operationB = new();
        OpaqueSessionReference shared = await operationB.AcquireAsync("operation-a");
        OpaqueSessionResolvedExecutionContext authorityB = await operationB.ResolveAsync("operation-b");
        OpaqueSessionHttpResponse operationBResponse = await operationB.HttpClient.SendAsync(authorityB, ReadOnlyMemory<byte>.Empty, shared, TestContext.Current.CancellationToken);
        Assert.Equal(200, operationBResponse.StatusCode);
        Assert.Equal(1, operationB.Transport.HttpDispatchCount);

        fixture = new();
        session = await fixture.AcquireAsync("operation-a");
        authority = await fixture.ResolveAsync("operation-a");
        fixture.SoapClient.InvalidateSession(fixture.Context("operation-a"), new(SessionEndpoint, 7), ProjectionFixture.Profile(), new OpaqueSoapSessionReference(session.Value));
        Assert.Equal("SESSION-HTTP-SESSION-INVALID", (await Assert.ThrowsAsync<OpaqueSessionAuthException>(() => fixture.HttpClient.SendAsync(authority, ReadOnlyMemory<byte>.Empty, session, TestContext.Current.CancellationToken))).Code);

        ProjectionFixture expired = new();
        OpaqueSessionReference expiring = await expired.AcquireAsync("operation-a");
        expired.Clock.UtcNow = expired.Clock.UtcNow.AddHours(2);
        OpaqueSessionResolvedExecutionContext renewedAuthority = await expired.ResolveAsync("operation-a");
        Assert.Equal("SESSION-HTTP-SESSION-INVALID", (await Assert.ThrowsAsync<OpaqueSessionAuthException>(() => expired.HttpClient.SendAsync(renewedAuthority, ReadOnlyMemory<byte>.Empty, expiring, TestContext.Current.CancellationToken))).Code);
        Assert.Equal(0, fixture.Transport.HttpDispatchCount);
        Assert.Equal(0, expired.Transport.HttpDispatchCount);
    }

    [Theory]
    [InlineData("disable")]
    [InlineData("rotate")]
    [InlineData("endpoint")]
    public async Task Wave1_SEC_deterministic_final_dispatch_race_revalidates_after_materialization_and_sends_zero(string mutation)
    {
        TaskCompletionSource entered = NewSignal();
        TaskCompletionSource release = NewSignal();
        async Task Hook(CancellationToken cancellationToken)
        {
            entered.TrySetResult();
            await release.Task.WaitAsync(cancellationToken);
        }

        ProjectionFixture fixture = new(beforeFinalAuthorization: Hook);
        OpaqueSessionReference session = await fixture.AcquireAsync("operation-a");
        OpaqueSessionResolvedExecutionContext authority = await fixture.ResolveAsync("operation-a");
        Task<OpaqueSessionHttpResponse> pending = fixture.HttpClient.SendAsync(authority, new byte[1024 * 1024], session, TestContext.Current.CancellationToken);
        await entered.Task;

        if (mutation == "disable") fixture.Snapshots.FailClosed = true;
        else if (mutation == "rotate") fixture.Snapshots.RotateCredential();
        else fixture.Snapshots.SubstituteEndpoint(new Uri("https://changed.synthetic.example"));
        release.TrySetResult();

        _ = await Assert.ThrowsAsync<OpaqueSessionAuthException>(() => pending);
        Assert.Equal(0, fixture.Transport.HttpDispatchCount);
        Assert.Null(fixture.Transport.ProjectedHeader);
    }

    [Fact]
    public async Task Wave1_SEC_attacker_destination_bad_session_and_transport_exception_are_sanitized()
    {
        ProjectionFixture badSession = new(sessionValue: "bad\r\nInjected: true");
        OpaqueSessionReference invalid = await badSession.AcquireAsync("operation-a");
        OpaqueSessionResolvedExecutionContext authority = await badSession.ResolveAsync("operation-a");
        Assert.Equal("SESSION-HTTP-SESSION-INVALID", (await Assert.ThrowsAsync<OpaqueSessionAuthException>(() => badSession.HttpClient.SendAsync(authority, ReadOnlyMemory<byte>.Empty, invalid, TestContext.Current.CancellationToken))).Code);
        Assert.Equal(0, badSession.Transport.HttpDispatchCount);

        ProjectionFixture attacker = new(resolver: new HostMappedResolver());
        OpaqueSessionReference attackerSession = await attacker.AcquireAsync("operation-a");
        OpaqueSessionResolvedExecutionContext attackerAuthority = await attacker.ResolveAsync("operation-a");
        Assert.Equal("SESSION-HTTP-EGRESS-DESTINATION-DENIED", (await Assert.ThrowsAsync<OpaqueSessionAuthException>(() => attacker.HttpClient.SendAsync(attackerAuthority, ReadOnlyMemory<byte>.Empty, attackerSession, TestContext.Current.CancellationToken))).Code);
        Assert.Equal(0, attacker.Transport.HttpDispatchCount);

        ProjectionFixture throwing = new();
        throwing.Transport.ThrowCanary = true;
        OpaqueSessionReference throwingSession = await throwing.AcquireAsync("operation-a");
        OpaqueSessionResolvedExecutionContext throwingAuthority = await throwing.ResolveAsync("operation-a");
        OpaqueSessionAuthException sanitized = await Assert.ThrowsAsync<OpaqueSessionAuthException>(() => throwing.HttpClient.SendAsync(throwingAuthority, ReadOnlyMemory<byte>.Empty, throwingSession, TestContext.Current.CancellationToken));
        Assert.Equal("SESSION-HTTP-TRANSPORT-FAILED", sanitized.Code);
        Assert.DoesNotContain("CANARY", sanitized.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("opaque-session-value", JsonSerializer.Serialize(throwingAuthority), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Wave1_UT_transport_deadline_and_caller_cancellation_remain_distinct()
    {
        ProjectionFixture deadline = new();
        OpaqueSessionReference deadlineSession = await deadline.AcquireAsync("operation-a");
        OpaqueSessionResolvedExecutionContext deadlineAuthority = await deadline.ResolveAsync("operation-a");
        deadline.Transport.CancelFromTransportDeadline = true;

        OpaqueSessionAuthException timeout = await Assert.ThrowsAsync<OpaqueSessionAuthException>(() =>
            deadline.HttpClient.SendAsync(deadlineAuthority, ReadOnlyMemory<byte>.Empty, deadlineSession, TestContext.Current.CancellationToken));

        Assert.Equal("SESSION-HTTP-TIMEOUT", timeout.Code);
        Assert.Equal(1, deadline.Transport.HttpDispatchCount);

        ProjectionFixture caller = new();
        OpaqueSessionReference callerSession = await caller.AcquireAsync("operation-a");
        OpaqueSessionResolvedExecutionContext callerAuthority = await caller.ResolveAsync("operation-a");
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            caller.HttpClient.SendAsync(callerAuthority, ReadOnlyMemory<byte>.Empty, callerSession, cancellation.Token));
        Assert.Equal(1, caller.Transport.HttpDispatchCount);
    }

    [Fact]
    public void Wave1_CT_authorized_handoff_and_generic_dispatch_cannot_be_forged_by_public_callers()
    {
        Assert.Empty(typeof(OpaqueSessionAuthorizedInvocation).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(OpaqueSessionResolvedExecutionContext).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(OpaqueSessionReference).GetConstructors(BindingFlags.Public | BindingFlags.Instance));

        ConstructorInfo request = Assert.Single(typeof(OpaqueSessionHttpAuthorityRequest).GetConstructors());
        Assert.Equal(PolicySelectorParameterNames, request.GetParameters().Select(value => value.Name).ToArray());
        MethodInfo dispatch = Assert.Single(typeof(OpaqueSessionHttpClient).GetMethods(), value => value.Name == nameof(OpaqueSessionHttpClient.SendAsync));
        string[] names = dispatch.GetParameters().Select(value => value.Name!).ToArray();
        Assert.DoesNotContain(names, value => value.Contains("endpoint", StringComparison.OrdinalIgnoreCase) || value.Contains("method", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("header", StringComparison.OrdinalIgnoreCase) || value.Contains("scheme", StringComparison.OrdinalIgnoreCase) || value.Contains("revision", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("operation", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(dispatch.GetParameters(), value => value.ParameterType == typeof(HttpRequestMessage));
        Assert.Equal("SecureIntegration.Gateway.ConnectorRuntime.Auth.Http", typeof(OpaqueSessionHttpClient).Assembly.GetName().Name);
        Assert.DoesNotContain(typeof(OpaqueSessionHttpClient).GetMethods().SelectMany(value => value.GetParameters()), value => value.ParameterType.Name.Contains("Soap", StringComparison.Ordinal));
        Assert.False(typeof(OpaqueSessionAuthException).IsAssignableTo(typeof(SoapAuthException)));
    }

    private sealed class ProjectionFixture
    {
        private readonly Guid tenantId = Guid.NewGuid();
        private readonly Guid installationId = Guid.NewGuid();
        private readonly Guid applicationId = Guid.NewGuid();
        private readonly Guid environmentId = Guid.NewGuid();
        private readonly Guid versionId = Guid.NewGuid();
        private readonly Guid connectorId = Guid.NewGuid();

        internal ProjectionFixture(OpaqueSessionHttpHeaderValueFormat format = OpaqueSessionHttpHeaderValueFormat.RawOpaqueValue, string? scheme = null,
            string sessionValue = "opaque-session-value", IHostResolver? resolver = null, Func<CancellationToken, Task>? beforeFinalAuthorization = null)
        {
            Clock = new();
            Transport = new() { SessionValue = sessionValue };
            Snapshots = new(CreateSnapshot(format, scheme));
            SoapClient = new(new FixedSecrets(), new FixedResolver(IPAddress.Parse("8.8.8.8")), Transport, Clock, new MatchingStampProvider());
            HttpClient = new(SoapClient.OpaqueSessionLeases, resolver ?? new FixedResolver(IPAddress.Parse("8.8.8.8")), Transport, Clock, null, beforeFinalAuthorization);
            Authority = new PublishedOpaqueSessionAuthorityResolver(Snapshots.ResolveAsync, Clock);
        }

        internal MutableClock Clock { get; }
        internal ProjectionTransport Transport { get; }
        internal MutableSnapshotSource Snapshots { get; }
        internal SoapSessionClient SoapClient { get; }
        internal OpaqueSessionHttpClient HttpClient { get; }
        internal PublishedOpaqueSessionAuthorityResolver Authority { get; }

        internal ConnectorAuthExecutionContext Context(string operationId) => new(tenantId, installationId, applicationId, environmentId, "synthetic-session", "1.0.0", operationId, 7, 7, 11, "opaque-session", Guid.NewGuid(), Clock.UtcNow.AddMinutes(5));

        internal async Task<OpaqueSessionReference> AcquireAsync(string operationId)
        {
            OpaqueSoapSessionReference session = await SoapClient.AcquireSessionAsync(Context(operationId), new(SessionEndpoint, 7), Profile(), TestContext.Current.CancellationToken);
            return session.ToOpaqueSessionReference();
        }

        internal Task<OpaqueSessionResolvedExecutionContext> ResolveAsync(string operationId)
        {
            RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
                Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], Clock.UtcNow.AddMinutes(-1), Clock.UtcNow.AddHours(1), "1.0.0", null);
            GatewayClientPrincipal principal = new(identity, Guid.NewGuid());
            return Authority.ResolveAsync(new OpaqueSessionAuthorizedInvocation(principal, "synthetic-session", operationId), new("session-header"), TestContext.Current.CancellationToken);
        }

        internal static SoapSessionProfile Profile()
        {
            const string ns = "urn:synthetic:session";
            SoapOperationProfile login = new("login", SoapEnvelopeVersion.Soap11, "urn:synthetic:login", new("Login", ns), new("LoginResponse", ns));
            SoapOperationProfile operationA = new("operation-a", SoapEnvelopeVersion.Soap11, "urn:synthetic:a", new("BusinessA", ns), new("BusinessAResponse", ns));
            SoapOperationProfile operationB = new("operation-b", SoapEnvelopeVersion.Soap11, "urn:synthetic:b", new("BusinessB", ns), new("BusinessBResponse", ns));
            return new("opaque-session", new("username", "password"), login, new("SessionId", ns), new("Session", ns), [operationA, operationB], TimeSpan.FromHours(1), []);
        }

        private PublishedConnectorSnapshot CreateSnapshot(OpaqueSessionHttpHeaderValueFormat format, string? scheme)
        {
            object Operation(string operationId) => new
            {
                operationId,
                endpointBinding = "service",
                path = "/resource",
                method = "POST",
                timeoutMs = 5000,
                authentication = new
                {
                    kind = "opaqueSessionHttp",
                    policyId = "session-header",
                    sessionProfileId = "opaque-session",
                    secretBinding = "session-credential",
                    headerName = "X-Session-Reference",
                    valueFormat = format == OpaqueSessionHttpHeaderValueFormat.RawOpaqueValue ? "rawOpaqueValue" : "fixedSchemeAndOpaqueValue",
                    fixedScheme = scheme
                },
                request = new { contentType = "application/json", maximumBytes = 2 * 1024 * 1024 },
                response = new { maximumBytes = 4096 }
            };
            string canonical = JsonSerializer.Serialize(new { connectorId = "synthetic-session", version = "1.0.0", operations = new[] { Operation("operation-a"), Operation("operation-b") } });
            ConnectorVersionRecord version = new(versionId, connectorId, "synthetic-session", "1.0.0", "wave1-test", ConnectorVersionState.Published,
                canonical, SHA256.HashData(Encoding.UTF8.GetBytes(canonical)), "test", Clock.UtcNow, 1, Clock.UtcNow, Clock.UtcNow);
            ProviderResourceBinding resource = new("synthetic", "Synthetic", "Synthetic", "session-secret", ProviderResourceType.Secret, "Session credential", environmentId,
                "synthetic-session", "*", "per-run", 11, null, null, "catalog-checksum");
            Dictionary<string, Uri> endpoints = new(StringComparer.Ordinal) { ["service"] = HttpBaseEndpoint };
            ConnectorBindingSet bindings = new(Guid.NewGuid(), connectorId, versionId, environmentId, endpoints,
                new Dictionary<string, ProviderResourceBinding>(StringComparer.Ordinal) { ["session-credential"] = resource },
                new Dictionary<string, ProviderResourceBinding>(StringComparer.Ordinal), 7, "binding-checksum", ConnectorBindingState.Active, Clock.UtcNow, "test");
            PublishedConnectorStamp stamp = new(versionId, 3, 7, "binding-checksum", "resource-stamp-11");
            return new(version, bindings, stamp, new Dictionary<string, string>(StringComparer.Ordinal), new Dictionary<string, string>(StringComparer.Ordinal));
        }
    }

    private sealed class MutableSnapshotSource(PublishedConnectorSnapshot snapshot)
    {
        internal PublishedConnectorSnapshot Snapshot { get; set; } = snapshot;
        internal bool FailClosed { get; set; }
        internal int Calls { get; private set; }

        internal Task<PublishedConnectorSnapshot?> ResolveAsync(string connectorId, Guid environmentId, PublishedConnectorAccessContext access, CancellationToken cancellationToken)
        {
            Calls++;
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

        internal void SubstituteEndpoint(Uri endpoint)
        {
            Snapshot = Snapshot with { Bindings = Snapshot.Bindings with { Endpoints = new Dictionary<string, Uri> { ["service"] = endpoint } } };
        }
    }

    private sealed class MutableClock : IGatewayClock
    {
        public DateTimeOffset UtcNow { get; set; } = new(2026, 8, 8, 12, 0, 0, TimeSpan.Zero);
    }

    private sealed class FixedSecrets : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string providerReference, CancellationToken cancellationToken) => Task.FromResult("synthetic");
    }

    private sealed class FixedResolver(IPAddress address) : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { address });
    }

    private sealed class HostMappedResolver : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { IPAddress.Loopback });
    }

    private sealed class MatchingStampProvider : ISoapSessionResourceStampProvider
    {
        public Task<SoapSessionResourceStamp?> GetCurrentAsync(ConnectorAuthExecutionContext context, CancellationToken cancellationToken) =>
            Task.FromResult<SoapSessionResourceStamp?>(new(context.CredentialRevision, SoapCredentialResourceStatus.Active, context.BindingRevision, context.EndpointRevision));
    }

    private sealed class ProjectionTransport : IRestrictedTransport
    {
        public int HttpDispatchCount { get; private set; }
        public string? ProjectedHeader { get; private set; }
        public Uri? RequestUri { get; private set; }
        public string SessionValue { get; set; } = "opaque-session-value";
        public bool ThrowCanary { get; set; }
        public bool CancelFromTransportDeadline { get; set; }

        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, System.Security.Cryptography.X509Certificates.X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            HttpDispatchCount++;
            RequestUri = request.RequestUri;
            ProjectedHeader = request.Headers.TryGetValues("X-Session-Reference", out IEnumerable<string>? values) ? Assert.Single(values) : null;
            if (cancellationToken.IsCancellationRequested) return Task.FromCanceled<ExternalResponse>(cancellationToken);
            if (CancelFromTransportDeadline) return Task.FromCanceled<ExternalResponse>(new CancellationToken(canceled: true));
            if (ThrowCanary) throw new HttpRequestException("CANARY opaque-session-value");
            return Task.FromResult(new ExternalResponse(200, "text/plain", Encoding.UTF8.GetBytes("accepted")));
        }

        public Task<ExternalResponse> SendSoapAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            string body = $"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><s:LoginResponse xmlns:s=\"urn:synthetic:session\"><s:SessionId>{System.Security.SecurityElement.Escape(SessionValue)}</s:SessionId></s:LoginResponse></soap:Body></soap:Envelope>";
            return Task.FromResult(new ExternalResponse(200, "text/xml; charset=utf-8", Encoding.UTF8.GetBytes(body)));
        }
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

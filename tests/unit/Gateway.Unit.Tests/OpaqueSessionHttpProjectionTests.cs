using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class OpaqueSessionHttpProjectionTests
{
    private static readonly Uri SessionEndpoint = new("https://session.synthetic.example/service");
    private static readonly Uri HttpEndpoint = new("https://api.synthetic.example/resource");

    [Theory]
    [InlineData(OpaqueSessionHttpHeaderValueFormat.RawOpaqueValue, null, "opaque-session-value")]
    [InlineData(OpaqueSessionHttpHeaderValueFormat.FixedSchemeAndOpaqueValue, "Session", "Session opaque-session-value")]
    public async Task Wave1_UT_opaque_session_is_projected_once_only_during_restricted_dispatch(
        OpaqueSessionHttpHeaderValueFormat format, string? scheme, string expectedHeader)
    {
        MutableClock clock = new();
        MutableStampProvider stamps = new(ContextStamp());
        MutablePolicySource policies = new(Policy(format, scheme));
        ProjectionTransport transport = new();
        SoapSessionClient client = Client(clock, stamps, policies, transport);
        ConnectorAuthExecutionContext context = Context(clock);
        OpaqueSoapSessionReference session = await client.AcquireSessionAsync(context, new(SessionEndpoint, 7), Profile(), TestContext.Current.CancellationToken);

        OpaqueSessionHttpResponse response = await client.SendWithOpaqueSessionAsync(context, "session-header", Encoding.UTF8.GetBytes("business-input"), session, TestContext.Current.CancellationToken);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("accepted", Encoding.UTF8.GetString(response.Body));
        Assert.Equal(expectedHeader, transport.ProjectedHeader);
        Assert.Equal(1, transport.HttpDispatchCount);
        Assert.Equal(HttpEndpoint, transport.RequestUri);
        Assert.Equal(3, policies.Calls);
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
    [InlineData("Bad Header")]
    [InlineData("X-Bad\r\nInjected")]
    public void Wave1_UT_header_field_name_is_a_valid_token_and_security_owned_headers_are_denied(string headerName)
    {
        SoapAuthException failure = Assert.Throws<SoapAuthException>(() => Policy(headerName: headerName));
        Assert.Equal("SESSION-HTTP-HEADER-FORBIDDEN", failure.Code);
    }

    [Fact]
    public async Task Wave1_SEC_operation_endpoint_generation_expiry_and_resource_revisions_fail_before_dispatch()
    {
        MutableClock clock = new();
        MutableStampProvider stamps = new(ContextStamp());
        MutablePolicySource policies = new(Policy());
        ProjectionTransport transport = new();
        SoapSessionClient client = Client(clock, stamps, policies, transport);
        ConnectorAuthExecutionContext context = Context(clock);
        OpaqueSoapSessionReference session = await client.AcquireSessionAsync(context, new(SessionEndpoint, 7), Profile(), TestContext.Current.CancellationToken);

        ConnectorAuthExecutionContext operationB = context with { OperationId = "operation-b", CorrelationId = Guid.NewGuid() };
        policies.Current = Policy(operationId: "operation-b");
        Assert.Equal("SESSION-HTTP-SESSION-INVALID", (await Assert.ThrowsAsync<SoapAuthException>(() => client.SendWithOpaqueSessionAsync(operationB, "session-header", ReadOnlyMemory<byte>.Empty, session, TestContext.Current.CancellationToken))).Code);

        policies.Current = Policy(endpointRevision: 8);
        Assert.Equal("SESSION-HTTP-POLICY-BINDING-MISMATCH", (await Assert.ThrowsAsync<SoapAuthException>(() => client.SendWithOpaqueSessionAsync(context, "session-header", ReadOnlyMemory<byte>.Empty, session, TestContext.Current.CancellationToken))).Code);

        policies.Current = Policy();
        OpaqueSoapSessionReference unknownReference = new(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_'));
        Assert.Equal("SESSION-HTTP-SESSION-INVALID", (await Assert.ThrowsAsync<SoapAuthException>(() => client.SendWithOpaqueSessionAsync(context, "session-header", ReadOnlyMemory<byte>.Empty, unknownReference, TestContext.Current.CancellationToken))).Code);
        client.InvalidateSession(context, new(SessionEndpoint, 7), Profile(), session);
        OpaqueSoapSessionReference nextGeneration = await client.AcquireSessionAsync(context, new(SessionEndpoint, 7), Profile(), TestContext.Current.CancellationToken);
        Assert.NotEqual(session.Value, nextGeneration.Value);
        Assert.Equal("SESSION-HTTP-SESSION-INVALID", (await Assert.ThrowsAsync<SoapAuthException>(() => client.SendWithOpaqueSessionAsync(context, "session-header", ReadOnlyMemory<byte>.Empty, session, TestContext.Current.CancellationToken))).Code);
        session = nextGeneration;

        stamps.Current = stamps.Current with { CredentialStatus = SoapCredentialResourceStatus.Disabled };
        Assert.Equal("SOAP-CREDENTIAL-INACTIVE", (await Assert.ThrowsAsync<SoapAuthException>(() => client.SendWithOpaqueSessionAsync(context, "session-header", ReadOnlyMemory<byte>.Empty, session, TestContext.Current.CancellationToken))).Code);
        stamps.Current = ContextStamp() with { CredentialResourceRevision = 12 };
        Assert.Equal("SOAP-RESOURCE-STAMP-STALE", (await Assert.ThrowsAsync<SoapAuthException>(() => client.SendWithOpaqueSessionAsync(context, "session-header", ReadOnlyMemory<byte>.Empty, session, TestContext.Current.CancellationToken))).Code);
        stamps.Current = ContextStamp() with { BindingRevision = 6 };
        Assert.Equal("SOAP-RESOURCE-STAMP-STALE", (await Assert.ThrowsAsync<SoapAuthException>(() => client.SendWithOpaqueSessionAsync(context, "session-header", ReadOnlyMemory<byte>.Empty, session, TestContext.Current.CancellationToken))).Code);
        stamps.Current = ContextStamp() with { EndpointRevision = 8 };
        Assert.Equal("SOAP-RESOURCE-STAMP-STALE", (await Assert.ThrowsAsync<SoapAuthException>(() => client.SendWithOpaqueSessionAsync(context, "session-header", ReadOnlyMemory<byte>.Empty, session, TestContext.Current.CancellationToken))).Code);

        stamps.Current = ContextStamp();
        clock.UtcNow = clock.UtcNow.AddHours(2);
        ConnectorAuthExecutionContext renewed = context with { Deadline = clock.UtcNow.AddMinutes(1), CorrelationId = Guid.NewGuid() };
        Assert.Equal("SESSION-HTTP-SESSION-INVALID", (await Assert.ThrowsAsync<SoapAuthException>(() => client.SendWithOpaqueSessionAsync(renewed, "session-header", ReadOnlyMemory<byte>.Empty, session, TestContext.Current.CancellationToken))).Code);
        Assert.Equal(0, transport.HttpDispatchCount);
    }

    [Fact]
    public async Task Wave1_SEC_disable_during_policy_await_applies_no_header_and_dispatches_zero_requests()
    {
        MutableClock clock = new();
        MutableStampProvider stamps = new(ContextStamp());
        BlockingSecondPolicySource policies = new(Policy());
        ProjectionTransport transport = new();
        SoapSessionClient client = Client(clock, stamps, policies, transport);
        ConnectorAuthExecutionContext context = Context(clock);
        OpaqueSoapSessionReference session = await client.AcquireSessionAsync(context, new(SessionEndpoint, 7), Profile(), TestContext.Current.CancellationToken);

        Task<OpaqueSessionHttpResponse> pending = client.SendWithOpaqueSessionAsync(context, "session-header", ReadOnlyMemory<byte>.Empty, session, TestContext.Current.CancellationToken);
        await policies.SecondResolveEntered.Task;
        stamps.Current = stamps.Current with { CredentialStatus = SoapCredentialResourceStatus.Disabled };
        policies.ReleaseSecondResolve.SetResult(true);

        SoapAuthException failure = await Assert.ThrowsAsync<SoapAuthException>(() => pending);
        Assert.Equal("SOAP-CREDENTIAL-INACTIVE", failure.Code);
        Assert.Equal(0, transport.HttpDispatchCount);
        Assert.Null(transport.ProjectedHeader);
    }

    [Fact]
    public async Task Wave1_SEC_attacker_destination_bad_session_and_transport_exception_are_sanitized()
    {
        MutableClock clock = new();
        MutableStampProvider stamps = new(ContextStamp());
        MutablePolicySource policies = new(Policy());
        ProjectionTransport transport = new() { SessionValue = "bad\r\nInjected: true" };
        SoapSessionClient client = Client(clock, stamps, policies, transport);
        ConnectorAuthExecutionContext context = Context(clock);
        OpaqueSoapSessionReference bad = await client.AcquireSessionAsync(context, new(SessionEndpoint, 7), Profile(), TestContext.Current.CancellationToken);
        Assert.Equal("SESSION-HTTP-SESSION-INVALID", (await Assert.ThrowsAsync<SoapAuthException>(() => client.SendWithOpaqueSessionAsync(context, "session-header", ReadOnlyMemory<byte>.Empty, bad, TestContext.Current.CancellationToken))).Code);
        Assert.Equal(0, transport.HttpDispatchCount);

        ProjectionTransport attackerTransport = new();
        SoapSessionClient attackerClient = new(new FixedSecrets(), new HostMappedResolver(), attackerTransport, clock, stamps, null, policies);
        OpaqueSoapSessionReference attackerSession = await attackerClient.AcquireSessionAsync(context, new(SessionEndpoint, 7), Profile(), TestContext.Current.CancellationToken);
        Assert.Equal("SESSION-HTTP-EGRESS-DESTINATION-DENIED", (await Assert.ThrowsAsync<SoapAuthException>(() => attackerClient.SendWithOpaqueSessionAsync(context, "session-header", ReadOnlyMemory<byte>.Empty, attackerSession, TestContext.Current.CancellationToken))).Code);
        Assert.Equal(0, attackerTransport.HttpDispatchCount);

        ProjectionTransport throwing = new() { ThrowCanary = true };
        SoapSessionClient throwingClient = Client(clock, stamps, policies, throwing);
        OpaqueSoapSessionReference throwingSession = await throwingClient.AcquireSessionAsync(context, new(SessionEndpoint, 7), Profile(), TestContext.Current.CancellationToken);
        SoapAuthException sanitized = await Assert.ThrowsAsync<SoapAuthException>(() => throwingClient.SendWithOpaqueSessionAsync(context, "session-header", ReadOnlyMemory<byte>.Empty, throwingSession, TestContext.Current.CancellationToken));
        Assert.Equal("SESSION-HTTP-TRANSPORT-FAILED", sanitized.Code);
        Assert.DoesNotContain("CANARY", sanitized.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("opaque-session-value", JsonSerializer.Serialize(Policy()), StringComparison.Ordinal);
    }

    [Fact]
    public void Wave1_CT_public_dispatch_has_no_header_session_value_endpoint_or_authenticated_request_override()
    {
        System.Reflection.MethodInfo method = Assert.Single(typeof(SoapSessionClient).GetMethods(), value => value.Name == nameof(SoapSessionClient.SendWithOpaqueSessionAsync));
        string[] names = method.GetParameters().Select(value => value.Name!).ToArray();
        Assert.DoesNotContain(names, value => value.Contains("header", StringComparison.OrdinalIgnoreCase) || value.Contains("endpoint", StringComparison.OrdinalIgnoreCase) || value.Contains("sessionValue", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(method.GetParameters(), value => value.ParameterType == typeof(HttpRequestMessage));
        Assert.Equal(OpaqueSessionPlacementKind.SoapXml, Profile().PlacementPolicy.Kind);
        Assert.Equal(OpaqueSessionPlacementKind.HttpRequestHeader, Policy().Placement.Kind);
    }

    private static SoapSessionClient Client(MutableClock clock, ISoapSessionResourceStampProvider stamps, IOpaqueSessionHttpPolicySource policies, ProjectionTransport transport) =>
        new(new FixedSecrets(), new FixedResolver(IPAddress.Parse("8.8.8.8")), transport, clock, stamps, null, policies);

    private static ConnectorAuthExecutionContext Context(MutableClock clock) => new(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "synthetic-session", "1.0.0", "operation-a", 5, 7, 11, "opaque-session", Guid.NewGuid(), clock.UtcNow.AddMinutes(5), "resource-stamp");
    private static SoapSessionResourceStamp ContextStamp() => new(11, SoapCredentialResourceStatus.Active, 5, 7, "resource-stamp");

    private static ServerOwnedOpaqueSessionHttpPolicySnapshot Policy(OpaqueSessionHttpHeaderValueFormat format = OpaqueSessionHttpHeaderValueFormat.RawOpaqueValue, string? scheme = null,
        string headerName = "X-Session-Reference", string operationId = "operation-a", long endpointRevision = 7) =>
        ServerOwnedOpaqueSessionHttpPolicySnapshot.Create("session-header", "synthetic-session", "1.0.0", operationId, "opaque-session", TestEnvironment,
            HttpEndpoint, HttpMethod.Post, "application/json", 5, endpointRevision, 11, "resource-stamp", headerName, format, scheme,
            TimeSpan.FromSeconds(5), 1024, 1024);

    private static Guid TestEnvironment { get; } = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    private static SoapSessionProfile Profile()
    {
        SoapElementRule session = new("SessionId", "urn:synthetic:session");
        SoapOperationProfile login = new("login", SoapEnvelopeVersion.Soap11, "urn:synthetic:login", new("Login", "urn:synthetic:session"), new("LoginResponse", "urn:synthetic:session"));
        SoapOperationProfile business = new("operation-a", SoapEnvelopeVersion.Soap11, "urn:synthetic:business", new("Business", "urn:synthetic:session"), new("BusinessResponse", "urn:synthetic:session"));
        return new("opaque-session", new("username", "password"), login, session, new("Session", "urn:synthetic:session"), [business], TimeSpan.FromHours(1), []);
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
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) =>
            Task.FromResult(new[] { string.Equals(host, SessionEndpoint.DnsSafeHost, StringComparison.Ordinal) ? IPAddress.Parse("8.8.8.8") : IPAddress.Loopback });
    }

    private sealed class MutableStampProvider(SoapSessionResourceStamp current) : ISoapSessionResourceStampProvider
    {
        public SoapSessionResourceStamp Current { get; set; } = current;
        public Task<SoapSessionResourceStamp?> GetCurrentAsync(ConnectorAuthExecutionContext context, CancellationToken cancellationToken) => Task.FromResult<SoapSessionResourceStamp?>(Current);
    }

    private sealed class MutablePolicySource(ServerOwnedOpaqueSessionHttpPolicySnapshot current) : IOpaqueSessionHttpPolicySource
    {
        public ServerOwnedOpaqueSessionHttpPolicySnapshot Current { get; set; } = current;
        public int Calls { get; private set; }
        public Task<ServerOwnedOpaqueSessionHttpPolicySnapshot> ResolveAsync(ConnectorAuthExecutionContext context, string policyId, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(Current.EnvironmentId == context.EnvironmentId ? Current : Rebind(Current, context.EnvironmentId));
        }
    }

    private sealed class BlockingSecondPolicySource(ServerOwnedOpaqueSessionHttpPolicySnapshot current) : IOpaqueSessionHttpPolicySource
    {
        private int calls;
        public TaskCompletionSource<bool> SecondResolveEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> ReleaseSecondResolve { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<ServerOwnedOpaqueSessionHttpPolicySnapshot> ResolveAsync(ConnectorAuthExecutionContext context, string policyId, CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref calls) == 2)
            {
                SecondResolveEntered.SetResult(true);
                await ReleaseSecondResolve.Task.WaitAsync(cancellationToken);
            }
            return Rebind(current, context.EnvironmentId);
        }
    }

    private sealed class ProjectionTransport : IRestrictedTransport
    {
        public int HttpDispatchCount { get; private set; }
        public string? ProjectedHeader { get; private set; }
        public Uri? RequestUri { get; private set; }
        public string SessionValue { get; set; } = "opaque-session-value";
        public bool ThrowCanary { get; set; }

        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, System.Security.Cryptography.X509Certificates.X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            HttpDispatchCount++;
            RequestUri = request.RequestUri;
            ProjectedHeader = request.Headers.TryGetValues("X-Session-Reference", out IEnumerable<string>? values) ? Assert.Single(values) : null;
            if (ThrowCanary) throw new HttpRequestException("CANARY opaque-session-value");
            return Task.FromResult(new ExternalResponse(200, "text/plain", Encoding.UTF8.GetBytes("accepted")));
        }

        public Task<ExternalResponse> SendSoapAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            string body = $"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><s:LoginResponse xmlns:s=\"urn:synthetic:session\"><s:SessionId>{System.Security.SecurityElement.Escape(SessionValue)}</s:SessionId></s:LoginResponse></soap:Body></soap:Envelope>";
            return Task.FromResult(new ExternalResponse(200, "text/xml; charset=utf-8", Encoding.UTF8.GetBytes(body)));
        }
    }

    private static ServerOwnedOpaqueSessionHttpPolicySnapshot Rebind(ServerOwnedOpaqueSessionHttpPolicySnapshot value, Guid environmentId) =>
        ServerOwnedOpaqueSessionHttpPolicySnapshot.Create(value.PolicyId, value.ConnectorId, value.ConnectorVersion, value.OperationId, value.ProfileId, environmentId,
            value.Endpoint, value.Method, value.ContentType, value.BindingRevision, value.EndpointRevision, value.CredentialRevision, value.ResourceStamp,
            value.Placement.HeaderName, value.Placement.ValueFormat, value.Placement.FixedScheme, value.Timeout, value.MaximumRequestBytes, value.MaximumResponseBytes);
}

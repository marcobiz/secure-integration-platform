using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class RuntimeExecutionStrategyTests
{
    [Theory]
    [InlineData(GatewayAuthenticationKind.SoapBasicOpaqueSession)]
    [InlineData(GatewayAuthenticationKind.OpaqueSessionHttp)]
    public async Task Wave1_UT_runtime_selects_the_exact_qualified_strategy_only_after_principal_grant_and_operation_resolution(GatewayAuthenticationKind kind)
    {
        RuntimeFixture fixture = await RuntimeFixture.CreateAsync(kind, grant: true);
        RecordingStrategy exact = new(kind);
        RecordingStrategy wrong = new(kind == GatewayAuthenticationKind.SoapBasicOpaqueSession ? GatewayAuthenticationKind.OpaqueSessionHttp : GatewayAuthenticationKind.SoapBasicOpaqueSession);
        RestrictedEgressService runtime = fixture.Runtime([wrong, exact]);

        GatewayInvokeResponse response = await runtime.InvokeAsync(fixture.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId, fixture.Request, TestContext.Current.CancellationToken);

        Assert.Equal(1, exact.Calls);
        Assert.Equal(0, wrong.Calls);
        Assert.Equal(0, fixture.Transport.Calls);
        Assert.Equal("qualified", System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(response.Result.Data)));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task Wave1_SEC_invalid_grant_missing_mode_and_duplicate_mode_deny_before_strategy_or_network(bool grant, bool duplicate)
    {
        RuntimeFixture fixture = await RuntimeFixture.CreateAsync(GatewayAuthenticationKind.SoapBasicOpaqueSession, grant);
        RecordingStrategy first = new(duplicate ? GatewayAuthenticationKind.SoapBasicOpaqueSession : GatewayAuthenticationKind.OpaqueSessionHttp);
        RecordingStrategy second = new(GatewayAuthenticationKind.SoapBasicOpaqueSession);
        IEnumerable<IGatewayOperationExecutionStrategy> strategies = duplicate ? [first, second] : [first];
        RestrictedEgressService runtime = fixture.Runtime(strategies);

        GatewayException failure = await Assert.ThrowsAsync<GatewayException>(() => runtime.InvokeAsync(fixture.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId,
            fixture.Request, TestContext.Current.CancellationToken));

        Assert.Equal(grant ? "BGW-EGRESS-AUTHENTICATION" : "BGW-AUTHZ-OPERATION-DENIED", failure.Code);
        Assert.Equal(0, first.Calls);
        Assert.Equal(0, second.Calls);
        Assert.Equal(0, fixture.Transport.Calls);
    }

    [Fact]
    public void Wave1_CT_qualified_execution_handoff_is_non_forgeable_and_hides_payload_and_operation_authority()
    {
        Assert.Empty(typeof(AuthorizedGatewayOperationExecution).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(typeof(AuthorizedGatewayOperationExecution).GetProperties(BindingFlags.Public | BindingFlags.Instance), property =>
            property.Name is "Payload" or "Operation" or "Principal" or "Endpoint" or "AuthenticationKind");
    }

    private sealed class RuntimeFixture
    {
        internal const string ConnectorId = "qualified-runtime";
        internal const string OperationId = "dispatch";
        private readonly InMemoryGatewayRegistry registry;
        private readonly GatewayOperationCatalog catalog;

        private RuntimeFixture(InMemoryGatewayRegistry registry, GatewayOperationCatalog catalog, GatewayClientPrincipal principal, GatewayInvokeRequest request)
        {
            this.registry = registry;
            this.catalog = catalog;
            Principal = principal;
            Request = request;
        }

        internal RecordingTransport Transport { get; } = new();
        internal GatewayClientPrincipal Principal { get; }
        internal GatewayInvokeRequest Request { get; }

        internal RestrictedEgressService Runtime(IEnumerable<IGatewayOperationExecutionStrategy> strategies) =>
            new(registry, catalog, new NeverSecrets(), new NeverCertificates(), new PublicResolver(), Transport, new FixedClock(), null, strategies);

        internal static async Task<RuntimeFixture> CreateAsync(GatewayAuthenticationKind kind, bool grant)
        {
            DateTimeOffset now = FixedClock.Now;
            Guid tenantId = Guid.NewGuid(); Guid applicationId = Guid.NewGuid(); Guid environmentId = Guid.NewGuid(); Guid installationId = Guid.NewGuid();
            InMemoryGatewayRegistry registry = new();
            await registry.AddTenantAsync(new(tenantId, "qualified", "Qualified", TenantStatus.Active, now), TestContext.Current.CancellationToken);
            await registry.AddApplicationAsync(new(applicationId, "qualified", "Qualified", ApplicationStatus.Active, "3.0.0", null, now), TestContext.Current.CancellationToken);
            await registry.AddEnvironmentAsync(new(environmentId, "qualified", "Qualified", false), TestContext.Current.CancellationToken);
            await registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "3.0.0", now), TestContext.Current.CancellationToken);
            if (grant) await registry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, ConnectorId, OperationId, true, now.AddMinutes(-1)), TestContext.Current.CancellationToken);
            GatewayOperationDefinition operation = new(ConnectorId, OperationId, "1.0.0", new("https://vendor.example.test/dispatch"), HttpMethod.Post,
                kind == GatewayAuthenticationKind.SoapBasicOpaqueSession ? "text/xml" : "application/json", kind,
                kind == GatewayAuthenticationKind.SoapBasicOpaqueSession ? "user-ref" : null,
                kind == GatewayAuthenticationKind.SoapBasicOpaqueSession ? "password-ref" : null,
                "session-ref", "X-Session-Reference", null, 5_000, 4096, 4096, false, 0, "qualified-policy", "qualified-session");
            RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
                Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], now.AddMinutes(-1), now.AddHours(1), "3.0.0", null);
            GatewayInvokeRequest request = new("1.0", new(kind == GatewayAuthenticationKind.SoapBasicOpaqueSession ? "text/xml" : "application/json", "utf8", "<request/>"), Guid.NewGuid());
            return new(registry, new([operation]), new(identity, request.CorrelationId), request);
        }
    }

    private sealed class RecordingStrategy(GatewayAuthenticationKind kind) : IGatewayOperationExecutionStrategy
    {
        public GatewayAuthenticationKind AuthenticationKind => kind;
        public int Calls { get; private set; }
        public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedGatewayOperationExecution execution, CancellationToken cancellationToken)
        {
            Calls++;
            Assert.Equal(RuntimeFixture.ConnectorId, execution.ConnectorId);
            Assert.Equal(RuntimeFixture.OperationId, execution.OperationId);
            return Task.FromResult(new QualifiedGatewayExecutionResult(200, "application/octet-stream", "qualified"u8.ToArray()));
        }
    }

    private sealed class RecordingTransport : IRestrictedTransport
    {
        public int Calls { get; private set; }
        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout,
            long maximumResponseBytes, CancellationToken cancellationToken)
        {
            Calls++;
            throw new InvalidOperationException("Qualified modes must not fall back to the ordinary transport path.");
        }
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

    private sealed class FixedClock : IGatewayClock
    {
        internal static readonly DateTimeOffset Now = new(2026, 8, 9, 12, 0, 0, TimeSpan.Zero);
        public DateTimeOffset UtcNow => Now;
    }
}

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.Authentication.CertificateSigning.Tests;

public sealed class MutualTlsSecurityTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 7, 10, 0, 0, TimeSpan.Zero);
    private static readonly string[] PurposeDenialCodes = ["BGW-AUTH-MTLS-CERTIFICATE-DENIED", "BGW-AUTH-MTLS-CERTIFICATE-PURPOSE"];

    [Fact]
    public async Task M6_MTLS_positive_dispatches_once_without_exposing_certificate_handle()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        ServerOwnedMutualTlsPolicySnapshot policy = AuthenticationTestData.MutualTlsPolicy(context, material.ClientCertificateRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        TrackingCertificateProvider tracking = new(AuthenticationTestData.Provider(material));
        MutableBindingResolver bindings = new(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1", policy));
        StaticHostResolver hosts = new(IPAddress.Parse("203.0.113.20"));
        TrackingTransport transport = new();
        PurposeBoundMutualTlsSender sender = new(policies, bindings, tracking, tracking, hosts, transport, new FixedClock(Now));
        using HttpRequestMessage request = new(HttpMethod.Get, context.Endpoint);

        MutualTlsAuthenticatedResponse result = await sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request, TestContext.Current.CancellationToken);

        Assert.Equal(200, result.Response.StatusCode);
        Assert.Equal(ClientCertificateHealth.Healthy, result.CertificateHealth);
        Assert.Equal(material.ClientCertificateRevision1.SerialNumber, result.CertificateVersion);
        Assert.Equal(1, result.CatalogRevision);
        Assert.Equal(["mtls-r1"], tracking.MetadataReferences);
        Assert.Equal(["mtls-r1"], tracking.CertificateReferences);
        Assert.Equal(2, bindings.Calls);
        Assert.Equal(1, transport.Calls);
        Assert.True(transport.CertificateHadPrivateKey);
    }

    [Fact]
    public async Task M6_MTLS_expired_and_wrong_purpose_certificates_are_denied_before_network()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        FixedClock clock = new(Now);

        AuthenticationExecutionContext expiredContext = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        ServerOwnedMutualTlsPolicySnapshot expiredPolicy = AuthenticationTestData.MutualTlsPolicy(expiredContext, material.ExpiredClientCertificate);
        MutablePolicySource expiredPolicies = AuthenticationTestData.Policies(expiredContext, material.SigningKeyRevision1, material.ExpiredClientCertificate);
        expiredPolicies.MutualTls = expiredPolicy;
        StaticHostResolver expiredHosts = new(IPAddress.Parse("203.0.113.20"));
        TrackingTransport expiredTransport = new();
        PurposeBoundMutualTlsSender expiredSender = new(expiredPolicies,
            new MutableBindingResolver(AuthenticationTestData.MutualTlsBinding(expiredContext, material.ExpiredClientCertificate, "mtls-expired", expiredPolicy)),
            provider, provider, expiredHosts, expiredTransport, clock);
        using HttpRequestMessage expiredRequest = new(HttpMethod.Get, expiredContext.Endpoint);
        AuthenticationPrimitiveException expired = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => expiredSender.SendAsync(expiredContext, AuthenticationTestData.MutualTlsProfileId, expiredRequest, TestContext.Current.CancellationToken));

        AuthenticationExecutionContext wrongContext = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        ServerOwnedMutualTlsPolicySnapshot wrongPolicy = AuthenticationTestData.MutualTlsPolicy(wrongContext, material.WrongPurposeCertificate);
        MutablePolicySource wrongPolicies = AuthenticationTestData.Policies(wrongContext, material.SigningKeyRevision1, material.WrongPurposeCertificate);
        wrongPolicies.MutualTls = wrongPolicy;
        StaticHostResolver wrongHosts = new(IPAddress.Parse("203.0.113.20"));
        TrackingTransport wrongTransport = new();
        PurposeBoundMutualTlsSender wrongSender = new(wrongPolicies,
            new MutableBindingResolver(AuthenticationTestData.MutualTlsBinding(wrongContext, material.WrongPurposeCertificate, "mtls-wrong-purpose", wrongPolicy)),
            provider, provider, wrongHosts, wrongTransport, clock);
        using HttpRequestMessage wrongRequest = new(HttpMethod.Get, wrongContext.Endpoint);
        AuthenticationPrimitiveException wrong = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => wrongSender.SendAsync(wrongContext, AuthenticationTestData.MutualTlsProfileId, wrongRequest, TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-MTLS-CERTIFICATE-DENIED", expired.Code);
        Assert.Contains(wrong.Code, PurposeDenialCodes);
        Assert.Equal(0, expiredHosts.Calls);
        Assert.Equal(0, wrongHosts.Calls);
        Assert.Equal(0, expiredTransport.Calls);
        Assert.Equal(0, wrongTransport.Calls);
    }

    [Fact]
    public async Task M6_MTLS_near_expiry_surfaces_warning_without_automatic_denial()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        ServerOwnedMutualTlsPolicySnapshot policy = AuthenticationTestData.MutualTlsPolicy(context, material.NearExpiryClientCertificate, warning: TimeSpan.FromDays(7));
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.NearExpiryClientCertificate);
        policies.MutualTls = policy;
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        PurposeBoundMutualTlsSender sender = new(policies,
            new MutableBindingResolver(AuthenticationTestData.MutualTlsBinding(context, material.NearExpiryClientCertificate, "mtls-near", policy)),
            provider, provider, new StaticHostResolver(IPAddress.Parse("203.0.113.20")), new TrackingTransport(), new FixedClock(Now));
        using HttpRequestMessage request = new(HttpMethod.Get, context.Endpoint);

        MutualTlsAuthenticatedResponse result = await sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request, TestContext.Current.CancellationToken);

        Assert.Equal(ClientCertificateHealth.NearExpiry, result.CertificateHealth);
    }

    [Fact]
    public async Task M6_MTLS_disabled_binding_denies_before_metadata_certificate_DNS_or_network()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        ServerOwnedMutualTlsPolicySnapshot policy = AuthenticationTestData.MutualTlsPolicy(context, material.ClientCertificateRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        TrackingCertificateProvider tracking = new(AuthenticationTestData.Provider(material));
        StaticHostResolver hosts = new(IPAddress.Parse("203.0.113.20"));
        TrackingTransport transport = new();
        PurposeBoundMutualTlsSender sender = new(policies,
            new MutableBindingResolver(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1", policy, status: AuthenticationResourceStatus.Disabled)),
            tracking, tracking, hosts, transport, new FixedClock(Now));
        using HttpRequestMessage request = new(HttpMethod.Get, context.Endpoint);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request, TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-RESOURCE-DISABLED", failure.Code);
        Assert.Empty(tracking.MetadataReferences);
        Assert.Empty(tracking.CertificateReferences);
        Assert.Equal(0, hosts.Calls);
        Assert.Equal(0, transport.Calls);
    }

    [Fact]
    public async Task M6_MTLS_rotation_uses_revision_two_and_never_returns_revision_one_handle()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        ServerOwnedMutualTlsPolicySnapshot revision1 = AuthenticationTestData.MutualTlsPolicy(context, material.ClientCertificateRevision1);
        ServerOwnedMutualTlsPolicySnapshot revision2 = AuthenticationTestData.MutualTlsPolicy(context, material.ClientCertificateRevision2, revision: 2);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        TrackingCertificateProvider tracking = new(AuthenticationTestData.Provider(material));
        MutableBindingResolver bindings = new(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1", revision1));
        TrackingTransport transport = new();
        PurposeBoundMutualTlsSender sender = new(policies, bindings, tracking, tracking, new StaticHostResolver(IPAddress.Parse("203.0.113.20")), transport, new FixedClock(Now));

        using (HttpRequestMessage request1 = new(HttpMethod.Get, context.Endpoint))
            await sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request1, TestContext.Current.CancellationToken);
        policies.MutualTls = revision2;
        bindings.Current = AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision2, "mtls-r2", revision2);
        using (HttpRequestMessage request2 = new(HttpMethod.Get, context.Endpoint))
            await sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request2, TestContext.Current.CancellationToken);

        Assert.Equal(["mtls-r1", "mtls-r2"], tracking.CertificateReferences);
        Assert.Equal(2, transport.Calls);
        Assert.Equal([material.ClientCertificateRevision1.SerialNumber, material.ClientCertificateRevision2.SerialNumber], transport.CertificateVersions);
    }

    [Fact]
    public async Task M6_MTLS_retained_revision_one_provider_result_after_rotate_causes_zero_connection()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        await using SyntheticMutualTlsServer server = await SyntheticMutualTlsServer.StartAsync(material.ServerCertificate, material.ClientCertificateRevision2, TestContext.Current.CancellationToken);
        Uri endpoint = new($"https://localhost:{server.Port}/synthetic");
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId, endpoint);
        ServerOwnedMutualTlsPolicySnapshot revision2 = AuthenticationTestData.MutualTlsPolicy(context, material.ClientCertificateRevision2, revision: 2);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision2);
        policies.MutualTls = revision2;
        InMemoryProvider validProvider = AuthenticationTestData.Provider(material);
        IClientCertificateProvider staleCertificate = new StaleCertificateProvider(material.ClientCertificateRevision1);
        StaticHostResolver hosts = new(IPAddress.Loopback);
        X509Certificate2Collection trust = new(material.RootCertificate);
        PurposeBoundMutualTlsSender sender = new(policies,
            new MutableBindingResolver(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision2, "mtls-r2", revision2)),
            staleCertificate, validProvider, hosts, RestrictedTransport(trust), new FixedClock(Now), new LoopbackAllowance());
        using HttpRequestMessage request = new(HttpMethod.Get, endpoint);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request, TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-MTLS-CERTIFICATE-DENIED", failure.Code);
        Assert.Equal(0, hosts.Calls);
        Assert.False(server.ConnectionAccepted);
    }

    [Theory]
    [InlineData("operation")]
    [InlineData("environment")]
    [InlineData("endpoint")]
    [InlineData("purpose")]
    public async Task M6_MTLS_scope_and_purpose_mismatch_deny_before_provider_or_network(string mismatch)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        ServerOwnedMutualTlsPolicySnapshot policy = AuthenticationTestData.MutualTlsPolicy(context, material.ClientCertificateRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        BoundAuthenticationResource binding = AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1", policy);
        binding = mismatch switch
        {
            "operation" => binding with { OperationId = "other-operation" },
            "environment" => binding with { EnvironmentId = Guid.NewGuid() },
            "endpoint" => binding with { Endpoint = new Uri("https://other.example.test/api") },
            "purpose" => binding with { Purpose = AuthenticationResourcePurpose.JwtSigning },
            _ => binding
        };
        TrackingCertificateProvider tracking = new(AuthenticationTestData.Provider(material));
        StaticHostResolver hosts = new(IPAddress.Parse("203.0.113.20"));
        TrackingTransport transport = new();
        PurposeBoundMutualTlsSender sender = new(policies, new MutableBindingResolver(binding), tracking, tracking, hosts, transport, new FixedClock(Now));
        using HttpRequestMessage request = new(HttpMethod.Get, context.Endpoint);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request, TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-RESOURCE-BOUNDARY", failure.Code);
        Assert.Empty(tracking.MetadataReferences);
        Assert.Empty(tracking.CertificateReferences);
        Assert.Equal(0, hosts.Calls);
        Assert.Equal(0, transport.Calls);
    }

    [Fact]
    public async Task M6_MTLS_endpoint_substitution_is_denied_before_handshake()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext contextA = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId, new Uri("https://endpoint-a.example.test/api"));
        AuthenticationExecutionContext contextB = contextA with { Endpoint = new Uri("https://endpoint-b.example.test/api") };
        ServerOwnedMutualTlsPolicySnapshot policyA = AuthenticationTestData.MutualTlsPolicy(contextA, material.ClientCertificateRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(contextA, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.MutualTls = policyA;
        StaticHostResolver hosts = new(IPAddress.Parse("203.0.113.20"));
        TrackingTransport transport = new();
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        PurposeBoundMutualTlsSender sender = new(policies,
            new MutableBindingResolver(AuthenticationTestData.MutualTlsBinding(contextA, material.ClientCertificateRevision1, "mtls-r1", policyA)),
            provider, provider, hosts, transport, new FixedClock(Now));
        using HttpRequestMessage request = new(HttpMethod.Get, contextB.Endpoint);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => sender.SendAsync(contextB, AuthenticationTestData.MutualTlsProfileId, request, TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-MTLS-POLICY-DENIED", failure.Code);
        Assert.Equal(0, hosts.Calls);
        Assert.Equal(0, transport.Calls);
    }

    [Fact]
    public async Task M6_MTLS_disable_during_one_shot_revalidation_causes_zero_dispatch()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        ServerOwnedMutualTlsPolicySnapshot policy = AuthenticationTestData.MutualTlsPolicy(context, material.ClientCertificateRevision1);
        BoundAuthenticationResource active = AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1", policy);
        MutableBindingResolver bindings = new(active) { OnResolve = call => call == 1 ? active : active with { Status = AuthenticationResourceStatus.Disabled } };
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        StaticHostResolver hosts = new(IPAddress.Parse("203.0.113.20"));
        TrackingTransport transport = new();
        PurposeBoundMutualTlsSender sender = new(policies, bindings, provider, provider, hosts, transport, new FixedClock(Now));
        using HttpRequestMessage request = new(HttpMethod.Get, context.Endpoint);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request, TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-RESOURCE-DISABLED", failure.Code);
        Assert.Equal(0, hosts.Calls);
        Assert.Equal(0, transport.Calls);
    }

    [Fact]
    public async Task M6_MTLS_missing_capability_has_clear_failure_state_and_zero_dispatch()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        ServerOwnedMutualTlsPolicySnapshot policy = AuthenticationTestData.MutualTlsPolicy(context, material.ClientCertificateRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        MutableBindingResolver bindings = new(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1", policy));
        StaticHostResolver hosts = new(IPAddress.Parse("203.0.113.20"));
        TrackingTransport transport = new();
        PurposeBoundMutualTlsSender sender = new(policies, bindings, null, null, hosts, transport, new FixedClock(Now));
        using HttpRequestMessage request = new(HttpMethod.Get, context.Endpoint);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request, TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-MTLS-CAPABILITY-UNAVAILABLE", failure.Code);
        Assert.Equal(0, bindings.Calls);
        Assert.Equal(0, hosts.Calls);
        Assert.Equal(0, transport.Calls);
    }

    [Fact]
    public async Task M6_MTLS_real_local_server_accepts_expected_certificate_over_pinned_egress()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        await using SyntheticMutualTlsServer server = await SyntheticMutualTlsServer.StartAsync(material.ServerCertificate, material.ClientCertificateRevision1, TestContext.Current.CancellationToken);
        Uri endpoint = new($"https://localhost:{server.Port}/synthetic");
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId, endpoint);
        ServerOwnedMutualTlsPolicySnapshot policy = AuthenticationTestData.MutualTlsPolicy(context, material.ClientCertificateRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.MutualTls = policy;
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        X509Certificate2Collection trust = new(material.RootCertificate);
        PurposeBoundMutualTlsSender sender = new(policies,
            new MutableBindingResolver(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1", policy)),
            provider, provider, new StaticHostResolver(IPAddress.Loopback), RestrictedTransport(trust), new FixedClock(Now), new LoopbackAllowance());
        using HttpRequestMessage request = new(HttpMethod.Get, endpoint);

        MutualTlsAuthenticatedResponse response = await sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request, TestContext.Current.CancellationToken);
        await server.WaitAsync();

        Assert.Equal(200, response.Response.StatusCode);
        Assert.True(server.ExpectedCertificateObserved);
    }

    [Fact]
    public async Task M6_MTLS_hostname_validation_and_rejected_certificate_fail_handshake()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        X509Certificate2Collection trust = new(material.RootCertificate);

        await using (SyntheticMutualTlsServer hostnameServer = await SyntheticMutualTlsServer.StartAsync(material.ServerCertificate, material.ClientCertificateRevision1, TestContext.Current.CancellationToken))
        {
            Uri endpoint = new($"https://wrong-host:{hostnameServer.Port}/synthetic");
            AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId, endpoint);
            ServerOwnedMutualTlsPolicySnapshot policy = AuthenticationTestData.MutualTlsPolicy(context, material.ClientCertificateRevision1);
            MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
            policies.MutualTls = policy;
            InMemoryProvider provider = AuthenticationTestData.Provider(material);
            PurposeBoundMutualTlsSender sender = new(policies,
                new MutableBindingResolver(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1", policy)),
                provider, provider, new StaticHostResolver(IPAddress.Loopback), RestrictedTransport(trust), new FixedClock(Now));
            using HttpRequestMessage request = new(HttpMethod.Get, endpoint);
            await Assert.ThrowsAnyAsync<Exception>(() => sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request, TestContext.Current.CancellationToken));
        }

        await using (SyntheticMutualTlsServer certificateServer = await SyntheticMutualTlsServer.StartAsync(material.ServerCertificate, material.ClientCertificateRevision1, TestContext.Current.CancellationToken))
        {
            Uri endpoint = new($"https://localhost:{certificateServer.Port}/synthetic");
            AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId, endpoint);
            ServerOwnedMutualTlsPolicySnapshot policy = AuthenticationTestData.MutualTlsPolicy(context, material.ClientCertificateRevision2, revision: 2);
            MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision2);
            policies.MutualTls = policy;
            InMemoryProvider provider = AuthenticationTestData.Provider(material);
            PurposeBoundMutualTlsSender sender = new(policies,
                new MutableBindingResolver(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision2, "mtls-r2", policy)),
                provider, provider, new StaticHostResolver(IPAddress.Loopback), RestrictedTransport(trust), new FixedClock(Now), new LoopbackAllowance());
            using HttpRequestMessage request = new(HttpMethod.Get, endpoint);
            await Assert.ThrowsAnyAsync<Exception>(() => sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request, TestContext.Current.CancellationToken));
            Assert.False(certificateServer.ExpectedCertificateObserved);
        }
    }

    [Fact]
    public async Task M6_MTLS_restricted_egress_denies_loopback_without_explicit_allowance()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId, new Uri("https://localhost/synthetic"));
        ServerOwnedMutualTlsPolicySnapshot policy = AuthenticationTestData.MutualTlsPolicy(context, material.ClientCertificateRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.MutualTls = policy;
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        TrackingTransport transport = new();
        PurposeBoundMutualTlsSender sender = new(policies,
            new MutableBindingResolver(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1", policy)),
            provider, provider, new StaticHostResolver(IPAddress.Loopback), transport, new FixedClock(Now));
        using HttpRequestMessage request = new(HttpMethod.Get, context.Endpoint);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request, TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-MTLS-DESTINATION-DENIED", failure.Code);
        Assert.Equal(0, transport.Calls);
    }

    [Theory]
    [InlineData("metadata", "BGW-AUTH-MTLS-METADATA-UNAVAILABLE")]
    [InlineData("certificate", "BGW-AUTH-MTLS-CERTIFICATE-UNAVAILABLE")]
    public async Task M6_MTLS_unexpected_provider_exceptions_are_sanitized(string boundary, string expectedCode)
    {
        const string canary = "locator=hidden token=hidden secret=hidden";
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        ServerOwnedMutualTlsPolicySnapshot policy = AuthenticationTestData.MutualTlsPolicy(context, material.ClientCertificateRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        InMemoryProvider valid = AuthenticationTestData.Provider(material);
        UnexpectedFailingCertificateProvider failing = new(valid, boundary, canary);
        PurposeBoundMutualTlsSender sender = new(policies,
            new MutableBindingResolver(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1", policy)),
            failing, failing, new StaticHostResolver(IPAddress.Parse("203.0.113.20")), new TrackingTransport(), new FixedClock(Now));
        using HttpRequestMessage request = new(HttpMethod.Get, context.Endpoint);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request, TestContext.Current.CancellationToken));

        Assert.Equal(expectedCode, failure.Code);
        Assert.Equal(expectedCode, failure.Message);
        Assert.Null(failure.InnerException);
        Assert.DoesNotContain(canary, failure.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("hidden", failure.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task M6_MTLS_provider_cancellation_preserves_cancellation_semantics()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        ServerOwnedMutualTlsPolicySnapshot policy = AuthenticationTestData.MutualTlsPolicy(context, material.ClientCertificateRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        InMemoryProvider valid = AuthenticationTestData.Provider(material);
        using CancellationTokenSource cancellation = new();
        CancelingCertificateProvider provider = new(valid, cancellation);
        PurposeBoundMutualTlsSender sender = new(policies,
            new MutableBindingResolver(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1", policy)),
            provider, provider, new StaticHostResolver(IPAddress.Parse("203.0.113.20")), new TrackingTransport(), new FixedClock(Now));
        using HttpRequestMessage request = new(HttpMethod.Get, context.Endpoint);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sender.SendAsync(context, AuthenticationTestData.MutualTlsProfileId, request, cancellation.Token));
    }

    [Fact]
    public void M6_public_mTLS_API_has_no_certificate_handle_resolve_or_arbitrary_attach()
    {
        MethodInfo method = Assert.Single(typeof(PurposeBoundMutualTlsSender).GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly));
        Type[] parameters = method.GetParameters().Select(value => value.ParameterType).ToArray();

        Assert.Equal("SendAsync", method.Name);
        Assert.Equal([typeof(AuthenticationExecutionContext), typeof(string), typeof(HttpRequestMessage), typeof(CancellationToken)], parameters);
        Assert.DoesNotContain(typeof(X509Certificate2), parameters);
        Assert.Null(typeof(PurposeBoundMutualTlsSender).Assembly.GetType("SecureIntegration.Authentication.CertificateSigning.ResolvedClientCertificate"));
        Assert.Null(typeof(PurposeBoundMutualTlsSender).Assembly.GetType("SecureIntegration.Authentication.CertificateSigning.MutualTlsClientProfile"));
        Assert.Null(typeof(PurposeBoundMutualTlsSender).Assembly.GetType("SecureIntegration.Authentication.CertificateSigning.PurposeBoundClientCertificateResolver"));
        Assert.DoesNotContain(typeof(MutualTlsAuthenticatedResponse).GetProperties(), property => property.PropertyType == typeof(X509Certificate2));
        Assert.Empty(typeof(MutualTlsCertificateLease).GetProperties(BindingFlags.Instance | BindingFlags.Public));
        Assert.Empty(typeof(MutualTlsCertificateLease).GetConstructors(BindingFlags.Instance | BindingFlags.Public));
    }

    [Fact]
    public void M6_MTLS_internal_transport_lease_is_consumable_exactly_once()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        using X509Certificate2 certificate = new(material.ClientCertificateRevision1);
        MutualTlsCertificateLease lease = new(certificate);

        Assert.Same(certificate, lease.TakeCertificate());
        AuthenticationPrimitiveException failure = Assert.Throws<AuthenticationPrimitiveException>(() => lease.TakeCertificate());
        Assert.Equal("BGW-AUTH-MTLS-LEASE-CONSUMED", failure.Code);
    }

    private static PurposeBoundMutualTlsTransportAdapter RestrictedTransport(X509Certificate2Collection trust) =>
        new PurposeBoundMutualTlsTransportAdapter(new SystemRestrictedTransport(trust));

    private sealed class TrackingTransport : IPurposeBoundMutualTlsTransport
    {
        public int Calls { get; private set; }
        public bool CertificateHadPrivateKey { get; private set; }
        public List<string> CertificateVersions { get; } = [];

        public Task<MutualTlsTransportResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, MutualTlsCertificateLease certificateLease, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            X509Certificate2 certificate = certificateLease.TakeCertificate();
            CertificateHadPrivateKey = certificate.HasPrivateKey;
            CertificateVersions.Add(certificate.SerialNumber);
            return Task.FromResult(new MutualTlsTransportResponse(200, "application/json", "{}"u8.ToArray()));
        }
    }

    private sealed class StaleCertificateProvider(X509Certificate2 staleCertificate) : IClientCertificateProvider
    {
        public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new X509Certificate2(staleCertificate));
        }
    }

    private sealed class UnexpectedFailingCertificateProvider(InMemoryProvider valid, string boundary, string canary) : IClientCertificateProvider, ICertificateMetadataProvider
    {
        public Task<ProviderCertificatePublicMetadata> GetPublicMetadataAsync(string logicalReference, CancellationToken cancellationToken) =>
            boundary == "metadata" ? throw new InvalidOperationException(canary) : valid.GetPublicMetadataAsync(logicalReference, cancellationToken);

        public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken) =>
            throw new InvalidOperationException(canary);
    }

    private sealed class CancelingCertificateProvider(InMemoryProvider valid, CancellationTokenSource cancellation) : IClientCertificateProvider, ICertificateMetadataProvider
    {
        public Task<ProviderCertificatePublicMetadata> GetPublicMetadataAsync(string logicalReference, CancellationToken cancellationToken) =>
            valid.GetPublicMetadataAsync(logicalReference, cancellationToken);

        public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken)
        {
            cancellation.Cancel();
            return Task.FromCanceled<X509Certificate2>(cancellationToken);
        }
    }

    private sealed class SyntheticMutualTlsServer : IAsyncDisposable
    {
        private readonly TcpListener listener;
        private readonly CancellationTokenSource stop = new(TimeSpan.FromSeconds(15));
        private readonly Task run;
        private readonly string expectedFingerprint;

        private SyntheticMutualTlsServer(TcpListener listener, X509Certificate2 serverCertificate, X509Certificate2 expectedClientCertificate)
        {
            this.listener = listener;
            expectedFingerprint = Convert.ToHexString(SHA256.HashData(expectedClientCertificate.RawData));
            run = RunAsync(serverCertificate);
        }

        public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
        public bool ConnectionAccepted { get; private set; }
        public bool ExpectedCertificateObserved { get; private set; }
        public Exception? Failure { get; private set; }
        public Task WaitAsync() => run;

        public static Task<SyntheticMutualTlsServer> StartAsync(X509Certificate2 serverCertificate, X509Certificate2 expectedClientCertificate, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            TcpListener listener = new(IPAddress.Loopback, 0);
            listener.Start(1);
            return Task.FromResult(new SyntheticMutualTlsServer(listener, serverCertificate, expectedClientCertificate));
        }

        private async Task RunAsync(X509Certificate2 serverCertificate)
        {
            try
            {
                using TcpClient client = await listener.AcceptTcpClientAsync(stop.Token).ConfigureAwait(false);
                ConnectionAccepted = true;
                using SslStream stream = new(client.GetStream(), false, (_, certificate, _, _) =>
                {
                    if (certificate is null) return false;
                    ExpectedCertificateObserved = string.Equals(Convert.ToHexString(SHA256.HashData(certificate.GetRawCertData())), expectedFingerprint, StringComparison.Ordinal);
                    return ExpectedCertificateObserved;
                });
                await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCertificate,
                    ClientCertificateRequired = true,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, stop.Token).ConfigureAwait(false);
                byte[] buffer = new byte[4096];
                int total = 0;
                while (total < buffer.Length)
                {
                    int read = await stream.ReadAsync(buffer.AsMemory(total), stop.Token).ConfigureAwait(false);
                    if (read == 0) break;
                    total += read;
                    if (Encoding.ASCII.GetString(buffer, 0, total).Contains("\r\n\r\n", StringComparison.Ordinal)) break;
                }
                byte[] response = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
                await stream.WriteAsync(response, stop.Token).ConfigureAwait(false);
                await stream.FlushAsync(stop.Token).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is AuthenticationException or IOException or OperationCanceledException or SocketException)
            {
                Failure = exception;
            }
        }

        public async ValueTask DisposeAsync()
        {
            stop.Cancel();
            listener.Stop();
            try { await run.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            stop.Dispose();
        }
    }
}

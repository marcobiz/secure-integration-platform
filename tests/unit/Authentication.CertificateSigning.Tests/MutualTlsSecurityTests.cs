using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.Authentication.CertificateSigning.Tests;

public sealed class MutualTlsSecurityTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 7, 10, 0, 0, TimeSpan.Zero);
    private static readonly string[] PurposeDenialCodes = ["BGW-AUTH-MTLS-CERTIFICATE-DENIED", "BGW-AUTH-MTLS-CERTIFICATE-PURPOSE"];

    [Fact]
    public async Task M6_MTLS_positive_validates_public_metadata_and_private_key_use()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        TrackingCertificateProvider tracking = new(provider);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        MutableBindingResolver bindings = new(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1"));
        PurposeBoundClientCertificateResolver resolver = new(bindings, tracking, tracking, new FixedClock(Now));

        using ResolvedClientCertificate result = await resolver.ResolveClientCertificateAsync(context, AuthenticationTestData.MutualTlsProfile(), TestContext.Current.CancellationToken);

        Assert.True(result.Certificate.HasPrivateKey);
        Assert.Equal(ClientCertificateHealth.Healthy, result.Health);
        Assert.Equal(AuthenticationTestData.Metadata(material.ClientCertificateRevision1).FingerprintSha256, result.FingerprintSha256);
        Assert.Equal(1, result.CatalogRevision);
        Assert.Equal(["mtls-r1"], tracking.MetadataReferences);
        Assert.Equal(["mtls-r1"], tracking.CertificateReferences);
    }

    [Fact]
    public async Task M6_MTLS_expired_and_wrong_purpose_certificates_are_denied()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        FixedClock clock = new(Now);

        MutableBindingResolver expiredBinding = new(AuthenticationTestData.MutualTlsBinding(context, material.ExpiredClientCertificate, "mtls-expired"));
        PurposeBoundClientCertificateResolver expiredResolver = new(expiredBinding, provider, provider, clock);
        AuthenticationPrimitiveException expired = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => expiredResolver.ResolveClientCertificateAsync(context, AuthenticationTestData.MutualTlsProfile(), TestContext.Current.CancellationToken));

        MutableBindingResolver wrongBinding = new(AuthenticationTestData.MutualTlsBinding(context, material.WrongPurposeCertificate, "mtls-wrong-purpose"));
        PurposeBoundClientCertificateResolver wrongResolver = new(wrongBinding, provider, provider, clock);
        AuthenticationPrimitiveException wrong = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => wrongResolver.ResolveClientCertificateAsync(context, AuthenticationTestData.MutualTlsProfile(), TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-MTLS-CERTIFICATE-DENIED", expired.Code);
        Assert.Contains(wrong.Code, PurposeDenialCodes);
    }

    [Fact]
    public async Task M6_MTLS_near_expiry_surfaces_warning_without_automatic_denial()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        MutableBindingResolver bindings = new(AuthenticationTestData.MutualTlsBinding(context, material.NearExpiryClientCertificate, "mtls-near"));
        PurposeBoundClientCertificateResolver resolver = new(bindings, provider, provider, new FixedClock(Now));

        using ResolvedClientCertificate result = await resolver.ResolveClientCertificateAsync(context, AuthenticationTestData.MutualTlsProfile(TimeSpan.FromDays(7)), TestContext.Current.CancellationToken);

        Assert.Equal(ClientCertificateHealth.NearExpiry, result.Health);
    }

    [Fact]
    public async Task M6_MTLS_disabled_binding_denies_before_metadata_certificate_or_network()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        TrackingCertificateProvider tracking = new(AuthenticationTestData.Provider(material));
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        MutableBindingResolver bindings = new(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1", status: AuthenticationResourceStatus.Disabled));
        PurposeBoundClientCertificateResolver resolver = new(bindings, tracking, tracking, new FixedClock(Now));

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => resolver.ResolveClientCertificateAsync(context, AuthenticationTestData.MutualTlsProfile(), TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-RESOURCE-DISABLED", failure.Code);
        Assert.Empty(tracking.MetadataReferences);
        Assert.Empty(tracking.CertificateReferences);
    }

    [Fact]
    public async Task M6_MTLS_rotation_uses_revision_two_and_does_not_reuse_revision_one()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        TrackingCertificateProvider tracking = new(AuthenticationTestData.Provider(material));
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        MutableBindingResolver bindings = new(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1"));
        PurposeBoundClientCertificateResolver resolver = new(bindings, tracking, tracking, new FixedClock(Now));
        using ResolvedClientCertificate revision1 = await resolver.ResolveClientCertificateAsync(context, AuthenticationTestData.MutualTlsProfile(), TestContext.Current.CancellationToken);

        bindings.Current = AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision2, "mtls-r2", revision: 2);
        using ResolvedClientCertificate revision2 = await resolver.ResolveClientCertificateAsync(context, AuthenticationTestData.MutualTlsProfile(), TestContext.Current.CancellationToken);

        Assert.NotEqual(revision1.FingerprintSha256, revision2.FingerprintSha256);
        Assert.Equal(2, revision2.CatalogRevision);
        Assert.Equal(["mtls-r1", "mtls-r2"], tracking.CertificateReferences);
    }

    [Theory]
    [InlineData("operation")]
    [InlineData("environment")]
    [InlineData("endpoint")]
    [InlineData("purpose")]
    public async Task M6_MTLS_scope_and_purpose_mismatch_deny_before_provider(string mismatch)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        TrackingCertificateProvider tracking = new(AuthenticationTestData.Provider(material));
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        BoundAuthenticationResource binding = AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1");
        binding = mismatch switch
        {
            "operation" => binding with { OperationId = "other-operation" },
            "environment" => binding with { EnvironmentId = Guid.NewGuid() },
            "endpoint" => binding with { Endpoint = new Uri("https://other.example.test/api") },
            "purpose" => binding with { Purpose = AuthenticationResourcePurpose.JwtSigning },
            _ => binding
        };
        PurposeBoundClientCertificateResolver resolver = new(new MutableBindingResolver(binding), tracking, tracking, new FixedClock(Now));

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => resolver.ResolveClientCertificateAsync(context, AuthenticationTestData.MutualTlsProfile(), TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-RESOURCE-BOUNDARY", failure.Code);
        Assert.Empty(tracking.MetadataReferences);
        Assert.Empty(tracking.CertificateReferences);
    }

    [Fact]
    public async Task M6_MTLS_missing_capability_has_clear_failure_state()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId);
        MutableBindingResolver bindings = new(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1"));
        PurposeBoundClientCertificateResolver resolver = new(bindings, null, null, new FixedClock(Now));

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => resolver.ResolveClientCertificateAsync(context, AuthenticationTestData.MutualTlsProfile(), TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-MTLS-CAPABILITY-UNAVAILABLE", failure.Code);
        Assert.Equal(0, bindings.Calls);
        Assert.DoesNotContain(typeof(MutualTlsClientProfile).GetProperties(), property => property.Name.Contains("Pfx", StringComparison.OrdinalIgnoreCase) || property.Name.Contains("Provider", StringComparison.Ordinal) || property.Name.Contains("Locator", StringComparison.Ordinal));
    }

    [Fact]
    public async Task M6_MTLS_real_local_server_accepts_expected_certificate_over_pinned_egress()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        await using SyntheticMutualTlsServer server = await SyntheticMutualTlsServer.StartAsync(material.ServerCertificate, material.ClientCertificateRevision1, TestContext.Current.CancellationToken);
        Uri endpoint = new($"https://localhost:{server.Port}/synthetic");
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.MutualTlsProfileId, endpoint);
        MutableBindingResolver bindings = new(AuthenticationTestData.MutualTlsBinding(context, material.ClientCertificateRevision1, "mtls-r1"));
        PurposeBoundClientCertificateResolver resolver = new(bindings, provider, provider, new FixedClock(Now));
        using ResolvedClientCertificate resolved = await resolver.ResolveClientCertificateAsync(context, AuthenticationTestData.MutualTlsProfile(), TestContext.Current.CancellationToken);
        X509Certificate2Collection trust = new(material.RootCertificate);
        SystemRestrictedTransport transport = new(trust);
        using HttpRequestMessage request = new(HttpMethod.Get, endpoint);

        Gateway.Application.ExternalResponse response;
        try { response = await transport.SendAsync(request, [IPAddress.Loopback], resolved.Certificate, TimeSpan.FromSeconds(10), 4096, TestContext.Current.CancellationToken); }
        catch (HttpRequestException exception)
        {
            await server.WaitAsync();
            throw new InvalidOperationException($"Synthetic mTLS server failure: {server.Failure?.GetType().Name}: {server.Failure?.Message}", exception);
        }

        Assert.Equal(200, response.StatusCode);
        Assert.True(server.ExpectedCertificateObserved);
    }

    [Fact]
    public async Task M6_MTLS_hostname_validation_and_rejected_certificate_fail_handshake()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        X509Certificate2Collection trust = new(material.RootCertificate);
        SystemRestrictedTransport transport = new(trust);

        await using (SyntheticMutualTlsServer hostnameServer = await SyntheticMutualTlsServer.StartAsync(material.ServerCertificate, material.ClientCertificateRevision1, TestContext.Current.CancellationToken))
        {
            using HttpRequestMessage wrongHost = new(HttpMethod.Get, $"https://wrong-host:{hostnameServer.Port}/synthetic");
            await Assert.ThrowsAnyAsync<Exception>(() => transport.SendAsync(wrongHost, [IPAddress.Loopback], material.ClientCertificateRevision1, TimeSpan.FromSeconds(5), 4096, TestContext.Current.CancellationToken));
        }

        await using (SyntheticMutualTlsServer certificateServer = await SyntheticMutualTlsServer.StartAsync(material.ServerCertificate, material.ClientCertificateRevision1, TestContext.Current.CancellationToken))
        {
            using HttpRequestMessage rejected = new(HttpMethod.Get, $"https://localhost:{certificateServer.Port}/synthetic");
            await Assert.ThrowsAnyAsync<Exception>(() => transport.SendAsync(rejected, [IPAddress.Loopback], material.ClientCertificateRevision2, TimeSpan.FromSeconds(5), 4096, TestContext.Current.CancellationToken));
            Assert.False(certificateServer.ExpectedCertificateObserved);
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
                // Expected by negative handshake tests; no sensitive detail escapes the test server.
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

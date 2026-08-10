using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class AuthorizedVerticalCapabilityHostedIntegrationTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    [Fact]
    public Task Wave1_IT_PRODUCTION_HOST_in_memory_Published_profile_signs_x5c_and_dispatches_real_mTLS() =>
        RunAsync(runtimeConnection: null, adminConnection: null, requirePostgres: false);

    [Fact]
    public async Task Wave1_IT_PRODUCTION_HOST_PostgreSQL18_Published_profile_signs_x5c_and_dispatches_real_mTLS()
    {
        string? adminConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(adminConnection)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(migrationConnection)) Assert.Skip("PostgreSQL migration connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await PostgresIsolationTests.ApplyMigrationAsync();
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole =
            await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(adminConnection, migrationConnection, TestContext.Current.CancellationToken);
        await RunAsync(runtimeRole.ConnectionString, adminConnection, requirePostgres: true);
    }

    [Fact]
    public void Wave1_SEC_synthetic_mTLS_server_requires_the_exact_trusted_client_certificate()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        using SyntheticAuthenticationMaterial attacker = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);

        Assert.True(SyntheticSignedMutualTlsServer.ValidateClientCertificate(
            material.ClientCertificateRevision1,
            material.ClientCertificateRevision1,
            material.RootCertificate));
        Assert.False(SyntheticSignedMutualTlsServer.ValidateClientCertificate(
            material.ClientCertificateRevision2,
            material.ClientCertificateRevision1,
            material.RootCertificate));
        Assert.False(SyntheticSignedMutualTlsServer.ValidateClientCertificate(
            material.ClientCertificateRevision1,
            material.ClientCertificateRevision1,
            attacker.RootCertificate));
    }

    [Fact]
    public async Task Wave1_SEC_Published_A_to_B_during_signing_public_material_returns_no_token_and_performs_no_transport()
    {
        TaskCompletionSource publicMaterialEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releasePublicMaterial = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        InMemoryProvider inner = new(
            new Dictionary<string, string>(),
            certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["mtls-r1"] = material.ClientCertificateRevision1
            },
            signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["sign-r1"] = material.SigningKeyRevision1
            },
            certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal)
            {
                ["sign-r1"] = [material.RootCertificate]
            });
        BlockingPublicMaterialProvider provider = new(inner, async cancellationToken =>
        {
            publicMaterialEntered.TrySetResult();
            await releasePublicMaterial.Task.WaitAsync(cancellationToken);
        });
        await using SyntheticSignedMutualTlsServer server = await SyntheticSignedMutualTlsServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-signing-race-candidate",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));
        string connectorId = "synthetic-signing-race-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("signing-race-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("signing-race-application");
        string signingSpki = SpkiSha256(material.SigningKeyRevision1);
        string clientSpki = SpkiSha256(material.ClientCertificateRevision1);
        HostedCapabilityAuthority authorityA = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            Definition(connectorId, "1.0.0", signingSpki, clientSpki),
            provider,
            "sign-r1",
            "mtls-r1");
        await fixture.PublishAsync(authorityA, expectedPublicationRevision: 0);
        HostedCapabilityAuthority authorityB = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "2.0.0",
            environmentId,
            server.Endpoint,
            Definition(connectorId, "2.0.0", signingSpki, clientSpki),
            provider,
            "sign-r1",
            "mtls-r1");
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId,
            applicationId,
            environmentId,
            "signing-race-identity");
        await fixture.Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddGrantAsync(new(
            Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
            "signed-submit", true, fixture.Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
        GatewayInvokeRequest request = new(
            "1.0",
            new("application/octet-stream", "utf8", "caller-body"),
            Guid.NewGuid());
        Task<HttpResponseMessage> pending = fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
            JsonSerializer.SerializeToUtf8Bytes(request, WebJson));
        await publicMaterialEntered.Task.WaitAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.Transport.GenericRequests);

        try
        {
            await fixture.PublishAsync(authorityB, expectedPublicationRevision: 1);
        }
        finally
        {
            releasePublicMaterial.TrySetResult();
        }

        using HttpResponseMessage response = await pending;
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("BGW-CONNECTOR-CONFIGURATION-STALE", body, StringComparison.Ordinal);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.Transport.GenericRequests);
    }

    [Fact]
    public async Task Wave1_SEC_Published_A_to_B_after_DNS_denies_before_restricted_transport()
    {
        TaskCompletionSource dnsEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseDns = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        InMemoryProvider provider = new(
            new Dictionary<string, string>(),
            certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["mtls-r1"] = material.ClientCertificateRevision1
            },
            signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["sign-r1"] = material.SigningKeyRevision1
            },
            certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal)
            {
                ["sign-r1"] = [material.RootCertificate]
            });
        await using SyntheticSignedMutualTlsServer server = await SyntheticSignedMutualTlsServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-transport-race-candidate",
            executionModule: Module(),
            capabilityProvider: new(provider, material.RootCertificate));
        string connectorId = "synthetic-transport-race-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("transport-race-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("transport-race-application");
        string signingSpki = SpkiSha256(material.SigningKeyRevision1);
        string clientSpki = SpkiSha256(material.ClientCertificateRevision1);
        HostedCapabilityAuthority authorityA = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            Definition(connectorId, "1.0.0", signingSpki, clientSpki),
            provider,
            "sign-r1",
            "mtls-r1");
        await fixture.PublishAsync(authorityA, expectedPublicationRevision: 0);
        HostedCapabilityAuthority authorityB = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "2.0.0",
            environmentId,
            server.Endpoint,
            Definition(connectorId, "2.0.0", signingSpki, clientSpki),
            provider,
            "sign-r1",
            "mtls-r1");
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId,
            applicationId,
            environmentId,
            "transport-race-identity");
        await fixture.Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddGrantAsync(new(
            Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
            "signed-submit", true, fixture.Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
        fixture.Factory.BeforeHostResolution = async cancellationToken =>
        {
            dnsEntered.TrySetResult();
            await releaseDns.Task.WaitAsync(cancellationToken);
        };
        GatewayInvokeRequest request = new(
            "1.0",
            new("application/octet-stream", "utf8", "caller-body"),
            Guid.NewGuid());
        Task<HttpResponseMessage> pending = fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
            JsonSerializer.SerializeToUtf8Bytes(request, WebJson));
        await dnsEntered.Task.WaitAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.Transport.GenericRequests);

        try
        {
            await fixture.PublishAsync(authorityB, expectedPublicationRevision: 1);
        }
        finally
        {
            releaseDns.TrySetResult();
        }

        using HttpResponseMessage response = await pending;
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("BGW-CONNECTOR-CONFIGURATION-STALE", body, StringComparison.Ordinal);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.Transport.GenericRequests);
    }

    private static async Task RunAsync(string? runtimeConnection, string? adminConnection, bool requirePostgres)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        InMemoryProvider provider = new(
            new Dictionary<string, string>(),
            certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["mtls-r1"] = material.ClientCertificateRevision1
            },
            signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["sign-r1"] = material.SigningKeyRevision1
            },
            certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal)
            {
                ["sign-r1"] = [material.RootCertificate]
            });
        await using SyntheticSignedMutualTlsServer server = await SyntheticSignedMutualTlsServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        HostedExecutionModuleConfiguration module = Module();
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-capability-candidate",
            runtimeConnection: runtimeConnection,
            adminConnection: adminConnection,
            executionModule: module,
            capabilityProvider: new(provider, material.RootCertificate));
        Assert.Equal(requirePostgres, fixture.Store is RoutingConnectorConfigurationStore);

        string connectorId = "synthetic-capability-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("capability-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("capability-application");
        string definition = Definition(
            connectorId,
            "1.0.0",
            SpkiSha256(material.SigningKeyRevision1),
            SpkiSha256(material.ClientCertificateRevision1));
        HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            definition,
            provider,
            "sign-r1",
            "mtls-r1");
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(tenantId, applicationId, environmentId, "capability-identity");
        await fixture.Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddGrantAsync(new(
            Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
            "signed-submit", true, fixture.Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);

        GatewayInvokeRequest request = new(
            "1.0",
            new("application/octet-stream", "utf8", "caller-controlled-body"),
            Guid.NewGuid(),
            Metadata: new Dictionary<string, JsonElement>
            {
                ["endpoint"] = JsonSerializer.SerializeToElement("https://attacker.invalid/collect"),
                ["keyBinding"] = JsonSerializer.SerializeToElement("attacker-key"),
                ["certificateBinding"] = JsonSerializer.SerializeToElement("attacker-certificate"),
                ["profileId"] = JsonSerializer.SerializeToElement("attacker-profile")
            },
            Extensions: new Dictionary<string, JsonElement>
            {
                ["transaction-id"] = JsonSerializer.SerializeToElement("caller-claim")
            });
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
            JsonSerializer.SerializeToUtf8Bytes(request, WebJson));
        string responseJson = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.True(response.StatusCode == HttpStatusCode.OK, responseJson);
        GatewayInvokeResponse gateway = JsonSerializer.Deserialize<GatewayInvokeResponse>(responseJson, WebJson)
            ?? throw new InvalidOperationException("Capability response was empty.");
        Assert.Contains("accepted", Encoding.UTF8.GetString(Convert.FromBase64String(gateway.Result.Data)), StringComparison.Ordinal);
        Assert.Equal(1, server.Requests);
        Assert.True(server.ExpectedClientCertificateObserved);
        Assert.True(server.ValidSignedTokenObserved);
        Assert.True(server.X5cChainObserved);
        Assert.True(server.PublishedClaimObserved);
        Assert.True(server.PublishedBodyObserved);
        Assert.Equal(1, fixture.Transport.GenericRequests);

        string deniedDefinition = Definition(
            connectorId,
            "2.0.0",
            SpkiSha256(material.SigningKeyRevision1),
            SpkiSha256(material.ClientCertificateRevision1)).Replace(
                "\"executionStrategy\":\"synthetic-signed-mtls\"",
                "\"executionStrategy\":\"synthetic-denied-signing-claim\"",
                StringComparison.Ordinal);
        HostedCapabilityAuthority deniedAuthority = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "2.0.0",
            environmentId,
            server.Endpoint,
            deniedDefinition,
            provider,
            "sign-r1",
            "mtls-r1");
        await fixture.PublishAsync(deniedAuthority, expectedPublicationRevision: 1);
        using HttpResponseMessage deniedResponse = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
            JsonSerializer.SerializeToUtf8Bytes(request with { CorrelationId = Guid.NewGuid() }, WebJson));
        string deniedBody = await deniedResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Conflict, deniedResponse.StatusCode);
        Assert.Contains("BGW-EGRESS-AUTHENTICATION", deniedBody, StringComparison.Ordinal);
        Assert.Equal(1, server.Requests);
        Assert.Equal(1, fixture.Transport.GenericRequests);
    }

    private static HostedExecutionModuleConfiguration Module()
    {
        string path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "SecureIntegration.Synthetic.ConnectorExecutionModule.dll"));
        string fullName = System.Reflection.AssemblyName.GetAssemblyName(path).FullName
            ?? throw new InvalidOperationException("Synthetic execution module identity is unavailable.");
        return new("synthetic-execution", path, fullName, "SecureIntegration.Synthetic.ConnectorExecutionModule.SyntheticExecutionModule");
    }

    private static string SpkiSha256(X509Certificate2 certificate)
    {
        using RSA rsa = certificate.GetRSAPublicKey() ?? throw new InvalidOperationException("Synthetic RSA public key is unavailable.");
        return Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()));
    }

    private static string Definition(string connectorId, string version, string signingSpki, string clientSpki) => $$$"""
        {
          "schemaVersion":"1.0","connectorId":"{{{connectorId}}}","version":"{{{version}}}","displayName":"Synthetic authorized capabilities",
          "bindings":{"endpoints":[{"name":"service"}],"secrets":[{"name":"signing-certificate","kind":"clientCertificate"},{"name":"mtls-certificate","kind":"clientCertificate"}]},
          "operations":[{
            "operationId":"signed-submit","endpointBinding":"service","method":"POST","path":"/submit",
            "request":{"contentType":"application/octet-stream","maximumBytes":4096},"response":{"maximumBytes":4096},
            "authentication":{"kind":"mtls","certificateBinding":"mtls-certificate"},"executionStrategy":"synthetic-signed-mtls",
            "extensionConfiguration":{"claimName":"transaction-id","claimValue":"published-claim","body":"published-body"},
            "authorizedCapabilities":{
              "signing":{"profileId":"synthetic-signing","revision":1,"keyBinding":"signing-certificate","publicKeySpkiSha256":"{{{signingSpki}}}","issuer":"synthetic-gateway","audience":"synthetic-upstream","subject":"installation","allowedClaims":["transaction-id"],"tokenLifetimeSeconds":60,"clockSkewSeconds":5,"certificateHeader":"chain","temporalClaims":"iat-nbf-exp","minimumRsaKeySize":2048},
              "restrictedTransport":{"profileId":"synthetic-transport","revision":1,"clientCertificateSpkiSha256":"{{{clientSpki}}}","authorization":"signedTokenBearer","nearExpirySeconds":30}
            },
            "timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0
          }]
        }
        """;
}

internal sealed class BlockingPublicMaterialProvider(
    InMemoryProvider inner,
    Func<CancellationToken, Task> beforeFirstPublicMaterial) :
    IClientCertificateProvider,
    IKeyOperationProvider,
    ICertificateMetadataProvider,
    ICertificatePublicMaterialProvider
{
    private int publicMaterialCalls;

    public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken) =>
        inner.GetClientCertificateAsync(logicalReference, cancellationToken);

    public Task<ProviderCertificatePublicMetadata> GetPublicMetadataAsync(string logicalReference, CancellationToken cancellationToken) =>
        inner.GetPublicMetadataAsync(logicalReference, cancellationToken);

    public Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken) =>
        inner.SignDigestAsync(logicalReference, algorithm, digest, cancellationToken);

    public Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken) =>
        inner.GetSigningKeyMetadataAsync(logicalReference, cancellationToken);

    public async Task<ProviderCertificatePublicMaterial> GetPublicMaterialAsync(string logicalReference, CancellationToken cancellationToken)
    {
        if (Interlocked.Increment(ref publicMaterialCalls) == 1)
            await beforeFirstPublicMaterial(cancellationToken).ConfigureAwait(false);
        return await inner.GetPublicMaterialAsync(logicalReference, cancellationToken).ConfigureAwait(false);
    }
}

internal sealed class SyntheticSignedMutualTlsServer : IAsyncDisposable
{
    private readonly WebApplication application;
    private readonly string expectedClientFingerprint;
    private readonly string expectedSigningFingerprint;
    private int requests;
    private int expectedClientCertificateObserved;
    private int validSignedTokenObserved;
    private int x5cChainObserved;
    private int publishedClaimObserved;
    private int publishedBodyObserved;

    private SyntheticSignedMutualTlsServer(
        WebApplication application,
        Uri endpoint,
        string expectedClientFingerprint,
        string expectedSigningFingerprint)
    {
        this.application = application;
        Endpoint = endpoint;
        this.expectedClientFingerprint = expectedClientFingerprint;
        this.expectedSigningFingerprint = expectedSigningFingerprint;
    }

    internal Uri Endpoint { get; }
    internal int Requests => Volatile.Read(ref requests);
    internal bool ExpectedClientCertificateObserved => Volatile.Read(ref expectedClientCertificateObserved) == 1;
    internal bool ValidSignedTokenObserved => Volatile.Read(ref validSignedTokenObserved) == 1;
    internal bool X5cChainObserved => Volatile.Read(ref x5cChainObserved) == 1;
    internal bool PublishedClaimObserved => Volatile.Read(ref publishedClaimObserved) == 1;
    internal bool PublishedBodyObserved => Volatile.Read(ref publishedBodyObserved) == 1;

    internal static async Task<SyntheticSignedMutualTlsServer> StartAsync(
        X509Certificate2 serverCertificate,
        X509Certificate2 expectedClientCertificate,
        X509Certificate2 expectedSigningCertificate,
        X509Certificate2 trustedRootCertificate,
        CancellationToken cancellationToken)
    {
        string expectedFingerprint = Convert.ToHexString(SHA256.HashData(expectedClientCertificate.RawData));
        string expectedSigner = Convert.ToHexString(SHA256.HashData(expectedSigningCertificate.RawData));
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(https =>
        {
            https.ServerCertificate = serverCertificate;
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation = (certificate, _, _) =>
                ValidateClientCertificate(certificate, expectedClientCertificate, trustedRootCertificate);
        })));
        WebApplication app = builder.Build();
        SyntheticSignedMutualTlsServer? server = null;
        app.MapPost("/submit", async context =>
        {
            Interlocked.Increment(ref server!.requests);
            X509Certificate2? clientCertificate = await context.Connection.GetClientCertificateAsync(context.RequestAborted);
            if (clientCertificate is not null && string.Equals(
                Convert.ToHexString(SHA256.HashData(clientCertificate.RawData)), server.expectedClientFingerprint, StringComparison.Ordinal))
                Interlocked.Exchange(ref server.expectedClientCertificateObserved, 1);
            string authorization = context.Request.Headers.Authorization.ToString();
            if (authorization.StartsWith("Bearer ", StringComparison.Ordinal))
            {
                string[] parts = authorization[7..].Split('.');
                if (parts.Length == 3)
                {
                    try
                    {
                        using JsonDocument header = JsonDocument.Parse(Decode(parts[0]));
                        using JsonDocument payload = JsonDocument.Parse(Decode(parts[1]));
                        if (header.RootElement.TryGetProperty("x5c", out JsonElement chain) &&
                            chain.ValueKind == JsonValueKind.Array && chain.GetArrayLength() == 2)
                        {
                            Interlocked.Exchange(ref server.x5cChainObserved, 1);
                            byte[] leafDer = Convert.FromBase64String(chain[0].GetString()!);
                            using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(leafDer);
                            using RSA rsa = leaf.GetRSAPublicKey() ?? throw new CryptographicException();
                            bool expectedLeaf = string.Equals(
                                Convert.ToHexString(SHA256.HashData(leaf.RawData)),
                                server.expectedSigningFingerprint,
                                StringComparison.Ordinal);
                            bool signatureValid = rsa.VerifyData(
                                Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]),
                                Decode(parts[2]),
                                HashAlgorithmName.SHA256,
                                RSASignaturePadding.Pkcs1);
                            bool fixedClaims = string.Equals(payload.RootElement.GetProperty("iss").GetString(), "synthetic-gateway", StringComparison.Ordinal) &&
                                string.Equals(payload.RootElement.GetProperty("aud").GetString(), "synthetic-upstream", StringComparison.Ordinal);
                            if (expectedLeaf && signatureValid && fixedClaims)
                                Interlocked.Exchange(ref server.validSignedTokenObserved, 1);
                        }
                        if (payload.RootElement.TryGetProperty("transaction-id", out JsonElement claim) &&
                            string.Equals(claim.GetString(), "published-claim", StringComparison.Ordinal))
                            Interlocked.Exchange(ref server.publishedClaimObserved, 1);
                    }
                    catch (Exception exception) when (exception is JsonException or FormatException or CryptographicException or KeyNotFoundException)
                    {
                    }
                }
            }
            using StreamReader reader = new(context.Request.Body, Encoding.UTF8);
            string body = await reader.ReadToEndAsync(context.RequestAborted);
            if (string.Equals(body, "published-body", StringComparison.Ordinal))
                Interlocked.Exchange(ref server.publishedBodyObserved, 1);
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"accepted\":true}", context.RequestAborted);
        });
        await app.StartAsync(cancellationToken);
        string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        Uri listening = new(address, UriKind.Absolute);
        server = new(app, new Uri($"https://localhost:{listening.Port}/", UriKind.Absolute), expectedFingerprint, expectedSigner);
        return server;
    }

    internal static bool ValidateClientCertificate(
        X509Certificate2 certificate,
        X509Certificate2 expectedCertificate,
        X509Certificate2 trustedRootCertificate)
    {
        if (!CryptographicOperations.FixedTimeEquals(certificate.RawData, expectedCertificate.RawData))
            return false;

        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(trustedRootCertificate);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        return chain.Build(certificate);
    }

    private static byte[] Decode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }

    public async ValueTask DisposeAsync()
    {
        await application.StopAsync();
        await application.DisposeAsync();
    }
}

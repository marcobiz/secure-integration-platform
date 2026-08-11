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
using SecureIntegration.Gateway.Integration.Tests;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Integration.Tests;

public sealed class Fse2OrganizationHostedIntegrationTests
{
    internal const string Subject = "12345678903^^^&2.16.840.1.113883.2.9.4.1.2&ISO";
    internal const string PersonId = "RSSMRA80A01H501U^^^&2.16.840.1.113883.2.9.4.3.2&ISO";
    internal const string Audience = "https://modipa.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1";
    internal const string AuthorizationIssuer = "auth:M6 Synthetic JWT Signing R1";
    internal const string IntegrityIssuer = "integrity:M6 Synthetic JWT Signing R1";
    internal const string Boundary = "broker-gateway-fse2-v1";
    internal const int TokenLifetimeSeconds = 300;
    private const string RequirePostgresGateVariable = "REQUIRE_FSE2_POSTGRES_GATE";
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    [Fact]
    public Task FSE2_IT_PRODUCTION_HOST_in_memory_Published_Organization_dual_JWT_mTLS_exact_bytes() =>
        RunSuccessAsync(runtimeConnection: null, adminConnection: null, requirePostgres: false, includeNegatives: true);

    [Fact]
    public async Task FSE2_IT_PRODUCTION_HOST_PostgreSQL18_Published_Organization_dual_JWT_mTLS_exact_bytes()
    {
        string adminConnection = GetRequiredPostgresConnectionOrSkip("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        string migrationConnection = GetRequiredPostgresConnectionOrSkip("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        await HostedPostgresTestSupport.ApplyMigrationAsync();
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole =
            await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(
                adminConnection,
                migrationConnection,
                TestContext.Current.CancellationToken);
        await RunSuccessAsync(runtimeRole.ConnectionString, adminConnection, requirePostgres: true, includeNegatives: false);
    }

    private static string GetRequiredPostgresConnectionOrSkip(string variableName)
    {
        string? value = Environment.GetEnvironmentVariable(variableName);
        if (!string.IsNullOrWhiteSpace(value)) return value;
        if (string.Equals(
            Environment.GetEnvironmentVariable(RequirePostgresGateVariable),
            "1",
            StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"FSE2_POSTGRES_GATE_REQUIRED_CONFIGURATION_MISSING:{variableName}");
        }

        Assert.Skip($"{variableName} is not configured; the dedicated PostgreSQL gate must provide it.");
        throw new InvalidOperationException("FSE2_POSTGRES_GATE_SKIP_DID_NOT_TERMINATE");
    }

    [Fact]
    public async Task FSE2_SEC_Published_A_to_B_during_second_slot_signing_denies_before_network()
    {
        TaskCompletionSource secondSlotEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseSecondSlot = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        InMemoryProvider inner = Provider(material);
        BlockingPublicMaterialProvider provider = new(inner, async cancellationToken =>
        {
            secondSlotEntered.TrySetResult();
            await releaseSecondSlot.Task.WaitAsync(cancellationToken);
        }, blockOnPublicMaterialCall: 2);
        await using SyntheticFse2OrganizationServer server = await SyntheticFse2OrganizationServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-race",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));

        string connectorId = "fse2-race-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-race-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-race-application");
        string signingSpki = SpkiSha256(material.SigningKeyRevision1);
        string clientSpki = SpkiSha256(material.ClientCertificateRevision1);
        HostedCapabilityAuthority authorityA = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            Definition(connectorId, "1.0.0", signingSpki, clientSpki, "1.0.0"),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: "create");
        await fixture.PublishAsync(authorityA, expectedPublicationRevision: 0);
        HostedCapabilityAuthority authorityB = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "2.0.0",
            environmentId,
            server.Endpoint,
            Definition(connectorId, "2.0.0", signingSpki, clientSpki, "2.0.0"),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: "create");
        HostedIdentity identity = await fixture.EnrollIdentityAsync(tenantId, applicationId, environmentId, "fse2-race-identity");
        await AddGrantAsync(fixture, identity, connectorId);

        Task<HttpResponseMessage> pending = fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/create:invoke",
            InvokeRequest(Payload()));
        await secondSlotEntered.Task.WaitAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, provider.SignDigestCalls);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.GenericTransportRequests);
        try
        {
            await fixture.PublishAsync(authorityB, expectedPublicationRevision: 1);
        }
        finally
        {
            releaseSecondSlot.TrySetResult();
        }

        using HttpResponseMessage response = await pending;
        string responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("BGW-CONNECTOR-CONFIGURATION-STALE", responseBody, StringComparison.Ordinal);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.GenericTransportRequests);
        Assert.Equal(1, provider.SignDigestCalls);
    }

    [Fact]
    public void FSE2_SEC_temporal_profile_rejects_nbf_even_when_equal_to_iat()
    {
        using JsonDocument exact = JsonDocument.Parse(
            $$"""{"iat":1700000000,"exp":1700000{{TokenLifetimeSeconds}},"jti":"fse2-exact-jti"}""");
        Assert.True(SyntheticFse2OrganizationServer.TemporalPolicyIsExact(exact.RootElement));

        using JsonDocument withNotBefore = JsonDocument.Parse(
            $$"""{"iat":1700000000,"nbf":1700000000,"exp":1700000{{TokenLifetimeSeconds}},"jti":"fse2-exact-jti"}""");
        Assert.False(SyntheticFse2OrganizationServer.TemporalPolicyIsExact(withNotBefore.RootElement));
    }

    private static async Task RunSuccessAsync(
        string? runtimeConnection,
        string? adminConnection,
        bool requirePostgres,
        bool includeNegatives)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Provider(material));
        await using SyntheticFse2OrganizationServer server = await SyntheticFse2OrganizationServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-organization",
            runtimeConnection: runtimeConnection,
            adminConnection: adminConnection,
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));
        Assert.Equal(requirePostgres, fixture.UsesPostgreSql);

        string connectorId = "fse2-organization-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-application");
        string signingSpki = SpkiSha256(material.SigningKeyRevision1);
        string clientSpki = SpkiSha256(material.ClientCertificateRevision1);
        HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            Definition(connectorId, "1.0.0", signingSpki, clientSpki, "1.0.0"),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: "create");
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(tenantId, applicationId, environmentId, "fse2-identity");
        await AddGrantAsync(fixture, identity, connectorId);

        GatewayInvokeRequest request = Request(Payload());
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/create:invoke",
            JsonSerializer.SerializeToUtf8Bytes(request, WebJson));
        string responseJson = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.True(response.StatusCode == HttpStatusCode.OK, responseJson);
        GatewayInvokeResponse gateway = JsonSerializer.Deserialize<GatewayInvokeResponse>(responseJson, WebJson)
            ?? throw new InvalidOperationException("FSE2 response was empty.");
        using JsonDocument normalized = JsonDocument.Parse(Convert.FromBase64String(gateway.Result.Data));
        Assert.Equal(202, normalized.RootElement.GetProperty("statusCode").GetInt32());
        Assert.Equal(1, server.Requests);
        Assert.True(server.ExpectedClientCertificateObserved);
        Assert.True(server.ExpectedMethodPathAndContentTypeObserved);
        Assert.True(server.DualTokensObserved);
        Assert.True(server.DistinctTokensAndJtiObserved);
        Assert.True(server.ValidRs256X5cObserved);
        Assert.True(server.SameSigningIdentityObserved);
        Assert.True(server.DistinctIssuersObserved);
        Assert.True(server.FixedSubjectObserved);
        Assert.True(server.OrganizationClaimsObserved);
        Assert.True(server.TemporalPolicyObserved);
        Assert.True(server.ExactPayloadDigestObserved);
        Assert.True(server.ExpectedMultipartPayloadObserved);
        Assert.Equal(2, provider.SignDigestCalls);
        Assert.Equal(1, fixture.GenericTransportRequests);

        if (!includeNegatives) return;

        int callsBeforeCallerOverride = provider.TotalCalls;
        using HttpResponseMessage callerOverride = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/create:invoke",
            InvokeRequest(Payload(extraProperty: "\"subject\":\"caller-controlled\",")));
        Assert.Equal(HttpStatusCode.BadGateway, callerOverride.StatusCode);
        Assert.Equal(callsBeforeCallerOverride, provider.TotalCalls);
        Assert.Equal(1, server.Requests);

        HostedCapabilityAuthority repeatedSlot = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "2.0.0",
            environmentId,
            server.Endpoint,
            Definition(connectorId, "2.0.0", signingSpki, clientSpki, "2.0.0").Replace(
                "\"integritySigningSlot\":\"integrity\"",
                "\"integritySigningSlot\":\"authorization\"",
                StringComparison.Ordinal),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: "create");
        await fixture.PublishAsync(repeatedSlot, expectedPublicationRevision: 1);
        int signingBeforeRepeated = provider.SignDigestCalls;
        using HttpResponseMessage repeated = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/create:invoke",
            InvokeRequest(Payload()));
        string repeatedBody = await repeated.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Conflict, repeated.StatusCode);
        Assert.Contains("BGW-EGRESS-AUTHENTICATION", repeatedBody, StringComparison.Ordinal);
        Assert.Equal(signingBeforeRepeated + 1, provider.SignDigestCalls);
        Assert.Equal(1, server.Requests);

        HostedCapabilityAuthority unknownSlot = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "3.0.0",
            environmentId,
            server.Endpoint,
            Definition(connectorId, "3.0.0", signingSpki, clientSpki, "3.0.0").Replace(
                "\"integritySigningSlot\":\"integrity\"",
                "\"integritySigningSlot\":\"unknown\"",
                StringComparison.Ordinal),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: "create");
        await fixture.PublishAsync(unknownSlot, expectedPublicationRevision: 2);
        int signingBeforeUnknown = provider.SignDigestCalls;
        using HttpResponseMessage unknown = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/create:invoke",
            InvokeRequest(Payload()));
        string unknownBody = await unknown.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Conflict, unknown.StatusCode);
        Assert.Contains("BGW-EGRESS-AUTHENTICATION", unknownBody, StringComparison.Ordinal);
        Assert.Equal(signingBeforeUnknown + 1, provider.SignDigestCalls);
        Assert.Equal(1, server.Requests);
        Assert.Equal(1, fixture.GenericTransportRequests);
    }

    private static InMemoryProvider Provider(SyntheticAuthenticationMaterial material) => new(
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

    private static HostedExecutionModuleConfiguration Module()
    {
        string path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "SecureIntegration.ConnectorPacks.Healthcare.FSE2.dll"));
        string fullName = System.Reflection.AssemblyName.GetAssemblyName(path).FullName
            ?? throw new InvalidOperationException("FSE2 execution module identity is unavailable.");
        return new(
            "healthcare-fse2",
            path,
            fullName,
            "SecureIntegration.ConnectorPacks.Healthcare.FSE2.Fse2OrganizationExecutionModule");
    }

    private static Task AddGrantAsync(HostedTypedSessionFixture fixture, HostedIdentity identity, string connectorId) =>
        fixture.AddOperationGrantAsync(identity, connectorId, "create");

    private static string Payload(string extraProperty = "") => $$"""
        {
          {{extraProperty}}
          "personId":"{{PersonId}}",
          "patientConsent":true,
          "resourceHl7Type":"('11502-2^^2.16.840.1.113883.6.1')",
          "documentBase64":"{{Convert.ToBase64String(DocumentBytes())}}",
          "requestBodyBase64":"{{Convert.ToBase64String("{\"metadata\":\"published-exact\"}"u8.ToArray())}}",
          "documentContentType":"application/pdf"
        }
        """;

    private static GatewayInvokeRequest Request(string payload) => new(
        "1.0",
        new("application/vnd.bgw.fse2+json", "utf8", payload),
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
            ["issuer"] = JsonSerializer.SerializeToElement("caller-issuer"),
            ["role"] = JsonSerializer.SerializeToElement("caller-role")
        });

    private static byte[] InvokeRequest(string payload) => JsonSerializer.SerializeToUtf8Bytes(Request(payload), WebJson);

    internal static byte[] DocumentBytes() => [0x00, 0x0d, 0x0a, 0xc3, 0xa8, 0xff, 0x42, 0x47, 0x57];

    private static string SpkiSha256(X509Certificate2 certificate)
    {
        using RSA rsa = certificate.GetRSAPublicKey() ?? throw new InvalidOperationException("Synthetic RSA public key is unavailable.");
        return Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()));
    }

    private static string Definition(
        string connectorId,
        string version,
        string signingSpki,
        string clientSpki,
        string applicationVersion) => $$$"""
        {
          "schemaVersion":"1.0","connectorId":"{{{connectorId}}}","version":"{{{version}}}","displayName":"FSE2 Organization",
          "bindings":{"endpoints":[{"name":"service"}],"secrets":[{"name":"signing-certificate","kind":"clientCertificate"},{"name":"mtls-certificate","kind":"clientCertificate"}]},
          "operations":[{
            "operationId":"create","endpointBinding":"service","method":"POST","path":"/documents",
            "request":{"contentType":"multipart/form-data; boundary={{{Boundary}}}","maximumBytes":2097152},"response":{"maximumBytes":4096},
            "authentication":{"kind":"mtls","certificateBinding":"mtls-certificate"},"executionStrategy":"healthcare-fse2-organization",
            "extensionConfiguration":{
              "profile":"fse2-organization-v1","environmentClass":"synthetic",
              "organizationIdentifier":"12345678903","organizationAssigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2",
              "organizationDescription":"ASL Roma 1","organizationDomainId":"asl-roma-1",
              "localityName":"ASL Roma 1","localityAssigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2","localityCode":"ASLROMA1",
              "subjectRole":"DAP","applicationId":"broker-gateway","applicationVendor":"Secure Integration","applicationVersion":"{{{applicationVersion}}}",
              "operationId":"create","method":"POST","relativePath":"documents",
              "requestContentType":"multipart/form-data; boundary={{{Boundary}}}","multipartBoundary":"{{{Boundary}}}",
              "authorizationSigningSlot":"authorization","integritySigningSlot":"integrity","maximumDocumentBytes":1048576
            },
            "authorizedCapabilities":{
              "signingSlots":[
                {
                  "slot":"authorization","required":true,
                  "signing":{"profileId":"fse2-authorization","revision":1,"keyBinding":"signing-certificate","publicKeySpkiSha256":"{{{signingSpki}}}","issuer":"{{{AuthorizationIssuer}}}","audience":"{{{Audience}}}","subject":"fixed","fixedSubject":"{{{Subject}}}","allowedClaims":[],"tokenLifetimeSeconds":{{{TokenLifetimeSeconds}}},"clockSkewSeconds":30,"certificateHeader":"chain","temporalClaims":"iat-exp","minimumRsaKeySize":2048},
                  "projection":{"kind":"authorizationBearer"}
                },
                {
                  "slot":"integrity","required":true,
                  "signing":{"profileId":"fse2-integrity","revision":1,"keyBinding":"signing-certificate","publicKeySpkiSha256":"{{{signingSpki}}}","issuer":"{{{IntegrityIssuer}}}","audience":"{{{Audience}}}","subject":"fixed","fixedSubject":"{{{Subject}}}","allowedClaims":["subject_role","purpose_of_use","subject_organization","subject_organization_id","locality","person_id","patient_consent","resource_hl7_type","action_id","attachment_hash","subject_application_id","subject_application_vendor","subject_application_version"],"tokenLifetimeSeconds":{{{TokenLifetimeSeconds}}},"clockSkewSeconds":30,"certificateHeader":"chain","temporalClaims":"iat-exp","minimumRsaKeySize":2048},
                  "projection":{"kind":"signedTokenHeader","headerName":"FSE-JWT-Signature"}
                }
              ],
              "restrictedTransport":{"profileId":"fse2-transport","revision":1,"clientCertificateSpkiSha256":"{{{clientSpki}}}","nearExpirySeconds":30}
            },
            "timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0
          }]
        }
        """;
}

internal sealed class SyntheticFse2OrganizationServer : IAsyncDisposable
{
    private readonly WebApplication application;
    private readonly string expectedClientFingerprint;
    private readonly string expectedSigningFingerprint;
    private readonly byte[] expectedRoot;
    private int requests;
    private int expectedClientCertificateObserved;
    private int expectedMethodPathAndContentTypeObserved;
    private int dualTokensObserved;
    private int distinctTokensAndJtiObserved;
    private int validRs256X5cObserved;
    private int sameSigningIdentityObserved;
    private int distinctIssuersObserved;
    private int fixedSubjectObserved;
    private int organizationClaimsObserved;
    private int temporalPolicyObserved;
    private int exactPayloadDigestObserved;
    private int expectedMultipartPayloadObserved;

    private SyntheticFse2OrganizationServer(
        WebApplication application,
        Uri endpoint,
        string expectedClientFingerprint,
        string expectedSigningFingerprint,
        byte[] expectedRoot)
    {
        this.application = application;
        Endpoint = endpoint;
        this.expectedClientFingerprint = expectedClientFingerprint;
        this.expectedSigningFingerprint = expectedSigningFingerprint;
        this.expectedRoot = expectedRoot;
    }

    internal Uri Endpoint { get; }
    internal int Requests => Volatile.Read(ref requests);
    internal bool ExpectedClientCertificateObserved => Volatile.Read(ref expectedClientCertificateObserved) == 1;
    internal bool ExpectedMethodPathAndContentTypeObserved => Volatile.Read(ref expectedMethodPathAndContentTypeObserved) == 1;
    internal bool DualTokensObserved => Volatile.Read(ref dualTokensObserved) == 1;
    internal bool DistinctTokensAndJtiObserved => Volatile.Read(ref distinctTokensAndJtiObserved) == 1;
    internal bool ValidRs256X5cObserved => Volatile.Read(ref validRs256X5cObserved) == 1;
    internal bool SameSigningIdentityObserved => Volatile.Read(ref sameSigningIdentityObserved) == 1;
    internal bool DistinctIssuersObserved => Volatile.Read(ref distinctIssuersObserved) == 1;
    internal bool FixedSubjectObserved => Volatile.Read(ref fixedSubjectObserved) == 1;
    internal bool OrganizationClaimsObserved => Volatile.Read(ref organizationClaimsObserved) == 1;
    internal bool TemporalPolicyObserved => Volatile.Read(ref temporalPolicyObserved) == 1;
    internal bool ExactPayloadDigestObserved => Volatile.Read(ref exactPayloadDigestObserved) == 1;
    internal bool ExpectedMultipartPayloadObserved => Volatile.Read(ref expectedMultipartPayloadObserved) == 1;

    internal static async Task<SyntheticFse2OrganizationServer> StartAsync(
        X509Certificate2 serverCertificate,
        X509Certificate2 expectedClientCertificate,
        X509Certificate2 expectedSigningCertificate,
        X509Certificate2 trustedRootCertificate,
        CancellationToken cancellationToken)
    {
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(https =>
        {
            https.ServerCertificate = serverCertificate;
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation = (certificate, _, _) =>
                SyntheticSignedMutualTlsServer.ValidateClientCertificate(certificate, expectedClientCertificate, trustedRootCertificate);
        })));
        WebApplication app = builder.Build();
        SyntheticFse2OrganizationServer? server = null;
        app.MapPost("/documents", context => server!.HandleAsync(context));
        await app.StartAsync(cancellationToken);
        string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        Uri listening = new(address, UriKind.Absolute);
        server = new(
            app,
            new Uri($"https://localhost:{listening.Port}/", UriKind.Absolute),
            Convert.ToHexString(SHA256.HashData(expectedClientCertificate.RawData)),
            Convert.ToHexString(SHA256.HashData(expectedSigningCertificate.RawData)),
            trustedRootCertificate.RawData.ToArray());
        return server;
    }

    private async Task HandleAsync(HttpContext context)
    {
        Interlocked.Increment(ref requests);
        X509Certificate2? clientCertificate = await context.Connection.GetClientCertificateAsync(context.RequestAborted);
        if (clientCertificate is not null && string.Equals(
            Convert.ToHexString(SHA256.HashData(clientCertificate.RawData)), expectedClientFingerprint, StringComparison.Ordinal))
            Interlocked.Exchange(ref expectedClientCertificateObserved, 1);
        if (HttpMethods.IsPost(context.Request.Method) && context.Request.Path == "/documents" &&
            string.Equals(context.Request.ContentType, $"multipart/form-data; boundary={Fse2OrganizationHostedIntegrationTests.Boundary}", StringComparison.Ordinal))
            Interlocked.Exchange(ref expectedMethodPathAndContentTypeObserved, 1);

        using MemoryStream bodyBuffer = new();
        await context.Request.Body.CopyToAsync(bodyBuffer, context.RequestAborted);
        byte[] body = bodyBuffer.ToArray();
        if (body.AsSpan().IndexOf(Fse2OrganizationHostedIntegrationTests.DocumentBytes()) >= 0 &&
            body.AsSpan().IndexOf("{\"metadata\":\"published-exact\"}"u8) >= 0)
            Interlocked.Exchange(ref expectedMultipartPayloadObserved, 1);

        string authorization = context.Request.Headers.Authorization.ToString();
        string integrityHeader = context.Request.Headers["FSE-JWT-Signature"].ToString();
        if (authorization.StartsWith("Bearer ", StringComparison.Ordinal) && !string.IsNullOrEmpty(integrityHeader))
        {
            Interlocked.Exchange(ref dualTokensObserved, 1);
            TokenObservation? auth = ValidateToken(authorization[7..], Fse2OrganizationHostedIntegrationTests.AuthorizationIssuer);
            TokenObservation? integrity = ValidateToken(integrityHeader, Fse2OrganizationHostedIntegrationTests.IntegrityIssuer);
            if (auth is not null && integrity is not null)
            {
                Interlocked.Exchange(ref validRs256X5cObserved, 1);
                bool exactAuthTemporal = TemporalPolicyIsExact(auth.Payload);
                bool exactIntegrityTemporal = TemporalPolicyIsExact(integrity.Payload);
                if (exactAuthTemporal && exactIntegrityTemporal)
                {
                    Interlocked.Exchange(ref temporalPolicyObserved, 1);
                    if (!string.Equals(auth.CompactToken, integrity.CompactToken, StringComparison.Ordinal) &&
                        !string.Equals(auth.Payload.GetProperty("jti").GetString(), integrity.Payload.GetProperty("jti").GetString(), StringComparison.Ordinal))
                        Interlocked.Exchange(ref distinctTokensAndJtiObserved, 1);
                }
                if (string.Equals(auth.SigningFingerprint, integrity.SigningFingerprint, StringComparison.Ordinal))
                    Interlocked.Exchange(ref sameSigningIdentityObserved, 1);
                if (!string.Equals(auth.Payload.GetProperty("iss").GetString(), integrity.Payload.GetProperty("iss").GetString(), StringComparison.Ordinal))
                    Interlocked.Exchange(ref distinctIssuersObserved, 1);
                if (string.Equals(auth.Payload.GetProperty("sub").GetString(), Fse2OrganizationHostedIntegrationTests.Subject, StringComparison.Ordinal) &&
                    string.Equals(integrity.Payload.GetProperty("sub").GetString(), Fse2OrganizationHostedIntegrationTests.Subject, StringComparison.Ordinal))
                    Interlocked.Exchange(ref fixedSubjectObserved, 1);
                if (OrganizationClaimsAreExact(integrity.Payload))
                    Interlocked.Exchange(ref organizationClaimsObserved, 1);
                string digest = Convert.ToHexStringLower(SHA256.HashData(body));
                if (string.Equals(integrity.Payload.GetProperty("attachment_hash").GetString(), digest, StringComparison.Ordinal))
                    Interlocked.Exchange(ref exactPayloadDigestObserved, 1);
            }
        }

        context.Response.StatusCode = StatusCodes.Status202Accepted;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(
            "{\"workflowInstanceId\":\"workflow-fse2-1\",\"traceID\":\"trace-fse2-1\",\"spanID\":\"span-fse2-1\"}",
            context.RequestAborted);
    }

    private TokenObservation? ValidateToken(string compactToken, string expectedIssuer)
    {
        string[] parts = compactToken.Split('.');
        if (parts.Length != 3) return null;
        try
        {
            using JsonDocument header = JsonDocument.Parse(Decode(parts[0]));
            using JsonDocument payload = JsonDocument.Parse(Decode(parts[1]));
            if (!string.Equals(header.RootElement.GetProperty("alg").GetString(), "RS256", StringComparison.Ordinal) ||
                !header.RootElement.TryGetProperty("x5c", out JsonElement chain) ||
                chain.ValueKind != JsonValueKind.Array || chain.GetArrayLength() != 2 ||
                !CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(chain[1].GetString()!), expectedRoot))
                return null;
            using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(chain[0].GetString()!));
            using RSA rsa = leaf.GetRSAPublicKey() ?? throw new CryptographicException();
            string fingerprint = Convert.ToHexString(SHA256.HashData(leaf.RawData));
            if (!string.Equals(fingerprint, expectedSigningFingerprint, StringComparison.Ordinal) ||
                !rsa.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), Decode(parts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1) ||
                !string.Equals(payload.RootElement.GetProperty("iss").GetString(), expectedIssuer, StringComparison.Ordinal) ||
                !string.Equals(payload.RootElement.GetProperty("aud").GetString(), Fse2OrganizationHostedIntegrationTests.Audience, StringComparison.Ordinal))
                return null;
            return new(compactToken, fingerprint, payload.RootElement.Clone());
        }
        catch (Exception exception) when (exception is JsonException or FormatException or CryptographicException or KeyNotFoundException)
        {
            return null;
        }
    }

    private static bool OrganizationClaimsAreExact(JsonElement payload) =>
        string.Equals(payload.GetProperty("subject_role").GetString(), "DAP", StringComparison.Ordinal) &&
        string.Equals(payload.GetProperty("purpose_of_use").GetString(), "TREATMENT", StringComparison.Ordinal) &&
        string.Equals(payload.GetProperty("action_id").GetString(), "CREATE", StringComparison.Ordinal) &&
        string.Equals(payload.GetProperty("subject_organization").GetString(), "ASL Roma 1", StringComparison.Ordinal) &&
        string.Equals(payload.GetProperty("subject_organization_id").GetString(), "asl-roma-1", StringComparison.Ordinal) &&
        string.Equals(payload.GetProperty("person_id").GetString(), Fse2OrganizationHostedIntegrationTests.PersonId, StringComparison.Ordinal) &&
        payload.GetProperty("patient_consent").GetBoolean() &&
        string.Equals(payload.GetProperty("subject_application_id").GetString(), "broker-gateway", StringComparison.Ordinal) &&
        string.Equals(payload.GetProperty("subject_application_vendor").GetString(), "Secure Integration", StringComparison.Ordinal) &&
        string.Equals(payload.GetProperty("subject_application_version").GetString(), "1.0.0", StringComparison.Ordinal);

    internal static bool TemporalPolicyIsExact(JsonElement payload)
    {
        return payload.TryGetProperty("iat", out JsonElement issuedAtElement) &&
            issuedAtElement.ValueKind == JsonValueKind.Number &&
            issuedAtElement.TryGetInt64(out long issuedAt) &&
            issuedAt <= long.MaxValue - Fse2OrganizationHostedIntegrationTests.TokenLifetimeSeconds &&
            payload.TryGetProperty("exp", out JsonElement expirationElement) &&
            expirationElement.ValueKind == JsonValueKind.Number &&
            expirationElement.TryGetInt64(out long expiration) &&
            expiration == issuedAt + Fse2OrganizationHostedIntegrationTests.TokenLifetimeSeconds &&
            payload.TryGetProperty("jti", out JsonElement tokenIdentifier) &&
            tokenIdentifier.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(tokenIdentifier.GetString()) &&
            !payload.TryGetProperty("nbf", out _);
    }

    private static byte[] Decode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }

    private sealed record TokenObservation(string CompactToken, string SigningFingerprint, JsonElement Payload);

    public async ValueTask DisposeAsync()
    {
        await application.StopAsync();
        await application.DisposeAsync();
    }
}

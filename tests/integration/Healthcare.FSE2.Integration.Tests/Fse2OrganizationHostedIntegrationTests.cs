using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
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
    internal const string Audience = "https://fse2.synthetic.test/gateway/v1";
    internal const string AuthorizationIssuer = "auth:M6 Synthetic JWT Signing R1";
    internal const string IntegrityIssuer = "integrity:M6 Synthetic JWT Signing R1";
    internal const string Boundary = "broker-gateway-fse2-v1";
    private const string BoundaryA = "broker-gateway-fse2-boundary-a";
    private const string BoundaryB = "broker-gateway-fse2-boundary-b";
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
    public async Task FSE2_SEC_Published_A_to_B_after_policy_preflight_before_first_signing_has_zero_signing_and_network()
    {
        TaskCompletionSource secondSlotEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseSecondSlot = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        InMemoryProvider inner = Provider(material);
        BlockingPublicMaterialProvider provider = new(inner, async cancellationToken =>
        {
            secondSlotEntered.TrySetResult();
            await releaseSecondSlot.Task.WaitAsync(cancellationToken);
        }, blockOnPublicMaterialCall: 4);
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
        Assert.Equal(0, provider.SignDigestCalls);
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
        Assert.Equal(0, provider.SignDigestCalls);
    }

    [Fact]
    public async Task FSE2_SEC_caller_supplied_stale_or_wrong_attachment_hash_is_denied_before_signing_DNS_and_network()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Provider(material));
        await using SyntheticFse2OperationMatrixServer server = await SyntheticFse2OperationMatrixServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-hash-authority-negative",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));

        string connectorId = "fse2-hash-authority-negative-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-hash-authority-negative-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-hash-authority-negative-application");
        HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            Definition(connectorId, "1.0.0", SpkiSha256(material.SigningKeyRevision1),
                SpkiSha256(material.ClientCertificateRevision1), "1.0.0"),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: "create");
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "fse2-hash-authority-negative-identity");
        await AddGrantAsync(fixture, identity, connectorId);

        string exactHash = Convert.ToHexStringLower(SHA256.HashData(DocumentBytes()));
        string staleHash = Convert.ToHexStringLower(SHA256.HashData([.. DocumentBytes(), 0x00]));
        string[] invalidPayloads =
        [
            Payload(extraProperty: $"\"attachment_hash\":\"{exactHash}\","),
            Payload(extraProperty: $"\"attachmentHash\":\"{exactHash}\","),
            Payload(requestBodyJson: $$"""{"metadata":"published-exact","attachment_hash":"{{staleHash}}"}"""),
            Payload(requestBodyJson: "{\"metadata\":\"published-exact\",\"attachment_hash\":\"wrong\"}"),
            Payload(requestBodyJson: $$"""{"metadata":"published-exact","attachmentHash":"{{exactHash}}"}"""),
            Payload(requestBodyJson: "{\"metadata\":\"published-exact\",\"attachment_hash_algorithm\":\"sha512\"}"),
            Payload(requestBodyJson: "{\"metadata\":\"published-exact\",\"attachmentHashInput\":\"multipart\"}")
        ];
        foreach (string invalidPayload in invalidPayloads)
        {
            int signingBefore = provider.SignDigestCalls;
            int dnsBefore = fixture.HostResolutionCount;
            int httpsBefore = server.Requests;
            int transportBefore = fixture.GenericTransportRequests;

            using HttpResponseMessage response = await fixture.SendSignedAsync(
                identity,
                HttpMethod.Post,
                $"/v1/connectors/{connectorId}/operations/create:invoke",
                InvokeRequest(invalidPayload));

            Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
            Assert.Equal(signingBefore, provider.SignDigestCalls);
            Assert.Equal(dnsBefore, fixture.HostResolutionCount);
            Assert.Equal(httpsBefore, server.Requests);
            Assert.Equal(transportBefore, fixture.GenericTransportRequests);
        }
        Assert.Equal(0, provider.SignDigestCalls);
        Assert.Equal(0, fixture.HostResolutionCount);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.GenericTransportRequests);
    }

    [Fact]
    public async Task FSE2_HASH_is_derived_before_multipart_composition_and_boundary_changes_multipart_bytes_but_not_exact_file_digest()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Provider(material));
        await using SyntheticFse2OperationMatrixServer server = await SyntheticFse2OperationMatrixServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-boundary-hash",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));

        Fse2OperationDescriptor create = Fse2OperationCatalog.Get(Fse2Operation.Create);
        string connectorId = "fse2-boundary-hash-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-boundary-hash-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-boundary-hash-application");
        string signingSpki = SpkiSha256(material.SigningKeyRevision1);
        string clientSpki = SpkiSha256(material.ClientCertificateRevision1);
        HostedCapabilityAuthority authorityA = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            DefinitionForOperations(connectorId, "1.0.0", signingSpki, clientSpki, "1.0.0", [create], BoundaryA),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: create.OperationId);
        await fixture.PublishAsync(authorityA, expectedPublicationRevision: 0);
        HostedCapabilityAuthority authorityB = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "2.0.0",
            environmentId,
            server.Endpoint,
            DefinitionForOperations(connectorId, "2.0.0", signingSpki, clientSpki, "1.0.0", [create], BoundaryB),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: create.OperationId);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "fse2-boundary-hash-identity");
        await AddGrantAsync(fixture, identity, connectorId);

        using (HttpResponseMessage responseA = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/create:invoke",
            InvokeRequest(Payload())))
        {
            Assert.Equal(HttpStatusCode.OK, responseA.StatusCode);
        }
        await fixture.PublishAsync(authorityB, expectedPublicationRevision: 1);
        using (HttpResponseMessage responseB = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/create:invoke",
            InvokeRequest(Payload())))
        {
            Assert.Equal(HttpStatusCode.OK, responseB.StatusCode);
        }

        Assert.Equal(2, server.Observations.Count);
        SyntheticFse2OperationMatrixServer.Observation observedA = server.Observations[0];
        SyntheticFse2OperationMatrixServer.Observation observedB = server.Observations[1];
        string exactFileDigest = Convert.ToHexStringLower(SHA256.HashData(DocumentBytes()));
        string envelopeDigestA = Convert.ToHexStringLower(SHA256.HashData(observedA.Body));
        string envelopeDigestB = Convert.ToHexStringLower(SHA256.HashData(observedB.Body));
        Assert.Equal($"multipart/form-data; boundary={BoundaryA}", observedA.ContentType);
        Assert.Equal($"multipart/form-data; boundary={BoundaryB}", observedB.ContentType);
        Assert.False(observedA.Body.SequenceEqual(observedB.Body));
        Assert.NotEqual(envelopeDigestA, envelopeDigestB);
        Assert.Equal(exactFileDigest, observedA.AttachmentHash);
        Assert.Equal(exactFileDigest, observedB.AttachmentHash);
        Assert.NotEqual(envelopeDigestA, observedA.AttachmentHash);
        Assert.NotEqual(envelopeDigestB, observedB.AttachmentHash);
        Assert.Equal(4, provider.SignDigestCalls);
        Assert.Equal(2, fixture.HostResolutionCount);
        Assert.Equal(2, server.Requests);
        Assert.Equal(2, fixture.GenericTransportRequests);
    }

    [Fact]
    public async Task FSE2_SEC_published_boundary_A_to_B_is_stale_with_zero_signing_DNS_and_network()
    {
        TaskCompletionSource secondSlotEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseSecondSlot = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        InMemoryProvider inner = Provider(material);
        BlockingPublicMaterialProvider provider = new(inner, async cancellationToken =>
        {
            secondSlotEntered.TrySetResult();
            await releaseSecondSlot.Task.WaitAsync(cancellationToken);
        }, blockOnPublicMaterialCall: 4);
        await using SyntheticFse2OperationMatrixServer server = await SyntheticFse2OperationMatrixServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-boundary-race",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));

        Fse2OperationDescriptor create = Fse2OperationCatalog.Get(Fse2Operation.Create);
        string connectorId = "fse2-boundary-race-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-boundary-race-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-boundary-race-application");
        string signingSpki = SpkiSha256(material.SigningKeyRevision1);
        string clientSpki = SpkiSha256(material.ClientCertificateRevision1);
        HostedCapabilityAuthority authorityA = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            DefinitionForOperations(connectorId, "1.0.0", signingSpki, clientSpki, "1.0.0", [create], BoundaryA),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: create.OperationId);
        await fixture.PublishAsync(authorityA, expectedPublicationRevision: 0);
        HostedCapabilityAuthority authorityB = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "2.0.0",
            environmentId,
            server.Endpoint,
            DefinitionForOperations(connectorId, "2.0.0", signingSpki, clientSpki, "1.0.0", [create], BoundaryB),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: create.OperationId);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "fse2-boundary-race-identity");
        await AddGrantAsync(fixture, identity, connectorId);

        Task<HttpResponseMessage> pending = fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/create:invoke",
            InvokeRequest(Payload()));
        await secondSlotEntered.Task.WaitAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, provider.SignDigestCalls);
        Assert.Equal(0, fixture.HostResolutionCount);
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
        Assert.Equal(0, provider.SignDigestCalls);
        Assert.Equal(0, fixture.HostResolutionCount);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.GenericTransportRequests);
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

        using JsonDocument missingJti = JsonDocument.Parse(
            $$"""{"iat":1700000000,"exp":1700000{{TokenLifetimeSeconds}}}""");
        Assert.False(SyntheticFse2OrganizationServer.TemporalPolicyIsExact(missingJti.RootElement));
        using JsonDocument emptyJti = JsonDocument.Parse(
            $$"""{"iat":1700000000,"exp":1700000{{TokenLifetimeSeconds}},"jti":""}""");
        Assert.False(SyntheticFse2OrganizationServer.TemporalPolicyIsExact(emptyJti.RootElement));
    }

    [Fact]
    public async Task FSE2_IT_all_11_operations_use_Published_paths_body_modes_and_exact_input_file_hash_contract()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Provider(material));
        await using SyntheticFse2OperationMatrixServer server = await SyntheticFse2OperationMatrixServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-matrix",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));

        string connectorId = "fse2-matrix-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-matrix-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-matrix-application");
        string allOperationsDefinition = DefinitionForOperations(
            connectorId, "1.0.0", SpkiSha256(material.SigningKeyRevision1),
            SpkiSha256(material.ClientCertificateRevision1), "1.0.0", Fse2OperationCatalog.All);
        using (JsonDocument definitionDocument = JsonDocument.Parse(allOperationsDefinition))
        {
            ConnectorValidationResult validation = new ConnectorDefinitionValidator().Validate(definitionDocument.RootElement);
            Assert.True(validation.Valid, string.Join(';', validation.Issues.Select(issue => $"{issue.Code}:{issue.Location}")));
        }
        HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            allOperationsDefinition,
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: "*",
            expectedOperationCount: Fse2OperationCatalog.All.Length);
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "fse2-matrix-identity");
        foreach (Fse2OperationDescriptor operation in Fse2OperationCatalog.All)
            await fixture.AddOperationGrantAsync(identity, connectorId, operation.OperationId);

        Fse2Operation[] ordered =
        [
            Fse2Operation.Create,
            Fse2Operation.GetStatusByWorkflow,
            Fse2Operation.GetStatusByTrace,
            .. Fse2OperationCatalog.All.Select(value => value.Operation).Where(value => value is not
                (Fse2Operation.Create or Fse2Operation.GetStatusByWorkflow or Fse2Operation.GetStatusByTrace))
        ];
        foreach (Fse2Operation operationValue in ordered)
        {
            Fse2OperationDescriptor operation = Fse2OperationCatalog.Get(operationValue);
            using HttpResponseMessage response = await fixture.SendSignedAsync(
                identity,
                HttpMethod.Post,
                $"/v1/connectors/{connectorId}/operations/{operation.OperationId}:invoke",
                InvokeRequest(PayloadFor(operation)));
            string responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.True(response.StatusCode == HttpStatusCode.OK, $"{operation.OperationId}:{responseBody}");
        }

        Assert.Equal(11, server.Requests);
        Assert.Equal(11, server.Observations.Count);
        Assert.Equal(22, provider.SignDigestCalls);
        Assert.Equal(11, fixture.GenericTransportRequests);
        foreach (Fse2OperationDescriptor operation in Fse2OperationCatalog.All)
        {
            SyntheticFse2OperationMatrixServer.Observation observed = Assert.Single(
                server.Observations, value => value.Operation == operation.Operation);
            Assert.Equal(operation.Method.Method, observed.Method);
            Assert.Equal(ExpectedPath(operation), observed.RawTarget);
            Assert.True(observed.ClientCertificateObserved);
            Assert.True(observed.DualDistinctTokensObserved);
            Assert.True(observed.ExactJwtPolicyObserved);
            Assert.True(observed.ExactClaimsObserved);
            Assert.True(observed.ExactInputFileDigestObserved);
            Assert.True(observed.MultipartEnvelopeDigestRejected);
            Assert.Equal(operation.RequiresAttachmentHash, observed.AttachmentHashPresent);
            if (operation.HasDocument)
            {
                Assert.Equal($"multipart/form-data; boundary={Boundary}", observed.ContentType);
                Assert.True(observed.ExactDocumentAndJsonObserved);
                Assert.True(observed.HasHttpContent);
            }
            else if (operation.HasJsonBody)
            {
                Assert.Equal("application/json", observed.ContentType);
                Assert.Equal("{\"metadata\":\"published-exact\"}", Encoding.UTF8.GetString(observed.Body));
                Assert.True(observed.HasHttpContent);
            }
            else
            {
                Assert.Empty(observed.Body);
                Assert.Null(observed.ContentType);
                Assert.False(observed.HasHttpContent);
            }
        }
    }

    [Fact]
    public async Task FSE2_SEC_dynamic_path_missing_extra_encoded_and_noncanonical_values_deny_before_signing_and_network()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Provider(material));
        await using SyntheticFse2OperationMatrixServer server = await SyntheticFse2OperationMatrixServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-path-negative",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));
        Fse2OperationDescriptor replace = Fse2OperationCatalog.Get(Fse2Operation.Replace);
        string connectorId = "fse2-path-negative-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-path-negative-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-path-negative-application");
        HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            DefinitionForOperations(connectorId, "1.0.0", SpkiSha256(material.SigningKeyRevision1),
                SpkiSha256(material.ClientCertificateRevision1), "1.0.0", [replace]),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: replace.OperationId);
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "fse2-path-negative-identity");
        await fixture.AddOperationGrantAsync(identity, connectorId, replace.OperationId);

        string exact = PayloadFor(replace);
        string exactIdentifier = "2.16.840.1.113883.2.9.99.1";
        string withoutIdentifier = exact.Replace(
            $",\"resourceIdentifier\":\"{exactIdentifier}\"", string.Empty, StringComparison.Ordinal);
        string[] invalidPayloads =
        [
            withoutIdentifier,
            exact.Replace(exactIdentifier, "a/b", StringComparison.Ordinal),
            exact.Replace(exactIdentifier, "a\\b", StringComparison.Ordinal),
            exact.Replace(exactIdentifier, "%2f", StringComparison.Ordinal),
            exact.Replace(exactIdentifier, "a?b", StringComparison.Ordinal),
            exact.Replace(exactIdentifier, "a#b", StringComparison.Ordinal),
            exact.Replace(exactIdentifier, ".", StringComparison.Ordinal),
            exact.Replace(exactIdentifier, "..", StringComparison.Ordinal),
            exact.Replace(exactIdentifier, "e\u0301", StringComparison.Ordinal),
            exact.Replace(exactIdentifier, new string('a', 513), StringComparison.Ordinal),
            exact.Replace("{", "{\"pathParameters\":[{\"name\":\"unknown\",\"value\":\"extra\"}],", StringComparison.Ordinal),
            exact.Replace("{", "{\"pathParameterName\":\"document-id\",", StringComparison.Ordinal)
        ];
        foreach (string invalidPayload in invalidPayloads)
        {
            int signingBefore = provider.SignDigestCalls;
            using HttpResponseMessage response = await fixture.SendSignedAsync(
                identity,
                HttpMethod.Post,
                $"/v1/connectors/{connectorId}/operations/{replace.OperationId}:invoke",
                InvokeRequest(invalidPayload));
            Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
            Assert.Equal(signingBefore, provider.SignDigestCalls);
            Assert.Equal(0, server.Requests);
            Assert.Equal(0, fixture.GenericTransportRequests);
        }
    }

    private static async Task RunSuccessAsync(
        string? runtimeConnection,
        string? adminConnection,
        bool requirePostgres,
        bool includeNegatives)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        X509KeyUsageFlags signingKeyUsage = Assert.Single(
            material.SigningKeyRevision1.Extensions.OfType<X509KeyUsageExtension>()).KeyUsages;
        X509KeyUsageFlags mutualTlsKeyUsage = Assert.Single(
            material.ClientCertificateRevision1.Extensions.OfType<X509KeyUsageExtension>()).KeyUsages;
        Assert.True((signingKeyUsage & X509KeyUsageFlags.NonRepudiation) != 0);
        Assert.False((signingKeyUsage & X509KeyUsageFlags.DigitalSignature) != 0);
        Assert.True((mutualTlsKeyUsage & X509KeyUsageFlags.DigitalSignature) != 0);
        Assert.False((mutualTlsKeyUsage & X509KeyUsageFlags.NonRepudiation) != 0);
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
        string publishedDefinition = Definition(connectorId, "1.0.0", signingSpki, clientSpki, "1.0.0");
        using (JsonDocument definitionDocument = JsonDocument.Parse(publishedDefinition))
        {
            JsonElement slots = definitionDocument.RootElement.GetProperty("operations")[0]
                .GetProperty("authorizedCapabilities").GetProperty("signingSlots");
            Assert.Equal(2, slots.GetArrayLength());
            Assert.All(slots.EnumerateArray(), slot => Assert.Equal(
                "contentCommitment",
                slot.GetProperty("signing").GetProperty("certificateKeyUsage").GetString()));
        }
        HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            publishedDefinition,
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
        Assert.True(server.ExactInputFileDigestObserved);
        Assert.True(server.MultipartEnvelopeDigestRejected);
        Assert.True(server.ExpectedMultipartPayloadObserved);
        Assert.Equal(2, provider.SignDigestCalls);
        Assert.Equal(1, fixture.GenericTransportRequests);

        if (!includeNegatives) return;

        using HttpResponseMessage callerOverride = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/create:invoke",
            InvokeRequest(Payload(extraProperty: "\"subject\":\"caller-controlled\",")));
        Assert.Equal(HttpStatusCode.BadGateway, callerOverride.StatusCode);
        Assert.Equal(1, server.Requests);

        Func<string, string>[] mismatches =
        [
            definition => definition.Replace(IntegrityIssuer, "integrity:Wrong Synthetic Signing CN", StringComparison.Ordinal),
            definition => definition.Replace(Audience, "https://fse2.wrong.test/gateway/v1", StringComparison.Ordinal),
            definition => definition.Replace(Subject, "12345678903^^^&2.16.840.1.113883.2.9.4.1.3&ISO", StringComparison.Ordinal),
            definition => definition.Replace("\"attachment_hash\",", string.Empty, StringComparison.Ordinal),
            definition => definition.Replace("\"tokenLifetimeSeconds\":300", "\"tokenLifetimeSeconds\":301", StringComparison.Ordinal),
            definition => definition.Replace("\"temporalClaims\":\"iat-exp\"", "\"temporalClaims\":\"iat-nbf-exp\"", StringComparison.Ordinal),
            definition => definition.Replace("\"certificateHeader\":\"chain\"", "\"certificateHeader\":\"leaf\"", StringComparison.Ordinal),
            definition => definition.Replace("\"certificateKeyUsage\":\"contentCommitment\"", "\"certificateKeyUsage\":\"digitalSignature\"", StringComparison.Ordinal),
            definition => definition.Replace("\"headerName\":\"FSE-JWT-Signature\"", "\"headerName\":\"X-Wrong-Signature\"", StringComparison.Ordinal),
            definition => RemoveIntegritySigningSlot(definition),
            definition => AddExtraSigningSlot(definition),
            definition => definition.Replace("\"slot\":\"integrity\"", "\"slot\":\"unknown\"", StringComparison.Ordinal),
            definition => BindIntegritySigningToMutualTls(definition, clientSpki)
        ];
        long publicationRevision = 1;
        int version = 2;
        foreach (Func<string, string> mismatch in mismatches)
        {
            string connectorVersion = $"{version}.0.0";
            HostedCapabilityAuthority mismatchAuthority = await fixture.PrepareCapabilityConnectorVersionAsync(
                connectorId,
                connectorVersion,
                environmentId,
                server.Endpoint,
                mismatch(Definition(connectorId, connectorVersion, signingSpki, clientSpki, "1.0.0")),
                provider,
                "sign-r1",
                "mtls-r1",
                operationId: "create");
            await fixture.PublishAsync(mismatchAuthority, expectedPublicationRevision: publicationRevision++);
            int signingBeforeMismatch = provider.SignDigestCalls;
            int networkBeforeMismatch = server.Requests;
            int genericTransportBeforeMismatch = fixture.GenericTransportRequests;
            int dnsBeforeMismatch = fixture.HostResolutionCount;
            using HttpResponseMessage mismatchResponse = await fixture.SendSignedAsync(
                identity,
                HttpMethod.Post,
                $"/v1/connectors/{connectorId}/operations/create:invoke",
                InvokeRequest(Payload(extraProperty: "\"subject\":\"strategy-sentinel\",")));
            string mismatchBody = await mismatchResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Conflict, mismatchResponse.StatusCode);
            Assert.Contains("BGW-EGRESS-AUTHENTICATION", mismatchBody, StringComparison.Ordinal);
            Assert.Equal(signingBeforeMismatch, provider.SignDigestCalls);
            Assert.Equal(dnsBeforeMismatch, fixture.HostResolutionCount);
            Assert.Equal(networkBeforeMismatch, server.Requests);
            Assert.Equal(genericTransportBeforeMismatch, fixture.GenericTransportRequests);
            version++;
        }
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
            ["sign-r1"] = [material.RootCertificate],
            ["mtls-r1"] = [material.RootCertificate]
        });

    private static string RemoveIntegritySigningSlot(string definition)
    {
        JsonObject root = JsonNode.Parse(definition)!.AsObject();
        JsonArray slots = root["operations"]![0]!["authorizedCapabilities"]!["signingSlots"]!.AsArray();
        slots.RemoveAt(1);
        return root.ToJsonString();
    }

    private static string AddExtraSigningSlot(string definition)
    {
        JsonObject root = JsonNode.Parse(definition)!.AsObject();
        JsonArray slots = root["operations"]![0]!["authorizedCapabilities"]!["signingSlots"]!.AsArray();
        JsonObject extra = JsonNode.Parse(slots[1]!.ToJsonString())!.AsObject();
        extra["slot"] = "extra";
        extra["signing"]!["profileId"] = "fse2-extra";
        extra["signing"]!["issuer"] = AuthorizationIssuer;
        extra["projection"]!["headerName"] = "X-FSE2-Extra-Signature";
        slots.Add(extra);
        return root.ToJsonString();
    }

    private static string BindIntegritySigningToMutualTls(string definition, string clientSpki)
    {
        JsonObject root = JsonNode.Parse(definition)!.AsObject();
        JsonObject signing = root["operations"]![0]!["authorizedCapabilities"]!["signingSlots"]![1]!["signing"]!.AsObject();
        signing["keyBinding"] = "mtls-certificate";
        signing["publicKeySpkiSha256"] = clientSpki;
        signing["issuer"] = "integrity:M6 Synthetic Client R1";
        return root.ToJsonString();
    }

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

    private static string Payload(
        string extraProperty = "",
        string requestBodyJson = "{\"metadata\":\"published-exact\"}") => $$"""
        {
          {{extraProperty}}
          "personId":"{{PersonId}}",
          "patientConsent":true,
          "resourceHl7Type":"('11502-2^^2.16.840.1.113883.6.1')",
          "documentBase64":"{{Convert.ToBase64String(DocumentBytes())}}",
          "requestBodyBase64":"{{Convert.ToBase64String(Encoding.UTF8.GetBytes(requestBodyJson))}}",
          "documentContentType":"application/pdf"
        }
        """;

    private static string PayloadFor(Fse2OperationDescriptor operation)
    {
        string? resourceIdentifier = operation.Operation switch
        {
            Fse2Operation.GetStatusByWorkflow => "workflow-fse2-1",
            Fse2Operation.GetStatusByTrace => "trace-fse2-1",
            _ when operation.RequiresResourceIdentifier => "2.16.840.1.113883.2.9.99.1",
            _ => null
        };
        Dictionary<string, object?> payload = new(StringComparer.Ordinal)
        {
            ["personId"] = PersonId,
            ["patientConsent"] = true,
            ["resourceHl7Type"] = "('11502-2^^2.16.840.1.113883.6.1')"
        };
        if (operation.HasDocument)
        {
            payload["documentBase64"] = Convert.ToBase64String(DocumentBytes());
            payload["documentContentType"] = operation.Operation == Fse2Operation.ValidateFhir
                ? "application/json"
                : "application/pdf";
        }
        if (operation.HasJsonBody)
            payload["requestBodyBase64"] = Convert.ToBase64String("{\"metadata\":\"published-exact\"}"u8);
        if (resourceIdentifier is not null) payload["resourceIdentifier"] = resourceIdentifier;
        return JsonSerializer.Serialize(payload, WebJson);
    }

    private static string ExpectedPath(Fse2OperationDescriptor operation) => operation.PathTemplate switch
    {
        string value when operation.PathParameterName is null => value,
        string value => value.Replace(
            "{" + operation.PathParameterName + "}",
            operation.Operation switch
            {
                Fse2Operation.GetStatusByWorkflow => "workflow-fse2-1",
                Fse2Operation.GetStatusByTrace => "trace-fse2-1",
                _ => "2.16.840.1.113883.2.9.99.1"
            },
            StringComparison.Ordinal)
    };

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
        string applicationVersion) => DefinitionForOperations(
            connectorId, version, signingSpki, clientSpki, applicationVersion,
            [Fse2OperationCatalog.Get(Fse2Operation.Create)]);

    private static string DefinitionForOperations(
        string connectorId,
        string version,
        string signingSpki,
        string clientSpki,
        string applicationVersion,
        IReadOnlyCollection<Fse2OperationDescriptor> operations,
        string multipartBoundary = Boundary) => $$$"""
        {
          "schemaVersion":"1.0","connectorId":"{{{connectorId}}}","version":"{{{version}}}","displayName":"FSE2 Organization",
          "bindings":{"endpoints":[{"name":"service"}],"secrets":[{"name":"signing-certificate","kind":"clientCertificate"},{"name":"mtls-certificate","kind":"clientCertificate"}]},
          "operations":[{{{string.Join(",", operations.Select(operation => OperationDefinition(operation, signingSpki, clientSpki, applicationVersion, multipartBoundary)))}}}]
        }
        """;

    private static string OperationDefinition(
        Fse2OperationDescriptor operation,
        string signingSpki,
        string clientSpki,
        string applicationVersion,
        string multipartBoundary)
    {
        string contentType = operation.HasDocument
            ? $"multipart/form-data; boundary={multipartBoundary}"
            : "application/json";
        string bodyMode = operation.HasDocument || operation.HasJsonBody ? "required" : "none";
        return $$$"""
          {
            "operationId":"{{{operation.OperationId}}}","endpointBinding":"service","method":"{{{operation.Method.Method}}}","pathTemplate":"{{{operation.PathTemplate}}}",
            "request":{"contentType":"{{{contentType}}}","maximumBytes":2097152},"response":{"maximumBytes":4096},
            "authentication":{"kind":"mtls","certificateBinding":"mtls-certificate"},"executionStrategy":"healthcare-fse2-organization",
            "extensionConfiguration":{
              "profile":"fse2-organization-v1","environmentClass":"synthetic",
              "organizationIdentifier":"12345678903","organizationAssigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2",
              "organizationDescription":"ASL Roma 1","organizationDomainId":"asl-roma-1",
              "localityName":"ASL Roma 1","localityAssigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2","localityCode":"ASLROMA1",
              "subjectRole":"DAP","applicationId":"broker-gateway","applicationVendor":"Secure Integration","applicationVersion":"{{{applicationVersion}}}",
              "maximumDocumentBytes":1048576
            },
            "authorizedCapabilities":{
              "signingSlots":[
                {
                  "slot":"authorization","required":true,
                  "signing":{"profileId":"fse2-authorization","revision":1,"keyBinding":"signing-certificate","publicKeySpkiSha256":"{{{signingSpki}}}","issuer":"{{{AuthorizationIssuer}}}","audience":"{{{Audience}}}","subject":"fixed","fixedSubject":"{{{Subject}}}","allowedClaims":[],"tokenLifetimeSeconds":{{{TokenLifetimeSeconds}}},"clockSkewSeconds":30,"certificateKeyUsage":"contentCommitment","certificateHeader":"chain","temporalClaims":"iat-exp","minimumRsaKeySize":2048},
                  "projection":{"kind":"authorizationBearer"}
                },
                {
                  "slot":"integrity","required":true,
                  "signing":{"profileId":"fse2-integrity","revision":1,"keyBinding":"signing-certificate","publicKeySpkiSha256":"{{{signingSpki}}}","issuer":"{{{IntegrityIssuer}}}","audience":"{{{Audience}}}","subject":"fixed","fixedSubject":"{{{Subject}}}","allowedClaims":["subject_role","purpose_of_use","subject_organization","subject_organization_id","locality","person_id","patient_consent","resource_hl7_type","action_id","attachment_hash","subject_application_id","subject_application_vendor","subject_application_version"],"tokenLifetimeSeconds":{{{TokenLifetimeSeconds}}},"clockSkewSeconds":30,"certificateKeyUsage":"contentCommitment","certificateHeader":"chain","temporalClaims":"iat-exp","minimumRsaKeySize":2048},
                  "projection":{"kind":"signedTokenHeader","headerName":"FSE-JWT-Signature"}
                }
              ],
              "restrictedTransport":{"profileId":"fse2-transport","revision":1,"clientCertificateSpkiSha256":"{{{clientSpki}}}","nearExpirySeconds":30,"bodyMode":"{{{bodyMode}}}"}
            },
            "timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0
          }
        """;
    }
}

internal sealed class SyntheticFse2OperationMatrixServer : IAsyncDisposable
{
    private readonly WebApplication application;
    private readonly string expectedClientFingerprint;
    private readonly string expectedSigningFingerprint;
    private readonly byte[] expectedRoot;
    private readonly List<Observation> observations = [];
    private readonly object observationGate = new();
    private int requests;

    private SyntheticFse2OperationMatrixServer(
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
    internal IReadOnlyList<Observation> Observations
    {
        get { lock (observationGate) return observations.ToArray(); }
    }

    internal static async Task<SyntheticFse2OperationMatrixServer> StartAsync(
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
                SyntheticSignedMutualTlsServer.ValidateClientCertificate(
                    certificate, expectedClientCertificate, trustedRootCertificate);
        })));
        WebApplication app = builder.Build();
        SyntheticFse2OperationMatrixServer? server = null;
        app.Run(context => server!.HandleAsync(context));
        await app.StartAsync(cancellationToken);
        string address = app.Services.GetRequiredService<IServer>().Features
            .Get<IServerAddressesFeature>()!.Addresses.Single();
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
        string rawTarget = context.Request.Path + context.Request.QueryString;
        Fse2OperationDescriptor operation = Fse2OperationCatalog.All.Single(value =>
            string.Equals(value.Method.Method, context.Request.Method, StringComparison.Ordinal) &&
            PathMatches(value, context.Request.Path));
        X509Certificate2? clientCertificate = await context.Connection.GetClientCertificateAsync(context.RequestAborted);
        bool clientObserved = clientCertificate is not null && string.Equals(
            Convert.ToHexString(SHA256.HashData(clientCertificate.RawData)),
            expectedClientFingerprint,
            StringComparison.Ordinal);
        using MemoryStream bodyBuffer = new();
        await context.Request.Body.CopyToAsync(bodyBuffer, context.RequestAborted);
        byte[] body = bodyBuffer.ToArray();
        string authorization = context.Request.Headers.Authorization.ToString();
        string integrity = context.Request.Headers[Fse2PublishedOrganizationProfile.IntegrityHeaderName].ToString();
        bool dualDistinct = authorization.StartsWith("Bearer ", StringComparison.Ordinal) &&
            !string.IsNullOrWhiteSpace(integrity) &&
            !string.Equals(authorization[7..], integrity, StringComparison.Ordinal);
        MatrixToken? authorizationToken = dualDistinct ? ValidateToken(
            authorization[7..], Fse2OrganizationHostedIntegrationTests.AuthorizationIssuer) : null;
        MatrixToken? integrityToken = dualDistinct ? ValidateToken(
            integrity, Fse2OrganizationHostedIntegrationTests.IntegrityIssuer) : null;
        bool exactJwtPolicy = authorizationToken is not null && integrityToken is not null &&
            SyntheticFse2OrganizationServer.TemporalPolicyIsExact(authorizationToken.Payload) &&
            SyntheticFse2OrganizationServer.TemporalPolicyIsExact(integrityToken.Payload) &&
            !string.Equals(
                authorizationToken.Payload.GetProperty("jti").GetString(),
                integrityToken.Payload.GetProperty("jti").GetString(),
                StringComparison.Ordinal);
        bool exactClaims = exactJwtPolicy && AuthorizationClaimsAreExact(authorizationToken!.Payload) &&
            IntegrityClaimsAreExact(integrityToken!.Payload, operation);
        JsonElement attachmentHash = default;
        bool attachmentHashPresent = exactClaims &&
            integrityToken!.Payload.TryGetProperty("attachment_hash", out attachmentHash);
        string exactInputFileDigest = Convert.ToHexStringLower(
            SHA256.HashData(Fse2OrganizationHostedIntegrationTests.DocumentBytes()));
        string multipartEnvelopeDigest = Convert.ToHexStringLower(SHA256.HashData(body));
        bool exactInputFileDigestObserved = exactClaims && (!operation.RequiresAttachmentHash || string.Equals(
            attachmentHash.GetString(), exactInputFileDigest, StringComparison.Ordinal));
        bool multipartEnvelopeDigestRejected = exactClaims && (!operation.RequiresAttachmentHash || !string.Equals(
            attachmentHash.GetString(), multipartEnvelopeDigest, StringComparison.Ordinal));
        bool exactDocumentAndJson = body.AsSpan().IndexOf(Fse2OrganizationHostedIntegrationTests.DocumentBytes()) >= 0 &&
            body.AsSpan().IndexOf("{\"metadata\":\"published-exact\"}"u8) >= 0;
        bool hasHttpContent = context.Request.ContentLength.HasValue ||
            context.Request.Headers.ContainsKey("Content-Type") ||
            context.Request.Headers.ContainsKey("Transfer-Encoding");
        lock (observationGate)
        {
            observations.Add(new(
                operation.Operation,
                context.Request.Method,
                rawTarget,
                context.Request.ContentType,
                body,
                hasHttpContent,
                clientObserved,
                dualDistinct,
                exactJwtPolicy,
                exactClaims,
                attachmentHashPresent,
                attachmentHashPresent ? attachmentHash.GetString() : null,
                exactInputFileDigestObserved,
                multipartEnvelopeDigestRejected,
                exactDocumentAndJson));
        }

        context.Response.StatusCode = operation.SuccessStatusCodes.Min();
        context.Response.ContentType = "application/json";
        string response = operation.Operation == Fse2Operation.Create
            ? "{\"workflowInstanceId\":\"workflow-fse2-1\",\"traceID\":\"trace-fse2-1\",\"spanID\":\"span-fse2-1\"}"
            : "{}";
        await context.Response.WriteAsync(response, context.RequestAborted);
    }

    private MatrixToken? ValidateToken(string compactToken, string expectedIssuer)
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
            using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(
                Convert.FromBase64String(chain[0].GetString()!));
            using RSA rsa = leaf.GetRSAPublicKey() ?? throw new CryptographicException();
            string fingerprint = Convert.ToHexString(SHA256.HashData(leaf.RawData));
            if (!string.Equals(fingerprint, expectedSigningFingerprint, StringComparison.Ordinal) ||
                string.Equals(fingerprint, expectedClientFingerprint, StringComparison.Ordinal) ||
                !rsa.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), Decode(parts[2]),
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1) ||
                !string.Equals(payload.RootElement.GetProperty("iss").GetString(), expectedIssuer, StringComparison.Ordinal) ||
                !string.Equals(payload.RootElement.GetProperty("aud").GetString(), Fse2OrganizationHostedIntegrationTests.Audience, StringComparison.Ordinal) ||
                !string.Equals(payload.RootElement.GetProperty("sub").GetString(), Fse2OrganizationHostedIntegrationTests.Subject, StringComparison.Ordinal))
                return null;
            return new(payload.RootElement.Clone());
        }
        catch (Exception exception) when (exception is JsonException or FormatException or CryptographicException or KeyNotFoundException)
        {
            return null;
        }
    }

    private static bool AuthorizationClaimsAreExact(JsonElement payload) =>
        payload.EnumerateObject().Select(value => value.Name).ToHashSet(StringComparer.Ordinal)
            .SetEquals(["iss", "aud", "sub", "iat", "exp", "jti"]);

    private static bool IntegrityClaimsAreExact(JsonElement payload, Fse2OperationDescriptor operation)
    {
        HashSet<string> expected =
        [
            "iss", "aud", "sub", "iat", "exp", "jti", "subject_role", "purpose_of_use",
            "subject_organization", "subject_organization_id", "locality", "person_id", "patient_consent",
            "resource_hl7_type", "action_id", "subject_application_id", "subject_application_vendor",
            "subject_application_version"
        ];
        if (operation.RequiresAttachmentHash) expected.Add("attachment_hash");
        Fse2PurposeOfUse purpose = operation.PurposeOfUse ?? Fse2PurposeOfUse.Treatment;
        Fse2Action action = operation.Action ?? Fse2Action.Create;
        return payload.EnumerateObject().Select(value => value.Name).ToHashSet(StringComparer.Ordinal).SetEquals(expected) &&
            string.Equals(payload.GetProperty("subject_role").GetString(), "DAP", StringComparison.Ordinal) &&
            string.Equals(payload.GetProperty("purpose_of_use").GetString(), Fse2OperationCatalog.ClaimValue(purpose), StringComparison.Ordinal) &&
            string.Equals(payload.GetProperty("action_id").GetString(), Fse2OperationCatalog.ClaimValue(action), StringComparison.Ordinal) &&
            string.Equals(payload.GetProperty("subject_organization").GetString(), "ASL Roma 1", StringComparison.Ordinal) &&
            string.Equals(payload.GetProperty("subject_organization_id").GetString(), "asl-roma-1", StringComparison.Ordinal) &&
            string.Equals(payload.GetProperty("person_id").GetString(), Fse2OrganizationHostedIntegrationTests.PersonId, StringComparison.Ordinal) &&
            payload.GetProperty("patient_consent").GetBoolean() &&
            string.Equals(payload.GetProperty("subject_application_id").GetString(), "broker-gateway", StringComparison.Ordinal) &&
            string.Equals(payload.GetProperty("subject_application_vendor").GetString(), "Secure Integration", StringComparison.Ordinal) &&
            string.Equals(payload.GetProperty("subject_application_version").GetString(), "1.0.0", StringComparison.Ordinal);
    }

    private static byte[] Decode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }

    private static bool PathMatches(Fse2OperationDescriptor operation, PathString path)
    {
        string[] expected = operation.PathTemplate.Split('/', StringSplitOptions.RemoveEmptyEntries);
        string[] candidate = (path.Value ?? string.Empty).Split('/', StringSplitOptions.RemoveEmptyEntries);
        return expected.Length == candidate.Length && expected.Zip(candidate).All(pair =>
            pair.First.Length >= 3 && pair.First[0] == '{' && pair.First[^1] == '}'
                ? pair.Second.Length > 0
                : string.Equals(pair.First, pair.Second, StringComparison.Ordinal));
    }

    internal sealed record Observation(
        Fse2Operation Operation,
        string Method,
        string RawTarget,
        string? ContentType,
        byte[] Body,
        bool HasHttpContent,
        bool ClientCertificateObserved,
        bool DualDistinctTokensObserved,
        bool ExactJwtPolicyObserved,
        bool ExactClaimsObserved,
        bool AttachmentHashPresent,
        string? AttachmentHash,
        bool ExactInputFileDigestObserved,
        bool MultipartEnvelopeDigestRejected,
        bool ExactDocumentAndJsonObserved);

    private sealed record MatrixToken(JsonElement Payload);

    public async ValueTask DisposeAsync()
    {
        await application.StopAsync();
        await application.DisposeAsync();
    }
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
    private int exactInputFileDigestObserved;
    private int multipartEnvelopeDigestRejected;
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
    internal bool ExactInputFileDigestObserved => Volatile.Read(ref exactInputFileDigestObserved) == 1;
    internal bool MultipartEnvelopeDigestRejected => Volatile.Read(ref multipartEnvelopeDigestRejected) == 1;
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
                string exactInputFileDigest = Convert.ToHexStringLower(
                    SHA256.HashData(Fse2OrganizationHostedIntegrationTests.DocumentBytes()));
                string multipartEnvelopeDigest = Convert.ToHexStringLower(SHA256.HashData(body));
                string? attachmentHash = integrity.Payload.GetProperty("attachment_hash").GetString();
                if (string.Equals(attachmentHash, exactInputFileDigest, StringComparison.Ordinal))
                    Interlocked.Exchange(ref exactInputFileDigestObserved, 1);
                if (!string.Equals(attachmentHash, multipartEnvelopeDigest, StringComparison.Ordinal))
                    Interlocked.Exchange(ref multipartEnvelopeDigestRejected, 1);
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

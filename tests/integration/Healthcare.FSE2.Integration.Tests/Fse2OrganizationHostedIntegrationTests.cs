using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
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
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Gateway.Integration.Tests;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;
using SecureIntegration.Tools.Fse2.OfficialTestProvisioner;
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
    internal const string OfficialTestBoundary = "broker-gateway-fse2-officialtest-v1";
    private const string BoundaryA = "broker-gateway-fse2-boundary-a";
    private const string BoundaryB = "broker-gateway-fse2-boundary-b";
    private const string HistoricalOfficialTestConnectorVersion = "1.0.0";
    private const string HistoricalValidateCdaRequestBody =
        "{\"healthDataFormat\":\"CDA\",\"activity\":\"VERIFICA\",\"mode\":\"ATTACHMENT\"}";
    private const string ParityValidateCdaRequestBody =
        "{\"healthDataFormat\":\"CDA\",\"activity\":\"VERIFICA\"}";
    internal const int TokenLifetimeSeconds = 300;
    private const string RequirePostgresGateVariable = "REQUIRE_FSE2_POSTGRES_GATE";
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);
    private static readonly Uri OfficialTestEffectiveUri = new(
        "https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1/documents/validation",
        UriKind.Absolute);

    [Fact]
    public Task FSE2_IT_PRODUCTION_HOST_in_memory_Published_Organization_dual_JWT_mTLS_exact_bytes() =>
        RunSuccessAsync(runtimeConnection: null, adminConnection: null, requirePostgres: false, includeNegatives: true);

    [Fact]
    public Task FSE2_TRANSPORT_sets_server_owned_application_json_accept() =>
        RunSuccessAsync(runtimeConnection: null, adminConnection: null, requirePostgres: false, includeNegatives: false);

    [Fact]
    public async Task FSE2_OFFICIALTEST_real_composition_dual_JWT_projects_exact_source_owned_application_claims()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Provider(material));
        await using SyntheticFse2OperationMatrixServer server = await SyntheticFse2OperationMatrixServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken,
            Fse2OfficialTestCanonicalDefinition.OfficialTestAudience,
            Fse2OfficialTestCanonicalDefinition.ApplicationId,
            Fse2OfficialTestCanonicalDefinition.ApplicationVendor,
            Fse2OfficialTestCanonicalDefinition.ApplicationVersion,
            expectLeafOnlyX5c: true);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-officialtest-application-identity",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));

        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Fse2OfficialTestProviderReference a1 = new("synthetic-capability", "officialtest-a1", "1", 1, 1);
        Fse2OfficialTestProviderReference s1 = new("synthetic-capability", "officialtest-s1", "1", 1, 1);
        string planJson = $$"""
            {
              "schemaVersion":"1.0",
              "tenantId":"22222222-2222-2222-2222-222222222222",
              "installationId":"33333333-3333-3333-3333-333333333333",
              "environmentId":"{{environmentId:D}}",
              "officialTestEndpoint":"{{Fse2OfficialTestCanonicalDefinition.OfficialTestEndpoint}}",
              "organization":{"identifier":"12345678903","assigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2","description":"ASL Roma 1","domainId":"asl-roma-1"},
              "locality":{"name":"ASL Roma 1","assigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2","code":"ASLROMA1"},
              "a1":{"providerId":"{{a1.ProviderId}}","resourceId":"{{a1.ResourceId}}","version":"{{a1.Version}}","catalogRevision":1,"publicMetadataRevision":1},
              "s1":{"providerId":"{{s1.ProviderId}}","resourceId":"{{s1.ResourceId}}","version":"{{s1.Version}}","catalogRevision":1,"publicMetadataRevision":1},
              "expectedBindingRevision":null
            }
            """;
        Fse2OfficialTestOperationalPlan plan = Fse2OfficialTestOperationalization.ParsePlan(Encoding.UTF8.GetBytes(planJson));
        Fse2OfficialTestCompiledConfiguration compiled = Fse2OfficialTestOperationalization.Compile(
            plan,
            new(a1, SpkiSha256(material.ClientCertificateRevision1), material.ClientCertificateRevision1.GetNameInfo(X509NameType.SimpleName, false), new string('C', 64)),
            new(s1, SpkiSha256(material.SigningKeyRevision1), material.SigningKeyRevision1.GetNameInfo(X509NameType.SimpleName, false), new string('D', 64)));

        Guid tenantId = await fixture.CreateTenantAsync("fse2-officialtest-identity-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-officialtest-identity-application");
        HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
            Fse2OfficialTestCanonicalDefinition.ConnectorId,
            Fse2OfficialTestCanonicalDefinition.ConnectorVersion,
            environmentId,
            server.Endpoint,
            compiled.CanonicalDefinition,
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: Fse2OfficialTestCanonicalDefinition.OperationId,
            endpointBinding: Fse2OfficialTestCanonicalDefinition.EndpointBinding,
            signingCertificateBinding: Fse2OfficialTestCanonicalDefinition.SigningBinding,
            clientCertificateBinding: Fse2OfficialTestCanonicalDefinition.MutualTlsBinding);
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "fse2-officialtest-identity");
        await fixture.AddOperationGrantAsync(identity, authority.ConnectorId, Fse2OfficialTestCanonicalDefinition.OperationId);

        Fse2OperationDescriptor operation = Fse2OperationCatalog.Get(Fse2Operation.ValidateCda);
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{authority.ConnectorId}/operations/{operation.OperationId}:invoke",
            InvokeRequest(PayloadFor(operation,
                "{\"healthDataFormat\":\"CDA\",\"activity\":\"VERIFICA\"}",
                DocumentBytes())));
        string responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, responseBody);
        SyntheticFse2OperationMatrixServer.Observation observation = Assert.Single(server.Observations);
        Assert.True(observation.DualDistinctTokensObserved);
        Assert.True(observation.ExactJwtPolicyObserved);
        Assert.True(observation.ExactClaimsObserved);
        Assert.Equal("multipart/form-data; boundary=broker-gateway-fse2-officialtest-v1", observation.ContentType);
        Assert.False(observation.AttachmentHashPresent);
    }

    [Fact]
    public Task FSE2_OFFICIALTEST_HOSTED_authoritative_runtime_recheck_preserves_effective_URI_and_dispatches_once_to_local_mock() =>
        RunOfficialTestRuntimeContractAsync();

    [Fact]
    public Task FSE2_OFFICIALTEST_authorization_and_integrity_x5c_contain_exactly_the_S1_leaf() =>
        RunOfficialTestRuntimeContractAsync();

    [Fact]
    public Task FSE2_OFFICIALTEST_validate_cda_VERIFICA_omits_mode_and_attachment_hash() =>
        RunOfficialTestRuntimeContractAsync();

    [Fact]
    public async Task FSE2_OFFICIALTEST_versions_1_0_0_and_1_0_1_preserve_distinct_published_contracts()
    {
        VersionPolicyResult historical = await RunVersionPolicyContractAsync(
            Fse2OfficialTestCanonicalDefinition.ConnectorId,
            HistoricalOfficialTestConnectorVersion,
            "chain",
            HistoricalValidateCdaRequestBody,
            "distinct-historical");
        VersionPolicyResult parity = await RunVersionPolicyContractAsync(
            Fse2OfficialTestCanonicalDefinition.ConnectorId,
            Fse2OfficialTestCanonicalDefinition.ConnectorVersion,
            "leaf",
            ParityValidateCdaRequestBody,
            "distinct-parity");

        AssertHistoricalWireContract(historical);
        AssertParityWireContract(parity);
        Assert.NotEqual(
            historical.Observation.AuthorizationX5cCount,
            parity.Observation.AuthorizationX5cCount);
        Assert.NotEqual(
            Encoding.UTF8.GetString(historical.Observation.RequestBody),
            Encoding.UTF8.GetString(parity.Observation.RequestBody));
    }

    [Fact]
    public async Task FSE2_OFFICIALTEST_1_0_0_preserves_chain_and_historical_mode_body() =>
        AssertHistoricalWireContract(await RunVersionPolicyContractAsync(
            Fse2OfficialTestCanonicalDefinition.ConnectorId,
            HistoricalOfficialTestConnectorVersion,
            "chain",
            HistoricalValidateCdaRequestBody,
            "historical"));

    [Fact]
    public async Task FSE2_OFFICIALTEST_1_0_1_uses_leaf_only_and_two_field_VERIFICA_body() =>
        AssertParityWireContract(await RunVersionPolicyContractAsync(
            Fse2OfficialTestCanonicalDefinition.ConnectorId,
            Fse2OfficialTestCanonicalDefinition.ConnectorVersion,
            "leaf",
            ParityValidateCdaRequestBody,
            "parity"));

    [Fact]
    public async Task FSE2_OFFICIALTEST_other_connector_id_does_not_inherit_1_0_1_policy()
    {
        VersionPolicyResult result = await RunVersionPolicyContractAsync(
            Fse2OfficialTestCanonicalDefinition.ConnectorId + "-other",
            Fse2OfficialTestCanonicalDefinition.ConnectorVersion,
            "chain",
            HistoricalValidateCdaRequestBody,
            "other-connector");

        AssertHistoricalWireContract(result);
    }

    [Fact]
    public async Task FSE2_OFFICIALTEST_unknown_version_does_not_silently_inherit_1_0_1_policy()
    {
        VersionPolicyResult result = await RunVersionPolicyContractAsync(
            Fse2OfficialTestCanonicalDefinition.ConnectorId,
            "1.0.2",
            "leaf",
            ParityValidateCdaRequestBody,
            "unknown-version");

        Assert.False((int)result.StatusCode is >= 200 and <= 299);
        Assert.Empty(result.TransportObservations);
        Assert.Equal(0, result.TransportRequests);
        Assert.Equal(0, result.HostResolutionCount);
        Assert.Equal(0, result.GenericTransportRequests);
        Assert.Equal(0, result.SignDigestCalls);
    }

    [Fact]
    public async Task FSE2_OFFICIALTEST_upgrade_and_rollback_preserve_effective_wire_contract()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Provider(material));
        Uri publishedBase = new(Fse2OfficialTestCanonicalDefinition.OfficialTestEndpoint, UriKind.Absolute);
        VersionPolicyInMemoryTransport localMock = new(
            OfficialTestEffectiveUri,
            Convert.ToHexString(SHA256.HashData(material.ClientCertificateRevision1.RawData)),
            material.SigningKeyRevision1.RawData,
            material.RootCertificate.RawData);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-officialtest-upgrade-rollback",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate),
            restrictedTransport: localMock,
            privateDestinationHosts: new HashSet<string>([publishedBase.DnsSafeHost], StringComparer.OrdinalIgnoreCase));

        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-officialtest-upgrade-rollback-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-officialtest-upgrade-rollback-application");
        HostedCapabilityAuthority historical = await PrepareVersionPolicyAuthorityAsync(
            fixture, provider, material, environmentId,
            Fse2OfficialTestCanonicalDefinition.ConnectorId,
            HistoricalOfficialTestConnectorVersion,
            "chain");
        _ = await fixture.PublishAsync(historical, expectedPublicationRevision: 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "fse2-officialtest-upgrade-rollback-identity");
        await fixture.AddOperationGrantAsync(identity, historical.ConnectorId, Fse2OfficialTestCanonicalDefinition.OperationId);

        await InvokeVersionPolicyAsync(fixture, identity, historical.ConnectorId, HistoricalValidateCdaRequestBody);

        HostedCapabilityAuthority parity = await PrepareVersionPolicyAuthorityAsync(
            fixture, provider, material, environmentId,
            Fse2OfficialTestCanonicalDefinition.ConnectorId,
            Fse2OfficialTestCanonicalDefinition.ConnectorVersion,
            "leaf");
        ConnectorVersionResource publishedParity = await fixture.PublishAsync(parity, expectedPublicationRevision: 1);
        await InvokeVersionPolicyAsync(fixture, identity, parity.ConnectorId, ParityValidateCdaRequestBody);

        _ = await fixture.RollbackAsync(
            parity,
            HistoricalOfficialTestConnectorVersion,
            publishedParity.RowVersion);
        await InvokeVersionPolicyAsync(fixture, identity, historical.ConnectorId, HistoricalValidateCdaRequestBody);

        VersionPolicyWireObservation[] observations = localMock.Observations;
        Assert.Equal(3, observations.Length);
        AssertHistoricalWireObservation(observations[0]);
        AssertParityWireObservation(observations[1]);
        AssertHistoricalWireObservation(observations[2]);
        Assert.Equal(3, localMock.Requests);
        Assert.Equal(3, fixture.HostResolutionCount);
        Assert.Equal(3, fixture.GenericTransportRequests);
        Assert.Equal(6, provider.SignDigestCalls);
    }

    private static async Task RunOfficialTestRuntimeContractAsync()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Provider(material));
        Uri publishedBase = new(Fse2OfficialTestCanonicalDefinition.OfficialTestEndpoint, UriKind.Absolute);
        Uri expectedEffective = new(
            "https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1/documents/validation",
            UriKind.Absolute);
        OfficialTestInMemoryTransport localMock = new(
            expectedEffective,
            Convert.ToHexString(SHA256.HashData(material.ClientCertificateRevision1.RawData)),
            material.SigningKeyRevision1.RawData,
            material.RootCertificate.RawData);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-officialtest-runtime-uri",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate),
            restrictedTransport: localMock,
            privateDestinationHosts: new HashSet<string>([publishedBase.DnsSafeHost], StringComparer.OrdinalIgnoreCase));

        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Fse2OfficialTestProviderReference a1 = new("synthetic-capability", "officialtest-a1", "1", 1, 1);
        Fse2OfficialTestProviderReference s1 = new("synthetic-capability", "officialtest-s1", "1", 1, 1);
        string planJson = $$"""
            {
              "schemaVersion":"1.0",
              "tenantId":"22222222-2222-2222-2222-222222222222",
              "installationId":"33333333-3333-3333-3333-333333333333",
              "environmentId":"{{environmentId:D}}",
              "officialTestEndpoint":"{{publishedBase}}",
              "organization":{"identifier":"12345678903","assigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2","description":"ASL Roma 1","domainId":"asl-roma-1"},
              "locality":{"name":"ASL Roma 1","assigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2","code":"ASLROMA1"},
              "a1":{"providerId":"{{a1.ProviderId}}","resourceId":"{{a1.ResourceId}}","version":"{{a1.Version}}","catalogRevision":1,"publicMetadataRevision":1},
              "s1":{"providerId":"{{s1.ProviderId}}","resourceId":"{{s1.ResourceId}}","version":"{{s1.Version}}","catalogRevision":1,"publicMetadataRevision":1},
              "expectedBindingRevision":null
            }
            """;
        Fse2OfficialTestOperationalPlan plan = Fse2OfficialTestOperationalization.ParsePlan(Encoding.UTF8.GetBytes(planJson));
        Fse2OfficialTestCompiledConfiguration compiled = Fse2OfficialTestOperationalization.Compile(
            plan,
            new(a1, SpkiSha256(material.ClientCertificateRevision1), material.ClientCertificateRevision1.GetNameInfo(X509NameType.SimpleName, false), new string('C', 64)),
            new(s1, SpkiSha256(material.SigningKeyRevision1), material.SigningKeyRevision1.GetNameInfo(X509NameType.SimpleName, false), new string('D', 64)));

        Guid tenantId = await fixture.CreateTenantAsync("fse2-officialtest-runtime-uri-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-officialtest-runtime-uri-application");
        HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
            Fse2OfficialTestCanonicalDefinition.ConnectorId,
            Fse2OfficialTestCanonicalDefinition.ConnectorVersion,
            environmentId,
            publishedBase,
            compiled.CanonicalDefinition,
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: Fse2OfficialTestCanonicalDefinition.OperationId,
            endpointBinding: Fse2OfficialTestCanonicalDefinition.EndpointBinding,
            signingCertificateBinding: Fse2OfficialTestCanonicalDefinition.SigningBinding,
            clientCertificateBinding: Fse2OfficialTestCanonicalDefinition.MutualTlsBinding);
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "fse2-officialtest-runtime-uri-identity");
        await fixture.AddOperationGrantAsync(identity, authority.ConnectorId, Fse2OfficialTestCanonicalDefinition.OperationId);

        Fse2OperationDescriptor operation = Fse2OperationCatalog.Get(Fse2Operation.ValidateCda);
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{authority.ConnectorId}/operations/{operation.OperationId}:invoke",
            InvokeRequest(PayloadFor(operation,
                "{\"healthDataFormat\":\"CDA\",\"activity\":\"VERIFICA\"}",
                DocumentBytes())));
        string responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.True(response.IsSuccessStatusCode, responseBody);
        Assert.Equal(1, localMock.Requests);
        Assert.Equal(expectedEffective, localMock.RequestUri);
        Assert.True(localMock.A1MutualTlsObserved);
        Assert.True(localMock.DualDistinctJwtObserved);
        Assert.True(localMock.S1LeafOnlyX5cObserved);
        Assert.True(localMock.ExactMinisterialRequestBodyObserved);
        Assert.True(localMock.AttachmentHashAbsent);
        Assert.Equal(1, fixture.HostResolutionCount);
        Assert.Equal(1, fixture.GenericTransportRequests);
        Assert.Equal(2, provider.SignDigestCalls);
    }

    private static async Task<VersionPolicyResult> RunVersionPolicyContractAsync(
        string connectorId,
        string connectorVersion,
        string certificateHeader,
        string requestBody,
        string identitySuffix)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Provider(material));
        Uri publishedBase = new(Fse2OfficialTestCanonicalDefinition.OfficialTestEndpoint, UriKind.Absolute);
        VersionPolicyInMemoryTransport localMock = new(
            OfficialTestEffectiveUri,
            Convert.ToHexString(SHA256.HashData(material.ClientCertificateRevision1.RawData)),
            material.SigningKeyRevision1.RawData,
            material.RootCertificate.RawData);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-officialtest-version-policy-" + identitySuffix,
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate),
            restrictedTransport: localMock,
            privateDestinationHosts: new HashSet<string>([publishedBase.DnsSafeHost], StringComparer.OrdinalIgnoreCase));

        Guid environmentId = await fixture.CreateEnvironmentAsync();
        HostedCapabilityAuthority authority = await PrepareVersionPolicyAuthorityAsync(
            fixture,
            provider,
            material,
            environmentId,
            connectorId,
            connectorVersion,
            certificateHeader);
        _ = await fixture.PublishAsync(authority, expectedPublicationRevision: 0);
        Guid tenantId = await fixture.CreateTenantAsync("fse2-officialtest-version-policy-tenant-" + identitySuffix);
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-officialtest-version-policy-application-" + identitySuffix);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId,
            applicationId,
            environmentId,
            "fse2-officialtest-version-policy-identity-" + identitySuffix);
        await fixture.AddOperationGrantAsync(identity, connectorId, Fse2OfficialTestCanonicalDefinition.OperationId);

        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{Fse2OfficialTestCanonicalDefinition.OperationId}:invoke",
            InvokeRequest(PayloadFor(
                Fse2OperationCatalog.Get(Fse2Operation.ValidateCda),
                requestBody,
                DocumentBytes())));
        string responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        if (response.IsSuccessStatusCode && string.Equals(
            connectorId,
            Fse2OfficialTestCanonicalDefinition.ConnectorId,
            StringComparison.Ordinal) && connectorVersion is "1.0.0" or "1.0.1")
        {
            string mismatchedBody = string.Equals(connectorVersion, HistoricalOfficialTestConnectorVersion, StringComparison.Ordinal)
                ? ParityValidateCdaRequestBody
                : HistoricalValidateCdaRequestBody;
            using HttpResponseMessage denied = await fixture.SendSignedAsync(
                identity,
                HttpMethod.Post,
                $"/v1/connectors/{connectorId}/operations/{Fse2OfficialTestCanonicalDefinition.OperationId}:invoke",
                InvokeRequest(PayloadFor(
                    Fse2OperationCatalog.Get(Fse2Operation.ValidateCda),
                    mismatchedBody,
                    DocumentBytes())));
            Assert.False(denied.IsSuccessStatusCode);
        }

        return new(
            response.StatusCode,
            responseBody,
            localMock.Requests,
            localMock.Observations,
            fixture.HostResolutionCount,
            fixture.GenericTransportRequests,
            provider.SignDigestCalls);
    }

    private static async Task<HostedCapabilityAuthority> PrepareVersionPolicyAuthorityAsync(
        HostedTypedSessionFixture fixture,
        TrackingCapabilityProvider provider,
        SyntheticAuthenticationMaterial material,
        Guid environmentId,
        string connectorId,
        string connectorVersion,
        string certificateHeader)
    {
        string definition = CompileVersionPolicyDefinition(
            environmentId,
            material,
            connectorId,
            connectorVersion,
            certificateHeader);
        return await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            connectorVersion,
            environmentId,
            new(Fse2OfficialTestCanonicalDefinition.OfficialTestEndpoint, UriKind.Absolute),
            definition,
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: Fse2OfficialTestCanonicalDefinition.OperationId,
            endpointBinding: Fse2OfficialTestCanonicalDefinition.EndpointBinding,
            signingCertificateBinding: Fse2OfficialTestCanonicalDefinition.SigningBinding,
            clientCertificateBinding: Fse2OfficialTestCanonicalDefinition.MutualTlsBinding);
    }

    private static string CompileVersionPolicyDefinition(
        Guid environmentId,
        SyntheticAuthenticationMaterial material,
        string connectorId,
        string connectorVersion,
        string certificateHeader)
    {
        Fse2OfficialTestProviderReference a1 = new("synthetic-capability", "officialtest-a1", "1", 1, 1);
        Fse2OfficialTestProviderReference s1 = new("synthetic-capability", "officialtest-s1", "1", 1, 1);
        string planJson = $$"""
            {
              "schemaVersion":"1.0",
              "tenantId":"22222222-2222-2222-2222-222222222222",
              "installationId":"33333333-3333-3333-3333-333333333333",
              "environmentId":"{{environmentId:D}}",
              "officialTestEndpoint":"{{Fse2OfficialTestCanonicalDefinition.OfficialTestEndpoint}}",
              "organization":{"identifier":"12345678903","assigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2","description":"ASL Roma 1","domainId":"asl-roma-1"},
              "locality":{"name":"ASL Roma 1","assigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2","code":"ASLROMA1"},
              "a1":{"providerId":"{{a1.ProviderId}}","resourceId":"{{a1.ResourceId}}","version":"{{a1.Version}}","catalogRevision":1,"publicMetadataRevision":1},
              "s1":{"providerId":"{{s1.ProviderId}}","resourceId":"{{s1.ResourceId}}","version":"{{s1.Version}}","catalogRevision":1,"publicMetadataRevision":1},
              "expectedBindingRevision":null
            }
            """;
        Fse2OfficialTestOperationalPlan plan = Fse2OfficialTestOperationalization.ParsePlan(Encoding.UTF8.GetBytes(planJson));
        Fse2OfficialTestCompiledConfiguration compiled = Fse2OfficialTestOperationalization.Compile(
            plan,
            new(a1, SpkiSha256(material.ClientCertificateRevision1), material.ClientCertificateRevision1.GetNameInfo(X509NameType.SimpleName, false), new string('C', 64)),
            new(s1, SpkiSha256(material.SigningKeyRevision1), material.SigningKeyRevision1.GetNameInfo(X509NameType.SimpleName, false), new string('D', 64)));
        JsonObject root = JsonNode.Parse(compiled.CanonicalDefinition)!.AsObject();
        root["connectorId"] = connectorId;
        root["version"] = connectorVersion;
        JsonObject operation = root["operations"]![0]!.AsObject();
        Assert.Equal("appendToBasePath", operation["pathResolution"]!.GetValue<string>());
        Assert.Equal("deny", operation["redirectPolicy"]!.GetValue<string>());
        Assert.Equal(0, operation["maximumRetries"]!.GetValue<int>());
        foreach (JsonNode? slot in operation["authorizedCapabilities"]!["signingSlots"]!.AsArray())
            slot!["signing"]!["certificateHeader"] = certificateHeader;
        return root.ToJsonString();
    }

    private static async Task InvokeVersionPolicyAsync(
        HostedTypedSessionFixture fixture,
        HostedIdentity identity,
        string connectorId,
        string requestBody)
    {
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{Fse2OfficialTestCanonicalDefinition.OperationId}:invoke",
            InvokeRequest(PayloadFor(
                Fse2OperationCatalog.Get(Fse2Operation.ValidateCda),
                requestBody,
                DocumentBytes())));
        string responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, responseBody);
    }

    private static void AssertHistoricalWireContract(VersionPolicyResult result)
    {
        Assert.True((int)result.StatusCode is >= 200 and <= 299, result.ResponseBody);
        Assert.Equal(1, result.TransportRequests);
        Assert.Equal(1, result.HostResolutionCount);
        Assert.Equal(1, result.GenericTransportRequests);
        Assert.Equal(2, result.SignDigestCalls);
        AssertHistoricalWireObservation(result.Observation);
    }

    private static void AssertHistoricalWireObservation(VersionPolicyWireObservation observation)
    {
        AssertWireObservation(observation);
        Assert.Equal(2, observation.AuthorizationX5cCount);
        Assert.Equal(2, observation.IntegrityX5cCount);
        Assert.Equal(HistoricalValidateCdaRequestBody, Encoding.UTF8.GetString(observation.RequestBody));
    }

    private static void AssertParityWireContract(VersionPolicyResult result)
    {
        Assert.True((int)result.StatusCode is >= 200 and <= 299, result.ResponseBody);
        Assert.Equal(1, result.TransportRequests);
        Assert.Equal(1, result.HostResolutionCount);
        Assert.Equal(1, result.GenericTransportRequests);
        Assert.Equal(2, result.SignDigestCalls);
        AssertParityWireObservation(result.Observation);
    }

    private static void AssertParityWireObservation(VersionPolicyWireObservation observation)
    {
        AssertWireObservation(observation);
        Assert.Equal(1, observation.AuthorizationX5cCount);
        Assert.Equal(1, observation.IntegrityX5cCount);
        Assert.Equal(ParityValidateCdaRequestBody, Encoding.UTF8.GetString(observation.RequestBody));
    }

    private static void AssertWireObservation(VersionPolicyWireObservation observation)
    {
        Assert.Equal(OfficialTestEffectiveUri, observation.RequestUri);
        Assert.True(observation.A1MutualTlsObserved);
        Assert.True(observation.DualDistinctJwtObserved);
        Assert.True(observation.ExactPdfObserved);
        Assert.True(observation.AttachmentHashAbsent);
    }

    [Fact]
    public async Task FSE2_AUDIT_failure_emits_exactly_one_failure_and_zero_success()
    {
        const string canary = "upstream-problem-raw-canary";
        FailureAuditObservation observation = await RunFailureAuditAsync(
            StatusCodes.Status400BadRequest,
            "application/problem+json",
            $$"""{"type":"https://fse.example/msg/syntax","title":"{{canary}}","detail":"{{canary}}"}""");

        Assert.Equal(HttpStatusCode.BadGateway, observation.StatusCode);
        Assert.Contains("BGW-EGRESS-UPSTREAM-REJECTED", observation.CallerProblem, StringComparison.Ordinal);
        Assert.DoesNotContain("syntax", observation.CallerProblem, StringComparison.Ordinal);
        Assert.DoesNotContain(canary, observation.CallerProblem, StringComparison.Ordinal);
        Assert.Contains("UPSTREAM_HTTP_RESPONSE", observation.Audit, StringComparison.Ordinal);
        Assert.Contains("upstreamStatus", observation.Audit, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("400", observation.Audit, StringComparison.Ordinal);
        Assert.Contains("safeUpstreamCode", observation.Audit, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("syntax", observation.Audit, StringComparison.Ordinal);
        Assert.DoesNotContain(canary, observation.Audit, StringComparison.Ordinal);
        (int failure, int success) = CountInvokeAuditOutcomes(observation.Audit);
        Assert.Equal(1, failure);
        Assert.Equal(0, success);
        Assert.Equal(1, observation.Requests);
        Assert.True(observation.ExactApplicationJsonAcceptObserved);
    }

    [Fact]
    public async Task FSE2_ADMIN_AUDIT_caller_problem_omits_failure_diagnostics()
    {
        FailureAuditObservation observation = await RunFailureAuditAsync(
            StatusCodes.Status400BadRequest,
            "application/problem+json",
            "{\"type\":\"https://fse.example/msg/syntax\"}");
        using JsonDocument problem = JsonDocument.Parse(observation.CallerProblem);

        Assert.Equal(HttpStatusCode.BadGateway, observation.StatusCode);
        Assert.Equal(
            ["code", "correlationId", "retryable", "status", "title", "type"],
            problem.RootElement.EnumerateObject().Select(value => value.Name).Order(StringComparer.Ordinal));
        Assert.Equal("BGW-EGRESS-UPSTREAM-REJECTED", problem.RootElement.GetProperty("code").GetString());
        Assert.Equal(502, problem.RootElement.GetProperty("status").GetInt32());
        Assert.False(problem.RootElement.GetProperty("retryable").GetBoolean());
        foreach (string forbidden in new[] { "failureDiagnostics", "failurePhase", "upstreamStatus", "statusCategory", "safeUpstreamCode", "localSafeCode", "syntax" })
            Assert.DoesNotContain(forbidden, observation.CallerProblem, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FSE2_ADMIN_AUDIT_local_response_mapping_failure_is_distinct_and_metadata_only()
    {
        const string rawCanary = "invalid-success-body-raw-canary";
        FailureAuditObservation observation = await RunFailureAuditAsync(
            StatusCodes.Status202Accepted,
            "application/json",
            "{\"workflowInstanceId\":{\"raw\":\"" + rawCanary + "\"}}");

        Assert.Equal(HttpStatusCode.BadGateway, observation.StatusCode);
        Assert.Contains("LOCAL_RESPONSE_MAPPING_FAILURE", observation.Audit, StringComparison.Ordinal);
        Assert.Contains("FSE2_RESPONSE_INVALID", observation.Audit, StringComparison.Ordinal);
        Assert.Contains("\"upstreamStatus\":202", observation.Audit, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SUCCESS", observation.Audit, StringComparison.Ordinal);
        Assert.DoesNotContain(rawCanary, observation.Audit, StringComparison.Ordinal);
        Assert.DoesNotContain(rawCanary, observation.CallerProblem, StringComparison.Ordinal);
        Assert.DoesNotContain("FSE2_RESPONSE_INVALID", observation.CallerProblem, StringComparison.Ordinal);
        (int failure, int success) = CountInvokeAuditOutcomes(observation.Audit);
        Assert.Equal(1, failure);
        Assert.Equal(0, success);
        Assert.Equal(1, observation.Requests);
    }

    [Fact]
    public async Task FSE2_IT_DAT_PostgreSQL18_transport_audit_Admin_API_and_evidence_reducer_round_trip()
    {
        PostgresFailureRoundTripObservation observation = await RunPostgresFailureRoundTripAsync(
            StatusCodes.Status400BadRequest,
            "application/problem+json",
            "{\"type\":\"https://fse.example/msg/syntax\",\"title\":\"raw-upstream-title-canary\",\"detail\":\"raw-upstream-detail-canary\"}",
            "upstream-http-failure");

        Assert.StartsWith("18.", observation.PostgresVersion, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.BadGateway, observation.StatusCode);
        Assert.Equal("UPSTREAM_HTTP_RESPONSE", observation.Diagnostics.FailurePhase);
        Assert.Equal(400, observation.Diagnostics.UpstreamStatus);
        Assert.Equal("CLIENT_ERROR", observation.Diagnostics.StatusCategory);
        Assert.Equal("syntax", observation.Diagnostics.SafeUpstreamCode);
        Assert.Null(observation.Diagnostics.LocalSafeCode);
        Assert.Equal(1, observation.FailureAudits);
        Assert.Equal(0, observation.SuccessAudits);
        Assert.Equal(1, observation.Requests);
        Assert.True(observation.ExpectedClientCertificateObserved);
        Assert.True(observation.DualTokensObserved);
        Assert.True(observation.DistinctTokensAndJtiObserved);
        Assert.DoesNotContain("failureDiagnostics", observation.CallerProblem, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("syntax", observation.CallerProblem, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("raw-upstream", observation.AdminAudit, StringComparison.OrdinalIgnoreCase);
        Assert.True(observation.ReducedEvidenceVerifiedBeforeCleanup);
    }

    [Fact]
    public async Task FSE2_IT_DAT_PostgreSQL18_local_mapping_failure_round_trip_is_bounded()
    {
        PostgresFailureRoundTripObservation observation = await RunPostgresFailureRoundTripAsync(
            StatusCodes.Status202Accepted,
            "application/json",
            "{\"workflowInstanceId\":{\"raw\":\"raw-local-mapping-canary\"}}",
            "local-mapping-failure");

        Assert.StartsWith("18.", observation.PostgresVersion, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.BadGateway, observation.StatusCode);
        Assert.Equal("LOCAL_RESPONSE_MAPPING_FAILURE", observation.Diagnostics.FailurePhase);
        Assert.Equal(202, observation.Diagnostics.UpstreamStatus);
        Assert.Equal("SUCCESS", observation.Diagnostics.StatusCategory);
        Assert.Null(observation.Diagnostics.SafeUpstreamCode);
        Assert.Equal("FSE2_RESPONSE_INVALID", observation.Diagnostics.LocalSafeCode);
        Assert.Equal(1, observation.FailureAudits);
        Assert.Equal(0, observation.SuccessAudits);
        Assert.Equal(1, observation.Requests);
        Assert.True(observation.ExpectedClientCertificateObserved);
        Assert.True(observation.DualTokensObserved);
        Assert.True(observation.DistinctTokensAndJtiObserved);
        Assert.DoesNotContain("FSE2_RESPONSE_INVALID", observation.CallerProblem, StringComparison.Ordinal);
        Assert.DoesNotContain("raw-local-mapping-canary", observation.AdminAudit, StringComparison.Ordinal);
        Assert.True(observation.ReducedEvidenceVerifiedBeforeCleanup);
    }

    [Fact]
    public async Task FSE2_TRANSPORT_bounded_redirect_reaches_mapper_without_following()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        await using SyntheticFse2OrganizationServer server = await SyntheticFse2OrganizationServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken,
            responseStatusCode: StatusCodes.Status302Found,
            responseContentType: "application/problem+json",
            responseBody: "{\"type\":\"https://fse.example/msg/syntax\"}",
            responseLocation: "https://redirect-canary.invalid/not-followed");
        SystemRestrictedTransport transport = new(new X509Certificate2Collection(material.RootCertificate));
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(server.Endpoint, "documents"));

        ExternalResponse upstream = await transport.SendProblemDetailsAsync(
            request,
            [IPAddress.Loopback],
            material.ClientCertificateRevision1,
            TimeSpan.FromSeconds(5),
            4096,
            TestContext.Current.CancellationToken);
        Fse2ConnectorException mapped = Fse2ResponseMapper.MapProblem(
            new(upstream.StatusCode, upstream.ContentType, upstream.Body),
            Fse2RetryClass.NoAutomaticRetry);

        Assert.Equal(StatusCodes.Status302Found, upstream.StatusCode);
        Assert.Equal("syntax", mapped.SafeCode);
        Assert.Equal(1, server.Requests);
    }

    [Fact]
    public async Task FSE2_AUDIT_bounded_redirect_emits_exactly_one_failure_and_zero_success()
    {
        const string locationCanary = "redirect-location-audit-canary.invalid";
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Provider(material));
        await using SyntheticFse2OrganizationServer server = await SyntheticFse2OrganizationServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken,
            responseStatusCode: StatusCodes.Status302Found,
            responseContentType: "application/problem+json",
            responseBody: "{\"type\":\"https://fse.example/msg/syntax\"}",
            responseLocation: $"https://{locationCanary}/not-followed");
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-redirect",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));

        string connectorId = "fse2-redirect-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-redirect-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-redirect-application");
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
            tenantId, applicationId, environmentId, "fse2-redirect-identity");
        await AddGrantAsync(fixture, identity, connectorId);

        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/create:invoke",
            InvokeRequest(Payload()));
        string callerProblem = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        string audit = await fixture.SerializeAuditAsync(tenantId);
        (int failure, int success) = CountInvokeAuditOutcomes(audit);

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.Contains("BGW-EGRESS-UPSTREAM-REJECTED", callerProblem, StringComparison.Ordinal);
        Assert.DoesNotContain("BGW-EGRESS-REDIRECT-DENIED", callerProblem, StringComparison.Ordinal);
        Assert.DoesNotContain(locationCanary, callerProblem, StringComparison.Ordinal);
        Assert.DoesNotContain(locationCanary, audit, StringComparison.Ordinal);
        Assert.Contains("syntax", audit, StringComparison.Ordinal);
        Assert.Equal(1, failure);
        Assert.Equal(0, success);
        Assert.Equal(1, server.Requests);
    }

    [Fact]
    public async Task FSE2_TRANSPORT_bounded_redirect_does_not_expose_location()
    {
        const string locationCanary = "redirect-location-must-not-escape.invalid";
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        await using SyntheticFse2OrganizationServer server = await SyntheticFse2OrganizationServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken,
            responseStatusCode: StatusCodes.Status307TemporaryRedirect,
            responseContentType: "application/problem+json",
            responseBody: "{}",
            responseLocation: $"https://{locationCanary}/not-followed");
        SystemRestrictedTransport transport = new(new X509Certificate2Collection(material.RootCertificate));
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(server.Endpoint, "documents"));

        ExternalResponse upstream = await transport.SendProblemDetailsAsync(
            request,
            [IPAddress.Loopback],
            material.ClientCertificateRevision1,
            TimeSpan.FromSeconds(5),
            4096,
            TestContext.Current.CancellationToken);

        Assert.Equal(StatusCodes.Status307TemporaryRedirect, upstream.StatusCode);
        Assert.DoesNotContain(typeof(ExternalResponse).GetProperties(), property =>
            property.Name.Contains("location", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("header", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(locationCanary, Encoding.UTF8.GetString(upstream.Body), StringComparison.Ordinal);
        Assert.Equal(1, server.Requests);
    }

    [Fact]
    public async Task FSE2_TRANSPORT_legacy_redirect_behavior_is_unchanged()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        await using SyntheticFse2OrganizationServer server = await SyntheticFse2OrganizationServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken,
            responseStatusCode: StatusCodes.Status302Found,
            responseContentType: "text/plain",
            responseBody: "legacy-redirect",
            responseLocation: "https://redirect-canary.invalid/not-followed");
        SystemRestrictedTransport transport = new(new X509Certificate2Collection(material.RootCertificate));
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(server.Endpoint, "documents"));

        GatewayException failure = await Assert.ThrowsAsync<GatewayException>(() => transport.SendAsync(
            request,
            [IPAddress.Loopback],
            material.ClientCertificateRevision1,
            TimeSpan.FromSeconds(5),
            4096,
            TestContext.Current.CancellationToken));

        Assert.Equal("BGW-EGRESS-REDIRECT-DENIED", failure.Code);
        Assert.Equal(1, server.Requests);
    }

    [Fact]
    public async Task FSE2_TRANSPORT_streaming_body_over_limit_is_bounded()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        SyntheticFse2RawResponseServer server = await SyntheticFse2RawResponseServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.RootCertificate,
            SyntheticFse2RawResponseBehavior.StreamingBodyOverRetainedLimit,
            TestContext.Current.CancellationToken);
        try
        {
            SystemRestrictedTransport transport = new(new X509Certificate2Collection(material.RootCertificate));
            using HttpRequestMessage request = new(HttpMethod.Post, new Uri(server.Endpoint, "documents"));

            ExternalResponse response = await transport.SendProblemDetailsAsync(
                request,
                [IPAddress.Loopback],
                material.ClientCertificateRevision1,
                TimeSpan.FromSeconds(5),
                maximumResponseBytes: 32 * 1024,
                TestContext.Current.CancellationToken);
            await server.WaitForPeerCloseAsync(TestContext.Current.CancellationToken);
            await server.WaitForServerCompletionAsync(TestContext.Current.CancellationToken);

            Assert.Equal(StatusCodes.Status400BadRequest, response.StatusCode);
            Assert.Equal("application/problem+json", response.ContentType);
            Assert.Empty(response.Body);
            Fse2ConnectorException failure = Fse2ResponseMapper.MapProblem(
                new(response.StatusCode, response.ContentType, response.Body),
                Fse2RetryClass.NoAutomaticRetry);
            Assert.Equal(Fse2ErrorCategory.UpstreamRejected, failure.Category);
            Assert.Equal("FSE2_UPSTREAM_REJECTED", failure.SafeCode);
            Assert.Null(failure.SafeUpstreamCode);
            Assert.False(failure.Retryable);
            Assert.Equal(1, server.Requests);
            Assert.True(server.ClientCertificateObserved);
            Assert.Equal(16 * 1024 + 1, server.BodyBytesSent);
            Assert.True(server.PeerClosed);
            Assert.True(server.ServerTaskCompleted);
        }
        finally
        {
            await server.DisposeAsync();
        }

        Assert.True(server.ShutdownCancellationRequested);
        Assert.True(server.DrainCompleted);
        Assert.True(server.ListenerStopped);
        Assert.True(server.ServerTaskCompleted);
    }

    [Fact]
    public async Task FSE2_TRANSPORT_content_length_over_limit_is_rejected_before_body_read()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        await using SyntheticFse2RawResponseServer server = await SyntheticFse2RawResponseServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.RootCertificate,
            SyntheticFse2RawResponseBehavior.HeadersOnlyOversizedContentLength,
            TestContext.Current.CancellationToken);
        SystemRestrictedTransport transport = new(new X509Certificate2Collection(material.RootCertificate));
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(server.Endpoint, "documents"));

        ExternalResponse response = await transport.SendProblemDetailsAsync(
            request,
            [IPAddress.Loopback],
            material.ClientCertificateRevision1,
            TimeSpan.FromSeconds(5),
            maximumResponseBytes: 32 * 1024,
            TestContext.Current.CancellationToken);

        Assert.Equal(StatusCodes.Status400BadRequest, response.StatusCode);
        Assert.Empty(response.Body);
        Assert.Equal(1, server.Requests);
        Assert.True(server.HeadersSent);
    }

    [Fact]
    public async Task FSE2_TRANSPORT_post_handshake_body_reset_is_transport_other()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        await using SyntheticFse2RawResponseServer server = await SyntheticFse2RawResponseServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.RootCertificate,
            SyntheticFse2RawResponseBehavior.ResetDuringBody,
            TestContext.Current.CancellationToken);
        SystemRestrictedTransport transport = new(new X509Certificate2Collection(material.RootCertificate));
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(server.Endpoint, "documents"));

        RestrictedTransportFailureException failure = await Assert.ThrowsAsync<RestrictedTransportFailureException>(() =>
            transport.SendProblemDetailsAsync(
                request,
                [IPAddress.Loopback],
                material.ClientCertificateRevision1,
                TimeSpan.FromSeconds(5),
                4096,
                TestContext.Current.CancellationToken));

        Assert.Equal(RestrictedTransportFailurePhase.TransportFailureOther, failure.Phase);
        Assert.Equal(1, server.Requests);
        Assert.True(server.HeadersSent);
    }

    [Fact]
    public async Task FSE2_TRANSPORT_successful_mtls_handshake_then_pre_header_reset_is_transport_other()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        await using SyntheticFse2RawResponseServer server = await SyntheticFse2RawResponseServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.RootCertificate,
            SyntheticFse2RawResponseBehavior.ResetBeforeResponseHeaders,
            TestContext.Current.CancellationToken);
        SystemRestrictedTransport transport = new(new X509Certificate2Collection(material.RootCertificate));
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(server.Endpoint, "documents"));

        RestrictedTransportFailureException failure = await Assert.ThrowsAsync<RestrictedTransportFailureException>(() =>
            transport.SendProblemDetailsAsync(
                request,
                [IPAddress.Loopback],
                material.ClientCertificateRevision1,
                TimeSpan.FromSeconds(5),
                4096,
                TestContext.Current.CancellationToken));
        await server.WaitForRequestAsync(TestContext.Current.CancellationToken);

        Assert.Equal(RestrictedTransportFailurePhase.TransportFailureOther, failure.Phase);
        Assert.Equal(1, server.Requests);
        Assert.True(server.ClientCertificateObserved);
        Assert.False(server.HeadersSent);
    }

    [Fact]
    public async Task FSE2_TRANSPORT_caller_cancellation_is_not_timeout()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        await using SyntheticFse2RawResponseServer server = await SyntheticFse2RawResponseServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.RootCertificate,
            SyntheticFse2RawResponseBehavior.HeadersThenWait,
            TestContext.Current.CancellationToken);
        SystemRestrictedTransport transport = new(new X509Certificate2Collection(material.RootCertificate));
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(server.Endpoint, "documents"));
        using CancellationTokenSource callerCancellation = new();

        Task<ExternalResponse> pending = transport.SendProblemDetailsAsync(
            request,
            [IPAddress.Loopback],
            material.ClientCertificateRevision1,
            TimeSpan.FromSeconds(10),
            4096,
            callerCancellation.Token);
        await server.WaitForHeadersAsync(TestContext.Current.CancellationToken);
        callerCancellation.Cancel();

        OperationCanceledException cancellation = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        Assert.IsNotType<RestrictedTransportFailureException>(cancellation);
        Assert.Equal(1, server.Requests);
    }

    [Fact]
    public async Task FSE2_TRANSPORT_ambiguous_TLS_failure_collapses_safely()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        await using SyntheticTlsAbortServer server = await SyntheticTlsAbortServer.StartAsync(TestContext.Current.CancellationToken);
        SystemRestrictedTransport transport = new(new X509Certificate2Collection(material.RootCertificate));
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(server.Endpoint, "documents"));

        RestrictedTransportFailureException failure = await Assert.ThrowsAsync<RestrictedTransportFailureException>(() =>
            transport.SendProblemDetailsAsync(
                request,
                [IPAddress.Loopback],
                material.ClientCertificateRevision1,
                TimeSpan.FromSeconds(5),
                4096,
                TestContext.Current.CancellationToken));

        Assert.Equal(RestrictedTransportFailurePhase.TransportFailureOther, failure.Phase);
        Assert.Equal(1, server.Connections);
    }

    [Fact]
    public async Task FSE2_TRANSPORT_mtls_failure_requires_pre_header_structural_evidence()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        using SyntheticAuthenticationMaterial wrongMaterial = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        await using SyntheticFse2OrganizationServer server = await SyntheticFse2OrganizationServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);

        using HttpRequestMessage tlsRequest = new(HttpMethod.Post, new Uri(server.Endpoint, "documents"));
        SystemRestrictedTransport wrongTrust = new(new X509Certificate2Collection(wrongMaterial.RootCertificate));
        RestrictedTransportFailureException tls = await Assert.ThrowsAsync<RestrictedTransportFailureException>(() =>
            wrongTrust.SendProblemDetailsAsync(
                tlsRequest,
                [IPAddress.Loopback],
                material.ClientCertificateRevision1,
                TimeSpan.FromSeconds(5),
                4096,
                TestContext.Current.CancellationToken));

        using X509Certificate2 publicOnlyClientCertificate = X509CertificateLoader.LoadCertificate(
            material.ClientCertificateRevision1.Export(X509ContentType.Cert));
        using HttpRequestMessage mutualTlsRequest = new(HttpMethod.Post, new Uri(server.Endpoint, "documents"));
        SystemRestrictedTransport correctTrust = new(new X509Certificate2Collection(material.RootCertificate));
        RestrictedTransportFailureException ambiguousClientAuthentication = await Assert.ThrowsAsync<RestrictedTransportFailureException>(() =>
            correctTrust.SendProblemDetailsAsync(
                mutualTlsRequest,
                [IPAddress.Loopback],
                publicOnlyClientCertificate,
                TimeSpan.FromSeconds(5),
                4096,
                TestContext.Current.CancellationToken));

        using TcpListener reservation = new(IPAddress.Loopback, 0);
        reservation.Start();
        int unusedPort = ((IPEndPoint)reservation.LocalEndpoint).Port;
        reservation.Stop();
        using HttpRequestMessage tcpRequest = new(HttpMethod.Post, $"https://localhost:{unusedPort}/documents");
        RestrictedTransportFailureException tcp = await Assert.ThrowsAsync<RestrictedTransportFailureException>(() =>
            correctTrust.SendProblemDetailsAsync(
                tcpRequest,
                [IPAddress.Loopback],
                material.ClientCertificateRevision1,
                TimeSpan.FromSeconds(5),
                4096,
                TestContext.Current.CancellationToken));

        Assert.Equal(RestrictedTransportFailurePhase.TlsServerValidationFailure, tls.Phase);
        Assert.Equal(RestrictedTransportFailurePhase.TransportFailureOther, ambiguousClientAuthentication.Phase);
        Assert.Equal(RestrictedTransportFailurePhase.TcpConnectFailure, tcp.Phase);
        Assert.Equal(0, server.Requests);
    }

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
            Assert.True(observed.ExactApplicationJsonAcceptObserved);
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
    public async Task FSE2_T03_case_476_reads_frozen_git_objects_and_preserves_exact_official_PDF_in_multipart()
    {
        string repositoryPath = Environment.GetEnvironmentVariable("FSE2_T03_DATASET_REPOSITORY_PATH")
            ?? throw new InvalidOperationException("FSE2_T03_DATASET_REPOSITORY_PATH_REQUIRED");
        Fse2T03FrozenDataset.Snapshot dataset = await Fse2T03FrozenDataset.ReadAsync(
            repositoryPath,
            TestContext.Current.CancellationToken);

        Assert.Equal(64, dataset.RawId476Rows);
        Assert.Equal(17, dataset.ExecutedRecords.Count);
        Assert.Equal(16, dataset.Candidates.Count);
        Assert.Equal(1, dataset.Candidates.Count(candidate => candidate.EmbeddedCdaMatch));
        Fse2T03FrozenDataset.PdfCandidate unparseable = Assert.Single(dataset.Candidates, candidate => !candidate.Parseable);
        Assert.Equal(
            "GATEWAY/A1#111#YOOMULTIMEDIAX1/YOO-Multimedia-SRL/YOOMULTIMEDIA-FSE-GATEWAY/1.1.0/FILES/T3_VALIDATION.pdf",
            unparseable.Path);
        Assert.False(unparseable.EmbeddedCdaMatch);

        Fse2T03FrozenDataset.ExecutedRecord daVinci = Assert.Single(dataset.ExecutedRecords, record =>
            record.WorkbookPath.Equals(
                "GATEWAY/A1#111#DAVINCI.CARE/DaVinci Healthcare/DaVinci/3.3/report-checklist.xlsx",
                StringComparison.Ordinal));
        Assert.Equal("VALIDAZIONE_CDA2_PSS_CT23", daVinci.TestCode);
        Fse2T03FrozenDataset.PdfCandidate selected = Assert.Single(dataset.Candidates, candidate =>
            candidate.Path.Equals(Fse2T03FrozenDataset.SelectedPdfPath, StringComparison.Ordinal));
        Assert.Equal(Fse2T03FrozenDataset.SelectedPdfBlob, selected.Blob);
        Assert.Equal(Fse2T03FrozenDataset.SelectedPdfBytes, selected.Bytes);
        Assert.Equal(Fse2T03FrozenDataset.SelectedPdfSha256, selected.Sha256);
        Assert.True(selected.Parseable);
        Assert.True(selected.EmbeddedCdaMatch);
        Assert.StartsWith(
            daVinci.WorkbookPath[..daVinci.WorkbookPath.LastIndexOf('/')],
            selected.Path,
            StringComparison.Ordinal);

        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Provider(material));
        await using SyntheticFse2OperationMatrixServer server = await SyntheticFse2OperationMatrixServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken,
            Fse2OfficialTestCanonicalDefinition.OfficialTestAudience,
            Fse2OfficialTestCanonicalDefinition.ApplicationId,
            Fse2OfficialTestCanonicalDefinition.ApplicationVendor,
            Fse2OfficialTestCanonicalDefinition.ApplicationVersion,
            expectLeafOnlyX5c: true);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-t03-frozen-dataset",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));

        Fse2OperationDescriptor operation = Fse2OperationCatalog.Get(Fse2Operation.ValidateCda);
        string connectorId = Fse2OfficialTestCanonicalDefinition.ConnectorId;
        string connectorVersion = Fse2OfficialTestCanonicalDefinition.ConnectorVersion;
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-t03-frozen-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-t03-frozen-application");
        HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            connectorVersion,
            environmentId,
            server.Endpoint,
            CompileVersionPolicyDefinition(
                environmentId,
                material,
                connectorId,
                connectorVersion,
                "leaf"),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: operation.OperationId,
            expectedOperationCount: 1,
            endpointBinding: Fse2OfficialTestCanonicalDefinition.EndpointBinding,
            signingCertificateBinding: Fse2OfficialTestCanonicalDefinition.SigningBinding,
            clientCertificateBinding: Fse2OfficialTestCanonicalDefinition.MutualTlsBinding);
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "fse2-t03-frozen-identity");
        await fixture.AddOperationGrantAsync(identity, connectorId, operation.OperationId);

        const string requestBody = ParityValidateCdaRequestBody;
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{operation.OperationId}:invoke",
            InvokeRequest(PayloadFor(operation, requestBody, dataset.SelectedPdfContent)));
        string responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.OK, responseBody);

        SyntheticFse2OperationMatrixServer.Observation observation = Assert.Single(server.Observations);
        Assert.Equal(Fse2Operation.ValidateCda, observation.Operation);
        Assert.Equal("POST", observation.Method);
        Assert.Equal("/documents/validation", observation.RawTarget);
        Assert.Equal($"multipart/form-data; boundary={OfficialTestBoundary}", observation.ContentType);
        Assert.False(observation.AttachmentHashPresent);
        Assert.True(observation.HasHttpContent);
        Assert.True(observation.ExactApplicationJsonAcceptObserved);
        Assert.True(observation.ClientCertificateObserved);
        Assert.True(observation.DualDistinctTokensObserved);
        Assert.True(observation.ExactJwtPolicyObserved);
        Assert.True(observation.ExactClaimsObserved);

        MultipartCapture multipart = await ReadMultipartCaptureAsync(
            observation.ContentType,
            observation.Body,
            OfficialTestBoundary,
            TestContext.Current.CancellationToken);
        Assert.Equal(1, multipart.FilePartCount);
        Assert.Equal(1, multipart.RequestBodyPartCount);
        Assert.Equal("document.pdf", multipart.FileName);
        Assert.Equal("application/pdf", multipart.FileMediaType);
        Assert.Equal(Fse2T03FrozenDataset.SelectedPdfBytes, multipart.FileBytes.Length);
        Assert.Equal(Fse2T03FrozenDataset.SelectedPdfSha256, Convert.ToHexString(SHA256.HashData(multipart.FileBytes)));
        Assert.Equal(dataset.SelectedPdfContent, multipart.FileBytes);
        using JsonDocument capturedRequestBody = JsonDocument.Parse(multipart.RequestBodyBytes);
        Assert.Equal("VERIFICA", capturedRequestBody.RootElement.GetProperty("activity").GetString());
        Assert.Equal("CDA", capturedRequestBody.RootElement.GetProperty("healthDataFormat").GetString());
        Assert.False(capturedRequestBody.RootElement.TryGetProperty("mode", out _));
        Assert.False(capturedRequestBody.RootElement.TryGetProperty("attachment_hash", out _));
        Assert.Equal(
            ["activity", "healthDataFormat"],
            capturedRequestBody.RootElement.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray());

        await WriteT03ResultIfConfiguredAsync(dataset, observation, multipart, TestContext.Current.CancellationToken);
    }

    [Fact]
    public Task FSE2_REQUEST_create_and_replace_workflowInstanceId_256_are_accepted_and_exact_wire_bytes_are_preserved()
    {
        string exactMaximum = new('w', 256);
        return AssertJsonBodiesAcceptedAndPreservedAsync(new Dictionary<Fse2Operation, string>
        {
            [Fse2Operation.Create] = JsonSerializer.Serialize(new { workflowInstanceId = exactMaximum, metadata = "create-exact" }, WebJson),
            [Fse2Operation.Replace] = JsonSerializer.Serialize(new { workflowInstanceId = exactMaximum, metadata = "replace-exact" }, WebJson)
        });
    }

    [Fact]
    public Task FSE2_REQUEST_absent_workflowInstanceId_and_innocent_string_remain_compatible()
    {
        return AssertJsonBodiesAcceptedAndPreservedAsync(new Dictionary<Fse2Operation, string>
        {
            [Fse2Operation.Create] = "{\"metadata\":\"workflow-field-absent\"}",
            [Fse2Operation.Replace] = "{\"note\":\"workflowInstanceId is text, not a property\"}"
        });
    }

    [Fact]
    public Task FSE2_REQUEST_other_operations_preserve_existing_JSON_object_behavior()
    {
        string existingBehaviorBody = JsonSerializer.Serialize(new
        {
            workflowInstanceId = new string('w', 257),
            mode = "ATTACHMENT",
            metadata = "operation-aware-scope"
        }, WebJson);
        return AssertJsonBodiesAcceptedAndPreservedAsync(new Dictionary<Fse2Operation, string>
        {
            [Fse2Operation.UpdateMetadata] = existingBehaviorBody
        });
    }

    [Fact]
    public Task FSE2_SEC_create_and_replace_workflowInstanceId_257_invoke_strategy_once_and_deny_before_store_signing_DNS_HTTPS_transport_and_network()
    {
        string invalidBody = JsonSerializer.Serialize(new
        {
            workflowInstanceId = new string('w', 257),
            metadata = "raw-workflow-canary-not-exposed"
        }, WebJson);
        return AssertPublicationWorkflowBodiesDeniedAsync("max-plus-one", [invalidBody]);
    }

    [Fact]
    public Task FSE2_SEC_create_and_replace_workflowInstanceId_alternative_JSON_types_invoke_strategy_once_and_deny_before_store_signing_DNS_HTTPS_transport_and_network() =>
        AssertPublicationWorkflowBodiesDeniedAsync("alternate-types",
        [
            "{\"workflowInstanceId\":7,\"metadata\":\"raw-workflow-canary-not-exposed\"}",
            "{\"workflowInstanceId\":true,\"metadata\":\"raw-workflow-canary-not-exposed\"}",
            "{\"workflowInstanceId\":{},\"metadata\":\"raw-workflow-canary-not-exposed\"}",
            "{\"workflowInstanceId\":[],\"metadata\":\"raw-workflow-canary-not-exposed\"}",
            "{\"workflowInstanceId\":null,\"metadata\":\"raw-workflow-canary-not-exposed\"}"
        ]);

    [Fact]
    public Task FSE2_SEC_create_and_replace_workflowInstanceId_duplicate_casing_escaped_and_exact_alias_forms_invoke_strategy_once_and_deny_before_store_signing_DNS_HTTPS_transport_and_network() =>
        AssertPublicationWorkflowBodiesDeniedAsync("property-forms",
        [
            "{\"workflowInstanceId\":\"raw-workflow-canary-not-exposed\",\"workflowInstanceId\":\"second\"}",
            "{\"WorkflowInstanceId\":\"raw-workflow-canary-not-exposed\"}",
            "{\"\\u0077orkflowInstanceId\":\"raw-workflow-canary-not-exposed\"}",
            "{\"workflowInstanceId\":\"raw-workflow-canary-not-exposed\",\"WorkflowInstanceId\":\"second\"}"
        ]);

    [Fact]
    public Task FSE2_SEC_create_and_replace_workflowInstanceId_whitespace_control_and_separator_forms_invoke_strategy_once_and_deny_before_store_signing_DNS_HTTPS_transport_and_network() =>
        AssertPublicationWorkflowBodiesDeniedAsync("identifier-forms",
        [
            "{\"workflowInstanceId\":\" raw-workflow-canary-not-exposed\"}",
            "{\"workflowInstanceId\":\"raw-workflow-canary-not-exposed \"}",
            "{\"workflowInstanceId\":\"raw-workflow-canary-not-exposed\\u000A\"}",
            "{\"workflowInstanceId\":\"raw-workflow-canary/not-exposed\"}"
        ]);

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

    [Fact]
    public async Task FSE2_SEC_workflowInstanceId_257_is_denied_before_signing_DNS_HTTPS_and_network()
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
            "unused-fse2-workflow-bound-negative",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));
        Fse2OperationDescriptor status = Fse2OperationCatalog.Get(Fse2Operation.GetStatusByWorkflow);
        string connectorId = "fse2-workflow-bound-negative-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-workflow-bound-negative-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-workflow-bound-negative-application");
        HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            DefinitionForOperations(connectorId, "1.0.0", SpkiSha256(material.SigningKeyRevision1),
                SpkiSha256(material.ClientCertificateRevision1), "1.0.0", [status]),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: status.OperationId);
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "fse2-workflow-bound-negative-identity");
        await fixture.AddOperationGrantAsync(identity, connectorId, status.OperationId);

        string invalidPayload = PayloadFor(status).Replace(
            "workflow-fse2-1",
            new string('w', 257),
            StringComparison.Ordinal);
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{status.OperationId}:invoke",
            InvokeRequest(invalidPayload));

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.Equal(0, provider.SignDigestCalls);
        Assert.Equal(0, fixture.HostResolutionCount);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.GenericTransportRequests);
    }

    private static async Task AssertJsonBodiesAcceptedAndPreservedAsync(
        IReadOnlyDictionary<Fse2Operation, string> requestBodies)
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
            "unused-fse2-workflow-request-positive",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));

        Fse2OperationDescriptor[] operations = requestBodies.Keys
            .Select(Fse2OperationCatalog.Get)
            .ToArray();
        string connectorId = "fse2-workflow-request-positive-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-workflow-request-positive-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-workflow-request-positive-application");
        HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            DefinitionForOperations(connectorId, "1.0.0", SpkiSha256(material.SigningKeyRevision1),
                SpkiSha256(material.ClientCertificateRevision1), "1.0.0", operations),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: "*",
            expectedOperationCount: operations.Length);
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "fse2-workflow-request-positive-identity");
        foreach (Fse2OperationDescriptor operation in operations)
            await fixture.AddOperationGrantAsync(identity, connectorId, operation.OperationId);

        foreach (Fse2OperationDescriptor operation in operations)
        {
            string exactRequestBody = requestBodies[operation.Operation];
            using HttpResponseMessage response = await fixture.SendSignedAsync(
                identity,
                HttpMethod.Post,
                $"/v1/connectors/{connectorId}/operations/{operation.OperationId}:invoke",
                InvokeRequest(PayloadFor(operation, exactRequestBody)));
            string responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.True(response.StatusCode == HttpStatusCode.OK, $"{operation.OperationId}:{responseBody}");
        }

        Assert.Equal(operations.Length, server.Requests);
        Assert.Equal(operations.Length * 2, provider.SignDigestCalls);
        Assert.Equal(operations.Length, fixture.HostResolutionCount);
        Assert.Equal(operations.Length, fixture.GenericTransportRequests);
        foreach (Fse2OperationDescriptor operation in operations)
        {
            SyntheticFse2OperationMatrixServer.Observation observation = Assert.Single(
                server.Observations, value => value.Operation == operation.Operation);
            byte[] exactRequestBody = Encoding.UTF8.GetBytes(requestBodies[operation.Operation]);
            if (operation.HasDocument)
                Assert.True(observation.Body.AsSpan().IndexOf(exactRequestBody) >= 0, operation.OperationId);
            else
                Assert.Equal(exactRequestBody, observation.Body);
            Assert.True(observation.DualDistinctTokensObserved);
            Assert.True(observation.ExactJwtPolicyObserved);
            Assert.True(observation.ExactClaimsObserved);
        }
    }

    private static async Task AssertPublicationWorkflowBodiesDeniedAsync(
        string scenario,
        IReadOnlyList<string> invalidRequestBodies)
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
            "unused-fse2-workflow-request-negative-" + scenario,
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));

        Fse2OperationDescriptor[] operations =
        [
            Fse2OperationCatalog.Get(Fse2Operation.Create),
            Fse2OperationCatalog.Get(Fse2Operation.Replace)
        ];
        string connectorId = "fse2-workflow-request-negative-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-workflow-request-negative-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-workflow-request-negative-application");
        HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            DefinitionForOperations(connectorId, "1.0.0", SpkiSha256(material.SigningKeyRevision1),
                SpkiSha256(material.ClientCertificateRevision1), "1.0.0", operations),
            provider,
            "sign-r1",
            "mtls-r1",
            operationId: "*",
            expectedOperationCount: operations.Length);
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "fse2-workflow-request-negative-identity");
        foreach (Fse2OperationDescriptor operation in operations)
            await fixture.AddOperationGrantAsync(identity, connectorId, operation.OperationId);

        foreach (Fse2OperationDescriptor operation in operations)
        {
            foreach (string invalidRequestBody in invalidRequestBodies)
            {
                int signingBefore = provider.SignDigestCalls;
                int dnsBefore = fixture.HostResolutionCount;
                int httpsBefore = server.Requests;
                int transportBefore = fixture.GenericTransportRequests;
                using HttpResponseMessage response = await fixture.SendSignedAsync(
                    identity,
                    HttpMethod.Post,
                    $"/v1/connectors/{connectorId}/operations/{operation.OperationId}:invoke",
                    InvokeRequest(PayloadFor(operation, invalidRequestBody)));
                string responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

                Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
                Assert.DoesNotContain("workflowInstanceId", responseBody, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("raw-workflow-canary-not-exposed", responseBody, StringComparison.Ordinal);
                Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes(invalidRequestBody)), responseBody, StringComparison.Ordinal);
                Assert.Equal(signingBefore, provider.SignDigestCalls);
                Assert.Equal(dnsBefore, fixture.HostResolutionCount);
                Assert.Equal(httpsBefore, server.Requests);
                Assert.Equal(transportBefore, fixture.GenericTransportRequests);
            }
        }

        Assert.Equal(0, provider.SignDigestCalls);
        Assert.Equal(0, fixture.HostResolutionCount);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.GenericTransportRequests);
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
        Assert.True(server.ExactApplicationJsonAcceptObserved);
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

    internal static InMemoryProvider Provider(SyntheticAuthenticationMaterial material) => new(
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

    private static (int Failure, int Success) CountInvokeAuditOutcomes(string serializedAudit)
    {
        using JsonDocument document = JsonDocument.Parse(serializedAudit);
        int failure = 0;
        int success = 0;
        foreach (JsonElement entry in document.RootElement.EnumerateArray())
        {
            string? action = Property(entry, "action");
            string? outcome = Property(entry, "outcome");
            if (!string.Equals(action, "operation.invoke", StringComparison.Ordinal)) continue;
            if (string.Equals(outcome, "failure", StringComparison.OrdinalIgnoreCase)) failure++;
            if (string.Equals(outcome, "success", StringComparison.OrdinalIgnoreCase)) success++;
        }
        return (failure, success);

        static string? Property(JsonElement entry, string name)
        {
            foreach (JsonProperty property in entry.EnumerateObject())
                if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase) &&
                    property.Value.ValueKind == JsonValueKind.String)
                    return property.Value.GetString();
            return null;
        }
    }

    private static async Task<FailureAuditObservation> RunFailureAuditAsync(
        int responseStatusCode,
        string responseContentType,
        string responseBody)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Provider(material));
        await using SyntheticFse2OrganizationServer server = await SyntheticFse2OrganizationServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken,
            responseStatusCode,
            responseContentType,
            responseBody);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-safe-failure-diagnostics",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));

        string connectorId = "fse2-diagnostics-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-diagnostics-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-diagnostics-application");
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
            tenantId, applicationId, environmentId, "fse2-diagnostics-identity");
        await AddGrantAsync(fixture, identity, connectorId);

        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/create:invoke",
            InvokeRequest(Payload()));
        string callerProblem = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        string audit = await fixture.SerializeAuditAsync(tenantId);
        return new(response.StatusCode, callerProblem, audit, server.Requests, server.ExactApplicationJsonAcceptObserved);
    }

    private static async Task<PostgresFailureRoundTripObservation> RunPostgresFailureRoundTripAsync(
        int responseStatusCode,
        string responseContentType,
        string responseBody,
        string evidenceName)
    {
        string adminConnection = GetRequiredPostgresConnectionOrSkip("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        string migrationConnection = GetRequiredPostgresConnectionOrSkip("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        await HostedPostgresTestSupport.ApplyMigrationAsync();
        await HostedPostgresTestSupport.ApplyMigrationAsync();
        await using NpgsqlConnection versionConnection = new(migrationConnection);
        await versionConnection.OpenAsync(TestContext.Current.CancellationToken);
        string postgresVersion = versionConnection.PostgreSqlVersion.ToString();
        await versionConnection.CloseAsync();

        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole =
            await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(
                adminConnection,
                migrationConnection,
                TestContext.Current.CancellationToken);
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Provider(material));
        await using SyntheticFse2OrganizationServer server = await SyntheticFse2OrganizationServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken,
            responseStatusCode,
            responseContentType,
            responseBody);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-fse2-postgres-failure-round-trip",
            runtimeConnection: runtimeRole.ConnectionString,
            adminConnection: adminConnection,
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate),
            enableDevelopmentAdmin: true);
        Assert.True(fixture.UsesPostgreSql);

        string suffix = Guid.NewGuid().ToString("N");
        string connectorId = "fse2-postgres-diagnostics-" + suffix;
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("fse2-diag-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("fse2-diag-app");
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
            tenantId, applicationId, environmentId, "fse2-diag-identity");
        await AddGrantAsync(fixture, identity, connectorId);

        Guid correlationId = Guid.NewGuid();
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/create:invoke",
            InvokeRequest(Payload(), correlationId));
        string callerProblem = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        using HttpClient administrator = fixture.CreateAdminClient();
        await LoginSecurityAdministratorAsync(administrator, TestContext.Current.CancellationToken);
        using HttpResponseMessage auditResponse = await administrator.GetAsync(
            $"/admin/api/v1/audit?tenantId={tenantId:D}&limit=100",
            TestContext.Current.CancellationToken);
        auditResponse.EnsureSuccessStatusCode();
        string adminAudit = await auditResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        using JsonDocument auditDocument = JsonDocument.Parse(adminAudit);
        Fse2FailureDiagnosticsEvidence reduced = Fse2FailureEvidenceReducer.Reduce(auditDocument.RootElement, correlationId);
        (int failure, int success) = CountAdminApiInvokeAuditOutcomes(auditDocument.RootElement, correlationId);
        bool evidenceVerified = await WriteAndVerifyReducedEvidenceBeforeCleanupAsync(
            evidenceName,
            correlationId,
            reduced,
            TestContext.Current.CancellationToken);

        return new(
            response.StatusCode,
            callerProblem,
            adminAudit,
            reduced,
            failure,
            success,
            server.Requests,
            server.ExpectedClientCertificateObserved,
            server.DualTokensObserved,
            server.DistinctTokensAndJtiObserved,
            postgresVersion,
            evidenceVerified);
    }

    private static async Task LoginSecurityAdministratorAsync(HttpClient client, CancellationToken cancellationToken)
    {
        string csrf = await GetAdminCsrfAsync(client, cancellationToken);
        using HttpRequestMessage request = new(HttpMethod.Post, "/admin/auth/development/login")
        {
            Content = JsonContent.Create(new { userName = "security-admin" })
        };
        request.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    private static async Task<string> GetAdminCsrfAsync(HttpClient client, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await client.GetAsync("/admin/auth/csrf", cancellationToken);
        response.EnsureSuccessStatusCode();
        using JsonDocument document = await JsonDocument.ParseAsync(
            await response.Content.ReadAsStreamAsync(cancellationToken),
            cancellationToken: cancellationToken);
        return document.RootElement.GetProperty("token").GetString()
            ?? throw new InvalidOperationException("Synthetic Admin CSRF token missing.");
    }

    private static (int Failure, int Success) CountAdminApiInvokeAuditOutcomes(JsonElement auditPage, Guid correlationId)
    {
        JsonElement[] matching = auditPage.GetProperty("items").EnumerateArray().Where(value =>
            value.GetProperty("correlationId").GetGuid() == correlationId &&
            string.Equals(value.GetProperty("action").GetString(), "operation.invoke", StringComparison.Ordinal)).ToArray();
        return (
            matching.Count(value => string.Equals(value.GetProperty("outcome").GetString(), "failure", StringComparison.Ordinal)),
            matching.Count(value => string.Equals(value.GetProperty("outcome").GetString(), "success", StringComparison.Ordinal)));
    }

    private static async Task<bool> WriteAndVerifyReducedEvidenceBeforeCleanupAsync(
        string evidenceName,
        Guid correlationId,
        Fse2FailureDiagnosticsEvidence diagnostics,
        CancellationToken cancellationToken)
    {
        string? configuredDirectory = Environment.GetEnvironmentVariable("FSE2_DIAGNOSTICS_EVIDENCE_OUTPUT");
        bool preserve = !string.IsNullOrWhiteSpace(configuredDirectory);
        string directory = preserve ? Path.GetFullPath(configuredDirectory!) : Path.GetTempPath();
        if (!Directory.Exists(directory) || File.GetAttributes(directory).HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException("FSE2_DIAGNOSTICS_EVIDENCE_DIRECTORY_INVALID");
        string path = Path.Combine(directory, $"{evidenceName}-{correlationId:N}.json");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(diagnostics, WebJson);
        await using (FileStream stream = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous))
            await stream.WriteAsync(bytes, cancellationToken);
        try
        {
            byte[] readBack = await File.ReadAllBytesAsync(path, cancellationToken);
            Assert.True(CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), SHA256.HashData(readBack)));
            using JsonDocument document = JsonDocument.Parse(readBack);
            Assert.Equal(
                ["failurePhase", "localSafeCode", "safeUpstreamCode", "statusCategory", "upstreamStatus"],
                document.RootElement.EnumerateObject().Select(value => value.Name).Order(StringComparer.Ordinal));
            return true;
        }
        finally
        {
            if (!preserve) File.Delete(path);
        }
    }

    private sealed record FailureAuditObservation(
        HttpStatusCode StatusCode,
        string CallerProblem,
        string Audit,
        int Requests,
        bool ExactApplicationJsonAcceptObserved);

    private sealed record PostgresFailureRoundTripObservation(
        HttpStatusCode StatusCode,
        string CallerProblem,
        string AdminAudit,
        Fse2FailureDiagnosticsEvidence Diagnostics,
        int FailureAudits,
        int SuccessAudits,
        int Requests,
        bool ExpectedClientCertificateObserved,
        bool DualTokensObserved,
        bool DistinctTokensAndJtiObserved,
        string PostgresVersion,
        bool ReducedEvidenceVerifiedBeforeCleanup);

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

    internal static HostedExecutionModuleConfiguration Module()
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

    internal static string PayloadFor(
        Fse2OperationDescriptor operation,
        string? requestBodyJson = null,
        byte[]? documentBytes = null)
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
            payload["documentBase64"] = Convert.ToBase64String(documentBytes ?? DocumentBytes());
            payload["documentContentType"] = operation.Operation == Fse2Operation.ValidateFhir
                ? "application/json"
                : "application/pdf";
        }
        if (operation.HasJsonBody)
        {
            requestBodyJson ??= operation.Operation == Fse2Operation.ValidateCda
                ? HistoricalValidateCdaRequestBody
                : "{\"metadata\":\"published-exact\"}";
            payload["requestBodyBase64"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(requestBodyJson));
        }
        if (resourceIdentifier is not null) payload["resourceIdentifier"] = resourceIdentifier;
        return JsonSerializer.Serialize(payload, WebJson);
    }

    private static async Task<MultipartCapture> ReadMultipartCaptureAsync(
        SyntheticFse2OperationMatrixServer.Observation observation,
        CancellationToken cancellationToken) => await ReadMultipartCaptureAsync(
            observation.ContentType,
            observation.Body,
            Boundary,
            cancellationToken);

    private static async Task<MultipartCapture> ReadMultipartCaptureAsync(
        string? rawContentType,
        byte[] rawBody,
        string expectedBoundary,
        CancellationToken cancellationToken)
    {
        Assert.NotNull(rawContentType);
        Assert.True(MediaTypeHeaderValue.TryParse(rawContentType, out MediaTypeHeaderValue? contentType));
        NameValueHeaderValue boundaryParameter = Assert.Single(
            contentType.Parameters,
            parameter => parameter.Name.Equals("boundary", StringComparison.OrdinalIgnoreCase));
        string boundary = HeaderUtilities.RemoveQuotes(boundaryParameter.Value).Value
            ?? throw new InvalidOperationException("FSE2_T03_MULTIPART_BOUNDARY_MISSING");
        Assert.Equal(expectedBoundary, boundary);

        using MemoryStream body = new(rawBody, writable: false);
        MultipartReader reader = new(boundary, body);
        int filePartCount = 0;
        int requestBodyPartCount = 0;
        string? fileName = null;
        string? fileMediaType = null;
        byte[] fileBytes = [];
        byte[] requestBodyBytes = [];
        MultipartSection? section;
        while ((section = await reader.ReadNextSectionAsync(cancellationToken)) is not null)
        {
            Assert.True(ContentDispositionHeaderValue.TryParse(
                section.ContentDisposition,
                out ContentDispositionHeaderValue? disposition));
            string name = HeaderUtilities.RemoveQuotes(disposition.Name).Value ?? string.Empty;
            using MemoryStream sectionBody = new();
            await section.Body.CopyToAsync(sectionBody, cancellationToken);
            if (name.Equals("file", StringComparison.Ordinal))
            {
                filePartCount++;
                fileName = HeaderUtilities.RemoveQuotes(disposition.FileName).Value;
                fileMediaType = section.ContentType;
                fileBytes = sectionBody.ToArray();
            }
            else if (name.Equals("requestBody", StringComparison.Ordinal))
            {
                requestBodyPartCount++;
                Assert.Equal("application/json", section.ContentType);
                requestBodyBytes = sectionBody.ToArray();
            }
            else
            {
                throw new InvalidOperationException("FSE2_T03_MULTIPART_UNEXPECTED_PART");
            }
        }
        return new(filePartCount, requestBodyPartCount, fileName, fileMediaType, fileBytes, requestBodyBytes);
    }

    private static async Task WriteT03ResultIfConfiguredAsync(
        Fse2T03FrozenDataset.Snapshot dataset,
        SyntheticFse2OperationMatrixServer.Observation observation,
        MultipartCapture multipart,
        CancellationToken cancellationToken)
    {
        string? resultPath = Environment.GetEnvironmentVariable("FSE2_T03_REDACTED_RESULT_PATH");
        if (string.IsNullOrWhiteSpace(resultPath)) return;
        string fullPath = Path.GetFullPath(resultPath);
        string? directory = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
            throw new InvalidOperationException("FSE2_T03_REDACTED_RESULT_DIRECTORY_MISSING");
        string sourceSha = Environment.GetEnvironmentVariable("FSE2_T03_SOURCE_SHA")
            ?? throw new InvalidOperationException("FSE2_T03_SOURCE_SHA_REQUIRED_FOR_RESULT");
        byte[] redacted = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1,
            sourceSha,
            datasetRepository = Fse2T03FrozenDataset.RepositoryUrl,
            datasetCommit = Fse2T03FrozenDataset.Commit,
            rawId476Rows = dataset.RawId476Rows,
            executedRecords = dataset.ExecutedRecords.Count,
            pdfCandidateCount = dataset.Candidates.Count,
            candidates = dataset.Candidates.Select(candidate => new
            {
                candidate.Path,
                candidate.Blob,
                candidate.Bytes,
                candidate.Sha256,
                candidate.Parseable,
                match = candidate.EmbeddedCdaMatch,
                candidate.EmbeddedCdaSha256
            }),
            xml = new
            {
                path = Fse2T03FrozenDataset.XmlPath,
                blob = Fse2T03FrozenDataset.XmlBlob,
                bytes = Fse2T03FrozenDataset.XmlBytes,
                sha256 = Fse2T03FrozenDataset.XmlSha256
            },
            selectedPdf = new
            {
                path = Fse2T03FrozenDataset.SelectedPdfPath,
                blob = Fse2T03FrozenDataset.SelectedPdfBlob,
                bytes = Fse2T03FrozenDataset.SelectedPdfBytes,
                sha256 = Fse2T03FrozenDataset.SelectedPdfSha256
            },
            embeddedCdaMatchCount = dataset.Candidates.Count(candidate => candidate.EmbeddedCdaMatch),
            multipart = new
            {
                operation = "validate-cda",
                method = observation.Method,
                path = observation.RawTarget,
                contentType = observation.ContentType,
                attachmentHashAbsent = !observation.AttachmentHashPresent,
                filePartCount = multipart.FilePartCount,
                requestBodyPartCount = multipart.RequestBodyPartCount,
                fileName = multipart.FileName,
                fileMediaType = multipart.FileMediaType,
                fileBytes = multipart.FileBytes.Length,
                fileSha256 = Convert.ToHexString(SHA256.HashData(multipart.FileBytes)),
                exactByteIdentity = multipart.FileBytes.AsSpan().SequenceEqual(dataset.SelectedPdfContent)
            }
        }, WebJson);
        await File.WriteAllBytesAsync(fullPath, redacted, cancellationToken);
    }

    private sealed record MultipartCapture(
        int FilePartCount,
        int RequestBodyPartCount,
        string? FileName,
        string? FileMediaType,
        byte[] FileBytes,
        byte[] RequestBodyBytes);

    private sealed record VersionPolicyResult(
        HttpStatusCode StatusCode,
        string ResponseBody,
        int TransportRequests,
        VersionPolicyWireObservation[] TransportObservations,
        int HostResolutionCount,
        int GenericTransportRequests,
        int SignDigestCalls)
    {
        internal VersionPolicyWireObservation Observation => Assert.Single(TransportObservations);
    }

    private sealed record VersionPolicyWireObservation(
        Uri RequestUri,
        int AuthorizationX5cCount,
        int IntegrityX5cCount,
        byte[] RequestBody,
        bool A1MutualTlsObserved,
        bool DualDistinctJwtObserved,
        bool ExactPdfObserved,
        bool AttachmentHashAbsent);

    private sealed class VersionPolicyInMemoryTransport(
        Uri expectedUri,
        string expectedClientFingerprint,
        byte[] expectedSigningLeaf,
        byte[] expectedRoot) : IRestrictedTransport
    {
        private readonly Lock observationGate = new();
        private readonly List<VersionPolicyWireObservation> observations = [];
        private int requests;

        internal int Requests => Volatile.Read(ref requests);
        internal VersionPolicyWireObservation[] Observations
        {
            get
            {
                lock (observationGate) return observations.ToArray();
            }
        }

        public async Task<ExternalResponse> SendAsync(
            HttpRequestMessage request,
            IReadOnlyList<IPAddress> approvedAddresses,
            X509Certificate2? clientCertificate,
            TimeSpan timeout,
            long maximumResponseBytes,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref requests);
            Assert.Equal(expectedUri, request.RequestUri);
            Assert.Equal([IPAddress.Loopback], approvedAddresses);
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal($"multipart/form-data; boundary={OfficialTestBoundary}", request.Content?.Headers.ContentType?.ToString());
            Assert.Equal("application/json", Assert.Single(request.Headers.Accept).MediaType);
            Assert.Equal(TimeSpan.FromSeconds(5), timeout);
            Assert.Equal(4096, maximumResponseBytes);

            bool a1MutualTlsObserved = clientCertificate is not null && string.Equals(
                Convert.ToHexString(SHA256.HashData(clientCertificate.RawData)),
                expectedClientFingerprint,
                StringComparison.Ordinal);
            string authorization = request.Headers.Authorization?.Parameter
                ?? throw new InvalidOperationException("FSE2_TEST_AUTHORIZATION_JWT_MISSING");
            string integrity = Assert.Single(request.Headers.GetValues(Fse2PublishedOrganizationProfile.IntegrityHeaderName));
            bool dualDistinctJwtObserved = !string.Equals(authorization, integrity, StringComparison.Ordinal);
            int authorizationX5cCount = AssertBoundedX5c(authorization);
            int integrityX5cCount = AssertBoundedX5c(integrity);
            string[] integrityParts = integrity.Split('.');
            Assert.Equal(3, integrityParts.Length);
            using JsonDocument integrityPayload = JsonDocument.Parse(DecodeBase64Url(integrityParts[1]));
            bool attachmentHashAbsent = !integrityPayload.RootElement.TryGetProperty("attachment_hash", out _);

            byte[] body = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            MultipartCapture multipart = await ReadMultipartCaptureAsync(
                request.Content.Headers.ContentType?.ToString(),
                body,
                OfficialTestBoundary,
                cancellationToken);
            Assert.Equal(1, multipart.FilePartCount);
            Assert.Equal(1, multipart.RequestBodyPartCount);
            bool exactPdfObserved = multipart.FileBytes.AsSpan().SequenceEqual(DocumentBytes());
            lock (observationGate)
            {
                observations.Add(new(
                    request.RequestUri!,
                    authorizationX5cCount,
                    integrityX5cCount,
                    multipart.RequestBodyBytes,
                    a1MutualTlsObserved,
                    dualDistinctJwtObserved,
                    exactPdfObserved,
                    attachmentHashAbsent));
            }
            return new ExternalResponse(200, "application/json", "{}"u8.ToArray());
        }

        private int AssertBoundedX5c(string compactToken)
        {
            string[] parts = compactToken.Split('.');
            Assert.Equal(3, parts.Length);
            using JsonDocument header = JsonDocument.Parse(DecodeBase64Url(parts[0]));
            JsonElement chain = header.RootElement.GetProperty("x5c");
            Assert.Equal(JsonValueKind.Array, chain.ValueKind);
            Assert.True(chain.GetArrayLength() is 1 or 2);
            Assert.Equal(Convert.ToBase64String(expectedSigningLeaf), chain[0].GetString());
            if (chain.GetArrayLength() == 2)
                Assert.Equal(Convert.ToBase64String(expectedRoot), chain[1].GetString());
            return chain.GetArrayLength();
        }

        private static byte[] DecodeBase64Url(string value)
        {
            string padded = value.Replace('-', '+').Replace('_', '/');
            padded += new string('=', (4 - padded.Length % 4) % 4);
            return Convert.FromBase64String(padded);
        }
    }

    private sealed class OfficialTestInMemoryTransport(
        Uri expectedUri,
        string expectedClientFingerprint,
        byte[] expectedSigningLeaf,
        byte[] excludedRoot) : IRestrictedTransport
    {
        private int requests;
        private int a1MutualTlsObserved;
        private int dualDistinctJwtObserved;
        private int s1LeafOnlyX5cObserved;
        private int exactMinisterialRequestBodyObserved;
        private int attachmentHashAbsent;

        internal int Requests => Volatile.Read(ref requests);
        internal Uri? RequestUri { get; private set; }
        internal bool A1MutualTlsObserved => Volatile.Read(ref a1MutualTlsObserved) == 1;
        internal bool DualDistinctJwtObserved => Volatile.Read(ref dualDistinctJwtObserved) == 1;
        internal bool S1LeafOnlyX5cObserved => Volatile.Read(ref s1LeafOnlyX5cObserved) == 1;
        internal bool ExactMinisterialRequestBodyObserved => Volatile.Read(ref exactMinisterialRequestBodyObserved) == 1;
        internal bool AttachmentHashAbsent => Volatile.Read(ref attachmentHashAbsent) == 1;

        public async Task<ExternalResponse> SendAsync(
            HttpRequestMessage request,
            IReadOnlyList<IPAddress> approvedAddresses,
            X509Certificate2? clientCertificate,
            TimeSpan timeout,
            long maximumResponseBytes,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal(1, Interlocked.Increment(ref requests));
            RequestUri = request.RequestUri;
            Assert.Equal(expectedUri, request.RequestUri);
            Assert.Equal([IPAddress.Loopback], approvedAddresses);
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("multipart/form-data; boundary=broker-gateway-fse2-officialtest-v1", request.Content?.Headers.ContentType?.ToString());
            Assert.Equal("application/json", Assert.Single(request.Headers.Accept).MediaType);

            if (clientCertificate is not null && string.Equals(
                Convert.ToHexString(SHA256.HashData(clientCertificate.RawData)),
                expectedClientFingerprint,
                StringComparison.Ordinal))
                Interlocked.Exchange(ref a1MutualTlsObserved, 1);

            string? authorization = request.Headers.Authorization?.Parameter;
            string integrity = Assert.Single(request.Headers.GetValues("FSE-JWT-Signature"));
            if (!string.IsNullOrWhiteSpace(authorization) &&
                !string.Equals(authorization, integrity, StringComparison.Ordinal))
                Interlocked.Exchange(ref dualDistinctJwtObserved, 1);
            if (!string.IsNullOrWhiteSpace(authorization) && !string.IsNullOrWhiteSpace(integrity))
            {
                byte[] authorizationLeaf = AssertSingleLeafX5c(authorization);
                byte[] integrityLeaf = AssertSingleLeafX5c(integrity);
                Assert.Equal(expectedSigningLeaf, authorizationLeaf);
                Assert.Equal(expectedSigningLeaf, integrityLeaf);
                Assert.False(authorizationLeaf.AsSpan().SequenceEqual(excludedRoot));
                Assert.False(integrityLeaf.AsSpan().SequenceEqual(excludedRoot));
                Interlocked.Exchange(ref s1LeafOnlyX5cObserved, 1);

                string[] integrityParts = integrity.Split('.');
                using JsonDocument payload = JsonDocument.Parse(DecodeBase64Url(integrityParts[1]));
                if (!payload.RootElement.TryGetProperty("attachment_hash", out _))
                    Interlocked.Exchange(ref attachmentHashAbsent, 1);
            }

            byte[] body = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            Assert.True(body.AsSpan().IndexOf(DocumentBytes()) >= 0);
            ReadOnlySpan<byte> expectedRequestBody = "{\"healthDataFormat\":\"CDA\",\"activity\":\"VERIFICA\"}"u8;
            Assert.True(body.AsSpan().IndexOf(expectedRequestBody) >= 0);
            Assert.True(body.AsSpan().IndexOf("\"mode\""u8) < 0);
            Assert.True(body.AsSpan().IndexOf("attachment_hash"u8) < 0);
            Interlocked.Exchange(ref exactMinisterialRequestBodyObserved, 1);
            return new ExternalResponse(200, "application/json", "{}"u8.ToArray());
        }

        private byte[] AssertSingleLeafX5c(string compactToken)
        {
            string[] parts = compactToken.Split('.');
            Assert.Equal(3, parts.Length);
            using JsonDocument header = JsonDocument.Parse(DecodeBase64Url(parts[0]));
            JsonElement chain = header.RootElement.GetProperty("x5c");
            Assert.Equal(JsonValueKind.Array, chain.ValueKind);
            string encodedLeaf = Assert.Single(chain.EnumerateArray()).GetString()!;
            Assert.Equal(Convert.ToBase64String(expectedSigningLeaf), encodedLeaf);
            return Convert.FromBase64String(encodedLeaf);
        }

        private static byte[] DecodeBase64Url(string value)
        {
            string padded = value.Replace('-', '+').Replace('_', '/');
            padded += new string('=', (4 - padded.Length % 4) % 4);
            return Convert.FromBase64String(padded);
        }
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

    private static GatewayInvokeRequest Request(string payload, Guid? correlationId = null) => new(
        "1.0",
        new("application/vnd.bgw.fse2+json", "utf8", payload),
        correlationId ?? Guid.NewGuid(),
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

    internal static byte[] InvokeRequest(string payload, Guid? correlationId = null) =>
        JsonSerializer.SerializeToUtf8Bytes(Request(payload, correlationId), WebJson);

    internal static byte[] DocumentBytes() => [0x00, 0x0d, 0x0a, 0xc3, 0xa8, 0xff, 0x42, 0x47, 0x57];

    internal static string SpkiSha256(X509Certificate2 certificate)
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

    internal static string DefinitionForOperations(
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
    private readonly string expectedAudience;
    private readonly string expectedApplicationId;
    private readonly string expectedApplicationVendor;
    private readonly string expectedApplicationVersion;
    private readonly bool expectLeafOnlyX5c;
    private readonly bool replaceReturnsWorkflowContext;
    private readonly List<Observation> observations = [];
    private readonly object observationGate = new();
    private int requests;

    private SyntheticFse2OperationMatrixServer(
        WebApplication application,
        Uri endpoint,
        string expectedClientFingerprint,
        string expectedSigningFingerprint,
        byte[] expectedRoot,
        string expectedAudience,
        string expectedApplicationId,
        string expectedApplicationVendor,
        string expectedApplicationVersion,
        bool expectLeafOnlyX5c,
        bool replaceReturnsWorkflowContext)
    {
        this.application = application;
        Endpoint = endpoint;
        this.expectedClientFingerprint = expectedClientFingerprint;
        this.expectedSigningFingerprint = expectedSigningFingerprint;
        this.expectedRoot = expectedRoot;
        this.expectedAudience = expectedAudience;
        this.expectedApplicationId = expectedApplicationId;
        this.expectedApplicationVendor = expectedApplicationVendor;
        this.expectedApplicationVersion = expectedApplicationVersion;
        this.expectLeafOnlyX5c = expectLeafOnlyX5c;
        this.replaceReturnsWorkflowContext = replaceReturnsWorkflowContext;
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
        CancellationToken cancellationToken,
        string expectedAudience = Fse2OrganizationHostedIntegrationTests.Audience,
        string expectedApplicationId = "broker-gateway",
        string expectedApplicationVendor = "Secure Integration",
        string expectedApplicationVersion = "1.0.0",
        bool expectLeafOnlyX5c = false,
        bool replaceReturnsWorkflowContext = false)
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
            trustedRootCertificate.RawData.ToArray(),
            expectedAudience,
            expectedApplicationId,
            expectedApplicationVendor,
            expectedApplicationVersion,
            expectLeafOnlyX5c,
            replaceReturnsWorkflowContext);
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
        ReadOnlySpan<byte> expectedRequestBody = operation.Operation == Fse2Operation.ValidateCda
            ? expectLeafOnlyX5c
                ? "{\"healthDataFormat\":\"CDA\",\"activity\":\"VERIFICA\"}"u8
                : "{\"healthDataFormat\":\"CDA\",\"activity\":\"VERIFICA\",\"mode\":\"ATTACHMENT\"}"u8
            : "{\"metadata\":\"published-exact\"}"u8;
        bool exactDocumentAndJson = body.AsSpan().IndexOf(Fse2OrganizationHostedIntegrationTests.DocumentBytes()) >= 0 &&
            body.AsSpan().IndexOf(expectedRequestBody) >= 0;
        bool hasHttpContent = context.Request.ContentLength.HasValue ||
            context.Request.Headers.ContainsKey("Content-Type") ||
            context.Request.Headers.ContainsKey("Transfer-Encoding");
        bool exactApplicationJsonAccept = context.Request.Headers.Accept.Count == 1 &&
            string.Equals(context.Request.Headers.Accept.ToString(), "application/json", StringComparison.Ordinal);
        lock (observationGate)
        {
            observations.Add(new(
                operation.Operation,
                context.Request.Method,
                rawTarget,
                context.Request.ContentType,
                body,
                hasHttpContent,
                exactApplicationJsonAccept,
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
        string response = operation.Operation == Fse2Operation.Create ||
            replaceReturnsWorkflowContext && operation.Operation == Fse2Operation.Replace
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
                chain.ValueKind != JsonValueKind.Array ||
                chain.GetArrayLength() != (expectLeafOnlyX5c ? 1 : 2) ||
                (!expectLeafOnlyX5c && !CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(chain[1].GetString()!), expectedRoot)))
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
                !string.Equals(payload.RootElement.GetProperty("aud").GetString(), expectedAudience, StringComparison.Ordinal) ||
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

    private bool IntegrityClaimsAreExact(JsonElement payload, Fse2OperationDescriptor operation)
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
            string.Equals(payload.GetProperty("subject_application_id").GetString(), expectedApplicationId, StringComparison.Ordinal) &&
            string.Equals(payload.GetProperty("subject_application_vendor").GetString(), expectedApplicationVendor, StringComparison.Ordinal) &&
            string.Equals(payload.GetProperty("subject_application_version").GetString(), expectedApplicationVersion, StringComparison.Ordinal);
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
        bool ExactApplicationJsonAcceptObserved,
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
    private readonly int responseStatusCode;
    private readonly string responseContentType;
    private readonly string responseBody;
    private readonly string? responseLocation;
    private int requests;
    private int expectedClientCertificateObserved;
    private int expectedMethodPathAndContentTypeObserved;
    private int exactApplicationJsonAcceptObserved;
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
        byte[] expectedRoot,
        int responseStatusCode,
        string responseContentType,
        string responseBody,
        string? responseLocation)
    {
        this.application = application;
        Endpoint = endpoint;
        this.expectedClientFingerprint = expectedClientFingerprint;
        this.expectedSigningFingerprint = expectedSigningFingerprint;
        this.expectedRoot = expectedRoot;
        this.responseStatusCode = responseStatusCode;
        this.responseContentType = responseContentType;
        this.responseBody = responseBody;
        this.responseLocation = responseLocation;
    }

    internal Uri Endpoint { get; }
    internal int Requests => Volatile.Read(ref requests);
    internal bool ExpectedClientCertificateObserved => Volatile.Read(ref expectedClientCertificateObserved) == 1;
    internal bool ExpectedMethodPathAndContentTypeObserved => Volatile.Read(ref expectedMethodPathAndContentTypeObserved) == 1;
    internal bool ExactApplicationJsonAcceptObserved => Volatile.Read(ref exactApplicationJsonAcceptObserved) == 1;
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
        CancellationToken cancellationToken,
        int responseStatusCode = StatusCodes.Status202Accepted,
        string responseContentType = "application/json",
        string responseBody = "{\"workflowInstanceId\":\"workflow-fse2-1\",\"traceID\":\"trace-fse2-1\",\"spanID\":\"span-fse2-1\"}",
        string? responseLocation = null)
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
            trustedRootCertificate.RawData.ToArray(),
            responseStatusCode,
            responseContentType,
            responseBody,
            responseLocation);
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
        if (context.Request.Headers.Accept.Count == 1 &&
            string.Equals(context.Request.Headers.Accept.ToString(), "application/json", StringComparison.Ordinal))
            Interlocked.Exchange(ref exactApplicationJsonAcceptObserved, 1);

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

        context.Response.StatusCode = responseStatusCode;
        context.Response.ContentType = responseContentType;
        if (responseLocation is not null) context.Response.Headers.Location = responseLocation;
        await context.Response.WriteAsync(responseBody, context.RequestAborted);
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

internal enum SyntheticFse2RawResponseBehavior
{
    HeadersOnlyOversizedContentLength,
    StreamingBodyOverRetainedLimit,
    HeadersThenWait,
    ResetDuringBody,
    ResetBeforeResponseHeaders
}

internal sealed class SyntheticFse2RawResponseServer : IAsyncDisposable
{
    private static readonly byte[] HeaderTerminator = "\r\n\r\n"u8.ToArray();
    private readonly TcpListener listener;
    private readonly CancellationTokenSource shutdown;
    private readonly Task serverTask;
    private readonly TaskCompletionSource requestRead = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource headersSent = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource peerClosed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int bodyBytesSent;
    private int clientCertificateObserved;
    private int drainCompleted;
    private int listenerStopped;
    private int shutdownCancellationRequested;
    private int requests;

    private SyntheticFse2RawResponseServer(
        TcpListener listener,
        X509Certificate2 serverCertificate,
        X509Certificate2 expectedClientCertificate,
        X509Certificate2 trustedRootCertificate,
        SyntheticFse2RawResponseBehavior behavior,
        CancellationToken cancellationToken)
    {
        this.listener = listener;
        shutdown = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Endpoint = new Uri($"https://localhost:{port}/", UriKind.Absolute);
        serverTask = ServeAsync(
            serverCertificate,
            expectedClientCertificate,
            trustedRootCertificate,
            behavior,
            shutdown.Token);
    }

    internal Uri Endpoint { get; }
    internal int BodyBytesSent => Volatile.Read(ref bodyBytesSent);
    internal bool ClientCertificateObserved => Volatile.Read(ref clientCertificateObserved) != 0;
    internal bool DrainCompleted => Volatile.Read(ref drainCompleted) != 0;
    internal int Requests => Volatile.Read(ref requests);
    internal bool HeadersSent => headersSent.Task.IsCompletedSuccessfully;
    internal bool ListenerStopped => Volatile.Read(ref listenerStopped) != 0;
    internal bool PeerClosed => peerClosed.Task.IsCompletedSuccessfully;
    internal bool ServerTaskCompleted => serverTask.IsCompletedSuccessfully;
    internal bool ShutdownCancellationRequested => Volatile.Read(ref shutdownCancellationRequested) != 0;

    internal static Task<SyntheticFse2RawResponseServer> StartAsync(
        X509Certificate2 serverCertificate,
        X509Certificate2 expectedClientCertificate,
        X509Certificate2 trustedRootCertificate,
        SyntheticFse2RawResponseBehavior behavior,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        return Task.FromResult(new SyntheticFse2RawResponseServer(
            listener,
            serverCertificate,
            expectedClientCertificate,
            trustedRootCertificate,
            behavior,
            cancellationToken));
    }

    internal Task WaitForHeadersAsync(CancellationToken cancellationToken) =>
        headersSent.Task.WaitAsync(cancellationToken);

    internal Task WaitForRequestAsync(CancellationToken cancellationToken) =>
        requestRead.Task.WaitAsync(cancellationToken);

    internal Task WaitForPeerCloseAsync(CancellationToken cancellationToken) =>
        peerClosed.Task.WaitAsync(cancellationToken);

    internal Task WaitForServerCompletionAsync(CancellationToken cancellationToken) =>
        serverTask.WaitAsync(cancellationToken);

    private async Task ServeAsync(
        X509Certificate2 serverCertificate,
        X509Certificate2 expectedClientCertificate,
        X509Certificate2 trustedRootCertificate,
        SyntheticFse2RawResponseBehavior behavior,
        CancellationToken cancellationToken)
    {
        try
        {
            using TcpClient client = await listener.AcceptTcpClientAsync(cancellationToken);
            using SslStream tls = new(client.GetStream(), leaveInnerStreamOpen: false);
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = serverCertificate,
                ClientCertificateRequired = true,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                {
                    bool accepted = ValidateClientCertificate(
                        certificate,
                        expectedClientCertificate,
                        trustedRootCertificate);
                    if (accepted) Interlocked.Exchange(ref clientCertificateObserved, 1);
                    return accepted;
                }
            }, cancellationToken);
            await ReadRequestHeadersAsync(tls, cancellationToken);
            Interlocked.Increment(ref requests);
            requestRead.TrySetResult();

            if (behavior == SyntheticFse2RawResponseBehavior.ResetBeforeResponseHeaders)
            {
                client.Client.LingerState = new LingerOption(enable: true, seconds: 0);
                client.Client.Dispose();
                return;
            }

            string responseHeaders = behavior switch
            {
                SyntheticFse2RawResponseBehavior.HeadersOnlyOversizedContentLength =>
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/problem+json\r\nContent-Length: 32768\r\nConnection: close\r\n\r\n",
                SyntheticFse2RawResponseBehavior.StreamingBodyOverRetainedLimit =>
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/problem+json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                SyntheticFse2RawResponseBehavior.HeadersThenWait =>
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/problem+json\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n",
                SyntheticFse2RawResponseBehavior.ResetDuringBody =>
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/problem+json\r\nContent-Length: 256\r\nConnection: close\r\n\r\n{\"type\":\"https://fse.example/msg/syntax\",",
                _ => throw new InvalidOperationException("Unknown synthetic response behavior.")
            };
            await tls.WriteAsync(Encoding.ASCII.GetBytes(responseHeaders), cancellationToken);
            await tls.FlushAsync(cancellationToken);
            headersSent.TrySetResult();

            if (behavior == SyntheticFse2RawResponseBehavior.ResetDuringBody)
            {
                client.Client.LingerState = new LingerOption(enable: true, seconds: 0);
                return;
            }
            if (behavior == SyntheticFse2RawResponseBehavior.StreamingBodyOverRetainedLimit)
            {
                byte[] retainedLimit = new byte[16 * 1024];
                Array.Fill(retainedLimit, (byte)'x');
                await WriteChunkAsync(tls, retainedLimit, cancellationToken);
                Interlocked.Add(ref bodyBytesSent, retainedLimit.Length);
                await WriteChunkAsync(tls, "x"u8.ToArray(), cancellationToken);
                Interlocked.Increment(ref bodyBytesSent);
                await tls.FlushAsync(cancellationToken);
                await ObservePeerCloseAsync(tls, cancellationToken);
                peerClosed.TrySetResult();
                return;
            }
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            requestRead.TrySetCanceled(cancellationToken);
            headersSent.TrySetCanceled(cancellationToken);
            peerClosed.TrySetCanceled(cancellationToken);
        }
        catch (Exception exception)
        {
            requestRead.TrySetException(exception);
            headersSent.TrySetException(exception);
            peerClosed.TrySetException(exception);
            throw;
        }
    }

    private static async Task WriteChunkAsync(Stream stream, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
    {
        await stream.WriteAsync(Encoding.ASCII.GetBytes($"{body.Length:X}\r\n"), cancellationToken);
        await stream.WriteAsync(body, cancellationToken);
        await stream.WriteAsync("\r\n"u8.ToArray(), cancellationToken);
    }

    private static async Task ObservePeerCloseAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] probe = new byte[1];
        try
        {
            while (await stream.ReadAsync(probe, cancellationToken) != 0) { }
        }
        catch (IOException) { }
    }

    private static async Task ReadRequestHeadersAsync(Stream stream, CancellationToken cancellationToken)
    {
        using MemoryStream buffer = new();
        byte[] chunk = new byte[1024];
        while (buffer.Length < 16 * 1024)
        {
            int read = await stream.ReadAsync(chunk, cancellationToken);
            if (read == 0) throw new IOException("Synthetic request ended before headers.");
            buffer.Write(chunk, 0, read);
            if (buffer.GetBuffer().AsSpan(0, checked((int)buffer.Length)).IndexOf(HeaderTerminator) >= 0) return;
        }
        throw new IOException("Synthetic request headers exceeded the test bound.");
    }

    private static bool ValidateClientCertificate(
        X509Certificate? certificate,
        X509Certificate2 expectedClientCertificate,
        X509Certificate2 trustedRootCertificate)
    {
        if (certificate is null) return false;
        if (certificate is X509Certificate2 certificate2)
            return SyntheticSignedMutualTlsServer.ValidateClientCertificate(
                certificate2,
                expectedClientCertificate,
                trustedRootCertificate);
        using X509Certificate2 copy = new(certificate);
        return SyntheticSignedMutualTlsServer.ValidateClientCertificate(
            copy,
            expectedClientCertificate,
            trustedRootCertificate);
    }

    public async ValueTask DisposeAsync()
    {
        Interlocked.Exchange(ref shutdownCancellationRequested, 1);
        shutdown.Cancel();
        listener.Stop();
        Interlocked.Exchange(ref listenerStopped, 1);
        try { await serverTask.ConfigureAwait(false); }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        Interlocked.Exchange(ref drainCompleted, 1);
        shutdown.Dispose();
    }
}

internal sealed class SyntheticTlsAbortServer : IAsyncDisposable
{
    private readonly TcpListener listener;
    private readonly CancellationTokenSource shutdown;
    private readonly Task serverTask;
    private int connections;

    private SyntheticTlsAbortServer(TcpListener listener, CancellationToken cancellationToken)
    {
        this.listener = listener;
        shutdown = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Endpoint = new Uri($"https://localhost:{port}/", UriKind.Absolute);
        serverTask = ServeAsync(shutdown.Token);
    }

    internal Uri Endpoint { get; }
    internal int Connections => Volatile.Read(ref connections);

    internal static Task<SyntheticTlsAbortServer> StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        return Task.FromResult(new SyntheticTlsAbortServer(listener, cancellationToken));
    }

    private async Task ServeAsync(CancellationToken cancellationToken)
    {
        try
        {
            using TcpClient client = await listener.AcceptTcpClientAsync(cancellationToken);
            Interlocked.Increment(ref connections);
            client.Client.LingerState = new LingerOption(enable: true, seconds: 0);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    }

    public async ValueTask DisposeAsync()
    {
        shutdown.Cancel();
        listener.Stop();
        try { await serverTask.ConfigureAwait(false); }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        shutdown.Dispose();
    }
}

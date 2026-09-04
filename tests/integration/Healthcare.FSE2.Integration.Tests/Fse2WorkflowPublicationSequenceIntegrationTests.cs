using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Integration.Tests;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Integration.Tests;

public sealed partial class Fse2DurableWorkflowCorrelationIntegrationTests
{
    [Theory]
    [InlineData(Fse2Operation.Create, null)]
    [InlineData(Fse2Operation.Replace, null)]
    [InlineData(Fse2Operation.CreateFhir, null)]
    [InlineData(Fse2Operation.ReplaceFhir, null)]
    [InlineData(Fse2Operation.Create, "storage-denied")]
    [InlineData(Fse2Operation.Create, "workflow-mismatch")]
    public async Task FSE2_DUR_E2E_PostgreSQL18_VALIDATION_publication_same_workflow_both_traces_second_instance(
        Fse2Operation publicationOperation, string? failure)
    {
        string adminConnection = RequiredConnection("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        string migrationConnection = RequiredConnection("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        await HostedPostgresTestSupport.ApplyMigrationAsync();
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole =
            await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(
                adminConnection, migrationConnection, TestContext.Current.CancellationToken);
        using SyntheticAuthenticationMaterial material =
            SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Fse2OrganizationHostedIntegrationTests.Provider(material));
        await using SyntheticFse2OperationMatrixServer server = await SyntheticFse2OperationMatrixServer.StartAsync(
            material.ServerCertificate, material.ClientCertificateRevision1, material.SigningKeyRevision1,
            material.RootCertificate, TestContext.Current.CancellationToken,
            expectedApplicationId: Fse2OfficialTestCanonicalDefinition.ApplicationId,
            expectedApplicationVendor: Fse2OfficialTestCanonicalDefinition.ApplicationVendor,
            expectedApplicationVersion: Fse2OfficialTestCanonicalDefinition.ApplicationVersion);
        server.UsesCurrentSpec = true;
        server.ValidationPublicationSequence = true;
        string connectorId = "fse2-sequence-" + Guid.NewGuid().ToString("N");
        Fse2OperationDescriptor publication = Fse2OperationCatalog.Get(publicationOperation);
        Fse2OperationDescriptor validation = Fse2OperationCatalog.Get(Fse2Operation.ValidateCda);
        Guid tenant = default;
        Guid installation = default;
        HostedIdentity? savedIdentity = null;
        string workflow = string.Empty;
        string tv = string.Empty;
        string tp = string.Empty;
        bool storageDenied = false;
        try
        {
            await using (HostedTypedSessionFixture first = await HostedTypedSessionFixture.CreateAsync(
                "unused-fse2-sequence-first", runtimeConnection: runtimeRole.ConnectionString,
                adminConnection: adminConnection, executionModule: Fse2OrganizationHostedIntegrationTests.Module(),
                capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate)))
            {
                Guid environment = await first.CreateEnvironmentAsync();
                tenant = await first.CreateTenantAsync("fse2-sequence-tenant");
                Guid application = await first.CreateApplicationAsync("fse2-sequence-application");
                Fse2OfficialTestOperationalPlan plan = new(
                    tenant, Guid.NewGuid(), environment, new(server.Endpoint, "gateway/v1/"),
                    new("12345678903", "2.16.840.1.113883.2.9.4.1.2", "ASL Roma 1", "asl-roma-1"),
                    new("ASL Roma 1", "2.16.840.1.113883.2.9.4.1.2", "ASLROMA1"),
                    new("synthetic-capability", "a1", "1", 1, 1), new("synthetic-capability", "s1", "1", 1, 1), null)
                    { UsesCurrentSpec = true, EnvironmentClass = Fse2EnvironmentClass.Synthetic, Activity = "VALIDATION" };
                Fse2OfficialTestCompiledConfiguration compiled = Fse2OfficialTestOperationalization.Compile(plan,
                    new(plan.A1, Fse2OrganizationHostedIntegrationTests.SpkiSha256(material.ClientCertificateRevision1), "Synthetic A1", new string('C', 64)),
                    new(plan.S1, Fse2OrganizationHostedIntegrationTests.SpkiSha256(material.SigningKeyRevision1),
                        material.SigningKeyRevision1.GetNameInfo(X509NameType.SimpleName, false), new string('D', 64)));
                // Only the registry ID varies to isolate cases in the shared PostgreSQL fixture.
                JsonObject definition = JsonNode.Parse(compiled.CanonicalDefinition)!.AsObject();
                definition["connectorId"] = connectorId;
                HostedCapabilityAuthority authority = await first.PrepareCapabilityConnectorVersionAsync(
                    connectorId, "1.0.0", environment, new(server.Endpoint, "gateway/v1/"), definition.ToJsonString(),
                    provider, "sign-r1", "mtls-r1", operationId: "*", expectedOperationCount: 14,
                    endpointBinding: Fse2OfficialTestCanonicalDefinition.EndpointBinding,
                    signingCertificateBinding: Fse2OfficialTestCanonicalDefinition.SigningBinding,
                    clientCertificateBinding: Fse2OfficialTestCanonicalDefinition.MutualTlsBinding);
                await first.PublishAsync(authority, expectedPublicationRevision: 0);
                HostedIdentity identity = await first.EnrollIdentityAsync(tenant, application, environment, "fse2-sequence-identity");
                installation = identity.Identity.InstallationId;
                foreach (string operation in new[] { "validate-cda", publication.OperationId, "get-status-by-workflow", "get-status-by-trace" })
                    await first.AddOperationGrantAsync(identity, connectorId, operation);

                Guid validationCorrelation = Guid.NewGuid();
                using (HttpResponseMessage response = await first.SendSignedAsync(identity, HttpMethod.Post,
                    $"/v1/connectors/{connectorId}/operations/validate-cda:invoke",
                    Fse2OrganizationHostedIntegrationTests.InvokeRequest(
                        Fse2OrganizationHostedIntegrationTests.PayloadFor(validation,
                            Fse2OrganizationHostedIntegrationTests.CurrentSpecBody(validation.Operation).Replace("VERIFICA", "VALIDATION", StringComparison.Ordinal)),
                        validationCorrelation)))
                {
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                    string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
                    using JsonDocument normalized = ReadNormalizedResult(body);
                    Assert.Equal(201, normalized.RootElement.GetProperty("statusCode").GetInt32());
                    workflow = ReadWorkflowIdentifier(body);
                    tv = ReadTraceIdentifier(body);
                }
                await AssertAuditOutcomeAsync(first, tenant, validationCorrelation, expectedFailure: 0, expectedSuccess: 1);

                using JsonDocument request = JsonDocument.Parse(Fse2OrganizationHostedIntegrationTests.CurrentSpecBody(publicationOperation));
                string priorWorkflow = request.RootElement.GetProperty("workflowInstanceId").GetString()!;
                string publicationBody = Fse2OrganizationHostedIntegrationTests.CurrentSpecBody(publicationOperation)
                    .Replace(priorWorkflow, workflow, StringComparison.Ordinal);
                string publicationPayload = Fse2OrganizationHostedIntegrationTests.PayloadFor(publication, publicationBody);
                Guid spoofCorrelation = Guid.NewGuid();
                using (HttpResponseMessage spoof = await first.SendSignedAsync(identity, HttpMethod.Post,
                    $"/v1/connectors/{connectorId}/operations/{publication.OperationId}:invoke",
                    Fse2OrganizationHostedIntegrationTests.InvokeRequest(publicationPayload.Insert(1,
                        "\"permittedPredecessor\":\"validate-cda\","), spoofCorrelation)))
                    Assert.False(spoof.IsSuccessStatusCode);
                await AssertAuditOutcomeAsync(first, tenant, spoofCorrelation, expectedFailure: 1, expectedSuccess: 0);
                Assert.Equal(1, server.Requests);
                Assert.Equal(2, provider.SignDigestCalls);

                if (failure == "storage-denied")
                {
                    await SetStorageInsertAsync(false);
                    storageDenied = true;
                }
                if (failure == "workflow-mismatch") server.PublicationSequenceWorkflow = "unexpected-workflow";
                Guid publicationCorrelation = Guid.NewGuid();
                using (HttpResponseMessage response = await first.SendSignedAsync(identity, HttpMethod.Post,
                    $"/v1/connectors/{connectorId}/operations/{publication.OperationId}:invoke",
                    Fse2OrganizationHostedIntegrationTests.InvokeRequest(publicationPayload, publicationCorrelation)))
                {
                    string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
                    if (failure is not null)
                    {
                        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
                        Assert.DoesNotContain("connector_workflow_context", body, StringComparison.Ordinal);
                        Assert.DoesNotContain("unexpected-workflow", body, StringComparison.Ordinal);
                        await AssertAuditOutcomeAsync(first, tenant, publicationCorrelation, expectedFailure: 1, expectedSuccess: 0);
                        Assert.Equal(2, server.Requests);
                        Assert.Single(server.Observations, value => value.Operation == publicationOperation);
                        Assert.Equal(1L, await CountContextsAsync(migrationConnection, tenant, installation, connectorId));
                        Assert.Equal(tv, (await ReadContextAsync(migrationConnection, tenant, installation, connectorId, "validate-cda")).TraceId);
                        return;
                    }
                    Assert.True(response.IsSuccessStatusCode, body);
                    using JsonDocument normalized = ReadNormalizedResult(body);
                    Assert.Equal(202, normalized.RootElement.GetProperty("statusCode").GetInt32());
                    Assert.Equal(workflow, ReadWorkflowIdentifier(body));
                    tp = ReadTraceIdentifier(body);
                    Assert.NotEqual(tv, tp);
                }
                await AssertAuditOutcomeAsync(first, tenant, publicationCorrelation, expectedFailure: 0, expectedSuccess: 1);
                Assert.Equal(2, server.Requests); // No publication replay for registration idempotency.
                Assert.Equal(2L, await CountContextsAsync(migrationConnection, tenant, installation, connectorId));
                ContextRow origin = await ReadContextAsync(migrationConnection, tenant, installation, connectorId, "validate-cda");
                ContextRow successor = await ReadContextAsync(migrationConnection, tenant, installation, connectorId, publication.OperationId);
                Assert.Equal(workflow, origin.WorkflowInstanceId);
                Assert.Equal(workflow, successor.WorkflowInstanceId);
                Assert.Equal(tv, origin.TraceId);
                Assert.Equal(tp, successor.TraceId);
                Assert.NotEqual(origin.OperationProfileChecksumSha256, successor.OperationProfileChecksumSha256);
                byte[] exported = identity.Certificate.Export(X509ContentType.Pkcs12);
                try
                {
                    savedIdentity = new(X509CertificateLoader.LoadPkcs12(exported, null,
                        X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable), identity.Identity);
                }
                finally { CryptographicOperations.ZeroMemory(exported); }
            }

            await using HostedTypedSessionFixture second = await HostedTypedSessionFixture.CreateAsync(
                "unused-fse2-sequence-second", runtimeConnection: runtimeRole.ConnectionString,
                adminConnection: adminConnection, executionModule: Fse2OrganizationHostedIntegrationTests.Module(),
                capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));
            foreach ((Fse2Operation lookup, string id, Fse2Operation origin) in new[]
            {
                (Fse2Operation.GetStatusByWorkflow, workflow, publicationOperation),
                (Fse2Operation.GetStatusByTrace, tv, Fse2Operation.ValidateCda),
                (Fse2Operation.GetStatusByTrace, tp, publicationOperation)
            })
            {
                server.ExpectedStatusOrigin = origin;
                await AssertStatusSuccessAsync(second, Assert.IsType<HostedIdentity>(savedIdentity), tenant,
                    connectorId, Fse2OperationCatalog.Get(lookup), id);
                Assert.True(server.Observations[^1].ExactClaimsObserved);
            }
            Assert.Equal(5, server.Requests);
            Assert.Single(server.Observations, value => value.Operation == publicationOperation);
            Assert.All(server.Observations, value =>
            {
                Assert.True(value.ClientCertificateObserved);
                Assert.True(value.DualDistinctTokensObserved);
                Assert.True(value.ExactJwtPolicyObserved);
                Assert.True(value.ExactClaimsObserved);
            });
            Assert.Equal(2L, await CountContextsAsync(migrationConnection, tenant, installation, connectorId));
        }
        finally
        {
            if (storageDenied) await SetStorageInsertAsync(true);
            savedIdentity?.Dispose();
        }

        async Task SetStorageInsertAsync(bool enabled)
        {
            // The existing collection serializes this task-owned PostgreSQL fixture. Restore in finally.
            await using NpgsqlConnection owner = new(migrationConnection);
            await owner.OpenAsync(CancellationToken.None);
            await using NpgsqlCommand command = new(enabled
                ? "GRANT INSERT ON gateway.connector_workflow_context TO gateway_runtime"
                : "REVOKE INSERT ON gateway.connector_workflow_context FROM gateway_runtime", owner);
            await command.ExecuteNonQueryAsync(CancellationToken.None);
        }
    }
}

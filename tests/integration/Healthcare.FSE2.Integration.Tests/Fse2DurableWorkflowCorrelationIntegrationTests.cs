using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Npgsql;
using SecureIntegration.Gateway.Integration.Tests;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Integration.Tests;

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class Fse2DurableWorkflowCorrelationIntegrationTests
{
    [Fact]
    public async Task FSE2_DUR_E2E_PostgreSQL18_create_is_idempotent_and_status_survives_restart_and_replica()
    {
        string adminConnection = RequiredConnection("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        string migrationConnection = RequiredConnection("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        await HostedPostgresTestSupport.ApplyMigrationAsync();
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole =
            await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(
                adminConnection,
                migrationConnection,
                TestContext.Current.CancellationToken);
        using SyntheticAuthenticationMaterial material =
            SyntheticAuthenticationMaterial.CreateContentCommitmentSigning(DateTimeOffset.UtcNow);
        TrackingCapabilityProvider provider = new(Fse2OrganizationHostedIntegrationTests.Provider(material));
        await using SyntheticFse2OperationMatrixServer server =
            await SyntheticFse2OperationMatrixServer.StartAsync(
                material.ServerCertificate,
                material.ClientCertificateRevision1,
                material.SigningKeyRevision1,
                material.RootCertificate,
                TestContext.Current.CancellationToken,
                replaceReturnsWorkflowContext: true);

        Fse2OperationDescriptor create = Fse2OperationCatalog.Get(Fse2Operation.Create);
        Fse2OperationDescriptor replace = Fse2OperationCatalog.Get(Fse2Operation.Replace);
        Fse2OperationDescriptor status = Fse2OperationCatalog.Get(Fse2Operation.GetStatusByWorkflow);
        string connectorId = "fse2-durable-" + Guid.NewGuid().ToString("N");
        HostedIdentity? durableIdentity = null;
        Guid tenantId = default;
        Guid installationId = default;

        try
        {
            await using (HostedTypedSessionFixture first = await HostedTypedSessionFixture.CreateAsync(
                "unused-fse2-durable-first",
                runtimeConnection: runtimeRole.ConnectionString,
                adminConnection: adminConnection,
                executionModule: Fse2OrganizationHostedIntegrationTests.Module(),
                capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate)))
            {
                Assert.True(first.UsesPostgreSql);
                Guid environmentId = await first.CreateEnvironmentAsync();
                tenantId = await first.CreateTenantAsync("fse2-durable-tenant-a");
                Guid applicationId = await first.CreateApplicationAsync("fse2-durable-application-a");
                HostedCapabilityAuthority authority = await first.PrepareCapabilityConnectorVersionAsync(
                    connectorId,
                    "1.0.0",
                    environmentId,
                    server.Endpoint,
                    Fse2OrganizationHostedIntegrationTests.DefinitionForOperations(
                        connectorId,
                        "1.0.0",
                        Fse2OrganizationHostedIntegrationTests.SpkiSha256(material.SigningKeyRevision1),
                        Fse2OrganizationHostedIntegrationTests.SpkiSha256(material.ClientCertificateRevision1),
                        "1.0.0",
                        [create, replace, status]),
                    provider,
                    "sign-r1",
                    "mtls-r1",
                    operationId: "*",
                    expectedOperationCount: 3);
                await first.PublishAsync(authority, expectedPublicationRevision: 0);
                HostedIdentity identity = await first.EnrollIdentityAsync(
                    tenantId,
                    applicationId,
                    environmentId,
                    "fse2-durable-identity-a");
                installationId = identity.Identity.InstallationId;
                await first.AddOperationGrantAsync(identity, connectorId, create.OperationId);
                await first.AddOperationGrantAsync(identity, connectorId, replace.OperationId);
                await first.AddOperationGrantAsync(identity, connectorId, status.OperationId);

                await AssertUnknownOrCrossScopeDeniedBeforeOutboundAsync(
                    first,
                    identity,
                    provider,
                    server,
                    connectorId,
                    status);

                for (int attempt = 0; attempt < 2; attempt++)
                {
                    using HttpResponseMessage response = await first.SendSignedAsync(
                        identity,
                        HttpMethod.Post,
                        $"/v1/connectors/{connectorId}/operations/{create.OperationId}:invoke",
                        Fse2OrganizationHostedIntegrationTests.InvokeRequest(
                            Fse2OrganizationHostedIntegrationTests.PayloadFor(create)));
                    string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
                    Assert.True(response.IsSuccessStatusCode, body);
                }

                Assert.Equal(1L, await CountContextsAsync(
                    migrationConnection,
                    tenantId,
                    installationId,
                    connectorId));
                using (HttpResponseMessage conflict = await first.SendSignedAsync(
                    identity,
                    HttpMethod.Post,
                    $"/v1/connectors/{connectorId}/operations/{replace.OperationId}:invoke",
                    Fse2OrganizationHostedIntegrationTests.InvokeRequest(
                        Fse2OrganizationHostedIntegrationTests.PayloadFor(replace))))
                {
                    string body = await conflict.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
                    Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
                    Assert.Contains("BGW-CONNECTOR-WORKFLOW-CONTEXT-CONFLICT", body, StringComparison.Ordinal);
                }
                Assert.Equal("create", await ReadOriginatingOperationAsync(
                    migrationConnection,
                    tenantId,
                    installationId,
                    connectorId));

                Guid tenantB = await first.CreateTenantAsync("fse2-durable-tenant-b");
                Guid applicationB = await first.CreateApplicationAsync("fse2-durable-application-b");
                HostedIdentity[] crossScopeIdentities =
                [
                    await first.EnrollIdentityAsync(tenantB, applicationId, environmentId, "fse2-durable-cross-tenant"),
                    await first.EnrollIdentityAsync(tenantId, applicationB, environmentId, "fse2-durable-cross-application"),
                    await first.EnrollIdentityAsync(tenantId, applicationId, environmentId, "fse2-durable-cross-installation")
                ];
                foreach (HostedIdentity crossScope in crossScopeIdentities)
                {
                    await first.AddOperationGrantAsync(crossScope, connectorId, status.OperationId);
                    await AssertUnknownOrCrossScopeDeniedBeforeOutboundAsync(
                        first,
                        crossScope,
                        provider,
                        server,
                        connectorId,
                        status);
                }

                byte[] exported = identity.Certificate.Export(X509ContentType.Pkcs12);
                try
                {
                    X509Certificate2 certificate = X509CertificateLoader.LoadPkcs12(
                        exported,
                        null,
                        X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
                    durableIdentity = new(certificate, identity.Identity);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(exported);
                }
            }

            HostedIdentity restartedIdentity = Assert.IsType<HostedIdentity>(durableIdentity);
            await using HostedTypedSessionFixture restarted = await HostedTypedSessionFixture.CreateAsync(
                "unused-fse2-durable-restarted",
                runtimeConnection: runtimeRole.ConnectionString,
                adminConnection: adminConnection,
                executionModule: Fse2OrganizationHostedIntegrationTests.Module(),
                capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));
            await AssertStatusSuccessAsync(restarted, restartedIdentity, connectorId, status);

            await using HostedTypedSessionFixture replica = await HostedTypedSessionFixture.CreateAsync(
                "unused-fse2-durable-replica",
                runtimeConnection: runtimeRole.ConnectionString,
                adminConnection: adminConnection,
                executionModule: Fse2OrganizationHostedIntegrationTests.Module(),
                capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));
            await AssertStatusSuccessAsync(replica, restartedIdentity, connectorId, status);

            Assert.Equal(1L, await CountContextsAsync(
                migrationConnection,
                tenantId,
                installationId,
                connectorId));
        }
        finally
        {
            durableIdentity?.Dispose();
        }
    }

    private static async Task AssertUnknownOrCrossScopeDeniedBeforeOutboundAsync(
        HostedTypedSessionFixture fixture,
        HostedIdentity identity,
        TrackingCapabilityProvider provider,
        SyntheticFse2OperationMatrixServer server,
        string connectorId,
        Fse2OperationDescriptor status)
    {
        int signingBefore = provider.SignDigestCalls;
        int dnsBefore = fixture.HostResolutionCount;
        int serverBefore = server.Requests;
        int transportBefore = fixture.GenericTransportRequests;
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{status.OperationId}:invoke",
            Fse2OrganizationHostedIntegrationTests.InvokeRequest(
                Fse2OrganizationHostedIntegrationTests.PayloadFor(status)));
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Contains("BGW-CONNECTOR-WORKFLOW-CONTEXT-NOT-FOUND", body, StringComparison.Ordinal);
        Assert.Equal(signingBefore, provider.SignDigestCalls);
        Assert.Equal(dnsBefore, fixture.HostResolutionCount);
        Assert.Equal(serverBefore, server.Requests);
        Assert.Equal(transportBefore, fixture.GenericTransportRequests);
    }

    private static async Task AssertStatusSuccessAsync(
        HostedTypedSessionFixture fixture,
        HostedIdentity identity,
        string connectorId,
        Fse2OperationDescriptor status)
    {
        Assert.True(fixture.UsesPostgreSql);
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{status.OperationId}:invoke",
            Fse2OrganizationHostedIntegrationTests.InvokeRequest(
                Fse2OrganizationHostedIntegrationTests.PayloadFor(status)));
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, body);
    }

    private static async Task<long> CountContextsAsync(
        string migrationConnection,
        Guid tenantId,
        Guid installationId,
        string connectorId)
    {
        await using NpgsqlConnection connection = new(migrationConnection);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using NpgsqlCommand command = new("""
            SELECT count(*)
              FROM gateway.connector_workflow_context
             WHERE tenant_id=$1 AND installation_id=$2 AND connector_id=$3
            """, connection);
        command.Parameters.AddWithValue(tenantId);
        command.Parameters.AddWithValue(installationId);
        command.Parameters.AddWithValue(connectorId);
        return Assert.IsType<long>(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken));
    }

    private static async Task<string> ReadOriginatingOperationAsync(
        string migrationConnection,
        Guid tenantId,
        Guid installationId,
        string connectorId)
    {
        await using NpgsqlConnection connection = new(migrationConnection);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using NpgsqlCommand command = new("""
            SELECT originating_operation_id
              FROM gateway.connector_workflow_context
             WHERE tenant_id=$1 AND installation_id=$2 AND connector_id=$3
            """, connection);
        command.Parameters.AddWithValue(tenantId);
        command.Parameters.AddWithValue(installationId);
        command.Parameters.AddWithValue(connectorId);
        return Assert.IsType<string>(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken));
    }

    private static string RequiredConnection(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        if (!string.IsNullOrWhiteSpace(value)) return value;
        Assert.Skip($"The dedicated PostgreSQL 18 gate must provide {name}.");
        throw new InvalidOperationException(name + " is required.");
    }
}

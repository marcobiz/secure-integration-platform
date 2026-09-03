using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Integration.Tests;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Integration.Tests;

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class Fse2DurableWorkflowCorrelationIntegrationTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task FSE2_DUR_E2E_PostgreSQL18_create_and_validate_trace_status_survive_restart_and_replica()
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

        Fse2OperationDescriptor validate = Fse2OperationCatalog.Get(Fse2Operation.ValidateCda);
        Fse2OperationDescriptor create = Fse2OperationCatalog.Get(Fse2Operation.Create);
        Fse2OperationDescriptor replace = Fse2OperationCatalog.Get(Fse2Operation.Replace);
        Fse2OperationDescriptor status = Fse2OperationCatalog.Get(Fse2Operation.GetStatusByWorkflow);
        Fse2OperationDescriptor traceStatus = Fse2OperationCatalog.Get(Fse2Operation.GetStatusByTrace);
        string connectorId = "fse2-durable-" + Guid.NewGuid().ToString("N");
        HostedIdentity? durableIdentity = null;
        Guid tenantId = default;
        Guid installationId = default;
        Guid environmentId = default;
        string? workflowInstanceId = null;
        string? validationTraceId = null;

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
                environmentId = await first.CreateEnvironmentAsync();
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
                        [validate, create, replace, status, traceStatus]),
                    provider,
                    "sign-r1",
                    "mtls-r1",
                    operationId: "*",
                    expectedOperationCount: 5);
                await first.PublishAsync(authority, expectedPublicationRevision: 0);
                HostedIdentity identity = await first.EnrollIdentityAsync(
                    tenantId,
                    applicationId,
                    environmentId,
                    "fse2-durable-identity-a");
                installationId = identity.Identity.InstallationId;
                await first.AddOperationGrantAsync(identity, connectorId, validate.OperationId);
                await first.AddOperationGrantAsync(identity, connectorId, create.OperationId);
                await first.AddOperationGrantAsync(identity, connectorId, replace.OperationId);
                await first.AddOperationGrantAsync(identity, connectorId, status.OperationId);
                await first.AddOperationGrantAsync(identity, connectorId, traceStatus.OperationId);

                await AssertUnknownOrCrossScopeDeniedBeforeOutboundAsync(
                    first,
                    identity,
                    provider,
                    server,
                    connectorId,
                    status);
                await AssertUnknownOrCrossScopeDeniedBeforeOutboundAsync(
                    first,
                    identity,
                    provider,
                    server,
                    connectorId,
                    traceStatus,
                    "trace-unknown-fse2-1");

                Guid validationCorrelationId = Guid.NewGuid();
                using (HttpResponseMessage validation = await first.SendSignedAsync(
                    identity,
                    HttpMethod.Post,
                    $"/v1/connectors/{connectorId}/operations/{validate.OperationId}:invoke",
                    Fse2OrganizationHostedIntegrationTests.InvokeRequest(
                        Fse2OrganizationHostedIntegrationTests.PayloadFor(validate), validationCorrelationId)))
                {
                    string body = await validation.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
                    Assert.True(validation.IsSuccessStatusCode, body);
                    validationTraceId = ReadTraceIdentifier(body);
                }
                await AssertAuditOutcomeAsync(first, tenantId, validationCorrelationId, expectedFailure: 0, expectedSuccess: 1);

                for (int attempt = 0; attempt < 2; attempt++)
                {
                    Guid correlationId = Guid.NewGuid();
                    using HttpResponseMessage response = await first.SendSignedAsync(
                        identity,
                        HttpMethod.Post,
                        $"/v1/connectors/{connectorId}/operations/{create.OperationId}:invoke",
                        Fse2OrganizationHostedIntegrationTests.InvokeRequest(
                            Fse2OrganizationHostedIntegrationTests.PayloadFor(create), correlationId));
                    string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
                    Assert.True(response.IsSuccessStatusCode, body);
                    string returnedWorkflow = ReadWorkflowIdentifier(body);
                    workflowInstanceId ??= returnedWorkflow;
                    Assert.Equal(workflowInstanceId, returnedWorkflow);
                    await AssertAuditOutcomeAsync(first, tenantId, correlationId, expectedFailure: 0, expectedSuccess: 1);
                }

                Assert.Equal(2L, await CountContextsAsync(
                    migrationConnection,
                    tenantId,
                    installationId,
                    connectorId));
                ContextRow context = await ReadContextAsync(
                    migrationConnection,
                    tenantId,
                    installationId,
                    connectorId,
                    "create");
                Assert.Equal("create", context.OriginatingOperationId);
                Assert.Equal("CREATE", context.ActionCode);
                Assert.Equal("TREATMENT", context.PurposeOfUseCode);
                Assert.Equal(64, context.OperationProfileChecksumSha256.Length);
                Assert.Equal(workflowInstanceId, context.WorkflowInstanceId);
                Assert.Equal("trace-fse2-1", context.TraceId);
                Assert.DoesNotContain(
                    Convert.ToBase64String(Fse2OrganizationHostedIntegrationTests.DocumentBytes()),
                    string.Join('|', context.OriginatingOperationId, context.ActionCode, context.PurposeOfUseCode,
                        context.OperationProfileChecksumSha256, context.WorkflowInstanceId, context.TraceId),
                    StringComparison.Ordinal);
                ContextRow validationContext = await ReadContextAsync(
                    migrationConnection,
                    tenantId,
                    installationId,
                    connectorId,
                    "validate-cda");
                Assert.Equal("validate-cda", validationContext.OriginatingOperationId);
                Assert.Equal("CREATE", validationContext.ActionCode);
                Assert.Equal("TREATMENT", validationContext.PurposeOfUseCode);
                Assert.Equal(64, validationContext.OperationProfileChecksumSha256.Length);
                Assert.Null(validationContext.WorkflowInstanceId);
                Assert.Equal(validationTraceId, validationContext.TraceId);
                Guid conflictCorrelationId = Guid.NewGuid();
                using (HttpResponseMessage conflict = await first.SendSignedAsync(
                    identity,
                    HttpMethod.Post,
                    $"/v1/connectors/{connectorId}/operations/{replace.OperationId}:invoke",
                    Fse2OrganizationHostedIntegrationTests.InvokeRequest(
                        Fse2OrganizationHostedIntegrationTests.PayloadFor(replace), conflictCorrelationId)))
                {
                    string body = await conflict.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
                    Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
                    Assert.Contains("BGW-CONNECTOR-WORKFLOW-CONTEXT-CONFLICT", body, StringComparison.Ordinal);
                }
                await AssertAuditOutcomeAsync(first, tenantId, conflictCorrelationId, expectedFailure: 1, expectedSuccess: 0);
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
                    await first.AddOperationGrantAsync(crossScope, connectorId, traceStatus.OperationId);
                    await AssertUnknownOrCrossScopeDeniedBeforeOutboundAsync(
                        first,
                        crossScope,
                        provider,
                        server,
                        connectorId,
                        status);
                    await AssertUnknownOrCrossScopeDeniedBeforeOutboundAsync(
                        first,
                        crossScope,
                        provider,
                        server,
                        connectorId,
                        traceStatus,
                        Assert.IsType<string>(validationTraceId));
                }

                using HostedIdentity unauthorized = await first.EnrollIdentityAsync(
                    tenantId, applicationId, environmentId, "fse2-durable-unauthorized");
                await AssertUnauthorizedDeniedBeforeOutboundAsync(
                    first,
                    unauthorized,
                    provider,
                    server,
                    connectorId,
                    status,
                    Assert.IsType<string>(workflowInstanceId));

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
            string exactWorkflowInstanceId = Assert.IsType<string>(workflowInstanceId);
            string exactValidationTraceId = Assert.IsType<string>(validationTraceId);
            await using HostedTypedSessionFixture restarted = await HostedTypedSessionFixture.CreateAsync(
                "unused-fse2-durable-restarted",
                runtimeConnection: runtimeRole.ConnectionString,
                adminConnection: adminConnection,
                executionModule: Fse2OrganizationHostedIntegrationTests.Module(),
                capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));
            await AssertStatusSuccessAsync(
                restarted, restartedIdentity, tenantId, connectorId, status, exactWorkflowInstanceId);
            await AssertStatusSuccessAsync(
                restarted, restartedIdentity, tenantId, connectorId, traceStatus, exactValidationTraceId);

            await using HostedTypedSessionFixture replica = await HostedTypedSessionFixture.CreateAsync(
                "unused-fse2-durable-replica",
                runtimeConnection: runtimeRole.ConnectionString,
                adminConnection: adminConnection,
                executionModule: Fse2OrganizationHostedIntegrationTests.Module(),
                capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));
            await AssertStatusSuccessAsync(
                replica, restartedIdentity, tenantId, connectorId, status, exactWorkflowInstanceId);
            await AssertStatusSuccessAsync(
                replica, restartedIdentity, tenantId, connectorId, traceStatus, exactValidationTraceId);
            server.SetStatusNotFound(true);
            try
            {
                await AssertStatusNotFoundAsync(
                    replica, restartedIdentity, tenantId, connectorId, traceStatus,
                    exactValidationTraceId, provider, server);
            }
            finally
            {
                server.SetStatusNotFound(false);
            }

            HostedCapabilityAuthority changedAuthority = await replica.PrepareCapabilityConnectorVersionAsync(
                connectorId,
                "2.0.0",
                environmentId,
                server.Endpoint,
                Fse2OrganizationHostedIntegrationTests.DefinitionForOperations(
                    connectorId,
                    "2.0.0",
                    Fse2OrganizationHostedIntegrationTests.SpkiSha256(material.SigningKeyRevision1),
                    Fse2OrganizationHostedIntegrationTests.SpkiSha256(material.ClientCertificateRevision1),
                    "2.0.0",
                    [validate, create, replace, status, traceStatus]),
                provider,
                "sign-r1",
                "mtls-r1",
                operationId: "*",
                expectedOperationCount: 5);
            await replica.PublishAsync(changedAuthority, expectedPublicationRevision: 1);
            await AssertUnknownOrCrossScopeDeniedBeforeOutboundAsync(
                replica,
                restartedIdentity,
                provider,
                server,
                connectorId,
                status,
                exactWorkflowInstanceId);
            await AssertUnknownOrCrossScopeDeniedBeforeOutboundAsync(
                replica,
                restartedIdentity,
                provider,
                server,
                connectorId,
                traceStatus,
                exactValidationTraceId);

            Assert.Equal(2L, await CountContextsAsync(
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
        Fse2OperationDescriptor status,
        string resourceIdentifier = "workflow-fse2-1")
    {
        int signingBefore = provider.SignDigestCalls;
        int dnsBefore = fixture.HostResolutionCount;
        int serverBefore = server.Requests;
        int transportBefore = fixture.GenericTransportRequests;
        Guid correlationId = Guid.NewGuid();
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{status.OperationId}:invoke",
            Fse2OrganizationHostedIntegrationTests.InvokeRequest(
                StatusPayload(resourceIdentifier), correlationId));
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Contains("BGW-CONNECTOR-WORKFLOW-CONTEXT-NOT-FOUND", body, StringComparison.Ordinal);
        Assert.Equal(signingBefore, provider.SignDigestCalls);
        Assert.Equal(dnsBefore, fixture.HostResolutionCount);
        Assert.Equal(serverBefore, server.Requests);
        Assert.Equal(transportBefore, fixture.GenericTransportRequests);
        await AssertAuditOutcomeAsync(
            fixture, identity.Identity.TenantId, correlationId, expectedFailure: 1, expectedSuccess: 0);
    }

    private static async Task AssertUnauthorizedDeniedBeforeOutboundAsync(
        HostedTypedSessionFixture fixture,
        HostedIdentity identity,
        TrackingCapabilityProvider provider,
        SyntheticFse2OperationMatrixServer server,
        string connectorId,
        Fse2OperationDescriptor status,
        string resourceIdentifier)
    {
        int signingBefore = provider.SignDigestCalls;
        int dnsBefore = fixture.HostResolutionCount;
        int serverBefore = server.Requests;
        int transportBefore = fixture.GenericTransportRequests;
        Guid correlationId = Guid.NewGuid();
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{status.OperationId}:invoke",
            Fse2OrganizationHostedIntegrationTests.InvokeRequest(StatusPayload(resourceIdentifier), correlationId));
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("BGW-AUTHZ-OPERATION-DENIED", body, StringComparison.Ordinal);
        Assert.Equal(signingBefore, provider.SignDigestCalls);
        Assert.Equal(dnsBefore, fixture.HostResolutionCount);
        Assert.Equal(serverBefore, server.Requests);
        Assert.Equal(transportBefore, fixture.GenericTransportRequests);
        await AssertAuditOutcomeAsync(
            fixture, identity.Identity.TenantId, correlationId, expectedFailure: 1, expectedSuccess: 0);
    }

    private static async Task AssertStatusSuccessAsync(
        HostedTypedSessionFixture fixture,
        HostedIdentity identity,
        Guid tenantId,
        string connectorId,
        Fse2OperationDescriptor status,
        string resourceIdentifier)
    {
        Assert.True(fixture.UsesPostgreSql);
        Guid correlationId = Guid.NewGuid();
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{status.OperationId}:invoke",
            Fse2OrganizationHostedIntegrationTests.InvokeRequest(
                StatusPayload(resourceIdentifier), correlationId));
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, body);
        using JsonDocument normalized = ReadNormalizedResult(body);
        if (status.Operation == Fse2Operation.GetStatusByWorkflow)
            Assert.Equal(resourceIdentifier, normalized.RootElement.GetProperty("workflowInstanceId").GetString());
        else
            Assert.Equal("trace-status-1", normalized.RootElement.GetProperty("traceId").GetString());
        JsonElement events = normalized.RootElement.GetProperty("workflowEvents");
        Assert.Equal("FOUND", normalized.RootElement.GetProperty("statusClassification").GetString());
        Assert.Equal(2, events.GetArrayLength());
        Assert.Equal("VALIDATION", events[0].GetProperty("eventType").GetString());
        Assert.Equal("SUCCESS", events[0].GetProperty("outcome").GetString());
        Assert.Equal("SEND_TO_INI", events[1].GetProperty("eventType").GetString());
        Assert.DoesNotContain("raw-status-message-not-exposed", body, StringComparison.Ordinal);
        await AssertAuditOutcomeAsync(fixture, tenantId, correlationId, expectedFailure: 0, expectedSuccess: 1);
    }

    private static async Task AssertStatusNotFoundAsync(
        HostedTypedSessionFixture fixture,
        HostedIdentity identity,
        Guid tenantId,
        string connectorId,
        Fse2OperationDescriptor status,
        string resourceIdentifier,
        TrackingCapabilityProvider provider,
        SyntheticFse2OperationMatrixServer server)
    {
        int signingBefore = provider.SignDigestCalls;
        int dnsBefore = fixture.HostResolutionCount;
        int serverBefore = server.Requests;
        int transportBefore = fixture.GenericTransportRequests;
        Guid correlationId = Guid.NewGuid();
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{status.OperationId}:invoke",
            Fse2OrganizationHostedIntegrationTests.InvokeRequest(
                StatusPayload(resourceIdentifier), correlationId));
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using JsonDocument normalized = ReadNormalizedResult(body);
        Assert.Equal(404, normalized.RootElement.GetProperty("statusCode").GetInt32());
        Assert.Equal("NOT_FOUND", normalized.RootElement.GetProperty("statusClassification").GetString());
        Assert.Empty(normalized.RootElement.GetProperty("workflowEvents").EnumerateArray());
        Assert.DoesNotContain(SyntheticFse2OperationMatrixServer.StatusNotFoundRawCanary, body, StringComparison.Ordinal);
        Assert.Equal(signingBefore + 2, provider.SignDigestCalls);
        Assert.Equal(dnsBefore + 1, fixture.HostResolutionCount);
        Assert.Equal(serverBefore + 1, server.Requests);
        Assert.Equal(transportBefore + 1, fixture.GenericTransportRequests);
        await AssertAuditOutcomeAsync(fixture, tenantId, correlationId, expectedFailure: 0, expectedSuccess: 1);
    }

    private static string StatusPayload(string workflowInstanceId) => JsonSerializer.Serialize(
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["resourceIdentifier"] = workflowInstanceId
        });

    private static string ReadWorkflowIdentifier(string gatewayResponse)
    {
        using JsonDocument normalized = ReadNormalizedResult(gatewayResponse);
        return Assert.IsType<string>(normalized.RootElement.GetProperty("workflowInstanceId").GetString());
    }

    private static string ReadTraceIdentifier(string gatewayResponse)
    {
        using JsonDocument normalized = ReadNormalizedResult(gatewayResponse);
        return Assert.IsType<string>(normalized.RootElement.GetProperty("traceId").GetString());
    }

    private static JsonDocument ReadNormalizedResult(string gatewayResponse)
    {
        GatewayInvokeResponse gateway = JsonSerializer.Deserialize<GatewayInvokeResponse>(
            gatewayResponse,
            WebJson)
            ?? throw new InvalidOperationException("The Gateway response was empty.");
        return JsonDocument.Parse(Convert.FromBase64String(gateway.Result.Data));
    }

    private static async Task AssertAuditOutcomeAsync(
        HostedTypedSessionFixture fixture,
        Guid tenantId,
        Guid correlationId,
        int expectedFailure,
        int expectedSuccess)
    {
        GatewayAuditEvent[] audit = JsonSerializer.Deserialize<GatewayAuditEvent[]>(
            await fixture.SerializeAuditAsync(tenantId)) ?? [];
        GatewayAuditEvent[] matching = audit
            .Where(item => item.CorrelationId == correlationId &&
                string.Equals(item.Action, "operation.invoke", StringComparison.Ordinal))
            .ToArray();
        Assert.Equal(expectedFailure, matching.Count(item =>
            string.Equals(item.Outcome, "failure", StringComparison.OrdinalIgnoreCase)));
        Assert.Equal(expectedSuccess, matching.Count(item =>
            string.Equals(item.Outcome, "success", StringComparison.OrdinalIgnoreCase)));
        Assert.Equal(expectedFailure + expectedSuccess, matching.Length);
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
               AND workflow_instance_id IS NOT NULL
            """, connection);
        command.Parameters.AddWithValue(tenantId);
        command.Parameters.AddWithValue(installationId);
        command.Parameters.AddWithValue(connectorId);
        return Assert.IsType<string>(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken));
    }

    private static async Task<ContextRow> ReadContextAsync(
        string migrationConnection,
        Guid tenantId,
        Guid installationId,
        string connectorId,
        string originatingOperationId)
    {
        await using NpgsqlConnection connection = new(migrationConnection);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using NpgsqlCommand command = new("""
            SELECT originating_operation_id, action_code, purpose_of_use_code,
                   operation_profile_checksum_sha256, workflow_instance_id, trace_id
             FROM gateway.connector_workflow_context
             WHERE tenant_id=$1 AND installation_id=$2 AND connector_id=$3
               AND originating_operation_id=$4
            """, connection);
        command.Parameters.AddWithValue(tenantId);
        command.Parameters.AddWithValue(installationId);
        command.Parameters.AddWithValue(connectorId);
        command.Parameters.AddWithValue(originatingOperationId);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        Assert.True(await reader.ReadAsync(TestContext.Current.CancellationToken));
        ContextRow result = new(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            Convert.ToHexString(reader.GetFieldValue<byte[]>(3)),
            reader.IsDBNull(4) ? null : reader.GetString(4),
            reader.IsDBNull(5) ? null : reader.GetString(5));
        Assert.False(await reader.ReadAsync(TestContext.Current.CancellationToken));
        return result;
    }

    private static string RequiredConnection(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        if (!string.IsNullOrWhiteSpace(value)) return value;
        Assert.Skip($"The dedicated PostgreSQL 18 gate must provide {name}.");
        throw new InvalidOperationException(name + " is required.");
    }

    private sealed record ContextRow(
        string OriginatingOperationId,
        string ActionCode,
        string PurposeOfUseCode,
        string OperationProfileChecksumSha256,
        string? WorkflowInstanceId,
        string? TraceId);
}

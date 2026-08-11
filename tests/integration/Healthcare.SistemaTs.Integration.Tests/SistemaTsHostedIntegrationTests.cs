using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Integration.Tests;
using SecureIntegration.Healthcare.SyntheticSistemaTsServer;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.Integration.Tests;

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class SistemaTsHostedIntegrationTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    [Fact]
    public Task HC_W1_SISTEMATS_IT_hosted_BGW1_create_admission_checkToken_and_business_use_one_shared_session() =>
        RunAsync(null, null, requirePostgres: false);

    [Fact]
    public async Task HC_W1_SISTEMATS_IT_PostgreSQL18_four_eyes_Published_hosted_full_lifecycle()
    {
        string? adminConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(adminConnection)) Assert.Skip("PostgreSQL admin connection is not configured; the PostgreSQL gate must provide it.");
        string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(migrationConnection)) Assert.Skip("PostgreSQL migration connection is not configured; the PostgreSQL gate must provide it.");
        await HostedPostgresSupport.ApplyMigrationsAsync();
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole =
            await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(adminConnection, migrationConnection,
                TestContext.Current.CancellationToken);
        await RunAsync(runtimeRole.ConnectionString, adminConnection, requirePostgres: true);
    }

    private static async Task RunAsync(string? runtimeConnection, string? adminConnection, bool requirePostgres)
    {
        const string candidate = "28f34143-8777-4a62-bca9-6a4f6b502735";
        Dictionary<string, string> fields = new(StringComparer.Ordinal)
        {
            ["user-id"] = "server-user-47", ["identificativo-tipo"] = "CF",
            ["identificativo-valore"] = "encrypted-identifier-47", ["codice-fiscale"] = "RSSMRA80A01H501U",
            ["codice-regione"] = "120", ["codice-asl"] = "201", ["codice-ssa"] = "000001"
        };
        SyntheticSistemaTsServerInstance? server = null;
        HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateExternalAsync(
            "sistema-ts.synthetic.test",
            async (certificate, cancellationToken) =>
            {
                server = await SyntheticSistemaTsServerHost.StartAsync(
                    new(HostedTypedSessionFixture.SyntheticUsername, HostedTypedSessionFixture.SyntheticPassword, candidate, fields),
                    certificate, cancellationToken);
                return (server, server.Endpoint);
            }, runtimeConnection, adminConnection, Module());
        await using (fixture)
        {
            Assert.Equal(requirePostgres, fixture.UsesPostgres);
            string connectorId = "sistema-ts-e2e-" + Guid.NewGuid().ToString("N");
            Guid environmentId = await fixture.CreateEnvironmentAsync();
            Guid tenantId = await fixture.CreateTenantAsync("sistema-ts-tenant");
            Guid applicationId = await fixture.CreateApplicationAsync("sistema-ts-application");
            Dictionary<string, string> bindingValues = new(StringComparer.Ordinal)
            {
                ["basic-username"] = HostedTypedSessionFixture.SyntheticUsername,
                ["basic-password"] = HostedTypedSessionFixture.SyntheticPassword,
                ["id-session-authority"] = "synthetic-session-authority",
                ["sts-user-id"] = fields["user-id"], ["sts-identifier-type"] = fields["identificativo-tipo"],
                ["sts-identifier-value"] = fields["identificativo-valore"], ["sts-tax-code"] = fields["codice-fiscale"],
                ["sts-region-code"] = fields["codice-regione"], ["sts-health-authority-code"] = fields["codice-asl"],
                ["sts-facility-code"] = fields["codice-ssa"]
            };
            HostedConnectorAuthority authority = await fixture.PrepareExternalConnectorVersionAsync(connectorId, "1.0.0",
                environmentId, Definition(connectorId), "sistema-ts-sac", bindingValues,
                "basic-username", "basic-password", "id-session-authority");
            await fixture.PublishAsync(authority, 0);
            HostedIdentity identity = await fixture.EnrollIdentityAsync(tenantId, applicationId, environmentId, "sistema-ts-identity");
            await fixture.GrantOperationsAsync(connectorId, identity, "session-create", "visualizza-erogato");

            GatewayInvokeRequest acquire = new("1.0", new("text/xml", "utf8",
                "<caller-spoof><userId>attacker</userId><cfUtente>attacker</cfUtente></caller-spoof>"), Guid.NewGuid(),
                Metadata: new Dictionary<string, JsonElement> { ["endpoint"] = JsonSerializer.SerializeToElement("https://attacker.invalid") });
            using HttpResponseMessage acquireResponse = await fixture.SendSignedAsync(identity, HttpMethod.Post,
                $"/v1/connectors/{connectorId}/operations/session-create:invoke", JsonSerializer.SerializeToUtf8Bytes(acquire, WebJson),
                new Dictionary<string, string> { ["Authorization2F"] = "Bearer attacker-session", ["SOAPAction"] = "attacker-action" });
            string acquireBody = await acquireResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, acquireResponse.StatusCode);
            GatewayInvokeResponse acquireGateway = JsonSerializer.Deserialize<GatewayInvokeResponse>(acquireBody, WebJson)!;
            HostedHandshakeResult acquired = HostedHandshakeResult.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(acquireGateway.Result.Data)));
            Assert.Equal("ExternalAdmissionRequired", acquired.Kind);

            using HttpResponseMessage completionResponse = await fixture.SendSignedAsync(identity, HttpMethod.Post,
                $"/v1/session-admissions/{acquired.IntentReference}:complete", Encoding.UTF8.GetBytes(candidate));
            string completionBody = await completionResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, completionResponse.StatusCode);
            Assert.Equal("Issued", HostedHandshakeResult.Parse(completionBody).Kind);
            long generation = fixture.CaptureCurrentSessionGeneration();

            using HttpResponseMessage businessResponse = await fixture.SendSignedAsync(identity, HttpMethod.Post,
                $"/v1/connectors/{connectorId}/operations/visualizza-erogato:invoke", BusinessInvocation());
            string businessBody = await businessResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, businessResponse.StatusCode);
            GatewayInvokeResponse businessGateway = JsonSerializer.Deserialize<GatewayInvokeResponse>(businessBody, WebJson)!;
            Assert.Contains("VisualizzaErogatoRicevuta", Encoding.UTF8.GetString(Convert.FromBase64String(businessGateway.Result.Data)), StringComparison.Ordinal);
            Assert.Equal(generation, fixture.CaptureCurrentSessionGeneration());
            Assert.Equal(1, server!.Counters.Create);
            Assert.Equal(1, server.Counters.CheckToken);
            Assert.Equal(1, server.Counters.Business);
            Assert.Equal(0, server.Counters.Generic);
            Assert.Equal(0, server.Counters.Rejected);
            Assert.Equal(0, fixture.GenericTransportRequests);
            Assert.Equal(3, fixture.TotalSoapTransportRequests);
            string diagnostics = string.Join('\n', acquireBody, completionBody, businessBody, string.Join('\n', fixture.HostedLogs));
            foreach (string sensitive in fields.Values.Append(candidate).Append(HostedTypedSessionFixture.SyntheticPassword))
                Assert.DoesNotContain(sensitive, diagnostics, StringComparison.Ordinal);
        }
    }

    private static HostedExecutionModuleConfiguration Module()
    {
        string path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.dll"));
        return new("healthcare-sistema-ts", path, AssemblyName.GetAssemblyName(path).FullName!,
            "SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.SistemaTsExecutionModule");
    }

    private static string Definition(string connectorId)
    {
        JsonObject root = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Samples", "sistema-ts.connector.json")))!.AsObject();
        root["connectorId"] = connectorId;
        return root.ToJsonString();
    }

    private static byte[] BusinessInvocation()
    {
        const string envelope = """
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>
              <req:VisualizzaErogatoRichiesta xmlns:req="http://visualizzaerogatorichiesta.xsd.dem.sanita.finanze.it">
                <req:pinCode>synthetic-pin</req:pinCode><req:codiceRegioneErogatore>120</req:codiceRegioneErogatore>
                <req:codiceAslErogatore>201</req:codiceAslErogatore><req:codiceSsaErogatore>000001</req:codiceSsaErogatore>
                <req:nre>123456789012345</req:nre><req:tipoOperazione>1</req:tipoOperazione>
              </req:VisualizzaErogatoRichiesta>
            </soap:Body></soap:Envelope>
            """;
        return JsonSerializer.SerializeToUtf8Bytes(new GatewayInvokeRequest("1.0", new("text/xml", "utf8", envelope), Guid.NewGuid()), WebJson);
    }
}

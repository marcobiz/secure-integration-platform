using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Integration.Tests;
using SecureIntegration.Healthcare.SyntheticSistemaTsServer;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.Integration.Tests;

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class SistemaTsHostedIntegrationTests
{
    private const string Candidate = "28f34143-8777-4a62-bca9-6a4f6b502735";
    private const string Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string Common = "http://tipodati.xsd.dem.sanita.finanze.it";
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    [Fact]
    public Task HC_W1_SISTEMATS_IT_hosted_BGW1_create_admission_checkToken_and_business_operations_fail_closed() =>
        RunAdmissionAsync(null, null, requirePostgres: false);

    [Fact]
    public async Task HC_W1_SISTEMATS_IT_PostgreSQL18_four_eyes_Published_admission_and_checkToken_execute_when_required()
    {
        string adminConnection = RequiredPostgresSetting("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        string migrationConnection = RequiredPostgresSetting("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        await HostedPostgresSupport.ApplyMigrationsAsync();
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole =
            await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(adminConnection, migrationConnection,
                TestContext.Current.CancellationToken);
        await RunAdmissionAsync(runtimeRole.ConnectionString, adminConnection, requirePostgres: true);
    }

    [Theory]
    [MemberData(nameof(BusinessWireCases))]
    public async Task HC_W1_SISTEMATS_IT_synthetic_server_asserts_exact_wire_and_negatives_for_every_business_operation(
        string operation, string action, string requestXml, string responseRoot, string resultField)
    {
        Dictionary<string, string> fields = ServerOwnedFields();
        using X509Certificate2 certificate = CreateServerCertificate();
        await using SyntheticSistemaTsServerInstance server = await SyntheticSistemaTsServerHost.StartAsync(
            new(HostedTypedSessionFixture.SyntheticUsername, HostedTypedSessionFixture.SyntheticPassword, Candidate, fields),
            certificate, TestContext.Current.CancellationToken);
        using HttpClient client = CreatePinnedClient(certificate);

        using HttpResponseMessage accepted = await SendBusinessAsync(client, server.Endpoint, action, requestXml,
            HostedTypedSessionFixture.SyntheticUsername, HostedTypedSessionFixture.SyntheticPassword, Candidate,
            "text/xml; charset=utf-8", TestContext.Current.CancellationToken);
        string acceptedBody = await accepted.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        XDocument response = XDocument.Parse(acceptedBody);
        XElement payload = response.Root!.Element(XName.Get("Body", Soap))!.Elements().Single();
        Assert.Equal(responseRoot, payload.Name.LocalName);
        Assert.Equal("0000", payload.Elements().Single(element => element.Name.LocalName == resultField).Value);

        List<HttpResponseMessage> rejected =
        [
            await SendBusinessAsync(client, server.Endpoint, action + "/wrong", requestXml,
                HostedTypedSessionFixture.SyntheticUsername, HostedTypedSessionFixture.SyntheticPassword, Candidate,
                "text/xml; charset=utf-8", TestContext.Current.CancellationToken),
            await SendBusinessAsync(client, server.Endpoint, action, requestXml.Replace(Soap, "http://www.w3.org/2003/05/soap-envelope", StringComparison.Ordinal),
                HostedTypedSessionFixture.SyntheticUsername, HostedTypedSessionFixture.SyntheticPassword, Candidate,
                "text/xml; charset=utf-8", TestContext.Current.CancellationToken),
            await SendBusinessAsync(client, server.Endpoint, action, requestXml,
                HostedTypedSessionFixture.SyntheticUsername, HostedTypedSessionFixture.SyntheticPassword, Candidate,
                "application/soap+xml; charset=utf-8", TestContext.Current.CancellationToken),
            await SendBusinessAsync(client, server.Endpoint, action, requestXml,
                HostedTypedSessionFixture.SyntheticUsername, HostedTypedSessionFixture.SyntheticPassword, Candidate,
                "text/xml; charset=utf-8; action=\"unexpected\"", TestContext.Current.CancellationToken),
            await SendBusinessAsync(client, server.Endpoint, action, requestXml,
                "wrong-user", HostedTypedSessionFixture.SyntheticPassword, Candidate,
                "text/xml; charset=utf-8", TestContext.Current.CancellationToken),
            await SendBusinessAsync(client, server.Endpoint, action, requestXml,
                HostedTypedSessionFixture.SyntheticUsername, HostedTypedSessionFixture.SyntheticPassword, "00000000-0000-0000-0000-000000000000",
                "text/xml; charset=utf-8", TestContext.Current.CancellationToken),
            await SendBusinessAsync(client, server.Endpoint, action, MutateBusinessValue(operation, requestXml),
                HostedTypedSessionFixture.SyntheticUsername, HostedTypedSessionFixture.SyntheticPassword, Candidate,
                "text/xml; charset=utf-8", TestContext.Current.CancellationToken)
        ];
        try
        {
            Assert.All(rejected, value => Assert.False(value.IsSuccessStatusCode));
        }
        finally
        {
            foreach (HttpResponseMessage value in rejected) value.Dispose();
        }

        Assert.Equal(1, AcceptedCounter(server.Counters, operation));
        Assert.Equal(1, server.Counters.Business);
        Assert.Equal(7, server.Counters.Rejected);
        Assert.Equal(0, server.Counters.Generic);
    }

    public static TheoryData<string, string, string, string, string> BusinessWireCases() => new()
    {
        { "visualizza-erogato", "http://visualizzaerogato.wsdl.dem.sanita.finanze.it/VisualizzaErogato", VisualizzaRequest(), "VisualizzaErogatoRicevuta", "codEsitoVisualizzazione" },
        { "invio-erogato", "http://invioerogato.wsdl.dem.sanita.finanze.it/InvioErogato", InvioRequest(), "InvioErogatoRicevuta", "codEsitoInserimento" },
        { "sospendi-erogato", "http://visualizzaerogato.wsdl.dem.sanita.finanze.it/SospendiErogato", SospendiRequest(), "SospendiErogatoRicevuta", "codEsitoSospensione" },
        { "annulla-erogato", "http://annullaerogato.wsdl.dem.sanita.finanze.it/AnnullaErogato", AnnullaRequest(), "AnnullaErogatoRicevuta", "codEsitoAnnullamento" }
    };

    private static async Task RunAdmissionAsync(string? runtimeConnection, string? adminConnection, bool requirePostgres)
    {
        Dictionary<string, string> fields = ServerOwnedFields();
        SyntheticSistemaTsServerInstance? server = null;
        HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateExternalAsync(
            "sistema-ts.synthetic.test",
            async (certificate, cancellationToken) =>
            {
                server = await SyntheticSistemaTsServerHost.StartAsync(
                    new(HostedTypedSessionFixture.SyntheticUsername, HostedTypedSessionFixture.SyntheticPassword, Candidate, fields),
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
                ["sts-user-id"] = fields["user-id"],
                ["sts-identifier-type"] = fields["identificativo-tipo"],
                ["sts-identifier-value"] = fields["identificativo-valore"],
                ["sts-tax-code"] = fields["codice-fiscale"],
                ["sts-region-code"] = fields["codice-regione"],
                ["sts-health-authority-code"] = fields["codice-asl"],
                ["sts-facility-code"] = fields["codice-ssa"]
            };
            HostedConnectorAuthority authority = await fixture.PrepareExternalConnectorVersionAsync(connectorId, "1.0.0",
                environmentId, Definition(connectorId), "sistema-ts-sac", bindingValues,
                "basic-username", "basic-password", "sts-user-id");
            await fixture.PublishAsync(authority, 0);
            HostedIdentity identity = await fixture.EnrollIdentityAsync(tenantId, applicationId, environmentId, "sistema-ts-identity");
            await fixture.GrantOperationsAsync(connectorId, identity, "session-create");

            GatewayInvokeRequest acquire = new("1.0", new("text/xml", "utf8",
                "<caller-spoof><userId>attacker</userId><cfUtente>attacker</cfUtente></caller-spoof>"), Guid.NewGuid(),
                Metadata: new Dictionary<string, JsonElement>
                {
                    ["endpoint"] = JsonSerializer.SerializeToElement("https://attacker.invalid")
                });
            using HttpResponseMessage acquireResponse = await fixture.SendSignedAsync(identity, HttpMethod.Post,
                $"/v1/connectors/{connectorId}/operations/session-create:invoke", JsonSerializer.SerializeToUtf8Bytes(acquire, WebJson),
                new Dictionary<string, string> { ["Authorization2F"] = "Bearer attacker-session", ["SOAPAction"] = "attacker-action" });
            string acquireBody = await acquireResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, acquireResponse.StatusCode);
            GatewayInvokeResponse acquireGateway = JsonSerializer.Deserialize<GatewayInvokeResponse>(acquireBody, WebJson)!;
            HostedHandshakeResult acquired = HostedHandshakeResult.Parse(
                Encoding.UTF8.GetString(Convert.FromBase64String(acquireGateway.Result.Data)));
            Assert.Equal("ExternalAdmissionRequired", acquired.Kind);

            using HttpResponseMessage completionResponse = await fixture.SendSignedAsync(identity, HttpMethod.Post,
                $"/v1/session-admissions/{acquired.IntentReference}:complete", Encoding.UTF8.GetBytes(Candidate));
            string completionBody = await completionResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, completionResponse.StatusCode);
            Assert.Equal("Issued", HostedHandshakeResult.Parse(completionBody).Kind);
            long generation = fixture.CaptureCurrentSessionGeneration();

            List<string> denialBodies = [];
            foreach (string operation in new[] { "visualizza-erogato", "invio-erogato", "sospendi-erogato", "annulla-erogato" })
            {
                using HttpResponseMessage denied = await fixture.SendSignedAsync(identity, HttpMethod.Post,
                    $"/v1/connectors/{connectorId}/operations/{operation}:invoke", BusinessInvocation(operation));
                denialBodies.Add(await denied.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
                Assert.False(denied.IsSuccessStatusCode);
            }

            Assert.Equal(generation, fixture.CaptureCurrentSessionGeneration());
            Assert.Equal(1, server!.Counters.Create);
            Assert.Equal(1, server.Counters.CheckToken);
            Assert.Equal(0, server.Counters.Business);
            Assert.Equal(0, server.Counters.Generic);
            Assert.Equal(0, server.Counters.Rejected);
            Assert.Equal(0, fixture.GenericTransportRequests);
            Assert.Equal(2, fixture.TotalSoapTransportRequests);
            string diagnostics = string.Join('\n', acquireBody, completionBody, string.Join('\n', denialBodies),
                string.Join('\n', fixture.HostedLogs));
            foreach (string sensitive in fields.Values.Append(Candidate).Append(HostedTypedSessionFixture.SyntheticPassword))
                Assert.DoesNotContain(sensitive, diagnostics, StringComparison.Ordinal);
        }
    }

    private static HostedExecutionModuleConfiguration Module()
    {
        string path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
            "SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.dll"));
        return new("healthcare-sistema-ts", path, AssemblyName.GetAssemblyName(path).FullName!,
            "SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.SistemaTsExecutionModule");
    }

    private static string Definition(string connectorId)
    {
        JsonObject root = JsonNode.Parse(File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "Samples", "sistema-ts.connector.json")))!.AsObject();
        root["connectorId"] = connectorId;
        return root.ToJsonString();
    }

    private static byte[] BusinessInvocation(string operation)
    {
        string envelope = operation switch
        {
            "visualizza-erogato" => VisualizzaRequest(),
            "invio-erogato" => InvioRequest(),
            "sospendi-erogato" => SospendiRequest(),
            "annulla-erogato" => AnnullaRequest(),
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };
        return JsonSerializer.SerializeToUtf8Bytes(
            new GatewayInvokeRequest("1.0", new("text/xml", "utf8", envelope), Guid.NewGuid()), WebJson);
    }

    private static async Task<HttpResponseMessage> SendBusinessAsync(HttpClient client, Uri endpoint, string action,
        string xml, string username, string password, string candidate, string contentType, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, new Uri(endpoint, "/erogatore"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(username + ":" + password)));
        request.Headers.TryAddWithoutValidation("Authorization2F", "Bearer " + candidate);
        request.Headers.TryAddWithoutValidation("SOAPAction", '"' + action + '"');
        request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(xml));
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        return await client.SendAsync(request, cancellationToken);
    }

    private static HttpClient CreatePinnedClient(X509Certificate2 certificate)
    {
        string expected = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        HttpClientHandler handler = new()
        {
            ServerCertificateCustomValidationCallback = (_, presented, _, _) =>
                presented is not null && string.Equals(presented.GetCertHashString(HashAlgorithmName.SHA256), expected,
                    StringComparison.OrdinalIgnoreCase)
        };
        return new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(10) };
    }

    private static X509Certificate2 CreateServerCertificate()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new("CN=127.0.0.1", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        SubjectAlternativeNameBuilder san = new();
        san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        using X509Certificate2 generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddHours(1));
        return X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
    }

    private static Dictionary<string, string> ServerOwnedFields() => new(StringComparer.Ordinal)
    {
        ["user-id"] = "server-user-47",
        ["identificativo-tipo"] = "CF",
        ["identificativo-valore"] = "encrypted-identifier-47",
        ["codice-fiscale"] = "RSSMRA80A01H501U",
        ["codice-regione"] = "120",
        ["codice-asl"] = "201",
        ["codice-ssa"] = "000001",
        ["business-pin-code"] = "server-pin"
    };

    private static string RequiredPostgresSetting(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        if (!string.IsNullOrWhiteSpace(value)) return value;
        if (string.Equals(Environment.GetEnvironmentVariable("REQUIRE_SISTEMA_TS_POSTGRES_GATE"), "1", StringComparison.Ordinal))
            throw new InvalidOperationException($"{name} is mandatory for the Sistema TS PostgreSQL CI gate.");
        Assert.Skip($"{name} is not configured; the PostgreSQL gate must provide it.");
        return null!;
    }

    private static int AcceptedCounter(SyntheticSistemaTsCounters counters, string operation) => operation switch
    {
        "visualizza-erogato" => counters.Visualizza,
        "invio-erogato" => counters.Invio,
        "sospendi-erogato" => counters.Sospendi,
        "annulla-erogato" => counters.Annulla,
        _ => throw new ArgumentOutOfRangeException(nameof(operation))
    };

    private static string MutateBusinessValue(string operation, string xml) => operation switch
    {
        "visualizza-erogato" => xml.Replace("123456789012345", "999999999999999", StringComparison.Ordinal),
        "invio-erogato" => xml.Replace("012345678", "999999999", StringComparison.Ordinal),
        "sospendi-erogato" => xml.Replace("<req:tipoOperazione>1</req:tipoOperazione>", "<req:tipoOperazione>2</req:tipoOperazione>", StringComparison.Ordinal),
        "annulla-erogato" => xml.Replace("<req:codAnnullamento>TEST</req:codAnnullamento>", "<req:codAnnullamento>OTHER</req:codAnnullamento>", StringComparison.Ordinal),
        _ => throw new ArgumentOutOfRangeException(nameof(operation))
    };

    private static string VisualizzaRequest() => Envelope("""
        <req:VisualizzaErogatoRichiesta xmlns:req="http://visualizzaerogatorichiesta.xsd.dem.sanita.finanze.it">
          <req:pinCode>server-pin</req:pinCode><req:codiceRegioneErogatore>120</req:codiceRegioneErogatore>
          <req:codiceAslErogatore>201</req:codiceAslErogatore><req:codiceSsaErogatore>000001</req:codiceSsaErogatore>
          <req:nre>123456789012345</req:nre><req:tipoOperazione>1</req:tipoOperazione>
        </req:VisualizzaErogatoRichiesta>
        """);

    private static string InvioRequest() => Envelope($"""
        <req:InvioErogatoRichiesta xmlns:req="http://invioerogatorichiesta.xsd.dem.sanita.finanze.it" xmlns:td="{Common}">
          <req:pinCode>server-pin</req:pinCode><req:codiceRegioneErogatore>120</req:codiceRegioneErogatore>
          <req:codiceAslErogatore>201</req:codiceAslErogatore><req:codiceSsaErogatore>000001</req:codiceSsaErogatore>
          <req:nre>123456789012345</req:nre><req:tipoOperazione>1</req:tipoOperazione><req:dataSpedizione>2026-08-11 08:00:00</req:dataSpedizione>
          <req:ElencoDettagliPrescrInviiErogato><td:DettaglioPrescrizioneInvioErogato>
            <td:codProdPrestErog>012345678</td:codProdPrestErog><td:dataMatrix><td:raw>01012345678901281726123110LOT1</td:raw><td:GTIN>01234567890123</td:GTIN><td:authToken>synthetic-auth-token</td:authToken></td:dataMatrix>
            <td:prezzo>12.50</td:prezzo><td:quantitaErogata>1</td:quantitaErogata><td:dataIniErog>2026-08-11 08:00:00</td:dataIniErog><td:dataFineErog>2026-08-11 08:30:00</td:dataFineErog>
          </td:DettaglioPrescrizioneInvioErogato></req:ElencoDettagliPrescrInviiErogato>
        </req:InvioErogatoRichiesta>
        """);

    private static string SospendiRequest() => Envelope("""
        <req:SospendiErogatoRichiesta xmlns:req="http://sospendierogatorichiesta.xsd.dem.sanita.finanze.it">
          <req:pinCode>server-pin</req:pinCode><req:codiceRegioneErogatore>120</req:codiceRegioneErogatore>
          <req:codiceAslErogatore>201</req:codiceAslErogatore><req:codiceSsaErogatore>000001</req:codiceSsaErogatore>
          <req:nre>123456789012345</req:nre><req:tipoOperazione>1</req:tipoOperazione>
        </req:SospendiErogatoRichiesta>
        """);

    private static string AnnullaRequest() => Envelope("""
        <req:AnnullaErogatoRichiesta xmlns:req="http://annullaerogatorichiesta.xsd.dem.sanita.finanze.it">
          <req:pinCode>server-pin</req:pinCode><req:codiceRegioneErogatore>120</req:codiceRegioneErogatore>
          <req:codiceAslErogatore>201</req:codiceAslErogatore><req:codiceSsaErogatore>000001</req:codiceSsaErogatore>
          <req:nre>123456789012345</req:nre><req:codAnnullamento>TEST</req:codAnnullamento>
        </req:AnnullaErogatoRichiesta>
        """);

    private static string Envelope(string payload) =>
        $"<soap:Envelope xmlns:soap=\"{Soap}\"><soap:Body>{payload}</soap:Body></soap:Envelope>";
}

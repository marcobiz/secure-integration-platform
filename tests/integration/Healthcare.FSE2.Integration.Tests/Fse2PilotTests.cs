using System.Text;
using System.Text.Json;
using System.Diagnostics;
using System.Security.Cryptography;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Tools.Fse2.OfficialTestProvisioner;
using Xunit;
using Pilot = SecureIntegration.Tools.Fse2.OfficialTestProvisioner.Program;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Integration.Tests;

public sealed class Fse2PilotTests
{
    [Theory]
    [InlineData("asl-roma-1", false)]
    [InlineData("190", true)]
    public void FSE2_PILOT_organization_domain_is_not_local_facility_id(string domain, bool accepted)
    {
        Pilot.PilotSettings settings = new(new("PROVAX00X00X000Y", "2.16.840.1.113883.2.9.4.3.2", "Regione Sicilia", domain),
            new("LABORATORIO DI PROVA", "2.16.840.1.113883.2.9.4.1.3", "190111123456"));
        if (accepted) Pilot.ValidatePilotSettings(settings);
        else Assert.Throws<Pilot.ProvisioningException>(() => Pilot.ValidatePilotSettings(settings));
    }

    [Fact]
    public async Task FSE2_PILOT_runtime_message_has_traceparent_and_exact_BGW1_body_signature()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const string target = "/v1/connectors/fse2-organization-current-spec/operations/validate-fhir:invoke";
        byte[] body = "{\"synthetic\":true}"u8.ToArray();
        using HttpRequestMessage message = Pilot.CreatePilotMessage(key, HttpMethod.Post, target, body);
        string Header(string name) => Assert.Single(message.Headers.GetValues(name));
        Assert.True(ActivityContext.TryParse(Header("traceparent"), null, out _));
        byte[] delivered = await message.Content!.ReadAsByteArrayAsync(TestContext.Current.CancellationToken);
        Assert.Equal(body, delivered);
        string signing = RuntimeIdentityService.BuildSigningInput("POST", target, Header("X-BG-Timestamp"), Header("X-BG-Nonce"), Header("X-BG-Content-SHA256"));
        byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/').PadRight((value.Length + 3) / 4 * 4, '='));
        Assert.Equal(SHA256.HashData(delivered), Decode(Header("X-BG-Content-SHA256")));
        Assert.True(key.VerifyData(Encoding.UTF8.GetBytes(signing), Decode(Header("X-BG-Signature")), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    [Fact]
    public void FSE2_PILOT_fhir_preserves_exact_bundle_and_official_VERIFICA_RESOURCE_body()
    {
        byte[] bundle = Encoding.UTF8.GetBytes("""
            {"resourceType":"Bundle","type":"transaction","entry":[
              {"resource":{"resourceType":"Patient","identifier":[{"system":"urn:oid:2.16.840.1.113883.2.9.4.3.2","value":"PROVAX00X00X000Y"}]}},
              {"resource":{"resourceType":"Composition","type":{"coding":[{"system":"http://loinc.org","code":"11526-1"}]}}}
            ]}
            """);
        Fse2Request request = Pilot.BuildPilotFhirRequest(bundle);
        using JsonDocument payload = JsonDocument.Parse(request.SerializeAuthorizedPayload());
        Assert.Equal(bundle, payload.RootElement.GetProperty("documentBase64").GetBytesFromBase64());
        Assert.Equal("application/json", payload.RootElement.GetProperty("documentContentType").GetString());
        Assert.Equal("{\"mode\":\"RESOURCE\",\"activity\":\"VERIFICA\"}",
            Encoding.UTF8.GetString(payload.RootElement.GetProperty("requestBodyBase64").GetBytesFromBase64()));
        Assert.Equal("('11526-1^^2.16.840.1.113883.6.1')", request.ClinicalClaims!.ResourceHl7Type);
        Assert.ThrowsAny<Exception>(() => Pilot.BuildPilotFhirRequest(Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(bundle).Replace("PROVAX00X00X000Y", "RSSMRA80A01H501U", StringComparison.Ordinal))));
    }

    [Theory]
    [InlineData("create")]
    [InlineData("validate-and-create")]
    [InlineData("VALIDATION")]
    public async Task FSE2_PILOT_document_publication_denied_before_configuration_or_dispatch(string command)
    {
        Assert.DoesNotContain(command, Pilot.PilotOperations);
        Assert.Equal(2, await Pilot.Main(["pilot", command, "nonexistent-settings.json"]));
    }

    [Fact]
    public void FSE2_PILOT_frozen_CDA_test_case_does_not_require_FHIR_PROVA_prefix()
    {
        byte[] xml = Encoding.UTF8.GetBytes("""
            <ClinicalDocument xmlns="urn:hl7-org:v3"><code code="60591-5"/>
              <recordTarget><patientRole><id root="2.16.840.1.113883.2.9.4.3.2" extension="RSSMRA80A01H501U"/></patientRole></recordTarget>
            </ClinicalDocument>
            """);
        byte[] pdf = "%PDF-synthetic-test-only"u8.ToArray();
        Fse2Request request = Pilot.BuildPilotCdaRequest(pdf, xml);
        using JsonDocument payload = JsonDocument.Parse(request.SerializeAuthorizedPayload());
        Assert.Equal(pdf, payload.RootElement.GetProperty("documentBase64").GetBytesFromBase64());
        Assert.Equal("{\"healthDataFormat\":\"CDA\",\"mode\":\"ATTACHMENT\",\"activity\":\"VERIFICA\"}",
            Encoding.UTF8.GetString(payload.RootElement.GetProperty("requestBodyBase64").GetBytesFromBase64()));
        Assert.All(xml, value => Assert.Equal(0, value));
    }

    [Theory]
    [InlineData(200, null, "VALIDATED")]
    [InlineData(200, "FOUND", "FOUND")]
    [InlineData(404, "NOT_FOUND", "NOT_FOUND")]
    public void FSE2_PILOT_success_projection_preserves_status_semantics_without_raw_fields(int status, string? classification, string expected)
    {
        Guid correlation = Guid.NewGuid();
        Pilot.PilotState pending = new(correlation, "get-status-by-workflow", null, null, "workflow-pilot", "trace-pilot", "DISPATCH_PENDING", 0);
        byte[] normalized = JsonSerializer.SerializeToUtf8Bytes(new
        {
            statusCode = status, correlationId = correlation, workflowInstanceId = "workflow-pilot", traceId = "trace-pilot", spanId = "span-pilot",
            safeWarning = "ignored-warning-canary", retryClass = 0, workflowEvents = Array.Empty<object>(), statusClassification = classification
        });
        byte[] envelope = JsonSerializer.SerializeToUtf8Bytes(new
        {
            correlationId = correlation, connectorVersion = "1.0.0", ignored = "raw-endpoint-token-canary",
            result = new { contentType = "application/json", encoding = "base64", data = Convert.ToBase64String(normalized) }
        });
        Pilot.PilotState result = Pilot.ReducePilotSuccess(envelope, pending);
        Assert.Equal(expected, result.Classification);
        Assert.Equal(status, result.UpstreamHttpStatus);
        Assert.Equal(200, result.GatewayHttpStatus);
        Assert.Equal("workflow-pilot", result.Workflow);
        Assert.Equal("trace-pilot", result.Trace);
        Assert.DoesNotContain("canary", JsonSerializer.Serialize(result), StringComparison.Ordinal);
        Assert.ThrowsAny<Exception>(() => Pilot.ReducePilotSuccess(envelope, pending with { CorrelationId = Guid.NewGuid() }));
    }

    [Fact]
    public void FSE2_PILOT_grants_are_closed_to_validation_and_status()
    {
        Assert.Equal(["validate-fhir", "validate-cda", "get-status-by-workflow", "get-status-by-trace"], Pilot.PilotOperations);
        Assert.DoesNotContain("create", Pilot.PilotOperations);
        Assert.DoesNotContain("replace", Pilot.PilotOperations);
        Assert.DoesNotContain("delete", Pilot.PilotOperations);
    }

    [Theory]
    [InlineData("{\"code\":\"BGW-AUTHN-CERTIFICATE-REQUIRED\",\"detail\":\"raw-token-endpoint-canary\"}", "BGW-AUTHN-CERTIFICATE-REQUIRED")]
    [InlineData("{\"code\":\"raw-token-endpoint-canary\"}", "FSE2_PILOT_GATEWAY_REJECTED")]
    [InlineData("not json raw-canary", "FSE2_PILOT_GATEWAY_REJECTED")]
    public void FSE2_PILOT_failure_retains_only_existing_published_wire_code(string body, string expected)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(body);
        Assert.Equal(expected, Pilot.ReducePilotFailure(bytes));
        Assert.All(bytes, value => Assert.Equal(0, value));
    }
}

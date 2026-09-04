using System.Text;
using System.Text.Json;
using SecureIntegration.Tools.Fse2.OfficialTestProvisioner;
using Xunit;
using Pilot = SecureIntegration.Tools.Fse2.OfficialTestProvisioner.Program;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Integration.Tests;

public sealed class Fse2PilotTests
{
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
}

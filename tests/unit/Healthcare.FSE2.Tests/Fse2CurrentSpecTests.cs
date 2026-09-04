using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecureIntegration.Gateway.Application;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Tests;

public sealed class Fse2CurrentSpecTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);
    private const string Metadata = """{"assettoOrganizzativo":"AD_PSC001","identificativoSottomissione":"2.16.840.1","tipoAttivitaClinica":"CON","tipoDocumentoLivAlto":"REF","tipologiaStruttura":"Ospedale"}""";

    [Fact]
    public void FSE2_CURRENT_supported_plan_schema_is_explicit_bounded_and_server_scoped()
    {
        Fse2OfficialTestOperationalPlan expected = Plan();
        string json = JsonSerializer.Serialize(new
        {
            schemaVersion = "2.0", expected.TenantId, expected.InstallationId, expected.EnvironmentId,
            officialTestEndpoint = expected.Endpoint.AbsoluteUri,
            expected.Organization, expected.Locality, expected.A1, expected.S1, expected.ExpectedBindingRevision,
            environmentClass = "synthetic", activity = "VERIFICA"
        }, WebJson);
        Fse2OfficialTestOperationalPlan parsed = Fse2OfficialTestOperationalization.ParsePlan(Encoding.UTF8.GetBytes(json));
        Assert.Equal(expected, parsed);
        Assert.Equal(Fse2CurrentSpec.ConnectorId, parsed.ConnectorId);
        Assert.Equal(14, Fse2OfficialTestOperationalization.Plan(parsed).OperationIds.Count);
        foreach (string invalid in new[]
        {
            json.Replace("\"synthetic\"", "\"production\"", StringComparison.Ordinal),
            json.Replace("\"VERIFICA\"", "\"verifica\"", StringComparison.Ordinal),
            json.Insert(1, "\"operationId\":\"delete\","),
            json.Replace("https://localhost:443/gateway/v1/", "https://untrusted.invalid/gateway/v1/", StringComparison.Ordinal)
                .Replace("https://localhost/gateway/v1/", "https://untrusted.invalid/gateway/v1/", StringComparison.Ordinal)
        })
            Assert.Throws<Fse2OfficialTestOperationalizationException>(() =>
                Fse2OfficialTestOperationalization.ParsePlan(Encoding.UTF8.GetBytes(invalid)));
    }

    [Fact]
    public void FSE2_CURRENT_validation_response_distinguishes_VERIFICA_and_VALIDATION_and_bounds_warning()
    {
        Fse2OperationDescriptor cda = Fse2OperationCatalog.Get(Fse2Operation.ValidateCda);
        byte[] body = """{"traceID":"trace-current","workflowInstanceId":"workflow-current"}"""u8.ToArray();
        _ = Fse2ResponseMapper.Map(new(200, "application/json", body), Guid.NewGuid(), cda, true, "VERIFICA");
        _ = Fse2ResponseMapper.Map(new(201, "application/json", body), Guid.NewGuid(), cda, true, "VALIDATION");
        Assert.Throws<Fse2ConnectorException>(() => Fse2ResponseMapper.Map(
            new(201, "application/json", body), Guid.NewGuid(), cda, true, "VERIFICA"));
        Assert.Throws<Fse2ConnectorException>(() => Fse2ResponseMapper.Map(
            new(201, "application/json", body), Guid.NewGuid(), Fse2OperationCatalog.Get(Fse2Operation.ValidateFhir), true));
        string largeWarning = """{"traceID":"trace-current","warning":""" + JsonSerializer.Serialize(new string('x', 200000)) + "}";
        Assert.Equal("FSE2_UPSTREAM_WARNING", Fse2ResponseMapper.Map(
            new(200, "application/json", Encoding.UTF8.GetBytes(largeWarning)), Guid.NewGuid(), cda, true, "VERIFICA").SafeWarning);
        Assert.Throws<Fse2ConnectorException>(() => Fse2ResponseMapper.Map(
            new(200, "application/json", new byte[262145]), Guid.NewGuid(), cda, true));
    }

    public static TheoryData<Fse2Operation> BodyOperations => new(
        Fse2OperationCatalog.All.Where(value => value.HasJsonBody).Select(value => value.Operation));

    [Theory]
    [MemberData(nameof(BodyOperations))]
    public void FSE2_CURRENT_closed_body_accepts_contract_and_rejects_unknown_duplicate_missing_and_wrong_type(Fse2Operation operation)
    {
        string body = Body(operation);
        Fse2CurrentSpec.ValidateRequestBody(operation, Encoding.UTF8.GetBytes(body));
        AssertDenied(operation, body.Insert(1, "\"endpoint\":\"https://untrusted.invalid/\","));
        using JsonDocument document = JsonDocument.Parse(body);
        JsonProperty required = document.RootElement.EnumerateObject().First();
        AssertDenied(operation, body.Insert(1, JsonSerializer.Serialize(required.Name) + ":" + required.Value.GetRawText() + ","));
        JsonObject missing = JsonNode.Parse(body)!.AsObject();
        missing.Remove(required.Name);
        AssertDenied(operation, missing.ToJsonString());
        missing[required.Name] = 7;
        AssertDenied(operation, missing.ToJsonString());
        AssertDenied(operation, "{}");
        AssertDenied(operation, "[");
    }

    [Fact]
    public void FSE2_CURRENT_validation_activity_and_operation_specific_fields_are_not_interchangeable()
    {
        Fse2CurrentSpec.ValidateRequestBody(Fse2Operation.ValidateCda, """{"activity":"VALIDATION","mode":"RESOURCE"}"""u8.ToArray(), "VALIDATION");
        Assert.Throws<ArgumentException>(() => Fse2CurrentSpec.ValidateRequestBody(
            Fse2Operation.ValidateCda, """{"activity":"VALIDATION"}"""u8.ToArray(), "VERIFICA"));
        AssertDenied(Fse2Operation.ValidateFhir, """{"activity":"VALIDATION","mode":"ATTACHMENT"}""");
        AssertDenied(Fse2Operation.ValidateFhir, """{"activity":"VERIFICA","mode":"attachment"}""");
        AssertDenied(Fse2Operation.UpdateMetadataChainConcealment, """{"attiCliniciRegoleAccesso":["P98"]}""");
        AssertDenied(Fse2Operation.Replace, Body(Fse2Operation.Replace).Insert(1, "\"priorita\":true,"));
        AssertDenied(Fse2Operation.ValidateAndCreate, Body(Fse2Operation.Create));
        AssertDenied(Fse2Operation.UpdateMetadataLegacy, Metadata.Insert(1, "\"identificativoDoc\":\"2.16.840.1\","));
        AssertDenied(Fse2Operation.Create, Body(Fse2Operation.Create).Replace("AD_PSC001", "AD_PSC016", StringComparison.Ordinal));
        AssertDenied(Fse2Operation.Create, Body(Fse2Operation.Create).Replace("Ospedale", "ospedale", StringComparison.Ordinal));
        JsonObject oversized = JsonNode.Parse(Metadata)!.AsObject();
        oversized["descriptions"] = new JsonArray(JsonValue.Create(new string('x', 1001)));
        AssertDenied(Fse2Operation.UpdateMetadata, oversized.ToJsonString());
        oversized["descriptions"] = new JsonArray(Enumerable.Range(0, 101).Select(_ => (JsonNode?)JsonValue.Create("x")).ToArray());
        AssertDenied(Fse2Operation.UpdateMetadata, oversized.ToJsonString());
    }

    [Fact]
    public void FSE2_CURRENT_product_source_compiles_all_14_routes_with_exact_policy_and_legacy_unchanged()
    {
        Fse2OfficialTestOperationalPlan plan = Plan();
        Fse2OfficialTestCompiledConfiguration compiled = Fse2OfficialTestOperationalization.Compile(
            plan, new(plan.A1, new string('A', 64), "Synthetic A1", new string('C', 64)),
            new(plan.S1, new string('B', 64), "Synthetic S1", new string('D', 64)));
        using JsonDocument document = JsonDocument.Parse(compiled.CanonicalDefinition);
        ConnectorValidationResult result = new ConnectorDefinitionValidator().Validate(document.RootElement);
        Assert.True(result.Valid, string.Join(';', result.Issues.Select(value => value.Code + ":" + value.Location)));
        Assert.Equal(14, document.RootElement.GetProperty("operations").GetArrayLength());
        foreach (JsonElement operation in document.RootElement.GetProperty("operations").EnumerateArray())
        {
            Fse2OperationDescriptor descriptor = Fse2OperationCatalog.Get(operation.GetProperty("operationId").GetString()!);
            Assert.Equal(descriptor.Method.Method, operation.GetProperty("method").GetString());
            Assert.Equal(descriptor.PathTemplate, operation.GetProperty("pathTemplate").GetString());
            Assert.Equal(0, operation.GetProperty("maximumRetries").GetInt32());
            Assert.Equal("deny", operation.GetProperty("redirectPolicy").GetString());
            Assert.Equal(5000, operation.GetProperty("timeoutMs").GetInt32());
            Assert.Equal(262144, operation.GetProperty("response").GetProperty("maximumBytes").GetInt32());
            string[] claims = operation.GetProperty("authorizedCapabilities").GetProperty("signingSlots")[1]
                .GetProperty("signing").GetProperty("allowedClaims").EnumerateArray().Select(value => value.GetString()!).ToArray();
            Assert.Equal(descriptor.RequiresAttachmentHash, claims.Contains("attachment_hash"));
            Assert.Equal(descriptor.Action is not null, claims.Contains("person_id"));
            Fse2PublishedOrganizationProfile profile = Fse2PublishedOrganizationProfile.ParseJson(
                Encoding.UTF8.GetBytes(operation.GetProperty("extensionConfiguration").GetRawText()), descriptor.OperationId);
            Assert.True(profile.UsesCurrentSpec);
        }
        Fse2OfficialTestOperationalization.VerifyDefinitionReadback(Encoding.UTF8.GetBytes(compiled.CanonicalDefinition), compiled);
        using JsonDocument legacy = JsonDocument.Parse(Fse2OfficialTestCanonicalDefinition.GetSourceBytes());
        Assert.Single(legacy.RootElement.GetProperty("operations").EnumerateArray());
        Assert.Equal("1.0.1", legacy.RootElement.GetProperty("version").GetString());
    }

    [Theory]
    [InlineData(Fse2Operation.Create)]
    [InlineData(Fse2Operation.Replace)]
    [InlineData(Fse2Operation.Delete)]
    [InlineData(Fse2Operation.UpdateMetadata)]
    [InlineData(Fse2Operation.UpdateMetadataLegacy)]
    [InlineData(Fse2Operation.UpdateMetadataChainConcealment)]
    [InlineData(Fse2Operation.ValidateAndCreate)]
    [InlineData(Fse2Operation.ValidateAndReplace)]
    [InlineData(Fse2Operation.CreateFhir)]
    [InlineData(Fse2Operation.ReplaceFhir)]
    public void FSE2_CURRENT_success_requires_technical_correlation_and_drops_clinical_response(Fse2Operation operation)
    {
        Fse2OperationDescriptor descriptor = Fse2OperationCatalog.Get(operation);
        string body = """{"traceID":"trace-current","workflowInstanceId":"workflow-current","warning":"line1\nline2","fhirBundle":"clinical-canary"}""";
        Fse2Response result = Fse2ResponseMapper.Map(new(descriptor.SuccessStatusCodes.Min(), "application/json", Encoding.UTF8.GetBytes(body)), Guid.NewGuid(), descriptor, true);
        Assert.Equal("FSE2_UPSTREAM_WARNING", result.SafeWarning);
        Assert.DoesNotContain("clinical-canary", JsonSerializer.Serialize(result), StringComparison.Ordinal);
        Assert.Throws<Fse2ConnectorException>(() => Fse2ResponseMapper.Map(
            new(descriptor.SuccessStatusCodes.Min(), "application/json", "{}"u8.ToArray()), Guid.NewGuid(), descriptor, true));
        Assert.Throws<Fse2ConnectorException>(() => Fse2ResponseMapper.Map(
            new(500, "text/plain", "raw-canary"u8.ToArray()), Guid.NewGuid(), descriptor, true));
    }

    [Fact]
    public void FSE2_CURRENT_status_retains_exact_NOT_FOUND_and_generic_failure()
    {
        foreach (Fse2Operation op in new[] { Fse2Operation.GetStatusByTrace, Fse2Operation.GetStatusByWorkflow })
        {
            Fse2OperationDescriptor descriptor = Fse2OperationCatalog.Get(op);
            Fse2Response found = Fse2ResponseMapper.Map(
                new(404, "application/problem+json", """{"type":"msg/record-not-found","detail":"raw-canary"}"""u8.ToArray()),
                Guid.NewGuid(), descriptor, true);
            Assert.Equal(Fse2StatusClassification.NotFound, found.StatusClassification);
            Assert.Throws<Fse2ConnectorException>(() => Fse2ResponseMapper.Map(
                new(404, "application/problem+json", """{"type":"msg/routing","detail":"record-not-found"}"""u8.ToArray()),
                Guid.NewGuid(), descriptor, true));
        }
    }

    private static Fse2OfficialTestOperationalPlan Plan() => new(
        Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), new("https://localhost:443/gateway/v1/"),
        new("12345678903", "2.16.840.1.113883.2.9.4.1.2", "Synthetic Organization", "synthetic-organization"),
        new("Synthetic Locality", "2.16.840.1.113883.2.9.4.1.2", "SYNTHETIC"),
        new("synthetic", "a1", "1", 1, 1), new("synthetic", "s1", "1", 1, 1), null)
        { UsesCurrentSpec = true, EnvironmentClass = Fse2EnvironmentClass.Synthetic };

    private static string Body(Fse2Operation operation) => operation switch
    {
        Fse2Operation.ValidateCda => """{"activity":"VERIFICA"}""",
        Fse2Operation.ValidateFhir => """{"activity":"VERIFICA","mode":"ATTACHMENT"}""",
        Fse2Operation.UpdateMetadataChainConcealment => """{"attiCliniciRegoleAccesso":["P99"]}""",
        Fse2Operation.UpdateMetadata or Fse2Operation.UpdateMetadataLegacy => Metadata,
        Fse2Operation.ValidateAndCreate or Fse2Operation.ValidateAndReplace => Metadata.Insert(1, "\"identificativoDoc\":\"2.16.840.1\",\"identificativoRep\":\"2.16.840.2\","),
        _ => Metadata.Insert(1, "\"identificativoDoc\":\"2.16.840.1\",\"identificativoRep\":\"2.16.840.2\",\"workflowInstanceId\":\"workflow-current\",")
    };

    private static void AssertDenied(Fse2Operation operation, string body) =>
        Assert.Throws<ArgumentException>(() => Fse2CurrentSpec.ValidateRequestBody(operation, Encoding.UTF8.GetBytes(body)));
}

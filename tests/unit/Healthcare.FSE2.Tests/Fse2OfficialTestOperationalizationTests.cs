using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Tests;

public sealed class Fse2OfficialTestOperationalizationTests
{
    private const string ExpectedCanonicalSourceSha256 = "51CFAE64FB7CA2F32336ED09EB6351CAA286A660D0D97E0EEE4489B7D01E741F";

    [Fact]
    public void FSE2_OFFICIALTEST_canonical_definition_bytes_checksum_and_single_operation_are_frozen()
    {
        byte[] bytes = Fse2OfficialTestCanonicalDefinition.GetSourceBytes();
        Assert.Equal(ExpectedCanonicalSourceSha256, Fse2OfficialTestCanonicalDefinition.SourceSha256);
        using JsonDocument document = JsonDocument.Parse(bytes);
        ValidatedConnectorDefinition validated = new ConnectorDefinitionValidator().ValidateRequired(document.RootElement);
        JsonElement operation = Assert.Single(document.RootElement.GetProperty("operations").EnumerateArray());

        Assert.Equal(Fse2OfficialTestCanonicalDefinition.ConnectorId, validated.ConnectorId);
        Assert.Equal(Fse2OfficialTestCanonicalDefinition.ConnectorVersion, validated.Version);
        Assert.Equal("validate-cda", operation.GetProperty("operationId").GetString());
        Assert.Equal("POST", operation.GetProperty("method").GetString());
        Assert.Equal("/documents/validation", operation.GetProperty("path").GetString());
        Assert.Equal("multipart/form-data; boundary=broker-gateway-fse2-officialtest-v1", operation.GetProperty("request").GetProperty("contentType").GetString());
        Assert.Equal(0, operation.GetProperty("maximumRetries").GetInt32());
        Assert.Equal("deny", operation.GetProperty("redirectPolicy").GetString());
        Assert.Empty(operation.GetProperty("allowedClientHeaders").EnumerateArray());
        Assert.DoesNotContain(Fse2OfficialTestCanonicalDefinition.OfficialTestAudience, Encoding.UTF8.GetString(bytes), StringComparison.Ordinal);
    }

    [Fact]
    public void FSE2_OFFICIALTEST_plan_is_redacted_and_has_zero_writes_signing_DNS_HTTPS_transport_and_network()
    {
        Fse2OfficialTestPlanResult result = Fse2OfficialTestOperationalization.Plan(Plan());

        Assert.Equal(Fse2OfficialTestSideEffectCounters.Zero, result.Counters);
        Assert.Equal(64, result.OperationalPlanDigestSha256.Length);
        Assert.Equal(64, result.OperationProfileChecksumSha256.Length);
        Assert.Equal(64, result.EndpointDigestSha256.Length);
        Assert.Equal(64, result.A1ReferenceDigestSha256.Length);
        Assert.Equal(64, result.S1ReferenceDigestSha256.Length);
        string output = JsonSerializer.Serialize(result);
        Assert.DoesNotContain(Fse2OfficialTestCanonicalDefinition.OfficialTestAudience, output, StringComparison.Ordinal);
        Assert.DoesNotContain("provider-a1", output, StringComparison.Ordinal);
        Assert.DoesNotContain("resource-s1", output, StringComparison.Ordinal);
    }

    [Fact]
    public void FSE2_OFFICIALTEST_compiler_closes_A1_mTLS_S1_dual_signing_and_no_GetSecret()
    {
        Fse2OfficialTestCompiledConfiguration compiled = Compile();
        using JsonDocument document = JsonDocument.Parse(compiled.CanonicalDefinition);
        JsonElement root = document.RootElement;
        JsonElement operation = Assert.Single(root.GetProperty("operations").EnumerateArray());
        JsonElement capabilities = operation.GetProperty("authorizedCapabilities");
        JsonElement[] slots = capabilities.GetProperty("signingSlots").EnumerateArray().ToArray();

        Assert.Equal("a1-mtls-certificate", operation.GetProperty("authentication").GetProperty("certificateBinding").GetString());
        Assert.Equal(["authorization", "integrity"], slots.Select(value => value.GetProperty("slot").GetString()));
        Assert.All(slots, value => Assert.Equal("s1-signing-certificate", value.GetProperty("signing").GetProperty("keyBinding").GetString()));
        Assert.All(slots, value => Assert.Equal(new string('B', 64), value.GetProperty("signing").GetProperty("publicKeySpkiSha256").GetString()));
        Assert.Equal(new string('A', 64), capabilities.GetProperty("restrictedTransport").GetProperty("clientCertificateSpkiSha256").GetString());
        Assert.DoesNotContain("attachment_hash", slots.Single(value => value.GetProperty("slot").GetString() == "integrity")
            .GetProperty("signing").GetProperty("allowedClaims").EnumerateArray().Select(value => value.GetString()));
        Assert.DoesNotContain(root.GetProperty("bindings").GetProperty("secrets").EnumerateArray(),
            value => value.GetProperty("kind").GetString() != "clientCertificate");
        Assert.Empty(compiled.BindingRequest.SecretResources);
        Assert.Equal(["a1-mtls-certificate", "s1-signing-certificate"], compiled.BindingRequest.CertificateResources!.Keys.Order(StringComparer.Ordinal));
        Assert.DoesNotContain(typeof(Fse2OfficialTestOperationalization).Assembly.GetTypes(), type =>
            type.Namespace == typeof(Fse2OfficialTestOperationalization).Namespace &&
            type.GetMethods().Any(method => method.Name.Contains("GetSecret", StringComparison.Ordinal)));
    }

    [Fact]
    public void FSE2_OFFICIALTEST_compiled_definition_and_operation_profile_are_checksum_specific_and_deterministic()
    {
        Fse2OfficialTestCompiledConfiguration first = Compile();
        Fse2OfficialTestCompiledConfiguration second = Compile();
        Assert.Equal(first.CanonicalDefinition, second.CanonicalDefinition);
        Assert.Equal(first.CanonicalDefinitionSha256, second.CanonicalDefinitionSha256);
        Assert.Equal(first.OperationProfileChecksumSha256, second.OperationProfileChecksumSha256);
        Assert.Equal(first.BindingConfigurationDigestSha256, second.BindingConfigurationDigestSha256);
        Assert.Equal(first.BindingRequest.Endpoints, second.BindingRequest.Endpoints);
        Assert.Equal(first.BindingRequest.CertificateResources, second.BindingRequest.CertificateResources);
        Assert.Equal(first.CanonicalDefinitionSha256, ConnectorCanonicalJson.Checksum(first.CanonicalDefinition));

        Fse2OfficialTestOperationalPlan changed = Plan() with
        {
            Locality = Plan().Locality with { Code = "SYNTHETIC-DRIFT" }
        };
        Fse2OfficialTestCompiledConfiguration drifted = Compile(changed);
        Assert.NotEqual(first.CanonicalDefinitionSha256, drifted.CanonicalDefinitionSha256);
        Assert.NotEqual(first.OperationProfileChecksumSha256, drifted.OperationProfileChecksumSha256);
        Assert.NotEqual(first.BindingConfigurationDigestSha256, drifted.BindingConfigurationDigestSha256);

        Fse2OfficialTestOperationalizationException operationDrift = Assert.Throws<Fse2OfficialTestOperationalizationException>(() =>
            Fse2OfficialTestOperationalization.VerifyDefinitionReadback(
                Encoding.UTF8.GetBytes(first.CanonicalDefinition),
                first with { OperationProfileChecksumSha256 = new string('0', 64) }));
        Assert.Equal("FSE2_OFFICIALTEST_OPERATION_PROFILE_DRIFT", operationDrift.SafeCode);
    }

    [Theory]
    [InlineData("https://attacker.invalid/gateway/v1/")]
    [InlineData("https://127.0.0.1/gateway/v1/")]
    [InlineData("http://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1/")]
    public void FSE2_OFFICIALTEST_endpoint_is_server_owned_and_noncanonical_selection_is_denied(string endpoint)
    {
        Fse2OfficialTestOperationalizationException error = Assert.Throws<Fse2OfficialTestOperationalizationException>(() =>
            Fse2OfficialTestOperationalization.Plan(Plan() with { Endpoint = new Uri(endpoint) }));
        Assert.Equal("FSE2_OFFICIALTEST_ENDPOINT_DENIED", error.SafeCode);
    }

    [Fact]
    public void FSE2_OFFICIALTEST_plan_rejects_caller_endpoint_provider_secret_certificate_and_principal_selectors()
    {
        string text = PlanJson().Replace("\"expectedBindingRevision\":null", "\"expectedBindingRevision\":null,\"principal\":\"caller\",\"certificateBinding\":\"caller\"", StringComparison.Ordinal);
        Fse2OfficialTestOperationalizationException error = Assert.Throws<Fse2OfficialTestOperationalizationException>(() =>
            Fse2OfficialTestOperationalization.ParsePlan(Encoding.UTF8.GetBytes(text)));
        Assert.Equal("FSE2_OFFICIALTEST_PLAN_PROPERTY_DENIED", error.SafeCode);
    }

    [Fact]
    public void FSE2_OFFICIALTEST_A1_S1_swap_or_reuse_is_denied_before_any_side_effect()
    {
        Fse2OfficialTestOperationalPlan plan = Plan();
        Fse2OfficialTestOperationalizationException same = Assert.Throws<Fse2OfficialTestOperationalizationException>(() =>
            Fse2OfficialTestOperationalization.Plan(plan with { S1 = plan.A1 }));
        Assert.Equal("FSE2_OFFICIALTEST_A1_S1_NOT_DISTINCT", same.SafeCode);

        Fse2OfficialTestOperationalizationException swapped = Assert.Throws<Fse2OfficialTestOperationalizationException>(() =>
            Fse2OfficialTestOperationalization.Compile(plan, Resolved(plan.S1, 'B', "A1 CN", 'C'), Resolved(plan.A1, 'A', "S1 CN", 'D')));
        Assert.Equal("FSE2_OFFICIALTEST_A1_REVISION_DRIFT", swapped.SafeCode);
    }

    [Fact]
    public void FSE2_OFFICIALTEST_provider_revision_drift_is_denied_before_signing_DNS_and_network()
    {
        Fse2OfficialTestOperationalPlan plan = Plan();
        Fse2OfficialTestProviderReference drifted = plan.S1 with { PublicMetadataRevision = plan.S1.PublicMetadataRevision + 1 };
        Fse2OfficialTestOperationalizationException error = Assert.Throws<Fse2OfficialTestOperationalizationException>(() =>
            Fse2OfficialTestOperationalization.Compile(plan, Resolved(plan.A1, 'A', "A1 CN", 'C'), Resolved(drifted, 'B', "S1 CN", 'D')));
        Assert.Equal("FSE2_OFFICIALTEST_S1_REVISION_DRIFT", error.SafeCode);
    }

    [Fact]
    public void FSE2_OFFICIALTEST_validate_cda_contract_requires_VERIFICA_CDA_ATTACHMENT_and_no_attachment_hash()
    {
        byte[] valid = "{\"activity\":\"VERIFICA\",\"healthDataFormat\":\"CDA\",\"mode\":\"ATTACHMENT\"}"u8.ToArray();
        Fse2ClinicalClaims claims = Fse2ClinicalClaims.CreatePerson(
            "RSSMRA80A01H501U", "2.16.840.1.113883.2.9.4.3.2", true, "('11502-2^^2.16.840.1.113883.6.1')");
        _ = Fse2Request.ValidateCda("synthetic-pdf"u8.ToArray(), valid, claims);

        foreach (string invalid in new[]
        {
            "{\"activity\":\"CREATE\",\"healthDataFormat\":\"CDA\",\"mode\":\"ATTACHMENT\"}",
            "{\"activity\":\"VERIFICA\",\"healthDataFormat\":\"FHIR\",\"mode\":\"ATTACHMENT\"}",
            "{\"activity\":\"VERIFICA\",\"healthDataFormat\":\"CDA\",\"mode\":\"ATTACHMENT\",\"attachment_hash\":\"caller\"}"
        })
            Assert.Throws<ArgumentException>(() => Fse2Request.ValidateCda("synthetic-pdf"u8.ToArray(), Encoding.UTF8.GetBytes(invalid), claims));
    }

    private static Fse2OfficialTestCompiledConfiguration Compile(Fse2OfficialTestOperationalPlan? value = null)
    {
        Fse2OfficialTestOperationalPlan plan = value ?? Plan();
        return Fse2OfficialTestOperationalization.Compile(
            plan,
            Resolved(plan.A1, 'A', "A1 Synthetic Client", 'C'),
            Resolved(plan.S1, 'B', "S1 Synthetic Signing", 'D'));
    }

    private static Fse2OfficialTestResolvedCertificate Resolved(
        Fse2OfficialTestProviderReference reference,
        char spki,
        string commonName,
        char checksum) => new(reference, new string(spki, 64), commonName, new string(checksum, 64));

    private static Fse2OfficialTestOperationalPlan Plan() =>
        Fse2OfficialTestOperationalization.ParsePlan(Encoding.UTF8.GetBytes(PlanJson()));

    private static string PlanJson() => """
        {
          "schemaVersion":"1.0",
          "environmentId":"11111111-1111-1111-1111-111111111111",
          "officialTestEndpoint":"https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1/",
          "organization":{
            "identifier":"12345678903",
            "assigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2",
            "description":"Synthetic Organization",
            "domainId":"synthetic-organization"
          },
          "locality":{
            "name":"Synthetic Locality",
            "assigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2",
            "code":"SYNTHETIC"
          },
          "a1":{"providerId":"provider-a1","resourceId":"resource-a1","version":"1","catalogRevision":7,"publicMetadataRevision":3},
          "s1":{"providerId":"provider-s1","resourceId":"resource-s1","version":"1","catalogRevision":11,"publicMetadataRevision":5},
          "expectedBindingRevision":null
        }
        """;
}

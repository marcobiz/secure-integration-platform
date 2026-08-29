using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using SecureIntegration.Gateway.Application;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Tests;

public sealed class Fse2OfficialTestOperationalizationTests
{
    private const string ExpectedCanonicalSourceSha256 = "AC6A1EBA9E04CFED9B7E365A04865636243BEA1211D5540BFFF1416DF60F1408";
    private const string ExpectedCompiledCanonicalDefinitionSha256 = "7E69C57D9F7AC50252CDB28D4DE5195367C6E2E16ADF6514CC537B828035BF58";

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
        Assert.Equal("appendToBasePath", operation.GetProperty("pathResolution").GetString());
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
        Assert.Equal(ExpectedCompiledCanonicalDefinitionSha256, first.CanonicalDefinitionSha256);
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
    [InlineData("https://modipa-val.fse.salute.gov.it:444/govway/rest/in/FSE/gateway/v1/")]
    [InlineData("https://caller@modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1/")]
    [InlineData("https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v2/")]
    [InlineData("https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1/?caller=true")]
    [InlineData("https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1/#caller")]
    public void FSE2_OFFICIALTEST_endpoint_is_server_owned_and_noncanonical_selection_is_denied(string endpoint)
    {
        Fse2OfficialTestOperationalizationException error = Assert.Throws<Fse2OfficialTestOperationalizationException>(() =>
            Fse2OfficialTestOperationalization.Plan(Plan() with { Endpoint = new Uri(endpoint) }));
        Assert.Equal("FSE2_OFFICIALTEST_ENDPOINT_DENIED", error.SafeCode);
    }

    [Fact]
    public void FSE2_OFFICIALTEST_plan_rejects_caller_endpoint_provider_secret_certificate_and_principal_selectors()
    {
        string text = PlanJson().Replace("\"expectedBindingRevision\":null", "\"expectedBindingRevision\":null,\"principal\":\"caller\",\"certificateBinding\":\"caller\",\"path\":\"/caller\",\"headers\":{\"Host\":\"caller\"}", StringComparison.Ordinal);
        Fse2OfficialTestOperationalizationException error = Assert.Throws<Fse2OfficialTestOperationalizationException>(() =>
            Fse2OfficialTestOperationalization.ParsePlan(Encoding.UTF8.GetBytes(text)));
        Assert.Equal("FSE2_OFFICIALTEST_PLAN_PROPERTY_DENIED", error.SafeCode);
    }

    [Fact]
    public void FSE2_OFFICIALTEST_application_identity_is_source_owned_and_matches_product_company_and_version()
    {
        Fse2OfficialTestCompiledConfiguration compiled = Compile();
        using JsonDocument definition = JsonDocument.Parse(compiled.CanonicalDefinition);
        JsonElement extension = Assert.Single(definition.RootElement.GetProperty("operations").EnumerateArray())
            .GetProperty("extensionConfiguration");
        Assert.Equal("secure-integration-platform", extension.GetProperty("applicationId").GetString());
        Assert.Equal("ApoCert S.r.l.", extension.GetProperty("applicationVendor").GetString());
        Assert.Equal("0.1.0-alpha.1", extension.GetProperty("applicationVersion").GetString());
        Assert.Equal(Fse2OfficialTestCanonicalDefinition.ApplicationId, extension.GetProperty("applicationId").GetString());

        XDocument properties = XDocument.Load(Path.Combine(FindRepositoryRoot(), "Directory.Build.props"));
        Assert.Equal(Fse2OfficialTestCanonicalDefinition.ApplicationVendor,
            properties.Descendants("Company").Single().Value);
        Assert.Equal(Fse2OfficialTestCanonicalDefinition.ApplicationVersion,
            properties.Descendants("ProductVersion").Single().Value);
    }

    [Fact]
    public void FSE2_OFFICIALTEST_caller_cannot_override_server_owned_application_identity()
    {
        string text = PlanJson().Replace(
            "\"expectedBindingRevision\":null",
            "\"expectedBindingRevision\":null,\"applicationId\":\"caller\",\"applicationVendor\":\"caller\",\"applicationVersion\":\"9.9.9\"",
            StringComparison.Ordinal);
        Fse2OfficialTestOperationalizationException error = Assert.Throws<Fse2OfficialTestOperationalizationException>(() =>
            Fse2OfficialTestOperationalization.ParsePlan(Encoding.UTF8.GetBytes(text)));
        Assert.Equal("FSE2_OFFICIALTEST_PLAN_PROPERTY_DENIED", error.SafeCode);
    }

    [Fact]
    public void FSE2_OFFICIALTEST_Admin_API_provider_authority_requires_exact_unique_active_same_environment_public_identity()
    {
        Fse2OfficialTestOperationalPlan plan = Plan();
        Fse2OfficialTestProviderCatalogResource a1 = Catalog(plan.EnvironmentId, plan.A1, 'A', "A1 Synthetic Client", 'C');
        Fse2OfficialTestProviderCatalogResource s1 = Catalog(plan.EnvironmentId, plan.S1, 'B', "S1 Synthetic Signing", 'D');
        Fse2OfficialTestResolvedProviderAuthority authority =
            Fse2OfficialTestOperationalization.ResolveProviderAuthority(plan, [a1, s1]);
        Assert.Equal(a1.SubjectPublicKeyInfoSha256, authority.A1.SubjectPublicKeyInfoSha256);
        Assert.Equal(s1.CatalogChecksumSha256, authority.S1.CatalogChecksumSha256);

        AssertAuthorityFailure(plan, [s1], "FSE2_OFFICIALTEST_A1_PROVIDER_AUTHORITY_MISSING");
        AssertAuthorityFailure(plan, [a1, a1, s1], "FSE2_OFFICIALTEST_A1_PROVIDER_AUTHORITY_AMBIGUOUS");
        AssertAuthorityFailure(plan, [a1 with { Status = "Disabled" }, s1], "FSE2_OFFICIALTEST_A1_PROVIDER_AUTHORITY_INACTIVE");
        AssertAuthorityFailure(plan, [a1 with { EnvironmentId = Guid.NewGuid() }, s1], "FSE2_OFFICIALTEST_A1_PROVIDER_AUTHORITY_MISMATCH");
        AssertAuthorityFailure(plan, [a1 with { ResourceType = "Secret" }, s1], "FSE2_OFFICIALTEST_A1_PROVIDER_AUTHORITY_MISMATCH");
        AssertAuthorityFailure(plan, [a1 with { Version = "wrong" }, s1], "FSE2_OFFICIALTEST_A1_PROVIDER_AUTHORITY_MISMATCH");
        AssertAuthorityFailure(plan, [a1 with { CatalogRevision = a1.CatalogRevision + 1 }, s1], "FSE2_OFFICIALTEST_A1_PROVIDER_AUTHORITY_MISMATCH");
        AssertAuthorityFailure(plan, [a1 with { PublicMetadataRevision = a1.PublicMetadataRevision + 1 }, s1], "FSE2_OFFICIALTEST_A1_PROVIDER_AUTHORITY_MISMATCH");
        AssertAuthorityFailure(plan, [a1 with { ConnectorScope = "foreign" }, s1], "FSE2_OFFICIALTEST_A1_PROVIDER_AUTHORITY_MISMATCH");
        AssertAuthorityFailure(plan, [a1 with { SubjectPublicKeyInfoSha256 = null }, s1], "FSE2_OFFICIALTEST_A1_PROVIDER_PUBLIC_METADATA_INVALID");
        AssertAuthorityFailure(plan, [a1 with { CatalogChecksumSha256 = new string('0', 64) }, s1], "FSE2_OFFICIALTEST_A1_PROVIDER_PUBLIC_METADATA_INVALID");
        AssertAuthorityFailure(plan, [a1 with { SubjectPublicKeyInfoSha256 = new string('0', 64) }, s1], "FSE2_OFFICIALTEST_A1_PROVIDER_PUBLIC_METADATA_INVALID");
        AssertAuthorityFailure(plan, [a1 with { SubjectCommonName = "wrong^common-name" }, s1], "FSE2_OFFICIALTEST_A1_PROVIDER_PUBLIC_METADATA_INVALID");
        Assert.Equal(Fse2OfficialTestSideEffectCounters.Zero, Fse2OfficialTestOperationalization.Plan(plan).Counters);
    }

    [Fact]
    public void FSE2_OFFICIALTEST_ARCH_external_metadata_file_or_mismatch_cannot_be_authority_and_Admin_API_catalog_is_required()
    {
        string root = FindRepositoryRoot();
        string source = File.ReadAllText(Path.Combine(root, "tools", "fse2", "OfficialTestProvisioner", "Program.cs"));
        string api = File.ReadAllText(Path.Combine(root, "src", "Gateway", "Gateway.Api", "Program.cs"));

        Assert.Contains("admin/api/v1/provider-resources:resolve?environmentId=", source, StringComparison.Ordinal);
        Assert.DoesNotContain("admin/api/v1/provider-resources?environmentId=", source, StringComparison.Ordinal);
        Assert.Contains("FindExactProviderResourcesAsync", api, StringComparison.Ordinal);
        Assert.Contains("ResolveProviderAuthority", source, StringComparison.Ordinal);
        Assert.Contains("RequirePublicAuthorityCurrentAsync", source, StringComparison.Ordinal);
        Assert.DoesNotContain("server-public-metadata.json", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ReadPublicMetadata", source, StringComparison.Ordinal);
        Assert.DoesNotContain("PublicMetadataPath", source, StringComparison.Ordinal);
        Assert.Contains("SubjectPublicKeyInfoSha256", api, StringComparison.Ordinal);
        Assert.Contains("CertificateSubjectCommonName", api, StringComparison.Ordinal);
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

    private static Fse2OfficialTestProviderCatalogResource Catalog(
        Guid environmentId,
        Fse2OfficialTestProviderReference reference,
        char spki,
        string commonName,
        char checksum) => new(
            reference.ProviderId,
            reference.ResourceId,
            reference.Version,
            reference.CatalogRevision,
            reference.PublicMetadataRevision,
            environmentId,
            "ClientCertificate",
            "Active",
            Fse2OfficialTestCanonicalDefinition.ConnectorId,
            Fse2OfficialTestCanonicalDefinition.OperationId,
            new string(checksum, 64),
            new string(spki, 64),
            commonName);

    private static void AssertAuthorityFailure(
        Fse2OfficialTestOperationalPlan plan,
        IEnumerable<Fse2OfficialTestProviderCatalogResource> resources,
        string expectedCode)
    {
        Fse2OfficialTestOperationalizationException error = Assert.Throws<Fse2OfficialTestOperationalizationException>(() =>
            Fse2OfficialTestOperationalization.ResolveProviderAuthority(plan, resources));
        Assert.Equal(expectedCode, error.SafeCode);
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Directory.Build.props"))) return current.FullName;
            current = current.Parent;
        }
        throw new InvalidOperationException("Repository root was not found.");
    }

    private static Fse2OfficialTestOperationalPlan Plan() =>
        Fse2OfficialTestOperationalization.ParsePlan(Encoding.UTF8.GetBytes(PlanJson()));

    private static string PlanJson() => """
        {
          "schemaVersion":"1.0",
          "tenantId":"22222222-2222-2222-2222-222222222222",
          "installationId":"33333333-3333-3333-3333-333333333333",
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

using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecureIntegration.Gateway.Application;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Tests;

public sealed class Fse2FoundationTests
{
    [Fact]
    public void FSE2_OPS_frozen_matrix_and_retry_policy_are_exact()
    {
        Assert.Equal(11, Fse2OperationCatalog.All.Length);
        Assert.Equal(9, Fse2OperationCatalog.All.Count(value => value.Availability == Fse2OperationAvailability.ProductionAvailable));
        Assert.Equal(2, Fse2OperationCatalog.All.Count(value => value.Availability == Fse2OperationAvailability.TestOnlyOfficial));
        Assert.All(Fse2OperationCatalog.All.Where(value => value.Operation is Fse2Operation.GetStatusByWorkflow or Fse2Operation.GetStatusByTrace),
            value => Assert.Equal(Fse2RetryClass.SafeRetry, value.RetryClass));
    }

    [Theory]
    [InlineData(Fse2Operation.ValidateCda, "POST", "/documents/validation", "TREATMENT", "CREATE")]
    [InlineData(Fse2Operation.Create, "POST", "/documents", "TREATMENT", "CREATE")]
    [InlineData(Fse2Operation.Replace, "PUT", "/documents/{document-id}", "UPDATE", "UPDATE")]
    [InlineData(Fse2Operation.Delete, "DELETE", "/documents/{document-id}", "UPDATE", "DELETE")]
    [InlineData(Fse2Operation.UpdateMetadataChainConcealment, "PUT", "/documents/{document-id}/metadata-oscuramento-catena", "ACCESS UPDATE", "UPDATE")]
    public void FSE2_CLAIMS_role_purpose_action_matrix_is_frozen(
        Fse2Operation operation,
        string method,
        string path,
        string purpose,
        string action)
    {
        Fse2OperationDescriptor descriptor = Fse2OperationCatalog.Get(operation);
        Assert.Equal(method, descriptor.Method.Method);
        Assert.Equal(path, descriptor.PathTemplate);
        Assert.Equal(purpose, Fse2OperationCatalog.ClaimValue(descriptor.PurposeOfUse!.Value));
        Assert.Equal(action, Fse2OperationCatalog.ClaimValue(descriptor.Action!.Value));
        Fse2OperationCatalog.ValidateOrganizationCombination("DAP", descriptor.OperationId, descriptor.PurposeOfUse.Value, descriptor.Action.Value);
    }

    [Fact]
    public void FSE2_MODULE_registers_one_minimal_mTLS_strategy_through_public_contracts()
    {
        RecordingRegistrar registrar = new();
        Fse2OrganizationExecutionModule module = new();
        module.RegisterExecutionStrategies(registrar);
        Fse2OrganizationExecutionStrategy strategy = new(new InMemoryFse2WorkflowCorrelationStore());

        Assert.Equal("healthcare-fse2", module.Id.Value);
        Assert.Equal([typeof(IFse2WorkflowCorrelationStore), typeof(InMemoryFse2WorkflowCorrelationStore)], registrar.Singleton);
        Assert.Equal(typeof(Fse2OrganizationExecutionStrategy), registrar.Strategy);
        Assert.Equal(typeof(Fse2OrganizationPublishedOperationExpectationProvider), registrar.ExpectationProvider);
        Assert.Equal("healthcare-fse2-organization", strategy.Key.Value);
        Assert.Equal([GatewayAuthenticationKind.MutualTls], strategy.SupportedAuthenticationKinds);
    }

    [Fact]
    public void FSE2_PROFILE_exact_Published_organization_projection_builds_canonical_subject_and_slots()
    {
        Fse2PublishedOrganizationProfile profile = Fse2PublishedOrganizationProfile.ParseJson(Profile(), "create");

        Assert.Equal("12345678903^^^&2.16.840.1.113883.2.9.4.1.2&ISO", profile.SubjectCx);
        Assert.Equal("DAP", profile.SubjectRole);
        Assert.Equal("authorization", profile.AuthorizationSigningSlot.Value);
        Assert.Equal("integrity", profile.IntegritySigningSlot.Value);
        Assert.Equal("create", profile.Operation.OperationId);
        Assert.Equal("https://fse2.synthetic.test/gateway/v1", profile.Audience);
        Assert.Equal(64, profile.SharedOrganizationProfileChecksumSha256.Length);
        Assert.Equal(64, profile.OperationProfileChecksumSha256.Length);
        Assert.NotEqual(profile.SharedOrganizationProfileChecksumSha256, profile.OperationProfileChecksumSha256);
    }

    [Theory]
    [InlineData("\"subjectRole\":\"DAP\"", "\"subjectRole\":\"PATIENT\"")]
    [InlineData("\"environmentClass\":\"synthetic\"", "\"environmentClass\":\"invalid\"")]
    public void FSE2_PROFILE_role_operation_and_environment_substitution_are_denied(string expected, string replacement) =>
        Assert.Throws<Fse2ConnectorException>(() =>
            Fse2PublishedOrganizationProfile.ParseJson(Encoding.UTF8.GetBytes(ProfileText().Replace(expected, replacement, StringComparison.Ordinal)), "create"));

    [Fact]
    public void FSE2_PROFILE_unknown_privileged_property_is_denied()
    {
        string tampered = ProfileText().Replace("{", "{\"issuer\":\"caller\",", StringComparison.Ordinal);
        Assert.Throws<Fse2ConnectorException>(() => Fse2PublishedOrganizationProfile.ParseJson(Encoding.UTF8.GetBytes(tampered), "create"));
    }

    [Theory]
    [InlineData("operationId", "create")]
    [InlineData("method", "POST")]
    [InlineData("relativePath", "documents")]
    [InlineData("requestContentType", "application/json")]
    [InlineData("resourceIdentifier", "document")]
    [InlineData("multipartBoundary", "broker-gateway-fse2-v1")]
    [InlineData("authorizationSigningSlot", "authorization")]
    public void FSE2_PROFILE_operation_routing_and_signing_authority_in_extension_is_denied(string name, string value)
    {
        string tampered = ProfileText().Replace("{", $$"""{"{{name}}":"{{value}}",""", StringComparison.Ordinal);
        Assert.Throws<Fse2ConnectorException>(() =>
            Fse2PublishedOrganizationProfile.ParseJson(Encoding.UTF8.GetBytes(tampered), "create"));
    }

    [Fact]
    public void FSE2_PROFILE_shared_checksum_is_stable_across_operations_while_operation_checksum_is_distinct()
    {
        Fse2PublishedOrganizationProfile create = Fse2PublishedOrganizationProfile.ParseJson(Profile(), "create");
        Fse2PublishedOrganizationProfile status = Fse2PublishedOrganizationProfile.ParseJson(Profile(), "get-status-by-workflow");
        Assert.Equal(create.SharedOrganizationProfileChecksumSha256, status.SharedOrganizationProfileChecksumSha256);
        Assert.NotEqual(create.OperationProfileChecksumSha256, status.OperationProfileChecksumSha256);
        Assert.Equal(create.OperationProfileChecksumSha256,
            status.CalculateOperationProfileChecksum(Fse2OperationCatalog.Get(Fse2Operation.Create)));
    }

    [Fact]
    public void FSE2_PROFILE_checksums_are_canonical_and_shared_authority_changes_are_fail_closed()
    {
        Fse2PublishedOrganizationProfile exact = Fse2PublishedOrganizationProfile.ParseJson(Profile(), "create");
        JsonObject reordered = JsonNode.Parse(ProfileText())!.AsObject();
        JsonNode profileName = reordered["profile"]!.DeepClone();
        Assert.True(reordered.Remove("profile"));
        reordered.Add("profile", profileName);
        Fse2PublishedOrganizationProfile canonical = Fse2PublishedOrganizationProfile.ParseJson(
            Encoding.UTF8.GetBytes(reordered.ToJsonString()), "create");
        Assert.Equal(exact.SharedOrganizationProfileChecksumSha256, canonical.SharedOrganizationProfileChecksumSha256);
        Assert.Equal(exact.OperationProfileChecksumSha256, canonical.OperationProfileChecksumSha256);

        byte[] changedProfile = Encoding.UTF8.GetBytes(ProfileText().Replace(
            "\"applicationVersion\":\"1.0.0\"", "\"applicationVersion\":\"1.0.1\"", StringComparison.Ordinal));
        Fse2PublishedOrganizationProfile changed = Fse2PublishedOrganizationProfile.ParseJson(changedProfile, "create");
        Assert.NotEqual(exact.SharedOrganizationProfileChecksumSha256, changed.SharedOrganizationProfileChecksumSha256);
        Assert.NotEqual(exact.OperationProfileChecksumSha256, changed.OperationProfileChecksumSha256);
    }

    [Theory]
    [InlineData("validate-fhir")]
    [InlineData("update-metadata-chain-concealment")]
    public void FSE2_PROFILE_test_only_operations_are_denied_in_production(string operationId)
    {
        byte[] production = Encoding.UTF8.GetBytes(ProfileText().Replace(
            "\"environmentClass\":\"synthetic\"", "\"environmentClass\":\"production\"", StringComparison.Ordinal));
        Assert.Throws<Fse2ConnectorException>(() => Fse2PublishedOrganizationProfile.ParseJson(production, operationId));
    }

    [Fact]
    public async Task FSE2_WORKFLOW_correlation_is_bound_to_every_shared_authority_dimension()
    {
        InMemoryFse2WorkflowCorrelationStore store = new();
        Guid tenant = Guid.NewGuid();
        Guid application = Guid.NewGuid();
        Guid installation = Guid.NewGuid();
        Guid environment = Guid.NewGuid();
        Fse2WorkflowAuthorityScope exact = new(
            tenant, application, installation, environment, "1.0.0", "fse2", new string('a', 64));
        Fse2WorkflowRecord record = new(
            exact,
            Fse2Operation.Create,
            "create",
            Fse2Action.Create,
            Fse2PurposeOfUse.Treatment,
            new string('b', 64),
            "workflow-1",
            "trace-1");
        await store.RecordAsync(Guid.NewGuid(), record, TestContext.Current.CancellationToken);
        Assert.Equal(record, await store.ResolveAsync(
            exact, Fse2Operation.GetStatusByWorkflow, "workflow-1", TestContext.Current.CancellationToken));
        Assert.Equal(record, await store.ResolveAsync(
            exact, Fse2Operation.GetStatusByTrace, "trace-1", TestContext.Current.CancellationToken));

        Fse2WorkflowAuthorityScope[] denied =
        [
            exact with { TenantId = Guid.NewGuid() },
            exact with { ApplicationId = Guid.NewGuid() },
            exact with { InstallationId = Guid.NewGuid() },
            exact with { EnvironmentId = Guid.NewGuid() },
            exact with { ConnectorVersion = "2.0.0" },
            exact with { ConnectorId = "other-fse2" },
            exact with { SharedOrganizationProfileChecksumSha256 = new string('c', 64) }
        ];
        foreach (Fse2WorkflowAuthorityScope scope in denied)
            await Assert.ThrowsAsync<Fse2ConnectorException>(() => store.ResolveAsync(
                scope, Fse2Operation.GetStatusByWorkflow, "workflow-1", TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<Fse2ConnectorException>(() => store.ResolveAsync(
            exact, Fse2Operation.GetStatusByWorkflow, "unknown", TestContext.Current.CancellationToken));
    }

    [Fact]
    public void FSE2_REQUEST_surface_has_no_actor_policy_endpoint_or_authentication_selector()
    {
        string[] properties = typeof(Fse2Request).GetProperties(BindingFlags.Instance | BindingFlags.Public).Select(value => value.Name).ToArray();
        string[] forbidden = ["Subject", "OrganizationIdentifier", "Vat", "Role", "Purpose", "Action", "Endpoint", "PathParameter", "Algorithm", "Issuer", "Audience", "X5c", "Certificate", "SigningSlot", "Provider", "UseSubjectAsAuthor"];
        Assert.DoesNotContain(properties, property => forbidden.Any(value => property.Contains(value, StringComparison.OrdinalIgnoreCase)));
        Assert.Empty(typeof(AuthorizedConnectorSignedToken).GetProperties(BindingFlags.Instance | BindingFlags.Public));
        Assert.Throws<Fse2ConnectorException>(() => Fse2OperationCatalog.GetClaimAuthority("use_subject_as_author"));
    }

    [Fact]
    public void FSE2_REQUEST_serialization_snapshots_business_input_and_excludes_privileged_fields()
    {
        byte[] document = [0x00, 0x0d, 0x0a, 0xff];
        Fse2Request request = Fse2Request.Create(document, "{\"metadata\":true}"u8.ToArray(), Claims());
        byte[] payload = request.SerializeAuthorizedPayload();
        document[0] = 0x7f;

        using JsonDocument parsed = JsonDocument.Parse(payload);
        Assert.Equal(0x00, Convert.FromBase64String(parsed.RootElement.GetProperty("documentBase64").GetString()!)[0]);
        Assert.False(parsed.RootElement.TryGetProperty("subject", out _));
        Assert.False(parsed.RootElement.TryGetProperty("issuer", out _));
        Assert.False(parsed.RootElement.TryGetProperty("role", out _));
        Assert.False(parsed.RootElement.TryGetProperty("endpoint", out _));
    }

    [Theory]
    [InlineData("attachment_hash")]
    [InlineData("attachmentHash")]
    [InlineData("attachment_hash_algorithm")]
    [InlineData("attachmentHashAlgorithm")]
    [InlineData("attachment_hash_input")]
    [InlineData("attachmentHashInput")]
    public void FSE2_SEC_request_body_attachment_hash_authority_is_denied(string propertyName)
    {
        byte[] requestBody = Encoding.UTF8.GetBytes($$"""{"metadata":true,"{{propertyName}}":"caller"}""");

        ArgumentException denied = Assert.Throws<ArgumentException>(() =>
            Fse2Request.Create(new byte[] { 0x01 }, requestBody, Claims()));

        Assert.Contains("FSE2_REQUEST_BODY_INVALID", denied.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("3.1")]
    [InlineData("1.40")]
    [InlineData("0.40")]
    [InlineData("1.01")]
    [InlineData("1..2")]
    [InlineData("1.-1")]
    [InlineData("1.a")]
    [InlineData("")]
    [InlineData("1")]
    public void FSE2_OID_semantically_invalid_vectors_are_denied(string value) =>
        Assert.ThrowsAny<ArgumentException>(() => Fse2Validation.ValidateOid(value));

    [Theory]
    [InlineData("0.0")]
    [InlineData("0.39")]
    [InlineData("1.39")]
    [InlineData("2.40")]
    [InlineData("2.999999999999999999999999999999999999999")]
    [InlineData("2.16.840.1.113883.2.9.4.1.2")]
    public void FSE2_OID_valid_canonical_vectors_pass(string value) => Assert.Equal(value, Fse2Validation.ValidateOid(value));

    [Fact]
    public void FSE2_CX_XON_canonical_organization_and_person_values_pass_and_malformed_values_fail()
    {
        string organization = Fse2IheFormatter.FormatOrganizationCx("12345678903", "2.16.840.1.113883.2.9.4.1.2");
        string person = Fse2IheFormatter.FormatPersonCx("RSSMRA80A01H501U", "2.16.840.1.113883.2.9.4.3.2");
        string locality = Fse2IheFormatter.FormatLocalityXon("ASL Roma 1", "2.16.840.1.113883.2.9.4.1.2", "ASLROMA1");
        Fse2IheFormatter.ValidateCx(organization, organization: true);
        Fse2IheFormatter.ValidateCx(person, organization: false);
        Fse2IheFormatter.ValidateXon(locality);
        Assert.ThrowsAny<ArgumentException>(() => Fse2IheFormatter.ValidateCx(organization + "^", organization: true));
        Assert.ThrowsAny<ArgumentException>(() => Fse2IheFormatter.ValidateXon(locality.Replace("ISO", "DNS", StringComparison.Ordinal)));
    }

    [Fact]
    public void FSE2_HASH_validate_cda_omits_claim_and_publication_uses_exact_input_file_bytes_not_multipart()
    {
        byte[] exact = [0x00, 0x0d, 0x0a, 0xc3, 0xa8, 0xff];
        byte[] multipartEnvelope = [0x2d, 0x2d, 0x62, 0x0d, 0x0a, .. exact, 0x0d, 0x0a, 0x2d, 0x2d, 0x62, 0x2d, 0x2d];
        Assert.Equal("50f0a4377f9046168548c11702a121faaa42eae07548682170d6e7202eb80124", Fse2Validation.ComputeAttachmentHash(exact));
        Assert.NotEqual(Fse2Validation.ComputeAttachmentHash(exact),
            Fse2Validation.ComputeAttachmentHash(exact.AsMemory(0, exact.Length - 1)));
        Assert.NotEqual(Fse2Validation.ComputeAttachmentHash(exact), Fse2Validation.ComputeAttachmentHash(multipartEnvelope));
        Assert.False(Fse2OperationCatalog.Get(Fse2Operation.ValidateCda).RequiresAttachmentHash);
        Assert.True(Fse2OperationCatalog.Get(Fse2Operation.Create).RequiresAttachmentHash);
        Assert.True(Fse2OperationCatalog.Get(Fse2Operation.Replace).RequiresAttachmentHash);
    }

    [Fact]
    public void FSE2_ERROR_RFC7807_mapper_retains_only_safe_code()
    {
        const string canary = "clinical-payload-redaction-canary";
        byte[] problem = Encoding.UTF8.GetBytes($$"""{"type":"https://errors.example/FSE2_DOCUMENT_REJECTED","detail":"{{canary}}"}""");
        Fse2ConnectorException error = Fse2ResponseMapper.MapProblem(
            new(400, "application/problem+json", problem), Fse2RetryClass.NoAutomaticRetry);
        Assert.Equal("FSE2_DOCUMENT_REJECTED", error.SafeCode);
        Assert.DoesNotContain(canary, error.ToString(), StringComparison.Ordinal);
    }

    private static Fse2ClinicalClaims Claims() => Fse2ClinicalClaims.CreatePerson(
        "RSSMRA80A01H501U",
        "2.16.840.1.113883.2.9.4.3.2",
        true,
        "('11502-2^^2.16.840.1.113883.6.1')");

    private static byte[] Profile() => Encoding.UTF8.GetBytes(ProfileText());

    private static string ProfileText() => """
        {
          "profile":"fse2-organization-v1",
          "environmentClass":"synthetic",
          "organizationIdentifier":"12345678903",
          "organizationAssigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2",
          "organizationDescription":"ASL Roma 1",
          "organizationDomainId":"asl-roma-1",
          "localityName":"ASL Roma 1",
          "localityAssigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2",
          "localityCode":"ASLROMA1",
          "subjectRole":"DAP",
          "applicationId":"broker-gateway",
          "applicationVendor":"Secure Integration",
          "applicationVersion":"1.0.0",
          "maximumDocumentBytes":1048576
        }
        """;

    private sealed class RecordingRegistrar : IConnectorExecutionStrategyRegistrar
    {
        internal Type[]? Singleton { get; private set; }
        internal Type? Strategy { get; private set; }
        internal Type? ExpectationProvider { get; private set; }

        public void AddSingleton<TService>() where TService : class => Singleton = [typeof(TService)];
        public void AddSingleton<TService, TImplementation>() where TService : class where TImplementation : class, TService =>
            Singleton = [typeof(TService), typeof(TImplementation)];
        public void AddStrategy<TStrategy>() where TStrategy : class, IConnectorExecutionStrategy => Strategy = typeof(TStrategy);
        public void AddTypedSessionHandshakeRequestAdapter<TAdapter>() where TAdapter : class => throw new NotSupportedException();
        public void AddTypedSessionHandshakeResponseAdapter<TAdapter>() where TAdapter : class => throw new NotSupportedException();
        public void AddExternalSessionValidationAdapter<TAdapter>() where TAdapter : class => throw new NotSupportedException();
        public void AddTypedComposedSoapRequestAdapter<TAdapter>() where TAdapter : class => throw new NotSupportedException();
        public void AddAuthorizedPublishedOperationExpectationProvider<TProvider>()
            where TProvider : class, IAuthorizedPublishedOperationExpectationProvider => ExpectationProvider = typeof(TProvider);
    }
}

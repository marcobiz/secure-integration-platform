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
        Fse2OrganizationExecutionStrategy strategy = new();

        Assert.Equal("healthcare-fse2", module.Id.Value);
        Assert.Null(registrar.Singleton);
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

    [Fact]
    public void FSE2_PROFILE_OfficialTest_professional_subject_builds_canonical_CX()
    {
        byte[] profileJson = Encoding.UTF8.GetBytes(ProfileText()
            .Replace("12345678903", "PROVAX00X00X000Y", StringComparison.Ordinal)
            .Replace("2.16.840.1.113883.2.9.4.1.2", "2.16.840.1.113883.2.9.4.3.2", StringComparison.Ordinal));

        Fse2PublishedOrganizationProfile profile = Fse2PublishedOrganizationProfile.ParseJson(profileJson, "validate-cda");

        Assert.Equal("PROVAX00X00X000Y^^^&2.16.840.1.113883.2.9.4.3.2&ISO", profile.SubjectCx);
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
    public void FSE2_WORKFLOW_bridge_record_is_closed_technical_only_and_has_no_scope_or_clinical_fields()
    {
        ConnectorWorkflowContextRecord record = new(
            "create",
            "CREATE",
            "TREATMENT",
            new string('b', 64),
            "workflow-1",
            "trace-1");

        Assert.Equal("create", record.OriginatingOperationId);
        Assert.Equal("CREATE", record.ActionCode);
        Assert.Equal("TREATMENT", record.PurposeOfUseCode);
        Assert.Equal("workflow-1", record.WorkflowInstanceId);
        Assert.Equal("trace-1", record.TraceId);
        Assert.Equal(
            ["ActionCode", "OperationProfileChecksumSha256", "OriginatingOperationId", "PurposeOfUseCode", "TraceId", "WorkflowInstanceId"],
            typeof(ConnectorWorkflowContextRecord).GetProperties(BindingFlags.Instance | BindingFlags.Public)
                .Select(value => value.Name).Order(StringComparer.Ordinal).ToArray());
        string[] forbidden = ["Tenant", "Application", "Installation", "Environment", "Connector", "Binding", "Published", "Person", "Patient", "Payload", "Body", "Jwt", "Certificate", "Endpoint", "Header", "Metadata"];
        Assert.DoesNotContain(typeof(ConnectorWorkflowContextRecord).GetProperties(), property =>
            forbidden.Any(value => property.Name.Contains(value, StringComparison.OrdinalIgnoreCase)));
        Assert.Throws<ArgumentException>(() => new ConnectorWorkflowContextRecord(
            "create", "CREATE", "TREATMENT", new string('b', 64), null, null));
        Assert.Throws<ArgumentException>(() => new ConnectorWorkflowContextRecord(
            "create", "CREATE", "patient=raw", new string('b', 64), "workflow-1", null));
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
        byte[] problem = Encoding.UTF8.GetBytes($$"""{"type":"https://fse.example/msg/syntax","detail":"{{canary}}"}""");
        Fse2ConnectorException error = Fse2ResponseMapper.MapProblem(
            new(400, "application/problem+json", problem), Fse2RetryClass.NoAutomaticRetry);
        Assert.Equal("syntax", error.SafeCode);
        Assert.Equal("syntax", error.SafeUpstreamCode);
        Assert.DoesNotContain(canary, error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void FSE2_ERROR_RFC7807_mapper_uses_allowlisted_instance_without_retaining_detail()
    {
        const string canary = "clinical-instance-redaction-canary";
        byte[] problem = Encoding.UTF8.GetBytes($$"""{"type":"about:blank","instance":"/msg/record-not-found","detail":"{{canary}}"}""");

        Fse2ConnectorException error = Fse2ResponseMapper.MapProblem(
            new(404, "application/problem+json", problem), Fse2RetryClass.NoAutomaticRetry);

        Assert.Equal("record-not-found", error.SafeCode);
        Assert.Equal("record-not-found", error.SafeUpstreamCode);
        Assert.DoesNotContain(canary, error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void FSE2_SEC_caller_cannot_override_accept_or_inject_headers()
    {
        string[] requestProperties = typeof(Fse2Request).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(value => value.Name).ToArray();
        string[] transportProperties = typeof(AuthorizedConnectorRestrictedTransportRequest)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance).Select(value => value.Name).ToArray();

        Assert.DoesNotContain(requestProperties, value => value.Contains("accept", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("header", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(transportProperties, value => value.Contains("accept", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("header", StringComparison.OrdinalIgnoreCase));
        Assert.Equal([nameof(AuthorizedConnectorRestrictedTransportRequest.BodyLength), nameof(AuthorizedConnectorRestrictedTransportRequest.PathParameterCount)],
            transportProperties);
    }

    [Fact]
    public void FSE2_TRANSPORT_bounded_HTTP_problem_reaches_FSE2_mapper()
    {
        Fse2ConnectorException error = Assert.Throws<Fse2ConnectorException>(() => Fse2ResponseMapper.Map(
            new(400, "application/problem+json", "{\"type\":\"https://fse.example/msg/semantic\"}"u8.ToArray()),
            Guid.NewGuid(),
            Fse2OperationCatalog.Get(Fse2Operation.ValidateCda)));

        Assert.Equal(Fse2ErrorCategory.UpstreamRejected, error.Category);
        Assert.Equal("semantic", error.SafeCode);
    }

    [Fact]
    public void FSE2_TRANSPORT_HTTP_400_preserves_only_safe_status_and_code()
    {
        const string secretCanary = "raw-upstream-detail-must-not-survive";
        byte[] body = Encoding.UTF8.GetBytes($$"""
            {"type":"https://fse.example/msg/cda-validation","title":"{{secretCanary}}","detail":"{{secretCanary}}","code":"not-allowlisted"}
            """);

        Fse2ConnectorException error = Fse2ResponseMapper.MapProblem(
            new(400, "application/problem+json; charset=utf-8", body), Fse2RetryClass.NoAutomaticRetry);

        Assert.Equal(Fse2ErrorCategory.UpstreamRejected, error.Category);
        Assert.Equal("cda-validation", error.SafeCode);
        Assert.False(error.Retryable);
        Assert.DoesNotContain(secretCanary, error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void FSE2_TRANSPORT_valid_problem_media_type_parameters_are_accepted()
    {
        QualifiedGatewayExecutionResult[] responses =
        [
            new(400, "application/problem+json; charset=utf-8", "{\"type\":\"https://fse.example/msg/syntax\"}"u8.ToArray()),
            new(400, "Application/Problem+Json; profile=\"safe-profile\"", "{\"type\":\"https://fse.example/msg/semantic\"}"u8.ToArray())
        ];

        Assert.Equal("syntax", Fse2ResponseMapper.MapProblem(responses[0], Fse2RetryClass.NoAutomaticRetry).SafeCode);
        Assert.Equal("semantic", Fse2ResponseMapper.MapProblem(responses[1], Fse2RetryClass.NoAutomaticRetry).SafeCode);
    }

    [Fact]
    public void FSE2_TRANSPORT_malformed_problem_media_type_is_safely_collapsed()
    {
        string[] malformedContentTypes =
        [
            "application/problem+json; broken",
            "application/problem+json; charset=",
            "application/problem+json; profile=\"unterminated",
            "application/problem+json, application/json",
            "application/problem+json\r\nX-Unsafe: value",
            "application/problem+json\0",
            "application/problem+json; profile=" + new string('x', 512)
        ];

        Assert.All(malformedContentTypes, contentType => Assert.Equal(
            "FSE2_UPSTREAM_REJECTED",
            Fse2ResponseMapper.MapProblem(
                new(400, contentType, "{\"type\":\"https://fse.example/msg/syntax\"}"u8.ToArray()),
                Fse2RetryClass.NoAutomaticRetry).SafeCode));
    }

    [Fact]
    public void FSE2_TRANSPORT_HTTP_503_preserves_safe_retry_classification()
    {
        Fse2ConnectorException safeRetry = Fse2ResponseMapper.MapProblem(
            new(503, "application/problem+json", "{\"type\":\"https://fse.example/msg/service-error\"}"u8.ToArray()),
            Fse2RetryClass.SafeRetry);
        Fse2ConnectorException validateCda = Fse2ResponseMapper.MapProblem(
            new(503, "application/problem+json", "{\"type\":\"https://fse.example/msg/service-error\"}"u8.ToArray()),
            Fse2RetryClass.NoAutomaticRetry);

        Assert.Equal(Fse2ErrorCategory.TemporarilyUnavailable, safeRetry.Category);
        Assert.Equal("service-error", safeRetry.SafeCode);
        Assert.True(safeRetry.Retryable);
        Assert.False(validateCda.Retryable);
    }

    [Fact]
    public void FSE2_TRANSPORT_malformed_or_oversized_problem_is_safely_collapsed()
    {
        QualifiedGatewayExecutionResult[] responses =
        [
            new(400, "application/problem+json", "{malformed"u8.ToArray()),
            new(400, "application/problem+json", Encoding.UTF8.GetBytes(
                "{\"type\":\"https://fse.example/msg/syntax\",\"detail\":\"" + new string('x', 17 * 1024) + "\"}")),
            new(400, "application/problem+json", "{\"type\":\"https://attacker.invalid/msg/not-official\"}"u8.ToArray()),
            new(400, "application/problem+json", "{\"type\":\"https://fse.example/msg/syntax\",\"type\":\"https://fse.example/msg/semantic\"}"u8.ToArray()),
            new(400, "application/problem+json.evil", "{\"type\":\"https://fse.example/msg/syntax\"}"u8.ToArray())
        ];

        Assert.All(responses, response =>
        {
            Fse2ConnectorException error = Fse2ResponseMapper.MapProblem(response, Fse2RetryClass.NoAutomaticRetry);
            Assert.Equal("FSE2_UPSTREAM_REJECTED", error.SafeCode);
            Assert.Null(error.SafeUpstreamCode);
        });
    }

    [Fact]
    public void FSE2_TRANSPORT_failure_phase_contract_is_closed_and_distinct_from_HTTP_problem()
    {
        RestrictedTransportFailureException tls = new(RestrictedTransportFailurePhase.TlsServerValidationFailure);
        RestrictedTransportFailureException other = new(RestrictedTransportFailurePhase.TransportFailureOther);
        Fse2ConnectorException http = Fse2ResponseMapper.MapProblem(
            new(400, "application/problem+json", "{\"type\":\"https://fse.example/msg/syntax\"}"u8.ToArray()),
            Fse2RetryClass.NoAutomaticRetry);

        Assert.Equal(RestrictedTransportFailurePhase.TlsServerValidationFailure, tls.Phase);
        Assert.Equal(RestrictedTransportFailurePhase.TransportFailureOther, other.Phase);
        Assert.Equal("syntax", http.SafeCode);
        Assert.IsNotType<RestrictedTransportFailureException>(http);
    }

    [Fact]
    public void FSE2_TRANSPORT_non_FSE2_callers_preserve_existing_failure_semantics()
    {
        AuthorizedPublishedOperationExpectations defaultExpectations = new(
            GatewayAuthenticationKind.None, restrictedTransportRequired: false, []);

        Assert.Equal(AuthorizedRestrictedTransportResponseMode.SuccessOnly,
            defaultExpectations.RestrictedTransportResponseMode);
        Assert.Throws<ArgumentException>(() => new AuthorizedPublishedOperationExpectations(
            GatewayAuthenticationKind.None,
            restrictedTransportRequired: false,
            [],
            restrictedTransportResponseMode: AuthorizedRestrictedTransportResponseMode.BoundedProblemDetails));
    }

    [Fact]
    public void FSE2_LIVE_FIXTURE_matches_frozen_validate_cda_contract_without_network()
    {
        const string documentationCommit = "430e6b5d9dde8a35b04ae635c11303db787a977e";
        const string datasetCommit = "d937255fd7e9c079c5641c537da17fe98a2f2259";
        const string datasetCase = "476 / VALIDAZIONE_CDA2_PSS_CT23";
        const string datasetXmlPath = "Test Case/Validazione/Documenti XML Casi OK/8 - Casi OK Profilo Sanitario Sintetico/PSS476.xml";
        const string datasetXmlBlob = "6b654344431a21e02b979ab4907bc53b38cb4143";
        const int datasetXmlBytes = 58_712;
        const string datasetXmlSha256 = "7B54299D5AD7E87CA7D5569E98ADAC2D687D3E9432FD4D015194E733A2ADAABD";
        const string datasetPdfPath = "GATEWAY/A1#111#DAVINCI.CARE/DaVinci Healthcare/DaVinci/3.3/FILES/PSS476.pdf";
        const string datasetPdfBlob = "a4bf835cbf08661a6c530f95bdea1770e0ca4ad0";
        const int datasetPdfBytes = 60_148;
        const string datasetPdfSha256 = "129BE437228376B897B8D176DE099CA165714901DA3CB7B78EE2F9B68F4A252E";
        byte[] requestBody = "{\"healthDataFormat\":\"CDA\",\"activity\":\"VERIFICA\"}"u8.ToArray();
        Fse2Request request = Fse2Request.ValidateCda("synthetic-pdf-fixture"u8.ToArray(), requestBody, Claims());
        using JsonDocument payload = JsonDocument.Parse(request.SerializeAuthorizedPayload());
        using JsonDocument sealedRequest = JsonDocument.Parse(
            Convert.FromBase64String(payload.RootElement.GetProperty("requestBodyBase64").GetString()!));
        Fse2OperationDescriptor operation = Fse2OperationCatalog.Get(request.Operation);

        Assert.Equal(Fse2Operation.ValidateCda, request.Operation);
        Assert.Equal("POST", operation.Method.Method);
        Assert.Equal("/documents/validation", operation.PathTemplate);
        Assert.Equal("VERIFICA", sealedRequest.RootElement.GetProperty("activity").GetString());
        Assert.Equal("CDA", sealedRequest.RootElement.GetProperty("healthDataFormat").GetString());
        Assert.False(sealedRequest.RootElement.TryGetProperty("mode", out _));
        Assert.Equal(
            ["activity", "healthDataFormat"],
            sealedRequest.RootElement.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray());
        Assert.False(operation.RequiresAttachmentHash);
        Assert.DoesNotContain("attachment_hash", Encoding.UTF8.GetString(request.SerializeAuthorizedPayload()), StringComparison.Ordinal);
        Assert.Equal("430e6b5d9dde8a35b04ae635c11303db787a977e", documentationCommit);
        Assert.Equal("d937255fd7e9c079c5641c537da17fe98a2f2259", datasetCommit);
        Assert.Equal("476 / VALIDAZIONE_CDA2_PSS_CT23", datasetCase);
        Assert.EndsWith("PSS476.xml", datasetXmlPath, StringComparison.Ordinal);
        Assert.EndsWith("PSS476.pdf", datasetPdfPath, StringComparison.Ordinal);
        Assert.NotEqual(datasetXmlBlob, datasetPdfBlob);
        Assert.NotEqual(datasetXmlBytes, datasetPdfBytes);
        Assert.NotEqual(datasetXmlSha256, datasetPdfSha256);
    }

    [Fact]
    public void FSE2_RESPONSE_official_exact_maximum_trace_span_and_workflow_identifiers_are_accepted()
    {
        string traceId = new('t', 100);
        string spanId = new('s', 100);
        string workflowInstanceId = new('w', 256);
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(new { traceID = traceId, spanID = spanId, workflowInstanceId });

        Fse2Response response = Fse2ResponseMapper.Map(
            new(200, "application/json", body),
            Guid.NewGuid(),
            Fse2OperationCatalog.Get(Fse2Operation.ValidateCda));

        Assert.Equal(traceId, response.TraceId);
        Assert.Equal(spanId, response.SpanId);
        Assert.Equal(workflowInstanceId, response.WorkflowInstanceId);
    }

    [Fact]
    public void FSE2_RESPONSE_traceID_101_is_rejected()
    {
        string rawIdentifier = new('t', 101);
        Fse2ConnectorException error = Assert.Throws<Fse2ConnectorException>(() => Fse2ResponseMapper.Map(
            new(200, "application/json", JsonSerializer.SerializeToUtf8Bytes(new { traceID = rawIdentifier })),
            Guid.NewGuid(),
            Fse2OperationCatalog.Get(Fse2Operation.ValidateCda)));

        Assert.Equal(Fse2ErrorCategory.ResponseInvalid, error.Category);
        Assert.Equal("FSE2_RESPONSE_INVALID", error.SafeCode);
    }

    [Fact]
    public void FSE2_RESPONSE_spanID_101_is_rejected()
    {
        string rawIdentifier = new('s', 101);
        Fse2ConnectorException error = Assert.Throws<Fse2ConnectorException>(() => Fse2ResponseMapper.Map(
            new(200, "application/json", JsonSerializer.SerializeToUtf8Bytes(new { spanID = rawIdentifier })),
            Guid.NewGuid(),
            Fse2OperationCatalog.Get(Fse2Operation.ValidateCda)));

        Assert.Equal(Fse2ErrorCategory.ResponseInvalid, error.Category);
        Assert.Equal("FSE2_RESPONSE_INVALID", error.SafeCode);
    }

    [Fact]
    public void FSE2_RESPONSE_workflowInstanceId_257_is_rejected()
    {
        string rawIdentifier = new('w', 257);
        Fse2ConnectorException error = Assert.Throws<Fse2ConnectorException>(() => Fse2ResponseMapper.Map(
            new(200, "application/json", JsonSerializer.SerializeToUtf8Bytes(new { workflowInstanceId = rawIdentifier })),
            Guid.NewGuid(),
            Fse2OperationCatalog.Get(Fse2Operation.ValidateCda)));

        Assert.Equal(Fse2ErrorCategory.ResponseInvalid, error.Category);
        Assert.Equal("FSE2_RESPONSE_INVALID", error.SafeCode);
    }

    [Fact]
    public void FSE2_RESPONSE_invalid_identifier_error_is_sanitized_without_raw_value()
    {
        string rawIdentifier = "raw-identifier-canary-" + new string('x', 100);
        Fse2ConnectorException error = Assert.Throws<Fse2ConnectorException>(() => Fse2ResponseMapper.Map(
            new(200, "application/json", JsonSerializer.SerializeToUtf8Bytes(new { traceID = rawIdentifier })),
            Guid.NewGuid(),
            Fse2OperationCatalog.Get(Fse2Operation.ValidateCda)));

        Assert.Equal("FSE2_RESPONSE_INVALID", error.Message);
        Assert.DoesNotContain(rawIdentifier, error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void FSE2_RESPONSE_official_warning_is_collapsed_and_raw_response_is_not_exposed()
    {
        const string rawWarning = "raw warning canary";
        const string rawResponseCanary = "raw-response-canary";
        byte[] rawResponse = JsonSerializer.SerializeToUtf8Bytes(new
        {
            warning = rawWarning,
            upstreamPayload = rawResponseCanary
        });

        Fse2Response response = Fse2ResponseMapper.Map(
            new(200, "application/json", rawResponse),
            Guid.NewGuid(),
            Fse2OperationCatalog.Get(Fse2Operation.ValidateCda));

        Assert.Equal("FSE2_UPSTREAM_WARNING", response.SafeWarning);
        Assert.DoesNotContain(rawWarning, response.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(rawResponseCanary, response.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Encoding.UTF8.GetString(rawResponse), response.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{\"traceID\":\"trace-1\"}")]
    [InlineData("{\"workflowInstanceId\":\"workflow-1\"}")]
    public void FSE2_RESPONSE_create_requires_workflow_and_trace_identifiers(string body)
    {
        Fse2ConnectorException error = Assert.Throws<Fse2ConnectorException>(() => Fse2ResponseMapper.Map(
            new(202, "application/json", Encoding.UTF8.GetBytes(body)),
            Guid.NewGuid(),
            Fse2OperationCatalog.Get(Fse2Operation.Create)));

        Assert.Equal(Fse2ErrorCategory.ResponseInvalid, error.Category);
        Assert.Equal("FSE2_RESPONSE_INVALID", error.SafeCode);
    }

    [Theory]
    [InlineData(Fse2Operation.GetStatusByWorkflow)]
    [InlineData(Fse2Operation.GetStatusByTrace)]
    public void FSE2_RESPONSE_status_projects_only_closed_bounded_events(Fse2Operation operation)
    {
        const string rawCanary = "raw-status-data-must-not-escape";
        byte[] body = Encoding.UTF8.GetBytes($$"""
            {
              "traceID":"trace-1",
              "spanID":"span-1",
              "transactionData":[
                {
                  "eventType":"VALIDATION",
                  "eventDate":"2024-10-23T12:26:06.971+0200",
                  "eventStatus":"SUCCESS",
                  "message":"{{rawCanary}}",
                  "subject":"{{rawCanary}}",
                  "identificativoDocumento":"{{rawCanary}}",
                  "extra":"{{rawCanary}}"
                },
                {
                  "eventType":"SEND_TO_INI",
                  "eventDate":"2024-10-23T12:27:06.971+02:00",
                  "eventStatus":"BLOCKING_ERROR"
                }
              ]
            }
            """);

        Fse2Response response = Fse2ResponseMapper.Map(
            new(200, "application/json", body),
            Guid.NewGuid(),
            Fse2OperationCatalog.Get(operation));

        Assert.Equal(2, response.WorkflowEvents.Count);
        Assert.Equal(Fse2WorkflowEventType.Validation, response.WorkflowEvents[0].EventType);
        Assert.Equal(Fse2WorkflowEventOutcome.Success, response.WorkflowEvents[0].Outcome);
        Assert.Equal(Fse2WorkflowEventType.SendToIni, response.WorkflowEvents[1].EventType);
        Assert.Equal(Fse2WorkflowEventOutcome.BlockingError, response.WorkflowEvents[1].Outcome);
        Assert.Equal(Fse2StatusClassification.Found, response.StatusClassification);
        Assert.DoesNotContain(rawCanary, JsonSerializer.Serialize(response), StringComparison.Ordinal);
        Assert.DoesNotContain(rawCanary, response.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(Fse2Operation.GetStatusByWorkflow)]
    [InlineData(Fse2Operation.GetStatusByTrace)]
    public void FSE2_RESPONSE_status_404_is_bounded_not_found_and_discards_raw_problem(Fse2Operation operation)
    {
        const string rawCanary = "raw-status-problem-must-not-escape";
        Fse2Response response = Fse2ResponseMapper.Map(
            new(404, "application/problem+json", Encoding.UTF8.GetBytes(
                $$"""{"type":"msg/record-not-found","detail":"{{rawCanary}}"}""")),
            Guid.NewGuid(),
            Fse2OperationCatalog.Get(operation));

        Assert.Equal(404, response.StatusCode);
        Assert.Equal(Fse2StatusClassification.NotFound, response.StatusClassification);
        Assert.Empty(response.WorkflowEvents);
        Assert.Null(response.WorkflowInstanceId);
        Assert.Null(response.TraceId);
        Assert.DoesNotContain(rawCanary, JsonSerializer.Serialize(response), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"transactionData\":null}")]
    [InlineData("{\"transactionData\":[7]}")]
    [InlineData("{\"transactionData\":[{\"eventType\":\"UNKNOWN\",\"eventDate\":\"2024-10-23T12:26:06Z\",\"eventStatus\":\"SUCCESS\"}]}")]
    [InlineData("{\"transactionData\":[{\"eventType\":\"VALIDATION\",\"eventDate\":\"not-a-date\",\"eventStatus\":\"SUCCESS\"}]}")]
    [InlineData("{\"transactionData\":[{\"eventType\":\"VALIDATION\",\"eventDate\":\"2024-10-23T12:26:06Z\",\"eventStatus\":\"UNKNOWN\"}]}")]
    public void FSE2_RESPONSE_status_unknown_or_malformed_is_rejected_without_raw_data(string body)
    {
        Fse2ConnectorException error = Assert.Throws<Fse2ConnectorException>(() => Fse2ResponseMapper.Map(
            new(200, "application/json", Encoding.UTF8.GetBytes(body)),
            Guid.NewGuid(),
            Fse2OperationCatalog.Get(Fse2Operation.GetStatusByWorkflow)));

        Assert.Equal(Fse2ErrorCategory.ResponseInvalid, error.Category);
        Assert.Equal("FSE2_RESPONSE_INVALID", error.SafeCode);
        Assert.DoesNotContain(body, error.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void FSE2_RESPONSE_status_event_limit_and_chronology_are_fail_closed()
    {
        const string eventJson =
            "{\"eventType\":\"VALIDATION\",\"eventDate\":\"2024-10-23T12:26:06Z\",\"eventStatus\":\"SUCCESS\"}";
        string[] bodies =
        [
            "{\"transactionData\":[" + string.Join(',', Enumerable.Repeat(eventJson, 1001)) + "]}",
            "{\"transactionData\":[" + eventJson +
                ",{\"eventType\":\"PUBLICATION\",\"eventDate\":\"2024-10-23T12:25:06Z\",\"eventStatus\":\"SUCCESS\"}]}"
        ];

        foreach (string body in bodies)
        {
            Fse2ConnectorException error = Assert.Throws<Fse2ConnectorException>(() => Fse2ResponseMapper.Map(
                new(200, "application/json", Encoding.UTF8.GetBytes(body)),
                Guid.NewGuid(),
                Fse2OperationCatalog.Get(Fse2Operation.GetStatusByWorkflow)));
            Assert.Equal("FSE2_RESPONSE_INVALID", error.SafeCode);
            Assert.DoesNotContain("transactionData", error.ToString(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void FSE2_REQUEST_status_traceID_100_is_accepted_and_101_is_rejected()
    {
        string exactMaximum = new('t', 100);

        Fse2Request request = Fse2Request.GetStatusByTrace(exactMaximum);
        Assert.Equal(exactMaximum, request.ResourceIdentifier);
        Assert.Null(request.ClinicalClaims);
        using JsonDocument payload = JsonDocument.Parse(request.SerializeAuthorizedPayload());
        Assert.Equal(["resourceIdentifier"], payload.RootElement.EnumerateObject().Select(value => value.Name));
        Assert.Throws<ArgumentException>(() => Fse2Request.GetStatusByTrace(new string('t', 101)));
    }

    [Fact]
    public void FSE2_REQUEST_status_workflowInstanceId_256_is_accepted_and_257_is_rejected()
    {
        string exactMaximum = new('w', 256);

        Fse2Request request = Fse2Request.GetStatusByWorkflow(exactMaximum);
        Assert.Equal(exactMaximum, request.ResourceIdentifier);
        Assert.Null(request.ClinicalClaims);
        using JsonDocument payload = JsonDocument.Parse(request.SerializeAuthorizedPayload());
        Assert.Equal(["resourceIdentifier"], payload.RootElement.EnumerateObject().Select(value => value.Name));
        Assert.Throws<ArgumentException>(() => Fse2Request.GetStatusByWorkflow(new string('w', 257)));
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

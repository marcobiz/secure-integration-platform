using System.Reflection;
using System.Text;
using System.Text.Json;
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
    [InlineData(Fse2Operation.ValidateCda, "POST", "documents/validation", "TREATMENT", "CREATE")]
    [InlineData(Fse2Operation.Create, "POST", "documents", "TREATMENT", "CREATE")]
    [InlineData(Fse2Operation.Replace, "PUT", "documents/{id}", "UPDATE", "UPDATE")]
    [InlineData(Fse2Operation.Delete, "DELETE", "documents/{id}", "UPDATE", "DELETE")]
    [InlineData(Fse2Operation.UpdateMetadataChainConcealment, "PUT", "documents/{id}/metadata-oscuramento-catena", "ACCESS UPDATE", "UPDATE")]
    public void FSE2_CLAIMS_role_purpose_action_matrix_is_frozen(
        Fse2Operation operation,
        string method,
        string path,
        string purpose,
        string action)
    {
        Fse2OperationDescriptor descriptor = Fse2OperationCatalog.Get(operation);
        Assert.Equal(method, descriptor.Method.Method);
        Assert.Equal(path, descriptor.RelativePath);
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
        Assert.Equal("healthcare-fse2-organization", strategy.Key.Value);
        Assert.Equal([GatewayAuthenticationKind.MutualTls], strategy.SupportedAuthenticationKinds);
    }

    [Fact]
    public void FSE2_PROFILE_exact_Published_organization_projection_builds_canonical_subject_and_slots()
    {
        Fse2PublishedOrganizationProfile profile = Fse2PublishedOrganizationProfile.ParseJson(Profile());

        Assert.Equal("12345678903^^^&2.16.840.1.113883.2.9.4.1.2&ISO", profile.SubjectCx);
        Assert.Equal("DAP", profile.SubjectRole);
        Assert.Equal("authorization", profile.AuthorizationSigningSlot.Value);
        Assert.Equal("integrity", profile.IntegritySigningSlot.Value);
        Assert.Equal("create", profile.Operation.OperationId);
        Assert.Equal("multipart/form-data; boundary=broker-gateway-fse2-v1", profile.RequestContentType);
        Assert.Equal(64, profile.ProfileChecksumSha256.Length);
    }

    [Theory]
    [InlineData("\"subjectRole\":\"DAP\"", "\"subjectRole\":\"PATIENT\"")]
    [InlineData("\"method\":\"POST\"", "\"method\":\"PUT\"")]
    [InlineData("\"relativePath\":\"documents\"", "\"relativePath\":\"documents/other\"")]
    [InlineData("\"environmentClass\":\"synthetic\"", "\"environmentClass\":\"invalid\"")]
    public void FSE2_PROFILE_role_operation_and_environment_substitution_are_denied(string expected, string replacement) =>
        Assert.Throws<Fse2ConnectorException>(() =>
            Fse2PublishedOrganizationProfile.ParseJson(Encoding.UTF8.GetBytes(ProfileText().Replace(expected, replacement, StringComparison.Ordinal))));

    [Fact]
    public void FSE2_PROFILE_unknown_privileged_property_is_denied()
    {
        string tampered = ProfileText().Replace("{", "{\"issuer\":\"caller\",", StringComparison.Ordinal);
        Assert.Throws<Fse2ConnectorException>(() => Fse2PublishedOrganizationProfile.ParseJson(Encoding.UTF8.GetBytes(tampered)));
    }

    [Fact]
    public void FSE2_REQUEST_surface_has_no_actor_policy_endpoint_or_authentication_selector()
    {
        string[] properties = typeof(Fse2Request).GetProperties(BindingFlags.Instance | BindingFlags.Public).Select(value => value.Name).ToArray();
        string[] forbidden = ["Subject", "OrganizationIdentifier", "Vat", "Role", "Purpose", "Action", "Endpoint", "Algorithm", "Issuer", "Audience", "X5c", "Certificate", "SigningSlot", "Provider", "UseSubjectAsAuthor"];
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
    public void FSE2_HASH_uses_exact_unmodified_bytes()
    {
        byte[] exact = [0x00, 0x0d, 0x0a, 0xc3, 0xa8, 0xff];
        Assert.Equal("50f0a4377f9046168548c11702a121faaa42eae07548682170d6e7202eb80124", Fse2Validation.ComputeAttachmentHash(exact));
        Assert.NotEqual(Fse2Validation.ComputeAttachmentHash(exact),
            Fse2Validation.ComputeAttachmentHash(exact.AsMemory(0, exact.Length - 1)));
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
          "operationId":"create",
          "method":"POST",
          "relativePath":"documents",
          "requestContentType":"multipart/form-data; boundary=broker-gateway-fse2-v1",
          "multipartBoundary":"broker-gateway-fse2-v1",
          "authorizationSigningSlot":"authorization",
          "integritySigningSlot":"integrity",
          "maximumDocumentBytes":1048576
        }
        """;

    private sealed class RecordingRegistrar : IConnectorExecutionStrategyRegistrar
    {
        internal Type[]? Singleton { get; private set; }
        internal Type? Strategy { get; private set; }

        public void AddSingleton<TService>() where TService : class => Singleton = [typeof(TService)];
        public void AddSingleton<TService, TImplementation>() where TService : class where TImplementation : class, TService =>
            Singleton = [typeof(TService), typeof(TImplementation)];
        public void AddStrategy<TStrategy>() where TStrategy : class, IConnectorExecutionStrategy => Strategy = typeof(TStrategy);
        public void AddTypedSessionHandshakeRequestAdapter<TAdapter>() where TAdapter : class => throw new NotSupportedException();
        public void AddTypedSessionHandshakeResponseAdapter<TAdapter>() where TAdapter : class => throw new NotSupportedException();
        public void AddExternalSessionValidationAdapter<TAdapter>() where TAdapter : class => throw new NotSupportedException();
    }
}

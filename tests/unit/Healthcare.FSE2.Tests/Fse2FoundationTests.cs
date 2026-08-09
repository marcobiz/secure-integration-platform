using System.Reflection;
using System.Text;
using SecureIntegration.Authentication.CertificateSigning;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Tests;

public sealed class Fse2FoundationTests
{
    [Fact]
    public void FSE2_OPS_frozen_matrix_has_only_nine_production_and_two_official_test_operations()
    {
        Assert.Equal(11, Fse2OperationCatalog.All.Count);
        Assert.Equal(9, Fse2OperationCatalog.All.Count(value => value.Availability == Fse2OperationAvailability.ProductionAvailable));
        Assert.Equal(2, Fse2OperationCatalog.All.Count(value => value.Availability == Fse2OperationAvailability.TestOnlyOfficial));
        Assert.Equal(Fse2OperationAvailability.NotAvailable, Fse2OperationCatalog.GetAvailability("direct-fhir-create"));
        Assert.Equal(Fse2OperationAvailability.NotAvailable, Fse2OperationCatalog.GetAvailability("callback-consumer"));

        Assert.All(Fse2OperationCatalog.All.Where(value => value.Operation is Fse2Operation.GetStatusByWorkflow or Fse2Operation.GetStatusByTrace),
            value => Assert.Equal(Fse2RetryClass.SafeRetry, value.RetryClass));
        Assert.All(Fse2OperationCatalog.All.Where(value => value.Operation is not (Fse2Operation.GetStatusByWorkflow or Fse2Operation.GetStatusByTrace)),
            value => Assert.Equal(Fse2RetryClass.NoAutomaticRetry, value.RetryClass));
    }

    [Theory]
    [InlineData(Fse2Operation.ValidateCda, "POST", "documents/validation", "TREATMENT", "CREATE")]
    [InlineData(Fse2Operation.ValidateFhir, "POST", "documents/fhir-validation", "TREATMENT", "CREATE")]
    [InlineData(Fse2Operation.Create, "POST", "documents", "TREATMENT", "CREATE")]
    [InlineData(Fse2Operation.Replace, "PUT", "documents/{id}", "UPDATE", "UPDATE")]
    [InlineData(Fse2Operation.Delete, "DELETE", "documents/{id}", "UPDATE", "DELETE")]
    [InlineData(Fse2Operation.UpdateMetadata, "PUT", "documents/{id}/metadata-iti-57", "UPDATE", "UPDATE")]
    [InlineData(Fse2Operation.UpdateMetadataChainConcealment, "PUT", "documents/{id}/metadata-oscuramento-catena", "ACCESS UPDATE", "UPDATE")]
    [InlineData(Fse2Operation.ValidateAndCreate, "POST", "documents/validate-and-create", "TREATMENT", "CREATE")]
    [InlineData(Fse2Operation.ValidateAndReplace, "PUT", "documents/validate-and-replace/{id}", "UPDATE", "UPDATE")]
    public void FSE2_CLAIMS_role_purpose_action_matrix_is_frozen(
        Fse2Operation operation, string method, string path, string purpose, string action)
    {
        Fse2OperationDescriptor descriptor = Fse2OperationCatalog.Get(operation);
        Assert.Equal(method, descriptor.Method.Method);
        Assert.Equal(path, descriptor.RelativePath);
        Assert.Equal(purpose, Fse2OperationCatalog.ClaimValue(descriptor.PurposeOfUse!.Value));
        Assert.Equal(action, Fse2OperationCatalog.ClaimValue(descriptor.Action!.Value));
        Fse2OperationCatalog.ValidateOrganizationCombination("DAP", descriptor.OperationId, descriptor.PurposeOfUse.Value, descriptor.Action.Value);
    }

    [Fact]
    public void FSE2_CLAIMS_authority_is_explicit_and_wrong_role_purpose_action_or_unknown_claim_fail_closed()
    {
        Assert.Equal(Fse2ClaimAuthority.ServerOwned, Fse2OperationCatalog.GetClaimAuthority("sub"));
        Assert.Equal(Fse2ClaimAuthority.ServerOwned, Fse2OperationCatalog.GetClaimAuthority("subject_organization"));
        Assert.Equal(Fse2ClaimAuthority.BusinessAllowlisted, Fse2OperationCatalog.GetClaimAuthority("person_id"));
        Assert.Equal(Fse2ClaimAuthority.Derived, Fse2OperationCatalog.GetClaimAuthority("attachment_hash"));
        Assert.Throws<Fse2ConnectorException>(() => Fse2OperationCatalog.GetClaimAuthority("use_subject_as_author"));
        Assert.Throws<Fse2ConnectorException>(() => Fse2OperationCatalog.ValidateOrganizationCombination("ASS", "create", Fse2PurposeOfUse.Treatment, Fse2Action.Create));
        Assert.Throws<Fse2ConnectorException>(() => Fse2OperationCatalog.ValidateOrganizationCombination("DAP", "create", Fse2PurposeOfUse.Update, Fse2Action.Create));
        Assert.Throws<Fse2ConnectorException>(() => Fse2OperationCatalog.ValidateOrganizationCombination("DAP", "create", Fse2PurposeOfUse.Treatment, Fse2Action.Delete));
    }

    [Fact]
    public void FSE2_PROFILE_organization_subject_is_fixed_CX_checksum_bound_and_four_eyes_approved()
    {
        Fse2PublishedOrganizationProfile profile = Fse2TestData.Profile(Fse2Operation.Create, new("https://fse.example.test/v1"));
        Fse2PublishedOrganizationProfile changedIdentity = Fse2TestData.Profile(Fse2Operation.Create, new("https://fse.example.test/v1"), organizationIdentifier: "00488410010");

        Assert.Equal("01114601006^^^&2.16.840.1.113883.2.9.4.1.2&ISO", profile.SubjectCx);
        Assert.Equal("DAP", profile.SubjectRole);
        Assert.NotEqual(profile.ChecksumSha256, changedIdentity.ChecksumSha256);
        Assert.NotEqual(profile.SigningBindingId, profile.MutualTlsBindingId);
        Assert.Throws<ArgumentException>(() => Fse2TestData.Profile(Fse2Operation.Create, new("https://fse.example.test/v1"), createdBy: "same", approvedBy: "same"));
        Assert.Throws<ArgumentException>(() => Fse2TestData.Profile(Fse2Operation.Create, new("https://fse.example.test/v1"), subjectRole: "ASS"));
        Assert.Throws<ArgumentException>(() => Fse2PublishedOrganizationProfile.ValidateSuccessor(profile, changedIdentity));
        Fse2PublishedOrganizationProfile successor = Fse2TestData.Profile(Fse2Operation.Create, new("https://fse.example.test/v1"), organizationIdentifier: "00488410010", revision: 8);
        Fse2PublishedOrganizationProfile.ValidateSuccessor(profile, successor);
    }

    [Fact]
    public void FSE2_PROFILE_production_rejects_official_test_only_operation()
    {
        Fse2PublishedOrganizationProfile profile = Fse2TestData.Profile(Fse2Operation.ValidateFhir, new("https://fse.example.test/v1"), Fse2EnvironmentClass.Production);
        Fse2PublishedProfileLookup lookup = profile.Authority;

        Fse2ConnectorException denied = Assert.Throws<Fse2ConnectorException>(() => InvokeValidateAuthority(profile, lookup));
        Assert.Equal("FSE2_OPERATION_NOT_PRODUCTION_AVAILABLE", denied.SafeCode);
    }

    [Fact]
    public void FSE2_IHE_CX_XON_are_canonical_and_malformed_ambiguous_or_injected_values_are_denied()
    {
        string organization = Fse2IheFormatter.FormatOrganizationCx("01114601006", "2.16.840.1.113883.2.9.4.1.2");
        string person = Fse2IheFormatter.FormatPersonCx("RSSMRA80A01H501U", "2.16.840.1.113883.2.9.4.3.2");
        string locality = Fse2IheFormatter.FormatLocalityXon("Azienda Sanitaria Sintetica", "2.16.840.1.113883.2.9.4.1.1", "001");

        Assert.Equal("01114601006^^^&2.16.840.1.113883.2.9.4.1.2&ISO", organization);
        Assert.Equal("RSSMRA80A01H501U^^^&2.16.840.1.113883.2.9.4.3.2&ISO", person);
        Assert.Equal("Azienda Sanitaria Sintetica^^^^^&2.16.840.1.113883.2.9.4.1.1&ISO^^^^001", locality);
        Fse2IheFormatter.ValidateCx(organization, organization: true);
        Fse2IheFormatter.ValidateCx(person, organization: false);
        Fse2IheFormatter.ValidateXon(locality);

        Assert.Throws<ArgumentException>(() => Fse2IheFormatter.ValidateCx("01114601006^^&2.16.840.1.113883.2.9.4.1.2&ISO", true));
        Assert.Throws<ArgumentException>(() => Fse2IheFormatter.ValidateCx("01114601006^^^&02.16.840.1&ISO", true));
        Assert.Throws<ArgumentException>(() => Fse2IheFormatter.ValidateXon("Azienda\rInjected^^^^^&2.16.840.1&ISO^^^^001"));
        Assert.Throws<ArgumentException>(() => Fse2IheFormatter.FormatLocalityXon("Azienda^Ambigua", "2.16.840.1", "001"));
        Assert.Throws<ArgumentException>(() => Fse2IheFormatter.FormatPersonCx("rssmra80a01h501u", "2.16.840.1"));
        Assert.Throws<ArgumentException>(() => Fse2IheFormatter.FormatPersonCx("RSSMRA80A01H501A", "2.16.840.1"));
    }

    [Fact]
    public void FSE2_HASH_uses_exact_unmodified_document_bytes()
    {
        byte[] exact = [0x00, 0x0d, 0x0a, 0xc3, 0xa8, 0xff];
        Assert.Equal("50f0a4377f9046168548c11702a121faaa42eae07548682170d6e7202eb80124", Fse2Validation.ComputeAttachmentHash(exact));
        Assert.NotEqual(Fse2Validation.ComputeAttachmentHash(exact), Fse2Validation.ComputeAttachmentHash(Encoding.UTF8.GetBytes("\0\nè�")));
    }

    [Fact]
    public void FSE2_AUTHORITY_caller_request_has_no_actor_policy_endpoint_or_use_subject_as_author_selector()
    {
        string[] publicProperties = typeof(Fse2Request).GetProperties(BindingFlags.Instance | BindingFlags.Public).Select(value => value.Name).ToArray();
        string[] forbidden = ["Subject", "OrganizationIdentifier", "Vat", "Role", "Purpose", "Action", "Endpoint", "Algorithm", "Issuer", "Audience", "X5c", "Certificate", "UseSubjectAsAuthor"];
        Assert.DoesNotContain(publicProperties, property => forbidden.Any(value => property.Contains(value, StringComparison.OrdinalIgnoreCase)));
        Assert.DoesNotContain(typeof(Fse2ClinicalClaims).GetProperties().Select(value => value.Name), value => value.Contains("Subject", StringComparison.OrdinalIgnoreCase));

        byte[] document = [1, 2, 3];
        byte[] body = "{}"u8.ToArray();
        Fse2Request request = Fse2Request.Create(document, body, Fse2TestData.Claims());
        document[0] = 99;
        body[0] = 99;
        Assert.Equal(1, request.Document.Span[0]);
        Assert.Equal((byte)'{', request.RequestBody.Span[0]);
    }

    [Fact]
    public void FSE2_ERROR_RFC7807_mapper_retains_only_allowlisted_safe_code_and_never_detail_canary()
    {
        const string canary = "clinical-payload-redaction-canary";
        byte[] problem = Encoding.UTF8.GetBytes($$"""{"type":"https://errors.example/FSE2_DOCUMENT_REJECTED","title":"rejected","detail":"{{canary}}","stack":"{{canary}}"}""");
        Fse2ConnectorException error = Fse2ResponseMapper.MapProblem(new(400, "application/problem+json", problem), Fse2RetryClass.NoAutomaticRetry);

        Assert.Equal("FSE2_DOCUMENT_REJECTED", error.SafeCode);
        Assert.Equal(Fse2ErrorCategory.UpstreamRejected, error.Category);
        Assert.DoesNotContain(canary, error.ToString(), StringComparison.Ordinal);
        Assert.Null(error.InnerException);
    }

    [Fact]
    public void FSE2_WORKFLOW_status_is_safe_retry_and_requires_server_stored_security_context()
    {
        Fse2OperationDescriptor workflow = Fse2OperationCatalog.Get(Fse2Operation.GetStatusByWorkflow);
        Fse2OperationDescriptor trace = Fse2OperationCatalog.Get(Fse2Operation.GetStatusByTrace);
        Assert.Equal(Fse2RetryClass.SafeRetry, workflow.RetryClass);
        Assert.Equal(Fse2RetryClass.SafeRetry, trace.RetryClass);
        Assert.Null(workflow.Action);
        Assert.Null(trace.PurposeOfUse);
        Assert.Null(Fse2Request.GetStatusByWorkflow("workflow-123").ClinicalClaims);
        Assert.Null(Fse2Request.GetStatusByTrace("trace-123").ClinicalClaims);
    }

    private static void InvokeValidateAuthority(Fse2PublishedOrganizationProfile profile, Fse2PublishedProfileLookup lookup)
    {
        MethodInfo method = typeof(Fse2PublishedOrganizationProfile).GetMethod("ValidateAuthority", BindingFlags.Static | BindingFlags.NonPublic)!;
        try { method.Invoke(null, [profile, lookup]); }
        catch (TargetInvocationException exception) when (exception.InnerException is not null) { throw exception.InnerException; }
    }
}

internal static class Fse2TestData
{
    internal static readonly Guid TenantId = Guid.Parse("10000000-0000-0000-0000-000000000001");
    internal static readonly Guid ApplicationId = Guid.Parse("20000000-0000-0000-0000-000000000002");
    internal static readonly Guid InstallationId = Guid.Parse("30000000-0000-0000-0000-000000000003");
    internal static readonly Guid EnvironmentId = Guid.Parse("40000000-0000-0000-0000-000000000004");
    internal static readonly Guid ConnectorVersionId = Guid.Parse("50000000-0000-0000-0000-000000000005");

    internal static Fse2ClinicalClaims Claims(string resource = "('11502-2^^2.16.840.1.113883.6.1')") =>
        Fse2ClinicalClaims.CreatePerson("RSSMRA80A01H501U", "2.16.840.1.113883.2.9.4.3.2", true, resource);

    internal static Fse2PublishedOrganizationProfile Profile(
        Fse2Operation operation,
        Uri baseEndpoint,
        Fse2EnvironmentClass environmentClass = Fse2EnvironmentClass.Synthetic,
        string organizationIdentifier = "01114601006",
        string createdBy = "author-one",
        string approvedBy = "approver-two",
        string subjectRole = "DAP",
        long revision = 7,
        TimeSpan? timeout = null) =>
        Fse2PublishedOrganizationProfile.CreateApproved(
            new(TenantId, ApplicationId, InstallationId, EnvironmentId, "fse2-national", operation),
            ConnectorVersionId,
            environmentClass,
            baseEndpoint,
            organizationIdentifier,
            "2.16.840.1.113883.2.9.4.1.2",
            "Azienda Sanitaria Sintetica",
            "asl-synthetic",
            "Azienda Sanitaria Sintetica",
            "2.16.840.1.113883.2.9.4.1.1",
            "001",
            subjectRole,
            "broker-gateway",
            "Synthetic Vendor",
            "1.0.0",
            "fse2-auth-jwt",
            "fse2-signature-jwt",
            "fse2-mtls",
            "fse2-signing-certificate",
            "fse2-mtls-certificate",
            TimeSpan.FromMinutes(5),
            TimeSpan.FromSeconds(30),
            timeout ?? TimeSpan.FromSeconds(5),
            8 * 1024 * 1024,
            64 * 1024,
            revision,
            createdBy,
            approvedBy);
}

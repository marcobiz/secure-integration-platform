using System.Formats.Asn1;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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

    [Fact]
    public void FSE2_OPS_catalog_exposes_no_mutable_array_set_or_entry_authority()
    {
        object all = Fse2OperationCatalog.All;
        Fse2OperationDescriptor create = Fse2OperationCatalog.Get(Fse2Operation.Create);
        Assert.False(all is Fse2OperationDescriptor[]);
        Assert.False(create.SuccessStatusCodes is HashSet<int>);
        ISet<int> setFacade = Assert.IsAssignableFrom<ISet<int>>(create.SuccessStatusCodes);
        Assert.Throws<NotSupportedException>(() => setFacade.Add(418));
        Assert.Throws<NotSupportedException>(() => setFacade.Remove(202));
        Fse2OperationDescriptor forged = create with { Availability = Fse2OperationAvailability.TestOnlyOfficial,
            SuccessStatusCodes = new HashSet<int> { 418 } };
        Assert.NotEqual(forged.Availability, Fse2OperationCatalog.Get(Fse2Operation.Create).Availability);
        Assert.DoesNotContain(418, Fse2OperationCatalog.Get(Fse2Operation.Create).SuccessStatusCodes);
        Assert.Contains(202, Fse2OperationCatalog.Get(Fse2Operation.Create).SuccessStatusCodes);
    }

    [Theory]
    [InlineData(Fse2Operation.ValidateCda, "POST", "documents/validation", "TREATMENT", "CREATE")]
    [InlineData(Fse2Operation.Create, "POST", "documents", "TREATMENT", "CREATE")]
    [InlineData(Fse2Operation.Replace, "PUT", "documents/{id}", "UPDATE", "UPDATE")]
    [InlineData(Fse2Operation.Delete, "DELETE", "documents/{id}", "UPDATE", "DELETE")]
    [InlineData(Fse2Operation.UpdateMetadataChainConcealment, "PUT", "documents/{id}/metadata-oscuramento-catena", "ACCESS UPDATE", "UPDATE")]
    public void FSE2_CLAIMS_role_purpose_action_matrix_is_frozen(Fse2Operation operation, string method, string path, string purpose, string action)
    {
        Fse2OperationDescriptor descriptor = Fse2OperationCatalog.Get(operation);
        Assert.Equal(method, descriptor.Method.Method); Assert.Equal(path, descriptor.RelativePath);
        Assert.Equal(purpose, Fse2OperationCatalog.ClaimValue(descriptor.PurposeOfUse!.Value));
        Assert.Equal(action, Fse2OperationCatalog.ClaimValue(descriptor.Action!.Value));
        Fse2OperationCatalog.ValidateOrganizationCombination("DAP", descriptor.OperationId, descriptor.PurposeOfUse.Value, descriptor.Action.Value);
    }

    [Fact]
    public void FSE2_CLAIMS_caller_surface_has_no_actor_policy_endpoint_or_certificate_selector()
    {
        string[] properties = typeof(Fse2Request).GetProperties(BindingFlags.Instance | BindingFlags.Public).Select(value => value.Name).ToArray();
        string[] forbidden = ["Subject", "OrganizationIdentifier", "Vat", "Role", "Purpose", "Action", "Endpoint", "Algorithm", "Issuer", "Audience", "X5c", "Certificate", "UseSubjectAsAuthor"];
        Assert.DoesNotContain(properties, property => forbidden.Any(value => property.Contains(value, StringComparison.OrdinalIgnoreCase)));
        Assert.Throws<Fse2ConnectorException>(() => Fse2OperationCatalog.GetClaimAuthority("use_subject_as_author"));
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
    public void FSE2_CN_exact_DER_parser_accepts_one_CN_in_single_or_multivalued_RDN()
    {
        using X509Certificate2 single = Certificate(Name(Rdn(("2.5.4.3", "Signing One"))));
        using X509Certificate2 multi = Certificate(Name(Rdn(("2.5.4.10", "Organization"), ("2.5.4.3", "Signing Multi"))));
        Assert.Equal("Signing One", Fse2X500CommonName.ReadExactlyOne(single.SubjectName.RawData));
        Assert.Equal("Signing Multi", Fse2X500CommonName.ReadExactlyOne(multi.SubjectName.RawData));
    }

    [Fact]
    public void FSE2_CN_absent_duplicate_multiple_empty_malformed_and_SAN_fallback_are_denied()
    {
        using X509Certificate2 absent = Certificate(Name(Rdn(("2.5.4.10", "Organization"))));
        using X509Certificate2 duplicateSameRdn = Certificate(Name(Rdn(("2.5.4.3", "One"), ("2.5.4.3", "Two"))));
        using X509Certificate2 duplicateRdns = Certificate(Name(Rdn(("2.5.4.3", "One")), Rdn(("2.5.4.3", "Two"))));
        using X509Certificate2 empty = Certificate(Name(Rdn(("2.5.4.3", ""))));
        using X509Certificate2 sanOnly = CertificateWithSan(Name(Rdn(("2.5.4.10", "Organization"))), "simple-name.example");
        Assert.ThrowsAny<CryptographicException>(() => Fse2X500CommonName.ReadExactlyOne(absent.SubjectName.RawData));
        Assert.ThrowsAny<CryptographicException>(() => Fse2X500CommonName.ReadExactlyOne(duplicateSameRdn.SubjectName.RawData));
        Assert.ThrowsAny<CryptographicException>(() => Fse2X500CommonName.ReadExactlyOne(duplicateRdns.SubjectName.RawData));
        Assert.ThrowsAny<CryptographicException>(() => Fse2X500CommonName.ReadExactlyOne(empty.SubjectName.RawData));
        Assert.ThrowsAny<CryptographicException>(() => Fse2X500CommonName.ReadExactlyOne(sanOnly.SubjectName.RawData));
        Assert.ThrowsAny<Exception>(() => Fse2X500CommonName.ReadExactlyOne(new byte[] { 0x30, 0x03, 0x31 }));
        Assert.Equal("simple-name.example", sanOnly.GetNameInfo(X509NameType.DnsName, false));
    }

    [Fact]
    public void FSE2_ENDPOINT_official_authorities_are_exact_and_synthetic_cannot_claim_Production()
    {
        Assert.Equal(Fse2EnvironmentClass.Production, Fse2EndpointAuthority.Resolve(Fse2EndpointAuthority.Production, Fse2EnvironmentClass.Production, null));
        Assert.Equal(Fse2EnvironmentClass.OfficialTest, Fse2EndpointAuthority.Resolve(Fse2EndpointAuthority.OfficialTest, Fse2EnvironmentClass.OfficialTest, null));
        Assert.Throws<Fse2ConnectorException>(() => Fse2EndpointAuthority.Resolve(new("https://attacker.example/v1"), Fse2EnvironmentClass.Production, null));
        Fse2SyntheticEndpointAuthority synthetic = Fse2SyntheticEndpointAuthority.CreateForTests(new("https://localhost:4443/v1"));
        Assert.Throws<Fse2ConnectorException>(() => Fse2EndpointAuthority.Resolve(new("https://localhost:4443/v1"), Fse2EnvironmentClass.Production, synthetic));
        Assert.Throws<Fse2ConnectorException>(() => Fse2EndpointAuthority.Resolve(new("https://sub.modipa.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1"), Fse2EnvironmentClass.Production, null));
    }

    [Fact]
    public void FSE2_HASH_uses_exact_unmodified_document_bytes()
    {
        byte[] exact = [0x00, 0x0d, 0x0a, 0xc3, 0xa8, 0xff];
        Assert.Equal("50f0a4377f9046168548c11702a121faaa42eae07548682170d6e7202eb80124", Fse2Validation.ComputeAttachmentHash(exact));
        Assert.NotEqual(Fse2Validation.ComputeAttachmentHash(exact), Fse2Validation.ComputeAttachmentHash(Encoding.UTF8.GetBytes("\0\nè�")));
    }

    [Fact]
    public void FSE2_ERROR_RFC7807_mapper_retains_only_safe_code()
    {
        const string canary = "clinical-payload-redaction-canary";
        byte[] problem = Encoding.UTF8.GetBytes($$"""{"type":"https://errors.example/FSE2_DOCUMENT_REJECTED","detail":"{{canary}}"}""");
        Fse2ConnectorException error = Fse2ResponseMapper.MapProblem(new(400, "application/problem+json", problem), Fse2RetryClass.NoAutomaticRetry);
        Assert.Equal("FSE2_DOCUMENT_REJECTED", error.SafeCode); Assert.DoesNotContain(canary, error.ToString(), StringComparison.Ordinal);
    }

    private static (string Oid, string Value)[] Rdn(params (string Oid, string Value)[] attributes) => attributes;
    private static byte[] Name(params (string Oid, string Value)[][] rdns)
    {
        AsnWriter writer = new(AsnEncodingRules.DER); writer.PushSequence();
        foreach ((string Oid, string Value)[] rdn in rdns)
        {
            writer.PushSetOf();
            foreach ((string oid, string value) in rdn)
            {
                writer.PushSequence(); writer.WriteObjectIdentifier(oid); writer.WriteCharacterString(UniversalTagNumber.UTF8String, value); writer.PopSequence();
            }
            writer.PopSetOf();
        }
        writer.PopSequence(); return writer.Encode();
    }
    private static X509Certificate2 Certificate(byte[] subject)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(new X500DistinguishedName(subject), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
    private static X509Certificate2 CertificateWithSan(byte[] subject, string dns)
    {
        using RSA rsa = RSA.Create(2048);
        CertificateRequest request = new(new X500DistinguishedName(subject), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        SubjectAlternativeNameBuilder san = new(); san.AddDnsName(dns); request.CertificateExtensions.Add(san.Build());
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}

internal static class Fse2TestData
{
    internal static readonly Guid TenantId = Guid.Parse("10000000-0000-0000-0000-000000000001");
    internal static readonly Guid ApplicationId = Guid.Parse("20000000-0000-0000-0000-000000000002");
    internal static readonly Guid InstallationId = Guid.Parse("30000000-0000-0000-0000-000000000003");
    internal static readonly Guid EnvironmentId = Guid.Parse("40000000-0000-0000-0000-000000000004");
    internal static readonly Guid ConnectorVersionId = Guid.Parse("50000000-0000-0000-0000-000000000005");
    internal static readonly Guid ConnectorId = Guid.Parse("60000000-0000-0000-0000-000000000006");
    internal static readonly Guid BindingId = Guid.Parse("70000000-0000-0000-0000-000000000007");
    internal static Fse2ClinicalClaims Claims(string resource = "('11502-2^^2.16.840.1.113883.6.1')") =>
        Fse2ClinicalClaims.CreatePerson("RSSMRA80A01H501U", "2.16.840.1.113883.2.9.4.3.2", true, resource);
}

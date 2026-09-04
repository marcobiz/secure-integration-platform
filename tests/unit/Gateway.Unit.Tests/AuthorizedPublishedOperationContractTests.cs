using System.Text;
using SecureIntegration.Gateway.Application;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class AuthorizedPublishedOperationContractTests
{
    [Theory]
    [InlineData(false, "/documents/caff%C3%A8%2B2026")]
    [InlineData(true, "/gateway/v1/documents/caff%C3%A8%2B2026")]
    public void CT_Published_path_template_honors_explicit_base_path_policy(bool append, string expected)
    {
        Uri endpoint = new("https://api.example.test:8443/gateway/v1/");
        Uri projected = PublishedPathTemplate.Project(endpoint, "/documents/{document}",
            [new("document", "caffè+2026")], append);
        Assert.Equal(expected, projected.AbsolutePath);
        Assert.Equal(endpoint.GetLeftPart(UriPartial.Authority), projected.GetLeftPart(UriPartial.Authority));
        Assert.Empty(projected.Query);
        Assert.Empty(projected.Fragment);
        if (append)
            Assert.Throws<GatewayException>(() => PublishedPathTemplate.Project(
                new("https://api.example.test/gateway%2Fv1/"), "/documents/{document}", [new("document", "doc")], true));
    }

    [Fact]
    public void Wave1_CT_Published_path_projection_is_exact_single_encoded_and_origin_preserving()
    {
        Uri endpoint = new("https://api.example.test:8443");
        AuthorizedConnectorPathParameter[] values =
        [
            new("tenant", "north west"),
            new("document", "caffè+2026")
        ];

        Uri projected = PublishedPathTemplate.Project(
            endpoint,
            "/v1/{tenant}/documents/{document}",
            values);

        Assert.Equal("https", projected.Scheme);
        Assert.Equal("api.example.test", projected.Host);
        Assert.Equal(8443, projected.Port);
        Assert.Equal("/v1/north%20west/documents/caff%C3%A8%2B2026", projected.AbsolutePath);
        Assert.Empty(projected.Query);
        Assert.Empty(projected.Fragment);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("a/b")]
    [InlineData("a\\b")]
    [InlineData("a%2fb")]
    [InlineData("a%5cb")]
    [InlineData("a%252fb")]
    [InlineData("a?b")]
    [InlineData("a#b")]
    [InlineData("https://attacker.invalid")]
    [InlineData("//attacker.invalid")]
    [InlineData("a\nb")]
    public void Wave1_SEC_Published_path_values_reject_empty_traversal_delimiters_percent_and_controls(string value)
    {
        Assert.Throws<ArgumentException>(() => new AuthorizedConnectorPathParameter("tenant", value));
    }

    [Fact]
    public void Wave1_SEC_Published_path_values_reject_non_NFC_and_oversize_UTF8()
    {
        Assert.Throws<ArgumentException>(() => new AuthorizedConnectorPathParameter("tenant", "e\u0301"));
        Assert.Throws<ArgumentException>(() => new AuthorizedConnectorPathParameter(
            "tenant",
            new string('\u00e8', (PublishedPathTemplate.MaximumParameterValueUtf8Bytes / 2) + 1)));
        Assert.Throws<ArgumentException>(() => new AuthorizedConnectorPathParameter("Upper", "value"));
        Assert.Throws<ArgumentException>(() => new AuthorizedConnectorPathParameter(new string('a', 33), "value"));
        Assert.Throws<ArgumentException>(() => PublishedPathTemplate.Validate(
            "/{one}/{two}/{three}/{four}/{five}/{six}/{seven}/{eight}/{nine}",
            "template"));
    }

    [Theory]
    [InlineData("relative/{tenant}")]
    [InlineData("//authority/{tenant}")]
    [InlineData("/v1/prefix-{tenant}")]
    [InlineData("/v1/{tenant}-suffix")]
    [InlineData("/v1/{tenant}/{tenant}")]
    [InlineData("/v1//{tenant}")]
    [InlineData("/v1/../{tenant}")]
    [InlineData("/v1/{Tenant}")]
    [InlineData("/v1/{tenant}?query=x")]
    [InlineData("/v1/{tenant}#fragment")]
    [InlineData("/v1/%7Btenant%7D")]
    public void Wave1_SEC_Published_path_template_rejects_authority_partial_duplicate_and_noncanonical_forms(string template)
    {
        Assert.Throws<ArgumentException>(() => PublishedPathTemplate.Validate(template, nameof(template)));
    }

    [Fact]
    public void Wave1_SEC_Published_path_projection_requires_exact_placeholder_set()
    {
        Uri endpoint = new("https://api.example.test");

        GatewayException missing = Assert.Throws<GatewayException>(() => PublishedPathTemplate.Project(
            endpoint,
            "/v1/{tenant}/{document}",
            [new("tenant", "north")])) ;
        GatewayException extra = Assert.Throws<GatewayException>(() => PublishedPathTemplate.Project(
            endpoint,
            "/v1/{tenant}",
            [new("tenant", "north"), new("document", "invoice")])) ;
        Assert.Equal("BGW-EGRESS-AUTHENTICATION", missing.Code);
        Assert.Equal("BGW-EGRESS-AUTHENTICATION", extra.Code);
        Assert.Throws<ArgumentException>(() => new AuthorizedConnectorRestrictedTransportRequest(
            Encoding.UTF8.GetBytes("body"),
            [new("tenant", "north"), new("tenant", "south")]));
    }

    [Fact]
    public void Wave1_CT_restricted_transport_request_represents_REQUIRED_and_NONE_without_URI_authority()
    {
        AuthorizedConnectorRestrictedTransportRequest none = new([new("tenant", "north")]);
        AuthorizedConnectorRestrictedTransportRequest required = new(
            Encoding.UTF8.GetBytes("published-body"),
            [new("tenant", "north")]);

        Assert.Equal(0, none.BodyLength);
        Assert.Equal(1, none.PathParameterCount);
        Assert.Equal(14, required.BodyLength);
        Assert.Equal(1, required.PathParameterCount);
        Assert.DoesNotContain(
            typeof(AuthorizedConnectorRestrictedTransportRequest).GetProperties(),
            property => property.PropertyType == typeof(Uri) || property.Name.Contains("Header", StringComparison.Ordinal));
        Assert.DoesNotContain(
            typeof(AuthorizedConnectorPathParameter).GetProperties(),
            property => property.PropertyType == typeof(Uri));
    }

    [Fact]
    public void Wave1_SEC_expectation_objects_are_bounded_immutable_and_redacted()
    {
        ConnectorSigningSlotKey primary = ConnectorSigningSlotKey.Parse("primary");
        AuthorizedSigningSlotExpectation slot = new(
            primary,
            required: true,
            AuthorizedSigningAlgorithm.Rs256,
            AuthorizedSigningTokenProjectionExpectation.AuthorizationBearer(),
            "synthetic-upstream",
            "synthetic-fixed-subject",
            ["transaction-id"],
            60,
            AuthorizedSigningTemporalMode.IssuedAtExpiration,
            jtiRequired: true,
            AuthorizedSigningCertificateHeaderMode.Chain,
            AuthorizedSigningIssuerExpectation.Exact("synthetic-issuer"));
        AuthorizedPublishedOperationExpectations expectations = new(
            GatewayAuthenticationKind.MutualTls,
            restrictedTransportRequired: true,
            [slot],
            signingIdentityDistinctFromMutualTlsSlots: [primary]);

        Assert.Single(expectations.SigningSlots);
        Assert.Single(expectations.SigningIdentityDistinctFromMutualTlsSlots);
        Assert.Equal(AuthorizedSigningCertificateKeyUsageMode.DigitalSignature, slot.CertificateKeyUsageMode);
        Assert.DoesNotContain("synthetic-issuer", slot.ToString(), StringComparison.Ordinal);
        AuthorizedSigningSlotExpectation contentCommitment = new(
            primary,
            required: true,
            AuthorizedSigningAlgorithm.Rs256,
            AuthorizedSigningTokenProjectionExpectation.AuthorizationBearer(),
            "synthetic-upstream",
            "synthetic-fixed-subject",
            ["transaction-id"],
            60,
            AuthorizedSigningTemporalMode.IssuedAtExpiration,
            jtiRequired: true,
            AuthorizedSigningCertificateHeaderMode.Chain,
            AuthorizedSigningIssuerExpectation.Exact("synthetic-issuer"),
            AuthorizedSigningCertificateKeyUsageMode.ContentCommitment);
        Assert.Equal(AuthorizedSigningCertificateKeyUsageMode.ContentCommitment, contentCommitment.CertificateKeyUsageMode);
        Assert.Throws<ArgumentException>(() => new AuthorizedSigningSlotExpectation(
            primary,
            true,
            AuthorizedSigningAlgorithm.Rs256,
            AuthorizedSigningTokenProjectionExpectation.AuthorizationBearer(),
            "synthetic-upstream",
            "synthetic-fixed-subject",
            ["duplicate", "duplicate"],
            60,
            AuthorizedSigningTemporalMode.IssuedAtExpiration,
            true,
            AuthorizedSigningCertificateHeaderMode.Chain,
            AuthorizedSigningIssuerExpectation.Exact("synthetic-issuer")));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AuthorizedSigningSlotExpectation(
            primary,
            true,
            AuthorizedSigningAlgorithm.Rs256,
            AuthorizedSigningTokenProjectionExpectation.AuthorizationBearer(),
            "synthetic-upstream",
            "synthetic-fixed-subject",
            [],
            60,
            AuthorizedSigningTemporalMode.IssuedAtExpiration,
            true,
            AuthorizedSigningCertificateHeaderMode.Chain,
            AuthorizedSigningIssuerExpectation.Exact("synthetic-issuer"),
            (AuthorizedSigningCertificateKeyUsageMode)99));
    }
}

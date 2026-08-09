using System.Collections.Frozen;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SecureIntegration.Authentication.CertificateSigning;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

/// <summary>Healthcare-owned policy projection over one registered, non-forgeable dispatch authority.</summary>
public sealed class Fse2AuthenticationPolicySource(
    Fse2DispatchAuthorityRegistry dispatches,
    ICertificatePublicMaterialProvider publicMaterial) : IAuthenticationPolicySource
{
    internal static readonly IReadOnlySet<string> SignatureClaims = new HashSet<string>(StringComparer.Ordinal)
    {
        "subject_role", "purpose_of_use", "subject_organization", "subject_organization_id", "locality",
        "person_id", "patient_consent", "resource_hl7_type", "action_id", "attachment_hash",
        "subject_application_id", "subject_application_vendor", "subject_application_version"
    }.ToFrozenSet(StringComparer.Ordinal);

    public async Task<ServerOwnedRs256PolicySnapshot> ResolveRs256Async(
        AuthenticationExecutionContext context, string policyId, CancellationToken cancellationToken)
    {
        AuthorizedFse2Dispatch authority = dispatches.GetRequired(context);
        Fse2PublishedOrganizationProfile profile = authority.Profile;
        bool authentication = string.Equals(policyId, profile.AuthenticationJwtProfileId, StringComparison.Ordinal);
        bool signature = string.Equals(policyId, profile.SignatureJwtProfileId, StringComparison.Ordinal);
        if ((!authentication && !signature) || !string.Equals(context.ProfileId, policyId, StringComparison.Ordinal))
            throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-POLICY-DENIED");

        string commonName = await ResolveVerifiedCommonNameAsync(authority.Signing, cancellationToken).ConfigureAwait(false);
        return ServerOwnedRs256PolicySnapshot.Create(
            policyId,
            profile.Revision,
            context.ConnectorVersionId,
            context.ConnectorId,
            context.OperationId,
            context.EnvironmentId,
            context.Endpoint,
            (authentication ? "auth:" : "integrity:") + commonName,
            profile.BaseEndpoint.AbsoluteUri,
            JwtSubjectPolicy.Fixed,
            profile.SubjectCx,
            authentication ? FrozenSet<string>.Empty : SignatureClaims,
            profile.TokenLifetime,
            profile.AllowedClockSkew,
            authority.Signing.LogicalBindingId,
            authority.Signing.PublicMetadata.Version,
            authority.Signing.CatalogRevision,
            authority.Signing.CatalogChecksumSha256,
            certificateHeaderMode: JwtCertificateHeaderMode.Leaf,
            temporalClaimMode: JwtTemporalClaimMode.IssuedAtExpiration);
    }

    public Task<ServerOwnedMutualTlsPolicySnapshot> ResolveMutualTlsAsync(
        AuthenticationExecutionContext context, string policyId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        AuthorizedFse2Dispatch authority = dispatches.GetRequired(context);
        Fse2PublishedOrganizationProfile profile = authority.Profile;
        if (!string.Equals(policyId, profile.MutualTlsProfileId, StringComparison.Ordinal) ||
            !string.Equals(context.ProfileId, policyId, StringComparison.Ordinal))
            throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-POLICY-DENIED");
        return Task.FromResult(ServerOwnedMutualTlsPolicySnapshot.Create(
            policyId,
            profile.Revision,
            context.ConnectorVersionId,
            context.ConnectorId,
            context.OperationId,
            context.EnvironmentId,
            context.Endpoint,
            authority.Operation.Method.Method,
            authority.MutualTls.LogicalBindingId,
            authority.MutualTls.PublicMetadata.Version,
            authority.MutualTls.CatalogRevision,
            authority.MutualTls.CatalogChecksumSha256,
            TimeSpan.FromDays(7),
            profile.TransportTimeout,
            profile.MaximumResponseBytes));
    }

    private async Task<string> ResolveVerifiedCommonNameAsync(Fse2ResolvedResourceAuthority signing, CancellationToken cancellationToken)
    {
        ProviderCertificatePublicMaterial material;
        try { material = await publicMaterial.GetPublicMaterialAsync(signing.ProviderReference, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-MATERIAL-UNAVAILABLE"); }
        try
        {
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(material.LeafCertificateDer.Span);
            using RSA? rsa = certificate.GetRSAPublicKey();
            if (rsa is null) throw new CryptographicException();
            string fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
            string spki = Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()));
            if (!FixedHexEquals(fingerprint, signing.PublicMetadata.FingerprintSha256) ||
                !FixedHexEquals(spki, signing.PublicMetadata.SubjectPublicKeyInfoSha256) ||
                !FixedHexEquals(fingerprint, material.Metadata.FingerprintSha256) ||
                !FixedHexEquals(spki, material.SubjectPublicKeyInfoSha256) ||
                !string.Equals(material.Metadata.Version, signing.PublicMetadata.Version, StringComparison.Ordinal))
                throw new CryptographicException();
            return Fse2X500CommonName.ReadExactlyOne(certificate.SubjectName.RawData);
        }
        catch (AuthenticationPrimitiveException) { throw; }
        catch (Exception) { throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-DENIED"); }
    }

    private static bool FixedHexEquals(string left, string right) => Fse2Validation.IsSha256(left) && Fse2Validation.IsSha256(right) &&
        CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));
}

/// <summary>Exact binding projection from the same composite authority used by both JWTs.</summary>
public sealed class Fse2AuthenticationResourceBindingResolver(
    Fse2AuthenticationPolicySource policies,
    Fse2DispatchAuthorityRegistry dispatches)
    : IAuthenticationResourceBindingResolver
{
    public Task<BoundAuthenticationResource> ResolveAsync(AuthenticationExecutionContext context, string logicalBindingId,
        AuthenticationResourcePurpose purpose, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        AuthorizedFse2Dispatch authority = dispatches.GetRequired(context);
        Fse2ResolvedResourceAuthority resource = purpose switch
        {
            AuthenticationResourcePurpose.JwtSigning => authority.Signing,
            AuthenticationResourcePurpose.MutualTlsClientAuthentication => authority.MutualTls,
            _ => throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-PURPOSE-DENIED")
        };
        if (resource.Purpose != purpose || !string.Equals(resource.LogicalBindingId, logicalBindingId, StringComparison.Ordinal))
            throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-BOUNDARY");
        return ResolveBoundAsync();

        async Task<BoundAuthenticationResource> ResolveBoundAsync()
        {
            string policyChecksum = purpose == AuthenticationResourcePurpose.JwtSigning
                ? (await policies.ResolveRs256Async(context, context.ProfileId, cancellationToken).ConfigureAwait(false)).PolicyChecksumSha256
                : (await policies.ResolveMutualTlsAsync(context, context.ProfileId, cancellationToken).ConfigureAwait(false)).PolicyChecksumSha256;
            return new BoundAuthenticationResource(
            resource.LogicalBindingId, purpose, AuthenticationResourceStatus.Active, context.ConnectorVersionId,
            context.ConnectorId, context.OperationId, context.ProfileId, authority.Profile.Revision,
            policyChecksum, context.EnvironmentId, context.Endpoint, resource.CatalogRevision,
            resource.CatalogChecksumSha256, resource.ProviderReference, resource.PublicMetadata);
        }
    }
}

/// <summary>DER X.500 Name parser accepting exactly one normalized commonName attribute.</summary>
internal static class Fse2X500CommonName
{
    private const string CommonNameOid = "2.5.4.3";

    internal static string ReadExactlyOne(ReadOnlyMemory<byte> rawName)
    {
        AsnReader root = new(rawName, AsnEncodingRules.DER);
        AsnReader name = root.ReadSequence();
        string? commonName = null;
        int count = 0;
        while (name.HasData)
        {
            AsnReader rdn = name.ReadSetOf(skipSortOrderValidation: true);
            while (rdn.HasData)
            {
                AsnReader attribute = rdn.ReadSequence();
                string oid = attribute.ReadObjectIdentifier();
                if (oid == CommonNameOid)
                {
                    count++;
                    if (count != 1) throw new CryptographicException();
                    commonName = ReadDirectoryString(attribute);
                }
                else
                {
                    _ = attribute.ReadEncodedValue();
                }
                if (attribute.HasData) throw new CryptographicException();
            }
        }
        if (root.HasData || count != 1 || commonName is null || string.IsNullOrWhiteSpace(commonName) ||
            commonName.Length > 128 || commonName != commonName.Trim() ||
            commonName.Normalize(NormalizationForm.FormC) != commonName || commonName.Any(char.IsControl))
            throw new CryptographicException();
        return commonName;
    }

    private static string ReadDirectoryString(AsnReader attribute)
    {
        Asn1Tag tag = attribute.PeekTag();
        foreach (UniversalTagNumber type in new[]
        {
            UniversalTagNumber.UTF8String, UniversalTagNumber.PrintableString, UniversalTagNumber.BMPString,
            UniversalTagNumber.UniversalString, UniversalTagNumber.TeletexString
        })
            if (tag.HasSameClassAndValue(new Asn1Tag(type))) return attribute.ReadCharacterString(type);
        throw new CryptographicException();
    }
}

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecureIntegration.Authentication.CertificateSigning;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

/// <summary>Protected runtime resource result; public Connector configuration contains only its logical binding.</summary>
public sealed record Fse2AuthenticationResource(
    string LogicalBindingId,
    AuthenticationResourcePurpose Purpose,
    AuthenticationResourceStatus Status,
    string ProviderReference,
    BoundResourcePublicMetadata PublicMetadata);

/// <summary>Resolves an exact server-owned provider resource behind a logical Published binding.</summary>
public interface IFse2AuthenticationResourceCatalog
{
    Task<Fse2AuthenticationResource> ResolveAsync(
        Fse2PublishedOrganizationProfile profile,
        string logicalBindingId,
        AuthenticationResourcePurpose purpose,
        CancellationToken cancellationToken);
}

/// <summary>
/// Healthcare-owned policy composition: fixed organization CX subject, official issuer prefix plus the CN
/// parsed from exact public signing DER, typed x5c and exact temporal inclusion. It adds no Core primitive.
/// </summary>
public sealed class Fse2AuthenticationPolicySource(
    IFse2PublishedProfileSource profiles,
    IFse2AuthenticationResourceCatalog resources,
    ICertificatePublicMaterialProvider publicMaterial) : IAuthenticationPolicySource
{
    internal static readonly IReadOnlySet<string> SignatureClaims = new HashSet<string>(StringComparer.Ordinal)
    {
        "subject_role", "purpose_of_use", "subject_organization", "subject_organization_id", "locality",
        "person_id", "patient_consent", "resource_hl7_type", "action_id", "attachment_hash",
        "subject_application_id", "subject_application_vendor", "subject_application_version"
    };

    public async Task<ServerOwnedRs256PolicySnapshot> ResolveRs256Async(AuthenticationExecutionContext context, string policyId, CancellationToken cancellationToken)
    {
        Fse2PublishedOrganizationProfile profile = await ResolveProfileAsync(context, cancellationToken).ConfigureAwait(false);
        bool authentication = string.Equals(policyId, profile.AuthenticationJwtProfileId, StringComparison.Ordinal);
        bool signature = string.Equals(policyId, profile.SignatureJwtProfileId, StringComparison.Ordinal);
        if ((!authentication && !signature) || !string.Equals(context.ProfileId, policyId, StringComparison.Ordinal))
            throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-POLICY-DENIED");

        Fse2AuthenticationResource signing = await ResolveResourceAsync(profile, profile.SigningBindingId, AuthenticationResourcePurpose.JwtSigning, cancellationToken).ConfigureAwait(false);
        string commonName = await ResolveVerifiedCommonNameAsync(signing, cancellationToken).ConfigureAwait(false);
        return ServerOwnedRs256PolicySnapshot.Create(
            policyId,
            profile.Revision,
            context.ConnectorVersionId,
            context.ConnectorId,
            context.OperationId,
            context.EnvironmentId,
            context.Endpoint,
            (authentication ? "auth:" : "integrity:") + commonName,
            profile.BaseEndpoint.AbsoluteUri.TrimEnd('/'),
            JwtSubjectPolicy.Fixed,
            profile.SubjectCx,
            authentication ? new HashSet<string>(StringComparer.Ordinal) : SignatureClaims,
            profile.TokenLifetime,
            profile.AllowedClockSkew,
            profile.SigningBindingId,
            signing.PublicMetadata.Version,
            profile.Revision,
            profile.ChecksumSha256,
            certificateHeaderMode: JwtCertificateHeaderMode.Leaf,
            temporalClaimMode: JwtTemporalClaimMode.IssuedAtExpiration);
    }

    public async Task<ServerOwnedMutualTlsPolicySnapshot> ResolveMutualTlsAsync(AuthenticationExecutionContext context, string policyId, CancellationToken cancellationToken)
    {
        Fse2PublishedOrganizationProfile profile = await ResolveProfileAsync(context, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(policyId, profile.MutualTlsProfileId, StringComparison.Ordinal) || !string.Equals(context.ProfileId, policyId, StringComparison.Ordinal))
            throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-POLICY-DENIED");
        Fse2AuthenticationResource mtls = await ResolveResourceAsync(profile, profile.MutualTlsBindingId, AuthenticationResourcePurpose.MutualTlsClientAuthentication, cancellationToken).ConfigureAwait(false);
        Fse2OperationDescriptor operation = Fse2OperationCatalog.Get(profile.Authority.Operation);
        return ServerOwnedMutualTlsPolicySnapshot.Create(
            policyId,
            profile.Revision,
            context.ConnectorVersionId,
            context.ConnectorId,
            context.OperationId,
            context.EnvironmentId,
            context.Endpoint,
            operation.Method.Method,
            profile.MutualTlsBindingId,
            mtls.PublicMetadata.Version,
            profile.Revision,
            profile.ChecksumSha256,
            TimeSpan.FromDays(7),
            profile.TransportTimeout,
            profile.MaximumResponseBytes);
    }

    internal async Task<Fse2PublishedOrganizationProfile> ResolveProfileAsync(AuthenticationExecutionContext context, CancellationToken cancellationToken)
    {
        Fse2Operation operation = OperationFromId(context.OperationId);
        Fse2PublishedProfileLookup lookup = new(context.TenantId, context.ApplicationId, context.InstallationId, context.EnvironmentId,
            context.ConnectorId, operation);
        Fse2PublishedOrganizationProfile profile = await profiles.ResolveAsync(lookup, cancellationToken).ConfigureAwait(false)
            ?? throw new AuthenticationPrimitiveException("BGW-AUTH-POLICY-BOUNDARY");
        try { Fse2PublishedOrganizationProfile.ValidateAuthority(profile, lookup); }
        catch (Fse2ConnectorException) { throw new AuthenticationPrimitiveException("BGW-AUTH-POLICY-BOUNDARY"); }
        if (profile.ConnectorVersionId != context.ConnectorVersionId || !Fse2OperationCatalog.MatchesEndpoint(profile.BaseEndpoint, operation, context.Endpoint))
            throw new AuthenticationPrimitiveException("BGW-AUTH-POLICY-BOUNDARY");
        return profile;
    }

    internal async Task<Fse2AuthenticationResource> ResolveResourceAsync(Fse2PublishedOrganizationProfile profile, string bindingId, AuthenticationResourcePurpose purpose, CancellationToken cancellationToken)
    {
        Fse2AuthenticationResource resource = await resources.ResolveAsync(profile, bindingId, purpose, cancellationToken).ConfigureAwait(false)
            ?? throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-BOUNDARY");
        if (resource.Status != AuthenticationResourceStatus.Active || !string.Equals(resource.LogicalBindingId, bindingId, StringComparison.Ordinal) || resource.Purpose != purpose ||
            string.IsNullOrWhiteSpace(resource.ProviderReference) || resource.ProviderReference.Length > 1024 || resource.ProviderReference.Any(character => character is '\r' or '\n') ||
            !Fse2Validation.IsSha256(resource.PublicMetadata.FingerprintSha256) || !Fse2Validation.IsSha256(resource.PublicMetadata.SubjectPublicKeyInfoSha256))
            throw new AuthenticationPrimitiveException(resource.Status == AuthenticationResourceStatus.Disabled ? "BGW-AUTH-RESOURCE-DISABLED" : "BGW-AUTH-RESOURCE-BOUNDARY");
        return resource;
    }

    private async Task<string> ResolveVerifiedCommonNameAsync(Fse2AuthenticationResource signing, CancellationToken cancellationToken)
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
            if (!FixedHexEquals(fingerprint, signing.PublicMetadata.FingerprintSha256) || !FixedHexEquals(spki, signing.PublicMetadata.SubjectPublicKeyInfoSha256) ||
                !FixedHexEquals(fingerprint, material.Metadata.FingerprintSha256) || !FixedHexEquals(spki, material.SubjectPublicKeyInfoSha256) ||
                !string.Equals(material.Metadata.Version, signing.PublicMetadata.Version, StringComparison.Ordinal))
                throw new CryptographicException();
            string commonName = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            if (string.IsNullOrWhiteSpace(commonName) || commonName.Length > 128 || commonName != commonName.Trim() || commonName.Any(char.IsControl))
                throw new CryptographicException();
            return commonName;
        }
        catch (AuthenticationPrimitiveException) { throw; }
        catch (Exception) { throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-DENIED"); }
    }

    private static Fse2Operation OperationFromId(string operationId)
    {
        Fse2OperationDescriptor? descriptor = Fse2OperationCatalog.All.SingleOrDefault(value => string.Equals(value.OperationId, operationId, StringComparison.Ordinal));
        return descriptor?.Operation ?? throw new AuthenticationPrimitiveException("BGW-AUTH-BOUND-CONTEXT-INVALID");
    }

    private static bool FixedHexEquals(string left, string right) => Fse2Validation.IsSha256(left) && Fse2Validation.IsSha256(right) &&
        CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));
}

/// <summary>Core binding resolver backed only by FSE2 Published profiles and protected resource catalog entries.</summary>
public sealed class Fse2AuthenticationResourceBindingResolver(
    Fse2AuthenticationPolicySource policies) : IAuthenticationResourceBindingResolver
{
    public async Task<BoundAuthenticationResource> ResolveAsync(AuthenticationExecutionContext context, string logicalBindingId, AuthenticationResourcePurpose purpose, CancellationToken cancellationToken)
    {
        Fse2PublishedOrganizationProfile profile = await policies.ResolveProfileAsync(context, cancellationToken).ConfigureAwait(false);
        Fse2AuthenticationResource resource = await policies.ResolveResourceAsync(profile, logicalBindingId, purpose, cancellationToken).ConfigureAwait(false);
        long policyRevision;
        string policyChecksum;
        if (purpose == AuthenticationResourcePurpose.JwtSigning)
        {
            ServerOwnedRs256PolicySnapshot policy = await policies.ResolveRs256Async(context, context.ProfileId, cancellationToken).ConfigureAwait(false);
            policyRevision = policy.PolicyRevision;
            policyChecksum = policy.PolicyChecksumSha256;
        }
        else
        {
            ServerOwnedMutualTlsPolicySnapshot policy = await policies.ResolveMutualTlsAsync(context, context.ProfileId, cancellationToken).ConfigureAwait(false);
            policyRevision = policy.PolicyRevision;
            policyChecksum = policy.PolicyChecksumSha256;
        }
        return new(resource.LogicalBindingId, purpose, resource.Status, context.ConnectorVersionId, context.ConnectorId,
            context.OperationId, context.ProfileId, policyRevision, policyChecksum, context.EnvironmentId, context.Endpoint,
            profile.Revision, profile.ChecksumSha256, resource.ProviderReference, resource.PublicMetadata);
    }
}

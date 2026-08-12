using System.Security.Cryptography;

namespace SecureIntegration.Authentication.CertificateSigning;

internal static class BindingPolicy
{
    internal static void ValidateContext(AuthenticationExecutionContext context)
    {
        if (context.TenantId == Guid.Empty || context.InstallationId == Guid.Empty || context.ApplicationId == Guid.Empty ||
            context.EnvironmentId == Guid.Empty || context.ConnectorVersionId == Guid.Empty || context.CorrelationId == Guid.Empty ||
            !IsIdentifier(context.ConnectorId) || !IsIdentifier(context.OperationId) || !IsIdentifier(context.ProfileId) ||
            !IsSafeEndpoint(context.Endpoint))
            throw new AuthenticationPrimitiveException("BGW-AUTH-BOUND-CONTEXT-INVALID");
    }

    internal static void ValidateBinding(AuthenticationExecutionContext context, BoundAuthenticationResource resource, string logicalBindingId, AuthenticationResourcePurpose purpose)
    {
        if (resource.Status != AuthenticationResourceStatus.Active)
            throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-DISABLED");
        if (!string.Equals(resource.LogicalBindingId, logicalBindingId, StringComparison.Ordinal) || resource.Purpose != purpose ||
            resource.ConnectorVersionId != context.ConnectorVersionId || resource.EnvironmentId != context.EnvironmentId ||
            !string.Equals(resource.ConnectorId, context.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(resource.OperationId, context.OperationId, StringComparison.Ordinal) ||
            !string.Equals(resource.ProfileId, context.ProfileId, StringComparison.Ordinal) ||
            resource.PolicyRevision <= 0 || !IsSha256(resource.PolicyChecksumSha256) ||
            resource.Endpoint != context.Endpoint || resource.CatalogRevision <= 0 ||
            !IsSha256(resource.CatalogChecksumSha256) || string.IsNullOrWhiteSpace(resource.ProviderReference) ||
            resource.ProviderReference.Length > 1024 || resource.ProviderReference.Any(character => character is '\r' or '\n'))
            throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-BOUNDARY");
        ValidateExpectedMetadata(resource.PublicMetadata);
    }

    internal static void ValidateExpectedMetadata(BoundResourcePublicMetadata metadata)
    {
        if (!IsSha256(metadata.FingerprintSha256) || !IsSha256(metadata.SubjectPublicKeyInfoSha256) || metadata.NotAfter <= metadata.NotBefore ||
            string.IsNullOrWhiteSpace(metadata.KeyAlgorithm) || metadata.PublicKeySize <= 0 ||
            string.IsNullOrWhiteSpace(metadata.Version) || metadata.Version.Length > 128)
            throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-METADATA");
    }

    internal static void MatchMetadata(BoundResourcePublicMetadata expected, string fingerprint, DateTimeOffset notBefore, DateTimeOffset notAfter, string algorithm, int keySize, string version)
    {
        if (!FixedHexEquals(expected.FingerprintSha256, fingerprint) || expected.NotBefore != notBefore || expected.NotAfter != notAfter ||
            !string.Equals(expected.KeyAlgorithm, algorithm, StringComparison.Ordinal) || expected.PublicKeySize != keySize ||
            !string.Equals(expected.Version, version, StringComparison.Ordinal))
            throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-METADATA-STALE");
    }

    internal static void ValidateRs256Policy(AuthenticationExecutionContext context, string requestedPolicyId, ServerOwnedRs256PolicySnapshot policy)
    {
        if (!IsIdentifier(requestedPolicyId) || !string.Equals(requestedPolicyId, context.ProfileId, StringComparison.Ordinal) ||
            !string.Equals(policy.PolicyId, requestedPolicyId, StringComparison.Ordinal) || policy.PolicyRevision <= 0 ||
            policy.ConnectorVersionId != context.ConnectorVersionId || policy.EnvironmentId != context.EnvironmentId ||
            !string.Equals(policy.ConnectorId, context.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(policy.OperationId, context.OperationId, StringComparison.Ordinal) || policy.Endpoint != context.Endpoint ||
            !FixedHexEquals(policy.PolicyChecksumSha256, AuthenticationPolicyDigest.Rs256(policy)) ||
            !SafeAuthority(policy.Issuer) || !SafeAuthority(policy.Audience) || !IsIdentifier(policy.LogicalKeyBindingId) ||
            policy.Lifetime <= TimeSpan.Zero || policy.Lifetime > TimeSpan.FromHours(1) ||
            policy.AllowedClockSkew < TimeSpan.Zero || policy.AllowedClockSkew > TimeSpan.FromMinutes(5) ||
            policy.MinimumRsaKeySize < 2048 || policy.MinimumRsaKeySize > 16384 || policy.AllowedClaims.Count > 32 ||
            policy.AllowedClaims.Any(name => !ValidClaimName(name) || Rs256JwtSigner.IsReservedClaim(name)) ||
            policy.SubjectPolicy is not (JwtSubjectPolicy.Installation or JwtSubjectPolicy.Application or JwtSubjectPolicy.Fixed or JwtSubjectPolicy.Tenant or JwtSubjectPolicy.TrustedRuntimeValue) ||
            (policy.SubjectPolicy == JwtSubjectPolicy.Fixed) != !string.IsNullOrWhiteSpace(policy.FixedSubject) ||
            (policy.SubjectPolicy == JwtSubjectPolicy.TrustedRuntimeValue) != policy.TrustedSubjectSource.HasValue ||
            (policy.TrustedSubjectSource.HasValue && !IsTrustedRuntimeSource(policy.TrustedSubjectSource.Value)) ||
            policy.CertificateHeaderMode is not (JwtCertificateHeaderMode.None or JwtCertificateHeaderMode.Leaf or JwtCertificateHeaderMode.Chain) ||
            policy.TemporalClaimMode is not (JwtTemporalClaimMode.IssuedAtNotBeforeExpiration or JwtTemporalClaimMode.IssuedAtExpiration) ||
            policy.CertificateKeyUsageMode is not (JwtSigningCertificateKeyUsageMode.DigitalSignature or JwtSigningCertificateKeyUsageMode.ContentCommitment) ||
            !ValidTrustedClaims(policy) ||
            policy.FixedSubject?.Length > 512 || string.IsNullOrWhiteSpace(policy.ResourceVersion) || policy.ResourceVersion.Length > 128 ||
            policy.CatalogRevision <= 0 || !IsSha256(policy.CatalogChecksumSha256))
            throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-POLICY-DENIED");
    }

    internal static void ValidateMutualTlsPolicy(AuthenticationExecutionContext context, string requestedPolicyId, ServerOwnedMutualTlsPolicySnapshot policy)
    {
        if (!IsIdentifier(requestedPolicyId) || !string.Equals(requestedPolicyId, context.ProfileId, StringComparison.Ordinal) ||
            !string.Equals(policy.PolicyId, requestedPolicyId, StringComparison.Ordinal) || policy.PolicyRevision <= 0 ||
            policy.ConnectorVersionId != context.ConnectorVersionId || policy.EnvironmentId != context.EnvironmentId ||
            !string.Equals(policy.ConnectorId, context.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(policy.OperationId, context.OperationId, StringComparison.Ordinal) || policy.Endpoint != context.Endpoint ||
            !FixedHexEquals(policy.PolicyChecksumSha256, AuthenticationPolicyDigest.MutualTls(policy)) ||
            !IsIdentifier(policy.LogicalCertificateBindingId) || string.IsNullOrWhiteSpace(policy.ResourceVersion) || policy.ResourceVersion.Length > 128 ||
            policy.CatalogRevision <= 0 || !IsSha256(policy.CatalogChecksumSha256) ||
            policy.HttpMethod is not ("GET" or "POST" or "PUT" or "DELETE") ||
            policy.NearExpiryWarningWindow < TimeSpan.Zero || policy.NearExpiryWarningWindow > TimeSpan.FromDays(90) ||
            policy.Timeout < TimeSpan.FromMilliseconds(100) || policy.Timeout > TimeSpan.FromMinutes(2) ||
            policy.MaximumResponseBytes <= 0 || policy.MaximumResponseBytes > 16 * 1024 * 1024 ||
            policy.MinimumRsaKeySize < 2048 || policy.MinimumRsaKeySize > 16384 ||
            policy.MinimumEcdsaKeySize < 256 || policy.MinimumEcdsaKeySize > 1024)
            throw new AuthenticationPrimitiveException("BGW-AUTH-MTLS-POLICY-DENIED");
    }

    internal static void ValidateExactPolicyBinding(BoundAuthenticationResource resource, long policyRevision, string policyChecksum, long catalogRevision, string catalogChecksum, string resourceVersion)
    {
        if (resource.PolicyRevision != policyRevision || !FixedHexEquals(resource.PolicyChecksumSha256, policyChecksum) ||
            resource.CatalogRevision != catalogRevision || !FixedHexEquals(resource.CatalogChecksumSha256, catalogChecksum) ||
            !string.Equals(resource.PublicMetadata.Version, resourceVersion, StringComparison.Ordinal))
            throw new AuthenticationPrimitiveException("BGW-AUTH-POLICY-BINDING-STALE");
    }

    internal static bool IsIdentifier(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    internal static bool IsSha256(string? value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);

    internal static bool ValidClaimName(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 64 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    private static bool ValidTrustedClaims(ServerOwnedRs256PolicySnapshot policy)
    {
        if (policy.TrustedClaims.Count > 16 || policy.AllowedClaims.Count + policy.TrustedClaims.Count > 32) return false;
        HashSet<string> names = new(StringComparer.Ordinal);
        foreach (JwtTrustedClaimBinding claim in policy.TrustedClaims)
        {
            if (!ValidClaimName(claim.Name) || Rs256JwtSigner.IsReservedClaim(claim.Name) || policy.AllowedClaims.Contains(claim.Name) ||
                !names.Add(claim.Name) || !IsTrustedValueSource(claim.Source))
                return false;
        }
        return true;
    }

    internal static bool IsTrustedRuntimeSource(JwtTrustedValueSource source) => source is
        JwtTrustedValueSource.ExternalActorId or
        JwtTrustedValueSource.DelegatedSubjectId or
        JwtTrustedValueSource.AuthorizedOperatorId;

    private static bool IsTrustedValueSource(JwtTrustedValueSource source) => source is
        JwtTrustedValueSource.AuthenticatedTenantId or
        JwtTrustedValueSource.AuthenticatedApplicationId or
        JwtTrustedValueSource.AuthenticatedInstallationId || IsTrustedRuntimeSource(source);

    private static bool FixedHexEquals(string left, string right)
    {
        if (!IsSha256(left) || !IsSha256(right)) return false;
        return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));
    }

    private static bool IsSafeEndpoint(Uri endpoint) => endpoint.IsAbsoluteUri && endpoint.Scheme == Uri.UriSchemeHttps &&
        string.IsNullOrEmpty(endpoint.UserInfo) && string.IsNullOrEmpty(endpoint.Fragment);

    private static bool SafeAuthority(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
}

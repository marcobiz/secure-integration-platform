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
            resource.Endpoint != context.Endpoint || resource.CatalogRevision <= 0 ||
            !IsSha256(resource.CatalogChecksumSha256) || string.IsNullOrWhiteSpace(resource.ProviderReference) ||
            resource.ProviderReference.Length > 1024 || resource.ProviderReference.Any(character => character is '\r' or '\n'))
            throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-BOUNDARY");
        ValidateExpectedMetadata(resource.PublicMetadata);
    }

    internal static void ValidateExpectedMetadata(BoundResourcePublicMetadata metadata)
    {
        if (!IsSha256(metadata.FingerprintSha256) || metadata.NotAfter <= metadata.NotBefore ||
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

    internal static bool IsIdentifier(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    internal static bool IsSha256(string? value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private static bool FixedHexEquals(string left, string right)
    {
        if (!IsSha256(left) || !IsSha256(right)) return false;
        return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));
    }

    private static bool IsSafeEndpoint(Uri endpoint) => endpoint.IsAbsoluteUri && endpoint.Scheme == Uri.UriSchemeHttps &&
        string.IsNullOrEmpty(endpoint.UserInfo) && string.IsNullOrEmpty(endpoint.Fragment);
}

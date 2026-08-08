using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecureIntegration.Authentication.CertificateSigning;

internal static class AuthenticationPolicyDigest
{
    internal static string Rs256(ServerOwnedRs256PolicySnapshot policy) => Compute(writer =>
    {
        Common(writer, policy.PolicyId, policy.PolicyRevision, policy.ConnectorVersionId, policy.ConnectorId, policy.OperationId, policy.EnvironmentId, policy.Endpoint);
        writer.WriteString("issuer", policy.Issuer);
        writer.WriteString("audience", policy.Audience);
        writer.WriteString("subjectPolicy", policy.SubjectPolicy.ToString());
        if (policy.FixedSubject is not null) writer.WriteString("fixedSubject", policy.FixedSubject);
        if (policy.TrustedSubjectSource is not null) writer.WriteString("trustedSubjectSource", policy.TrustedSubjectSource.Value.ToString());
        writer.WriteStartArray("allowedClaims");
        foreach (string claim in policy.AllowedClaims.Order(StringComparer.Ordinal)) writer.WriteStringValue(claim);
        writer.WriteEndArray();
        writer.WriteNumber("lifetimeTicks", policy.Lifetime.Ticks);
        writer.WriteNumber("allowedClockSkewTicks", policy.AllowedClockSkew.Ticks);
        writer.WriteString("certificateHeaderMode", policy.CertificateHeaderMode.ToString());
        writer.WriteString("temporalClaimMode", policy.TemporalClaimMode.ToString());
        writer.WriteStartArray("trustedClaims");
        foreach (JwtTrustedClaimBinding claim in policy.TrustedClaims.OrderBy(value => value.Name, StringComparer.Ordinal))
        {
            writer.WriteStartObject();
            writer.WriteString("name", claim.Name);
            writer.WriteString("source", claim.Source.ToString());
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
        writer.WriteString("logicalKeyBindingId", policy.LogicalKeyBindingId);
        writer.WriteString("resourceVersion", policy.ResourceVersion);
        writer.WriteNumber("catalogRevision", policy.CatalogRevision);
        writer.WriteString("catalogChecksumSha256", policy.CatalogChecksumSha256);
        writer.WriteNumber("minimumRsaKeySize", policy.MinimumRsaKeySize);
    });

    internal static string MutualTls(ServerOwnedMutualTlsPolicySnapshot policy) => Compute(writer =>
    {
        Common(writer, policy.PolicyId, policy.PolicyRevision, policy.ConnectorVersionId, policy.ConnectorId, policy.OperationId, policy.EnvironmentId, policy.Endpoint);
        writer.WriteString("httpMethod", policy.HttpMethod);
        writer.WriteString("logicalCertificateBindingId", policy.LogicalCertificateBindingId);
        writer.WriteString("resourceVersion", policy.ResourceVersion);
        writer.WriteNumber("catalogRevision", policy.CatalogRevision);
        writer.WriteString("catalogChecksumSha256", policy.CatalogChecksumSha256);
        writer.WriteNumber("nearExpiryWarningWindowTicks", policy.NearExpiryWarningWindow.Ticks);
        writer.WriteNumber("timeoutTicks", policy.Timeout.Ticks);
        writer.WriteNumber("maximumResponseBytes", policy.MaximumResponseBytes);
        writer.WriteNumber("minimumRsaKeySize", policy.MinimumRsaKeySize);
        writer.WriteNumber("minimumEcdsaKeySize", policy.MinimumEcdsaKeySize);
    });

    private static string Compute(Action<Utf8JsonWriter> fields)
    {
        using MemoryStream stream = new();
        using (Utf8JsonWriter writer = new(stream))
        {
            writer.WriteStartObject();
            fields(writer);
            writer.WriteEndObject();
        }
        return Convert.ToHexString(SHA256.HashData(stream.ToArray()));
    }

    private static void Common(Utf8JsonWriter writer, string policyId, long policyRevision, Guid connectorVersionId, string connectorId, string operationId, Guid environmentId, Uri endpoint)
    {
        writer.WriteString("policyId", policyId);
        writer.WriteNumber("policyRevision", policyRevision);
        writer.WriteString("connectorVersionId", connectorVersionId);
        writer.WriteString("connectorId", connectorId);
        writer.WriteString("operationId", operationId);
        writer.WriteString("environmentId", environmentId);
        writer.WriteString("endpoint", endpoint.AbsoluteUri);
    }
}

using System.Collections.Frozen;
using System.Text.Json;

namespace SecureIntegration.Tools.Fse2.OfficialTestProvisioner;

internal sealed record Fse2FailureDiagnosticsEvidence(
    string FailurePhase,
    int? UpstreamStatus,
    string StatusCategory,
    string? SafeUpstreamCode,
    string? LocalSafeCode);

/// <summary>Reduces one authorized Admin audit read-back to the closed diagnostics DTO only.</summary>
internal static class Fse2FailureEvidenceReducer
{
    private static readonly FrozenSet<string> FailurePhases = new[]
    {
        "DNS_FAILURE", "TCP_CONNECT_FAILURE", "TLS_SERVER_VALIDATION_FAILURE",
        "MTLS_CLIENT_AUTH_FAILURE", "TIMEOUT", "TRANSPORT_FAILURE_OTHER",
        "UPSTREAM_HTTP_RESPONSE", "LOCAL_RESPONSE_MAPPING_FAILURE"
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> StatusCategories = new[]
    {
        "NO_UPSTREAM_RESPONSE", "INFORMATIONAL", "SUCCESS", "REDIRECTION",
        "CLIENT_ERROR", "SERVER_ERROR"
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> OfficialProblemCodes = new[]
    {
        "cda-element", "cda-extraction", "cda-match", "cda-validation", "document-hash",
        "document-type", "eds-document-missing", "eds-error", "empty-file", "fhir-element",
        "fhir-extraction", "fhir-mapping-type", "generic-error", "generic-timeout", "ini-error",
        "invalid-format", "jwt-validation", "mandatory-element", "mandatory-element-token",
        "max-day-limit-exceed", "missing-token", "record-not-found", "semantic", "service-error",
        "syntax", "vocabulary", "workflow-id-error-extraction"
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> LocalSafeCodes = new[]
    {
        "FSE2_RESPONSE_INVALID"
    }.ToFrozenSet(StringComparer.Ordinal);

    internal static Fse2FailureDiagnosticsEvidence Reduce(JsonElement auditPage, Guid correlationId)
    {
        if (correlationId == Guid.Empty || auditPage.ValueKind != JsonValueKind.Object ||
            !auditPage.TryGetProperty("items", out JsonElement items) || items.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("FSE2_EVIDENCE_AUDIT_INPUT_INVALID");

        JsonElement[] matches = items.EnumerateArray().Where(value =>
            value.ValueKind == JsonValueKind.Object &&
            RequiredString(value, "action") == "operation.invoke" &&
            RequiredString(value, "outcome") == "failure" &&
            value.TryGetProperty("correlationId", out JsonElement correlation) &&
            correlation.ValueKind == JsonValueKind.String && correlation.TryGetGuid(out Guid parsed) &&
            parsed == correlationId).ToArray();
        if (matches.Length != 1 ||
            !matches[0].TryGetProperty("failureDiagnostics", out JsonElement diagnostics) ||
            diagnostics.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("FSE2_EVIDENCE_FAILURE_DIAGNOSTICS_NOT_UNIQUE");

        string[] expectedProperties =
        [
            "failurePhase", "upstreamStatus", "statusCategory", "safeUpstreamCode", "localSafeCode"
        ];
        string[] actualProperties = diagnostics.EnumerateObject().Select(value => value.Name).Order(StringComparer.Ordinal).ToArray();
        if (!actualProperties.SequenceEqual(expectedProperties.Order(StringComparer.Ordinal), StringComparer.Ordinal))
            throw new InvalidDataException("FSE2_EVIDENCE_FAILURE_DIAGNOSTICS_NOT_BOUNDED");

        string phase = RequiredString(diagnostics, "failurePhase");
        string category = RequiredString(diagnostics, "statusCategory");
        int? status = NullableStatus(diagnostics.GetProperty("upstreamStatus"));
        string? upstreamCode = NullableString(diagnostics.GetProperty("safeUpstreamCode"));
        string? localCode = NullableString(diagnostics.GetProperty("localSafeCode"));
        if (!FailurePhases.Contains(phase) || !StatusCategories.Contains(category) ||
            (upstreamCode is not null && !OfficialProblemCodes.Contains(upstreamCode)) ||
            (localCode is not null && !LocalSafeCodes.Contains(localCode)) ||
            !string.Equals(category, Category(status), StringComparison.Ordinal))
            throw new InvalidDataException("FSE2_EVIDENCE_FAILURE_DIAGNOSTICS_INVALID");

        bool transport = phase is "DNS_FAILURE" or "TCP_CONNECT_FAILURE" or
            "TLS_SERVER_VALIDATION_FAILURE" or "MTLS_CLIENT_AUTH_FAILURE" or
            "TIMEOUT" or "TRANSPORT_FAILURE_OTHER";
        if (transport && (status is not null || upstreamCode is not null || localCode is not null) ||
            phase == "UPSTREAM_HTTP_RESPONSE" && (status is null || localCode is not null) ||
            phase == "LOCAL_RESPONSE_MAPPING_FAILURE" && (status is null || localCode != "FSE2_RESPONSE_INVALID"))
            throw new InvalidDataException("FSE2_EVIDENCE_FAILURE_DIAGNOSTICS_INCONSISTENT");

        return new(phase, status, category, upstreamCode, localCode);
    }

    private static string RequiredString(JsonElement value, string name) =>
        value.TryGetProperty(name, out JsonElement property) && property.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(property.GetString())
            ? property.GetString()!
            : throw new InvalidDataException("FSE2_EVIDENCE_AUDIT_INPUT_INVALID");

    private static int? NullableStatus(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Null => null,
        JsonValueKind.Number when value.TryGetInt32(out int status) && status is >= 100 and <= 599 => status,
        _ => throw new InvalidDataException("FSE2_EVIDENCE_UPSTREAM_STATUS_INVALID")
    };

    private static string? NullableString(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Null => null,
        JsonValueKind.String when value.GetString() is { Length: >= 1 and <= 96 } text &&
            text.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.') => text,
        _ => throw new InvalidDataException("FSE2_EVIDENCE_SAFE_CODE_INVALID")
    };

    private static string Category(int? status) => status switch
    {
        null => "NO_UPSTREAM_RESPONSE",
        <= 199 => "INFORMATIONAL",
        <= 299 => "SUCCESS",
        <= 399 => "REDIRECTION",
        <= 499 => "CLIENT_ERROR",
        _ => "SERVER_ERROR"
    };
}

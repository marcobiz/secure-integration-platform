using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Json.Schema;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Application;

/// <summary>One redacted validation finding.</summary>
public sealed record ConnectorValidationIssue(string Code, string Location, string Message = "Connector definition validation failed.");

/// <summary>Validation output safe to return through the Admin API.</summary>
public sealed record ConnectorValidationResult(bool Valid, string? ChecksumSha256, IReadOnlyList<ConnectorValidationIssue> Issues);

/// <summary>Connector list projection without definition contents or bindings.</summary>
public sealed record ConnectorSummary(string ConnectorId, string DisplayName, int Versions, string? PublishedVersion, long PublicationRevision);

/// <summary>Admin API projection for one version.</summary>
public sealed record ConnectorVersionResource(
    string ConnectorId,
    string Version,
    string SchemaVersion,
    ConnectorVersionState State,
    string ChecksumSha256,
    long RowVersion,
    DateTimeOffset CreatedAt,
    DateTimeOffset? PublishedAt);

/// <summary>Import envelope; expected checksum protects artefact transfer.</summary>
public sealed record ConnectorImportRequest(JsonElement Definition, string? ExpectedChecksumSha256 = null);

/// <summary>Optimistic-concurrency envelope for lifecycle transitions.</summary>
public sealed record ConnectorVersionActionRequest(long ExpectedRowVersion, long? ExpectedPublicationRevision = null);

/// <summary>Rollback request targeting a version that was Published previously.</summary>
public sealed record ConnectorRollbackRequest(string TargetVersion, long ExpectedActiveRowVersion);

/// <summary>Environment binding request. Values remain server-side and are never part of Connector JSON.</summary>
public sealed record ConnectorBindingRequest(
    Guid EnvironmentId,
    IReadOnlyDictionary<string, string> Endpoints,
    IReadOnlyDictionary<string, ProviderResourceReference> SecretResources,
    long? ExpectedRevision = null,
    IReadOnlyDictionary<string, ProviderResourceReference>? CertificateResources = null,
    string? ConnectorVersion = null);

/// <summary>Non-destructive contract test of one Published operation and Environment binding.</summary>
public sealed record ConnectorTestRequest(Guid EnvironmentId, string OperationId);

/// <summary>Fail-closed syntax guard applied before the authoritative catalog lookup.</summary>
public static class ProviderResourceReferenceValidator
{
    private const int MaximumIdentifierLength = 128;

    /// <summary>Validates bounded logical identifiers. Catalog membership remains the primary security control.</summary>
    public static void Validate(ProviderResourceReference reference)
    {
        ValidateIdentifier(reference.ProviderId);
        ValidateIdentifier(reference.ResourceId);
        if (reference.Version is not null) ValidateIdentifier(reference.Version);
        if (reference.ResourceId.Contains("://", StringComparison.Ordinal) || reference.ResourceId.Contains("-----BEGIN", StringComparison.OrdinalIgnoreCase) ||
            reference.ResourceId.Contains("base64", StringComparison.OrdinalIgnoreCase) || reference.ResourceId.Contains("password=", StringComparison.OrdinalIgnoreCase) ||
            reference.ResourceId.Contains("user id=", StringComparison.OrdinalIgnoreCase) || reference.ResourceId.Contains("accountkey=", StringComparison.OrdinalIgnoreCase))
            throw new GatewayException("BGW-PROVIDER-RESOURCE-REFERENCE-DENIED", 400);
    }

    private static void ValidateIdentifier(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaximumIdentifierLength || value.Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.')))
            throw new GatewayException("BGW-PROVIDER-RESOURCE-REFERENCE-DENIED", 400);
    }
}

/// <summary>Machine-readable Connector artefacts embedded from their authoritative repository files.</summary>
public static class ConnectorDefinitionArtifacts
{
    private const string SchemaResource = "SecureIntegration.Gateway.Application.Connectors.connector-definition.schema.json";
    private const string SampleResource = "SecureIntegration.Gateway.Application.Connectors.sample-secure-service.connector.json";

    /// <summary>The authoritative Connector Definition JSON Schema Draft 2020-12 document.</summary>
    public static string SchemaJson { get; } = Read(SchemaResource);

    /// <summary>The authoritative synthetic Connector Definition example.</summary>
    public static string SampleJson { get; } = Read(SampleResource);

    private static string Read(string resource)
    {
        using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource)
            ?? throw new InvalidOperationException($"Embedded Connector artefact is missing: {resource}");
        using StreamReader reader = new(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}

/// <summary>Canonical JSON implementation for the constrained Connector v1 number domain.</summary>
public static class ConnectorCanonicalJson
{
    /// <summary>Sorts object names, removes insignificant whitespace and normalizes integer values.</summary>
    public static string Canonicalize(JsonElement value)
    {
        using MemoryStream buffer = new();
        using (Utf8JsonWriter writer = new(buffer, new JsonWriterOptions { Indented = false, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
            Write(writer, value);
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>Returns an uppercase SHA-256 digest of canonical UTF-8 JSON.</summary>
    public static string Checksum(string canonicalJson) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalJson)));

    private static void Write(Utf8JsonWriter writer, JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (JsonProperty property in value.EnumerateObject().OrderBy(item => item.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    Write(writer, property.Value);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (JsonElement item in value.EnumerateArray()) Write(writer, item);
                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                writer.WriteStringValue(value.GetString());
                break;
            case JsonValueKind.Number when value.TryGetInt64(out long signed):
                writer.WriteNumberValue(signed);
                break;
            case JsonValueKind.Number when value.TryGetUInt64(out ulong unsigned):
                writer.WriteNumberValue(unsigned);
                break;
            case JsonValueKind.Number:
                throw new GatewayException("BGW-CONNECTOR-NUMBER-UNSUPPORTED", 400);
            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;
            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;
            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;
            default:
                throw new GatewayException("BGW-CONNECTOR-JSON", 400);
        }
    }
}

/// <summary>Canonical checksums binding a Connector version to immutable server-owned resources.</summary>
public static class ConnectorBindingDigests
{
    /// <summary>Checksums one redaction-safe logical binding component for approval comparison.</summary>
    public static string Component<T>(IReadOnlyDictionary<string, T> values) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(values.OrderBy(value => value.Key, StringComparer.Ordinal).ToDictionary(value => value.Key, value => value.Value, StringComparer.Ordinal))));

    /// <summary>Checksums one exact Environment binding revision.</summary>
    public static string Revision(Guid connectorVersionId, Guid environmentId, IReadOnlyDictionary<string, Uri> endpoints, IReadOnlyDictionary<string, ProviderResourceBinding> secrets, IReadOnlyDictionary<string, ProviderResourceBinding> certificates)
    {
        var canonical = new
        {
            connectorVersionId = connectorVersionId.ToString("D"),
            environmentId = environmentId.ToString("D"),
            endpoints = endpoints.OrderBy(value => value.Key, StringComparer.Ordinal).ToDictionary(value => value.Key, value => value.Value.AbsoluteUri, StringComparer.Ordinal),
            secrets = secrets.OrderBy(value => value.Key, StringComparer.Ordinal).ToDictionary(value => value.Key, value => value.Value, StringComparer.Ordinal),
            certificates = certificates.OrderBy(value => value.Key, StringComparer.Ordinal).ToDictionary(value => value.Key, value => value.Value, StringComparer.Ordinal)
        };
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(canonical)));
    }

    /// <summary>Checksums the same semantic, non-secret artefact shown to the approver.</summary>
    public static byte[] Bundle(ConnectorVersionRecord version, IEnumerable<ConnectorBindingSet> bindings) =>
        Convert.FromHexString(ConnectorApprovalArtifacts.Create(version, bindings).DigestSha256);
}

/// <summary>Connector identity included in an approval review.</summary>
public sealed record ApprovalConnectorReview(string ConnectorId, string Version, string DisplayName, string SchemaVersion, string CanonicalDefinitionChecksumSha256);

/// <summary>Exact non-secret destination used by one operation in one Environment.</summary>
public sealed record ApprovalEndpointReview(
    string LogicalBindingId,
    long BindingRevision,
    string Scheme,
    string Hostname,
    int Port,
    string Path,
    string Query,
    IReadOnlyList<string> AllowedMethods,
    string RedirectPolicy,
    string TlsPolicy,
    string EndpointChecksumSha256,
    string BindingChecksumSha256,
    string DestinationClassification);

/// <summary>OAuth authority destination and its protocol role in one operation.</summary>
public sealed record ApprovalAuthorityEndpointReview(string Role, ApprovalEndpointReview Endpoint);

/// <summary>Logical secret-provider binding; credential material is absent by construction.</summary>
public sealed record ApprovalSecretReview(
    string LogicalBindingId,
    long BindingRevision,
    string ProviderDisplayName,
    string ProviderType,
    string ProviderId,
    string ResourceLogicalId,
    string ResourceType,
    string? ResourceVersion,
    long CatalogRevision,
    long? PublicMetadataRevision,
    string Environment,
    string ConnectorScope,
    string OperationScope,
    string CatalogChecksumSha256,
    string ResourceBindingChecksumSha256,
    string BindingChecksumSha256);

/// <summary>Logical certificate-provider binding and optional public certificate metadata.</summary>
public sealed record ApprovalCertificateReview(
    string LogicalBindingId,
    long BindingRevision,
    string ProviderDisplayName,
    string ProviderType,
    string ProviderId,
    string CertificateLogicalId,
    string ResourceType,
    string? ResourceVersion,
    long CatalogRevision,
    long PublicMetadataRevision,
    string PublicFingerprintSha256,
    string PublicSubject,
    string PublicIssuer,
    DateTimeOffset NotBefore,
    DateTimeOffset ExpiresAt,
    string KeyAlgorithm,
    int PublicKeySize,
    string CertificateVersion,
    string Environment,
    string ConnectorScope,
    string OperationScope,
    string CatalogChecksumSha256,
    string ResourceBindingChecksumSha256,
    string BindingChecksumSha256);

/// <summary>One exact runtime operation projection reviewed before publication.</summary>
public sealed record ApprovalOperationReview(
    string OperationId,
    string Environment,
    string ExecutionStrategy,
    string Protocol,
    OperationBindingDependencies BindingDependencies,
    ApprovalEndpointReview Endpoint,
    IReadOnlyList<ApprovalAuthorityEndpointReview> AuthorityEndpoints,
    IReadOnlyList<ApprovalSecretReview> SecretBindings,
    IReadOnlyList<ApprovalCertificateReview> CertificateBindings);

/// <summary>Canonical immutable logical bindings required by one Connector operation.</summary>
public sealed record OperationBindingDependencies(
    string OperationId,
    string EndpointBindingId,
    IReadOnlyList<string> AuthorityEndpointBindingIds,
    IReadOnlyList<string> SecretBindingIds,
    IReadOnlyList<string> CertificateBindingIds);

/// <summary>Derives operation dependencies only from the validated immutable Connector definition.</summary>
public static class ConnectorOperationBindings
{
    /// <summary>Returns the exact dependency set for one operation.</summary>
    public static OperationBindingDependencies Required(string canonicalJson, string operationId)
    {
        using JsonDocument document = JsonDocument.Parse(canonicalJson);
        JsonElement operation = document.RootElement.GetProperty("operations").EnumerateArray()
            .SingleOrDefault(value => string.Equals(value.GetProperty("operationId").GetString(), operationId, StringComparison.Ordinal));
        if (operation.ValueKind == JsonValueKind.Undefined) throw new GatewayException("BGW-OPERATION-NOT-FOUND", 404);
        return From(operation);
    }

    /// <summary>Returns every operation dependency set in stable operation-id order.</summary>
    public static IReadOnlyList<OperationBindingDependencies> All(string canonicalJson)
    {
        using JsonDocument document = JsonDocument.Parse(canonicalJson);
        return document.RootElement.GetProperty("operations").EnumerateArray()
            .Select(From).OrderBy(value => value.OperationId, StringComparer.Ordinal).ToArray();
    }

    private static OperationBindingDependencies From(JsonElement operation)
    {
        string operationId = operation.GetProperty("operationId").GetString()!;
        JsonElement authentication = operation.GetProperty("authentication");
        List<string> secrets = [];
        foreach (string property in new[] { "usernameBinding", "passwordBinding", "secretBinding" })
            if (authentication.TryGetProperty(property, out JsonElement value)) secrets.Add(value.GetString()!);
        List<string> certificates = [];
        if (authentication.TryGetProperty("certificateBinding", out JsonElement certificate)) certificates.Add(certificate.GetString()!);
        List<string> authorityEndpoints = [];
        foreach (string property in new[] { "authorizationEndpointBinding", "tokenEndpointBinding" })
            if (authentication.TryGetProperty(property, out JsonElement value)) authorityEndpoints.Add(value.GetString()!);
        if (operation.TryGetProperty("typedSessionHandshake", out JsonElement handshake) &&
            handshake.TryGetProperty("externalAdmission", out JsonElement admission))
            authorityEndpoints.Add(admission.GetProperty("endpointBinding").GetString()!);
        if (operation.TryGetProperty("typedSessionHandshake", out handshake))
        {
            AddServerOwnedInputs(handshake, secrets);
            if (handshake.TryGetProperty("externalAdmission", out admission)) AddServerOwnedInputs(admission, secrets);
        }
        if (operation.TryGetProperty("authorizedCapabilities", out JsonElement capabilities))
        {
            if (capabilities.TryGetProperty("signing", out JsonElement legacySigning))
                certificates.Add(legacySigning.GetProperty("keyBinding").GetString()!);
            if (capabilities.TryGetProperty("signingSlots", out JsonElement signingSlots))
                foreach (JsonElement slot in signingSlots.EnumerateArray())
                    certificates.Add(slot.GetProperty("signing").GetProperty("keyBinding").GetString()!);
        }
        return new(operationId, operation.GetProperty("endpointBinding").GetString()!,
            authorityEndpoints.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
            secrets.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
            certificates.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray());

        static void AddServerOwnedInputs(JsonElement container, List<string> target)
        {
            if (!container.TryGetProperty("serverOwnedInputs", out JsonElement inputs)) return;
            foreach (JsonElement input in inputs.EnumerateArray()) target.Add(input.GetProperty("secretBinding").GetString()!);
        }
    }
}

/// <summary>Canonical, server-built approval artefact containing every non-secret runtime decision.</summary>
public sealed record ApprovalReviewArtifact(ApprovalConnectorReview Connector, IReadOnlyList<ApprovalOperationReview> Operations);

/// <summary>One immutable binding revision participating in the approval.</summary>
public sealed record ApprovalRevisionReview(Guid BindingId, Guid EnvironmentId, long Revision, string ChecksumSha256);

/// <summary>Server-computed semantic change visible to an approver.</summary>
public sealed record ApprovalSemanticDiff(string Change, string Path, string? PreviousValue, string? CurrentValue);

/// <summary>Server-computed, non-colour-only approval warning.</summary>
public sealed record ApprovalRiskIndicator(string Code, string Severity, string Path);

/// <summary>Complete review response. Canonical JSON and digest always describe <see cref="Artifact"/>.</summary>
public sealed record ApprovalReviewResult(
    ApprovalReviewArtifact Artifact,
    string CanonicalJson,
    string DigestSha256,
    IReadOnlyList<ApprovalRevisionReview> Revisions,
    IReadOnlyList<ApprovalSemanticDiff> Diff,
    IReadOnlyList<ApprovalRiskIndicator> RiskIndicators);

/// <summary>Builds the exact semantic artefact shared by approval, publication and Admin UI.</summary>
public static class ConnectorApprovalArtifacts
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    /// <summary>Creates the canonical artefact and digest without resolving credential values.</summary>
    public static ApprovalReviewResult Create(ConnectorVersionRecord version, IEnumerable<ConnectorBindingSet> values, ApprovalReviewArtifact? previous = null)
    {
        ConnectorBindingSet[] bindings = values.OrderBy(value => value.EnvironmentId).ThenBy(value => value.Revision).ToArray();
        if (bindings.Length == 0) throw new GatewayException("BGW-CONNECTOR-BINDING-MISSING", 409);
        using JsonDocument definition = JsonDocument.Parse(version.CanonicalJson);
        JsonElement root = definition.RootElement;
        string displayName = root.GetProperty("displayName").GetString() ?? version.ConnectorSlug;
        List<ApprovalOperationReview> operations = [];
        foreach (ConnectorBindingSet binding in bindings)
        {
            foreach (JsonElement operation in root.GetProperty("operations").EnumerateArray().OrderBy(value => value.GetProperty("operationId").GetString(), StringComparer.Ordinal))
                operations.Add(Operation(version, binding, operation));
        }
        ApprovalReviewArtifact artifact = new(new(version.ConnectorSlug, version.Version, displayName, version.SchemaVersion, Convert.ToHexString(version.ChecksumSha256)), operations);
        string canonical = Canonical(artifact);
        string digest = ConnectorCanonicalJson.Checksum(canonical);
        IReadOnlyList<ApprovalSemanticDiff> diff = Diff(previous, artifact);
        return new(artifact, canonical, digest,
            bindings.Select(value => new ApprovalRevisionReview(value.Id, value.EnvironmentId, value.Revision, value.ChecksumSha256)).ToArray(),
            diff, Risks(previous, artifact, diff));
    }

    private static ApprovalOperationReview Operation(ConnectorVersionRecord version, ConnectorBindingSet binding, JsonElement operation)
    {
        string operationId = operation.GetProperty("operationId").GetString()!;
        OperationBindingDependencies dependencies = ConnectorOperationBindings.Required(version.CanonicalJson, operationId);
        string endpointName = operation.GetProperty("endpointBinding").GetString()!;
        if (!binding.Endpoints.TryGetValue(endpointName, out Uri? baseUri)) throw new GatewayException("BGW-CONNECTOR-ENDPOINT-BINDING-MISSING", 503);
        string path = operation.GetProperty("path").GetString()!;
        Uri effective = new(baseUri, path);
        string method = operation.GetProperty("method").GetString()!;
        string redirect = operation.TryGetProperty("redirectPolicy", out JsonElement redirectElement) ? redirectElement.GetString() ?? "deny" : "deny";
        ApprovalEndpointReview endpoint = ReviewEndpoint(endpointName, binding, effective, [method], redirect);
        JsonElement authentication = operation.GetProperty("authentication");
        List<ApprovalAuthorityEndpointReview> authorityEndpoints = [];
        foreach ((string property, string role, string authorityMethod) in new[]
        {
            ("authorizationEndpointBinding", "authorization", "GET"),
            ("tokenEndpointBinding", "token", "POST")
        })
        {
            if (!authentication.TryGetProperty(property, out JsonElement logicalElement)) continue;
            string logical = logicalElement.GetString()!;
            if (!binding.Endpoints.TryGetValue(logical, out Uri? authorityEndpoint)) throw new GatewayException("BGW-CONNECTOR-ENDPOINT-BINDING-MISSING", 503);
            authorityEndpoints.Add(new(role, ReviewEndpoint(logical, binding, authorityEndpoint, [authorityMethod], "deny")));
        }
        if (operation.TryGetProperty("typedSessionHandshake", out JsonElement handshake) &&
            handshake.TryGetProperty("externalAdmission", out JsonElement admission))
        {
            string logical = admission.GetProperty("endpointBinding").GetString()!;
            if (!binding.Endpoints.TryGetValue(logical, out Uri? admissionBase)) throw new GatewayException("BGW-CONNECTOR-ENDPOINT-BINDING-MISSING", 503);
            Uri admissionEndpoint = new(admissionBase, admission.GetProperty("path").GetString()!);
            authorityEndpoints.Add(new("session-admission-validation", ReviewEndpoint(logical, binding, admissionEndpoint, ["POST"], "deny")));
        }
        List<ApprovalSecretReview> secrets = [];
        foreach (string logical in dependencies.SecretBindingIds)
        {
            if (!binding.SecretResources.TryGetValue(logical, out ProviderResourceBinding? resource)) throw new GatewayException("BGW-CONNECTOR-SECRET-BINDING-MISSING", 503);
            secrets.Add(new(logical, binding.Revision, resource.ProviderDisplayName, resource.ProviderType, resource.ProviderId, resource.ResourceId, resource.ResourceType.ToString(), resource.Version,
                resource.CatalogRevision, resource.PublicMetadataRevision, binding.EnvironmentId.ToString("D"), resource.ConnectorScope, resource.OperationScope,
                resource.CatalogChecksumSha256, Component(logical, resource), binding.ChecksumSha256));
        }
        List<ApprovalCertificateReview> certificates = [];
        foreach (string logical in dependencies.CertificateBindingIds)
        {
            if (!binding.CertificateResources.TryGetValue(logical, out ProviderResourceBinding? resource)) throw new GatewayException("BGW-CONNECTOR-CERTIFICATE-BINDING-MISSING", 503);
            CertificatePublicMetadata metadata = resource.CertificateMetadata ?? throw new GatewayException("BGW-PROVIDER-CERTIFICATE-METADATA-REQUIRED", 409);
            certificates.Add(new(logical, binding.Revision, resource.ProviderDisplayName, resource.ProviderType, resource.ProviderId, resource.ResourceId,
                resource.ResourceType.ToString(), resource.Version, resource.CatalogRevision,
                resource.PublicMetadataRevision ?? throw new GatewayException("BGW-PROVIDER-CERTIFICATE-METADATA-REQUIRED", 409),
                metadata.FingerprintSha256, metadata.Subject, metadata.Issuer, metadata.NotBefore, metadata.NotAfter, metadata.KeyAlgorithm, metadata.PublicKeySize, metadata.Version,
                binding.EnvironmentId.ToString("D"), resource.ConnectorScope, resource.OperationScope, resource.CatalogChecksumSha256,
                Component(logical, resource), binding.ChecksumSha256));
        }
        return new(operationId, binding.EnvironmentId.ToString("D"), ConnectorExecutionStrategyKeys.Resolve(operation).Value,
            effective.Scheme.ToUpperInvariant(), dependencies, endpoint, authorityEndpoints, secrets, certificates);
    }

    private static ApprovalEndpointReview ReviewEndpoint(string logicalId, ConnectorBindingSet binding, Uri endpoint, IReadOnlyList<string> methods, string redirectPolicy) =>
        new(logicalId, binding.Revision, endpoint.Scheme, endpoint.DnsSafeHost, endpoint.IsDefaultPort ? DefaultPort(endpoint.Scheme) : endpoint.Port,
            endpoint.AbsolutePath, endpoint.Query, methods, redirectPolicy, "validate-system-trust-and-hostname", Component(logicalId, endpoint.AbsoluteUri), binding.ChecksumSha256, Classify(endpoint));

    private static string Canonical(ApprovalReviewArtifact artifact)
    {
        using JsonDocument document = JsonDocument.Parse(JsonSerializer.Serialize(artifact, WebJson));
        return ConnectorCanonicalJson.Canonicalize(document.RootElement);
    }

    private static string Component<T>(string logicalId, T value)
    {
        string json = JsonSerializer.Serialize(new { logicalId, value }, WebJson);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
    }

    private static int DefaultPort(string scheme) => string.Equals(scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ? 443 : 80;

    private static string Classify(Uri endpoint)
    {
        if (string.Equals(endpoint.DnsSafeHost, "localhost", StringComparison.OrdinalIgnoreCase)) return "loopback";
        if (IPAddress.TryParse(endpoint.DnsSafeHost, out IPAddress? address))
        {
            if (IPAddress.IsLoopback(address)) return "loopback";
            byte[] bytes = address.GetAddressBytes();
            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && (bytes[0] == 10 || bytes[0] == 127 || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) || (bytes[0] == 192 && bytes[1] == 168))) return "private";
            return "publicInternet";
        }
        return endpoint.DnsSafeHost.EndsWith(".local", StringComparison.OrdinalIgnoreCase) || endpoint.DnsSafeHost.EndsWith(".internal", StringComparison.OrdinalIgnoreCase) ? "private" : "publicInternet";
    }

    private static List<ApprovalSemanticDiff> Diff(ApprovalReviewArtifact? previous, ApprovalReviewArtifact current)
    {
        if (previous is null) return [new("added", "/", null, "approvalArtifact")];
        using JsonDocument before = JsonDocument.Parse(Canonical(previous));
        using JsonDocument after = JsonDocument.Parse(Canonical(current));
        List<ApprovalSemanticDiff> result = [];
        Compare(before.RootElement, after.RootElement, string.Empty, result);
        return result;
    }

    private static void Compare(JsonElement before, JsonElement after, string path, List<ApprovalSemanticDiff> result)
    {
        if (before.ValueKind == JsonValueKind.Object && after.ValueKind == JsonValueKind.Object)
        {
            Dictionary<string, JsonElement> left = before.EnumerateObject().ToDictionary(value => value.Name, value => value.Value, StringComparer.Ordinal);
            Dictionary<string, JsonElement> right = after.EnumerateObject().ToDictionary(value => value.Name, value => value.Value, StringComparer.Ordinal);
            foreach (string name in left.Keys.Union(right.Keys, StringComparer.Ordinal).OrderBy(value => value, StringComparer.Ordinal))
            {
                string child = path + "/" + name;
                if (!left.TryGetValue(name, out JsonElement oldValue)) result.Add(new("added", child, null, right[name].GetRawText()));
                else if (!right.TryGetValue(name, out JsonElement newValue)) result.Add(new("removed", child, oldValue.GetRawText(), null));
                else Compare(oldValue, newValue, child, result);
            }
            return;
        }
        if (before.ValueKind == JsonValueKind.Array && after.ValueKind == JsonValueKind.Array)
        {
            JsonElement[] left = before.EnumerateArray().ToArray(); JsonElement[] right = after.EnumerateArray().ToArray();
            for (int index = 0; index < Math.Max(left.Length, right.Length); index++)
            {
                string child = path + "/" + index.ToString(System.Globalization.CultureInfo.InvariantCulture);
                if (index >= left.Length) result.Add(new("added", child, null, right[index].GetRawText()));
                else if (index >= right.Length) result.Add(new("removed", child, left[index].GetRawText(), null));
                else Compare(left[index], right[index], child, result);
            }
            return;
        }
        if (!JsonElement.DeepEquals(before, after)) result.Add(new("changed", string.IsNullOrEmpty(path) ? "/" : path, before.GetRawText(), after.GetRawText()));
    }

    private static List<ApprovalRiskIndicator> Risks(ApprovalReviewArtifact? previous, ApprovalReviewArtifact current, IReadOnlyList<ApprovalSemanticDiff> diff)
    {
        List<ApprovalRiskIndicator> result = [];
        if (current.Operations.Any(value => value.Endpoint.DestinationClassification == "publicInternet" || value.AuthorityEndpoints.Any(authority => authority.Endpoint.DestinationClassification == "publicInternet")))
            result.Add(new("PUBLIC_INTERNET_DESTINATION", "high", "/operations"));
        if (previous is null)
        {
            foreach (int index in Enumerable.Range(0, current.Operations.Count))
            {
                result.Add(new("BINDING_PREVIOUSLY_UNUSED", "warning", $"/operations/{index}"));
                result.Add(new("NEW_HOSTNAME", "warning", $"/operations/{index}/endpoint/hostname"));
                result.Add(new("NEW_PORT", "warning", $"/operations/{index}/endpoint/port"));
                foreach (int authorityIndex in Enumerable.Range(0, current.Operations[index].AuthorityEndpoints.Count))
                {
                    result.Add(new("NEW_HOSTNAME", "warning", $"/operations/{index}/authorityEndpoints/{authorityIndex}/endpoint/hostname"));
                    result.Add(new("NEW_PORT", "warning", $"/operations/{index}/authorityEndpoints/{authorityIndex}/endpoint/port"));
                }
            }
        }
        foreach ((ApprovalOperationReview operation, int operationIndex) in current.Operations.Select((value, index) => (value, index)))
        {
            foreach ((ApprovalCertificateReview certificate, int certificateIndex) in operation.CertificateBindings.Select((value, index) => (value, index)))
            {
                if (certificate.ExpiresAt <= DateTimeOffset.UtcNow.AddDays(30))
                    result.Add(new("CERTIFICATE_NEAR_EXPIRY", "high", $"/operations/{operationIndex}/certificates/{certificateIndex}/expiresAt"));
            }
        }
        foreach (ApprovalSemanticDiff change in diff)
        {
            string code = change.Path switch
            {
                string value when value.EndsWith("/hostname", StringComparison.Ordinal) => previous is null ? "NEW_HOSTNAME" : "HOSTNAME_CHANGED",
                string value when value.EndsWith("/port", StringComparison.Ordinal) => previous is null ? "NEW_PORT" : "PORT_CHANGED",
                string value when value.EndsWith("/path", StringComparison.Ordinal) => "PATH_CHANGED",
                string value when value.Contains("/allowedMethods/", StringComparison.Ordinal) => "HTTP_METHOD_CHANGED",
                string value when value.EndsWith("/redirectPolicy", StringComparison.Ordinal) => "REDIRECT_POLICY_CHANGED",
                string value when value.EndsWith("/tlsPolicy", StringComparison.Ordinal) => "TLS_POLICY_CHANGED",
                string value when value.EndsWith("/providerId", StringComparison.Ordinal) || value.EndsWith("/providerType", StringComparison.Ordinal) => "PROVIDER_CHANGED",
                string value when value.EndsWith("/resourceLogicalId", StringComparison.Ordinal) => "SECRET_RESOURCE_CHANGED",
                string value when value.EndsWith("/certificateLogicalId", StringComparison.Ordinal) || value.EndsWith("/publicFingerprintSha256", StringComparison.Ordinal) => "CERTIFICATE_CHANGED",
                string value when value.EndsWith("/environment", StringComparison.Ordinal) => "ENVIRONMENT_CHANGED",
                string value when value.EndsWith("/connectorScope", StringComparison.Ordinal) || value.EndsWith("/operationScope", StringComparison.Ordinal) => "SCOPE_CHANGED",
                _ => string.Empty
            };
            if (!string.IsNullOrEmpty(code) && !result.Any(value => value.Code == code && value.Path == change.Path)) result.Add(new(code, code is "HOSTNAME_CHANGED" or "PROVIDER_CHANGED" or "SECRET_RESOURCE_CHANGED" or "CERTIFICATE_CHANGED" or "SCOPE_CHANGED" ? "high" : "warning", change.Path));
        }
        return result;
    }

}

/// <summary>Draft 2020-12 and semantic validator for Connector Definition JSON v1.</summary>
public sealed class ConnectorDefinitionValidator
{
    private static readonly JsonSchema Schema = LoadSchema();
    private readonly JsonSchema schema = Schema;
    private static readonly HashSet<string> LegacyAllowedClientHeadersForbidden = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "Cookie", "Host", "Forwarded", "Proxy-Authorization", "Connection", "Transfer-Encoding", "Upgrade"
    };
    private static readonly HashSet<string> AuthenticationPlacementHeadersForbidden = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "SOAPAction", "Content-Type", "Cookie", "Set-Cookie", "Host", "Content-Length", "Forwarded", "Via", "Expect", "TE", "Trailer",
        "Proxy-Authorization", "Proxy-Authenticate", "Connection", "Transfer-Encoding", "Upgrade", "X-Correlation-ID", "traceparent", "tracestate", "baggage"
    };

    /// <summary>Validates a parsed definition and returns only bounded issue codes/locations.</summary>
    public ConnectorValidationResult Validate(JsonElement definition)
    {
        List<ConnectorValidationIssue> issues = [];
        EvaluationResults schemaResult = schema.Evaluate(definition, new EvaluationOptions { OutputFormat = OutputFormat.List });
        if (!schemaResult.IsValid)
        {
            foreach (EvaluationResults detail in (schemaResult.Details ?? []).Where(result => !result.IsValid && result.Errors is { Count: > 0 }))
                issues.Add(new("BGW-CONNECTOR-SCHEMA-INVALID", Pointer(detail.InstanceLocation.ToString())));
            if (issues.Count == 0) issues.Add(new("BGW-CONNECTOR-SCHEMA-INVALID", "/"));
        }
        if (definition.ValueKind != JsonValueKind.Object)
            return new(false, null, issues);

        string? schemaVersion = OptionalString(definition, "schemaVersion");
        if (!string.Equals(schemaVersion, "1.0", StringComparison.Ordinal)) issues.Add(new("BGW-CONNECTOR-SCHEMA-VERSION-UNSUPPORTED", "$.schemaVersion"));

        if (issues.Count == 0) ValidateSemantics(definition, issues);
        if (issues.Count != 0) return new(false, null, issues);

        string canonical = ConnectorCanonicalJson.Canonicalize(definition);
        return new(true, ConnectorCanonicalJson.Checksum(canonical), []);
    }

    /// <summary>Validates and returns a canonical representation, or throws a stable error.</summary>
    public ValidatedConnectorDefinition ValidateRequired(JsonElement definition, string? expectedChecksum = null)
    {
        ConnectorValidationResult result = Validate(definition);
        if (!result.Valid) throw new GatewayException(result.Issues.Any(issue => issue.Code == "BGW-CONNECTOR-SCHEMA-VERSION-UNSUPPORTED") ? "BGW-CONNECTOR-SCHEMA-VERSION" : "BGW-CONNECTOR-VALIDATION", 400);
        string canonical = ConnectorCanonicalJson.Canonicalize(definition);
        if (expectedChecksum is not null && !string.Equals(expectedChecksum, result.ChecksumSha256, StringComparison.OrdinalIgnoreCase))
            throw new GatewayException("BGW-CONNECTOR-CHECKSUM", 409);
        return Parse(canonical, result.ChecksumSha256!);
    }

    /// <summary>Parses already-canonical, already-validated JSON into runtime metadata.</summary>
    public ValidatedConnectorDefinition ParseStored(string canonicalJson, byte[] checksum)
    {
        using JsonDocument document = JsonDocument.Parse(canonicalJson, new JsonDocumentOptions { MaxDepth = 32 });
        string actual = ConnectorCanonicalJson.Checksum(ConnectorCanonicalJson.Canonicalize(document.RootElement));
        if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(actual), checksum))
            throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-CORRUPT", 503);
        ConnectorValidationResult result = Validate(document.RootElement);
        if (!result.Valid) throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-CORRUPT", 503);
        return Parse(canonicalJson, actual);
    }

    private static void ValidateSemantics(JsonElement definition, List<ConnectorValidationIssue> issues)
    {
        JsonElement bindings = definition.GetProperty("bindings");
        Dictionary<string, string> endpoints = UniqueBindings(bindings.GetProperty("endpoints"), issues, "endpoint");
        Dictionary<string, string> secrets = UniqueBindings(bindings.GetProperty("secrets"), issues, "secret", includeKind: true);
        HashSet<string> operations = new(StringComparer.Ordinal);
        int index = 0;
        foreach (JsonElement operation in definition.GetProperty("operations").EnumerateArray())
        {
            string operationId = operation.GetProperty("operationId").GetString()!;
            if (!operations.Add(operationId)) issues.Add(new("BGW-CONNECTOR-OPERATION-DUPLICATE", $"$.operations[{index}].operationId"));
            string endpoint = operation.GetProperty("endpointBinding").GetString()!;
            if (!endpoints.ContainsKey(endpoint)) issues.Add(new("BGW-CONNECTOR-ENDPOINT-BINDING-UNKNOWN", $"$.operations[{index}].endpointBinding"));
            JsonElement authentication = operation.GetProperty("authentication");
            foreach (string property in new[] { "authorizationEndpointBinding", "tokenEndpointBinding" })
                if (authentication.TryGetProperty(property, out JsonElement oauthEndpoint) && !endpoints.ContainsKey(oauthEndpoint.GetString()!))
                    issues.Add(new("BGW-CONNECTOR-ENDPOINT-BINDING-UNKNOWN", $"$.operations[{index}].authentication.{property}"));
            if (operation.TryGetProperty("typedSessionHandshake", out JsonElement handshake) &&
                handshake.TryGetProperty("externalAdmission", out JsonElement admission) &&
                !endpoints.ContainsKey(admission.GetProperty("endpointBinding").GetString()!))
                issues.Add(new("BGW-CONNECTOR-ENDPOINT-BINDING-UNKNOWN", $"$.operations[{index}].typedSessionHandshake.externalAdmission.endpointBinding"));
            if (operation.TryGetProperty("typedSessionHandshake", out handshake))
            {
                string method = operation.GetProperty("method").GetString()!;
                string authenticationKind = authentication.GetProperty("kind").GetString()!;
                string version = handshake.GetProperty("soapVersion").GetString()!;
                string contentType = operation.GetProperty("request").GetProperty("contentType").GetString()!;
                string expectedMediaType = string.Equals(version, "1.1", StringComparison.Ordinal) ? "text/xml" : "application/soap+xml";
                if (!string.Equals(method, "POST", StringComparison.Ordinal))
                    issues.Add(new("BGW-CONNECTOR-TYPED-HANDSHAKE-METHOD", $"$.operations[{index}].method"));
                if (authenticationKind is not ("none" or "basic"))
                    issues.Add(new("BGW-CONNECTOR-TYPED-HANDSHAKE-AUTH", $"$.operations[{index}].authentication.kind"));
                if (!MediaTypeHeaderValue.TryParse(contentType, out MediaTypeHeaderValue? parsedContentType) ||
                    !string.Equals(parsedContentType.MediaType, expectedMediaType, StringComparison.OrdinalIgnoreCase))
                    issues.Add(new("BGW-CONNECTOR-TYPED-HANDSHAKE-CONTENT-TYPE", $"$.operations[{index}].request.contentType"));
                ValidateServerOwnedInputs(handshake, secrets, issues, $"$.operations[{index}].typedSessionHandshake");
                if (handshake.TryGetProperty("externalAdmission", out admission))
                    ValidateServerOwnedInputs(admission, secrets, issues, $"$.operations[{index}].typedSessionHandshake.externalAdmission");
            }
            if (operation.TryGetProperty("extensionConfiguration", out JsonElement extensionConfiguration))
                ValidateExtensionConfiguration(extensionConfiguration, issues, $"$.operations[{index}].extensionConfiguration");
            if (operation.TryGetProperty("authorizedCapabilities", out JsonElement capabilities))
                ValidateAuthorizedCapabilities(operation, authentication, capabilities, secrets, issues, index);
            bool idempotent = operation.TryGetProperty("idempotent", out JsonElement idempotentElement) && idempotentElement.GetBoolean();
            int retries = operation.TryGetProperty("maximumRetries", out JsonElement retriesElement) ? retriesElement.GetInt32() : 0;
            if (retries > 0 && !idempotent) issues.Add(new("BGW-CONNECTOR-RETRY-REQUIRES-IDEMPOTENCY", $"$.operations[{index}].maximumRetries"));
            foreach (JsonElement headerElement in operation.GetProperty("allowedClientHeaders").EnumerateArray())
            {
                string header = headerElement.GetString()!;
                if (LegacyAllowedClientHeadersForbidden.Contains(header) || header.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase) || header.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase))
                    issues.Add(new("BGW-CONNECTOR-HEADER-FORBIDDEN", $"$.operations[{index}].allowedClientHeaders"));
            }
            ValidateAuthentication(operation, authentication, secrets, issues, index);
            index++;
        }
    }

    private static void ValidateServerOwnedInputs(
        JsonElement container,
        Dictionary<string, string> secrets,
        List<ConnectorValidationIssue> issues,
        string location)
    {
        if (!container.TryGetProperty("serverOwnedInputs", out JsonElement inputs)) return;
        HashSet<string> names = new(StringComparer.Ordinal);
        int inputIndex = 0;
        foreach (JsonElement input in inputs.EnumerateArray())
        {
            string name = input.GetProperty("name").GetString()!;
            string binding = input.GetProperty("secretBinding").GetString()!;
            if (!names.Add(name)) issues.Add(new("BGW-CONNECTOR-SERVER-INPUT-DUPLICATE", $"{location}.serverOwnedInputs[{inputIndex}].name"));
            if (!secrets.TryGetValue(binding, out string? kind) || !string.Equals(kind, "opaque", StringComparison.Ordinal))
                issues.Add(new("BGW-CONNECTOR-SERVER-INPUT-BINDING-INVALID", $"{location}.serverOwnedInputs[{inputIndex}].secretBinding"));
            inputIndex++;
        }
    }

    private static void ValidateExtensionConfiguration(
        JsonElement configuration,
        List<ConnectorValidationIssue> issues,
        string location)
    {
        int bytes = Encoding.UTF8.GetByteCount(configuration.GetRawText());
        int nodes = 0;
        if (bytes > AuthorizedPublishedExtensionConfiguration.MaximumJsonBytes || !Visit(configuration, 1, ref nodes))
            issues.Add(new("BGW-CONNECTOR-EXTENSION-CONFIGURATION-BOUNDS", location));

        static bool Visit(JsonElement value, int depth, ref int nodes)
        {
            nodes++;
            if (depth > AuthorizedPublishedExtensionConfiguration.MaximumDepth || nodes > 256) return false;
            if (value.ValueKind == JsonValueKind.Object)
                foreach (JsonProperty property in value.EnumerateObject())
                    if (!Visit(property.Value, depth + 1, ref nodes)) return false;
            if (value.ValueKind == JsonValueKind.Array)
                foreach (JsonElement item in value.EnumerateArray())
                    if (!Visit(item, depth + 1, ref nodes)) return false;
            return true;
        }
    }

    private static void ValidateAuthorizedCapabilities(
        JsonElement operation,
        JsonElement authentication,
        JsonElement capabilities,
        Dictionary<string, string> secrets,
        List<ConnectorValidationIssue> issues,
        int operationIndex)
    {
        string location = $"$.operations[{operationIndex}].authorizedCapabilities";
        if (!string.Equals(authentication.GetProperty("kind").GetString(), "mtls", StringComparison.Ordinal))
            issues.Add(new("BGW-CONNECTOR-CAPABILITY-AUTH-INVALID", $"$.operations[{operationIndex}].authentication.kind"));
        if (!operation.TryGetProperty("executionStrategy", out _))
            issues.Add(new("BGW-CONNECTOR-CAPABILITY-STRATEGY-REQUIRED", $"$.operations[{operationIndex}].executionStrategy"));
        bool hasLegacy = capabilities.TryGetProperty("signing", out JsonElement legacySigning);
        bool hasSlots = capabilities.TryGetProperty("signingSlots", out JsonElement signingSlots);
        if (hasLegacy && hasSlots)
            issues.Add(new("BGW-CONNECTOR-SIGNING-MODE-AMBIGUOUS", location));
        if (hasLegacy)
            ValidateSigningBinding(legacySigning, $"{location}.signing");
        if (!hasSlots) return;

        HashSet<string> keys = new(StringComparer.Ordinal);
        HashSet<string> profileIds = new(StringComparer.Ordinal);
        HashSet<string> projectionHeaders = new(StringComparer.OrdinalIgnoreCase);
        bool authorizationProjection = false;
        int slotIndex = 0;
        foreach (JsonElement slot in signingSlots.EnumerateArray())
        {
            string slotLocation = $"{location}.signingSlots[{slotIndex}]";
            string key = slot.GetProperty("slot").GetString()!;
            if (!keys.Add(key))
                issues.Add(new("BGW-CONNECTOR-SIGNING-SLOT-DUPLICATE", $"{slotLocation}.slot"));
            JsonElement signing = slot.GetProperty("signing");
            if (!profileIds.Add(signing.GetProperty("profileId").GetString()!))
                issues.Add(new("BGW-CONNECTOR-SIGNING-PROFILE-DUPLICATE", $"{slotLocation}.signing.profileId"));
            ValidateSigningBinding(signing, $"{slotLocation}.signing");

            JsonElement projection = slot.GetProperty("projection");
            string projectionKind = projection.GetProperty("kind").GetString()!;
            if (string.Equals(projectionKind, "authorizationBearer", StringComparison.Ordinal))
            {
                if (authorizationProjection)
                    issues.Add(new("BGW-CONNECTOR-SIGNING-AUTHORIZATION-DUPLICATE", $"{slotLocation}.projection"));
                authorizationProjection = true;
            }
            else if (string.Equals(projectionKind, "signedTokenHeader", StringComparison.Ordinal))
            {
                string header = projection.GetProperty("headerName").GetString()!;
                if (!IsHttpToken(header) || AuthenticationPlacementHeadersForbidden.Contains(header) ||
                    header.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase) ||
                    header.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase))
                    issues.Add(new("BGW-CONNECTOR-SIGNING-HEADER-FORBIDDEN", $"{slotLocation}.projection.headerName"));
                if (!projectionHeaders.Add(header))
                    issues.Add(new("BGW-CONNECTOR-SIGNING-HEADER-DUPLICATE", $"{slotLocation}.projection.headerName"));
            }
            slotIndex++;
        }

        void ValidateSigningBinding(JsonElement signing, string signingLocation)
        {
            string keyBinding = signing.GetProperty("keyBinding").GetString()!;
            if (!secrets.TryGetValue(keyBinding, out string? kind) || !string.Equals(kind, "clientCertificate", StringComparison.Ordinal))
                issues.Add(new("BGW-CONNECTOR-CAPABILITY-SIGNING-BINDING-INVALID", $"{signingLocation}.keyBinding"));
        }
    }

    private static Dictionary<string, string> UniqueBindings(JsonElement values, List<ConnectorValidationIssue> issues, string category, bool includeKind = false)
    {
        Dictionary<string, string> result = new(StringComparer.Ordinal);
        int index = 0;
        foreach (JsonElement value in values.EnumerateArray())
        {
            string name = value.GetProperty("name").GetString()!;
            string kind = includeKind ? value.GetProperty("kind").GetString()! : category;
            if (!result.TryAdd(name, kind)) issues.Add(new("BGW-CONNECTOR-BINDING-DUPLICATE", $"$.bindings.{category}s[{index}].name"));
            index++;
        }
        return result;
    }

    private static void ValidateAuthentication(JsonElement operation, JsonElement auth, Dictionary<string, string> secrets, List<ConnectorValidationIssue> issues, int operationIndex)
    {
        string kind = auth.GetProperty("kind").GetString()!;
        if (string.Equals(kind, "oauthAuthorizationCode", StringComparison.Ordinal) && auth.TryGetProperty("redirectUri", out JsonElement redirectElement))
        {
            string redirectValue = redirectElement.GetString()!;
            if (!Uri.TryCreate(redirectValue, UriKind.Absolute, out Uri? redirectUri) || !redirectUri.IsAbsoluteUri || redirectUri.Scheme != Uri.UriSchemeHttps ||
                !string.IsNullOrEmpty(redirectUri.UserInfo) || !string.IsNullOrEmpty(redirectUri.Query) || !string.IsNullOrEmpty(redirectUri.Fragment))
                issues.Add(new("BGW-CONNECTOR-OAUTH-REDIRECT-URI-INVALID", $"$.operations[{operationIndex}].authentication.redirectUri"));
        }
        if (kind is "opaqueSessionHttp" or "soapBasicOpaqueSession")
        {
            string headerName = auth.GetProperty("headerName").GetString()!;
            if (!IsHttpToken(headerName) || AuthenticationPlacementHeadersForbidden.Contains(headerName) || headerName.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase) || headerName.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase))
                issues.Add(new("BGW-CONNECTOR-HEADER-FORBIDDEN", $"$.operations[{operationIndex}].authentication.headerName"));
            string valueFormat = auth.GetProperty("valueFormat").GetString()!;
            bool hasScheme = auth.TryGetProperty("fixedScheme", out JsonElement schemeElement);
            if (valueFormat == "rawOpaqueValue" && hasScheme || valueFormat == "fixedSchemeAndOpaqueValue" && (!hasScheme || !IsHttpToken(schemeElement.GetString()!)))
                issues.Add(new("BGW-CONNECTOR-SESSION-HEADER-FORMAT-INVALID", $"$.operations[{operationIndex}].authentication.valueFormat"));
        }
        if (kind == "soapBasicOpaqueSession")
        {
            JsonElement soap = auth.GetProperty("soapHttp");
            string version = soap.GetProperty("version").GetString()!;
            string action = soap.GetProperty("action").GetString()!;
            string expectedContentType = version == "1.1" ? "text/xml" : "application/soap+xml";
            if (!string.Equals(operation.GetProperty("method").GetString(), "POST", StringComparison.Ordinal))
                issues.Add(new("BGW-CONNECTOR-SOAP-METHOD-INVALID", $"$.operations[{operationIndex}].method"));
            if (!string.Equals(operation.GetProperty("request").GetProperty("contentType").GetString(), expectedContentType, StringComparison.OrdinalIgnoreCase))
                issues.Add(new("BGW-CONNECTOR-SOAP-CONTENT-TYPE-INVALID", $"$.operations[{operationIndex}].request.contentType"));
            if (!Uri.TryCreate(action, UriKind.Absolute, out Uri? parsedAction) || !parsedAction.IsAbsoluteUri || action.Any(character => char.IsControl(character) || char.IsWhiteSpace(character) || character is '"' or '\\'))
                issues.Add(new("BGW-CONNECTOR-SOAP-ACTION-INVALID", $"$.operations[{operationIndex}].authentication.soapHttp.action"));
        }
        Check("usernameBinding", "username");
        Check("passwordBinding", "password");
        Check("secretBinding", "opaque");
        Check("certificateBinding", "clientCertificate");
        return;

        void Check(string property, string requiredKind)
        {
            if (!auth.TryGetProperty(property, out JsonElement binding)) return;
            string name = binding.GetString()!;
            if (!secrets.TryGetValue(name, out string? actualKind) || !string.Equals(actualKind, requiredKind, StringComparison.Ordinal))
                issues.Add(new("CONNECTOR_SECRET_BINDING_INVALID", $"$.operations[{operationIndex}].authentication.{property}"));
        }
    }

    private static bool IsHttpToken(string value) => !string.IsNullOrEmpty(value) && value.Length <= 100 && value.All(character =>
        char.IsAsciiLetterOrDigit(character) || character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~');

    private static ValidatedConnectorDefinition Parse(string canonicalJson, string checksum)
    {
        using JsonDocument document = JsonDocument.Parse(canonicalJson);
        JsonElement root = document.RootElement;
        return new(root.GetProperty("schemaVersion").GetString()!, root.GetProperty("connectorId").GetString()!, root.GetProperty("version").GetString()!, root.GetProperty("displayName").GetString()!, canonicalJson, checksum);
    }

    private static string? OptionalString(JsonElement element, string name) => element.TryGetProperty(name, out JsonElement property) && property.ValueKind == JsonValueKind.String ? property.GetString() : null;

    private static string Pointer(string location) => string.IsNullOrEmpty(location) || location == "$" ? "/" : location.StartsWith('/') ? location : "/" + location.TrimStart('$', '.').Replace('.', '/');

    private static JsonSchema LoadSchema()
    {
        return JsonSchema.FromText(ConnectorDefinitionArtifacts.SchemaJson);
    }
}

/// <summary>Validated definition identity and canonical artefact.</summary>
public sealed record ValidatedConnectorDefinition(string SchemaVersion, string ConnectorId, string Version, string DisplayName, string CanonicalJson, string ChecksumSha256);

/// <summary>Administrative Connector lifecycle with redacted audit and cache invalidation.</summary>
public sealed class ConnectorAdministrationService(
    IConnectorConfigurationStore store,
    ConnectorDefinitionValidator validator,
    IGatewayOperationCatalog runtimeCatalog,
    IGatewayRegistry registry,
    IGatewayClock clock,
    IConnectorApprovalPolicy approvalPolicy)
{
    /// <summary>Validates without persisting a definition.</summary>
    public ConnectorValidationResult Validate(JsonElement definition) => validator.Validate(definition);

    /// <summary>Imports a new Draft and computes its canonical checksum.</summary>
    public async Task<ConnectorVersionResource> ImportAsync(JsonElement definition, string? expectedChecksum, string actor, Guid correlationId, CancellationToken cancellationToken)
    {
        ValidatedConnectorDefinition validated = validator.ValidateRequired(definition, expectedChecksum);
        ConnectorVersionRecord draft = new(Guid.NewGuid(), Guid.Empty, validated.ConnectorId, validated.Version, validated.SchemaVersion, ConnectorVersionState.Draft, validated.CanonicalJson, Convert.FromHexString(validated.ChecksumSha256), actor, clock.UtcNow, 1);
        GatewayAuditEvent audit = Audit(actor, "connector.import", draft, correlationId, "success", "BGW-CONNECTOR-IMPORTED");
        ConnectorVersionRecord created = await store.CreateDraftWithAuditAsync(draft, audit, cancellationToken).ConfigureAwait(false);
        return Resource(created);
    }

    /// <summary>Validates one stored Draft using its immutable checksum.</summary>
    public async Task<ConnectorVersionResource> ValidateStoredAsync(string connectorId, string version, long expectedRowVersion, string actor, Guid correlationId, CancellationToken cancellationToken)
    {
        ConnectorVersionRecord existing = await RequiredAsync(connectorId, version, cancellationToken).ConfigureAwait(false);
        if (existing.State != ConnectorVersionState.Draft) throw new GatewayException("BGW-CONNECTOR-STATE", 409);
        _ = validator.ParseStored(existing.CanonicalJson, existing.ChecksumSha256);
        GatewayAuditEvent audit = Audit(actor, "connector.validate", existing with { State = ConnectorVersionState.Validated }, correlationId, "success", "BGW-CONNECTOR-VALIDATED");
        ConnectorVersionRecord updated = await store.MarkValidatedWithAuditAsync(existing.Id, expectedRowVersion, clock.UtcNow, audit, cancellationToken).ConfigureAwait(false);
        return Resource(updated);
    }

    /// <summary>Atomically publishes a Validated version.</summary>
    public async Task<ConnectorVersionResource> PublishAsync(string connectorId, string version, long expectedRowVersion, long expectedPublicationRevision, string actor, Guid correlationId, CancellationToken cancellationToken)
    {
        ConnectorVersionRecord existing = await RequiredAsync(connectorId, version, cancellationToken).ConfigureAwait(false);
        _ = validator.ParseStored(existing.CanonicalJson, existing.ChecksumSha256);
        ConnectorVersionRecord updated = await approvalPolicy.PublishAsync(store, existing, expectedRowVersion, expectedPublicationRevision, actor, correlationId, clock.UtcNow, cancellationToken).ConfigureAwait(false);
        runtimeCatalog.Invalidate(connectorId);
        if (approvalPolicy is DevelopmentConnectorApprovalPolicy) await AuditAsync(actor, "connector.publish", updated, correlationId, "success", "BGW-CONNECTOR-PUBLISHED", cancellationToken).ConfigureAwait(false);
        return Resource(updated);
    }

    /// <summary>Reactivates a Superseded version; Draft/Validated/Retired targets fail closed.</summary>
    public async Task<ConnectorVersionResource> RollbackAsync(string connectorId, ConnectorRollbackRequest request, string actor, Guid correlationId, CancellationToken cancellationToken)
    {
        ConnectorVersionRecord updated = await store.RollbackAsync(connectorId, request.TargetVersion, request.ExpectedActiveRowVersion, actor, correlationId, clock.UtcNow, cancellationToken).ConfigureAwait(false);
        runtimeCatalog.Invalidate(connectorId);
        return Resource(updated);
    }

    /// <summary>Retires a version and immediately invalidates runtime cache.</summary>
    public async Task<ConnectorVersionResource> RetireAsync(string connectorId, string version, long expectedRowVersion, string actor, Guid correlationId, CancellationToken cancellationToken)
    {
        ConnectorVersionRecord existing = await RequiredAsync(connectorId, version, cancellationToken).ConfigureAwait(false);
        ConnectorVersionRecord updated = await store.RetireAsync(existing.Id, expectedRowVersion, actor, correlationId, clock.UtcNow, cancellationToken).ConfigureAwait(false);
        runtimeCatalog.Invalidate(connectorId);
        return Resource(updated);
    }

    /// <summary>Stores logical binding values without changing the definition.</summary>
    public async Task<long> PutBindingsAsync(string connectorId, ConnectorBindingRequest request, string actor, Guid correlationId, CancellationToken cancellationToken)
    {
        IReadOnlyList<ConnectorVersionRecord> versions = await store.ListVersionsAsync(connectorId, cancellationToken).ConfigureAwait(false);
        ConnectorVersionRecord reference = request.ConnectorVersion is null
            ? versions.FirstOrDefault(value => value.State == ConnectorVersionState.Validated) ?? throw new GatewayException("BGW-CONNECTOR-BINDING-REQUIRES-VALIDATED-VERSION", 409)
            : versions.SingleOrDefault(value => string.Equals(value.Version, request.ConnectorVersion, StringComparison.Ordinal)) ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);
        if (reference.State != ConnectorVersionState.Validated) throw new GatewayException("BGW-CONNECTOR-BINDING-REQUIRES-VALIDATED-VERSION", 409);
        Dictionary<string, Uri> endpoints = new(StringComparer.Ordinal);
        foreach ((string name, string value) in request.Endpoints)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? endpoint) || endpoint.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(endpoint.UserInfo) || !string.IsNullOrEmpty(endpoint.Query) || !string.IsNullOrEmpty(endpoint.Fragment) || IPAddress.TryParse(endpoint.DnsSafeHost, out _))
                throw new GatewayException("BGW-CONNECTOR-ENDPOINT-BINDING", 400);
            endpoints[name] = endpoint!;
        }
        Dictionary<string, ProviderResourceReference> requestedSecrets = new(request.SecretResources, StringComparer.Ordinal);
        Dictionary<string, ProviderResourceReference> requestedCertificates = request.CertificateResources is null ? [] : new(request.CertificateResources, StringComparer.Ordinal);
        Dictionary<string, HashSet<string>> operationScopes = new(StringComparer.Ordinal);
        using (JsonDocument document = JsonDocument.Parse(reference.CanonicalJson))
        {
            HashSet<string> requiredEndpoints = document.RootElement.GetProperty("bindings").GetProperty("endpoints").EnumerateArray().Select(value => value.GetProperty("name").GetString()!).ToHashSet(StringComparer.Ordinal);
            Dictionary<string, string> requiredSecrets = document.RootElement.GetProperty("bindings").GetProperty("secrets").EnumerateArray().ToDictionary(value => value.GetProperty("name").GetString()!, value => value.GetProperty("kind").GetString()!, StringComparer.Ordinal);
            HashSet<string> ordinarySecrets = requiredSecrets.Where(value => value.Value != "clientCertificate").Select(value => value.Key).ToHashSet(StringComparer.Ordinal);
            HashSet<string> certificateSecrets = requiredSecrets.Where(value => value.Value == "clientCertificate").Select(value => value.Key).ToHashSet(StringComparer.Ordinal);
            if (!requiredEndpoints.SetEquals(endpoints.Keys) || !ordinarySecrets.SetEquals(requestedSecrets.Keys) || !certificateSecrets.SetEquals(requestedCertificates.Keys))
                throw new GatewayException("BGW-CONNECTOR-BINDING-SCOPE", 400);
            foreach (JsonElement operation in document.RootElement.GetProperty("operations").EnumerateArray())
            {
                string operationId = operation.GetProperty("operationId").GetString()!;
                JsonElement authentication = operation.GetProperty("authentication");
                OperationBindingDependencies dependencies = ConnectorOperationBindings.Required(reference.CanonicalJson, operationId);
                foreach (string logical in dependencies.SecretBindingIds.Concat(dependencies.CertificateBindingIds))
                {
                    if (!operationScopes.TryGetValue(logical, out HashSet<string>? scopes)) operationScopes.Add(logical, scopes = new(StringComparer.Ordinal));
                    scopes.Add(operationId);
                }
            }
        }
        Dictionary<string, ProviderResourceBinding> secretResources = new(StringComparer.Ordinal);
        foreach ((string logical, ProviderResourceReference requested) in requestedSecrets)
        {
            ProviderResourceReferenceValidator.Validate(requested);
            ProviderResourceCatalogRecord resource = await store.ResolveProviderResourceAsync(requested, request.EnvironmentId, connectorId, operationScopes[logical].ToArray(), cancellationToken).ConfigureAwait(false);
            if (resource.ResourceType != ProviderResourceType.Secret) throw new GatewayException("BGW-PROVIDER-RESOURCE-TYPE", 400);
            secretResources.Add(logical, Binding(resource));
        }
        Dictionary<string, ProviderResourceBinding> certificateResources = new(StringComparer.Ordinal);
        foreach ((string logical, ProviderResourceReference requested) in requestedCertificates)
        {
            ProviderResourceReferenceValidator.Validate(requested);
            ProviderResourceCatalogRecord resource = await store.ResolveProviderResourceAsync(requested, request.EnvironmentId, connectorId, operationScopes[logical].ToArray(), cancellationToken).ConfigureAwait(false);
            if (resource.ResourceType != ProviderResourceType.ClientCertificate || resource.CertificateMetadata is null) throw new GatewayException("BGW-PROVIDER-CERTIFICATE-METADATA-REQUIRED", 409);
            certificateResources.Add(logical, Binding(resource));
        }
        string checksum = ConnectorBindingDigests.Revision(reference.Id, request.EnvironmentId, endpoints, secretResources, certificateResources);
        ConnectorBindingSet saved = await store.PutBindingsAsync(new(Guid.NewGuid(), reference.ConnectorId, reference.Id, request.EnvironmentId, endpoints, secretResources, certificateResources, 0, checksum, ConnectorBindingState.Draft, clock.UtcNow, actor), request.ExpectedRevision, correlationId, cancellationToken).ConfigureAwait(false);
        runtimeCatalog.Invalidate(connectorId);
        return saved.Revision;
    }

    /// <summary>Lists Connector summaries.</summary>
    public Task<IReadOnlyList<ConnectorSummary>> ListAsync(CancellationToken cancellationToken) => store.ListConnectorsAsync(cancellationToken);

    /// <summary>Lists version metadata.</summary>
    public async Task<IReadOnlyList<ConnectorVersionResource>> VersionsAsync(string connectorId, CancellationToken cancellationToken) =>
        (await store.ListVersionsAsync(connectorId, cancellationToken).ConfigureAwait(false)).Select(Resource).ToArray();

    /// <summary>Returns version metadata.</summary>
    public async Task<ConnectorVersionResource> ShowAsync(string connectorId, string version, CancellationToken cancellationToken) => Resource(await RequiredAsync(connectorId, version, cancellationToken).ConfigureAwait(false));

    /// <summary>Exports canonical JSON for reproducible source control.</summary>
    public async Task<string> ExportAsync(string connectorId, string version, CancellationToken cancellationToken) => (await RequiredAsync(connectorId, version, cancellationToken).ConfigureAwait(false)).CanonicalJson;

    private async Task<ConnectorVersionRecord> RequiredAsync(string connectorId, string version, CancellationToken cancellationToken) =>
        await store.GetVersionAsync(connectorId, version, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-VERSION-NOT-FOUND", 404);

    private Task AuditAsync(string actor, string action, ConnectorVersionRecord version, Guid correlationId, string outcome, string reason, CancellationToken cancellationToken) =>
        registry.AppendAuditAsync(Audit(actor, action, version, correlationId, outcome, reason), cancellationToken);

    private GatewayAuditEvent Audit(string actor, string action, ConnectorVersionRecord version, Guid correlationId, string outcome, string reason) =>
        new(Guid.NewGuid(), clock.UtcNow, null, "administrator", actor, action, "connectorVersion", version.ConnectorSlug + "/" + version.Version, correlationId, outcome, reason, new Dictionary<string, string> { ["state"] = version.State.ToString(), ["checksum"] = Convert.ToHexString(version.ChecksumSha256) });

    private static ProviderResourceBinding Binding(ProviderResourceCatalogRecord value) => new(
        value.ProviderId, value.ProviderDisplayName, value.ProviderType, value.ResourceId, value.ResourceType, value.DisplayName,
        value.EnvironmentId, value.ConnectorScope, value.OperationScope, value.Version, value.Revision, value.PublicMetadataRevision,
        value.CertificateMetadata, value.ChecksumSha256);

    /// <summary>Projects internal persistence metadata to the redacted Admin API resource.</summary>
    public static ConnectorVersionResource Resource(ConnectorVersionRecord value) => new(value.ConnectorSlug, value.Version, value.SchemaVersion, value.State, Convert.ToHexString(value.ChecksumSha256), value.RowVersion, value.CreatedAt, value.PublishedAt);
}

/// <summary>Published-only cache that validates a lightweight store stamp on every invocation.</summary>
public sealed class PublishedConnectorCatalog(
    IConnectorConfigurationStore store,
    ConnectorDefinitionValidator validator,
    IGatewayClock clock,
    TimeSpan ttl) : IGatewayOperationCatalog, IAuthorizedPublishedOperationCatalog
{
    private readonly ConcurrentDictionary<string, CacheEntry> cache = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<GatewayOperationDefinition> GetRequiredAsync(string connectorId, string operationId, Guid environmentId, CancellationToken cancellationToken) =>
        GetRequiredOperationAsync(connectorId, operationId, environmentId, null, cancellationToken);

    /// <inheritdoc />
    public Task<GatewayOperationDefinition> GetRequiredAsync(string connectorId, string operationId, Guid environmentId, PublishedConnectorAccessContext accessContext, CancellationToken cancellationToken) =>
        GetRequiredOperationAsync(connectorId, operationId, environmentId, accessContext, cancellationToken);

    async Task<AuthorizedPublishedOperation> IAuthorizedPublishedOperationCatalog.GetRequiredAuthorizedAsync(
        string connectorId,
        string operationId,
        Guid environmentId,
        PublishedConnectorAccessContext accessContext,
        CancellationToken cancellationToken) =>
        await GetRequiredCoreAsync(connectorId, operationId, environmentId, accessContext, cancellationToken).ConfigureAwait(false);

    private async Task<GatewayOperationDefinition> GetRequiredOperationAsync(
        string connectorId,
        string operationId,
        Guid environmentId,
        PublishedConnectorAccessContext? accessContext,
        CancellationToken cancellationToken) =>
        (await GetRequiredCoreAsync(connectorId, operationId, environmentId, accessContext, cancellationToken).ConfigureAwait(false)).Operation;

    private async Task<AuthorizedPublishedOperation> GetRequiredCoreAsync(string connectorId, string operationId, Guid environmentId, PublishedConnectorAccessContext? accessContext, CancellationToken cancellationToken)
    {
        if (accessContext is not null && !string.Equals(accessContext.OperationId, operationId, StringComparison.Ordinal))
            throw new GatewayException("BGW-AUTHZ-OPERATION-DENIED", 403);
        string key = connectorId + "\n" + environmentId.ToString("D") + "\n" + operationId + "\n" + (accessContext?.InstallationId.ToString("D") ?? "admin");
        PublishedConnectorStamp? stamp;
        try { stamp = await store.GetPublishedStampAsync(connectorId, environmentId, accessContext, cancellationToken).ConfigureAwait(false); }
        catch (GatewayException) { throw; }
        catch (Exception) { throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-UNAVAILABLE", 503, true); }
        if (stamp is null) { cache.TryRemove(key, out _); throw new GatewayException("BGW-CONNECTOR-NOT-PUBLISHED", 404); }
        if (!cache.TryGetValue(key, out CacheEntry? entry) || entry.ExpiresAt <= clock.UtcNow || entry.Stamp != stamp)
        {
            PublishedConnectorSnapshot snapshot;
            try { snapshot = await store.GetPublishedSnapshotAsync(connectorId, environmentId, accessContext, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-BINDING-MISSING", 503); }
            catch (GatewayException) { throw; }
            catch (Exception) { throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-UNAVAILABLE", 503, true); }
            if (snapshot.Stamp != stamp || snapshot.Version.State != ConnectorVersionState.Published) throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-STALE", 503, true);
            entry = Build(snapshot, operationId);
            cache[key] = entry;
        }
        if (!entry.Operations.TryGetValue(operationId, out AuthorizedPublishedOperation? operation)) throw new GatewayException("BGW-OPERATION-NOT-FOUND", 404);
        return operation;
    }

    /// <inheritdoc />
    public void Invalidate(string connectorId)
    {
        foreach (string key in cache.Keys.Where(value => value.StartsWith(connectorId + "\n", StringComparison.Ordinal)).ToArray()) cache.TryRemove(key, out _);
    }

    private CacheEntry Build(PublishedConnectorSnapshot snapshot, string requiredOperationId)
    {
        ValidatedConnectorDefinition parsed = validator.ParseStored(snapshot.Version.CanonicalJson, snapshot.Version.ChecksumSha256);
        using JsonDocument document = JsonDocument.Parse(parsed.CanonicalJson);
        Dictionary<string, AuthorizedPublishedOperation> operations = new(StringComparer.Ordinal);
        foreach (JsonElement operation in document.RootElement.GetProperty("operations").EnumerateArray())
        {
            string operationId = operation.GetProperty("operationId").GetString()!;
            if (!string.Equals(operationId, requiredOperationId, StringComparison.Ordinal)) continue;
            string endpointName = operation.GetProperty("endpointBinding").GetString()!;
            if (!snapshot.Bindings.Endpoints.TryGetValue(endpointName, out Uri? baseUri)) throw new GatewayException("BGW-CONNECTOR-ENDPOINT-BINDING-MISSING", 503);
            Uri endpoint = new(baseUri, operation.GetProperty("path").GetString()!);
            JsonElement auth = operation.GetProperty("authentication");
            GatewayAuthenticationKind authKind = ParseAuthentication(auth.GetProperty("kind").GetString()!);
            string? Resolve(string property) => auth.TryGetProperty(property, out JsonElement logical) && (property == "certificateBinding" ? snapshot.CertificateProviderReferences : snapshot.SecretProviderReferences).TryGetValue(logical.GetString()!, out string? reference)
                ? reference
                : auth.TryGetProperty(property, out _) ? throw new GatewayException("BGW-CONNECTOR-SECRET-BINDING-MISSING", 503) : null;
            JsonElement request = operation.GetProperty("request");
            JsonElement response = operation.GetProperty("response");
            GatewayOperationDefinition definition = new(parsed.ConnectorId, operationId, parsed.Version, endpoint, new HttpMethod(operation.GetProperty("method").GetString()!), request.GetProperty("contentType").GetString()!, authKind,
                Resolve("usernameBinding"), Resolve("passwordBinding"), Resolve("secretBinding"), auth.TryGetProperty("headerName", out JsonElement header) ? header.GetString() : null, Resolve("certificateBinding"),
                operation.GetProperty("timeoutMs").GetInt32(), request.GetProperty("maximumBytes").GetInt64(), response.GetProperty("maximumBytes").GetInt64(),
                operation.TryGetProperty("idempotent", out JsonElement idempotent) && idempotent.GetBoolean(), operation.TryGetProperty("maximumRetries", out JsonElement retries) ? retries.GetInt32() : 0,
                auth.TryGetProperty("policyId", out JsonElement policyId) ? policyId.GetString() : null,
                auth.TryGetProperty("sessionProfileId", out JsonElement sessionProfileId) ? sessionProfileId.GetString() : null,
                operation.TryGetProperty("executionStrategy", out JsonElement executionStrategy)
                    ? ConnectorExecutionStrategyKey.Parse(executionStrategy.GetString()!)
                    : null);
            _ = new GatewayOperationCatalog([definition]);
            ConnectorExecutionStrategyKey strategyKey = ConnectorExecutionStrategyKeys.Resolve(definition);
            byte[] extensionConfiguration = operation.TryGetProperty("extensionConfiguration", out JsonElement extension)
                ? Encoding.UTF8.GetBytes(extension.GetRawText())
                : "{}"u8.ToArray();
            operations.Add(operationId, new(
                definition,
                AuthorizedPublishedExecutionStamp.Capture(snapshot, snapshot.Bindings.EnvironmentId, definition, strategyKey),
                new AuthorizedPublishedExtensionConfiguration(extensionConfiguration)));
        }
        return new(snapshot.Stamp, clock.UtcNow.Add(ttl), operations);
    }

    private static GatewayAuthenticationKind ParseAuthentication(string kind) => kind switch
    {
        "none" => GatewayAuthenticationKind.None,
        "basic" => GatewayAuthenticationKind.Basic,
        "apiKey" => GatewayAuthenticationKind.ApiKey,
        "mtls" => GatewayAuthenticationKind.MutualTls,
        "apiKeyAndMtls" => GatewayAuthenticationKind.ApiKeyAndMutualTls,
        "oauthAuthorizationCode" => GatewayAuthenticationKind.OAuthAuthorizationCode,
        "oauthClientCredentials" => GatewayAuthenticationKind.OAuthClientCredentials,
        "opaqueSessionHttp" => GatewayAuthenticationKind.OpaqueSessionHttp,
        "soapBasicOpaqueSession" => GatewayAuthenticationKind.SoapBasicOpaqueSession,
        _ => throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-CORRUPT", 503)
    };

    private sealed record CacheEntry(PublishedConnectorStamp Stamp, DateTimeOffset ExpiresAt, IReadOnlyDictionary<string, AuthorizedPublishedOperation> Operations);
}

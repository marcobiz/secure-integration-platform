using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Json.Schema;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Application;

/// <summary>One redacted validation finding.</summary>
public sealed record ConnectorValidationIssue(string Code, string Location);

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
    IReadOnlyDictionary<string, string> SecretReferences,
    long? ExpectedRevision = null);

/// <summary>Non-destructive contract test of one Published operation and Environment binding.</summary>
public sealed record ConnectorTestRequest(Guid EnvironmentId, string OperationId);

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

/// <summary>Draft 2020-12 and semantic validator for Connector Definition JSON v1.</summary>
public sealed class ConnectorDefinitionValidator
{
    private static readonly JsonSchema Schema = LoadSchema();
    private readonly JsonSchema schema = Schema;
    private static readonly HashSet<string> ForbiddenHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "Cookie", "Host", "Forwarded", "Proxy-Authorization", "Connection", "Transfer-Encoding", "Upgrade"
    };

    /// <summary>Validates a parsed definition and returns only bounded issue codes/locations.</summary>
    public ConnectorValidationResult Validate(JsonElement definition)
    {
        List<ConnectorValidationIssue> issues = [];
        EvaluationResults schemaResult = schema.Evaluate(definition, new EvaluationOptions { OutputFormat = OutputFormat.List });
        if (!schemaResult.IsValid) issues.Add(new("CONNECTOR_SCHEMA_INVALID", "$"));
        if (definition.ValueKind != JsonValueKind.Object)
            return new(false, null, issues);

        string? schemaVersion = OptionalString(definition, "schemaVersion");
        if (!string.Equals(schemaVersion, "1.0", StringComparison.Ordinal)) issues.Add(new("CONNECTOR_SCHEMA_VERSION_UNSUPPORTED", "$.schemaVersion"));

        if (issues.Count == 0) ValidateSemantics(definition, issues);
        if (issues.Count != 0) return new(false, null, issues);

        string canonical = ConnectorCanonicalJson.Canonicalize(definition);
        return new(true, ConnectorCanonicalJson.Checksum(canonical), []);
    }

    /// <summary>Validates and returns a canonical representation, or throws a stable error.</summary>
    public ValidatedConnectorDefinition ValidateRequired(JsonElement definition, string? expectedChecksum = null)
    {
        ConnectorValidationResult result = Validate(definition);
        if (!result.Valid) throw new GatewayException(result.Issues.Any(issue => issue.Code == "CONNECTOR_SCHEMA_VERSION_UNSUPPORTED") ? "BGW-CONNECTOR-SCHEMA-VERSION" : "BGW-CONNECTOR-VALIDATION", 400);
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
            if (!operations.Add(operationId)) issues.Add(new("CONNECTOR_OPERATION_DUPLICATE", $"$.operations[{index}].operationId"));
            string endpoint = operation.GetProperty("endpointBinding").GetString()!;
            if (!endpoints.ContainsKey(endpoint)) issues.Add(new("CONNECTOR_ENDPOINT_BINDING_UNKNOWN", $"$.operations[{index}].endpointBinding"));
            bool idempotent = operation.TryGetProperty("idempotent", out JsonElement idempotentElement) && idempotentElement.GetBoolean();
            int retries = operation.TryGetProperty("maximumRetries", out JsonElement retriesElement) ? retriesElement.GetInt32() : 0;
            if (retries > 0 && !idempotent) issues.Add(new("CONNECTOR_RETRY_REQUIRES_IDEMPOTENCY", $"$.operations[{index}].maximumRetries"));
            foreach (JsonElement headerElement in operation.GetProperty("allowedClientHeaders").EnumerateArray())
            {
                string header = headerElement.GetString()!;
                if (ForbiddenHeaders.Contains(header) || header.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase) || header.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase))
                    issues.Add(new("CONNECTOR_HEADER_FORBIDDEN", $"$.operations[{index}].allowedClientHeaders"));
            }
            ValidateAuthentication(operation.GetProperty("authentication"), secrets, issues, index);
            index++;
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
            if (!result.TryAdd(name, kind)) issues.Add(new("CONNECTOR_BINDING_DUPLICATE", $"$.bindings.{category}s[{index}].name"));
            index++;
        }
        return result;
    }

    private static void ValidateAuthentication(JsonElement auth, Dictionary<string, string> secrets, List<ConnectorValidationIssue> issues, int operationIndex)
    {
        string kind = auth.GetProperty("kind").GetString()!;
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

    private static ValidatedConnectorDefinition Parse(string canonicalJson, string checksum)
    {
        using JsonDocument document = JsonDocument.Parse(canonicalJson);
        JsonElement root = document.RootElement;
        return new(root.GetProperty("schemaVersion").GetString()!, root.GetProperty("connectorId").GetString()!, root.GetProperty("version").GetString()!, root.GetProperty("displayName").GetString()!, canonicalJson, checksum);
    }

    private static string? OptionalString(JsonElement element, string name) => element.TryGetProperty(name, out JsonElement property) && property.ValueKind == JsonValueKind.String ? property.GetString() : null;

    private static JsonSchema LoadSchema()
    {
        using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("SecureIntegration.Gateway.Application.Connectors.connector-definition.schema.json")
            ?? throw new InvalidOperationException("Embedded Connector schema is missing.");
        using StreamReader reader = new(stream, Encoding.UTF8);
        return JsonSchema.FromText(reader.ReadToEnd());
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
    IConnectorApprovalPolicy? approvalPolicy = null)
{
    /// <summary>Validates without persisting a definition.</summary>
    public ConnectorValidationResult Validate(JsonElement definition) => validator.Validate(definition);

    /// <summary>Imports a new Draft and computes its canonical checksum.</summary>
    public async Task<ConnectorVersionResource> ImportAsync(JsonElement definition, string? expectedChecksum, string actor, Guid correlationId, CancellationToken cancellationToken)
    {
        ValidatedConnectorDefinition validated = validator.ValidateRequired(definition, expectedChecksum);
        ConnectorVersionRecord draft = new(Guid.NewGuid(), Guid.Empty, validated.ConnectorId, validated.Version, validated.SchemaVersion, ConnectorVersionState.Draft, validated.CanonicalJson, Convert.FromHexString(validated.ChecksumSha256), actor, clock.UtcNow, 1);
        ConnectorVersionRecord created = await store.CreateDraftAsync(draft, cancellationToken).ConfigureAwait(false);
        await AuditAsync(actor, "connector.import", created, correlationId, "success", "BGW-CONNECTOR-IMPORTED", cancellationToken).ConfigureAwait(false);
        return Resource(created);
    }

    /// <summary>Validates one stored Draft using its immutable checksum.</summary>
    public async Task<ConnectorVersionResource> ValidateStoredAsync(string connectorId, string version, long expectedRowVersion, string actor, Guid correlationId, CancellationToken cancellationToken)
    {
        ConnectorVersionRecord existing = await RequiredAsync(connectorId, version, cancellationToken).ConfigureAwait(false);
        if (existing.State != ConnectorVersionState.Draft) throw new GatewayException("BGW-CONNECTOR-STATE", 409);
        _ = validator.ParseStored(existing.CanonicalJson, existing.ChecksumSha256);
        ConnectorVersionRecord updated = await store.MarkValidatedAsync(existing.Id, expectedRowVersion, clock.UtcNow, cancellationToken).ConfigureAwait(false);
        await AuditAsync(actor, "connector.validate", updated, correlationId, "success", "BGW-CONNECTOR-VALIDATED", cancellationToken).ConfigureAwait(false);
        return Resource(updated);
    }

    /// <summary>Atomically publishes a Validated version.</summary>
    public async Task<ConnectorVersionResource> PublishAsync(string connectorId, string version, long expectedRowVersion, long expectedPublicationRevision, string actor, Guid correlationId, CancellationToken cancellationToken)
    {
        ConnectorVersionRecord existing = await RequiredAsync(connectorId, version, cancellationToken).ConfigureAwait(false);
        if (approvalPolicy is not null) await approvalPolicy.EnsurePublishApprovedAsync(existing, actor, cancellationToken).ConfigureAwait(false);
        _ = validator.ParseStored(existing.CanonicalJson, existing.ChecksumSha256);
        ConnectorVersionRecord updated = await store.PublishAsync(existing.Id, expectedRowVersion, expectedPublicationRevision, actor, clock.UtcNow, cancellationToken).ConfigureAwait(false);
        runtimeCatalog.Invalidate(connectorId);
        await AuditAsync(actor, "connector.publish", updated, correlationId, "success", "BGW-CONNECTOR-PUBLISHED", cancellationToken).ConfigureAwait(false);
        return Resource(updated);
    }

    /// <summary>Reactivates a Superseded version; Draft/Validated/Retired targets fail closed.</summary>
    public async Task<ConnectorVersionResource> RollbackAsync(string connectorId, ConnectorRollbackRequest request, string actor, Guid correlationId, CancellationToken cancellationToken)
    {
        ConnectorVersionRecord updated = await store.RollbackAsync(connectorId, request.TargetVersion, request.ExpectedActiveRowVersion, actor, clock.UtcNow, cancellationToken).ConfigureAwait(false);
        runtimeCatalog.Invalidate(connectorId);
        await AuditAsync(actor, "connector.rollback", updated, correlationId, "success", "BGW-CONNECTOR-ROLLED-BACK", cancellationToken).ConfigureAwait(false);
        return Resource(updated);
    }

    /// <summary>Retires a version and immediately invalidates runtime cache.</summary>
    public async Task<ConnectorVersionResource> RetireAsync(string connectorId, string version, long expectedRowVersion, string actor, Guid correlationId, CancellationToken cancellationToken)
    {
        ConnectorVersionRecord existing = await RequiredAsync(connectorId, version, cancellationToken).ConfigureAwait(false);
        ConnectorVersionRecord updated = await store.RetireAsync(existing.Id, expectedRowVersion, actor, clock.UtcNow, cancellationToken).ConfigureAwait(false);
        runtimeCatalog.Invalidate(connectorId);
        await AuditAsync(actor, "connector.retire", updated, correlationId, "success", "BGW-CONNECTOR-RETIRED", cancellationToken).ConfigureAwait(false);
        return Resource(updated);
    }

    /// <summary>Stores logical binding values without changing the definition.</summary>
    public async Task<long> PutBindingsAsync(string connectorId, ConnectorBindingRequest request, string actor, Guid correlationId, CancellationToken cancellationToken)
    {
        IReadOnlyList<ConnectorVersionRecord> versions = await store.ListVersionsAsync(connectorId, cancellationToken).ConfigureAwait(false);
        ConnectorVersionRecord reference = versions.Count == 0 ? throw new GatewayException("BGW-CONNECTOR-NOT-FOUND", 404) : versions[0];
        Dictionary<string, Uri> endpoints = new(StringComparer.Ordinal);
        foreach ((string name, string value) in request.Endpoints)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? endpoint) || endpoint.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(endpoint.UserInfo) || !string.IsNullOrEmpty(endpoint.Query) || !string.IsNullOrEmpty(endpoint.Fragment) || IPAddress.TryParse(endpoint.DnsSafeHost, out _))
                throw new GatewayException("BGW-CONNECTOR-ENDPOINT-BINDING", 400);
            endpoints[name] = endpoint!;
        }
        if (request.SecretReferences.Any(pair => string.IsNullOrWhiteSpace(pair.Key) || string.IsNullOrWhiteSpace(pair.Value))) throw new GatewayException("BGW-CONNECTOR-SECRET-BINDING", 400);
        ConnectorBindingSet saved = await store.PutBindingsAsync(new(reference.ConnectorId, request.EnvironmentId, endpoints, new Dictionary<string, string>(request.SecretReferences, StringComparer.Ordinal), 0, clock.UtcNow, actor), request.ExpectedRevision, cancellationToken).ConfigureAwait(false);
        runtimeCatalog.Invalidate(connectorId);
        await AuditAsync(actor, "connector.bindings.update", reference, correlationId, "success", "BGW-CONNECTOR-BINDINGS-UPDATED", cancellationToken).ConfigureAwait(false);
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
        registry.AppendAuditAsync(new(Guid.NewGuid(), clock.UtcNow, null, "administrator", actor, action, "connectorVersion", version.ConnectorSlug + "/" + version.Version, correlationId, outcome, reason, new Dictionary<string, string> { ["state"] = version.State.ToString(), ["checksum"] = Convert.ToHexString(version.ChecksumSha256) }), cancellationToken);

    private static ConnectorVersionResource Resource(ConnectorVersionRecord value) => new(value.ConnectorSlug, value.Version, value.SchemaVersion, value.State, Convert.ToHexString(value.ChecksumSha256), value.RowVersion, value.CreatedAt, value.PublishedAt);
}

/// <summary>Published-only cache that validates a lightweight store stamp on every invocation.</summary>
public sealed class PublishedConnectorCatalog(
    IConnectorConfigurationStore store,
    ConnectorDefinitionValidator validator,
    IGatewayClock clock,
    TimeSpan ttl) : IGatewayOperationCatalog
{
    private readonly ConcurrentDictionary<string, CacheEntry> cache = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public async Task<GatewayOperationDefinition> GetRequiredAsync(string connectorId, string operationId, Guid environmentId, CancellationToken cancellationToken)
    {
        string key = connectorId + "\n" + environmentId.ToString("D");
        PublishedConnectorStamp? stamp;
        try { stamp = await store.GetPublishedStampAsync(connectorId, environmentId, cancellationToken).ConfigureAwait(false); }
        catch (GatewayException) { throw; }
        catch (Exception) { throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-UNAVAILABLE", 503, true); }
        if (stamp is null) { cache.TryRemove(key, out _); throw new GatewayException("BGW-CONNECTOR-NOT-PUBLISHED", 404); }
        if (!cache.TryGetValue(key, out CacheEntry? entry) || entry.ExpiresAt <= clock.UtcNow || entry.Stamp != stamp)
        {
            PublishedConnectorSnapshot snapshot;
            try { snapshot = await store.GetPublishedSnapshotAsync(connectorId, environmentId, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-CONNECTOR-BINDING-MISSING", 503); }
            catch (GatewayException) { throw; }
            catch (Exception) { throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-UNAVAILABLE", 503, true); }
            if (snapshot.Stamp != stamp || snapshot.Version.State != ConnectorVersionState.Published) throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-STALE", 503, true);
            entry = Build(snapshot);
            cache[key] = entry;
        }
        if (!entry.Operations.TryGetValue(operationId, out GatewayOperationDefinition? operation)) throw new GatewayException("BGW-OPERATION-NOT-FOUND", 404);
        return operation;
    }

    /// <inheritdoc />
    public void Invalidate(string connectorId)
    {
        foreach (string key in cache.Keys.Where(value => value.StartsWith(connectorId + "\n", StringComparison.Ordinal)).ToArray()) cache.TryRemove(key, out _);
    }

    private CacheEntry Build(PublishedConnectorSnapshot snapshot)
    {
        ValidatedConnectorDefinition parsed = validator.ParseStored(snapshot.Version.CanonicalJson, snapshot.Version.ChecksumSha256);
        using JsonDocument document = JsonDocument.Parse(parsed.CanonicalJson);
        Dictionary<string, GatewayOperationDefinition> operations = new(StringComparer.Ordinal);
        foreach (JsonElement operation in document.RootElement.GetProperty("operations").EnumerateArray())
        {
            string operationId = operation.GetProperty("operationId").GetString()!;
            string endpointName = operation.GetProperty("endpointBinding").GetString()!;
            if (!snapshot.Bindings.Endpoints.TryGetValue(endpointName, out Uri? baseUri)) throw new GatewayException("BGW-CONNECTOR-ENDPOINT-BINDING-MISSING", 503);
            Uri endpoint = new(baseUri, operation.GetProperty("path").GetString()!);
            JsonElement auth = operation.GetProperty("authentication");
            GatewayAuthenticationKind authKind = ParseAuthentication(auth.GetProperty("kind").GetString()!);
            string? Resolve(string property) => auth.TryGetProperty(property, out JsonElement logical) && snapshot.Bindings.SecretReferences.TryGetValue(logical.GetString()!, out string? reference)
                ? reference
                : auth.TryGetProperty(property, out _) ? throw new GatewayException("BGW-CONNECTOR-SECRET-BINDING-MISSING", 503) : null;
            JsonElement request = operation.GetProperty("request");
            JsonElement response = operation.GetProperty("response");
            GatewayOperationDefinition definition = new(parsed.ConnectorId, operationId, parsed.Version, endpoint, new HttpMethod(operation.GetProperty("method").GetString()!), request.GetProperty("contentType").GetString()!, authKind,
                Resolve("usernameBinding"), Resolve("passwordBinding"), Resolve("secretBinding"), auth.TryGetProperty("headerName", out JsonElement header) ? header.GetString() : null, Resolve("certificateBinding"),
                operation.GetProperty("timeoutMs").GetInt32(), request.GetProperty("maximumBytes").GetInt64(), response.GetProperty("maximumBytes").GetInt64(),
                operation.TryGetProperty("idempotent", out JsonElement idempotent) && idempotent.GetBoolean(), operation.TryGetProperty("maximumRetries", out JsonElement retries) ? retries.GetInt32() : 0);
            _ = new GatewayOperationCatalog([definition]);
            operations.Add(operationId, definition);
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
        _ => throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-CORRUPT", 503)
    };

    private sealed record CacheEntry(PublishedConnectorStamp Stamp, DateTimeOffset ExpiresAt, IReadOnlyDictionary<string, GatewayOperationDefinition> Operations);
}

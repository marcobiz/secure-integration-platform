using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Net;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

/// <summary>External Healthcare module for the frozen FSE2 Organization profile.</summary>
public sealed class Fse2OrganizationExecutionModule : IConnectorExecutionModule
{
    public ConnectorExecutionModuleId Id => ConnectorExecutionModuleId.Parse("healthcare-fse2");

    public void RegisterExecutionStrategies(IConnectorExecutionStrategyRegistrar registrar)
    {
        ArgumentNullException.ThrowIfNull(registrar);
        registrar.AddSingleton<IFse2WorkflowCorrelationStore, InMemoryFse2WorkflowCorrelationStore>();
        registrar.AddStrategy<Fse2OrganizationExecutionStrategy>();
    }
}

/// <summary>
/// Connector-local FSE2 composition. Core has already authenticated, granted and resolved Published
/// A; the strategy receives no store, provider, endpoint, certificate, key, token or HttpClient.
/// </summary>
public sealed class Fse2OrganizationExecutionStrategy(
    IFse2WorkflowCorrelationStore workflowStore) : IConnectorExecutionStrategy
{
    private static readonly ConnectorExecutionStrategyKey StrategyKey =
        ConnectorExecutionStrategyKey.Parse("healthcare-fse2-organization");
    private static readonly IReadOnlySet<GatewayAuthenticationKind> AuthenticationKinds =
        new HashSet<GatewayAuthenticationKind> { GatewayAuthenticationKind.MutualTls }.ToFrozenSet();
    private static readonly IReadOnlyDictionary<string, JsonElement> EmptyClaims =
        new Dictionary<string, JsonElement>(StringComparer.Ordinal).ToFrozenDictionary(StringComparer.Ordinal);
    private static readonly JsonSerializerOptions ResponseJson = new(JsonSerializerDefaults.Web);

    public ConnectorExecutionStrategyKey Key => StrategyKey;
    public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => AuthenticationKinds;

    public async Task<QualifiedGatewayExecutionResult> ExecuteAsync(
        AuthorizedConnectorExecution execution,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        if (execution.ExecutionStrategyKey != StrategyKey || execution.AuthenticationKind != GatewayAuthenticationKind.MutualTls)
            throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_EXECUTION_AUTHORITY_DENIED");

        Fse2PublishedOrganizationProfile profile =
            Fse2PublishedOrganizationProfile.Parse(execution.OpenPublishedExtensionConfiguration());
        if (!string.Equals(profile.Operation.OperationId, execution.OperationId, StringComparison.Ordinal) ||
            !string.Equals(profile.RequestContentType, execution.RequestContentType, StringComparison.Ordinal))
            throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_PUBLISHED_OPERATION_MISMATCH");

        Fse2InboundPayload inbound;
        using (Stream payload = execution.OpenPayloadStream())
            inbound = Fse2InboundPayload.Parse(payload, execution.PayloadLength);
        ValidateRequest(profile, inbound);

        Fse2WorkflowExecutionContext security = await ResolveSecurityContextAsync(
            execution, profile, inbound, cancellationToken).ConfigureAwait(false);
        byte[] exactOutboundBody = Fse2ExactBodyComposer.Compose(profile, inbound);
        IReadOnlyDictionary<string, JsonElement> integrityClaims = BuildIntegrityClaims(
            profile, inbound, security, exactOutboundBody);

        _ = await execution.Capabilities.CreateSignedTokenAsync(
            profile.AuthorizationSigningSlot,
            EmptyClaims,
            cancellationToken).ConfigureAwait(false);
        _ = await execution.Capabilities.CreateSignedTokenAsync(
            profile.IntegritySigningSlot,
            integrityClaims,
            cancellationToken).ConfigureAwait(false);

        QualifiedGatewayExecutionResult upstream = await execution.Capabilities.ExecuteRestrictedTransportAsync(
            new AuthorizedConnectorRestrictedTransportRequest(exactOutboundBody),
            cancellationToken).ConfigureAwait(false);
        Fse2Response normalized = Fse2ResponseMapper.Map(upstream, execution.CorrelationId, profile.Operation);
        if (profile.Operation.Operation is not (Fse2Operation.GetStatusByWorkflow or Fse2Operation.GetStatusByTrace) &&
            (normalized.WorkflowInstanceId is not null || normalized.TraceId is not null))
        {
            await workflowStore.RecordAsync(execution.CorrelationId, new(
                WorkflowScope(execution, profile),
                profile.Operation.Operation,
                security.OperationReference,
                security.Action,
                security.PurposeOfUse,
                normalized.WorkflowInstanceId,
                normalized.TraceId), cancellationToken).ConfigureAwait(false);
        }

        return new(upstream.StatusCode, "application/json", JsonSerializer.SerializeToUtf8Bytes(normalized, ResponseJson));
    }

    private async Task<Fse2WorkflowExecutionContext> ResolveSecurityContextAsync(
        AuthorizedConnectorExecution execution,
        Fse2PublishedOrganizationProfile profile,
        Fse2InboundPayload inbound,
        CancellationToken cancellationToken)
    {
        Fse2OperationDescriptor operation = profile.Operation;
        if (operation.Action is Fse2Action action && operation.PurposeOfUse is Fse2PurposeOfUse purpose)
        {
            if (operation.Operation != Fse2Operation.Delete && inbound.ClinicalClaims.ResourceHl7Type is null)
                throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_RESOURCE_HL7_TYPE_REQUIRED");
            Fse2OperationCatalog.ValidateOrganizationCombination(profile.SubjectRole, operation.OperationId, purpose, action);
            return new(action, purpose, inbound.ClinicalClaims, operation.OperationId);
        }

        try
        {
            Fse2WorkflowAuthorityScope scope = WorkflowScope(execution, profile);
            Fse2WorkflowRecord stored = await workflowStore.ResolveAsync(
                scope,
                operation.Operation,
                profile.ResourceIdentifier!,
                cancellationToken).ConfigureAwait(false);
            Fse2OperationDescriptor origin = Fse2OperationCatalog.Get(stored.OriginatingOperation);
            if (stored.Authority != scope ||
                !string.Equals(origin.OperationId, stored.OriginatingOperationId, StringComparison.Ordinal))
                throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_WORKFLOW_CONTEXT_DENIED");
            Fse2OperationCatalog.ValidateOrganizationCombination(
                profile.SubjectRole,
                stored.OriginatingOperationId,
                stored.PurposeOfUse,
                stored.Action);
            return new(stored.Action, stored.PurposeOfUse, inbound.ClinicalClaims, stored.OriginatingOperationId);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Fse2ConnectorException) { throw; }
        catch (Exception) { throw Denied(Fse2ErrorCategory.PolicyDenied, "FSE2_WORKFLOW_CONTEXT_NOT_FOUND"); }
    }

    private static void ValidateRequest(Fse2PublishedOrganizationProfile profile, Fse2InboundPayload inbound)
    {
        Fse2OperationDescriptor operation = profile.Operation;
        if (inbound.Document.Length > profile.MaximumDocumentBytes ||
            operation.HasDocument != !inbound.Document.IsEmpty ||
            operation.HasJsonBody != !inbound.RequestBody.IsEmpty ||
            operation.RequiresResourceIdentifier != (inbound.ResourceIdentifier is not null) ||
            !string.Equals(profile.ResourceIdentifier, inbound.ResourceIdentifier, StringComparison.Ordinal))
            throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_REQUEST_SHAPE_DENIED");
        if (operation.HasJsonBody) Fse2Validation.ValidateJsonObject(inbound.RequestBody);
        if (operation.HasDocument && inbound.DocumentContentType is not ("application/pdf" or "application/json"))
            throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_DOCUMENT_CONTENT_TYPE_DENIED");
        if (operation.Operation != Fse2Operation.ValidateFhir && inbound.DocumentContentType == "application/json")
            throw Denied(Fse2ErrorCategory.InputDenied, "FSE2_DOCUMENT_CONTENT_TYPE_DENIED");
    }

    private static FrozenDictionary<string, JsonElement> BuildIntegrityClaims(
        Fse2PublishedOrganizationProfile profile,
        Fse2InboundPayload inbound,
        Fse2WorkflowExecutionContext security,
        ReadOnlyMemory<byte> exactOutboundBody)
    {
        Dictionary<string, JsonElement> claims = new(StringComparer.Ordinal)
        {
            ["subject_role"] = JsonSerializer.SerializeToElement(profile.SubjectRole),
            ["purpose_of_use"] = JsonSerializer.SerializeToElement(Fse2OperationCatalog.ClaimValue(security.PurposeOfUse)),
            ["subject_organization"] = JsonSerializer.SerializeToElement(profile.OrganizationDescription),
            ["subject_organization_id"] = JsonSerializer.SerializeToElement(profile.OrganizationDomainId),
            ["locality"] = JsonSerializer.SerializeToElement(profile.Locality),
            ["person_id"] = JsonSerializer.SerializeToElement(security.ClinicalClaims.PersonId),
            ["patient_consent"] = JsonSerializer.SerializeToElement(security.ClinicalClaims.PatientConsent),
            ["action_id"] = JsonSerializer.SerializeToElement(Fse2OperationCatalog.ClaimValue(security.Action)),
            ["subject_application_id"] = JsonSerializer.SerializeToElement(profile.ApplicationId),
            ["subject_application_vendor"] = JsonSerializer.SerializeToElement(profile.ApplicationVendor),
            ["subject_application_version"] = JsonSerializer.SerializeToElement(profile.ApplicationVersion)
        };
        if (security.ClinicalClaims.ResourceHl7Type is not null)
            claims["resource_hl7_type"] = JsonSerializer.SerializeToElement(security.ClinicalClaims.ResourceHl7Type);
        if (profile.Operation.RequiresAttachmentHash)
            claims["attachment_hash"] = JsonSerializer.SerializeToElement(Fse2Validation.ComputeAttachmentHash(exactOutboundBody));
        return claims.ToFrozenDictionary(StringComparer.Ordinal);
    }

    private static Fse2WorkflowAuthorityScope WorkflowScope(
        AuthorizedConnectorExecution execution,
        Fse2PublishedOrganizationProfile profile) => new(
            execution.TenantId,
            execution.ApplicationId,
            execution.InstallationId,
            execution.EnvironmentId,
            execution.ConnectorVersion,
            execution.ConnectorId,
            profile.ProfileChecksumSha256);

    private static Fse2ConnectorException Denied(Fse2ErrorCategory category, string code) => new(category, code);

    private sealed record Fse2WorkflowExecutionContext(
        Fse2Action Action,
        Fse2PurposeOfUse PurposeOfUse,
        Fse2ClinicalClaims ClinicalClaims,
        string OperationReference);
}

/// <summary>Bounded, process-local technical correlation store owned by the FSE2 module.</summary>
public sealed class InMemoryFse2WorkflowCorrelationStore : IFse2WorkflowCorrelationStore
{
    private const int MaximumRecords = 10_000;
    private readonly ConcurrentDictionary<(Fse2WorkflowAuthorityScope Authority, string Identifier), Fse2WorkflowRecord> records = new();

    public Task RecordAsync(Guid correlationId, Fse2WorkflowRecord record, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(record);
        if (correlationId == Guid.Empty || records.Count >= MaximumRecords ||
            record.WorkflowInstanceId is null && record.TraceId is null)
            throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_WORKFLOW_RECORD_FAILED");
        Add(record.WorkflowInstanceId);
        Add(record.TraceId);
        return Task.CompletedTask;

        void Add(string? identifier)
        {
            if (identifier is null) return;
            if (!records.TryAdd((record.Authority, identifier), record))
                throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_WORKFLOW_RECORD_FAILED");
        }
    }

    public Task<Fse2WorkflowRecord> ResolveAsync(
        Fse2WorkflowAuthorityScope authority,
        Fse2Operation statusOperation,
        string resourceIdentifier,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (statusOperation is not (Fse2Operation.GetStatusByWorkflow or Fse2Operation.GetStatusByTrace) ||
            !records.TryGetValue((authority, resourceIdentifier), out Fse2WorkflowRecord? record) ||
            statusOperation == Fse2Operation.GetStatusByWorkflow && !string.Equals(record.WorkflowInstanceId, resourceIdentifier, StringComparison.Ordinal) ||
            statusOperation == Fse2Operation.GetStatusByTrace && !string.Equals(record.TraceId, resourceIdentifier, StringComparison.Ordinal))
            throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_WORKFLOW_CONTEXT_NOT_FOUND");
        return Task.FromResult(record);
    }
}

internal sealed record Fse2InboundPayload(
    ReadOnlyMemory<byte> Document,
    ReadOnlyMemory<byte> RequestBody,
    string? DocumentContentType,
    string? ResourceIdentifier,
    Fse2ClinicalClaims ClinicalClaims)
{
    private static readonly HashSet<string> AllowedProperties = new(StringComparer.Ordinal)
    {
        "personId", "patientConsent", "resourceHl7Type", "documentBase64", "requestBodyBase64",
        "documentContentType", "resourceIdentifier"
    };

    internal static Fse2InboundPayload Parse(Stream stream, int payloadLength)
    {
        if (payloadLength is < 2 or > 16 * 1024 * 1024)
            throw new Fse2ConnectorException(Fse2ErrorCategory.InputDenied, "FSE2_REQUEST_PAYLOAD_INVALID");
        try
        {
            using JsonDocument document = JsonDocument.Parse(stream, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4
            });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new JsonException();
            HashSet<string> observed = new(StringComparer.Ordinal);
            foreach (JsonProperty property in root.EnumerateObject())
                if (!AllowedProperties.Contains(property.Name) || !observed.Add(property.Name)) throw new JsonException();
            if (!observed.Contains("personId") || !observed.Contains("patientConsent")) throw new JsonException();

            string personId = String(root, "personId", 512)!;
            bool consent = root.GetProperty("patientConsent").GetBoolean();
            string? resourceType = String(root, "resourceHl7Type", 256);
            Fse2ClinicalClaims clinical = Fse2ClinicalClaims.CreateCanonicalPerson(personId, consent, resourceType);
            byte[] documentBytes = Decode(root, "documentBase64");
            byte[] requestBytes = Decode(root, "requestBodyBase64");
            return new(documentBytes, requestBytes, String(root, "documentContentType", 128),
                String(root, "resourceIdentifier", 512), clinical);
        }
        catch (Fse2ConnectorException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidOperationException or JsonException or KeyNotFoundException or OverflowException)
        {
            throw new Fse2ConnectorException(Fse2ErrorCategory.InputDenied, "FSE2_REQUEST_PAYLOAD_INVALID");
        }
    }

    private static string? String(JsonElement root, string name, int maximumLength)
    {
        if (!root.TryGetProperty(name, out JsonElement property) || property.ValueKind == JsonValueKind.Null) return null;
        if (property.ValueKind != JsonValueKind.String) throw new JsonException();
        string value = property.GetString()!;
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value != value.Trim() || value.Any(char.IsControl))
            throw new JsonException();
        return value;
    }

    private static byte[] Decode(JsonElement root, string name)
    {
        string? encoded = String(root, name, 21 * 1024 * 1024);
        return encoded is null ? [] : Convert.FromBase64String(encoded);
    }
}

internal static class Fse2ExactBodyComposer
{
    internal static byte[] Compose(Fse2PublishedOrganizationProfile profile, Fse2InboundPayload inbound)
    {
        if (!profile.Operation.HasDocument)
            return inbound.RequestBody.IsEmpty ? "{}"u8.ToArray() : inbound.RequestBody.ToArray();

        using MemoryStream output = new();
        string boundary = profile.MultipartBoundary!;
        WriteAscii(output, $"--{boundary}\r\nContent-Disposition: form-data; name=\"requestBody\"\r\nContent-Type: application/json\r\n\r\n");
        output.Write(inbound.RequestBody.Span);
        WriteAscii(output, $"\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{(inbound.DocumentContentType == "application/json" ? "bundle.json" : "document.pdf")}\"\r\nContent-Type: {inbound.DocumentContentType}\r\n\r\n");
        output.Write(inbound.Document.Span);
        WriteAscii(output, $"\r\n--{boundary}--\r\n");
        return output.ToArray();
    }

    private static void WriteAscii(Stream stream, string value) => stream.Write(Encoding.ASCII.GetBytes(value));
}

/// <summary>RFC7807 and success response mapper retaining technical allowlisted metadata only.</summary>
public static class Fse2ResponseMapper
{
    public static Fse2Response Map(QualifiedGatewayExecutionResult response, Guid correlationId, Fse2OperationDescriptor operation)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (!operation.SuccessStatusCodes.Contains(response.StatusCode)) throw MapProblem(response, operation.RetryClass);
        try
        {
            using JsonDocument document = JsonDocument.Parse(response.Body, new JsonDocumentOptions { MaxDepth = 16 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new JsonException();
            return new(response.StatusCode, correlationId, Safe(root, "workflowInstanceId", 512, workflow: true),
                Safe(root, "traceID", 128), Safe(root, "spanID", 128), Safe(root, "warning", 96), operation.RetryClass);
        }
        catch (Fse2ConnectorException) { throw; }
        catch (Exception) { throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID"); }
    }

    public static Fse2ConnectorException MapProblem(QualifiedGatewayExecutionResult response, Fse2RetryClass retryClass)
    {
        string safeCode = "FSE2_UPSTREAM_REJECTED";
        if (response.ContentType.StartsWith("application/problem+json", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                using JsonDocument document = JsonDocument.Parse(response.Body, new JsonDocumentOptions { MaxDepth = 12 });
                JsonElement root = document.RootElement;
                string? candidate = SafeProblemValue(root, "type") ?? SafeProblemValue(root, "code");
                if (candidate is not null)
                {
                    int slash = candidate.LastIndexOf('/');
                    candidate = slash >= 0 ? candidate[(slash + 1)..] : candidate;
                    if (Fse2Validation.IsSafeCode(candidate)) safeCode = candidate;
                }
            }
            catch (Exception) { safeCode = "FSE2_UPSTREAM_REJECTED"; }
        }
        bool retryable = retryClass == Fse2RetryClass.SafeRetry && response.StatusCode is 429 or 502 or 503 or 504;
        Fse2ErrorCategory category = response.StatusCode is 429 or >= 500
            ? Fse2ErrorCategory.TemporarilyUnavailable
            : Fse2ErrorCategory.UpstreamRejected;
        return new(category, safeCode, retryable);
    }

    private static string? SafeProblemValue(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String) throw new JsonException();
        string text = value.GetString()!;
        if (string.IsNullOrWhiteSpace(text) || text.Length > 512 || text != text.Trim() || text.Any(char.IsControl)) throw new JsonException();
        return text;
    }

    private static string? Safe(JsonElement root, string name, int maximumLength, bool workflow = false)
    {
        if (!root.TryGetProperty(name, out JsonElement value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String)
            throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
        string text = value.GetString()!;
        if (string.IsNullOrWhiteSpace(text) || text.Length > maximumLength || text.Any(char.IsControl))
            throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
        if (!workflow && name != "warning" && !text.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'))
            throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
        if (name == "warning" && !Fse2Validation.IsSafeCode(text))
            throw new Fse2ConnectorException(Fse2ErrorCategory.ResponseInvalid, "FSE2_RESPONSE_INVALID");
        return text;
    }
}

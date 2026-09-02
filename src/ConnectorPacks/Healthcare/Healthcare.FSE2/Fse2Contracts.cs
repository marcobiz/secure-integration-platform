using System.Text.Json;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

/// <summary>Explicit FSE2 outbound operations frozen from the official Gateway profile.</summary>
public enum Fse2Operation
{
    ValidateCda,
    ValidateFhir,
    Create,
    Replace,
    Delete,
    UpdateMetadata,
    UpdateMetadataChainConcealment,
    ValidateAndCreate,
    ValidateAndReplace,
    GetStatusByWorkflow,
    GetStatusByTrace
}

/// <summary>Official deployment availability; test-only operations are never promoted to production.</summary>
public enum Fse2OperationAvailability
{
    ProductionAvailable,
    TestOnlyOfficial,
    NotAvailable
}

/// <summary>Retry classification fixed by operation semantics.</summary>
public enum Fse2RetryClass
{
    SafeRetry,
    ConditionalRetry,
    NoAutomaticRetry
}

/// <summary>Server-owned target environment classification.</summary>
public enum Fse2EnvironmentClass
{
    Synthetic,
    OfficialTest,
    Production
}

/// <summary>Official FSE action claim values used by the supported organization profile.</summary>
public enum Fse2Action
{
    Create,
    Update,
    Delete
}

/// <summary>Official FSE purpose-of-use values used by the frozen operation profile.</summary>
public enum Fse2PurposeOfUse
{
    Treatment,
    Update,
    AccessUpdate
}

/// <summary>Authority classification for every emitted FSE2 claim.</summary>
public enum Fse2ClaimAuthority
{
    ServerOwned,
    TrustedRuntime,
    BusinessAllowlisted,
    Derived
}

/// <summary>Sanitized connector failure categories.</summary>
public enum Fse2ErrorCategory
{
    PolicyDenied,
    InputDenied,
    AuthenticationDenied,
    DestinationDenied,
    UpstreamRejected,
    TemporarilyUnavailable,
    ResponseInvalid
}

/// <summary>Metadata-safe FSE2 failure. It never retains provider text, JWTs or clinical bodies.</summary>
public sealed class Fse2ConnectorException : Exception
{
    public Fse2ConnectorException(Fse2ErrorCategory category, string safeCode, bool retryable = false, string? safeUpstreamCode = null)
        : base(safeCode)
    {
        if (!Fse2Validation.IsSafeCode(safeCode)) throw new ArgumentException("FSE2_SAFE_CODE_INVALID", nameof(safeCode));
        if (safeUpstreamCode is not null && !Fse2Validation.IsSafeCode(safeUpstreamCode))
            throw new ArgumentException("FSE2_SAFE_UPSTREAM_CODE_INVALID", nameof(safeUpstreamCode));
        Category = category;
        SafeCode = safeCode;
        Retryable = retryable;
        SafeUpstreamCode = safeUpstreamCode;
    }

    public Fse2ErrorCategory Category { get; }
    public string SafeCode { get; }
    public bool Retryable { get; }
    public string? SafeUpstreamCode { get; }
}

/// <summary>Validated business/clinical claims that never establish the authenticated actor.</summary>
public sealed class Fse2ClinicalClaims
{
    private Fse2ClinicalClaims(string personId, bool patientConsent, string? resourceHl7Type)
    {
        PersonId = personId;
        PatientConsent = patientConsent;
        ResourceHl7Type = resourceHl7Type;
    }

    public string PersonId { get; }
    public bool PatientConsent { get; }
    public string? ResourceHl7Type { get; }

    public static Fse2ClinicalClaims CreatePerson(
        string taxIdentifier,
        string assigningAuthorityOid,
        bool patientConsent,
        string? resourceHl7Type = null) =>
        new(Fse2IheFormatter.FormatPersonCx(taxIdentifier, assigningAuthorityOid), patientConsent,
            resourceHl7Type is null ? null : Fse2Validation.ValidateResourceHl7Type(resourceHl7Type));

    public static Fse2ClinicalClaims CreateCanonicalPerson(
        string canonicalPersonCx,
        bool patientConsent,
        string? resourceHl7Type = null)
    {
        Fse2IheFormatter.ValidateCx(canonicalPersonCx, organization: false);
        return new(canonicalPersonCx, patientConsent,
            resourceHl7Type is null ? null : Fse2Validation.ValidateResourceHl7Type(resourceHl7Type));
    }
}

/// <summary>
/// Immutable caller-visible request. Static factories expose only frozen operations and contain no endpoint,
/// actor subject, role, purpose, algorithm, certificate, x5c or temporal selectors.
/// </summary>
public sealed class Fse2Request
{
    private const int MaximumDocumentInputBytes = 128 * 1024 * 1024;
    private const int MaximumJsonInputBytes = 1024 * 1024;
    private readonly byte[] document;
    private readonly byte[] requestBody;

    private Fse2Request(
        Fse2Operation operation,
        ReadOnlyMemory<byte> document,
        ReadOnlyMemory<byte> requestBody,
        string? documentContentType,
        string? resourceIdentifier,
        Fse2ClinicalClaims? clinicalClaims)
    {
        Operation = operation;
        if (document.Length > MaximumDocumentInputBytes || requestBody.Length > MaximumJsonInputBytes)
            throw new ArgumentException("FSE2_PAYLOAD_TOO_LARGE");
        this.document = document.ToArray();
        this.requestBody = requestBody.ToArray();
        DocumentContentType = documentContentType;
        ResourceIdentifier = resourceIdentifier;
        ClinicalClaims = clinicalClaims;
    }

    public Fse2Operation Operation { get; }
    public ReadOnlyMemory<byte> Document => document.ToArray();
    public ReadOnlyMemory<byte> RequestBody => requestBody.ToArray();
    public string? DocumentContentType { get; }
    public string? ResourceIdentifier { get; }
    public Fse2ClinicalClaims? ClinicalClaims { get; }

    /// <summary>
    /// Creates the connector-specific BGW1 payload. It contains business input only and exposes no
    /// endpoint, actor, issuer, audience, signing slot, certificate or provider selector.
    /// </summary>
    public byte[] SerializeAuthorizedPayload()
    {
        using MemoryStream output = new();
        using (Utf8JsonWriter writer = new(output))
        {
            writer.WriteStartObject();
            writer.WriteString("personId", ClinicalClaims?.PersonId);
            writer.WriteBoolean("patientConsent", ClinicalClaims?.PatientConsent ?? false);
            if (ClinicalClaims?.ResourceHl7Type is not null)
                writer.WriteString("resourceHl7Type", ClinicalClaims.ResourceHl7Type);
            if (document.Length > 0)
                writer.WriteBase64String("documentBase64", document);
            if (requestBody.Length > 0)
                writer.WriteBase64String("requestBodyBase64", requestBody);
            if (DocumentContentType is not null)
                writer.WriteString("documentContentType", DocumentContentType);
            if (ResourceIdentifier is not null)
                writer.WriteString("resourceIdentifier", ResourceIdentifier);
            writer.WriteEndObject();
        }
        return output.ToArray();
    }

    public static Fse2Request ValidateCda(ReadOnlyMemory<byte> document, ReadOnlyMemory<byte> requestBody, Fse2ClinicalClaims claims) =>
        DocumentRequest(Fse2Operation.ValidateCda, document, requestBody, "application/pdf", null, claims);

    public static Fse2Request ValidateFhir(ReadOnlyMemory<byte> document, ReadOnlyMemory<byte> requestBody, string contentType, Fse2ClinicalClaims claims) =>
        DocumentRequest(Fse2Operation.ValidateFhir, document, requestBody, contentType, null, claims);

    public static Fse2Request Create(ReadOnlyMemory<byte> document, ReadOnlyMemory<byte> requestBody, Fse2ClinicalClaims claims) =>
        DocumentRequest(Fse2Operation.Create, document, requestBody, "application/pdf", null, claims);

    public static Fse2Request Replace(string documentId, ReadOnlyMemory<byte> document, ReadOnlyMemory<byte> requestBody, Fse2ClinicalClaims claims) =>
        DocumentRequest(Fse2Operation.Replace, document, requestBody, "application/pdf", Fse2Validation.ValidateDocumentId(documentId), claims);

    public static Fse2Request Delete(string documentId, Fse2ClinicalClaims claims) =>
        new(Fse2Operation.Delete, default, default, null, Fse2Validation.ValidateDocumentId(documentId), claims ?? throw new ArgumentNullException(nameof(claims)));

    public static Fse2Request UpdateMetadata(string documentId, ReadOnlyMemory<byte> requestBody, Fse2ClinicalClaims claims) =>
        JsonRequest(Fse2Operation.UpdateMetadata, documentId, requestBody, claims);

    public static Fse2Request UpdateMetadataChainConcealment(string documentId, ReadOnlyMemory<byte> requestBody, Fse2ClinicalClaims claims) =>
        JsonRequest(Fse2Operation.UpdateMetadataChainConcealment, documentId, requestBody, claims);

    public static Fse2Request ValidateAndCreate(ReadOnlyMemory<byte> document, ReadOnlyMemory<byte> requestBody, Fse2ClinicalClaims claims) =>
        DocumentRequest(Fse2Operation.ValidateAndCreate, document, requestBody, "application/pdf", null, claims);

    public static Fse2Request ValidateAndReplace(string documentId, ReadOnlyMemory<byte> document, ReadOnlyMemory<byte> requestBody, Fse2ClinicalClaims claims) =>
        DocumentRequest(Fse2Operation.ValidateAndReplace, document, requestBody, "application/pdf", Fse2Validation.ValidateDocumentId(documentId), claims);

    public static Fse2Request GetStatusByWorkflow(string workflowInstanceId, Fse2ClinicalClaims claims) =>
        new(Fse2Operation.GetStatusByWorkflow, default, default, null, Fse2Validation.ValidateWorkflowId(workflowInstanceId),
            claims ?? throw new ArgumentNullException(nameof(claims)));

    public static Fse2Request GetStatusByTrace(string traceId, Fse2ClinicalClaims claims) =>
        new(Fse2Operation.GetStatusByTrace, default, default, null, Fse2Validation.ValidateTraceId(traceId),
            claims ?? throw new ArgumentNullException(nameof(claims)));

    private static Fse2Request DocumentRequest(Fse2Operation operation, ReadOnlyMemory<byte> document, ReadOnlyMemory<byte> requestBody, string contentType, string? id, Fse2ClinicalClaims claims)
    {
        ArgumentNullException.ThrowIfNull(claims);
        if (document.IsEmpty) throw new ArgumentException("FSE2_DOCUMENT_REQUIRED", nameof(document));
        Fse2Validation.ValidateJsonObject(requestBody, operation);
        if (contentType is not ("application/pdf" or "application/json")) throw new ArgumentException("FSE2_DOCUMENT_CONTENT_TYPE_DENIED", nameof(contentType));
        return new(operation, document, requestBody, contentType, id, claims);
    }

    private static Fse2Request JsonRequest(Fse2Operation operation, string documentId, ReadOnlyMemory<byte> requestBody, Fse2ClinicalClaims claims)
    {
        ArgumentNullException.ThrowIfNull(claims);
        Fse2Validation.ValidateJsonObject(requestBody);
        return new(operation, default, requestBody, null, Fse2Validation.ValidateDocumentId(documentId), claims);
    }
}

/// <summary>Technical-only normalized response.</summary>
public sealed record Fse2Response(
    int StatusCode,
    Guid CorrelationId,
    string? WorkflowInstanceId,
    string? TraceId,
    string? SpanId,
    string? SafeWarning,
    Fse2RetryClass RetryClass);

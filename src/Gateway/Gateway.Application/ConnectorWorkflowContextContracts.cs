using System.Text;

namespace SecureIntegration.Gateway.Application;

/// <summary>Closed identifier kinds supported by the durable Connector workflow correlation bridge.</summary>
public enum ConnectorWorkflowIdentifierKind
{
    /// <summary>Resolve by exact workflow instance identifier.</summary>
    WorkflowInstanceId,
    /// <summary>Resolve by exact trace identifier.</summary>
    TraceId
}

/// <summary>
/// Provider-neutral technical context supplied by a trusted Connector runtime. It cannot carry
/// clinical payloads, arbitrary metadata, scope selectors or Published authority.
/// </summary>
public sealed class ConnectorWorkflowContextRecord
{
    /// <summary>Creates one closed technical context without any authority selector.</summary>
    public ConnectorWorkflowContextRecord(
        string originatingOperationId,
        string actionCode,
        string purposeOfUseCode,
        string operationProfileChecksumSha256,
        string? workflowInstanceId,
        string? traceId)
        : this(originatingOperationId, actionCode, purposeOfUseCode, operationProfileChecksumSha256,
            workflowInstanceId, traceId, null) { }

    /// <summary>Allows one protocol-defined successor to an exact immutable originating profile.</summary>
    public ConnectorWorkflowContextRecord(
        string originatingOperationId,
        string actionCode,
        string purposeOfUseCode,
        string operationProfileChecksumSha256,
        string? workflowInstanceId,
        string? traceId,
        ConnectorWorkflowContextPredecessor? permittedPredecessor)
    {
        OriginatingOperationId = ConnectorWorkflowContextValidation.OperationId(originatingOperationId);
        ActionCode = ConnectorWorkflowContextValidation.Code(actionCode, nameof(actionCode));
        PurposeOfUseCode = ConnectorWorkflowContextValidation.Code(purposeOfUseCode, nameof(purposeOfUseCode));
        OperationProfileChecksumSha256 = ConnectorWorkflowContextValidation.Sha256(
            operationProfileChecksumSha256,
            nameof(operationProfileChecksumSha256));
        WorkflowInstanceId = ConnectorWorkflowContextValidation.OptionalWorkflowIdentifier(workflowInstanceId);
        TraceId = ConnectorWorkflowContextValidation.OptionalTraceIdentifier(traceId);
        if (WorkflowInstanceId is null && TraceId is null)
            throw new ArgumentException("At least one workflow correlation identifier is required.");
        if (permittedPredecessor is not null && (WorkflowInstanceId is null || TraceId is null ||
            permittedPredecessor.OriginatingOperationId == OriginatingOperationId))
            throw new ArgumentException("A workflow successor requires distinct operations and both identifiers.");
        PermittedPredecessor = permittedPredecessor;
    }

    /// <summary>Exact operation identifier that originated the workflow.</summary>
    public string OriginatingOperationId { get; }
    /// <summary>Bounded protocol action code.</summary>
    public string ActionCode { get; }
    /// <summary>Bounded purpose-of-use code.</summary>
    public string PurposeOfUseCode { get; }
    /// <summary>SHA-256 of the originating operation profile.</summary>
    public string OperationProfileChecksumSha256 { get; }
    /// <summary>Optional exact workflow instance identifier.</summary>
    public string? WorkflowInstanceId { get; }
    /// <summary>Optional exact trace identifier.</summary>
    public string? TraceId { get; }
    /// <summary>Protocol permission supplied by the trusted runtime, never by invocation input.</summary>
    public ConnectorWorkflowContextPredecessor? PermittedPredecessor { get; }
}

/// <summary>Closed originating profile permitted by the current authorized protocol operation.</summary>
public sealed class ConnectorWorkflowContextPredecessor
{
    /// <summary>Creates an exact protocol precondition without scope or caller-selected trace authority.</summary>
    public ConnectorWorkflowContextPredecessor(string originatingOperationId, string actionCode,
        string purposeOfUseCode, string operationProfileChecksumSha256)
    {
        OriginatingOperationId = ConnectorWorkflowContextValidation.OperationId(originatingOperationId);
        ActionCode = ConnectorWorkflowContextValidation.Code(actionCode, nameof(actionCode));
        PurposeOfUseCode = ConnectorWorkflowContextValidation.Code(purposeOfUseCode, nameof(purposeOfUseCode));
        OperationProfileChecksumSha256 = ConnectorWorkflowContextValidation.Sha256(
            operationProfileChecksumSha256, nameof(operationProfileChecksumSha256));
    }

    /// <summary>Exact originating operation allowed by the protocol.</summary>
    public string OriginatingOperationId { get; }
    /// <summary>Exact originating action.</summary>
    public string ActionCode { get; }
    /// <summary>Exact originating purpose of use.</summary>
    public string PurposeOfUseCode { get; }
    /// <summary>Exact originating Published operation-profile checksum.</summary>
    public string OperationProfileChecksumSha256 { get; }
}

/// <summary>One bounded exact workflow or trace lookup. Authority is always derived by Core.</summary>
public sealed class ConnectorWorkflowContextLookup
{
    /// <summary>Creates one exact bounded lookup without any authority selector.</summary>
    public ConnectorWorkflowContextLookup(ConnectorWorkflowIdentifierKind kind, string identifier)
    {
        if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        Kind = kind;
        Identifier = kind == ConnectorWorkflowIdentifierKind.WorkflowInstanceId
            ? ConnectorWorkflowContextValidation.WorkflowIdentifier(identifier)
            : ConnectorWorkflowContextValidation.TraceIdentifier(identifier);
    }

    /// <summary>Closed identifier kind.</summary>
    public ConnectorWorkflowIdentifierKind Kind { get; }
    /// <summary>Exact bounded identifier.</summary>
    public string Identifier { get; }
}

/// <summary>Core-owned read-back of one exact technical workflow context.</summary>
public sealed class AuthorizedConnectorWorkflowContext
{
    internal AuthorizedConnectorWorkflowContext(
        string originatingOperationId,
        string actionCode,
        string purposeOfUseCode,
        string operationProfileChecksumSha256,
        string? workflowInstanceId,
        string? traceId,
        DateTimeOffset recordedAtUtc)
    {
        OriginatingOperationId = ConnectorWorkflowContextValidation.OperationId(originatingOperationId);
        ActionCode = ConnectorWorkflowContextValidation.Code(actionCode, nameof(actionCode));
        PurposeOfUseCode = ConnectorWorkflowContextValidation.Code(purposeOfUseCode, nameof(purposeOfUseCode));
        OperationProfileChecksumSha256 = ConnectorWorkflowContextValidation.Sha256(
            operationProfileChecksumSha256,
            nameof(operationProfileChecksumSha256));
        WorkflowInstanceId = ConnectorWorkflowContextValidation.OptionalWorkflowIdentifier(workflowInstanceId);
        TraceId = ConnectorWorkflowContextValidation.OptionalTraceIdentifier(traceId);
        if (WorkflowInstanceId is null && TraceId is null || recordedAtUtc == default)
            throw new InvalidOperationException("Persisted Connector workflow context is invalid.");
        RecordedAtUtc = recordedAtUtc.ToUniversalTime();
    }

    /// <summary>Exact operation identifier that originated the workflow.</summary>
    public string OriginatingOperationId { get; }
    /// <summary>Bounded protocol action code.</summary>
    public string ActionCode { get; }
    /// <summary>Bounded purpose-of-use code.</summary>
    public string PurposeOfUseCode { get; }
    /// <summary>SHA-256 of the originating operation profile.</summary>
    public string OperationProfileChecksumSha256 { get; }
    /// <summary>Optional exact workflow instance identifier.</summary>
    public string? WorkflowInstanceId { get; }
    /// <summary>Optional exact trace identifier.</summary>
    public string? TraceId { get; }
    /// <summary>Server-owned technical insertion timestamp.</summary>
    public DateTimeOffset RecordedAtUtc { get; }
}

internal sealed record ConnectorWorkflowContextAuthorityScope(
    Guid TenantId,
    Guid ApplicationId,
    Guid InstallationId,
    Guid EnvironmentId,
    string ConnectorId,
    string ConnectorVersion,
    byte[] PublishedContextSha256);

internal sealed record ConnectorWorkflowContextStorageRecord(
    ConnectorWorkflowContextAuthorityScope Authority,
    ConnectorWorkflowContextRecord Context,
    DateTimeOffset RecordedAtUtc);

internal enum ConnectorWorkflowContextRecordResult
{
    Created,
    Unchanged,
    Conflict
}

internal interface IConnectorWorkflowContextStore
{
    Task<ConnectorWorkflowContextRecordResult> RecordAsync(
        ConnectorWorkflowContextStorageRecord record,
        CancellationToken cancellationToken);

    Task<AuthorizedConnectorWorkflowContext?> ResolveAsync(
        ConnectorWorkflowContextAuthorityScope authority,
        ConnectorWorkflowContextLookup lookup,
        CancellationToken cancellationToken);
}

internal static class ConnectorWorkflowContextValidation
{
    internal const int MaximumOperationIdLength = 100;
    internal const int MaximumCodeLength = 64;
    internal const int MaximumWorkflowIdentifierLength = 256;
    internal const int MaximumTraceIdentifierLength = 100;

    internal static string OperationId(string value)
    {
        if (!ConnectorExecutionIdentifier.IsValid(value, MaximumOperationIdLength))
            throw new ArgumentException("Connector workflow operation identifier is invalid.", nameof(value));
        return value;
    }

    internal static string Code(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > MaximumCodeLength || value != value.Trim() || value[0] is < 'A' or > 'Z' ||
            value.Any(character => character is not (>= 'A' and <= 'Z') &&
                character is not (>= '0' and <= '9') && character is not (' ' or '_' or '-')))
            throw new ArgumentException("Connector workflow code is invalid.", parameterName);
        return value;
    }

    internal static string Sha256(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
            throw new ArgumentException("Connector workflow checksum is invalid.", parameterName);
        return value.ToLowerInvariant();
    }

    internal static string? OptionalWorkflowIdentifier(string? value) =>
        value is null ? null : WorkflowIdentifier(value);

    internal static string WorkflowIdentifier(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > MaximumWorkflowIdentifierLength || value != value.Trim() ||
            value.Normalize(NormalizationForm.FormC) != value ||
            value.Any(character => char.IsControl(character) || character is '/' or '?' or '#' or '\\'))
            throw new ArgumentException("Connector workflow identifier is invalid.", nameof(value));
        return value;
    }

    internal static string? OptionalTraceIdentifier(string? value) =>
        value is null ? null : TraceIdentifier(value);

    internal static string TraceIdentifier(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > MaximumTraceIdentifierLength || !char.IsAsciiLetterOrDigit(value[0]) ||
            value.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('-' or '_' or '.')))
            throw new ArgumentException("Connector trace identifier is invalid.", nameof(value));
        return value;
    }
}

using System.Text.Json.Serialization;
using System.Net.Http.Headers;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;

/// <summary>Closed formatting choices for an opaque session HTTP header.</summary>
public enum OpaqueSessionHttpHeaderValueFormat
{
    /// <summary>Place only the opaque upstream value.</summary>
    RawOpaqueValue,
    /// <summary>Place one fixed server-owned token followed by the opaque upstream value.</summary>
    FixedSchemeAndOpaqueValue
}

/// <summary>Only selector a caller may supply to the server-owned authority resolver.</summary>
public sealed class OpaqueSessionHttpAuthorityRequest
{
    /// <summary>Selects a logical policy in the already-authorized Published operation.</summary>
    public OpaqueSessionHttpAuthorityRequest(string policyId)
    {
        if (!OpaqueSessionHttpValidation.Identifier(policyId)) throw OpaqueSessionHttpFailures.Configuration();
        PolicyId = policyId;
    }

    /// <summary>Logical policy identifier; it cannot override any resolved policy field.</summary>
    public string PolicyId { get; }

    /// <inheritdoc />
    public override string ToString() => $"OpaqueSessionHttpAuthorityRequest(PolicyId={PolicyId})";
}

/// <summary>Unforgeable handoff created by the authenticated and authorized Gateway runtime.</summary>
public sealed class OpaqueSessionAuthorizedInvocation
{
    internal OpaqueSessionAuthorizedInvocation(GatewayClientPrincipal principal, string connectorId, string operationId)
    {
        ArgumentNullException.ThrowIfNull(principal);
        if (!OpaqueSessionHttpValidation.Identifier(connectorId) || !OpaqueSessionHttpValidation.Identifier(operationId))
            throw OpaqueSessionHttpFailures.Configuration();
        Principal = principal;
        ConnectorId = connectorId;
        OperationId = operationId;
    }

    [JsonIgnore] internal GatewayClientPrincipal Principal { get; }
    /// <summary>Connector authorized by the shared runtime.</summary>
    public string ConnectorId { get; }
    /// <summary>Operation authorized by the shared runtime.</summary>
    public string OperationId { get; }
    /// <summary>Authenticated correlation identifier.</summary>
    public Guid CorrelationId => Principal.CorrelationId;

    /// <inheritdoc />
    public override string ToString() => $"OpaqueSessionAuthorizedInvocation(ConnectorId={ConnectorId}, OperationId={OperationId}, CorrelationId={CorrelationId:D})";
}

/// <summary>Opaque handle to a Gateway-owned upstream session lifecycle.</summary>
public sealed class OpaqueSessionReference
{
    internal OpaqueSessionReference(string value) => Value = value;
    [JsonIgnore] internal string Value { get; }
    /// <inheritdoc />
    public override string ToString() => "OpaqueSessionReference(Redacted)";
}

/// <summary>
/// Non-forgeable immutable authority resolved from authenticated identity and a current Published snapshot.
/// Endpoint, method, placement, revisions and environment are deliberately not public or serializable.
/// </summary>
public sealed class OpaqueSessionResolvedExecutionContext
{
    internal OpaqueSessionResolvedExecutionContext(OpaqueSessionHttpAuthorityState state, Func<CancellationToken, Task<OpaqueSessionHttpAuthorityState>> revalidate)
    {
        State = state;
        Revalidate = revalidate;
    }

    /// <summary>Resolved Published Connector identifier.</summary>
    public string ConnectorId => State.ConnectorId;
    /// <summary>Resolved operation identifier.</summary>
    public string OperationId => State.OperationId;
    /// <summary>Resolved logical projection policy identifier.</summary>
    public string PolicyId => State.PolicyId;
    /// <summary>Authenticated correlation identifier.</summary>
    public Guid CorrelationId => State.CorrelationId;

    [JsonIgnore] internal OpaqueSessionHttpAuthorityState State { get; }
    [JsonIgnore] internal Func<CancellationToken, Task<OpaqueSessionHttpAuthorityState>> Revalidate { get; }

    /// <inheritdoc />
    public override string ToString() => $"OpaqueSessionResolvedExecutionContext(ConnectorId={ConnectorId}, OperationId={OperationId}, PolicyId={PolicyId}, CorrelationId={CorrelationId:D})";
}

/// <summary>Bounded sanitized response from one authenticated HTTP dispatch.</summary>
public sealed record OpaqueSessionHttpResponse(int StatusCode, string ContentType, byte[] Body);

/// <summary>Stable generic opaque-session projection failure; it never carries provider or session material.</summary>
public sealed class OpaqueSessionAuthException : Exception
{
    internal OpaqueSessionAuthException(string code) : base(code) => Code = code;
    /// <summary>Stable non-sensitive failure code.</summary>
    public string Code { get; }
}

/// <summary>
/// Controlled bridge from an opaque-session lifecycle into the generic HTTP projection module.
/// The security-sensitive lease operation is internal, so caller code cannot implement a value oracle.
/// </summary>
public abstract class OpaqueSessionLeaseProvider
{
    internal abstract OpaqueSessionDispatchLease AcquireFinalLease(OpaqueSessionReference reference, OpaqueSessionLifecycleBinding binding, DateTimeOffset now);
}

internal sealed record OpaqueSessionLifecycleBinding(
    Guid TenantId,
    Guid InstallationId,
    Guid ApplicationId,
    Guid EnvironmentId,
    string ConnectorId,
    string ConnectorVersion,
    long BindingRevision,
    long EndpointRevision,
    long CredentialRevision,
    string ProfileId);

internal sealed class OpaqueSessionDispatchLease(string upstreamValue, DateTimeOffset expiresAt, Action<DateTimeOffset> ensureCurrent)
{
    internal string UpstreamValue { get; } = upstreamValue;
    internal DateTimeOffset ExpiresAt { get; } = expiresAt;
    internal void EnsureCurrent(DateTimeOffset now) => ensureCurrent(now);
    public override string ToString() => $"OpaqueSessionDispatchLease(ExpiresAt={ExpiresAt:O}, Redacted=True)";
}

internal sealed class OpaqueSessionHttpAuthorityState
{
    internal OpaqueSessionHttpAuthorityState(
        Guid tenantId,
        Guid installationId,
        Guid applicationId,
        Guid environmentId,
        Guid connectorVersionId,
        string connectorId,
        string connectorVersion,
        string operationId,
        string policyId,
        string profileId,
        Uri endpoint,
        HttpMethod method,
        string? contentType,
        long bindingRevision,
        long endpointRevision,
        long credentialRevision,
        string resourceStamp,
        string headerName,
        OpaqueSessionHttpHeaderValueFormat valueFormat,
        string? fixedScheme,
        TimeSpan timeout,
        long maximumRequestBytes,
        long maximumResponseBytes,
        Guid correlationId,
        DateTimeOffset deadline,
        string securityFingerprint)
    {
        TenantId = tenantId;
        InstallationId = installationId;
        ApplicationId = applicationId;
        EnvironmentId = environmentId;
        ConnectorVersionId = connectorVersionId;
        ConnectorId = connectorId;
        ConnectorVersion = connectorVersion;
        OperationId = operationId;
        PolicyId = policyId;
        ProfileId = profileId;
        Endpoint = endpoint;
        Method = method;
        ContentType = contentType;
        BindingRevision = bindingRevision;
        EndpointRevision = endpointRevision;
        CredentialRevision = credentialRevision;
        ResourceStamp = resourceStamp;
        Placement = new(headerName, valueFormat, fixedScheme);
        Timeout = timeout;
        MaximumRequestBytes = maximumRequestBytes;
        MaximumResponseBytes = maximumResponseBytes;
        CorrelationId = correlationId;
        Deadline = deadline;
        SecurityFingerprint = securityFingerprint;
        Validate();
    }

    internal Guid TenantId { get; }
    internal Guid InstallationId { get; }
    internal Guid ApplicationId { get; }
    internal Guid EnvironmentId { get; }
    internal Guid ConnectorVersionId { get; }
    internal string ConnectorId { get; }
    internal string ConnectorVersion { get; }
    internal string OperationId { get; }
    internal string PolicyId { get; }
    internal string ProfileId { get; }
    internal Uri Endpoint { get; }
    internal HttpMethod Method { get; }
    internal string? ContentType { get; }
    internal long BindingRevision { get; }
    internal long EndpointRevision { get; }
    internal long CredentialRevision { get; }
    internal string ResourceStamp { get; }
    internal HttpRequestHeaderOpaqueSessionPlacement Placement { get; }
    internal TimeSpan Timeout { get; }
    internal long MaximumRequestBytes { get; }
    internal long MaximumResponseBytes { get; }
    internal Guid CorrelationId { get; }
    internal DateTimeOffset Deadline { get; }
    internal string SecurityFingerprint { get; }

    internal OpaqueSessionLifecycleBinding LifecycleBinding => new(TenantId, InstallationId, ApplicationId, EnvironmentId, ConnectorId, ConnectorVersion,
        BindingRevision, EndpointRevision, CredentialRevision, ProfileId);

    private void Validate()
    {
        if (TenantId == Guid.Empty || InstallationId == Guid.Empty || ApplicationId == Guid.Empty || EnvironmentId == Guid.Empty || ConnectorVersionId == Guid.Empty || CorrelationId == Guid.Empty ||
            !OpaqueSessionHttpValidation.Identifier(ConnectorId) || !OpaqueSessionHttpValidation.Identifier(ConnectorVersion) || !OpaqueSessionHttpValidation.Identifier(OperationId) ||
            !OpaqueSessionHttpValidation.Identifier(PolicyId) || !OpaqueSessionHttpValidation.Identifier(ProfileId) || !OpaqueSessionHttpValidation.HttpsEndpoint(Endpoint) ||
            BindingRevision < 1 || EndpointRevision < 1 || CredentialRevision < 1 || string.IsNullOrWhiteSpace(ResourceStamp) || ResourceStamp.Length > 256 || ResourceStamp.Any(char.IsControl) ||
            Timeout < TimeSpan.FromMilliseconds(100) || Timeout > TimeSpan.FromMinutes(2) || MaximumRequestBytes is < 1 or > 16 * 1024 * 1024 || MaximumResponseBytes is < 1 or > 16 * 1024 * 1024 ||
            (Method != HttpMethod.Get && (string.IsNullOrWhiteSpace(ContentType) || !MediaTypeHeaderValue.TryParse(ContentType, out _))) || (Method == HttpMethod.Get && ContentType is not null) ||
            Deadline == default || string.IsNullOrWhiteSpace(SecurityFingerprint))
            throw OpaqueSessionHttpFailures.Configuration();
    }
}

internal sealed class HttpRequestHeaderOpaqueSessionPlacement
{
    private static readonly HashSet<string> Forbidden = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "Host", "Content-Length", "Transfer-Encoding", "Connection", "Cookie", "Set-Cookie",
        "Proxy-Authorization", "Proxy-Authenticate", "Forwarded", "Via", "Expect", "Upgrade", "TE", "Trailer",
        "X-Correlation-ID", "traceparent", "tracestate", "baggage"
    };

    internal HttpRequestHeaderOpaqueSessionPlacement(string headerName, OpaqueSessionHttpHeaderValueFormat valueFormat, string? fixedScheme)
    {
        if (!OpaqueSessionHttpValidation.HttpToken(headerName) || headerName.Length > 100 || Forbidden.Contains(headerName) ||
            headerName.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase) || headerName.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase))
            throw OpaqueSessionHttpFailures.HeaderForbidden();
        if (valueFormat == OpaqueSessionHttpHeaderValueFormat.RawOpaqueValue && fixedScheme is not null)
            throw OpaqueSessionHttpFailures.Configuration();
        if (valueFormat == OpaqueSessionHttpHeaderValueFormat.FixedSchemeAndOpaqueValue && (!OpaqueSessionHttpValidation.HttpToken(fixedScheme) || fixedScheme!.Length > 32))
            throw OpaqueSessionHttpFailures.Configuration();
        HeaderName = headerName;
        ValueFormat = valueFormat;
        FixedScheme = fixedScheme;
    }

    internal string HeaderName { get; }
    internal OpaqueSessionHttpHeaderValueFormat ValueFormat { get; }
    internal string? FixedScheme { get; }

    internal string Format(string opaqueValue)
    {
        if (string.IsNullOrEmpty(opaqueValue) || opaqueValue.Length > 16_384 || opaqueValue.Any(character => character is '\r' or '\n' or '\0' || char.IsControl(character)))
            throw OpaqueSessionHttpFailures.SessionInvalid();
        return ValueFormat == OpaqueSessionHttpHeaderValueFormat.RawOpaqueValue ? opaqueValue : FixedScheme + " " + opaqueValue;
    }

    public override string ToString() => $"HttpRequestHeaderOpaqueSessionPlacement(HeaderName={HeaderName}, ValueFormat={ValueFormat})";
}

internal static class OpaqueSessionHttpValidation
{
    internal static bool Identifier(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 100 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    internal static bool HttpsEndpoint(Uri value) => value.IsAbsoluteUri && value.Scheme == Uri.UriSchemeHttps && string.IsNullOrEmpty(value.UserInfo) && string.IsNullOrEmpty(value.Fragment);
    internal static bool HttpToken(string? value) => !string.IsNullOrEmpty(value) && value.All(character =>
        char.IsAsciiLetterOrDigit(character) || character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~');
}

internal static class OpaqueSessionHttpFailures
{
    internal static OpaqueSessionAuthException Configuration() => new("SESSION-HTTP-CONFIGURATION-INVALID");
    internal static OpaqueSessionAuthException Rejected() => new("SESSION-HTTP-AUTHORITY-REJECTED");
    internal static OpaqueSessionAuthException Stale() => new("SESSION-HTTP-AUTHORITY-STALE");
    internal static OpaqueSessionAuthException HeaderForbidden() => new("SESSION-HTTP-HEADER-FORBIDDEN");
    internal static OpaqueSessionAuthException SessionInvalid() => new("SESSION-HTTP-SESSION-INVALID");
    internal static OpaqueSessionAuthException SessionStale() => new("SESSION-HTTP-SESSION-STALE");
    internal static OpaqueSessionAuthException RequestInvalid() => new("SESSION-HTTP-REQUEST-INVALID");
    internal static OpaqueSessionAuthException DestinationDenied() => new("SESSION-HTTP-EGRESS-DESTINATION-DENIED");
    internal static OpaqueSessionAuthException DeadlineExpired() => new("SESSION-HTTP-DEADLINE-EXPIRED");
    internal static OpaqueSessionAuthException Timeout() => new("SESSION-HTTP-TIMEOUT");
    internal static OpaqueSessionAuthException Transport() => new("SESSION-HTTP-TRANSPORT-FAILED");
}

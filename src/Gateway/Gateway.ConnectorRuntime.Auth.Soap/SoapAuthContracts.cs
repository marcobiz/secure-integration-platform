using System.Collections.ObjectModel;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>SOAP envelope versions supported by the bounded connector runtime.</summary>
public enum SoapEnvelopeVersion
{
    /// <summary>SOAP 1.1.</summary>
    Soap11,
    /// <summary>SOAP 1.2.</summary>
    Soap12
}

/// <summary>Sanitized SOAP fault categories understood by session profiles.</summary>
public enum SoapFaultCategory
{
    /// <summary>An upstream business fault unrelated to authentication.</summary>
    Business,
    /// <summary>The upstream session expired.</summary>
    SessionExpired,
    /// <summary>The upstream session was rejected or invalidated.</summary>
    InvalidSession,
    /// <summary>An upstream authentication request was denied.</summary>
    AuthenticationDenied,
    /// <summary>The fault was structurally valid but not recognized by the compiled profile.</summary>
    Unknown
}

/// <summary>
/// Immutable server-derived scope for one outbound connector authentication flow.
/// No value in this context is accepted from a runtime payload.
/// </summary>
public sealed record ConnectorAuthExecutionContext(
    Guid TenantId,
    Guid InstallationId,
    Guid ApplicationId,
    Guid EnvironmentId,
    string ConnectorId,
    string ConnectorVersion,
    string OperationId,
    long EndpointRevision,
    long CredentialRevision,
    string SessionProfileId,
    Guid CorrelationId,
    DateTimeOffset Deadline);

/// <summary>Resolved server-side Basic binding. Provider references are deliberately excluded from <see cref="ToString"/>.</summary>
public sealed class ResolvedBasicCredentialBinding
{
    /// <summary>Creates an exact pair of provider references resolved from a Published binding.</summary>
    public ResolvedBasicCredentialBinding(string usernameProviderReference, string passwordProviderReference)
    {
        UsernameProviderReference = RequireReference(usernameProviderReference);
        PasswordProviderReference = RequireReference(passwordProviderReference);
    }

    /// <summary>Provider reference for the username. Runtime-only and never audit metadata.</summary>
    public string UsernameProviderReference { get; }
    /// <summary>Provider reference for the password. Runtime-only and never audit metadata.</summary>
    public string PasswordProviderReference { get; }

    /// <inheritdoc />
    public override string ToString() => nameof(ResolvedBasicCredentialBinding);

    private static string RequireReference(string value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 500
            ? value
            : throw new ArgumentException("A resolved Basic credential binding is required.", nameof(value));
}

/// <summary>Server-owned HTTPS endpoint and immutable binding revision.</summary>
public sealed class SoapEndpointBinding
{
    /// <summary>Creates a validated SOAP endpoint binding.</summary>
    public SoapEndpointBinding(Uri endpoint, long revision)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(endpoint.UserInfo) || !string.IsNullOrEmpty(endpoint.Fragment))
            throw new ArgumentException("SOAP endpoints must be absolute HTTPS URIs without user information or fragments.", nameof(endpoint));
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(revision);
        Endpoint = endpoint;
        Revision = revision;
    }

    /// <summary>Approved endpoint URI.</summary>
    public Uri Endpoint { get; }
    /// <summary>Immutable endpoint binding revision.</summary>
    public long Revision { get; }
}

/// <summary>One exact XML element name used by a compiled SOAP profile.</summary>
public sealed record SoapElementRule
{
    /// <summary>Creates an exact namespace-qualified element rule.</summary>
    public SoapElementRule(string localName, string namespaceUri)
    {
        if (!IsXmlName(localName)) throw new ArgumentException("Invalid SOAP element local name.", nameof(localName));
        if (!Uri.TryCreate(namespaceUri, UriKind.Absolute, out _)) throw new ArgumentException("SOAP element namespaces must be absolute URIs.", nameof(namespaceUri));
        LocalName = localName;
        NamespaceUri = namespaceUri;
    }

    /// <summary>Exact local name.</summary>
    public string LocalName { get; }
    /// <summary>Exact namespace URI.</summary>
    public string NamespaceUri { get; }

    internal bool Matches(string localName, string namespaceUri) =>
        string.Equals(LocalName, localName, StringComparison.Ordinal) && string.Equals(NamespaceUri, namespaceUri, StringComparison.Ordinal);

    private static bool IsXmlName(string value) => value.Length is > 0 and <= 100 && (char.IsAsciiLetter(value[0]) || value[0] == '_') && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.');
}

/// <summary>Maps one connector-domain value to one exact SOAP child element.</summary>
public sealed record SoapFieldRule
{
    /// <summary>Creates a bounded logical-to-XML field mapping.</summary>
    public SoapFieldRule(string logicalName, SoapElementRule element, int maximumCharacters = 4096)
    {
        if (!IsIdentifier(logicalName)) throw new ArgumentException("Invalid SOAP logical field name.", nameof(logicalName));
        ArgumentNullException.ThrowIfNull(element);
        if (maximumCharacters is < 1 or > 65_536) throw new ArgumentOutOfRangeException(nameof(maximumCharacters));
        LogicalName = logicalName;
        Element = element;
        MaximumCharacters = maximumCharacters;
    }

    /// <summary>Connector-facing logical field name.</summary>
    public string LogicalName { get; }
    /// <summary>Exact XML element.</summary>
    public SoapElementRule Element { get; }
    /// <summary>Maximum decoded character count.</summary>
    public int MaximumCharacters { get; }

    private static bool IsIdentifier(string value) => value.Length is > 0 and <= 100 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
}

/// <summary>Maps one exact upstream SOAP fault code to a sanitized runtime category.</summary>
public sealed record SoapFaultRule(SoapElementRule Code, SoapFaultCategory Category);

/// <summary>Fixed, declarative mapping for one SOAP operation.</summary>
public sealed class SoapOperationProfile
{
    /// <summary>Creates a bounded compiled operation profile.</summary>
    public SoapOperationProfile(
        string operationId,
        SoapEnvelopeVersion version,
        string action,
        SoapElementRule requestElement,
        SoapElementRule responseElement,
        IEnumerable<SoapFieldRule>? requestFields = null,
        IEnumerable<SoapFieldRule>? responseFields = null,
        int timeoutMilliseconds = 30_000,
        long maximumRequestBytes = 1_048_576,
        long maximumResponseBytes = 1_048_576,
        bool retryAfterSessionReacquisition = false)
    {
        if (!IsIdentifier(operationId)) throw new ArgumentException("Invalid SOAP operation identifier.", nameof(operationId));
        if (!Uri.TryCreate(action, UriKind.Absolute, out _)) throw new ArgumentException("SOAPAction must be an absolute server-owned URI.", nameof(action));
        ArgumentNullException.ThrowIfNull(requestElement);
        ArgumentNullException.ThrowIfNull(responseElement);
        if (timeoutMilliseconds is < 100 or > 120_000) throw new ArgumentOutOfRangeException(nameof(timeoutMilliseconds));
        if (maximumRequestBytes is < 256 or > 16 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(maximumRequestBytes));
        if (maximumResponseBytes is < 256 or > 16 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(maximumResponseBytes));
        OperationId = operationId;
        Version = version;
        Action = action;
        RequestElement = requestElement;
        ResponseElement = responseElement;
        RequestFields = Index(requestFields);
        ResponseFields = Index(responseFields);
        TimeoutMilliseconds = timeoutMilliseconds;
        MaximumRequestBytes = maximumRequestBytes;
        MaximumResponseBytes = maximumResponseBytes;
        RetryAfterSessionReacquisition = retryAfterSessionReacquisition;
    }

    /// <summary>Server-owned operation identifier.</summary>
    public string OperationId { get; }
    /// <summary>SOAP envelope version.</summary>
    public SoapEnvelopeVersion Version { get; }
    /// <summary>Exact server-owned SOAP action.</summary>
    public string Action { get; }
    /// <summary>Exact request body element.</summary>
    public SoapElementRule RequestElement { get; }
    /// <summary>Exact response body element.</summary>
    public SoapElementRule ResponseElement { get; }
    /// <summary>Allowlisted request fields, in deterministic serialization order.</summary>
    public IReadOnlyDictionary<string, SoapFieldRule> RequestFields { get; }
    /// <summary>Allowlisted response fields.</summary>
    public IReadOnlyDictionary<string, SoapFieldRule> ResponseFields { get; }
    /// <summary>Per-request timeout.</summary>
    public int TimeoutMilliseconds { get; }
    /// <summary>Maximum serialized request bytes.</summary>
    public long MaximumRequestBytes { get; }
    /// <summary>Maximum response bytes.</summary>
    public long MaximumResponseBytes { get; }
    /// <summary>Whether an expired-session response may be retried once after controlled reacquisition.</summary>
    public bool RetryAfterSessionReacquisition { get; }

    private static ReadOnlyDictionary<string, SoapFieldRule> Index(IEnumerable<SoapFieldRule>? fields)
    {
        Dictionary<string, SoapFieldRule> indexed = new(StringComparer.Ordinal);
        foreach (SoapFieldRule field in fields ?? [])
        {
            if (!indexed.TryAdd(field.LogicalName, field)) throw new ArgumentException("Duplicate SOAP logical field mapping.", nameof(fields));
            if (indexed.Values.Count(value => value.Element == field.Element) > 1) throw new ArgumentException("Duplicate SOAP XML field mapping.", nameof(fields));
        }
        return new ReadOnlyDictionary<string, SoapFieldRule>(indexed);
    }

    private static bool IsIdentifier(string value) => value.Length is > 0 and <= 100 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
}

/// <summary>Declarative Basic/session lifecycle profile compiled by a connector pack.</summary>
public sealed class SoapSessionProfile
{
    /// <summary>Creates a fixed session acquisition, placement, expiry and logout profile.</summary>
    public SoapSessionProfile(
        string profileId,
        ResolvedBasicCredentialBinding basicCredential,
        SoapOperationProfile loginOperation,
        SoapElementRule sessionElement,
        SoapElementRule sessionHeaderElement,
        IEnumerable<SoapOperationProfile> businessOperations,
        TimeSpan sessionLifetime,
        IEnumerable<SoapFaultRule> faultRules,
        SoapElementRule? challengeElement = null,
        SoapOperationProfile? challengeCompletionOperation = null,
        string? challengeArtifactField = null,
        string? challengeStateField = null,
        TimeSpan? interactionLifetime = null,
        SoapOperationProfile? logoutOperation = null)
    {
        if (!IsIdentifier(profileId)) throw new ArgumentException("Invalid SOAP session profile identifier.", nameof(profileId));
        ArgumentNullException.ThrowIfNull(basicCredential);
        ArgumentNullException.ThrowIfNull(loginOperation);
        ArgumentNullException.ThrowIfNull(sessionElement);
        ArgumentNullException.ThrowIfNull(sessionHeaderElement);
        if (sessionLifetime < TimeSpan.FromMinutes(1) || sessionLifetime > TimeSpan.FromDays(7)) throw new ArgumentOutOfRangeException(nameof(sessionLifetime));
        Dictionary<string, SoapOperationProfile> operations = businessOperations?.ToDictionary(value => value.OperationId, StringComparer.Ordinal) ?? throw new ArgumentNullException(nameof(businessOperations));
        if (operations.Count == 0) throw new ArgumentException("At least one SOAP business operation is required.", nameof(businessOperations));
        Dictionary<(string LocalName, string NamespaceUri), SoapFaultCategory> faults = [];
        foreach (SoapFaultRule fault in faultRules ?? throw new ArgumentNullException(nameof(faultRules)))
            if (!faults.TryAdd((fault.Code.LocalName, fault.Code.NamespaceUri), fault.Category)) throw new ArgumentException("Duplicate SOAP fault rule.", nameof(faultRules));
        bool hasChallenge = challengeElement is not null || challengeCompletionOperation is not null || challengeArtifactField is not null || challengeStateField is not null;
        if (hasChallenge && (challengeElement is null || challengeCompletionOperation is null || string.IsNullOrWhiteSpace(challengeArtifactField) || string.IsNullOrWhiteSpace(challengeStateField)))
            throw new ArgumentException("Interactive SOAP challenge configuration must be complete.");
        TimeSpan effectiveInteractionLifetime = interactionLifetime ?? TimeSpan.FromMinutes(5);
        if (effectiveInteractionLifetime < TimeSpan.FromSeconds(30) || effectiveInteractionLifetime > TimeSpan.FromMinutes(30)) throw new ArgumentOutOfRangeException(nameof(interactionLifetime));
        if (challengeCompletionOperation is not null && (!challengeCompletionOperation.RequestFields.ContainsKey(challengeArtifactField!) || !challengeCompletionOperation.RequestFields.ContainsKey(challengeStateField!)))
            throw new ArgumentException("Challenge completion fields must be declared by the completion operation.");
        ProfileId = profileId;
        BasicCredential = basicCredential;
        LoginOperation = loginOperation;
        SessionElement = sessionElement;
        SessionHeaderElement = sessionHeaderElement;
        BusinessOperations = new ReadOnlyDictionary<string, SoapOperationProfile>(operations);
        SessionLifetime = sessionLifetime;
        FaultRules = new ReadOnlyDictionary<(string LocalName, string NamespaceUri), SoapFaultCategory>(faults);
        ChallengeElement = challengeElement;
        ChallengeCompletionOperation = challengeCompletionOperation;
        ChallengeArtifactField = challengeArtifactField;
        ChallengeStateField = challengeStateField;
        InteractionLifetime = effectiveInteractionLifetime;
        LogoutOperation = logoutOperation;
    }

    /// <summary>Profile identifier included in the session cache key.</summary>
    public string ProfileId { get; }
    /// <summary>Resolved server-owned Basic binding.</summary>
    public ResolvedBasicCredentialBinding BasicCredential { get; }
    /// <summary>Fixed login operation.</summary>
    public SoapOperationProfile LoginOperation { get; }
    /// <summary>Exact session extraction element under the login response.</summary>
    public SoapElementRule SessionElement { get; }
    /// <summary>Exact SOAP header placement element.</summary>
    public SoapElementRule SessionHeaderElement { get; }
    /// <summary>Fixed business-operation mappings.</summary>
    public IReadOnlyDictionary<string, SoapOperationProfile> BusinessOperations { get; }
    /// <summary>Maximum upstream session lifetime.</summary>
    public TimeSpan SessionLifetime { get; }
    /// <summary>Exact fault-code mappings.</summary>
    public IReadOnlyDictionary<(string LocalName, string NamespaceUri), SoapFaultCategory> FaultRules { get; }
    /// <summary>Optional exact challenge extraction element.</summary>
    public SoapElementRule? ChallengeElement { get; }
    /// <summary>Optional fixed challenge completion operation.</summary>
    public SoapOperationProfile? ChallengeCompletionOperation { get; }
    /// <summary>Logical completion-artifact field.</summary>
    public string? ChallengeArtifactField { get; }
    /// <summary>Logical stored challenge-state field.</summary>
    public string? ChallengeStateField { get; }
    /// <summary>Absolute interactive challenge lifetime.</summary>
    public TimeSpan InteractionLifetime { get; }
    /// <summary>Optional fixed logout operation.</summary>
    public SoapOperationProfile? LogoutOperation { get; }

    private static bool IsIdentifier(string value) => value.Length is > 0 and <= 100 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
}

/// <summary>Opaque reference to a Gateway-owned upstream session.</summary>
public sealed record OpaqueSoapSessionReference(string Value)
{
    /// <inheritdoc />
    public override string ToString() => nameof(OpaqueSoapSessionReference);
}

/// <summary>Transport-neutral interactive state returned when an upstream challenge must be completed.</summary>
public sealed record SoapInteractiveChallenge(string InteractionReference, string OpaqueChallenge, DateTimeOffset ExpiresAt)
{
    /// <inheritdoc />
    public override string ToString() => nameof(SoapInteractiveChallenge);
}

/// <summary>Sanitized mapped values returned by one compiled business operation.</summary>
public sealed record SoapBusinessResult(IReadOnlyDictionary<string, string> Values);

/// <summary>Stable, sanitized SOAP authentication or boundary failure.</summary>
public class SoapAuthException : Exception
{
    /// <summary>Creates a failure carrying only a stable non-sensitive code.</summary>
    public SoapAuthException(string code) : base(code) => Code = code;
    /// <summary>Stable non-sensitive failure code.</summary>
    public string Code { get; }
}

/// <summary>A sanitized upstream SOAP Fault.</summary>
public sealed class SoapFaultException : SoapAuthException
{
    /// <summary>Creates a typed fault without raw fault detail.</summary>
    public SoapFaultException(SoapFaultCategory category) : base("SOAP-FAULT-" + category.ToString().ToUpperInvariant()) => Category = category;
    /// <summary>Mapped fault category.</summary>
    public SoapFaultCategory Category { get; }
}

/// <summary>Signals that a transport-neutral interactive completion is required.</summary>
public sealed class SoapInteractionRequiredException : SoapAuthException
{
    /// <summary>Creates the control-flow exception returned to the connector runtime.</summary>
    public SoapInteractionRequiredException(SoapInteractiveChallenge challenge) : base("SOAP-INTERACTION-REQUIRED") => Challenge = challenge;
    /// <summary>Opaque challenge state; contains no upstream session.</summary>
    public SoapInteractiveChallenge Challenge { get; }
}

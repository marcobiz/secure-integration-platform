using System.Text.Json;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Application;

/// <summary>Stable application error translated to sanitized RFC 9457 output by the host.</summary>
public sealed class GatewayException : Exception
{
    /// <summary>Creates a stable Gateway failure.</summary>
    public GatewayException(string code, int statusCode, bool retryable = false)
        : base(code)
    {
        if (!BackendRuntimeWireCodes.IsPublished(RuntimeWireCodeKind.Reason, code))
            throw new InvalidOperationException($"Gateway reason code is not in the authoritative backend catalog: {code}");
        Code = code;
        StatusCode = statusCode;
        Retryable = retryable;
    }

    internal GatewayException(string code, int statusCode, bool retryable, SafeUpstreamFailureDiagnostics diagnostics)
        : this(code, statusCode, retryable) => Diagnostics = diagnostics ?? throw new ArgumentNullException(nameof(diagnostics));

    /// <summary>Stable non-secret error code.</summary>
    public string Code { get; }
    /// <summary>HTTP status associated with the failure.</summary>
    public int StatusCode { get; }
    /// <summary>Whether a caller may retry safely.</summary>
    public bool Retryable { get; }
    internal SafeUpstreamFailureDiagnostics? Diagnostics { get; }
}

/// <summary>Closed phase emitted by the qualified restricted transport without raw exception data.</summary>
public enum RestrictedTransportFailurePhase
{
    /// <summary>DNS resolution did not produce a usable result.</summary>
    DnsFailure,
    /// <summary>No approved address accepted a TCP connection.</summary>
    TcpConnectFailure,
    /// <summary>The upstream server certificate failed validation.</summary>
    TlsServerValidationFailure,
    /// <summary>The TLS peer rejected or could not complete client-certificate authentication.</summary>
    MutualTlsClientAuthenticationFailure,
    /// <summary>The bounded operation deadline elapsed.</summary>
    Timeout,
    /// <summary>A different transport failure occurred without safe lower-level detail.</summary>
    TransportFailureOther
}

/// <summary>Metadata-only qualified transport failure; it never retains an inner exception.</summary>
public sealed class RestrictedTransportFailureException : Exception
{
    /// <summary>Creates one bounded failure classification.</summary>
    public RestrictedTransportFailureException(RestrictedTransportFailurePhase phase)
        : base("Qualified restricted transport failed.")
    {
        if (!Enum.IsDefined(phase)) throw new ArgumentOutOfRangeException(nameof(phase));
        Phase = phase;
    }

    /// <summary>Safe closed failure phase.</summary>
    public RestrictedTransportFailurePhase Phase { get; }
}

internal sealed record SafeUpstreamFailureDiagnostics(
    GatewayAuditFailurePhase FailurePhase,
    int? UpstreamStatus,
    string? SafeUpstreamCode,
    string? LocalSafeCode)
{
    internal GatewayAuditFailureDiagnostics ToAuditDiagnostics() => GatewayAuditFailureDiagnostics.Create(
        FailurePhase,
        UpstreamStatus,
        GatewayAuditFailureDiagnostics.Category(UpstreamStatus),
        SafeUpstreamCode,
        LocalSafeCode);

    internal static SafeUpstreamFailureDiagnostics HttpResponse(int statusCode, string? safeCode) =>
        new(GatewayAuditFailurePhase.UpstreamHttpResponse, statusCode, safeCode, null);

    internal static SafeUpstreamFailureDiagnostics LocalResponseMapping(int statusCode, string localSafeCode, string? safeUpstreamCode = null) =>
        new(GatewayAuditFailurePhase.LocalResponseMappingFailure, statusCode, safeUpstreamCode, localSafeCode);

    internal static SafeUpstreamFailureDiagnostics Transport(RestrictedTransportFailurePhase phase) =>
        new(phase switch
        {
            RestrictedTransportFailurePhase.DnsFailure => GatewayAuditFailurePhase.DnsFailure,
            RestrictedTransportFailurePhase.TcpConnectFailure => GatewayAuditFailurePhase.TcpConnectFailure,
            RestrictedTransportFailurePhase.TlsServerValidationFailure => GatewayAuditFailurePhase.TlsServerValidationFailure,
            RestrictedTransportFailurePhase.MutualTlsClientAuthenticationFailure => GatewayAuditFailurePhase.MutualTlsClientAuthenticationFailure,
            RestrictedTransportFailurePhase.Timeout => GatewayAuditFailurePhase.Timeout,
            RestrictedTransportFailurePhase.TransportFailureOther => GatewayAuditFailurePhase.TransportFailureOther,
            _ => throw new ArgumentOutOfRangeException(nameof(phase))
        }, null, null, null);
}

/// <summary>Enrollment challenge request.</summary>
public sealed record EnrollmentChallengeRequest(Guid ActivationCodeId, string PublicKeySpki);
/// <summary>Short-lived enrollment challenge.</summary>
public sealed record EnrollmentChallengeResponse(Guid ChallengeId, string Challenge, DateTimeOffset ExpiresAt);
/// <summary>Activation code, certificate and proof-of-possession request.</summary>
/// <remarks>BrokerVersion is retained for BGW1 Broker compatibility; Direct clients use ClientVersion.</remarks>
public sealed record ActivationRequest(Guid ChallengeId, string ActivationCode, string ClientCertificate, string ProofSignature, string? BrokerVersion = null, string? ClientVersion = null);
/// <summary>Credential renewal request.</summary>
public sealed record RenewalRequest(string NewClientCertificate, string ProofSignature);
/// <summary>Successful enrollment or renewal result.</summary>
public sealed record EnrollmentResult(Guid InstallationId, Guid TenantId, Guid ApplicationId, DateTimeOffset CredentialExpiresAt, DateTimeOffset RenewalStartsAt);
/// <summary>One-time provisioning result; the code is never returned again.</summary>
public sealed record ProvisionedActivation(Guid InstallationId, Guid ActivationCodeId, string ActivationCode, DateTimeOffset ExpiresAt);
/// <summary>Protocol and compatibility policy for an authenticated Broker.</summary>
public sealed record BrokerPolicy(string MinimumBrokerVersion, int ProtocolMajor, int ProtocolMinor, bool Revoked);

/// <summary>Bounded, explicitly encoded Gateway payload.</summary>
public sealed record GatewayPayload(string ContentType, string Encoding, string Data);

/// <summary>Runtime invoke envelope.</summary>
public sealed record GatewayInvokeRequest(
    string ProtocolVersion,
    GatewayPayload Payload,
    Guid CorrelationId,
    string? IdempotencyKey = null,
    JsonElement? OperatorContext = null,
    IReadOnlyDictionary<string, JsonElement>? Metadata = null,
    IReadOnlyDictionary<string, JsonElement>? Extensions = null);

/// <summary>Runtime invoke result envelope.</summary>
public sealed record GatewayInvokeResponse(Guid CorrelationId, string ConnectorVersion, GatewayPayload Result);

/// <summary>Authentication kinds implemented by the M2 built-in operation pipeline.</summary>
public enum GatewayAuthenticationKind
{
    /// <summary>No external authentication.</summary>
    None,
    /// <summary>HTTP Basic populated from server-side secrets.</summary>
    Basic,
    /// <summary>Header API key populated from a server-side secret.</summary>
    ApiKey,
    /// <summary>TLS client certificate populated from a server-side secret.</summary>
    MutualTls,
    /// <summary>Header API key and TLS client certificate, both resolved server-side.</summary>
    ApiKeyAndMutualTls,
    /// <summary>OAuth Authorization Code is executed only by the capability-based outbound auth module.</summary>
    OAuthAuthorizationCode,
    /// <summary>OAuth Client Credentials is executed only by the capability-based outbound auth module.</summary>
    OAuthClientCredentials,
    /// <summary>Opaque-session HTTP projection is executed only by its authority-bound capability.</summary>
    OpaqueSessionHttp,
    /// <summary>Basic + SOAP metadata + opaque-session dispatch is executed only by its composed capability.</summary>
    SoapBasicOpaqueSession
}

/// <summary>Server-owned operation definition. No field is copied from an invoke request.</summary>
public sealed record GatewayOperationDefinition(
    string ConnectorId,
    string OperationId,
    string Version,
    Uri Endpoint,
    HttpMethod Method,
    string RequestContentType,
    GatewayAuthenticationKind Authentication,
    string? UsernameSecretReference,
    string? PasswordSecretReference,
    string? ApiKeySecretReference,
    string? ApiKeyHeaderName,
    string? ClientCertificateReference,
    int TimeoutMilliseconds,
    long MaximumRequestBytes,
    long MaximumResponseBytes,
    bool Idempotent,
    int MaximumRetries = 0,
    string? AuthenticationPolicyId = null,
    string? SessionProfileId = null,
    ConnectorExecutionStrategyKey? ExecutionStrategy = null);

/// <summary>Bounded result returned by one server-selected qualified execution strategy.</summary>
public sealed record QualifiedGatewayExecutionResult(int StatusCode, string ContentType, byte[] Body);

/// <summary>Runtime headers covered by the Installation signature.</summary>
public sealed record RuntimeSignatureHeaders(string Timestamp, string Nonce, string ContentSha256, string Signature);

/// <summary>Inbound authentication method used to establish a Gateway client principal.</summary>
public enum GatewayClientAuthenticationMethod
{
    /// <summary>Registry-bound ClientAuth certificate plus ECDSA-signed BGW1 envelope.</summary>
    MutualTlsPopBgw1
}

/// <summary>
/// Provider-neutral principal consumed by the shared runtime after inbound authentication.
/// Tenant, Application, Installation and kind are derived exclusively from server state.
/// </summary>
public sealed record GatewayClientPrincipal(RegisteredInstallationIdentity Identity, Guid CorrelationId)
{
    /// <summary>Server-derived Tenant identity.</summary>
    public Guid TenantId => Identity.TenantId;
    /// <summary>Server-derived Application identity.</summary>
    public Guid ApplicationId => Identity.ApplicationId;
    /// <summary>Server-derived Installation identity.</summary>
    public Guid InstallationId => Identity.InstallationId;
    /// <summary>Server-derived caller kind.</summary>
    public InstallationKind InstallationKind => Identity.InstallationKind;
    /// <summary>Credential that authenticated this request.</summary>
    public Guid AuthenticatedCredentialId => Identity.CredentialId;
    /// <summary>Inbound authentication mechanism; independent from outbound Connector authentication.</summary>
    public GatewayClientAuthenticationMethod AuthenticationMethod { get; init; } = GatewayClientAuthenticationMethod.MutualTlsPopBgw1;
    /// <summary>Authenticated protocol scopes. Operation grants remain a separate server-side authorization check.</summary>
    public IReadOnlySet<string> AuthenticatedScopes { get; init; } = new HashSet<string>(StringComparer.Ordinal) { "gateway.runtime" };
}

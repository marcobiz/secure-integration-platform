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

    /// <summary>Stable non-secret error code.</summary>
    public string Code { get; }
    /// <summary>HTTP status associated with the failure.</summary>
    public int StatusCode { get; }
    /// <summary>Whether a caller may retry safely.</summary>
    public bool Retryable { get; }
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
    OAuthClientCredentials
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
    int MaximumRetries = 0);

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

using System.Collections.ObjectModel;
using System.Text.Json.Serialization;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OAuth;

/// <summary>Authentication policy compiled from a Published Connector snapshot.</summary>
public enum HttpAuthenticationPolicy
{
    /// <summary>OAuth 2.0 Authorization Code with a server-owned confidential client.</summary>
    OAuthAuthorizationCode,
    /// <summary>OAuth 2.0 Client Credentials with a server-owned confidential client.</summary>
    OAuthClientCredentials
}

/// <summary>Server-owned PKCE policy. Callers cannot supply a verifier or select a downgrade.</summary>
internal enum OAuthPkcePolicy
{
    None,
    S256Required
}

/// <summary>Allowlisted client authentication selected by the Published profile.</summary>
internal enum OAuthClientAuthenticationMethod
{
    ClientSecretBasic
}

/// <summary>Unforgeable handoff created by the authenticated and authorized Gateway runtime.</summary>
public sealed class OAuthAuthorizedInvocation
{
    internal OAuthAuthorizedInvocation(GatewayClientPrincipal principal, string connectorId, string operationId)
    {
        ArgumentNullException.ThrowIfNull(principal);
        if (!OAuthValidation.Identifier(connectorId) || !OAuthValidation.Identifier(operationId)) throw OAuthFailures.Configuration();
        Principal = principal;
        ConnectorId = connectorId;
        OperationId = operationId;
    }
    [JsonIgnore] internal GatewayClientPrincipal Principal { get; }
    /// <summary>Connector authorized by the shared runtime.</summary>
    public string ConnectorId { get; }
    /// <summary>Operation authorized by the shared runtime.</summary>
    public string OperationId { get; }
    /// <summary>Authenticated request correlation.</summary>
    public Guid CorrelationId => Principal.CorrelationId;
    /// <inheritdoc />
    public override string ToString() => $"OAuthAuthorizedInvocation(ConnectorId={ConnectorId}, OperationId={OperationId}, CorrelationId={CorrelationId:D})";
}

/// <summary>Only selector a Connector may supply to the server-owned authority resolver.</summary>
public sealed class OAuthAuthorityRequest
{
    /// <summary>Selects one logical profile in the already-authorized Published operation.</summary>
    public OAuthAuthorityRequest(string profileId)
    {
        if (!OAuthValidation.Identifier(profileId)) throw OAuthFailures.Configuration();
        ProfileId = profileId;
    }
    /// <summary>Logical OAuth profile identifier; it cannot override profile fields.</summary>
    public string ProfileId { get; }
    /// <inheritdoc />
    public override string ToString() => $"OAuthAuthorityRequest(ProfileId={ProfileId})";
}

/// <summary>
/// Unforgeable immutable capability resolved from authenticated identity and a current Published snapshot.
/// Sensitive authority values are deliberately not public or serializable.
/// </summary>
public sealed class OAuthResolvedExecutionContext
{
    internal OAuthResolvedExecutionContext(
        OutboundAuthContext authority,
        IOAuthProfile profile,
        ScopedOAuthSecretCapability clientSecret,
        Uri protectedResourceEndpoint,
        HttpMethod protectedResourceMethod,
        string? protectedResourceContentType,
        TimeSpan protectedResourceTimeout,
        long maximumProtectedResourceResponseBytes,
        Func<CancellationToken, Task> revalidate)
    {
        Authority = authority;
        Profile = profile;
        ClientSecret = clientSecret;
        ProtectedResourceEndpoint = protectedResourceEndpoint;
        ProtectedResourceMethod = protectedResourceMethod;
        ProtectedResourceContentType = protectedResourceContentType;
        ProtectedResourceTimeout = protectedResourceTimeout;
        MaximumProtectedResourceResponseBytes = maximumProtectedResourceResponseBytes;
        Revalidate = revalidate;
    }

    /// <summary>Authenticated request correlation.</summary>
    public Guid CorrelationId => Authority.CorrelationId;
    /// <summary>Resolved Published Connector identifier.</summary>
    public string ConnectorId => Authority.ConnectorId;
    /// <summary>Resolved operation identifier.</summary>
    public string OperationId => Authority.OperationId;
    /// <summary>Resolved logical profile identifier.</summary>
    public string ProfileId => Profile.ProfileId;

    [JsonIgnore] internal OutboundAuthContext Authority { get; }
    [JsonIgnore] internal IOAuthProfile Profile { get; }
    [JsonIgnore] internal ScopedOAuthSecretCapability ClientSecret { get; }
    [JsonIgnore] internal Uri ProtectedResourceEndpoint { get; }
    [JsonIgnore] internal HttpMethod ProtectedResourceMethod { get; }
    [JsonIgnore] internal string? ProtectedResourceContentType { get; }
    [JsonIgnore] internal TimeSpan ProtectedResourceTimeout { get; }
    [JsonIgnore] internal long MaximumProtectedResourceResponseBytes { get; }
    [JsonIgnore] internal Func<CancellationToken, Task> Revalidate { get; }

    /// <inheritdoc />
    public override string ToString() => $"OAuthResolvedExecutionContext(ConnectorId={ConnectorId}, OperationId={OperationId}, ProfileId={ProfileId}, CorrelationId={CorrelationId:D})";
}

/// <summary>Common immutable profile surface compiled from Published state only.</summary>
internal interface IOAuthProfile
{
    HttpAuthenticationPolicy Policy { get; }
    string ProfileId { get; }
    Uri TokenEndpoint { get; }
    string ClientId { get; }
    IReadOnlyList<string> Scopes { get; }
    string? Audience { get; }
    string? Resource { get; }
    TimeSpan TokenRequestTimeout { get; }
    long MaximumTokenResponseBytes { get; }
    TimeSpan ExpirySkew { get; }
    OAuthClientAuthenticationMethod ClientAuthenticationMethod { get; }
    string Fingerprint { get; }
}

/// <summary>Immutable server-derived security identity. It is never constructible by Connector code.</summary>
internal sealed class OutboundAuthContext
{
    internal OutboundAuthContext(Guid tenantId, Guid installationId, Guid applicationId, Guid environmentId, Guid connectorVersionId, string connectorId, string connectorVersion, string operationId,
        long authBindingRevision, long endpointRevision, long secretRevision, string resourceStamp, Guid correlationId, DateTimeOffset deadline)
    {
        TenantId = tenantId;
        InstallationId = installationId;
        ApplicationId = applicationId;
        EnvironmentId = environmentId;
        ConnectorVersionId = connectorVersionId;
        ConnectorId = connectorId;
        ConnectorVersion = connectorVersion;
        OperationId = operationId;
        AuthBindingRevision = authBindingRevision;
        EndpointRevision = endpointRevision;
        SecretRevision = secretRevision;
        ResourceStamp = resourceStamp;
        CorrelationId = correlationId;
        Deadline = deadline;
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
    internal long AuthBindingRevision { get; }
    internal long EndpointRevision { get; }
    internal long SecretRevision { get; }
    internal string ResourceStamp { get; }
    internal Guid CorrelationId { get; }
    internal DateTimeOffset Deadline { get; }

    private void Validate()
    {
        if (TenantId == Guid.Empty || InstallationId == Guid.Empty || ApplicationId == Guid.Empty || EnvironmentId == Guid.Empty || ConnectorVersionId == Guid.Empty || CorrelationId == Guid.Empty)
            throw OAuthFailures.Configuration();
        if (!OAuthValidation.Identifier(ConnectorId) || !OAuthValidation.Identifier(ConnectorVersion) || !OAuthValidation.Identifier(OperationId) || AuthBindingRevision < 1 || EndpointRevision < 1 || SecretRevision < 1 || string.IsNullOrWhiteSpace(ResourceStamp) || ResourceStamp.Length > 256)
            throw OAuthFailures.Configuration();
    }

    public override string ToString() => $"OutboundAuthContext(ConnectorId={ConnectorId}, OperationId={OperationId}, CorrelationId={CorrelationId:D})";
}

/// <summary>Raw profile compiled only inside the authority resolver from a Published snapshot.</summary>
internal sealed class OAuthAuthorizationCodeProfile : IOAuthProfile
{
    private static readonly HashSet<string> ReservedAuthorizationParameters = new(StringComparer.OrdinalIgnoreCase)
    {
        "state", "redirect_uri", "client_id", "scope", "audience", "response_type", "code_challenge", "code_challenge_method", "nonce", "request", "request_uri"
    };
    private readonly ReadOnlyCollection<string> scopes;

    internal OAuthAuthorizationCodeProfile(string profileId, Uri authorizationEndpoint, Uri tokenEndpoint, Uri redirectUri, string clientId, IEnumerable<string> scopes, string? audience,
        TimeSpan authorizationLifetime, TimeSpan tokenRequestTimeout, long maximumTokenResponseBytes, TimeSpan expirySkew, bool allowRefresh,
        OAuthPkcePolicy pkcePolicy = OAuthPkcePolicy.None, OAuthClientAuthenticationMethod clientAuthenticationMethod = OAuthClientAuthenticationMethod.ClientSecretBasic)
    {
        string[] scopeValues = scopes?.ToArray() ?? [];
        if (!OAuthValidation.Identifier(profileId) || !OAuthValidation.HttpsEndpoint(authorizationEndpoint) || ContainsReservedAuthorizationParameter(authorizationEndpoint) || !OAuthValidation.HttpsEndpoint(tokenEndpoint) ||
            !OAuthValidation.HttpsRedirect(redirectUri) || !OAuthValidation.ClientId(clientId) || scopeValues.Length is < 1 or > 32 ||
            scopeValues.Any(value => !OAuthValidation.Scope(value)) || scopeValues.Distinct(StringComparer.Ordinal).Count() != scopeValues.Length || !OAuthValidation.OptionalParameter(audience) ||
            authorizationLifetime < TimeSpan.FromMinutes(1) || authorizationLifetime > TimeSpan.FromMinutes(30) || tokenRequestTimeout < TimeSpan.FromMilliseconds(100) || tokenRequestTimeout > TimeSpan.FromSeconds(30) ||
            maximumTokenResponseBytes is < 256 or > 64 * 1024 || expirySkew < TimeSpan.Zero || expirySkew > TimeSpan.FromMinutes(5) ||
            clientAuthenticationMethod != OAuthClientAuthenticationMethod.ClientSecretBasic)
            throw OAuthFailures.Configuration();

        ProfileId = profileId;
        AuthorizationEndpoint = authorizationEndpoint;
        TokenEndpoint = tokenEndpoint;
        RedirectUri = redirectUri;
        ClientId = clientId;
        this.scopes = Array.AsReadOnly(scopeValues);
        Audience = audience;
        AuthorizationLifetime = authorizationLifetime;
        TokenRequestTimeout = tokenRequestTimeout;
        MaximumTokenResponseBytes = maximumTokenResponseBytes;
        ExpirySkew = expirySkew;
        AllowRefresh = allowRefresh;
        PkcePolicy = pkcePolicy;
        ClientAuthenticationMethod = clientAuthenticationMethod;
    }

    internal HttpAuthenticationPolicy Policy { get; } = HttpAuthenticationPolicy.OAuthAuthorizationCode;
    internal string ProfileId { get; }
    [JsonIgnore] internal Uri AuthorizationEndpoint { get; }
    [JsonIgnore] internal Uri TokenEndpoint { get; }
    [JsonIgnore] internal Uri RedirectUri { get; }
    [JsonIgnore] internal string ClientId { get; }
    [JsonIgnore] internal IReadOnlyList<string> Scopes => scopes;
    [JsonIgnore] internal string? Audience { get; }
    [JsonIgnore] public string? Resource => null;
    internal TimeSpan AuthorizationLifetime { get; }
    internal TimeSpan TokenRequestTimeout { get; }
    internal long MaximumTokenResponseBytes { get; }
    internal TimeSpan ExpirySkew { get; }
    internal bool AllowRefresh { get; }
    internal OAuthPkcePolicy PkcePolicy { get; }
    public OAuthClientAuthenticationMethod ClientAuthenticationMethod { get; }
    internal string Fingerprint => string.Join('\n', [Policy.ToString(), ProfileId, AuthorizationEndpoint.AbsoluteUri, TokenEndpoint.AbsoluteUri, RedirectUri.AbsoluteUri, ClientId,
        ClientAuthenticationMethod.ToString(), string.Join(' ', scopes), Audience ?? string.Empty, Resource ?? string.Empty, AllowRefresh ? "refresh" : "reacquire", PkcePolicy.ToString(),
        AuthorizationLifetime.Ticks, TokenRequestTimeout.Ticks, MaximumTokenResponseBytes, ExpirySkew.Ticks]);

    HttpAuthenticationPolicy IOAuthProfile.Policy => Policy;
    string IOAuthProfile.ProfileId => ProfileId;
    Uri IOAuthProfile.TokenEndpoint => TokenEndpoint;
    string IOAuthProfile.ClientId => ClientId;
    IReadOnlyList<string> IOAuthProfile.Scopes => Scopes;
    string? IOAuthProfile.Audience => Audience;
    TimeSpan IOAuthProfile.TokenRequestTimeout => TokenRequestTimeout;
    long IOAuthProfile.MaximumTokenResponseBytes => MaximumTokenResponseBytes;
    TimeSpan IOAuthProfile.ExpirySkew => ExpirySkew;
    string IOAuthProfile.Fingerprint => Fingerprint;

    public override string ToString() => $"OAuthAuthorizationCodeProfile(ProfileId={ProfileId}, Policy={Policy})";

    private static bool ContainsReservedAuthorizationParameter(Uri endpoint)
    {
        if (string.IsNullOrEmpty(endpoint.Query)) return false;
        foreach (string pair in endpoint.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string encodedName = pair.Split('=', 2)[0].Replace('+', ' ');
            string name;
            try { name = Uri.UnescapeDataString(encodedName); }
            catch (UriFormatException) { return true; }
            if (ReservedAuthorizationParameters.Contains(name)) return true;
        }
        return false;
    }
}

/// <summary>Raw Client Credentials profile compiled only inside the authority resolver.</summary>
internal sealed class OAuthClientCredentialsProfile : IOAuthProfile
{
    private readonly ReadOnlyCollection<string> scopes;

    internal OAuthClientCredentialsProfile(string profileId, Uri tokenEndpoint, string clientId, IEnumerable<string> scopes, string? audience, string? resource,
        TimeSpan tokenRequestTimeout, long maximumTokenResponseBytes, TimeSpan expirySkew,
        OAuthClientAuthenticationMethod clientAuthenticationMethod = OAuthClientAuthenticationMethod.ClientSecretBasic)
    {
        string[] scopeValues = scopes?.ToArray() ?? [];
        if (!OAuthValidation.Identifier(profileId) || !OAuthValidation.HttpsEndpoint(tokenEndpoint) || !OAuthValidation.ClientId(clientId) ||
            scopeValues.Length is < 1 or > 32 || scopeValues.Any(value => !OAuthValidation.Scope(value)) || scopeValues.Distinct(StringComparer.Ordinal).Count() != scopeValues.Length ||
            !OAuthValidation.OptionalParameter(audience) || !OAuthValidation.OptionalParameter(resource) ||
            tokenRequestTimeout < TimeSpan.FromMilliseconds(100) || tokenRequestTimeout > TimeSpan.FromSeconds(30) || maximumTokenResponseBytes is < 256 or > 64 * 1024 ||
            expirySkew < TimeSpan.Zero || expirySkew > TimeSpan.FromMinutes(5) || clientAuthenticationMethod != OAuthClientAuthenticationMethod.ClientSecretBasic)
            throw OAuthFailures.Configuration();

        ProfileId = profileId;
        TokenEndpoint = tokenEndpoint;
        ClientId = clientId;
        this.scopes = Array.AsReadOnly(scopeValues);
        Audience = audience;
        Resource = resource;
        TokenRequestTimeout = tokenRequestTimeout;
        MaximumTokenResponseBytes = maximumTokenResponseBytes;
        ExpirySkew = expirySkew;
        ClientAuthenticationMethod = clientAuthenticationMethod;
    }

    public HttpAuthenticationPolicy Policy { get; } = HttpAuthenticationPolicy.OAuthClientCredentials;
    public string ProfileId { get; }
    [JsonIgnore] public Uri TokenEndpoint { get; }
    [JsonIgnore] public string ClientId { get; }
    [JsonIgnore] public IReadOnlyList<string> Scopes => scopes;
    [JsonIgnore] public string? Audience { get; }
    [JsonIgnore] public string? Resource { get; }
    public TimeSpan TokenRequestTimeout { get; }
    public long MaximumTokenResponseBytes { get; }
    public TimeSpan ExpirySkew { get; }
    public OAuthClientAuthenticationMethod ClientAuthenticationMethod { get; }
    public string Fingerprint => string.Join('\n', [Policy.ToString(), ProfileId, TokenEndpoint.AbsoluteUri, ClientId, ClientAuthenticationMethod.ToString(),
        string.Join(' ', scopes), Audience ?? string.Empty, Resource ?? string.Empty, TokenRequestTimeout.Ticks, MaximumTokenResponseBytes, ExpirySkew.Ticks]);
    public override string ToString() => $"OAuthClientCredentialsProfile(ProfileId={ProfileId}, Policy={Policy})";
}

/// <summary>Capability scoped to the exact provider locator resolved for the Published secret binding.</summary>
internal sealed class ScopedOAuthSecretCapability(ISecretValueProvider provider, string exactProviderReference)
{
    internal Task<string> UseAsync(CancellationToken cancellationToken) => provider.GetSecretAsync(exactProviderReference, cancellationToken);
    public override string ToString() => "ScopedOAuthSecretCapability(Redacted)";
}

/// <summary>Opaque authorization attempt for external user-agent navigation only.</summary>
public sealed class OAuthAuthorizationChallenge
{
    internal OAuthAuthorizationChallenge(string opaqueAttemptReference, Uri authorizationUri, Guid correlationId, DateTimeOffset expiresAt)
    {
        OpaqueAttemptReference = opaqueAttemptReference;
        AuthorizationUri = authorizationUri;
        CorrelationId = correlationId;
        ExpiresAt = expiresAt;
    }
    /// <summary>Opaque one-time attempt reference.</summary>
    [JsonIgnore] public string OpaqueAttemptReference { get; }
    /// <summary>Approved URL to present to an external user agent; never fetched by this module.</summary>
    [JsonIgnore] public Uri AuthorizationUri { get; }
    /// <summary>Original authenticated invocation correlation.</summary>
    public Guid CorrelationId { get; }
    /// <summary>Absolute attempt expiry.</summary>
    public DateTimeOffset ExpiresAt { get; }
    /// <summary>Explicit presentation boundary.</summary>
    public string PresentationKind { get; } = "external-user-agent-navigation";
    /// <inheritdoc />
    public override string ToString() => $"OAuthAuthorizationChallenge(CorrelationId={CorrelationId:D}, ExpiresAt={ExpiresAt:O}, PresentationKind={PresentationKind})";
}

/// <summary>Transport-neutral completion state. Sensitive callback material is never included.</summary>
public enum OAuthAuthorizationState
{
    /// <summary>Awaiting callback.</summary>
    Pending,
    /// <summary>Consumed successfully.</summary>
    Completed,
    /// <summary>Absolute lifetime elapsed.</summary>
    Expired,
    /// <summary>Rejected or invalidated.</summary>
    Failed
}

/// <summary>Opaque handle to a server-side token session.</summary>
public sealed class OAuthTokenSessionReference
{
    internal OAuthTokenSessionReference(string value) => Value = value;
    [JsonIgnore] internal string Value { get; }
    /// <inheritdoc />
    public override string ToString() => "OAuthTokenSessionReference(Redacted)";
}

/// <summary>Metadata-only audit record. It cannot carry codes, tokens, state or provider references.</summary>
public sealed record OutboundAuthAuditRecord(Guid CorrelationId, Guid TenantId, string ConnectorId, string OperationId, string ProfileId, string Action, string Outcome, DateTimeOffset OccurredAt, DateTimeOffset? ExpiresAt = null);

/// <summary>Narrow metadata-only sink for outbound-auth audit.</summary>
public interface IOutboundAuthAuditSink
{
    /// <summary>Writes one allowlisted metadata-only event.</summary>
    Task WriteAsync(OutboundAuthAuditRecord record, CancellationToken cancellationToken);
}

/// <summary>No-op audit sink for hosts that provide the durable adapter at composition time.</summary>
public sealed class NullOutboundAuthAuditSink : IOutboundAuthAuditSink
{
    /// <inheritdoc />
    public Task WriteAsync(OutboundAuthAuditRecord record, CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Task.CompletedTask; }
}

internal static class OAuthValidation
{
    internal static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 100 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    internal static bool Scope(string value) => value.Length is > 0 and <= 128 && value.All(character => character is >= '!' and <= '~' && character is not '"' and not '\\');
    internal static bool ClientId(string value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 256 && !value.Any(character => char.IsControl(character) || character is '\r' or '\n' or '\0');
    internal static bool HttpsEndpoint(Uri value) => value.IsAbsoluteUri && value.Scheme == Uri.UriSchemeHttps && string.IsNullOrEmpty(value.UserInfo) && string.IsNullOrEmpty(value.Fragment);
    internal static bool HttpsRedirect(Uri value) => HttpsEndpoint(value) && string.IsNullOrEmpty(value.Query);
    internal static bool OptionalParameter(string? value) => value is null || value.Length is > 0 and <= 256 && !value.Any(character => char.IsControl(character) || character is '\r' or '\n' or '\0');
    internal static bool PkceVerifier(string? value) => value is not null && value.Length is >= 43 and <= 128 && value.All(IsPkceCharacter);
    internal static bool PkceVerifier(byte[]? value) => value is not null && value.Length is >= 43 and <= 128 && value.All(character => character <= 0x7f && IsPkceCharacter((char)character));
    internal static bool PkceChallenge(string? value) => value is { Length: 43 } && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
    private static bool IsPkceCharacter(char character) => char.IsAsciiLetterOrDigit(character) || character is '-' or '.' or '_' or '~';
}

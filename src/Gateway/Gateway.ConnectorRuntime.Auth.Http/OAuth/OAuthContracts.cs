using System.Collections.ObjectModel;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OAuth;

/// <summary>Authentication policy exposed to compiled Connector profiles.</summary>
public enum HttpAuthenticationPolicy
{
    /// <summary>OAuth 2.0 Authorization Code with a server-owned confidential client.</summary>
    OAuthAuthorizationCode
}

/// <summary>Immutable server-derived security identity for an outbound authentication operation.</summary>
public sealed record OutboundAuthContext(
    Guid TenantId,
    Guid InstallationId,
    Guid ApplicationId,
    Guid EnvironmentId,
    Guid ConnectorVersionId,
    string ConnectorId,
    string ConnectorVersion,
    string OperationId,
    long AuthBindingRevision,
    long EndpointRevision,
    long SecretRevision,
    string ResourceStamp,
    Guid CorrelationId,
    DateTimeOffset Deadline)
{
    internal void Validate()
    {
        if (TenantId == Guid.Empty || InstallationId == Guid.Empty || ApplicationId == Guid.Empty || EnvironmentId == Guid.Empty || ConnectorVersionId == Guid.Empty || CorrelationId == Guid.Empty)
            throw OAuthFailures.Configuration();
        if (!OAuthValidation.Identifier(ConnectorId) || !OAuthValidation.Identifier(ConnectorVersion) || !OAuthValidation.Identifier(OperationId) || AuthBindingRevision < 1 || EndpointRevision < 1 || SecretRevision < 1 || string.IsNullOrWhiteSpace(ResourceStamp) || ResourceStamp.Length > 256)
            throw OAuthFailures.Configuration();
    }
}

/// <summary>Small declarative profile compiled from a Published Connector and its approved bindings.</summary>
public sealed class OAuthAuthorizationCodeProfile
{
    private readonly ReadOnlyCollection<string> scopes;

    /// <summary>Creates an immutable server-owned Authorization Code profile.</summary>
    public OAuthAuthorizationCodeProfile(
        string profileId,
        Uri authorizationEndpoint,
        Uri tokenEndpoint,
        Uri redirectUri,
        string clientId,
        string clientSecretReference,
        IEnumerable<string> scopes,
        string? audience,
        TimeSpan authorizationLifetime,
        TimeSpan tokenRequestTimeout,
        long maximumTokenResponseBytes,
        TimeSpan expirySkew,
        bool allowRefresh)
    {
        string[] scopeValues = scopes?.ToArray() ?? [];
        if (!OAuthValidation.Identifier(profileId) || !OAuthValidation.HttpsEndpoint(authorizationEndpoint) || !OAuthValidation.HttpsEndpoint(tokenEndpoint) ||
            !OAuthValidation.HttpsRedirect(redirectUri) || string.IsNullOrWhiteSpace(clientId) || clientId.Length > 256 || string.IsNullOrWhiteSpace(clientSecretReference) || clientSecretReference.Length > 256 ||
            scopeValues.Length is < 1 or > 32 || scopeValues.Any(value => !OAuthValidation.Scope(value)) || scopeValues.Distinct(StringComparer.Ordinal).Count() != scopeValues.Length ||
            audience is { Length: > 256 } || audience?.Any(char.IsControl) == true || authorizationLifetime < TimeSpan.FromMinutes(1) || authorizationLifetime > TimeSpan.FromMinutes(30) ||
            tokenRequestTimeout < TimeSpan.FromMilliseconds(100) || tokenRequestTimeout > TimeSpan.FromSeconds(30) || maximumTokenResponseBytes is < 256 or > 64 * 1024 ||
            expirySkew < TimeSpan.Zero || expirySkew > TimeSpan.FromMinutes(5))
            throw OAuthFailures.Configuration();

        Policy = HttpAuthenticationPolicy.OAuthAuthorizationCode;
        ProfileId = profileId;
        AuthorizationEndpoint = authorizationEndpoint;
        TokenEndpoint = tokenEndpoint;
        RedirectUri = redirectUri;
        ClientId = clientId;
        ClientSecretReference = clientSecretReference;
        this.scopes = Array.AsReadOnly(scopeValues);
        Audience = audience;
        AuthorizationLifetime = authorizationLifetime;
        TokenRequestTimeout = tokenRequestTimeout;
        MaximumTokenResponseBytes = maximumTokenResponseBytes;
        ExpirySkew = expirySkew;
        AllowRefresh = allowRefresh;
    }

    /// <summary>Fixed policy kind.</summary>
    public HttpAuthenticationPolicy Policy { get; }
    /// <summary>Compiled token profile identifier.</summary>
    public string ProfileId { get; }
    /// <summary>Approved authorization endpoint.</summary>
    public Uri AuthorizationEndpoint { get; }
    /// <summary>Approved token endpoint.</summary>
    public Uri TokenEndpoint { get; }
    /// <summary>Registered callback URI.</summary>
    public Uri RedirectUri { get; }
    /// <summary>Connector-owned client identifier.</summary>
    public string ClientId { get; }
    /// <summary>Server-side logical secret reference.</summary>
    public string ClientSecretReference { get; }
    /// <summary>Fixed approved scopes.</summary>
    public IReadOnlyList<string> Scopes => scopes;
    /// <summary>Fixed optional resource audience.</summary>
    public string? Audience { get; }
    /// <summary>Absolute authorization-attempt lifetime.</summary>
    public TimeSpan AuthorizationLifetime { get; }
    /// <summary>Bounded token request timeout.</summary>
    public TimeSpan TokenRequestTimeout { get; }
    /// <summary>Maximum accepted token response bytes.</summary>
    public long MaximumTokenResponseBytes { get; }
    /// <summary>Safety margin subtracted from upstream expiry.</summary>
    public TimeSpan ExpirySkew { get; }
    /// <summary>Whether this exact characterized profile permits refresh.</summary>
    public bool AllowRefresh { get; }

    internal string Fingerprint => string.Join('\n', [ProfileId, AuthorizationEndpoint.AbsoluteUri, TokenEndpoint.AbsoluteUri, RedirectUri.AbsoluteUri, ClientId, string.Join(' ', scopes), Audience ?? string.Empty, AllowRefresh ? "refresh" : "reacquire"]);
}

/// <summary>Opaque authorization attempt safe to hand to a trusted presentation adapter.</summary>
public sealed record OAuthAuthorizationChallenge(string OpaqueAttemptReference, Uri AuthorizationUri, Guid CorrelationId, DateTimeOffset ExpiresAt);

/// <summary>Transport-neutral completion state. Sensitive callback material is never included.</summary>
public enum OAuthAuthorizationState
{
    /// <summary>Waiting for the callback.</summary>
    Pending,
    /// <summary>Completed and consumed exactly once.</summary>
    Completed,
    /// <summary>No longer usable.</summary>
    Expired,
    /// <summary>Invalidated after a failed or rejected completion.</summary>
    Failed
}

/// <summary>Opaque handle to a server-side token session.</summary>
public sealed record OAuthTokenSessionReference(string Value);

/// <summary>Metadata-only audit record. It cannot carry codes, tokens, state or provider references.</summary>
public sealed record OutboundAuthAuditRecord(Guid CorrelationId, Guid TenantId, string ConnectorId, string OperationId, string ProfileId, string Action, string Outcome, DateTimeOffset OccurredAt, DateTimeOffset? ExpiresAt = null);

/// <summary>Narrow metadata-only sink for outbound-auth audit.</summary>
public interface IOutboundAuthAuditSink
{
    /// <summary>Persists one allowlisted metadata record.</summary>
    Task WriteAsync(OutboundAuthAuditRecord record, CancellationToken cancellationToken);
}

/// <summary>No-op audit sink for hosts that provide the durable adapter at composition time.</summary>
public sealed class NullOutboundAuthAuditSink : IOutboundAuthAuditSink
{
    /// <inheritdoc />
    public Task WriteAsync(OutboundAuthAuditRecord record, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }
}

internal static class OAuthValidation
{
    internal static bool Identifier(string value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 100 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    internal static bool Scope(string value) => value.Length is > 0 and <= 128 && value.All(character => character is >= '!' and <= '~' && character is not '"' and not '\\');
    internal static bool HttpsEndpoint(Uri value) => value.IsAbsoluteUri && value.Scheme == Uri.UriSchemeHttps && string.IsNullOrEmpty(value.UserInfo) && string.IsNullOrEmpty(value.Fragment);
    internal static bool HttpsRedirect(Uri value) => HttpsEndpoint(value) && string.IsNullOrEmpty(value.Query);
}

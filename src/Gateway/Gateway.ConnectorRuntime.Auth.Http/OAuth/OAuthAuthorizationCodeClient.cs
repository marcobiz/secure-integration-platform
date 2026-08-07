using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.Http;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OAuth;

/// <summary>Authorization Code, bounded token cache, refresh and bearer application over restricted egress.</summary>
public sealed class OAuthAuthorizationCodeClient
{
    private readonly object sync = new();
    private readonly Dictionary<string, AuthorizationAttempt> attempts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, TokenSession> sessions = new(StringComparer.Ordinal);
    private readonly int attemptCapacity;
    private readonly int tokenCapacity;
    private readonly ISecretValueProvider secrets;
    private readonly RestrictedEndpointPolicy endpoints;
    private readonly IRestrictedTransport transport;
    private readonly IGatewayClock clock;
    private readonly IOutboundAuthAuditSink audit;

    /// <summary>Creates bounded in-memory stores. Tokens never leave this component.</summary>
    public OAuthAuthorizationCodeClient(int attemptCapacity, int tokenCapacity, ISecretValueProvider secrets, RestrictedEndpointPolicy endpoints, IRestrictedTransport transport, IGatewayClock clock, IOutboundAuthAuditSink? audit = null)
    {
        if (attemptCapacity is < 1 or > 100_000) throw new ArgumentOutOfRangeException(nameof(attemptCapacity));
        if (tokenCapacity is < 1 or > 100_000) throw new ArgumentOutOfRangeException(nameof(tokenCapacity));
        this.attemptCapacity = attemptCapacity;
        this.tokenCapacity = tokenCapacity;
        this.secrets = secrets;
        this.endpoints = endpoints;
        this.transport = transport;
        this.clock = clock;
        this.audit = audit ?? new NullOutboundAuthAuditSink();
    }

    /// <summary>Number of cached token sessions, exposed as non-sensitive operational metadata.</summary>
    public int CachedSessionCount { get { lock (sync) return sessions.Count; } }

    /// <summary>Starts one short-lived authorization attempt after applying endpoint SSRF policy.</summary>
    public async Task<OAuthAuthorizationChallenge> BeginAuthorizationAsync(OutboundAuthContext context, OAuthAuthorizationCodeProfile profile, CancellationToken cancellationToken)
    {
        Validate(context, profile);
        _ = await endpoints.ResolveAsync(profile.AuthorizationEndpoint, cancellationToken).ConfigureAwait(false);
        string attemptReference = OpaqueValue();
        string state = OpaqueValue();
        DateTimeOffset expiresAt = Min(clock.UtcNow + profile.AuthorizationLifetime, context.Deadline);
        string key = SecurityKey(context, profile);
        lock (sync)
        {
            Prune();
            EnsureAttemptCapacity();
            attempts.Add(attemptReference, new(key, profile.Fingerprint, Hash(state), expiresAt, context.CorrelationId, OAuthAuthorizationState.Pending, clock.UtcNow));
        }
        Uri authorizationUri = AuthorizationUri(profile, state);
        try { await WriteAuditAsync(context, profile, "oauth.authorization.begin", "pending", expiresAt, cancellationToken).ConfigureAwait(false); }
        catch
        {
            lock (sync)
                if (attempts.Remove(attemptReference, out AuthorizationAttempt? removed)) CryptographicOperations.ZeroMemory(removed.StateHash);
            throw;
        }
        return new(attemptReference, authorizationUri, context.CorrelationId, expiresAt);
    }

    /// <summary>Returns only the state of an opaque attempt.</summary>
    public OAuthAuthorizationState PollAuthorization(OutboundAuthContext context, OAuthAuthorizationCodeProfile profile, string opaqueAttemptReference)
    {
        Validate(context, profile);
        lock (sync)
        {
            if (!attempts.TryGetValue(opaqueAttemptReference, out AuthorizationAttempt? attempt) || attempt.SecurityKey != SecurityKey(context, profile) || attempt.ProfileFingerprint != profile.Fingerprint)
                throw OAuthFailures.Rejected();
            if (attempt.ExpiresAt <= clock.UtcNow && attempt.State == OAuthAuthorizationState.Pending) attempt.State = OAuthAuthorizationState.Expired;
            attempt.LastAccess = clock.UtcNow;
            return attempt.State;
        }
    }

    /// <summary>Consumes callback code/state once and exchanges the code through restricted egress.</summary>
    public async Task<OAuthTokenSessionReference> CompleteAuthorizationAsync(OutboundAuthContext context, OAuthAuthorizationCodeProfile profile, string opaqueAttemptReference, string code, string state, CancellationToken cancellationToken)
    {
        Validate(context, profile);
        if (!BoundedSecret(code, 8192) || !BoundedSecret(state, 1024)) throw OAuthFailures.Rejected();
        AuthorizationAttempt attempt;
        lock (sync)
        {
            if (!attempts.TryGetValue(opaqueAttemptReference, out attempt!) || attempt.SecurityKey != SecurityKey(context, profile) || attempt.ProfileFingerprint != profile.Fingerprint || attempt.State != OAuthAuthorizationState.Pending)
                throw OAuthFailures.Rejected();
            if (attempt.ExpiresAt <= clock.UtcNow)
            {
                attempt.State = OAuthAuthorizationState.Expired;
                throw OAuthFailures.Rejected();
            }
            byte[] presentedStateHash = Hash(state);
            bool stateAccepted = CryptographicOperations.FixedTimeEquals(attempt.StateHash, presentedStateHash);
            CryptographicOperations.ZeroMemory(presentedStateHash);
            if (!stateAccepted)
            {
                attempt.State = OAuthAuthorizationState.Failed;
                CryptographicOperations.ZeroMemory(attempt.StateHash);
                throw OAuthFailures.Rejected();
            }
            attempt.State = OAuthAuthorizationState.Failed; // reserve before the non-repeatable exchange
        }

        string? createdSessionReference = null;
        try
        {
            TokenSet tokens = await RequestTokenAsync(context, profile, "authorization_code", code, cancellationToken).ConfigureAwait(false);
            string sessionReference = OpaqueValue();
            createdSessionReference = sessionReference;
            TokenSession session = new(SecurityKey(context, profile), profile.Fingerprint, context.ConnectorId, tokens, clock.UtcNow);
            lock (sync)
            {
                Prune();
                EnsureTokenCapacity();
                sessions.Add(sessionReference, session);
                attempt.State = OAuthAuthorizationState.Completed;
                CryptographicOperations.ZeroMemory(attempt.StateHash);
            }
            await WriteAuditAsync(context, profile, "oauth.authorization.complete", "success", tokens.ExpiresAt, cancellationToken).ConfigureAwait(false);
            return new(sessionReference);
        }
        catch
        {
            lock (sync)
            {
                attempt.State = OAuthAuthorizationState.Failed;
                if (createdSessionReference is not null) RemoveSessionCore(createdSessionReference);
            }
            try { await WriteAuditAsync(context, profile, "oauth.authorization.complete", "denied", null, CancellationToken.None).ConfigureAwait(false); }
            catch { /* The host maps audit failure to a sanitized generic error; token state is already removed. */ }
            throw;
        }
    }

    /// <summary>Applies exactly one bearer header after cache validation and refresh when permitted.</summary>
    public async Task ApplyBearerAsync(OutboundAuthContext context, OAuthAuthorizationCodeProfile profile, OAuthTokenSessionReference sessionReference, HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Validate(context, profile);
        if (request.Headers.Authorization is not null || request.RequestUri is null) throw OAuthFailures.Configuration();
        TokenSession session = RequiredSession(context, profile, sessionReference);
        await session.RefreshGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            session = RequiredSession(context, profile, sessionReference);
            if (session.Tokens.ExpiresAt <= clock.UtcNow + profile.ExpirySkew)
            {
                if (!profile.AllowRefresh || string.IsNullOrEmpty(session.Tokens.RefreshToken))
                {
                    RemoveSession(sessionReference.Value);
                    throw OAuthFailures.ReacquisitionRequired();
                }
                try
                {
                    TokenSet refreshed = await RequestTokenAsync(context, profile, "refresh_token", session.Tokens.RefreshToken, cancellationToken).ConfigureAwait(false);
                    if (string.IsNullOrEmpty(refreshed.RefreshToken)) refreshed = refreshed with { RefreshToken = session.Tokens.RefreshToken };
                    lock (sync)
                    {
                        session.Tokens = refreshed;
                        session.LastAccess = clock.UtcNow;
                    }
                    await WriteAuditAsync(context, profile, "oauth.token.refresh", "success", refreshed.ExpiresAt, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    RemoveSession(sessionReference.Value);
                    try { await WriteAuditAsync(context, profile, "oauth.token.refresh", "denied", null, CancellationToken.None).ConfigureAwait(false); }
                    catch { /* Preserve the sanitized refresh failure after invalidation. */ }
                    throw;
                }
            }
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", session.Tokens.AccessToken);
            lock (sync) session.LastAccess = clock.UtcNow;
        }
        finally { session.RefreshGate.Release(); }
    }

    /// <summary>Invalidates an opaque token session.</summary>
    public void Invalidate(OAuthTokenSessionReference sessionReference) => RemoveSession(sessionReference.Value);

    /// <summary>Immediately invalidates every entry whose immutable security identity no longer matches.</summary>
    public void InvalidateConnector(string connectorId)
    {
        lock (sync)
            foreach (string key in sessions.Where(value => string.Equals(value.Value.ConnectorId, connectorId, StringComparison.Ordinal)).Select(value => value.Key).ToArray()) RemoveSessionCore(key);
    }

    private async Task<TokenSet> RequestTokenAsync(OutboundAuthContext context, OAuthAuthorizationCodeProfile profile, string grantType, string sensitiveValue, CancellationToken cancellationToken)
    {
        IReadOnlyList<System.Net.IPAddress> addresses = await endpoints.ResolveAsync(profile.TokenEndpoint, cancellationToken).ConfigureAwait(false);
        string clientSecret;
        try { clientSecret = await secrets.GetSecretAsync(profile.ClientSecretReference, cancellationToken).ConfigureAwait(false); }
        catch (Exception exception) when (exception is not OperationCanceledException) { throw OAuthFailures.Rejected(); }
        if (!BoundedSecret(clientSecret, 4096)) throw OAuthFailures.Rejected();
        Dictionary<string, string> form = new(StringComparer.Ordinal)
        {
            ["grant_type"] = grantType,
            [grantType == "authorization_code" ? "code" : "refresh_token"] = sensitiveValue,
            ["client_id"] = profile.ClientId
        };
        if (grantType == "authorization_code") form["redirect_uri"] = profile.RedirectUri.AbsoluteUri;
        using HttpRequestMessage request = new(HttpMethod.Post, profile.TokenEndpoint) { Content = new FormUrlEncodedContent(form) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(profile.ClientId + ":" + clientSecret)));
        ExternalResponse response;
        try
        {
            response = await transport.SendAsync(request, addresses, null, profile.TokenRequestTimeout, profile.MaximumTokenResponseBytes, cancellationToken).ConfigureAwait(false);
        }
        catch (GatewayException) { throw; }
        catch (Exception exception) when (exception is not OperationCanceledException) { throw OAuthFailures.Rejected(); }
        return ParseToken(response, profile);
    }

    private TokenSet ParseToken(ExternalResponse response, OAuthAuthorizationCodeProfile profile)
    {
        if (!MediaTypeHeaderValue.TryParse(response.ContentType, out MediaTypeHeaderValue? contentType) || !string.Equals(contentType.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)) throw OAuthFailures.Rejected();
        try
        {
            using JsonDocument document = JsonDocument.Parse(response.Body, new JsonDocumentOptions { MaxDepth = 8 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("access_token", out JsonElement accessElement) || accessElement.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("token_type", out JsonElement typeElement) || typeElement.ValueKind != JsonValueKind.String ||
                !root.TryGetProperty("expires_in", out JsonElement expiryElement) || !expiryElement.TryGetInt64(out long expiresIn) || expiresIn is < 1 or > 604800)
                throw OAuthFailures.Rejected();
            string accessToken = accessElement.GetString()!;
            if (!BoundedSecret(accessToken, 16_384) || !string.Equals(typeElement.GetString(), "Bearer", StringComparison.OrdinalIgnoreCase)) throw OAuthFailures.Rejected();
            string? refreshToken = null;
            if (root.TryGetProperty("refresh_token", out JsonElement refreshElement))
            {
                if (refreshElement.ValueKind != JsonValueKind.String || !BoundedSecret(refreshElement.GetString(), 16_384)) throw OAuthFailures.Rejected();
                refreshToken = refreshElement.GetString();
            }
            DateTimeOffset expiresAt = clock.UtcNow + TimeSpan.FromSeconds(expiresIn);
            if (expiresAt <= clock.UtcNow + profile.ExpirySkew) throw OAuthFailures.Rejected();
            return new(accessToken, refreshToken, expiresAt);
        }
        catch (JsonException) { throw OAuthFailures.Rejected(); }
    }

    private TokenSession RequiredSession(OutboundAuthContext context, OAuthAuthorizationCodeProfile profile, OAuthTokenSessionReference reference)
    {
        if (reference is null || string.IsNullOrWhiteSpace(reference.Value) || reference.Value.Length > 128) throw OAuthFailures.Rejected();
        lock (sync)
        {
            if (!sessions.TryGetValue(reference.Value, out TokenSession? session) || session.SecurityKey != SecurityKey(context, profile) || session.ProfileFingerprint != profile.Fingerprint)
            {
                if (session is not null) RemoveSessionCore(reference.Value);
                throw OAuthFailures.ReacquisitionRequired();
            }
            return session;
        }
    }

    private void Validate(OutboundAuthContext context, OAuthAuthorizationCodeProfile profile)
    {
        context.Validate();
        if (context.Deadline <= clock.UtcNow || profile.Policy != HttpAuthenticationPolicy.OAuthAuthorizationCode) throw OAuthFailures.Rejected();
    }

    private async Task WriteAuditAsync(OutboundAuthContext context, OAuthAuthorizationCodeProfile profile, string action, string outcome, DateTimeOffset? expiresAt, CancellationToken cancellationToken) =>
        await audit.WriteAsync(new(context.CorrelationId, context.TenantId, context.ConnectorId, context.OperationId, profile.ProfileId, action, outcome, clock.UtcNow, expiresAt), cancellationToken).ConfigureAwait(false);

    private void Prune()
    {
        foreach ((string key, AuthorizationAttempt attempt) in attempts.Where(value => value.Value.ExpiresAt <= clock.UtcNow).ToArray())
        {
            CryptographicOperations.ZeroMemory(attempt.StateHash);
            attempts.Remove(key);
        }
        foreach (string key in sessions.Where(value => value.Value.Tokens.ExpiresAt <= clock.UtcNow && string.IsNullOrEmpty(value.Value.Tokens.RefreshToken)).Select(value => value.Key).ToArray()) RemoveSessionCore(key);
    }

    private void EnsureAttemptCapacity()
    {
        if (attempts.Count < attemptCapacity) return;
        KeyValuePair<string, AuthorizationAttempt> oldest = attempts.MinBy(value => value.Value.LastAccess);
        CryptographicOperations.ZeroMemory(oldest.Value.StateHash);
        attempts.Remove(oldest.Key);
    }

    private void EnsureTokenCapacity()
    {
        if (sessions.Count < tokenCapacity) return;
        string oldest = sessions.MinBy(value => value.Value.LastAccess).Key;
        RemoveSessionCore(oldest);
    }

    private void RemoveSession(string key) { lock (sync) RemoveSessionCore(key); }
    private void RemoveSessionCore(string key)
    {
        if (!sessions.Remove(key, out TokenSession? removed)) return;
        removed.Tokens = new(string.Empty, string.Empty, DateTimeOffset.MinValue);
    }

    private static Uri AuthorizationUri(OAuthAuthorizationCodeProfile profile, string state)
    {
        List<KeyValuePair<string, string?>> query =
        [
            new("response_type", "code"),
            new("client_id", profile.ClientId),
            new("redirect_uri", profile.RedirectUri.AbsoluteUri),
            new("scope", string.Join(' ', profile.Scopes)),
            new("state", state)
        ];
        if (profile.Audience is not null) query.Add(new("audience", profile.Audience));
        string encoded = string.Join('&', query.Select(value => Uri.EscapeDataString(value.Key) + "=" + Uri.EscapeDataString(value.Value!)));
        UriBuilder builder = new(profile.AuthorizationEndpoint) { Query = string.IsNullOrEmpty(profile.AuthorizationEndpoint.Query) ? encoded : profile.AuthorizationEndpoint.Query.TrimStart('?') + "&" + encoded };
        return builder.Uri;
    }

    private static string SecurityKey(OutboundAuthContext context, OAuthAuthorizationCodeProfile profile) => string.Join('\n', context.TenantId, context.InstallationId, context.ApplicationId, context.EnvironmentId, context.ConnectorVersionId, context.ConnectorVersion, context.ConnectorId, context.OperationId, context.AuthBindingRevision, context.EndpointRevision, profile.ClientId, string.Join(' ', profile.Scopes), profile.Audience ?? string.Empty, context.SecretRevision, context.ResourceStamp, profile.Fingerprint);
    private static string OpaqueValue() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Hash(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));
    private static bool BoundedSecret(string? value, int maximumLength) => !string.IsNullOrEmpty(value) && value.Length <= maximumLength && !value.Any(character => character is '\r' or '\n' or '\0');
    private static DateTimeOffset Min(DateTimeOffset left, DateTimeOffset right) => left <= right ? left : right;

    private sealed class AuthorizationAttempt(string securityKey, string profileFingerprint, byte[] stateHash, DateTimeOffset expiresAt, Guid correlationId, OAuthAuthorizationState state, DateTimeOffset lastAccess)
    {
        internal string SecurityKey { get; } = securityKey;
        internal string ProfileFingerprint { get; } = profileFingerprint;
        internal byte[] StateHash { get; } = stateHash;
        internal DateTimeOffset ExpiresAt { get; } = expiresAt;
        internal Guid CorrelationId { get; } = correlationId;
        internal OAuthAuthorizationState State { get; set; } = state;
        internal DateTimeOffset LastAccess { get; set; } = lastAccess;
    }

    private sealed class TokenSession(string securityKey, string profileFingerprint, string connectorId, TokenSet tokens, DateTimeOffset lastAccess)
    {
        internal string SecurityKey { get; } = securityKey;
        internal string ProfileFingerprint { get; } = profileFingerprint;
        internal string ConnectorId { get; } = connectorId;
        internal TokenSet Tokens { get; set; } = tokens;
        internal DateTimeOffset LastAccess { get; set; } = lastAccess;
        internal SemaphoreSlim RefreshGate { get; } = new(1, 1);
    }

    private sealed record TokenSet(string AccessToken, string? RefreshToken, DateTimeOffset ExpiresAt);
}

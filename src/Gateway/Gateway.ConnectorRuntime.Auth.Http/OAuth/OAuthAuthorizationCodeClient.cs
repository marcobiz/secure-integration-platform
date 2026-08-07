using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.Http;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OAuth;

/// <summary>Authorization Code, bounded token cache and endpoint-bound dispatch over restricted egress.</summary>
public sealed class OAuthAuthorizationCodeClient
{
    private readonly object sync = new();
    private readonly Dictionary<string, AuthorizationAttempt> attempts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, TokenSession> sessions = new(StringComparer.Ordinal);
    private readonly int attemptCapacity;
    private readonly int tokenCapacity;
    private readonly RestrictedEndpointPolicy endpoints;
    private readonly IRestrictedTransport transport;
    private readonly IGatewayClock clock;
    private readonly IOutboundAuthAuditSink audit;
    private long invalidationGeneration;

    /// <summary>Creates bounded stores. Secret use is available only through a resolved authority capability.</summary>
    public OAuthAuthorizationCodeClient(int attemptCapacity, int tokenCapacity, RestrictedEndpointPolicy endpoints, IRestrictedTransport transport, IGatewayClock clock, IOutboundAuthAuditSink? audit = null)
    {
        if (attemptCapacity is < 1 or > 100_000) throw new ArgumentOutOfRangeException(nameof(attemptCapacity));
        if (tokenCapacity is < 1 or > 100_000) throw new ArgumentOutOfRangeException(nameof(tokenCapacity));
        this.attemptCapacity = attemptCapacity;
        this.tokenCapacity = tokenCapacity;
        this.endpoints = endpoints;
        this.transport = transport;
        this.clock = clock;
        this.audit = audit ?? new NullOutboundAuthAuditSink();
    }

    /// <summary>Number of cached sessions; non-sensitive operational metadata.</summary>
    public int CachedSessionCount { get { lock (sync) return sessions.Count; } }

    /// <summary>Starts user-agent presentation without dereferencing the authorization URL server-side.</summary>
    public async Task<OAuthAuthorizationChallenge> BeginAuthorizationAsync(OAuthResolvedExecutionContext resolvedContext, CancellationToken cancellationToken)
    {
        Validate(resolvedContext);
        long generation = CurrentGeneration;
        await RevalidateAsync(resolvedContext, generation, cancellationToken).ConfigureAwait(false);
        _ = await endpoints.ResolveAsync(resolvedContext.Profile.AuthorizationEndpoint, cancellationToken).ConfigureAwait(false);
        await RevalidateAsync(resolvedContext, generation, cancellationToken).ConfigureAwait(false);

        OutboundAuthContext context = resolvedContext.Authority;
        OAuthAuthorizationCodeProfile profile = resolvedContext.Profile;
        string attemptReference = OpaqueValue();
        string state = OpaqueValue();
        DateTimeOffset expiresAt = Min(clock.UtcNow + profile.AuthorizationLifetime, context.Deadline);
        string key = SecurityKey(resolvedContext);
        lock (sync)
        {
            EnsureGeneration(generation);
            Prune();
            EnsureAttemptCapacity();
            attempts.Add(attemptReference, new(key, profile.Fingerprint, Hash(state), expiresAt, context.CorrelationId, OAuthAuthorizationState.Pending, clock.UtcNow));
        }
        Uri authorizationUri = AuthorizationUri(profile, state);
        try { await WriteAuditAsync(resolvedContext, "oauth.authorization.begin", "pending", expiresAt, cancellationToken).ConfigureAwait(false); }
        catch
        {
            lock (sync)
                if (attempts.Remove(attemptReference, out AuthorizationAttempt? removed)) CryptographicOperations.ZeroMemory(removed.StateHash);
            throw;
        }
        return new(attemptReference, authorizationUri, context.CorrelationId, expiresAt);
    }

    /// <summary>Returns only the state of an opaque attempt and enforces original correlation.</summary>
    public OAuthAuthorizationState PollAuthorization(OAuthResolvedExecutionContext resolvedContext, string opaqueAttemptReference)
    {
        Validate(resolvedContext);
        OutboundAuthContext context = resolvedContext.Authority;
        OAuthAuthorizationCodeProfile profile = resolvedContext.Profile;
        lock (sync)
        {
            if (!attempts.TryGetValue(opaqueAttemptReference, out AuthorizationAttempt? attempt) || attempt.SecurityKey != SecurityKey(resolvedContext) ||
                attempt.ProfileFingerprint != profile.Fingerprint || attempt.CorrelationId != context.CorrelationId)
                throw OAuthFailures.Rejected();
            if (attempt.ExpiresAt <= clock.UtcNow && attempt.State == OAuthAuthorizationState.Pending) attempt.State = OAuthAuthorizationState.Expired;
            attempt.LastAccess = clock.UtcNow;
            return attempt.State;
        }
    }

    /// <summary>Consumes callback code/state once and exchanges through restricted egress.</summary>
    public async Task<OAuthTokenSessionReference> CompleteAuthorizationAsync(OAuthResolvedExecutionContext resolvedContext, string opaqueAttemptReference, string code, string state, CancellationToken cancellationToken)
    {
        Validate(resolvedContext);
        if (!BoundedSecret(code, 8192) || !BoundedSecret(state, 1024)) throw OAuthFailures.Rejected();
        OutboundAuthContext context = resolvedContext.Authority;
        OAuthAuthorizationCodeProfile profile = resolvedContext.Profile;
        AuthorizationAttempt attempt;
        long generation = CurrentGeneration;
        lock (sync)
        {
            if (!attempts.TryGetValue(opaqueAttemptReference, out attempt!) || attempt.SecurityKey != SecurityKey(resolvedContext) || attempt.ProfileFingerprint != profile.Fingerprint ||
                attempt.CorrelationId != context.CorrelationId || attempt.State != OAuthAuthorizationState.Pending)
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
            attempt.State = OAuthAuthorizationState.Failed;
        }

        string? createdSessionReference = null;
        try
        {
            TokenSet tokens = await RequestTokenAsync(resolvedContext, "authorization_code", code, generation, cancellationToken).ConfigureAwait(false);
            await RevalidateAsync(resolvedContext, generation, cancellationToken).ConfigureAwait(false);
            string sessionReference = OpaqueValue();
            createdSessionReference = sessionReference;
            TokenSession session = new(SecurityKey(resolvedContext), profile.Fingerprint, context.ConnectorId, tokens, clock.UtcNow, generation);
            lock (sync)
            {
                EnsureGeneration(generation);
                Prune();
                EnsureTokenCapacity();
                sessions.Add(sessionReference, session);
                attempt.State = OAuthAuthorizationState.Completed;
                CryptographicOperations.ZeroMemory(attempt.StateHash);
            }
            await WriteAuditAsync(resolvedContext, "oauth.authorization.complete", "success", tokens.ExpiresAt, cancellationToken).ConfigureAwait(false);
            return new(sessionReference);
        }
        catch
        {
            lock (sync)
            {
                attempt.State = OAuthAuthorizationState.Failed;
                if (createdSessionReference is not null) RemoveSessionCore(createdSessionReference);
            }
            try { await WriteAuditAsync(resolvedContext, "oauth.authorization.complete", "denied", null, CancellationToken.None).ConfigureAwait(false); }
            catch { }
            throw;
        }
    }

    /// <summary>Builds, authenticates and dispatches exactly one request to the Published protected-resource endpoint.</summary>
    public async Task<ExternalResponse> SendAuthenticatedAsync(OAuthResolvedExecutionContext resolvedContext, OAuthTokenSessionReference sessionReference, ReadOnlyMemory<byte> requestPayload, CancellationToken cancellationToken)
    {
        Validate(resolvedContext);
        long generation = CurrentGeneration;
        TokenSession session = RequiredSession(resolvedContext, sessionReference, generation);
        await session.RefreshGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            session = RequiredSession(resolvedContext, sessionReference, generation);
            await RevalidateAsync(resolvedContext, generation, cancellationToken).ConfigureAwait(false);
            OAuthAuthorizationCodeProfile profile = resolvedContext.Profile;
            if (session.Tokens.ExpiresAt <= clock.UtcNow + profile.ExpirySkew)
            {
                if (!profile.AllowRefresh || string.IsNullOrEmpty(session.Tokens.RefreshToken))
                {
                    Invalidate(sessionReference);
                    throw OAuthFailures.ReacquisitionRequired();
                }
                try
                {
                    TokenSet refreshed = await RequestTokenAsync(resolvedContext, "refresh_token", session.Tokens.RefreshToken, generation, cancellationToken).ConfigureAwait(false);
                    if (string.IsNullOrEmpty(refreshed.RefreshToken)) refreshed = refreshed.WithRefreshToken(session.Tokens.RefreshToken);
                    await RevalidateAsync(resolvedContext, generation, cancellationToken).ConfigureAwait(false);
                    lock (sync)
                    {
                        EnsureCurrentSession(sessionReference.Value, session, generation);
                        session.Tokens = refreshed;
                        session.LastAccess = clock.UtcNow;
                    }
                    await WriteAuditAsync(resolvedContext, "oauth.token.refresh", "success", refreshed.ExpiresAt, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    Invalidate(sessionReference);
                    try { await WriteAuditAsync(resolvedContext, "oauth.token.refresh", "denied", null, CancellationToken.None).ConfigureAwait(false); }
                    catch { }
                    throw;
                }
            }

            IReadOnlyList<System.Net.IPAddress> addresses = await endpoints.ResolveAsync(resolvedContext.ProtectedResourceEndpoint, cancellationToken).ConfigureAwait(false);
            await RevalidateAsync(resolvedContext, generation, cancellationToken).ConfigureAwait(false);
            string accessToken;
            lock (sync)
            {
                EnsureCurrentSession(sessionReference.Value, session, generation);
                accessToken = session.Tokens.AccessToken;
                session.LastAccess = clock.UtcNow;
            }
            using HttpRequestMessage request = new(resolvedContext.ProtectedResourceMethod, resolvedContext.ProtectedResourceEndpoint);
            if (!requestPayload.IsEmpty)
            {
                request.Content = new ByteArrayContent(requestPayload.ToArray());
                if (!string.IsNullOrWhiteSpace(resolvedContext.ProtectedResourceContentType)) request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(resolvedContext.ProtectedResourceContentType);
            }
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            EnsureGeneration(generation);
            return await transport.SendAsync(request, addresses, null, resolvedContext.ProtectedResourceTimeout, resolvedContext.MaximumProtectedResourceResponseBytes, cancellationToken).ConfigureAwait(false);
        }
        finally { session.RefreshGate.Release(); }
    }

    /// <summary>Invalidates an opaque token session and tombstones in-flight refresh results.</summary>
    public void Invalidate(OAuthTokenSessionReference sessionReference)
    {
        ArgumentNullException.ThrowIfNull(sessionReference);
        Interlocked.Increment(ref invalidationGeneration);
        lock (sync) RemoveSessionCore(sessionReference.Value);
    }

    /// <summary>Invalidates matching sessions and tombstones in-flight acquisition/refresh work.</summary>
    public void InvalidateConnector(string connectorId)
    {
        Interlocked.Increment(ref invalidationGeneration);
        lock (sync)
            foreach (string key in sessions.Where(value => string.Equals(value.Value.ConnectorId, connectorId, StringComparison.Ordinal)).Select(value => value.Key).ToArray()) RemoveSessionCore(key);
    }

    private async Task<TokenSet> RequestTokenAsync(OAuthResolvedExecutionContext resolvedContext, string grantType, string sensitiveValue, long generation, CancellationToken cancellationToken)
    {
        OAuthAuthorizationCodeProfile profile = resolvedContext.Profile;
        await RevalidateAsync(resolvedContext, generation, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<System.Net.IPAddress> addresses = await endpoints.ResolveAsync(profile.TokenEndpoint, cancellationToken).ConfigureAwait(false);
        await RevalidateAsync(resolvedContext, generation, cancellationToken).ConfigureAwait(false);
        string clientSecret;
        try { clientSecret = await resolvedContext.ClientSecret.UseAsync(cancellationToken).ConfigureAwait(false); }
        catch (Exception exception) when (exception is not OperationCanceledException) { throw OAuthFailures.Rejected(); }
        await RevalidateAsync(resolvedContext, generation, cancellationToken).ConfigureAwait(false);
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
        try { response = await transport.SendAsync(request, addresses, null, profile.TokenRequestTimeout, profile.MaximumTokenResponseBytes, cancellationToken).ConfigureAwait(false); }
        catch (GatewayException) { throw; }
        catch (Exception exception) when (exception is not OperationCanceledException) { throw OAuthFailures.Rejected(); }
        await RevalidateAsync(resolvedContext, generation, cancellationToken).ConfigureAwait(false);
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

    private TokenSession RequiredSession(OAuthResolvedExecutionContext resolvedContext, OAuthTokenSessionReference reference, long generation)
    {
        ArgumentNullException.ThrowIfNull(reference);
        OutboundAuthContext context = resolvedContext.Authority;
        OAuthAuthorizationCodeProfile profile = resolvedContext.Profile;
        lock (sync)
        {
            if (!sessions.TryGetValue(reference.Value, out TokenSession? session) || session.SecurityKey != SecurityKey(resolvedContext) || session.ProfileFingerprint != profile.Fingerprint || session.Generation != generation)
            {
                if (session is not null) RemoveSessionCore(reference.Value);
                throw OAuthFailures.ReacquisitionRequired();
            }
            return session;
        }
    }

    private void Validate(OAuthResolvedExecutionContext resolvedContext)
    {
        ArgumentNullException.ThrowIfNull(resolvedContext);
        if (resolvedContext.Authority.Deadline <= clock.UtcNow || resolvedContext.Profile.Policy != HttpAuthenticationPolicy.OAuthAuthorizationCode) throw OAuthFailures.Rejected();
    }

    private async Task RevalidateAsync(OAuthResolvedExecutionContext resolvedContext, long generation, CancellationToken cancellationToken)
    {
        EnsureGeneration(generation);
        await resolvedContext.Revalidate(cancellationToken).ConfigureAwait(false);
        EnsureGeneration(generation);
    }

    private async Task WriteAuditAsync(OAuthResolvedExecutionContext resolvedContext, string action, string outcome, DateTimeOffset? expiresAt, CancellationToken cancellationToken)
    {
        OutboundAuthContext context = resolvedContext.Authority;
        await audit.WriteAsync(new(context.CorrelationId, context.TenantId, context.ConnectorId, context.OperationId, resolvedContext.Profile.ProfileId, action, outcome, clock.UtcNow, expiresAt), cancellationToken).ConfigureAwait(false);
    }

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
        RemoveSessionCore(sessions.MinBy(value => value.Value.LastAccess).Key);
    }

    private void EnsureCurrentSession(string reference, TokenSession expected, long generation)
    {
        EnsureGeneration(generation);
        if (!sessions.TryGetValue(reference, out TokenSession? current) || !ReferenceEquals(current, expected) || current.Generation != generation) throw OAuthFailures.ReacquisitionRequired();
    }

    private void RemoveSessionCore(string key)
    {
        if (!sessions.Remove(key, out TokenSession? removed)) return;
        removed.Tokens.Redact();
        removed.Disabled = true;
    }

    private long CurrentGeneration => Interlocked.Read(ref invalidationGeneration);
    private void EnsureGeneration(long generation) { if (CurrentGeneration != generation) throw OAuthFailures.ReacquisitionRequired(); }

    private static Uri AuthorizationUri(OAuthAuthorizationCodeProfile profile, string state)
    {
        List<KeyValuePair<string, string>> query = ParseExistingQuery(profile.AuthorizationEndpoint.Query);
        query.Add(new("response_type", "code"));
        query.Add(new("client_id", profile.ClientId));
        query.Add(new("redirect_uri", profile.RedirectUri.AbsoluteUri));
        query.Add(new("scope", string.Join(' ', profile.Scopes)));
        query.Add(new("state", state));
        if (profile.Audience is not null) query.Add(new("audience", profile.Audience));
        string encoded = string.Join('&', query.Select(value => Uri.EscapeDataString(value.Key) + "=" + Uri.EscapeDataString(value.Value)));
        return new UriBuilder(profile.AuthorizationEndpoint) { Query = encoded }.Uri;
    }

    private static List<KeyValuePair<string, string>> ParseExistingQuery(string query)
    {
        if (string.IsNullOrEmpty(query)) return [];
        return query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries).Select(pair =>
        {
            string[] parts = pair.Split('=', 2);
            return new KeyValuePair<string, string>(Decode(parts[0]), parts.Length == 2 ? Decode(parts[1]) : string.Empty);
        }).OrderBy(value => value.Key, StringComparer.Ordinal).ThenBy(value => value.Value, StringComparer.Ordinal).ToList();
    }

    private static string Decode(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));
    private static string SecurityKey(OAuthResolvedExecutionContext resolvedContext)
    {
        OutboundAuthContext context = resolvedContext.Authority;
        OAuthAuthorizationCodeProfile profile = resolvedContext.Profile;
        return string.Join('\n', context.TenantId, context.InstallationId, context.ApplicationId, context.EnvironmentId,
        context.ConnectorVersionId, context.ConnectorVersion, context.ConnectorId, context.OperationId, context.AuthBindingRevision, context.EndpointRevision, profile.ClientId, string.Join(' ', profile.Scopes),
        profile.Audience ?? string.Empty, context.SecretRevision, context.ResourceStamp, resolvedContext.ProtectedResourceEndpoint.AbsoluteUri, resolvedContext.ProtectedResourceMethod.Method, profile.Fingerprint);
    }
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
        public override string ToString() => $"AuthorizationAttempt(State={State}, ExpiresAt={ExpiresAt:O})";
    }

    private sealed class TokenSession(string securityKey, string profileFingerprint, string connectorId, TokenSet tokens, DateTimeOffset lastAccess, long generation)
    {
        internal string SecurityKey { get; } = securityKey;
        internal string ProfileFingerprint { get; } = profileFingerprint;
        internal string ConnectorId { get; } = connectorId;
        internal TokenSet Tokens { get; set; } = tokens;
        internal DateTimeOffset LastAccess { get; set; } = lastAccess;
        internal long Generation { get; } = generation;
        internal bool Disabled { get; set; }
        internal SemaphoreSlim RefreshGate { get; } = new(1, 1);
        public override string ToString() => $"TokenSession(ConnectorId={ConnectorId}, Disabled={Disabled})";
    }

    private sealed class TokenSet(string accessToken, string? refreshToken, DateTimeOffset expiresAt)
    {
        [JsonIgnore] internal string AccessToken { get; private set; } = accessToken;
        [JsonIgnore] internal string? RefreshToken { get; private set; } = refreshToken;
        internal DateTimeOffset ExpiresAt { get; } = expiresAt;
        internal TokenSet WithRefreshToken(string value) => new(AccessToken, value, ExpiresAt);
        internal void Redact() { AccessToken = string.Empty; RefreshToken = string.Empty; }
        public override string ToString() => $"TokenSet(ExpiresAt={ExpiresAt:O}, Redacted=True)";
    }
}

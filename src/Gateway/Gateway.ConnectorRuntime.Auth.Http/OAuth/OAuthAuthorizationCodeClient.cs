using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.Http;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OAuth;

/// <summary>Authorization Code, bounded token cache and endpoint-bound dispatch over restricted egress.</summary>
public sealed class OAuthAuthorizationCodeClient : IDisposable
{
    private readonly object sync = new();
    private readonly Dictionary<string, AuthorizationAttempt> attempts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, TokenSession> sessions = new(StringComparer.Ordinal);
    private readonly Dictionary<string, AcquisitionGate> acquisitionGates = new(StringComparer.Ordinal);
    private readonly Dictionary<string, GenerationState> keyGenerations = new(StringComparer.Ordinal);
    private readonly Dictionary<string, GenerationState> connectorGenerations = new(StringComparer.Ordinal);
    private readonly int attemptCapacity;
    private readonly int tokenCapacity;
    private readonly RestrictedEndpointPolicy endpoints;
    private readonly IRestrictedTransport transport;
    private readonly IGatewayClock clock;
    private readonly IOutboundAuthAuditSink audit;
    private int disposed;

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

    /// <summary>Releases local synchronization primitives after the owning host stops using this client.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        lock (sync)
        {
            foreach (AuthorizationAttempt attempt in attempts.Values) attempt.Redact();
            attempts.Clear();
            foreach (TokenSession session in sessions.Values)
            {
                session.Tokens.Redact();
                session.RefreshGate.Dispose();
            }
            sessions.Clear();
            foreach (AcquisitionGate gate in acquisitionGates.Values) gate.Semaphore.Dispose();
            acquisitionGates.Clear();
            keyGenerations.Clear();
            connectorGenerations.Clear();
        }
    }

    /// <summary>Starts user-agent presentation without dereferencing the authorization URL server-side.</summary>
    public async Task<OAuthAuthorizationChallenge> BeginAuthorizationAsync(OAuthResolvedExecutionContext resolvedContext, CancellationToken cancellationToken)
    {
        Validate(resolvedContext);
        using WorkStamp stamp = CaptureStamp(resolvedContext);
        await RevalidateAsync(resolvedContext, stamp, cancellationToken).ConfigureAwait(false);
        OAuthAuthorizationCodeProfile profile = RequiredAuthorizationCodeProfile(resolvedContext);
        _ = await endpoints.ResolveAsync(profile.AuthorizationEndpoint, cancellationToken).ConfigureAwait(false);
        await RevalidateAsync(resolvedContext, stamp, cancellationToken).ConfigureAwait(false);

        OutboundAuthContext context = resolvedContext.Authority;
        string attemptReference = OpaqueValue();
        string state = OpaqueValue();
        byte[]? codeVerifier = profile.PkcePolicy == OAuthPkcePolicy.S256Required ? PkceVerifier() : null;
        string? codeChallenge = codeVerifier is null ? null : Base64Url(SHA256.HashData(codeVerifier));
        DateTimeOffset expiresAt = Min(clock.UtcNow + profile.AuthorizationLifetime, context.Deadline);
        string key = SecurityKey(resolvedContext);
        lock (sync)
        {
            EnsureStamp(stamp);
            Prune();
            EnsureAttemptCapacity();
            attempts.Add(attemptReference, new(key, context.ConnectorId, stamp.KeyGeneration, stamp.ConnectorGeneration, profile.Fingerprint, Hash(state), codeVerifier, expiresAt, context.CorrelationId, OAuthAuthorizationState.Pending, clock.UtcNow));
        }
        Uri authorizationUri = AuthorizationUri(profile, state, codeChallenge);
        try { await WriteAuditAsync(resolvedContext, "oauth.authorization.begin", "pending", expiresAt, cancellationToken).ConfigureAwait(false); }
        catch
        {
            lock (sync)
                if (attempts.Remove(attemptReference, out AuthorizationAttempt? removed)) removed.Redact();
            throw;
        }
        return new(attemptReference, authorizationUri, context.CorrelationId, expiresAt);
    }

    /// <summary>Returns only the state of an opaque attempt and enforces original correlation.</summary>
    public OAuthAuthorizationState PollAuthorization(OAuthResolvedExecutionContext resolvedContext, string opaqueAttemptReference)
    {
        Validate(resolvedContext);
        OutboundAuthContext context = resolvedContext.Authority;
        OAuthAuthorizationCodeProfile profile = RequiredAuthorizationCodeProfile(resolvedContext);
        lock (sync)
        {
            if (!attempts.TryGetValue(opaqueAttemptReference, out AuthorizationAttempt? attempt) || attempt.SecurityKey != SecurityKey(resolvedContext) ||
                attempt.ProfileFingerprint != profile.Fingerprint || attempt.CorrelationId != context.CorrelationId)
                throw OAuthFailures.Rejected();
            if (attempt.ExpiresAt <= clock.UtcNow && attempt.State == OAuthAuthorizationState.Pending)
            {
                attempt.State = OAuthAuthorizationState.Expired;
                attempt.Redact();
            }
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
        OAuthAuthorizationCodeProfile profile = RequiredAuthorizationCodeProfile(resolvedContext);
        AuthorizationAttempt attempt;
        string? codeVerifier = null;
        using WorkStamp stamp = CaptureStamp(resolvedContext);
        lock (sync)
        {
            if (!attempts.TryGetValue(opaqueAttemptReference, out attempt!) || attempt.SecurityKey != stamp.SecurityKey || attempt.ProfileFingerprint != profile.Fingerprint ||
                attempt.KeyGeneration != stamp.KeyGeneration || attempt.ConnectorGeneration != stamp.ConnectorGeneration ||
                attempt.CorrelationId != context.CorrelationId || attempt.State != OAuthAuthorizationState.Pending)
                throw OAuthFailures.Rejected();
            if (attempt.ExpiresAt <= clock.UtcNow)
            {
                attempt.State = OAuthAuthorizationState.Expired;
                attempt.Redact();
                throw OAuthFailures.Rejected();
            }
            byte[] presentedStateHash = Hash(state);
            bool stateAccepted = CryptographicOperations.FixedTimeEquals(attempt.StateHash, presentedStateHash);
            CryptographicOperations.ZeroMemory(presentedStateHash);
            if (!stateAccepted)
            {
                attempt.State = OAuthAuthorizationState.Failed;
                attempt.Redact();
                throw OAuthFailures.Rejected();
            }
            if (profile.PkcePolicy == OAuthPkcePolicy.S256Required)
            {
                if (!OAuthValidation.PkceVerifier(attempt.CodeVerifier))
                {
                    attempt.State = OAuthAuthorizationState.Failed;
                    attempt.Redact();
                    throw OAuthFailures.Rejected();
                }
                codeVerifier = Encoding.ASCII.GetString(attempt.CodeVerifier!);
            }
            attempt.State = OAuthAuthorizationState.Failed;
        }

        string? createdSessionReference = null;
        try
        {
            TokenSet tokens = await RequestTokenAsync(resolvedContext, "authorization_code", code, codeVerifier, stamp, cancellationToken).ConfigureAwait(false);
            await RevalidateAsync(resolvedContext, stamp, cancellationToken).ConfigureAwait(false);
            string sessionReference = OpaqueValue();
            createdSessionReference = sessionReference;
            TokenSession session = new(stamp.SecurityKey, profile.Fingerprint, context.ConnectorId, profile.Policy, tokens, clock.UtcNow, stamp.KeyGeneration, stamp.ConnectorGeneration);
            lock (sync)
            {
                EnsureStamp(stamp);
                Prune();
                EnsureTokenCapacity();
                sessions.Add(sessionReference, session);
                attempt.State = OAuthAuthorizationState.Completed;
                attempt.Redact();
            }
            await WriteAuditAsync(resolvedContext, "oauth.authorization.complete", "success", tokens.ExpiresAt, cancellationToken).ConfigureAwait(false);
            return new(sessionReference);
        }
        catch
        {
            lock (sync)
            {
                attempt.State = OAuthAuthorizationState.Failed;
                attempt.Redact();
                if (createdSessionReference is not null) RemoveSessionCore(createdSessionReference);
            }
            try { await WriteAuditAsync(resolvedContext, "oauth.authorization.complete", "denied", null, CancellationToken.None).ConfigureAwait(false); }
            catch { }
            throw;
        }
    }

    /// <summary>Acquires or reuses a server-owned Client Credentials token session through the shared bounded cache.</summary>
    public async Task<OAuthTokenSessionReference> AcquireClientCredentialsAsync(OAuthResolvedExecutionContext resolvedContext, CancellationToken cancellationToken)
    {
        Validate(resolvedContext);
        OAuthClientCredentialsProfile profile = RequiredClientCredentialsProfile(resolvedContext);
        using WorkStamp stamp = CaptureStamp(resolvedContext);
        string? createdSessionReference = null;
        AcquisitionGate acquisitionGate = LeaseAcquisitionGate(stamp.SecurityKey);
        bool entered = false;
        try
        {
            await acquisitionGate.Semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            await RevalidateAsync(resolvedContext, stamp, cancellationToken).ConfigureAwait(false);
            lock (sync)
            {
                Prune();
                KeyValuePair<string, TokenSession>? cached = FindClientCredentialsSession(stamp.SecurityKey, profile.Fingerprint, stamp);
                if (cached is not null && cached.Value.Value.Tokens.ExpiresAt > clock.UtcNow + profile.ExpirySkew)
                {
                    cached.Value.Value.LastAccess = clock.UtcNow;
                    return new(cached.Value.Key);
                }
                if (cached is not null) RemoveSessionCore(cached.Value.Key);
            }

            TokenSet tokens = await RequestTokenAsync(resolvedContext, "client_credentials", null, null, stamp, cancellationToken).ConfigureAwait(false);
            await RevalidateAsync(resolvedContext, stamp, cancellationToken).ConfigureAwait(false);
            string sessionReference = OpaqueValue();
            createdSessionReference = sessionReference;
            TokenSession session = new(stamp.SecurityKey, profile.Fingerprint, resolvedContext.ConnectorId, profile.Policy, tokens, clock.UtcNow, stamp.KeyGeneration, stamp.ConnectorGeneration);
            lock (sync)
            {
                EnsureStamp(stamp);
                Prune();
                EnsureTokenCapacity();
                sessions.Add(sessionReference, session);
            }
            await WriteAuditAsync(resolvedContext, "oauth.client-credentials.acquire", "success", tokens.ExpiresAt, cancellationToken).ConfigureAwait(false);
            return new(sessionReference);
        }
        catch
        {
            if (createdSessionReference is not null)
                lock (sync) RemoveSessionCore(createdSessionReference);
            try { await WriteAuditAsync(resolvedContext, "oauth.client-credentials.acquire", "denied", null, CancellationToken.None).ConfigureAwait(false); }
            catch { }
            throw;
        }
        finally
        {
            if (entered) acquisitionGate.Semaphore.Release();
            ReleaseAcquisitionGate(stamp.SecurityKey, acquisitionGate);
        }
    }

    /// <summary>Builds, authenticates and dispatches exactly one request to the Published protected-resource endpoint.</summary>
    public async Task<ExternalResponse> SendAuthenticatedAsync(OAuthResolvedExecutionContext resolvedContext, OAuthTokenSessionReference sessionReference, ReadOnlyMemory<byte> requestPayload, CancellationToken cancellationToken)
    {
        Validate(resolvedContext);
        using WorkStamp stamp = CaptureStamp(resolvedContext);
        TokenSession session = RequiredSession(resolvedContext, sessionReference, stamp);
        await session.RefreshGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            session = RequiredSession(resolvedContext, sessionReference, stamp);
            await RevalidateAsync(resolvedContext, stamp, cancellationToken).ConfigureAwait(false);
            IOAuthProfile profile = resolvedContext.Profile;
            if (session.Tokens.ExpiresAt <= clock.UtcNow + profile.ExpirySkew)
            {
                if (profile is OAuthClientCredentialsProfile)
                {
                    try
                    {
                        TokenSet reacquired = await RequestTokenAsync(resolvedContext, "client_credentials", null, null, stamp, cancellationToken).ConfigureAwait(false);
                        await RevalidateAsync(resolvedContext, stamp, cancellationToken).ConfigureAwait(false);
                        lock (sync)
                        {
                            EnsureCurrentSession(sessionReference.Value, session, stamp);
                            session.Tokens.Redact();
                            session.Tokens = reacquired;
                            session.LastAccess = clock.UtcNow;
                        }
                        await WriteAuditAsync(resolvedContext, "oauth.client-credentials.reacquire", "success", reacquired.ExpiresAt, cancellationToken).ConfigureAwait(false);
                    }
                    catch
                    {
                        Invalidate(sessionReference);
                        try { await WriteAuditAsync(resolvedContext, "oauth.client-credentials.reacquire", "denied", null, CancellationToken.None).ConfigureAwait(false); }
                        catch { }
                        throw;
                    }
                }
                else if (profile is not OAuthAuthorizationCodeProfile authorizationCode || !authorizationCode.AllowRefresh || string.IsNullOrEmpty(session.Tokens.RefreshToken))
                {
                    Invalidate(sessionReference);
                    throw OAuthFailures.ReacquisitionRequired();
                }
                else try
                {
                    TokenSet refreshed = await RequestTokenAsync(resolvedContext, "refresh_token", session.Tokens.RefreshToken, null, stamp, cancellationToken).ConfigureAwait(false);
                    if (string.IsNullOrEmpty(refreshed.RefreshToken)) refreshed = refreshed.WithRefreshToken(session.Tokens.RefreshToken);
                    await RevalidateAsync(resolvedContext, stamp, cancellationToken).ConfigureAwait(false);
                    lock (sync)
                    {
                        EnsureCurrentSession(sessionReference.Value, session, stamp);
                        session.Tokens.Redact();
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
            await RevalidateAsync(resolvedContext, stamp, cancellationToken).ConfigureAwait(false);
            string accessToken;
            lock (sync)
            {
                EnsureCurrentSession(sessionReference.Value, session, stamp);
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
            EnsureStamp(stamp);
            return await transport.SendAsync(request, addresses, null, resolvedContext.ProtectedResourceTimeout, resolvedContext.MaximumProtectedResourceResponseBytes, cancellationToken).ConfigureAwait(false);
        }
        finally { session.RefreshGate.Release(); }
    }

    /// <summary>Invalidates an opaque token session and tombstones in-flight refresh results.</summary>
    public void Invalidate(OAuthTokenSessionReference sessionReference)
    {
        ArgumentNullException.ThrowIfNull(sessionReference);
        lock (sync)
        {
            if (!sessions.TryGetValue(sessionReference.Value, out TokenSession? session)) return;
            RequiredGenerationState(keyGenerations, session.SecurityKey).Generation++;
            foreach (string key in sessions.Where(value => value.Value.SecurityKey == session.SecurityKey).Select(value => value.Key).ToArray()) RemoveSessionCore(key);
            CleanupGenerationStatesCore(session.SecurityKey, session.ConnectorId);
        }
    }

    /// <summary>Invalidates matching sessions and tombstones in-flight acquisition/refresh work.</summary>
    public void InvalidateConnector(string connectorId)
    {
        if (!OAuthValidation.Identifier(connectorId)) throw OAuthFailures.Configuration();
        lock (sync)
        {
            RequiredGenerationState(connectorGenerations, connectorId).Generation++;
            foreach (string key in sessions.Where(value => string.Equals(value.Value.ConnectorId, connectorId, StringComparison.Ordinal)).Select(value => value.Key).ToArray()) RemoveSessionCore(key);
            foreach (string key in attempts.Where(value => string.Equals(value.Value.ConnectorId, connectorId, StringComparison.Ordinal)).Select(value => value.Key).ToArray())
            {
                attempts[key].Redact();
                attempts.Remove(key);
            }
            CleanupGenerationStatesCore(null, connectorId);
        }
    }

    private async Task<TokenSet> RequestTokenAsync(OAuthResolvedExecutionContext resolvedContext, string grantType, string? sensitiveValue, string? codeVerifier, WorkStamp stamp, CancellationToken cancellationToken)
    {
        IOAuthProfile profile = resolvedContext.Profile;
        await RevalidateAsync(resolvedContext, stamp, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<System.Net.IPAddress> addresses = await endpoints.ResolveAsync(profile.TokenEndpoint, cancellationToken).ConfigureAwait(false);
        await RevalidateAsync(resolvedContext, stamp, cancellationToken).ConfigureAwait(false);
        string clientSecret;
        try { clientSecret = await resolvedContext.ClientSecret.UseAsync(cancellationToken).ConfigureAwait(false); }
        catch (Exception exception) when (exception is not OperationCanceledException) { throw OAuthFailures.Rejected(); }
        await RevalidateAsync(resolvedContext, stamp, cancellationToken).ConfigureAwait(false);
        if (!BoundedSecret(clientSecret, 4096)) throw OAuthFailures.Rejected();
        Dictionary<string, string> form = new(StringComparer.Ordinal) { ["grant_type"] = grantType, ["client_id"] = profile.ClientId };
        bool allowRefreshToken;
        if (grantType == "authorization_code" && profile is OAuthAuthorizationCodeProfile authorizationCode && BoundedSecret(sensitiveValue, 8192))
        {
            form["code"] = sensitiveValue!;
            form["redirect_uri"] = authorizationCode.RedirectUri.AbsoluteUri;
            if (authorizationCode.PkcePolicy == OAuthPkcePolicy.S256Required)
            {
                if (!OAuthValidation.PkceVerifier(codeVerifier)) throw OAuthFailures.Rejected();
                form["code_verifier"] = codeVerifier!;
            }
            else if (codeVerifier is not null) throw OAuthFailures.Rejected();
            allowRefreshToken = authorizationCode.AllowRefresh;
        }
        else if (grantType == "refresh_token" && profile is OAuthAuthorizationCodeProfile refreshProfile && refreshProfile.AllowRefresh && BoundedSecret(sensitiveValue, 16_384))
        {
            form["refresh_token"] = sensitiveValue!;
            allowRefreshToken = true;
        }
        else if (grantType == "client_credentials" && profile is OAuthClientCredentialsProfile && sensitiveValue is null && codeVerifier is null)
        {
            form["scope"] = string.Join(' ', profile.Scopes);
            if (profile.Audience is not null) form["audience"] = profile.Audience;
            if (profile.Resource is not null) form["resource"] = profile.Resource;
            allowRefreshToken = false;
        }
        else throw OAuthFailures.Rejected();
        using HttpRequestMessage request = new(HttpMethod.Post, profile.TokenEndpoint) { Content = new FormUrlEncodedContent(form) };
        if (profile.ClientAuthenticationMethod != OAuthClientAuthenticationMethod.ClientSecretBasic) throw OAuthFailures.Rejected();
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(FormEncode(profile.ClientId) + ":" + FormEncode(clientSecret))));
        ExternalResponse response;
        try { response = await transport.SendAsync(request, addresses, null, profile.TokenRequestTimeout, profile.MaximumTokenResponseBytes, cancellationToken).ConfigureAwait(false); }
        catch (GatewayException) { throw; }
        catch (Exception exception) when (exception is not OperationCanceledException) { throw OAuthFailures.Rejected(); }
        try
        {
            await RevalidateAsync(resolvedContext, stamp, cancellationToken).ConfigureAwait(false);
            if (response.StatusCode is < 200 or >= 300) throw OAuthFailures.Rejected();
            return ParseToken(response, profile, allowRefreshToken);
        }
        finally { CryptographicOperations.ZeroMemory(response.Body); }
    }

    private TokenSet ParseToken(ExternalResponse response, IOAuthProfile profile, bool allowRefreshToken)
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
                if (!allowRefreshToken || refreshElement.ValueKind != JsonValueKind.String || !BoundedSecret(refreshElement.GetString(), 16_384)) throw OAuthFailures.Rejected();
                refreshToken = refreshElement.GetString();
            }
            DateTimeOffset expiresAt = clock.UtcNow + TimeSpan.FromSeconds(expiresIn);
            if (expiresAt <= clock.UtcNow + profile.ExpirySkew) throw OAuthFailures.Rejected();
            return new(accessToken, refreshToken, expiresAt);
        }
        catch (JsonException) { throw OAuthFailures.Rejected(); }
    }

    private TokenSession RequiredSession(OAuthResolvedExecutionContext resolvedContext, OAuthTokenSessionReference reference, WorkStamp stamp)
    {
        ArgumentNullException.ThrowIfNull(reference);
        IOAuthProfile profile = resolvedContext.Profile;
        lock (sync)
        {
            EnsureStampCore(stamp);
            if (!sessions.TryGetValue(reference.Value, out TokenSession? session) || session.SecurityKey != stamp.SecurityKey || session.ProfileFingerprint != profile.Fingerprint ||
                session.Policy != profile.Policy || session.KeyGeneration != stamp.KeyGeneration || session.ConnectorGeneration != stamp.ConnectorGeneration)
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
        if (resolvedContext.Authority.Deadline <= clock.UtcNow || resolvedContext.Profile.Policy is not (HttpAuthenticationPolicy.OAuthAuthorizationCode or HttpAuthenticationPolicy.OAuthClientCredentials))
            throw OAuthFailures.Rejected();
    }

    private async Task RevalidateAsync(OAuthResolvedExecutionContext resolvedContext, WorkStamp stamp, CancellationToken cancellationToken)
    {
        EnsureStamp(stamp);
        await resolvedContext.Revalidate(cancellationToken).ConfigureAwait(false);
        EnsureStamp(stamp);
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
            attempt.Redact();
            attempts.Remove(key);
            CleanupGenerationStatesCore(attempt.SecurityKey, attempt.ConnectorId);
        }
        foreach (string key in sessions.Where(value => value.Value.Tokens.ExpiresAt <= clock.UtcNow && string.IsNullOrEmpty(value.Value.Tokens.RefreshToken)).Select(value => value.Key).ToArray()) RemoveSessionCore(key);
    }

    private void EnsureAttemptCapacity()
    {
        if (attempts.Count < attemptCapacity) return;
        KeyValuePair<string, AuthorizationAttempt> oldest = attempts.MinBy(value => value.Value.LastAccess);
        oldest.Value.Redact();
        attempts.Remove(oldest.Key);
    }

    private void EnsureTokenCapacity()
    {
        if (sessions.Count < tokenCapacity) return;
        RemoveSessionCore(sessions.MinBy(value => value.Value.LastAccess).Key);
    }

    private void EnsureCurrentSession(string reference, TokenSession expected, WorkStamp stamp)
    {
        EnsureStampCore(stamp);
        if (!sessions.TryGetValue(reference, out TokenSession? current) || !ReferenceEquals(current, expected) ||
            current.KeyGeneration != stamp.KeyGeneration || current.ConnectorGeneration != stamp.ConnectorGeneration) throw OAuthFailures.ReacquisitionRequired();
    }

    private void RemoveSessionCore(string key)
    {
        if (!sessions.Remove(key, out TokenSession? removed)) return;
        removed.Tokens.Redact();
        removed.Disabled = true;
        CleanupGenerationStatesCore(removed.SecurityKey, removed.ConnectorId);
    }

    private WorkStamp CaptureStamp(OAuthResolvedExecutionContext resolvedContext)
    {
        string securityKey = SecurityKey(resolvedContext);
        string connectorId = resolvedContext.ConnectorId;
        lock (sync)
        {
            GenerationState keyState = RequiredGenerationState(keyGenerations, securityKey);
            GenerationState connectorState = RequiredGenerationState(connectorGenerations, connectorId);
            keyState.Leases++;
            connectorState.Leases++;
            return new(this, securityKey, connectorId, keyState.Generation, connectorState.Generation);
        }
    }

    private void EnsureStamp(WorkStamp stamp) { lock (sync) EnsureStampCore(stamp); }
    private void EnsureStampCore(WorkStamp stamp)
    {
        if (CurrentKeyGenerationCore(stamp.SecurityKey) != stamp.KeyGeneration || CurrentConnectorGenerationCore(stamp.ConnectorId) != stamp.ConnectorGeneration)
            throw OAuthFailures.ReacquisitionRequired();
    }

    private long CurrentKeyGenerationCore(string securityKey) => keyGenerations.TryGetValue(securityKey, out GenerationState? value) ? value.Generation : 0;
    private long CurrentConnectorGenerationCore(string connectorId) => connectorGenerations.TryGetValue(connectorId, out GenerationState? value) ? value.Generation : 0;

    private static GenerationState RequiredGenerationState(Dictionary<string, GenerationState> values, string key)
    {
        if (!values.TryGetValue(key, out GenerationState? state))
        {
            state = new();
            values.Add(key, state);
        }
        return state;
    }

    private void ReleaseStamp(WorkStamp stamp)
    {
        lock (sync)
        {
            if (keyGenerations.TryGetValue(stamp.SecurityKey, out GenerationState? keyState)) keyState.Leases--;
            if (connectorGenerations.TryGetValue(stamp.ConnectorId, out GenerationState? connectorState)) connectorState.Leases--;
            CleanupGenerationStatesCore(stamp.SecurityKey, stamp.ConnectorId);
        }
    }

    private void CleanupGenerationStatesCore(string? securityKey, string connectorId)
    {
        if (securityKey is not null && keyGenerations.TryGetValue(securityKey, out GenerationState? keyState) && keyState.Leases == 0 &&
            !sessions.Values.Any(value => value.SecurityKey == securityKey) && !attempts.Values.Any(value => value.SecurityKey == securityKey))
            keyGenerations.Remove(securityKey);
        if (connectorGenerations.TryGetValue(connectorId, out GenerationState? connectorState) && connectorState.Leases == 0 &&
            !sessions.Values.Any(value => value.ConnectorId == connectorId) && !attempts.Values.Any(value => value.ConnectorId == connectorId))
            connectorGenerations.Remove(connectorId);
    }

    private AcquisitionGate LeaseAcquisitionGate(string securityKey)
    {
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed != 0, this);
            if (!acquisitionGates.TryGetValue(securityKey, out AcquisitionGate? gate))
            {
                if (acquisitionGates.Count >= tokenCapacity) throw OAuthFailures.Rejected();
                gate = new();
                acquisitionGates.Add(securityKey, gate);
            }
            gate.Leases++;
            return gate;
        }
    }

    private void ReleaseAcquisitionGate(string securityKey, AcquisitionGate gate)
    {
        lock (sync)
        {
            gate.Leases--;
            if (gate.Leases == 0 && acquisitionGates.Remove(securityKey, out AcquisitionGate? removed)) removed.Semaphore.Dispose();
        }
    }

    private static Uri AuthorizationUri(OAuthAuthorizationCodeProfile profile, string state, string? codeChallenge)
    {
        List<KeyValuePair<string, string>> query = ParseExistingQuery(profile.AuthorizationEndpoint.Query);
        query.Add(new("response_type", "code"));
        query.Add(new("client_id", profile.ClientId));
        query.Add(new("redirect_uri", profile.RedirectUri.AbsoluteUri));
        query.Add(new("scope", string.Join(' ', profile.Scopes)));
        query.Add(new("state", state));
        if (profile.Audience is not null) query.Add(new("audience", profile.Audience));
        if (profile.PkcePolicy == OAuthPkcePolicy.S256Required)
        {
            if (!OAuthValidation.PkceChallenge(codeChallenge)) throw OAuthFailures.Rejected();
            query.Add(new("code_challenge", codeChallenge!));
            query.Add(new("code_challenge_method", "S256"));
        }
        else if (codeChallenge is not null) throw OAuthFailures.Rejected();
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
    private static string FormEncode(string value) => Uri.EscapeDataString(value).Replace("%20", "+", StringComparison.Ordinal);
    private static string SecurityKey(OAuthResolvedExecutionContext resolvedContext)
    {
        OutboundAuthContext context = resolvedContext.Authority;
        IOAuthProfile profile = resolvedContext.Profile;
        return string.Join('\n', context.TenantId, context.InstallationId, context.ApplicationId, context.EnvironmentId,
        context.ConnectorVersionId, context.ConnectorVersion, context.ConnectorId, context.OperationId, context.AuthBindingRevision, context.EndpointRevision, profile.Policy, profile.TokenEndpoint.AbsoluteUri,
        profile.ClientId, profile.ClientAuthenticationMethod, string.Join(' ', profile.Scopes), profile.Audience ?? string.Empty, profile.Resource ?? string.Empty, context.SecretRevision,
        context.ResourceStamp, resolvedContext.ProtectedResourceEndpoint.AbsoluteUri, resolvedContext.ProtectedResourceMethod.Method, profile.Fingerprint);
    }
    private static string OpaqueValue() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] PkceVerifier() => Encoding.ASCII.GetBytes(Base64Url(RandomNumberGenerator.GetBytes(32)));
    private static string Base64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Hash(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));
    private static bool BoundedSecret(string? value, int maximumLength) => !string.IsNullOrEmpty(value) && value.Length <= maximumLength && !value.Any(character => character is '\r' or '\n' or '\0');
    private static DateTimeOffset Min(DateTimeOffset left, DateTimeOffset right) => left <= right ? left : right;

    private static OAuthAuthorizationCodeProfile RequiredAuthorizationCodeProfile(OAuthResolvedExecutionContext resolvedContext) =>
        resolvedContext.Profile as OAuthAuthorizationCodeProfile ?? throw OAuthFailures.Rejected();

    private static OAuthClientCredentialsProfile RequiredClientCredentialsProfile(OAuthResolvedExecutionContext resolvedContext) =>
        resolvedContext.Profile as OAuthClientCredentialsProfile ?? throw OAuthFailures.Rejected();

    private KeyValuePair<string, TokenSession>? FindClientCredentialsSession(string securityKey, string profileFingerprint, WorkStamp stamp)
    {
        foreach (KeyValuePair<string, TokenSession> candidate in sessions)
            if (candidate.Value.Policy == HttpAuthenticationPolicy.OAuthClientCredentials && candidate.Value.SecurityKey == securityKey &&
                candidate.Value.ProfileFingerprint == profileFingerprint && candidate.Value.KeyGeneration == stamp.KeyGeneration &&
                candidate.Value.ConnectorGeneration == stamp.ConnectorGeneration) return candidate;
        return null;
    }

    private sealed class AuthorizationAttempt(string securityKey, string connectorId, long keyGeneration, long connectorGeneration, string profileFingerprint, byte[] stateHash, byte[]? codeVerifier, DateTimeOffset expiresAt, Guid correlationId, OAuthAuthorizationState state, DateTimeOffset lastAccess)
    {
        internal string SecurityKey { get; } = securityKey;
        internal string ConnectorId { get; } = connectorId;
        internal long KeyGeneration { get; } = keyGeneration;
        internal long ConnectorGeneration { get; } = connectorGeneration;
        internal string ProfileFingerprint { get; } = profileFingerprint;
        internal byte[] StateHash { get; } = stateHash;
        [JsonIgnore] internal byte[]? CodeVerifier { get; } = codeVerifier;
        internal DateTimeOffset ExpiresAt { get; } = expiresAt;
        internal Guid CorrelationId { get; } = correlationId;
        internal OAuthAuthorizationState State { get; set; } = state;
        internal DateTimeOffset LastAccess { get; set; } = lastAccess;
        internal void Redact()
        {
            CryptographicOperations.ZeroMemory(StateHash);
            if (CodeVerifier is not null) CryptographicOperations.ZeroMemory(CodeVerifier);
        }
        public override string ToString() => $"AuthorizationAttempt(State={State}, ExpiresAt={ExpiresAt:O})";
    }

    private sealed class TokenSession(string securityKey, string profileFingerprint, string connectorId, HttpAuthenticationPolicy policy, TokenSet tokens, DateTimeOffset lastAccess, long keyGeneration, long connectorGeneration)
    {
        internal string SecurityKey { get; } = securityKey;
        internal string ProfileFingerprint { get; } = profileFingerprint;
        internal string ConnectorId { get; } = connectorId;
        internal HttpAuthenticationPolicy Policy { get; } = policy;
        internal TokenSet Tokens { get; set; } = tokens;
        internal DateTimeOffset LastAccess { get; set; } = lastAccess;
        internal long KeyGeneration { get; } = keyGeneration;
        internal long ConnectorGeneration { get; } = connectorGeneration;
        internal bool Disabled { get; set; }
        internal SemaphoreSlim RefreshGate { get; } = new(1, 1);
        public override string ToString() => $"TokenSession(ConnectorId={ConnectorId}, Disabled={Disabled})";
    }

    private sealed class AcquisitionGate
    {
        internal SemaphoreSlim Semaphore { get; } = new(1, 1);
        internal int Leases { get; set; }
    }

    private sealed class GenerationState
    {
        internal long Generation { get; set; }
        internal int Leases { get; set; }
    }

    private sealed class WorkStamp(OAuthAuthorizationCodeClient owner, string securityKey, string connectorId, long keyGeneration, long connectorGeneration) : IDisposable
    {
        private int disposed;
        internal string SecurityKey { get; } = securityKey;
        internal string ConnectorId { get; } = connectorId;
        internal long KeyGeneration { get; } = keyGeneration;
        internal long ConnectorGeneration { get; } = connectorGeneration;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0) owner.ReleaseStamp(this);
        }
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

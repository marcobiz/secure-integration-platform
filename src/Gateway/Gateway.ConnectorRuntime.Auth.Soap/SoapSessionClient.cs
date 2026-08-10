using System.Net;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>
/// Executes the fixed Basic/SOAP/session lifecycle for a compiled connector profile.
/// Upstream credentials and session values never leave this component.
/// </summary>
public sealed class SoapSessionClient
{
    private readonly ServerBoundBasicAuthentication basicAuthentication;
    private readonly IHostResolver resolver;
    private readonly IRestrictedTransport transport;
    private readonly IGatewayClock clock;
    private readonly ISoapSessionResourceStampProvider resourceStamps;
    private readonly IPrivateDestinationAllowance? privateDestinationAllowance;
    private readonly Func<CancellationToken, Task>? beforeAdmissionPromotion;
    private readonly Func<CancellationToken, Task>? beforeHandshakeFinalAuthorization;
    private readonly SoapSessionCache cache = new();
    private readonly SemaphoreSlim[] acquisitionLocks = Enumerable.Range(0, 64).Select(_ => new SemaphoreSlim(1, 1)).ToArray();

    /// <summary>Creates the session client from provider-neutral secret and restricted-egress capabilities.</summary>
    public SoapSessionClient(ISecretValueProvider secrets, IHostResolver resolver, IRestrictedTransport transport, IGatewayClock clock, ISoapSessionResourceStampProvider resourceStamps, IPrivateDestinationAllowance? privateDestinationAllowance = null)
    {
        basicAuthentication = new ServerBoundBasicAuthentication(secrets ?? throw new ArgumentNullException(nameof(secrets)));
        this.resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.resourceStamps = resourceStamps ?? throw new ArgumentNullException(nameof(resourceStamps));
        this.privateDestinationAllowance = privateDestinationAllowance;
        beforeAdmissionPromotion = null;
        beforeHandshakeFinalAuthorization = null;
        OpaqueSessionLeases = new SoapOpaqueSessionLeaseProvider(cache);
    }

    internal SoapSessionClient(
        ISecretValueProvider secrets,
        IHostResolver resolver,
        IRestrictedTransport transport,
        IGatewayClock clock,
        ISoapSessionResourceStampProvider resourceStamps,
        IPrivateDestinationAllowance? privateDestinationAllowance,
        Func<CancellationToken, Task>? beforeAdmissionPromotion,
        Func<CancellationToken, Task>? beforeHandshakeFinalAuthorization = null)
        : this(secrets, resolver, transport, clock, resourceStamps, privateDestinationAllowance)
    {
        this.beforeAdmissionPromotion = beforeAdmissionPromotion;
        this.beforeHandshakeFinalAuthorization = beforeHandshakeFinalAuthorization;
    }

    /// <summary>Controlled adapter from the qualified SOAP lifecycle to provider-neutral opaque-session capabilities.</summary>
    public OpaqueSessionLeaseProvider OpaqueSessionLeases { get; }

    internal int CachedSessionCount => cache.CurrentSessionCount;

    /// <summary>
    /// Runs one server-resolved typed handshake. The request/response adapters and all wire authority are selected
    /// by the Published profile; caller business fields are not accepted by this boundary.
    /// </summary>
    public async Task<TypedSessionHandshakeResult> AcquireTypedSessionAsync(
        ResolvedTypedSessionHandshake resolvedHandshake,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolvedHandshake);
        TypedSessionHandshakeAuthorityState expected = resolvedHandshake.State;
        TypedSessionHandshakeAuthorityState current = await RevalidateTypedAsync(resolvedHandshake, expected, cancellationToken).ConfigureAwait(false);
        await ValidateResourceStampAsync(current.ExecutionContext, cancellationToken).ConfigureAwait(false);
        (OpaqueSoapSessionReference Reference, DateTimeOffset ExpiresAt)? cached = cache.ResolveCurrentMetadata(current.CacheKey, clock.UtcNow);
        if (cached is not null)
            return new(TypedSessionHandshakeResultKind.Issued, cached.Value.Reference, null, null, cached.Value.ExpiresAt, null);

        SemaphoreSlim gate = AcquisitionLock(current.CacheKey);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            current = await RevalidateTypedAsync(resolvedHandshake, expected, cancellationToken).ConfigureAwait(false);
            await ValidateResourceStampAsync(current.ExecutionContext, cancellationToken).ConfigureAwait(false);
            cached = cache.ResolveCurrentMetadata(current.CacheKey, clock.UtcNow);
            if (cached is not null)
                return new(TypedSessionHandshakeResultKind.Issued, cached.Value.Reference, null, null, cached.Value.ExpiresAt, null);

            TypedSessionHandshakeAdapterOutcome outcome = await SendTypedHandshakeAsync(resolvedHandshake, expected, current, cancellationToken).ConfigureAwait(false);
            current = await RevalidateTypedAsync(resolvedHandshake, expected, cancellationToken).ConfigureAwait(false);
            await ValidateResourceStampAsync(current.ExecutionContext, cancellationToken).ConfigureAwait(false);
            DateTimeOffset now = clock.UtcNow;
            if (outcome is TypedSessionIssuedAdapterOutcome issued)
            {
                DateTimeOffset expiresAt = ComputeExpiry(now, current.LocalMaximumSessionLifetime, issued.RemoteExpiry);
                OpaqueSoapSessionReference session = cache.Store(current.CacheKey, issued.SensitiveSessionValue, now, expiresAt);
                return new(TypedSessionHandshakeResultKind.Issued, session, null, null, expiresAt, null);
            }
            if (outcome is TypedExternalAdmissionRequiredAdapterOutcome admission)
            {
                if (current.AdmissionValidationAdapter is null || current.AdmissionEndpoint is null || current.AdmissionOperation is null)
                    throw TypedSessionHandshakeFailures.AdmissionNotSupported();
                DateTimeOffset expiresAt = now.Add(current.AdmissionIntentLifetime);
                ExternalSessionAdmissionIntent intent = cache.StoreAdmissionIntent(current.CacheKey, current.SecurityFingerprint,
                    current.ExecutionContext.OperationId, current.ProfileId, admission.Provenance, now, expiresAt);
                return new(TypedSessionHandshakeResultKind.ExternalAdmissionRequired, null, intent, null, expiresAt, admission.Provenance);
            }
            if (outcome is TypedSessionRejectedAdapterOutcome rejected)
                return new(TypedSessionHandshakeResultKind.Rejected, null, null, rejected.Rejection, null, null);
            throw TypedSessionHandshakeFailures.AdapterRejected();
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>
    /// Consumes one single-use admission intent and sensitive presentation candidate, validates it through the
    /// Published typed validator, revalidates all authority, then atomically promotes it into the existing cache.
    /// </summary>
    internal ExternalAdmissionPresentation ResolveAdmissionPresentation(GatewayClientPrincipal principal, string intentReference) =>
        cache.ResolveAdmissionPresentation(intentReference, principal, clock.UtcNow);

    internal async Task<TypedSessionHandshakeResult> CompleteExternalAdmissionAsync(
        ResolvedTypedSessionHandshake resolvedHandshake,
        ExternalAdmissionPresentation presentation,
        ExternalSessionCandidate candidate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolvedHandshake);
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(candidate);
        TypedSessionHandshakeAuthorityState expected = resolvedHandshake.State;
        AdmissionCompletion? completion = null;
        bool promoted = false;
        try
        {
            TypedSessionHandshakeAuthorityState current = await RevalidateTypedAsync(resolvedHandshake, expected, cancellationToken).ConfigureAwait(false);
            await ValidateResourceStampAsync(current.ExecutionContext, cancellationToken).ConfigureAwait(false);
            if (current.AdmissionValidationAdapter is null || current.AdmissionEndpoint is null || current.AdmissionOperation is null)
                throw TypedSessionHandshakeFailures.AdmissionNotSupported();
            if (presentation.Key != current.CacheKey || !string.Equals(presentation.OperationId, current.ExecutionContext.OperationId, StringComparison.Ordinal))
                throw TypedSessionHandshakeFailures.AdmissionIntentInvalid();
            AdmissionCompletion reserved = cache.BeginAdmission(presentation, current.SecurityFingerprint, clock.UtcNow);
            completion = reserved;

            ExternalSessionValidationResult validation;
            try
            {
                validation = await SendExternalValidationAsync(current, candidate, reserved.Provenance, cancellationToken).ConfigureAwait(false)
                    ?? throw TypedSessionHandshakeFailures.ValidationFailed();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw new OperationCanceledException(cancellationToken); }
            catch (OperationCanceledException) { throw TypedSessionHandshakeFailures.ValidationFailed(); }
            catch (SoapAuthException) { throw; }
            catch (Exception) { throw TypedSessionHandshakeFailures.ValidationFailed(); }
            if (validation.Status != ExternalSessionValidationStatus.Valid)
                throw validation.Status == ExternalSessionValidationStatus.Rejected
                    ? TypedSessionHandshakeFailures.ValidationRejected()
                    : TypedSessionHandshakeFailures.ValidationFailed();

            DateTimeOffset remoteExpiry = validation.RemoteExpiry ?? throw TypedSessionHandshakeFailures.RemoteExpiryInvalid();
            AdmissionValidationProof proof = new(reserved, candidate.DigestForValidationProof());
            SemaphoreSlim gate = AcquisitionLock(current.CacheKey);
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                // All asynchronous authority checks finish before the deterministic final-window hook.
                current = await RevalidateTypedAsync(resolvedHandshake, expected, cancellationToken).ConfigureAwait(false);
                await ValidateResourceStampAsync(current.ExecutionContext, cancellationToken).ConfigureAwait(false);
                if (beforeAdmissionPromotion is not null)
                    await beforeAdmissionPromotion(cancellationToken).ConfigureAwait(false);

                // No await is permitted between the mutation-authority CAS and cache generation promotion.
                DateTimeOffset now = clock.UtcNow;
                DateTimeOffset expiresAt = ComputeExpiry(now, current.LocalMaximumSessionLifetime, remoteExpiry);
                if (!current.MutationAuthority.TryPromoteIfCurrent(expected.AuthorityGeneration,
                        () => cache.CompleteAdmission(proof, candidate.DecodeForPromotion(), now, expiresAt),
                        out OpaqueSoapSessionReference? session) || session is null)
                    throw TypedSessionHandshakeFailures.AuthorityStale();
                promoted = true;
                return new(TypedSessionHandshakeResultKind.Issued, session, null, null, expiresAt, reserved.Provenance);
            }
            finally
            {
                gate.Release();
            }
        }
        finally
        {
            if (!promoted && completion is not null) cache.AbandonAdmission(completion);
            candidate.Dispose();
        }
    }

    /// <summary>Returns the current opaque session reference or performs one fixed login acquisition.</summary>
    public async Task<OpaqueSoapSessionReference> AcquireSessionAsync(ConnectorAuthExecutionContext context, SoapEndpointBinding endpoint, SoapSessionProfile profile, CancellationToken cancellationToken)
    {
        SoapSessionCacheKey key = ValidateAndKey(context, endpoint, profile);
        await ValidateResourceStampAsync(context, cancellationToken).ConfigureAwait(false);
        (OpaqueSoapSessionReference Reference, string UpstreamSession)? current = cache.ResolveCurrent(key, clock.UtcNow);
        if (current is not null) return current.Value.Reference;
        return await AcquireSessionCoreAsync(context, endpoint, profile, key, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Consumes an opaque one-time interaction state and completes the fixed upstream challenge operation.</summary>
    public async Task<OpaqueSoapSessionReference> CompleteInteractiveChallengeAsync(
        ConnectorAuthExecutionContext context,
        SoapEndpointBinding endpoint,
        SoapSessionProfile profile,
        string interactionReference,
        string userProvidedArtifact,
        CancellationToken cancellationToken)
    {
        SoapSessionCacheKey key = ValidateAndKey(context, endpoint, profile);
        await ValidateResourceStampAsync(context, cancellationToken).ConfigureAwait(false);
        SoapOperationProfile operation = profile.ChallengeCompletionOperation ?? throw new SoapAuthException("SOAP-INTERACTION-NOT-SUPPORTED");
        if (string.IsNullOrWhiteSpace(userProvidedArtifact) || userProvidedArtifact.Length > operation.RequestFields[profile.ChallengeArtifactField!].MaximumCharacters)
            throw new SoapAuthException("SOAP-INTERACTION-ARTIFACT-INVALID");
        InteractionCompletion completion = cache.BeginInteractionCompletion(key, interactionReference, clock.UtcNow);
        Dictionary<string, string> values = new(StringComparer.Ordinal)
        {
            [profile.ChallengeStateField!] = completion.UpstreamChallenge,
            [profile.ChallengeArtifactField!] = userProvidedArtifact
        };
        try
        {
            SoapDecodedResponse response = await SendAsync(context, endpoint, profile, operation, values, null, includeSessionExtraction: true, includeChallengeExtraction: false, cancellationToken).ConfigureAwait(false);
            if (response.SessionValue is null) throw new SoapAuthException("SOAP-SESSION-MISSING");
            DateTimeOffset now = clock.UtcNow;
            return cache.CompleteInteraction(completion, response.SessionValue, now, now.Add(profile.SessionLifetime));
        }
        catch
        {
            cache.AbandonInteraction(completion);
            throw;
        }
    }

    /// <summary>
    /// Invokes one profile-declared business operation with an internal session. On a recognized session fault,
    /// reacquisition and business retry occur at most once and only when the operation explicitly allows it.
    /// </summary>
    public async Task<SoapBusinessResult> InvokeAsync(
        ConnectorAuthExecutionContext context,
        SoapEndpointBinding endpoint,
        SoapSessionProfile profile,
        IReadOnlyDictionary<string, string> requestValues,
        OpaqueSoapSessionReference? sessionReference,
        CancellationToken cancellationToken)
    {
        SoapSessionCacheKey key = ValidateAndKey(context, endpoint, profile);
        await ValidateResourceStampAsync(context, cancellationToken).ConfigureAwait(false);
        if (!profile.BusinessOperations.TryGetValue(context.OperationId, out SoapOperationProfile? operation)) throw new SoapAuthException("SOAP-OPERATION-NOT-DECLARED");
        (OpaqueSoapSessionReference Reference, string UpstreamSession) session;
        if (sessionReference is not null)
        {
            string upstream = cache.Resolve(key, sessionReference, clock.UtcNow) ?? throw new SoapAuthException("SOAP-SESSION-INVALID");
            session = (sessionReference, upstream);
        }
        else
        {
            (OpaqueSoapSessionReference Reference, string UpstreamSession)? current = cache.ResolveCurrent(key, clock.UtcNow);
            if (current is null)
            {
                OpaqueSoapSessionReference acquired = await AcquireSessionCoreAsync(context, endpoint, profile, key, cancellationToken).ConfigureAwait(false);
                session = (acquired, cache.Resolve(key, acquired, clock.UtcNow) ?? throw new SoapAuthException("SOAP-SESSION-INVALID"));
            }
            else session = current.Value;
        }

        for (int attempt = 0; ; attempt++)
        {
            try
            {
                SoapDecodedResponse response = await SendAsync(context, endpoint, profile, operation, requestValues, session.UpstreamSession, includeSessionExtraction: false, includeChallengeExtraction: false, cancellationToken).ConfigureAwait(false);
                return new SoapBusinessResult(response.Values);
            }
            catch (SoapFaultException fault) when (fault.Category is SoapFaultCategory.SessionExpired or SoapFaultCategory.InvalidSession)
            {
                cache.Invalidate(key, session.Reference);
                if (attempt != 0 || !operation.RetryAfterSessionReacquisition) throw;
                OpaqueSoapSessionReference reacquired = await AcquireSessionCoreAsync(context, endpoint, profile, key, cancellationToken).ConfigureAwait(false);
                session = (reacquired, cache.Resolve(key, reacquired, clock.UtcNow) ?? throw new SoapAuthException("SOAP-SESSION-INVALID"));
            }
        }
    }

    /// <summary>Sends the fixed logout operation when declared, then always invalidates the local opaque session.</summary>
    public async Task LogoutAsync(ConnectorAuthExecutionContext context, SoapEndpointBinding endpoint, SoapSessionProfile profile, OpaqueSoapSessionReference sessionReference, CancellationToken cancellationToken)
    {
        SoapSessionCacheKey key = ValidateAndKey(context, endpoint, profile);
        try
        {
            await ValidateResourceStampAsync(context, cancellationToken).ConfigureAwait(false);
            string? session = cache.Resolve(key, sessionReference, clock.UtcNow);
            if (session is not null && profile.LogoutOperation is not null)
                _ = await SendAsync(context, endpoint, profile, profile.LogoutOperation, new Dictionary<string, string>(StringComparer.Ordinal), session, includeSessionExtraction: false, includeChallengeExtraction: false, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            cache.Invalidate(key, sessionReference);
        }
    }

    /// <summary>Invalidates a session without exposing or returning its upstream value.</summary>
    public void InvalidateSession(ConnectorAuthExecutionContext context, SoapEndpointBinding endpoint, SoapSessionProfile profile, OpaqueSoapSessionReference? sessionReference = null)
    {
        SoapSessionCacheKey key = ValidateAndKey(context, endpoint, profile);
        cache.Invalidate(key, sessionReference);
    }

    private async Task<OpaqueSoapSessionReference> AcquireSessionCoreAsync(ConnectorAuthExecutionContext context, SoapEndpointBinding endpoint, SoapSessionProfile profile, SoapSessionCacheKey key, CancellationToken cancellationToken)
    {
        SemaphoreSlim gate = AcquisitionLock(key);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await ValidateResourceStampAsync(context, cancellationToken).ConfigureAwait(false);
            (OpaqueSoapSessionReference Reference, string UpstreamSession)? current = cache.ResolveCurrent(key, clock.UtcNow);
            if (current is not null) return current.Value.Reference;
            SoapDecodedResponse response = await SendAsync(context, endpoint, profile, profile.LoginOperation, new Dictionary<string, string>(StringComparer.Ordinal), null, includeSessionExtraction: true, includeChallengeExtraction: true, cancellationToken).ConfigureAwait(false);
            if (response.SessionValue is not null)
            {
                DateTimeOffset now = clock.UtcNow;
                return cache.Store(key, response.SessionValue, now, now.Add(profile.SessionLifetime));
            }
            if (response.ChallengeValue is not null && profile.ChallengeCompletionOperation is not null)
            {
                DateTimeOffset now = clock.UtcNow;
                SoapInteractiveChallenge challenge = cache.StoreInteraction(key, response.ChallengeValue, now, now.Add(profile.InteractionLifetime));
                throw new SoapInteractionRequiredException(challenge);
            }
            throw new SoapAuthException("SOAP-SESSION-MISSING");
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<SoapDecodedResponse> SendAsync(
        ConnectorAuthExecutionContext context,
        SoapEndpointBinding endpoint,
        SoapSessionProfile profile,
        SoapOperationProfile operation,
        IReadOnlyDictionary<string, string> values,
        string? upstreamSession,
        bool includeSessionExtraction,
        bool includeChallengeExtraction,
        CancellationToken cancellationToken)
    {
        EnsureDeadline(context);
        await ValidateResourceStampAsync(context, cancellationToken).ConfigureAwait(false);
        byte[] envelope = SoapXmlBoundary.SerializeRequest(operation, values, upstreamSession is null ? null : profile.SessionHeaderElement, upstreamSession);
        using HttpRequestMessage request = new(HttpMethod.Post, endpoint.Endpoint);
        request.Headers.TryAddWithoutValidation("X-Correlation-ID", context.CorrelationId.ToString("D"));
        SoapXmlBoundary.ApplyHttpHeaders(request, operation, envelope);
        await basicAuthentication.ApplyAsync(request, profile.BasicCredential, cancellationToken).ConfigureAwait(false);
        IPAddress[] addresses = await resolver.ResolveAsync(endpoint.Endpoint.DnsSafeHost, cancellationToken).ConfigureAwait(false);
        if (addresses.Length == 0 || addresses.Any(address => RestrictedEgressService.IsForbiddenAddress(address) && privateDestinationAllowance?.IsAllowed(endpoint.Endpoint.DnsSafeHost, address) != true))
            throw new SoapAuthException("SOAP-EGRESS-DESTINATION-DENIED");

        TimeSpan configuredTimeout = TimeSpan.FromMilliseconds(operation.TimeoutMilliseconds);
        TimeSpan remaining = context.Deadline - clock.UtcNow;
        if (remaining <= TimeSpan.Zero) throw new SoapAuthException("SOAP-DEADLINE-EXPIRED");
        TimeSpan timeout = remaining < configuredTimeout ? remaining : configuredTimeout;
        using CancellationTokenSource effectiveDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        effectiveDeadline.CancelAfter(timeout);
        try
        {
            ExternalResponse response = await transport.SendSoapAsync(request, addresses, timeout, operation.MaximumResponseBytes, effectiveDeadline.Token).ConfigureAwait(false);
            return SoapXmlBoundary.ParseResponse(operation, response, includeSessionExtraction ? profile.SessionElement : null, includeChallengeExtraction ? profile.ChallengeElement : null, profile.FaultRules, effectiveDeadline.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new SoapAuthException("SOAP-TIMEOUT");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (effectiveDeadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested && exception is HttpRequestException or IOException)
        {
            throw new SoapAuthException("SOAP-TIMEOUT");
        }
        catch (SoapAuthException) { throw; }
        catch (GatewayException exception) when (string.Equals(exception.Code, "BGW-EGRESS-RESPONSE-TOO-LARGE", StringComparison.Ordinal))
        {
            throw new SoapAuthException("SOAP-RESPONSE-TOO-LARGE");
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or TimeoutException or GatewayException)
        {
            _ = exception;
            throw new SoapAuthException("SOAP-TRANSPORT-FAILED");
        }
    }

    private async Task<TypedSessionHandshakeAdapterOutcome> SendTypedHandshakeAsync(
        ResolvedTypedSessionHandshake resolvedHandshake,
        TypedSessionHandshakeAuthorityState expected,
        TypedSessionHandshakeAuthorityState state,
        CancellationToken cancellationToken)
    {
        ConnectorAuthExecutionContext context = state.ExecutionContext;
        SoapOperationProfile operation = state.Operation;
        EnsureDeadline(context);
        await ValidateResourceStampAsync(context, cancellationToken).ConfigureAwait(false);
        byte[] envelope = TypedSessionHandshakeXmlBoundary.SerializeRequest(state, cancellationToken);
        using HttpRequestMessage request = new(HttpMethod.Post, state.Endpoint.Endpoint);
        request.Headers.TryAddWithoutValidation("X-Correlation-ID", context.CorrelationId.ToString("D"));
        TypedSessionHandshakeXmlBoundary.ApplyHttpHeaders(request, operation, envelope);
        if (state.BasicCredential is not null)
            await basicAuthentication.ApplyAsync(request, state.BasicCredential, cancellationToken).ConfigureAwait(false);
        IPAddress[] addresses;
        try { addresses = await resolver.ResolveAsync(state.Endpoint.Endpoint.DnsSafeHost, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { throw new SoapAuthException("SOAP-EGRESS-DESTINATION-DENIED"); }
        if (addresses.Length == 0 || addresses.Any(address => RestrictedEgressService.IsForbiddenAddress(address) && privateDestinationAllowance?.IsAllowed(state.Endpoint.Endpoint.DnsSafeHost, address) != true))
            throw new SoapAuthException("SOAP-EGRESS-DESTINATION-DENIED");

        if (beforeHandshakeFinalAuthorization is not null)
            await beforeHandshakeFinalAuthorization(cancellationToken).ConfigureAwait(false);

        // Resource/provider/DNS preparation is complete. Revalidate the entire initially-authorized
        // Published authority immediately before the first network/session side effect.
        state = await RevalidateTypedAsync(resolvedHandshake, expected, cancellationToken).ConfigureAwait(false);
        await ValidateResourceStampAsync(state.ExecutionContext, cancellationToken).ConfigureAwait(false);
        state = await RevalidateTypedAsync(resolvedHandshake, expected, cancellationToken).ConfigureAwait(false);
        TimeSpan configuredTimeout = TimeSpan.FromMilliseconds(operation.TimeoutMilliseconds);
        TimeSpan remaining = context.Deadline - clock.UtcNow;
        if (remaining <= TimeSpan.Zero) throw new SoapAuthException("SOAP-DEADLINE-EXPIRED");
        TimeSpan timeout = remaining < configuredTimeout ? remaining : configuredTimeout;
        using CancellationTokenSource effectiveDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        effectiveDeadline.CancelAfter(timeout);
        try
        {
            ExternalResponse response = await transport.SendSoapAsync(request, addresses, timeout, operation.MaximumResponseBytes, effectiveDeadline.Token).ConfigureAwait(false);
            return TypedSessionHandshakeXmlBoundary.ParseResponse(state, response, effectiveDeadline.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw new SoapAuthException("SOAP-TIMEOUT"); }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (effectiveDeadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested && exception is HttpRequestException or IOException)
        {
            throw new SoapAuthException("SOAP-TIMEOUT");
        }
        catch (SoapAuthException) { throw; }
        catch (GatewayException exception) when (string.Equals(exception.Code, "BGW-EGRESS-RESPONSE-TOO-LARGE", StringComparison.Ordinal))
        {
            throw new SoapAuthException("SOAP-RESPONSE-TOO-LARGE");
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or TimeoutException or GatewayException)
        {
            _ = exception;
            throw new SoapAuthException("SOAP-TRANSPORT-FAILED");
        }
    }

    private async Task<ExternalSessionValidationResult> SendExternalValidationAsync(
        TypedSessionHandshakeAuthorityState state,
        ExternalSessionCandidate candidate,
        ExternalSessionProvenance provenance,
        CancellationToken cancellationToken)
    {
        ConnectorAuthExecutionContext context = state.ExecutionContext;
        SoapOperationProfile operation = state.AdmissionOperation ?? throw TypedSessionHandshakeFailures.AdmissionNotSupported();
        Uri endpoint = state.AdmissionEndpoint ?? throw TypedSessionHandshakeFailures.AdmissionNotSupported();
        EnsureDeadline(context);
        await ValidateResourceStampAsync(context, cancellationToken).ConfigureAwait(false);
        byte[] envelope = TypedSessionHandshakeXmlBoundary.SerializeValidationRequest(state, candidate, provenance, cancellationToken);
        using HttpRequestMessage request = new(HttpMethod.Post, endpoint);
        request.Headers.TryAddWithoutValidation("X-Correlation-ID", context.CorrelationId.ToString("D"));
        TypedSessionHandshakeXmlBoundary.ApplyHttpHeaders(request, operation, envelope);
        if (state.BasicCredential is not null)
            await basicAuthentication.ApplyAsync(request, state.BasicCredential, cancellationToken).ConfigureAwait(false);

        IPAddress[] addresses;
        try { addresses = await resolver.ResolveAsync(endpoint.DnsSafeHost, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw new OperationCanceledException(cancellationToken); }
        catch (OperationCanceledException) { throw TypedSessionHandshakeFailures.ValidationFailed(); }
        catch (Exception) { throw new SoapAuthException("SOAP-EGRESS-DESTINATION-DENIED"); }
        if (addresses.Length == 0 || addresses.Any(address => RestrictedEgressService.IsForbiddenAddress(address) && privateDestinationAllowance?.IsAllowed(endpoint.DnsSafeHost, address) != true))
            throw new SoapAuthException("SOAP-EGRESS-DESTINATION-DENIED");

        TimeSpan configuredTimeout = TimeSpan.FromMilliseconds(operation.TimeoutMilliseconds);
        TimeSpan remaining = context.Deadline - clock.UtcNow;
        if (remaining <= TimeSpan.Zero) throw new SoapAuthException("SOAP-DEADLINE-EXPIRED");
        TimeSpan timeout = remaining < configuredTimeout ? remaining : configuredTimeout;
        using CancellationTokenSource effectiveDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        effectiveDeadline.CancelAfter(timeout);
        try
        {
            ExternalResponse response = await transport.SendSoapAsync(request, addresses, timeout, operation.MaximumResponseBytes, effectiveDeadline.Token).ConfigureAwait(false);
            return TypedSessionHandshakeXmlBoundary.ParseValidationResponse(state, response, effectiveDeadline.Token);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw new OperationCanceledException(cancellationToken); }
        catch (OperationCanceledException) when (effectiveDeadline.IsCancellationRequested) { throw new SoapAuthException("SOAP-TIMEOUT"); }
        catch (OperationCanceledException) { throw TypedSessionHandshakeFailures.ValidationFailed(); }
        catch (Exception exception) when (effectiveDeadline.IsCancellationRequested && exception is HttpRequestException or IOException)
        {
            throw new SoapAuthException("SOAP-TIMEOUT");
        }
        catch (SoapAuthException) { throw; }
        catch (GatewayException exception) when (string.Equals(exception.Code, "BGW-EGRESS-RESPONSE-TOO-LARGE", StringComparison.Ordinal))
        {
            throw new SoapAuthException("SOAP-RESPONSE-TOO-LARGE");
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or TimeoutException or GatewayException)
        {
            _ = exception;
            throw TypedSessionHandshakeFailures.ValidationFailed();
        }
    }

    private static async Task<TypedSessionHandshakeAuthorityState> RevalidateTypedAsync(
        ResolvedTypedSessionHandshake resolvedHandshake,
        TypedSessionHandshakeAuthorityState expected,
        CancellationToken cancellationToken)
    {
        try
        {
            TypedSessionHandshakeAuthorityState current = await resolvedHandshake.Revalidate(cancellationToken).ConfigureAwait(false);
            if (!string.Equals(current.SecurityFingerprint, expected.SecurityFingerprint, StringComparison.Ordinal))
                throw TypedSessionHandshakeFailures.AuthorityStale();
            return current;
        }
        catch (OperationCanceledException) { throw; }
        catch (SoapAuthException) { throw; }
        catch (Exception) { throw TypedSessionHandshakeFailures.AuthorityRejected(); }
    }

    private static DateTimeOffset ComputeExpiry(DateTimeOffset now, TimeSpan localMaximum, DateTimeOffset? remoteExpiry)
    {
        DateTimeOffset localExpiry = now.Add(localMaximum);
        if (remoteExpiry is null) return localExpiry;
        DateTimeOffset remote = remoteExpiry.Value;
        if (remote <= now) throw TypedSessionHandshakeFailures.RemoteExpiryInvalid();
        return remote < localExpiry ? remote : localExpiry;
    }

    private SemaphoreSlim AcquisitionLock(SoapSessionCacheKey key) => acquisitionLocks[(key.GetHashCode() & int.MaxValue) % acquisitionLocks.Length];

    private SoapSessionCacheKey ValidateAndKey(ConnectorAuthExecutionContext context, SoapEndpointBinding endpoint, SoapSessionProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        return ValidateAndKey(context, endpoint, profile.ProfileId);
    }

    private SoapSessionCacheKey ValidateAndKey(ConnectorAuthExecutionContext context, SoapEndpointBinding endpoint, string profileId)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(endpoint);
        if (context.TenantId == Guid.Empty || context.InstallationId == Guid.Empty || context.ApplicationId == Guid.Empty || context.EnvironmentId == Guid.Empty || context.CorrelationId == Guid.Empty)
            throw new SoapAuthException("SOAP-CONTEXT-INVALID");
        if (!IsIdentifier(context.ConnectorId) || !IsIdentifier(context.ConnectorVersion) || !IsIdentifier(context.OperationId) || context.BindingRevision <= 0 || context.EndpointRevision <= 0 || context.CredentialRevision <= 0)
            throw new SoapAuthException("SOAP-CONTEXT-INVALID");
        if (!string.Equals(context.SessionProfileId, profileId, StringComparison.Ordinal) || context.EndpointRevision != endpoint.Revision)
            throw new SoapAuthException("SOAP-CONTEXT-BINDING-MISMATCH");
        EnsureDeadline(context);
        return new SoapSessionCacheKey(context.TenantId, context.InstallationId, context.ApplicationId, context.EnvironmentId, context.ConnectorId, context.ConnectorVersion, context.BindingRevision, context.EndpointRevision, context.CredentialRevision, context.SessionProfileId);
    }

    private async Task ValidateResourceStampAsync(ConnectorAuthExecutionContext context, CancellationToken cancellationToken)
    {
        SoapSessionResourceStamp? current;
        try
        {
            current = await resourceStamps.GetCurrentAsync(context, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception)
        {
            throw new SoapAuthException("SOAP-RESOURCE-STAMP-UNAVAILABLE");
        }
        if (current is null) throw new SoapAuthException("SOAP-RESOURCE-STAMP-UNAVAILABLE");
        if (current.CredentialStatus != SoapCredentialResourceStatus.Active) throw new SoapAuthException("SOAP-CREDENTIAL-INACTIVE");
        if (current.CredentialResourceRevision != context.CredentialRevision || current.BindingRevision != context.BindingRevision || current.EndpointRevision != context.EndpointRevision)
            throw new SoapAuthException("SOAP-RESOURCE-STAMP-STALE");
    }

    private void EnsureDeadline(ConnectorAuthExecutionContext context)
    {
        if (context.Deadline <= clock.UtcNow) throw new SoapAuthException("SOAP-DEADLINE-EXPIRED");
    }

    private static bool IsIdentifier(string value) => value.Length is > 0 and <= 100 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
}

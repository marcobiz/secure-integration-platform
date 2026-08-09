using System.Net;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>
/// Performs one closed Basic + SOAP HTTP metadata + opaque-session custom-header dispatch.
/// No authenticated request or raw session value is returned to the caller.
/// </summary>
public sealed class ComposedSoapAuthenticatedClient
{
    private readonly ServerBoundBasicAuthentication basicAuthentication;
    private readonly OpaqueSessionLeaseProvider sessions;
    private readonly IHostResolver resolver;
    private readonly IRestrictedTransport transport;
    private readonly IGatewayClock clock;
    private readonly IPrivateDestinationAllowance? privateDestinationAllowance;
    private readonly Func<CancellationToken, Task>? beforeFinalAuthorization;

    /// <summary>Creates the one-shot composed dispatcher from existing Core capabilities.</summary>
    public ComposedSoapAuthenticatedClient(
        ISecretValueProvider secrets,
        OpaqueSessionLeaseProvider sessions,
        IHostResolver resolver,
        IRestrictedTransport transport,
        IGatewayClock clock,
        IPrivateDestinationAllowance? privateDestinationAllowance = null)
        : this(secrets, sessions, resolver, transport, clock, privateDestinationAllowance, null)
    {
    }

    internal ComposedSoapAuthenticatedClient(
        ISecretValueProvider secrets,
        OpaqueSessionLeaseProvider sessions,
        IHostResolver resolver,
        IRestrictedTransport transport,
        IGatewayClock clock,
        IPrivateDestinationAllowance? privateDestinationAllowance,
        Func<CancellationToken, Task>? beforeFinalAuthorization)
    {
        basicAuthentication = new(secrets ?? throw new ArgumentNullException(nameof(secrets)));
        this.sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
        this.resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.privateDestinationAllowance = privateDestinationAllowance;
        this.beforeFinalAuthorization = beforeFinalAuthorization;
    }

    /// <summary>Validates, authenticates and sends one SOAP envelope without exposing an authenticated request.</summary>
    public async Task<ComposedSoapHttpResponse> SendAsync(
        ComposedSoapResolvedExecutionContext resolvedContext,
        ReadOnlyMemory<byte> soapEnvelope,
        OpaqueSessionReference sessionReference,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolvedContext);
        ArgumentNullException.ThrowIfNull(sessionReference);
        ComposedSoapAuthorityState expected = resolvedContext.State;
        EnsureDeadline(expected);

        // Caller-controlled XML is copied and hardened before credentials or final authority are acquired.
        byte[] envelope = SoapXmlBoundary.ValidateRequestEnvelope(soapEnvelope, expected.SoapHttp, expected.SessionAuthority.MaximumRequestBytes);
        using HttpRequestMessage outbound = new(HttpMethod.Post, expected.SessionAuthority.Endpoint);
        outbound.Headers.TryAddWithoutValidation("X-Correlation-ID", expected.SessionAuthority.CorrelationId.ToString("D"));
        expected.SoapHttp.Apply(outbound, envelope);

        IPAddress[] addresses;
        try { addresses = await resolver.ResolveAsync(expected.SessionAuthority.Endpoint.DnsSafeHost, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { throw new SoapAuthException("SOAP-EGRESS-DESTINATION-DENIED"); }
        if (addresses.Length == 0 || addresses.Any(address => RestrictedEgressService.IsForbiddenAddress(address) &&
            privateDestinationAllowance?.IsAllowed(expected.SessionAuthority.Endpoint.DnsSafeHost, address) != true))
            throw new SoapAuthException("SOAP-EGRESS-DESTINATION-DENIED");

        // Basic is server-resolved on the one internal request; a subsequent Published revalidation
        // rejects any credential rotation that occurred while the provider was awaited.
        await basicAuthentication.ApplyAsync(outbound, expected.BasicCredential, cancellationToken).ConfigureAwait(false);

        if (beforeFinalAuthorization is not null)
            await beforeFinalAuthorization(cancellationToken).ConfigureAwait(false);

        ComposedSoapAuthorityState current = await RevalidateAsync(resolvedContext, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(expected.SecurityFingerprint, current.SecurityFingerprint, StringComparison.Ordinal))
            throw new SoapAuthException("SOAP-AUTHORITY-STALE");
        EnsureDeadline(current);
        TimeSpan remaining = current.SessionAuthority.Deadline - clock.UtcNow;
        TimeSpan timeout = remaining < current.SessionAuthority.Timeout ? remaining : current.SessionAuthority.Timeout;
        if (timeout <= TimeSpan.Zero) throw new SoapAuthException("SOAP-DEADLINE-EXPIRED");
        using CancellationTokenSource effectiveDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        effectiveDeadline.CancelAfter(timeout);

        Task<ExternalResponse> dispatch;
        SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions.OpaqueSessionDispatchLease lease;
        try
        {
            // Final synchronous authorization section: no await or caller callback before SendSoapAsync.
            lease = sessions.AcquireFinalLease(sessionReference, current.SessionAuthority.LifecycleBinding, clock.UtcNow);
            string projected = current.SessionAuthority.Placement.Format(lease.UpstreamValue);
            if (outbound.Headers.Authorization is null || !string.Equals(outbound.Headers.Authorization.Scheme, "Basic", StringComparison.Ordinal) ||
                outbound.Headers.Contains(current.SessionAuthority.Placement.HeaderName) ||
                !outbound.Headers.TryAddWithoutValidation(current.SessionAuthority.Placement.HeaderName, projected) ||
                outbound.Headers.GetValues(current.SessionAuthority.Placement.HeaderName).Count() != 1)
                throw new SoapAuthException("SOAP-HTTP-POLICY-VIOLATION");
            current.SoapHttp.EnsureApplied(outbound);
            lease.EnsureCurrent(clock.UtcNow);
            dispatch = transport.SendSoapAsync(outbound, addresses, timeout, current.SessionAuthority.MaximumResponseBytes, effectiveDeadline.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw new SoapAuthException("SOAP-TIMEOUT"); }
        catch (OperationCanceledException) { throw; }
        catch (OpaqueSessionAuthException exception) { throw Map(exception); }
        catch (SoapAuthException) { throw; }
        catch (Exception exception) when (exception is HttpRequestException or IOException or TimeoutException or GatewayException)
        {
            _ = exception;
            throw new SoapAuthException("SOAP-TRANSPORT-FAILED");
        }

        try
        {
            ExternalResponse response = await dispatch.ConfigureAwait(false);
            ComposedSoapAuthorityState afterDispatch = await RevalidateAsync(resolvedContext, effectiveDeadline.Token).ConfigureAwait(false);
            EnsureDeadline(afterDispatch);
            lease.EnsureCurrent(clock.UtcNow);
            if (!string.Equals(current.SecurityFingerprint, afterDispatch.SecurityFingerprint, StringComparison.Ordinal))
                throw new SoapAuthException("SOAP-AUTHORITY-STALE");
            return new(response.StatusCode, response.ContentType, response.Body);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw new SoapAuthException("SOAP-TIMEOUT"); }
        catch (OperationCanceledException) { throw; }
        catch (OpaqueSessionAuthException exception) { throw Map(exception); }
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

    private static async Task<ComposedSoapAuthorityState> RevalidateAsync(ComposedSoapResolvedExecutionContext context, CancellationToken cancellationToken)
    {
        try { return await context.Revalidate(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (SoapAuthException) { throw; }
        catch (Exception) { throw new SoapAuthException("SOAP-AUTHORITY-REJECTED"); }
    }

    private void EnsureDeadline(ComposedSoapAuthorityState state)
    {
        if (state.SessionAuthority.Deadline <= clock.UtcNow) throw new SoapAuthException("SOAP-DEADLINE-EXPIRED");
    }

    private static SoapAuthException Map(OpaqueSessionAuthException exception) => exception.Code switch
    {
        "SESSION-HTTP-SESSION-INVALID" => new("SOAP-SESSION-INVALID"),
        "SESSION-HTTP-SESSION-STALE" => new("SOAP-SESSION-STALE"),
        "SESSION-HTTP-HEADER-FORBIDDEN" => new("SOAP-HTTP-POLICY-VIOLATION"),
        _ => new("SOAP-AUTHORITY-REJECTED")
    };
}

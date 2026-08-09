using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using SecureIntegration.Authentication.CertificateSigning;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

/// <summary>
/// Invocation-local composite authority registry. Only the Published resolver can create the authority it
/// accepts; connector consumers cannot register profiles, resources, endpoints or JWT material.
/// </summary>
public sealed class Fse2DispatchAuthorityRegistry
{
    private readonly PublishedConnectorFse2ProfileResolver resolver;
    private readonly ConcurrentDictionary<Guid, Fse2DispatchLease> leases = new();
    private readonly ConcurrentDictionary<HttpRequestMessage, Fse2PreparedDispatch> prepared = new();

    public Fse2DispatchAuthorityRegistry(PublishedConnectorFse2ProfileResolver resolver) => this.resolver = resolver;

    internal Fse2DispatchLease Begin(AuthorizedFse2Dispatch authority, Uri endpoint, IFse2DispatchTestHook? hook = null)
    {
        if (!Fse2OperationCatalog.MatchesEndpoint(authority.Profile.BaseEndpoint, authority.Profile.Authority.Operation, endpoint))
            throw new Fse2ConnectorException(Fse2ErrorCategory.DestinationDenied, "FSE2_ENDPOINT_AUTHORITY_DENIED");
        Fse2DispatchLease lease = new(Guid.NewGuid(), authority, endpoint, hook ?? NoOpFse2DispatchTestHook.Instance);
        if (!leases.TryAdd(lease.Id, lease)) throw new InvalidOperationException("FSE2_DISPATCH_ID_COLLISION");
        return lease;
    }

    internal AuthorizedFse2Dispatch GetRequired(AuthenticationExecutionContext context)
    {
        if (!leases.TryGetValue(context.CorrelationId, out Fse2DispatchLease? lease) ||
            context.TenantId != lease.Authority.Profile.Authority.TenantId ||
            context.ApplicationId != lease.Authority.Profile.Authority.ApplicationId ||
            context.InstallationId != lease.Authority.Profile.Authority.InstallationId ||
            context.EnvironmentId != lease.Authority.Profile.Authority.EnvironmentId ||
            context.ConnectorVersionId != lease.Authority.Profile.ConnectorVersionId ||
            !string.Equals(context.ConnectorId, lease.Authority.Profile.Authority.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(context.OperationId, lease.Authority.Operation.OperationId, StringComparison.Ordinal) ||
            context.Endpoint != lease.Endpoint)
            throw new AuthenticationPrimitiveException("BGW-AUTH-POLICY-BOUNDARY");
        return lease.Authority;
    }

    internal void Prepare(HttpRequestMessage request, Fse2DispatchLease lease, string authenticationJwt, string signatureJwt)
    {
        if (!leases.TryGetValue(lease.Id, out Fse2DispatchLease? current) || !ReferenceEquals(current, lease) ||
            request.RequestUri != lease.Endpoint || request.Headers.Authorization is not null || request.Headers.Contains("FSE-JWT-Signature") ||
            !prepared.TryAdd(request, new(lease, authenticationJwt, signatureJwt)))
            throw new AuthenticationPrimitiveException("FSE2_DISPATCH_PREPARATION_DENIED");
    }

    internal async Task<Fse2PreparedDispatch> FinalizeAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!prepared.TryGetValue(request, out Fse2PreparedDispatch? value) ||
            !leases.TryGetValue(value.Lease.Id, out Fse2DispatchLease? lease) || !ReferenceEquals(lease, value.Lease))
            throw new AuthenticationPrimitiveException("FSE2_DISPATCH_AUTHORITY_MISSING");
        await lease.Hook.BeforeFinalRevalidationAsync(cancellationToken).ConfigureAwait(false);
        try { await resolver.RevalidateAsync(lease.Authority, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { throw new AuthenticationPrimitiveException("FSE2_COMPOSITE_AUTHORITY_STALE"); }
        if (!Fse2OperationCatalog.MatchesEndpoint(lease.Authority.Profile.BaseEndpoint,
            lease.Authority.Profile.Authority.Operation, request.RequestUri!))
            throw new AuthenticationPrimitiveException("FSE2_ENDPOINT_AUTHORITY_DENIED");
        return value;
    }

    internal void Complete(Fse2DispatchLease lease, HttpRequestMessage? request = null)
    {
        leases.TryRemove(lease.Id, out _);
        if (request is not null) prepared.TryRemove(request, out _);
    }
}

internal sealed record Fse2DispatchLease(Guid Id, AuthorizedFse2Dispatch Authority, Uri Endpoint, IFse2DispatchTestHook Hook);
internal sealed record Fse2PreparedDispatch(Fse2DispatchLease Lease, string AuthenticationJwt, string SignatureJwt);

internal interface IFse2DispatchTestHook
{
    Task AfterBothJwtPreparedAsync(CancellationToken cancellationToken);
    Task BeforeFinalRevalidationAsync(CancellationToken cancellationToken);
}

internal sealed class NoOpFse2DispatchTestHook : IFse2DispatchTestHook
{
    internal static NoOpFse2DispatchTestHook Instance { get; } = new();
    public Task AfterBothJwtPreparedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task BeforeFinalRevalidationAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>
/// Last transport boundary: after Core has resolved and validated the mTLS material it revalidates the
/// complete FSE2 authority, then projects both JWT headers synchronously and invokes the network transport.
/// </summary>
public sealed class Fse2FinalAuthorityTransport(
    Fse2DispatchAuthorityRegistry dispatches,
    IPurposeBoundMutualTlsTransport inner) : IPurposeBoundMutualTlsTransport
{
    public async Task<MutualTlsTransportResponse> SendAsync(HttpRequestMessage request,
        IReadOnlyList<IPAddress> approvedAddresses, MutualTlsCertificateLease certificateLease,
        TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
    {
        Fse2PreparedDispatch prepared = await dispatches.FinalizeAsync(request, cancellationToken).ConfigureAwait(false);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", prepared.AuthenticationJwt);
        if (!request.Headers.TryAddWithoutValidation("FSE-JWT-Signature", prepared.SignatureJwt))
            throw new AuthenticationPrimitiveException("FSE2_DUAL_JWT_HEADER_FAILED");
        return await inner.SendAsync(request, approvedAddresses, certificateLease, timeout, maximumResponseBytes, cancellationToken)
            .ConfigureAwait(false);
    }
}

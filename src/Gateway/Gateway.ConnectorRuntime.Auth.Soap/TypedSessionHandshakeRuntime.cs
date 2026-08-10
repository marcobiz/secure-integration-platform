using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>
/// Authenticated runtime presentation boundary for typed session acquisition and external admission.
/// Completion accepts only the authenticated principal, an opaque intent reference and sensitive bytes.
/// </summary>
public sealed class TypedSessionHandshakeRuntime(
    IGatewayInvocationAuthorizer authorizer,
    PublishedTypedSessionHandshakeResolver resolver,
    SoapSessionClient sessions)
{
    /// <summary>Acquires or starts one Published typed session profile for an authorized operation.</summary>
    public async Task<TypedSessionHandshakeResult> AcquireAsync(
        GatewayClientPrincipal principal,
        string connectorId,
        string operationId,
        string profileId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        AuthorizedGatewayInvocation invocation = await authorizer.AuthorizeAsync(principal, connectorId, operationId, cancellationToken).ConfigureAwait(false);
        ResolvedTypedSessionHandshake resolved = await resolver.ResolveAsync(invocation, new(profileId), cancellationToken).ConfigureAwait(false);
        return await sessions.AcquireTypedSessionAsync(resolved, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<TypedSessionHandshakeResult> AcquireAuthorizedAsync(
        AuthorizedGatewayInvocation invocation,
        AuthorizedPublishedExecutionStamp publishedAuthority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        ArgumentNullException.ThrowIfNull(publishedAuthority);
        ResolvedTypedSessionHandshake resolved = await resolver.ResolveCurrentAsync(invocation, publishedAuthority, cancellationToken).ConfigureAwait(false);
        return await sessions.AcquireTypedSessionAsync(resolved, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Completes an opaque single-use intent. Connector, operation, profile, cache key, provenance,
    /// expiry, endpoint, adapter and credential authority are recovered exclusively from server state.
    /// </summary>
    public async Task<TypedSessionHandshakeResult> CompleteExternalAdmissionAsync(
        GatewayClientPrincipal principal,
        string intentReference,
        ReadOnlyMemory<byte> sensitiveCandidate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ExternalAdmissionPresentation presentation = sessions.ResolveAdmissionPresentation(principal, intentReference);
        AuthorizedGatewayInvocation invocation = await authorizer.AuthorizeAsync(principal, presentation.Key.ConnectorId, presentation.OperationId, cancellationToken).ConfigureAwait(false);
        ResolvedTypedSessionHandshake resolved = await resolver.ResolveAsync(invocation, new(presentation.Key.ProfileId), cancellationToken).ConfigureAwait(false);
        using ExternalSessionCandidate candidate = ExternalSessionCandidate.Create(sensitiveCandidate.Span);
        return await sessions.CompleteExternalAdmissionAsync(resolved, presentation, candidate, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>Reads the current SOAP resource stamp from the authoritative Published store.</summary>
public sealed class PublishedSoapSessionResourceStampProvider(IConnectorConfigurationStore store) : ISoapSessionResourceStampProvider
{
    /// <inheritdoc />
    public async Task<SoapSessionResourceStamp?> GetCurrentAsync(ConnectorAuthExecutionContext context, CancellationToken cancellationToken)
    {
        PublishedConnectorAccessContext access = new(context.InstallationId, context.TenantId, context.ApplicationId, context.OperationId);
        PublishedConnectorSnapshot? snapshot = await store.GetPublishedSnapshotAsync(context.ConnectorId, context.EnvironmentId, access, cancellationToken).ConfigureAwait(false);
        if (snapshot is null || snapshot.Version.State != ConnectorVersionState.Published || snapshot.Bindings.State != ConnectorBindingState.Active ||
            !string.Equals(snapshot.Version.Version, context.ConnectorVersion, StringComparison.Ordinal) || snapshot.Bindings.Revision != context.BindingRevision)
            return null;
        OperationBindingDependencies dependencies = ConnectorOperationBindings.Required(snapshot.Version.CanonicalJson, context.OperationId);
        ProviderResourceBinding[] operationSecrets = dependencies.SecretBindingIds
            .Select(id => snapshot.Bindings.SecretResources.TryGetValue(id, out ProviderResourceBinding? value) ? value : throw new GatewayException("BGW-CONNECTOR-SECRET-BINDING-MISSING", 503))
            .ToArray();
        long credentialRevision = operationSecrets.Length == 0
            ? snapshot.Bindings.Revision
            : operationSecrets.Max(value => value.CatalogRevision);
        return new(credentialRevision, SoapCredentialResourceStatus.Active, snapshot.Bindings.Revision, snapshot.Bindings.Revision);
    }
}

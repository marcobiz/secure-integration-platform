using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>Resolves typed handshake authority only from authenticated identity and a current Published snapshot.</summary>
public sealed class PublishedTypedSessionHandshakeResolver
{
    private readonly Func<string, Guid, PublishedConnectorAccessContext, CancellationToken, Task<PublishedConnectorSnapshot?>> snapshotSource;
    private readonly TypedSessionHandshakeAdapterRegistry adapters;
    private readonly IGatewayClock clock;
    private readonly PublishedConnectorMutationAuthority mutationAuthority;

    /// <summary>Creates the controlled resolver over the server-owned Connector configuration store.</summary>
    public PublishedTypedSessionHandshakeResolver(IConnectorConfigurationStore store, TypedSessionHandshakeAdapterRegistry adapters, IGatewayClock clock)
        : this((connectorId, environmentId, access, cancellationToken) => store.GetPublishedSnapshotAsync(connectorId, environmentId, access, cancellationToken),
            adapters, clock, (store as IPublishedConnectorMutationAuthoritySource)?.RuntimeMutationAuthority
                ?? throw new ArgumentException("Connector store must expose the runtime mutation authority.", nameof(store)))
    {
    }

    internal PublishedTypedSessionHandshakeResolver(
        Func<string, Guid, PublishedConnectorAccessContext, CancellationToken, Task<PublishedConnectorSnapshot?>> snapshotSource,
        TypedSessionHandshakeAdapterRegistry adapters,
        IGatewayClock clock,
        PublishedConnectorMutationAuthority mutationAuthority)
    {
        this.snapshotSource = snapshotSource ?? throw new ArgumentNullException(nameof(snapshotSource));
        this.adapters = adapters ?? throw new ArgumentNullException(nameof(adapters));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.mutationAuthority = mutationAuthority ?? throw new ArgumentNullException(nameof(mutationAuthority));
    }

    /// <summary>
    /// Resolves one logical profile after shared Core has authenticated and authorized the exact operation.
    /// Adapter IDs/types, QNames, SOAP version, endpoints, resources, revisions and checksums come only from Published state.
    /// </summary>
    public async Task<ResolvedTypedSessionHandshake> ResolveAsync(
        AuthorizedGatewayInvocation invocation,
        TypedSessionHandshakeAuthorityRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        ArgumentNullException.ThrowIfNull(request);
        GatewayClientPrincipal principal = invocation.Principal;
        if (principal.CorrelationId == Guid.Empty || principal.TenantId == Guid.Empty || principal.InstallationId == Guid.Empty ||
            principal.ApplicationId == Guid.Empty || principal.Identity.EnvironmentId == Guid.Empty ||
            !TypedSessionHandshakeValidation.Identifier(invocation.ConnectorId) || !TypedSessionHandshakeValidation.Identifier(invocation.OperationId))
            throw TypedSessionHandshakeFailures.AuthorityRejected();

        PublishedConnectorAccessContext access = new(principal.InstallationId, principal.TenantId, principal.ApplicationId, invocation.OperationId);
        PublishedConnectorSnapshot expectedSnapshot = await RequiredSnapshotAsync(invocation.ConnectorId, principal.Identity.EnvironmentId, access, cancellationToken).ConfigureAwait(false);
        TypedSessionHandshakeAuthorityState expected = Parse(expectedSnapshot, invocation, request, principal);

        async Task<TypedSessionHandshakeAuthorityState> Revalidate(CancellationToken token)
        {
            PublishedConnectorSnapshot currentSnapshot = await RequiredSnapshotAsync(invocation.ConnectorId, principal.Identity.EnvironmentId, access, token).ConfigureAwait(false);
            TypedSessionHandshakeAuthorityState current = Parse(currentSnapshot, invocation, request, principal);
            if (currentSnapshot.Stamp != expectedSnapshot.Stamp || currentSnapshot.Version.Id != expectedSnapshot.Version.Id ||
                currentSnapshot.Version.State != ConnectorVersionState.Published || currentSnapshot.Bindings.State != ConnectorBindingState.Active ||
                currentSnapshot.Bindings.Id != expectedSnapshot.Bindings.Id || currentSnapshot.Bindings.Revision != expectedSnapshot.Bindings.Revision ||
                current.AuthorityGeneration != expected.AuthorityGeneration ||
                !string.Equals(current.SecurityFingerprint, expected.SecurityFingerprint, StringComparison.Ordinal))
                throw TypedSessionHandshakeFailures.AuthorityStale();
            return current;
        }

        return new(expected, Revalidate);
    }

    internal async Task<ResolvedTypedSessionHandshake> ResolveCurrentAsync(
        AuthorizedGatewayInvocation invocation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        GatewayClientPrincipal principal = invocation.Principal;
        PublishedConnectorAccessContext access = new(
            principal.InstallationId,
            principal.TenantId,
            principal.ApplicationId,
            invocation.OperationId);
        PublishedConnectorSnapshot snapshot = await RequiredSnapshotAsync(
            invocation.ConnectorId,
            principal.Identity.EnvironmentId,
            access,
            cancellationToken).ConfigureAwait(false);
        string profileId;
        try
        {
            using JsonDocument document = JsonDocument.Parse(snapshot.Version.CanonicalJson, new JsonDocumentOptions { MaxDepth = 32 });
            JsonElement operation = document.RootElement.GetProperty("operations").EnumerateArray()
                .Single(value => string.Equals(value.GetProperty("operationId").GetString(), invocation.OperationId, StringComparison.Ordinal));
            profileId = operation.GetProperty("typedSessionHandshake").GetProperty("profileId").GetString()
                ?? throw TypedSessionHandshakeFailures.AuthorityRejected();
        }
        catch (SoapAuthException) { throw; }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or KeyNotFoundException)
        {
            throw TypedSessionHandshakeFailures.AuthorityRejected();
        }

        return await ResolveAsync(invocation, new(profileId), cancellationToken).ConfigureAwait(false);
    }

    private async Task<PublishedConnectorSnapshot> RequiredSnapshotAsync(
        string connectorId,
        Guid environmentId,
        PublishedConnectorAccessContext access,
        CancellationToken cancellationToken)
    {
        try
        {
            PublishedConnectorSnapshot? snapshot = await snapshotSource(connectorId, environmentId, access, cancellationToken).ConfigureAwait(false);
            if (snapshot is null || snapshot.Version.State != ConnectorVersionState.Published || snapshot.Version.PublishedAt is null ||
                snapshot.Bindings.State != ConnectorBindingState.Active || snapshot.Bindings.EnvironmentId != environmentId || snapshot.Stamp.PublicationRevision < 1)
                throw TypedSessionHandshakeFailures.AuthorityRejected();
            return snapshot;
        }
        catch (OperationCanceledException) { throw; }
        catch (SoapAuthException) { throw; }
        catch (Exception) { throw TypedSessionHandshakeFailures.AuthorityRejected(); }
    }

    private TypedSessionHandshakeAuthorityState Parse(
        PublishedConnectorSnapshot snapshot,
        AuthorizedGatewayInvocation invocation,
        TypedSessionHandshakeAuthorityRequest request,
        GatewayClientPrincipal principal)
    {
        try
        {
            if (!string.Equals(snapshot.Version.ConnectorSlug, invocation.ConnectorId, StringComparison.Ordinal) ||
                snapshot.Version.Id != snapshot.Bindings.ConnectorVersionId || snapshot.Version.ConnectorId != snapshot.Bindings.ConnectorId ||
                snapshot.Stamp.VersionId != snapshot.Version.Id || snapshot.Stamp.BindingRevision != snapshot.Bindings.Revision ||
                !string.Equals(snapshot.Stamp.BindingChecksumSha256, snapshot.Bindings.ChecksumSha256, StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(snapshot.Stamp.ResourceStampSha256))
                throw TypedSessionHandshakeFailures.AuthorityRejected();

            using JsonDocument document = JsonDocument.Parse(snapshot.Version.CanonicalJson, new JsonDocumentOptions { MaxDepth = 32 });
            JsonElement operation = document.RootElement.GetProperty("operations").EnumerateArray()
                .Single(value => string.Equals(value.GetProperty("operationId").GetString(), invocation.OperationId, StringComparison.Ordinal));
            JsonElement profile = operation.GetProperty("typedSessionHandshake");
            if (!string.Equals(profile.GetProperty("profileId").GetString(), request.ProfileId, StringComparison.Ordinal) ||
                !string.Equals(operation.GetProperty("method").GetString(), "POST", StringComparison.Ordinal))
                throw TypedSessionHandshakeFailures.AuthorityRejected();

            string endpointBindingId = operation.GetProperty("endpointBinding").GetString()!;
            if (!snapshot.Bindings.Endpoints.TryGetValue(endpointBindingId, out Uri? endpointBase))
                throw TypedSessionHandshakeFailures.AuthorityRejected();
            Uri endpoint = new(endpointBase, operation.GetProperty("path").GetString()!);
            if (!Https(endpoint)) throw TypedSessionHandshakeFailures.AuthorityRejected();

            JsonElement requestAdapterElement = profile.GetProperty("requestAdapter");
            string requestAdapterId = requestAdapterElement.GetProperty("id").GetString()!;
            string requestAdapterType = requestAdapterElement.GetProperty("type").GetString()!;
            JsonElement responseAdapterElement = profile.GetProperty("responseAdapter");
            string responseAdapterId = responseAdapterElement.GetProperty("id").GetString()!;
            string responseAdapterType = responseAdapterElement.GetProperty("type").GetString()!;
            ITypedSessionHandshakeRequestAdapter requestAdapter = adapters.Request(requestAdapterId, requestAdapterType);
            ITypedSessionHandshakeResponseAdapter responseAdapter = adapters.Response(responseAdapterId, responseAdapterType);

            SoapEnvelopeVersion soapVersion = profile.GetProperty("soapVersion").GetString() switch
            {
                "1.1" => SoapEnvelopeVersion.Soap11,
                "1.2" => SoapEnvelopeVersion.Soap12,
                _ => throw TypedSessionHandshakeFailures.AuthorityRejected()
            };
            JsonElement requestQName = profile.GetProperty("requestElement");
            JsonElement responseQName = profile.GetProperty("responseElement");
            JsonElement requestPolicy = operation.GetProperty("request");
            JsonElement responsePolicy = operation.GetProperty("response");
            int timeoutMilliseconds = operation.GetProperty("timeoutMs").GetInt32();
            SoapOperationProfile handshakeOperation = new(
                "typed-session-handshake",
                soapVersion,
                profile.GetProperty("action").GetString()!,
                new(requestQName.GetProperty("localName").GetString()!, requestQName.GetProperty("namespaceUri").GetString()!),
                new(responseQName.GetProperty("localName").GetString()!, responseQName.GetProperty("namespaceUri").GetString()!),
                timeoutMilliseconds: timeoutMilliseconds,
                maximumRequestBytes: requestPolicy.GetProperty("maximumBytes").GetInt64(),
                maximumResponseBytes: responsePolicy.GetProperty("maximumBytes").GetInt64());

            JsonElement authentication = operation.GetProperty("authentication");
            ResolvedBasicCredentialBinding? basic = null;
            List<ProviderResourceBinding> credentialResources = [];
            string authenticationKind = authentication.GetProperty("kind").GetString()!;
            if (string.Equals(authenticationKind, "basic", StringComparison.Ordinal))
            {
                string usernameBinding = authentication.GetProperty("usernameBinding").GetString()!;
                string passwordBinding = authentication.GetProperty("passwordBinding").GetString()!;
                ProviderResourceBinding username = RequiredSecret(snapshot, usernameBinding, invocation);
                ProviderResourceBinding password = RequiredSecret(snapshot, passwordBinding, invocation);
                if (!snapshot.SecretProviderReferences.TryGetValue(usernameBinding, out string? usernameReference) ||
                    !snapshot.SecretProviderReferences.TryGetValue(passwordBinding, out string? passwordReference))
                    throw TypedSessionHandshakeFailures.AuthorityRejected();
                basic = new(usernameReference, passwordReference);
                credentialResources.Add(username);
                credentialResources.Add(password);
            }
            else if (!string.Equals(authenticationKind, "none", StringComparison.Ordinal))
            {
                throw TypedSessionHandshakeFailures.AuthorityRejected();
            }

            ITypedExternalSessionValidationAdapter? validationAdapter = null;
            Uri? admissionEndpoint = null;
            SoapOperationProfile? admissionOperation = null;
            TimeSpan admissionIntentLifetime = default;
            string? validatorId = null;
            string? validatorType = null;
            string? admissionEndpointBindingId = null;
            if (profile.TryGetProperty("externalAdmission", out JsonElement admission))
            {
                JsonElement validatorElement = admission.GetProperty("validator");
                validatorId = validatorElement.GetProperty("id").GetString()!;
                validatorType = validatorElement.GetProperty("type").GetString()!;
                validationAdapter = adapters.Validation(validatorId, validatorType);
                admissionEndpointBindingId = admission.GetProperty("endpointBinding").GetString()!;
                if (!snapshot.Bindings.Endpoints.TryGetValue(admissionEndpointBindingId, out Uri? validationBase))
                    throw TypedSessionHandshakeFailures.AuthorityRejected();
                admissionEndpoint = new(validationBase, admission.GetProperty("path").GetString()!);
                if (!Https(admissionEndpoint)) throw TypedSessionHandshakeFailures.AuthorityRejected();
                admissionIntentLifetime = TimeSpan.FromSeconds(admission.GetProperty("intentLifetimeSeconds").GetInt32());
                SoapEnvelopeVersion admissionSoapVersion = admission.GetProperty("soapVersion").GetString() switch
                {
                    "1.1" => SoapEnvelopeVersion.Soap11,
                    "1.2" => SoapEnvelopeVersion.Soap12,
                    _ => throw TypedSessionHandshakeFailures.AuthorityRejected()
                };
                JsonElement admissionRequestQName = admission.GetProperty("requestElement");
                JsonElement admissionResponseQName = admission.GetProperty("responseElement");
                admissionOperation = new("typed-session-admission-validation", admissionSoapVersion, admission.GetProperty("action").GetString()!,
                    new(admissionRequestQName.GetProperty("localName").GetString()!, admissionRequestQName.GetProperty("namespaceUri").GetString()!),
                    new(admissionResponseQName.GetProperty("localName").GetString()!, admissionResponseQName.GetProperty("namespaceUri").GetString()!),
                    timeoutMilliseconds: admission.GetProperty("timeoutMs").GetInt32(),
                    maximumRequestBytes: admission.GetProperty("maximumRequestBytes").GetInt64(),
                    maximumResponseBytes: admission.GetProperty("maximumResponseBytes").GetInt64());
            }

            string policyChecksum = Convert.ToHexString(snapshot.Version.ChecksumSha256);
            long credentialRevision = credentialResources.Count == 0 ? snapshot.Bindings.Revision : credentialResources.Max(value => value.CatalogRevision);
            string resourcesFingerprint = string.Join('|', credentialResources.OrderBy(value => value.ResourceId, StringComparer.Ordinal)
                .Select(value => string.Join(':', value.ProviderId, value.ResourceId, value.Version ?? string.Empty, value.CatalogRevision, value.CatalogChecksumSha256)));
            string fingerprintInput = string.Join('\n', snapshot.Version.Id, snapshot.Version.Version, policyChecksum, snapshot.Bindings.Id,
                snapshot.Bindings.Revision, snapshot.Bindings.ChecksumSha256, snapshot.Stamp.PublicationRevision, snapshot.Stamp.ResourceStampSha256,
                invocation.OperationId, request.ProfileId, endpointBindingId, endpoint.AbsoluteUri, soapVersion, handshakeOperation.Action,
                handshakeOperation.RequestElement.NamespaceUri, handshakeOperation.RequestElement.LocalName,
                handshakeOperation.ResponseElement.NamespaceUri, handshakeOperation.ResponseElement.LocalName,
                requestAdapterId, requestAdapterType, responseAdapterId, responseAdapterType, authenticationKind, resourcesFingerprint,
                profile.GetProperty("sessionLifetimeSeconds").GetInt32(), validatorId ?? string.Empty, validatorType ?? string.Empty,
                admissionEndpointBindingId ?? string.Empty, admissionEndpoint?.AbsoluteUri ?? string.Empty, admissionIntentLifetime,
                admissionOperation?.Version, admissionOperation?.Action, admissionOperation?.RequestElement.NamespaceUri,
                admissionOperation?.RequestElement.LocalName, admissionOperation?.ResponseElement.NamespaceUri,
                admissionOperation?.ResponseElement.LocalName, admissionOperation?.TimeoutMilliseconds,
                admissionOperation?.MaximumRequestBytes, admissionOperation?.MaximumResponseBytes,
                timeoutMilliseconds, handshakeOperation.MaximumRequestBytes, handshakeOperation.MaximumResponseBytes);
            string fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintInput)));
            ConnectorAuthExecutionContext execution = new(principal.TenantId, principal.InstallationId, principal.ApplicationId, principal.Identity.EnvironmentId,
                snapshot.Version.ConnectorSlug, snapshot.Version.Version, invocation.OperationId, snapshot.Bindings.Revision, snapshot.Bindings.Revision,
                credentialRevision, request.ProfileId, principal.CorrelationId, clock.UtcNow.AddMinutes(30));

            return new()
            {
                ExecutionContext = execution,
                ConnectorVersionId = snapshot.Version.Id,
                ProfileId = request.ProfileId,
                Endpoint = new(endpoint, snapshot.Bindings.Revision),
                Operation = handshakeOperation,
                BasicCredential = basic,
                RequestAdapter = requestAdapter,
                ResponseAdapter = responseAdapter,
                LocalMaximumSessionLifetime = TimeSpan.FromSeconds(profile.GetProperty("sessionLifetimeSeconds").GetInt32()),
                PublishedPolicyChecksum = policyChecksum,
                ResourceStamp = snapshot.Stamp.ResourceStampSha256,
                SecurityFingerprint = fingerprint,
                AdmissionValidationAdapter = validationAdapter,
                AdmissionEndpoint = admissionEndpoint,
                AdmissionOperation = admissionOperation,
                AdmissionIntentLifetime = admissionIntentLifetime,
                MutationAuthority = mutationAuthority,
                AuthorityGeneration = mutationAuthority.Capture(invocation.ConnectorId, principal.Identity.EnvironmentId)
            };
        }
        catch (SoapAuthException) { throw; }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or ArgumentException or KeyNotFoundException or FormatException or OverflowException)
        {
            throw TypedSessionHandshakeFailures.AuthorityRejected();
        }
    }

    private static ProviderResourceBinding RequiredSecret(PublishedConnectorSnapshot snapshot, string logical, AuthorizedGatewayInvocation invocation)
    {
        if (!snapshot.Bindings.SecretResources.TryGetValue(logical, out ProviderResourceBinding? resource) || resource.ResourceType != ProviderResourceType.Secret ||
            resource.EnvironmentId != snapshot.Bindings.EnvironmentId || resource.CatalogRevision < 1 ||
            !string.Equals(resource.ConnectorScope, invocation.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(resource.OperationScope, invocation.OperationId, StringComparison.Ordinal) && !string.Equals(resource.OperationScope, "*", StringComparison.Ordinal))
            throw TypedSessionHandshakeFailures.AuthorityRejected();
        return resource;
    }

    private static bool Https(Uri endpoint) => endpoint.IsAbsoluteUri && endpoint.Scheme == Uri.UriSchemeHttps &&
        string.IsNullOrEmpty(endpoint.UserInfo) && string.IsNullOrEmpty(endpoint.Query) && string.IsNullOrEmpty(endpoint.Fragment);
}

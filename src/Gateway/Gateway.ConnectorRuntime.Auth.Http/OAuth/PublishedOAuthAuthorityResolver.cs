using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OAuth;

/// <summary>Resolves an OAuth capability only from authenticated identity and the current Published snapshot.</summary>
public sealed class PublishedOAuthAuthorityResolver
{
    private readonly Func<string, Guid, PublishedConnectorAccessContext, CancellationToken, Task<PublishedConnectorSnapshot?>> snapshotSource;
    private readonly ISecretValueProvider secretValues;
    private readonly IGatewayClock clock;

    /// <summary>Creates the controlled resolver over the server-owned Connector configuration store.</summary>
    public PublishedOAuthAuthorityResolver(IConnectorConfigurationStore store, ISecretValueProvider secretValues, IGatewayClock clock)
        : this((connectorId, environmentId, access, cancellationToken) => store.GetPublishedSnapshotAsync(connectorId, environmentId, access, cancellationToken), secretValues, clock)
    {
    }

    internal PublishedOAuthAuthorityResolver(Func<string, Guid, PublishedConnectorAccessContext, CancellationToken, Task<PublishedConnectorSnapshot?>> snapshotSource, ISecretValueProvider secretValues, IGatewayClock clock)
    {
        this.snapshotSource = snapshotSource;
        this.secretValues = secretValues;
        this.clock = clock;
    }

    /// <summary>
    /// Resolves one logical profile after the shared runtime has authenticated and authorized the principal.
    /// Connector code cannot supply endpoints, client identity, scopes, audience or provider locators.
    /// </summary>
    public async Task<OAuthResolvedExecutionContext> ResolveAsync(OAuthAuthorizedInvocation invocation, OAuthAuthorityRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        ArgumentNullException.ThrowIfNull(request);
        GatewayClientPrincipal principal = invocation.Principal;
        if (principal.CorrelationId == Guid.Empty || principal.TenantId == Guid.Empty || principal.InstallationId == Guid.Empty || principal.ApplicationId == Guid.Empty || principal.Identity.EnvironmentId == Guid.Empty)
            throw OAuthFailures.Rejected();

        PublishedConnectorAccessContext access = new(principal.InstallationId, principal.TenantId, principal.ApplicationId, invocation.OperationId);
        PublishedConnectorSnapshot snapshot = await RequiredSnapshotAsync(invocation.ConnectorId, principal.Identity.EnvironmentId, access, cancellationToken).ConfigureAwait(false);
        ResolvedPublishedProfile resolved = Parse(snapshot, invocation, request);
        OutboundAuthContext authority = new(principal.TenantId, principal.InstallationId, principal.ApplicationId, principal.Identity.EnvironmentId, snapshot.Version.Id,
            snapshot.Version.ConnectorSlug, snapshot.Version.Version, invocation.OperationId, snapshot.Bindings.Revision, snapshot.Bindings.Revision,
            resolved.SecretResource.CatalogRevision, snapshot.Stamp.ResourceStampSha256, principal.CorrelationId, clock.UtcNow.AddMinutes(30));

        async Task Revalidate(CancellationToken token)
        {
            PublishedConnectorSnapshot current = await RequiredSnapshotAsync(invocation.ConnectorId, principal.Identity.EnvironmentId, access, token).ConfigureAwait(false);
            if (current.Stamp != snapshot.Stamp || current.Version.Id != snapshot.Version.Id || current.Version.State != ConnectorVersionState.Published ||
                current.Bindings.State != ConnectorBindingState.Active || current.Bindings.Revision != snapshot.Bindings.Revision)
                throw OAuthFailures.ReacquisitionRequired();
            ResolvedPublishedProfile currentProfile = Parse(current, invocation, request);
            if (!string.Equals(currentProfile.Profile.Fingerprint, resolved.Profile.Fingerprint, StringComparison.Ordinal) ||
                currentProfile.SecretResource.CatalogRevision != resolved.SecretResource.CatalogRevision ||
                !string.Equals(currentProfile.SecretProviderReference, resolved.SecretProviderReference, StringComparison.Ordinal) ||
                currentProfile.ProtectedResourceEndpoint != resolved.ProtectedResourceEndpoint)
                throw OAuthFailures.ReacquisitionRequired();
        }

        return new(authority, resolved.Profile, new ScopedOAuthSecretCapability(secretValues, resolved.SecretProviderReference), resolved.ProtectedResourceEndpoint,
            resolved.ProtectedResourceMethod, resolved.ProtectedResourceContentType, resolved.ProtectedResourceTimeout, resolved.MaximumProtectedResourceResponseBytes, Revalidate);
    }

    private async Task<PublishedConnectorSnapshot> RequiredSnapshotAsync(string connectorId, Guid environmentId, PublishedConnectorAccessContext access, CancellationToken cancellationToken)
    {
        try
        {
            PublishedConnectorSnapshot? snapshot = await snapshotSource(connectorId, environmentId, access, cancellationToken).ConfigureAwait(false);
            if (snapshot is null || snapshot.Version.State != ConnectorVersionState.Published || snapshot.Bindings.State != ConnectorBindingState.Active || snapshot.Bindings.EnvironmentId != environmentId)
                throw OAuthFailures.Rejected();
            return snapshot;
        }
        catch (GatewayException) { throw; }
        catch (Exception exception) when (exception is not OperationCanceledException) { throw OAuthFailures.Rejected(); }
    }

    private static ResolvedPublishedProfile Parse(PublishedConnectorSnapshot snapshot, OAuthAuthorizedInvocation invocation, OAuthAuthorityRequest request)
    {
        try
        {
            if (!string.Equals(snapshot.Version.ConnectorSlug, invocation.ConnectorId, StringComparison.Ordinal) || snapshot.Version.Id != snapshot.Bindings.ConnectorVersionId || snapshot.Version.ConnectorId != snapshot.Bindings.ConnectorId ||
                snapshot.Stamp.VersionId != snapshot.Version.Id || snapshot.Stamp.BindingRevision != snapshot.Bindings.Revision ||
                !string.Equals(snapshot.Stamp.BindingChecksumSha256, snapshot.Bindings.ChecksumSha256, StringComparison.Ordinal) || string.IsNullOrWhiteSpace(snapshot.Stamp.ResourceStampSha256))
                throw OAuthFailures.Rejected();
            OperationBindingDependencies dependencies = ConnectorOperationBindings.Required(snapshot.Version.CanonicalJson, invocation.OperationId);
            using JsonDocument document = JsonDocument.Parse(snapshot.Version.CanonicalJson, new JsonDocumentOptions { MaxDepth = 32 });
            JsonElement operation = document.RootElement.GetProperty("operations").EnumerateArray().Single(value => string.Equals(value.GetProperty("operationId").GetString(), invocation.OperationId, StringComparison.Ordinal));
            JsonElement authentication = operation.GetProperty("authentication");
            if (!string.Equals(authentication.GetProperty("kind").GetString(), "oauthAuthorizationCode", StringComparison.Ordinal) ||
                !string.Equals(authentication.GetProperty("profileId").GetString(), request.ProfileId, StringComparison.Ordinal))
                throw OAuthFailures.Rejected();

            string protectedEndpointBinding = dependencies.EndpointBindingId;
            string authorizationEndpointBinding = authentication.GetProperty("authorizationEndpointBinding").GetString()!;
            string tokenEndpointBinding = authentication.GetProperty("tokenEndpointBinding").GetString()!;
            string secretBinding = authentication.GetProperty("secretBinding").GetString()!;
            if (!dependencies.SecretBindingIds.Contains(secretBinding, StringComparer.Ordinal) || dependencies.SecretBindingIds.Count != 1 ||
                !snapshot.Bindings.Endpoints.TryGetValue(authorizationEndpointBinding, out Uri? authorizationEndpoint) ||
                !snapshot.Bindings.Endpoints.TryGetValue(tokenEndpointBinding, out Uri? tokenEndpoint) ||
                !snapshot.Bindings.Endpoints.TryGetValue(protectedEndpointBinding, out Uri? protectedBaseEndpoint) ||
                !snapshot.Bindings.SecretResources.TryGetValue(secretBinding, out ProviderResourceBinding? secretResource) ||
                !snapshot.SecretProviderReferences.TryGetValue(secretBinding, out string? secretProviderReference) || string.IsNullOrWhiteSpace(secretProviderReference))
                throw OAuthFailures.Rejected();
            if (secretResource.ResourceType != ProviderResourceType.Secret || secretResource.EnvironmentId != snapshot.Bindings.EnvironmentId ||
                !string.Equals(secretResource.ConnectorScope, invocation.ConnectorId, StringComparison.Ordinal) ||
                !string.Equals(secretResource.OperationScope, invocation.OperationId, StringComparison.Ordinal) || secretResource.CatalogRevision < 1)
                throw OAuthFailures.Rejected();

            string[] scopes = authentication.GetProperty("scopes").EnumerateArray().Select(value => value.GetString()!).ToArray();
            string? audience = authentication.TryGetProperty("audience", out JsonElement audienceElement) ? audienceElement.GetString() : null;
            OAuthAuthorizationCodeProfile profile = new(request.ProfileId, authorizationEndpoint, tokenEndpoint, new Uri(authentication.GetProperty("redirectUri").GetString()!, UriKind.Absolute),
                authentication.GetProperty("clientId").GetString()!, scopes, audience,
                TimeSpan.FromSeconds(OptionalInt(authentication, "authorizationLifetimeSeconds", 300)),
                TimeSpan.FromMilliseconds(OptionalInt(authentication, "tokenRequestTimeoutMilliseconds", 5000)),
                OptionalLong(authentication, "maximumTokenResponseBytes", 16 * 1024),
                TimeSpan.FromSeconds(OptionalInt(authentication, "expirySkewSeconds", 30)),
                !authentication.TryGetProperty("allowRefresh", out JsonElement allowRefresh) || allowRefresh.GetBoolean());

            Uri protectedEndpoint = new(protectedBaseEndpoint, operation.GetProperty("path").GetString()!);
            if (!OAuthValidation.HttpsEndpoint(protectedEndpoint)) throw OAuthFailures.Rejected();
            JsonElement requestShape = operation.GetProperty("request");
            JsonElement responseShape = operation.GetProperty("response");
            int timeoutMilliseconds = operation.GetProperty("timeoutMs").GetInt32();
            long maximumResponseBytes = responseShape.GetProperty("maximumBytes").GetInt64();
            if (timeoutMilliseconds is < 100 or > 120_000 || maximumResponseBytes is < 1 or > 16 * 1024 * 1024) throw OAuthFailures.Rejected();
            return new(profile, secretResource, secretProviderReference, protectedEndpoint, new HttpMethod(operation.GetProperty("method").GetString()!),
                requestShape.TryGetProperty("contentType", out JsonElement contentType) ? contentType.GetString() : null,
                TimeSpan.FromMilliseconds(timeoutMilliseconds), maximumResponseBytes);
        }
        catch (GatewayException) { throw; }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or ArgumentException or KeyNotFoundException or FormatException or OverflowException)
        {
            throw OAuthFailures.Rejected();
        }
    }

    private static int OptionalInt(JsonElement value, string property, int fallback) => value.TryGetProperty(property, out JsonElement element) ? element.GetInt32() : fallback;
    private static long OptionalLong(JsonElement value, string property, long fallback) => value.TryGetProperty(property, out JsonElement element) ? element.GetInt64() : fallback;

    private sealed class ResolvedPublishedProfile(OAuthAuthorizationCodeProfile profile, ProviderResourceBinding secretResource, string secretProviderReference, Uri protectedResourceEndpoint,
        HttpMethod protectedResourceMethod, string? protectedResourceContentType, TimeSpan protectedResourceTimeout, long maximumProtectedResourceResponseBytes)
    {
        internal OAuthAuthorizationCodeProfile Profile { get; } = profile;
        internal ProviderResourceBinding SecretResource { get; } = secretResource;
        internal string SecretProviderReference { get; } = secretProviderReference;
        internal Uri ProtectedResourceEndpoint { get; } = protectedResourceEndpoint;
        internal HttpMethod ProtectedResourceMethod { get; } = protectedResourceMethod;
        internal string? ProtectedResourceContentType { get; } = protectedResourceContentType;
        internal TimeSpan ProtectedResourceTimeout { get; } = protectedResourceTimeout;
        internal long MaximumProtectedResourceResponseBytes { get; } = maximumProtectedResourceResponseBytes;
    }
}

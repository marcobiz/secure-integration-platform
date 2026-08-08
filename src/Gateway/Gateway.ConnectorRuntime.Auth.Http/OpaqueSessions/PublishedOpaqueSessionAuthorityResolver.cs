using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;

/// <summary>Resolves opaque-session HTTP authority only from authenticated identity and the current Published snapshot.</summary>
public sealed class PublishedOpaqueSessionAuthorityResolver
{
    private readonly Func<string, Guid, PublishedConnectorAccessContext, CancellationToken, Task<PublishedConnectorSnapshot?>> snapshotSource;
    private readonly IGatewayClock clock;

    /// <summary>Creates the controlled resolver over the server-owned Connector configuration store.</summary>
    public PublishedOpaqueSessionAuthorityResolver(IConnectorConfigurationStore store, IGatewayClock clock)
        : this((connectorId, environmentId, access, cancellationToken) => store.GetPublishedSnapshotAsync(connectorId, environmentId, access, cancellationToken), clock)
    {
    }

    internal PublishedOpaqueSessionAuthorityResolver(Func<string, Guid, PublishedConnectorAccessContext, CancellationToken, Task<PublishedConnectorSnapshot?>> snapshotSource, IGatewayClock clock)
    {
        this.snapshotSource = snapshotSource ?? throw new ArgumentNullException(nameof(snapshotSource));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    /// <summary>
    /// Resolves one logical policy after the shared runtime has authenticated and authorized the principal.
    /// Caller code cannot supply endpoint, method, placement, revision, operation or environment authority.
    /// </summary>
    public async Task<OpaqueSessionResolvedExecutionContext> ResolveAsync(OpaqueSessionAuthorizedInvocation invocation, OpaqueSessionHttpAuthorityRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        ArgumentNullException.ThrowIfNull(request);
        GatewayClientPrincipal principal = invocation.Principal;
        if (principal.CorrelationId == Guid.Empty || principal.TenantId == Guid.Empty || principal.InstallationId == Guid.Empty || principal.ApplicationId == Guid.Empty || principal.Identity.EnvironmentId == Guid.Empty)
            throw OpaqueSessionHttpFailures.Rejected();

        PublishedConnectorAccessContext access = new(principal.InstallationId, principal.TenantId, principal.ApplicationId, invocation.OperationId);
        PublishedConnectorSnapshot expectedSnapshot = await RequiredSnapshotAsync(invocation.ConnectorId, principal.Identity.EnvironmentId, access, cancellationToken).ConfigureAwait(false);
        ResolvedPolicy expected = Parse(expectedSnapshot, invocation, request);
        OpaqueSessionHttpAuthorityState expectedState = State(principal, expectedSnapshot, invocation, request, expected);

        async Task<OpaqueSessionHttpAuthorityState> Revalidate(CancellationToken token)
        {
            PublishedConnectorSnapshot currentSnapshot = await RequiredSnapshotAsync(invocation.ConnectorId, principal.Identity.EnvironmentId, access, token).ConfigureAwait(false);
            ResolvedPolicy current = Parse(currentSnapshot, invocation, request);
            OpaqueSessionHttpAuthorityState currentState = State(principal, currentSnapshot, invocation, request, current);
            if (currentSnapshot.Stamp != expectedSnapshot.Stamp || currentSnapshot.Version.Id != expectedSnapshot.Version.Id ||
                currentSnapshot.Version.State != ConnectorVersionState.Published || currentSnapshot.Bindings.State != ConnectorBindingState.Active ||
                currentSnapshot.Bindings.Id != expectedSnapshot.Bindings.Id || currentSnapshot.Bindings.Revision != expectedSnapshot.Bindings.Revision ||
                !string.Equals(currentState.SecurityFingerprint, expectedState.SecurityFingerprint, StringComparison.Ordinal))
                throw OpaqueSessionHttpFailures.Stale();
            return currentState;
        }

        return new(expectedState, Revalidate);
    }

    private async Task<PublishedConnectorSnapshot> RequiredSnapshotAsync(string connectorId, Guid environmentId, PublishedConnectorAccessContext access, CancellationToken cancellationToken)
    {
        try
        {
            PublishedConnectorSnapshot? snapshot = await snapshotSource(connectorId, environmentId, access, cancellationToken).ConfigureAwait(false);
            if (snapshot is null || snapshot.Version.State != ConnectorVersionState.Published || snapshot.Bindings.State != ConnectorBindingState.Active || snapshot.Bindings.EnvironmentId != environmentId)
                throw OpaqueSessionHttpFailures.Rejected();
            return snapshot;
        }
        catch (OperationCanceledException) { throw; }
        catch (OpaqueSessionAuthException) { throw; }
        catch (Exception) { throw OpaqueSessionHttpFailures.Rejected(); }
    }

    private OpaqueSessionHttpAuthorityState State(GatewayClientPrincipal principal, PublishedConnectorSnapshot snapshot, OpaqueSessionAuthorizedInvocation invocation,
        OpaqueSessionHttpAuthorityRequest request, ResolvedPolicy resolved) => new(
            principal.TenantId, principal.InstallationId, principal.ApplicationId, principal.Identity.EnvironmentId, snapshot.Version.Id,
            snapshot.Version.ConnectorSlug, snapshot.Version.Version, invocation.OperationId, request.PolicyId, resolved.ProfileId,
            resolved.Endpoint, resolved.Method, resolved.ContentType, snapshot.Bindings.Revision, snapshot.Bindings.Revision,
            resolved.Credential.CatalogRevision, snapshot.Stamp.ResourceStampSha256, resolved.HeaderName, resolved.ValueFormat, resolved.FixedScheme,
            resolved.Timeout, resolved.MaximumRequestBytes, resolved.MaximumResponseBytes, principal.CorrelationId, clock.UtcNow.AddMinutes(30), resolved.SecurityFingerprint);

    private static ResolvedPolicy Parse(PublishedConnectorSnapshot snapshot, OpaqueSessionAuthorizedInvocation invocation, OpaqueSessionHttpAuthorityRequest request)
    {
        try
        {
            if (!string.Equals(snapshot.Version.ConnectorSlug, invocation.ConnectorId, StringComparison.Ordinal) || snapshot.Version.Id != snapshot.Bindings.ConnectorVersionId ||
                snapshot.Version.ConnectorId != snapshot.Bindings.ConnectorId || snapshot.Stamp.VersionId != snapshot.Version.Id || snapshot.Stamp.BindingRevision != snapshot.Bindings.Revision ||
                !string.Equals(snapshot.Stamp.BindingChecksumSha256, snapshot.Bindings.ChecksumSha256, StringComparison.Ordinal) || string.IsNullOrWhiteSpace(snapshot.Stamp.ResourceStampSha256))
                throw OpaqueSessionHttpFailures.Rejected();

            OperationBindingDependencies dependencies = ConnectorOperationBindings.Required(snapshot.Version.CanonicalJson, invocation.OperationId);
            using JsonDocument document = JsonDocument.Parse(snapshot.Version.CanonicalJson, new JsonDocumentOptions { MaxDepth = 32 });
            JsonElement operation = document.RootElement.GetProperty("operations").EnumerateArray().Single(value => string.Equals(value.GetProperty("operationId").GetString(), invocation.OperationId, StringComparison.Ordinal));
            JsonElement authentication = operation.GetProperty("authentication");
            if (!string.Equals(authentication.GetProperty("kind").GetString(), "opaqueSessionHttp", StringComparison.Ordinal) ||
                !string.Equals(authentication.GetProperty("policyId").GetString(), request.PolicyId, StringComparison.Ordinal))
                throw OpaqueSessionHttpFailures.Rejected();

            string credentialBinding = authentication.GetProperty("secretBinding").GetString()!;
            if (dependencies.SecretBindingIds.Count != 1 || !dependencies.SecretBindingIds.Contains(credentialBinding, StringComparer.Ordinal) ||
                !snapshot.Bindings.SecretResources.TryGetValue(credentialBinding, out ProviderResourceBinding? credential) ||
                !snapshot.Bindings.Endpoints.TryGetValue(dependencies.EndpointBindingId, out Uri? baseEndpoint))
                throw OpaqueSessionHttpFailures.Rejected();
            if (credential.ResourceType != ProviderResourceType.Secret || credential.EnvironmentId != snapshot.Bindings.EnvironmentId || credential.CatalogRevision < 1 ||
                !string.Equals(credential.ConnectorScope, invocation.ConnectorId, StringComparison.Ordinal) ||
                !string.Equals(credential.OperationScope, invocation.OperationId, StringComparison.Ordinal) && !string.Equals(credential.OperationScope, "*", StringComparison.Ordinal))
                throw OpaqueSessionHttpFailures.Rejected();

            Uri endpoint = new(baseEndpoint, operation.GetProperty("path").GetString()!);
            if (!OpaqueSessionHttpValidation.HttpsEndpoint(endpoint)) throw OpaqueSessionHttpFailures.Rejected();
            HttpMethod method = new(operation.GetProperty("method").GetString()!);
            if (method != HttpMethod.Get && method != HttpMethod.Post && method != HttpMethod.Put && method != HttpMethod.Delete)
                throw OpaqueSessionHttpFailures.Rejected();
            JsonElement requestShape = operation.GetProperty("request");
            JsonElement responseShape = operation.GetProperty("response");
            string? contentType = method == HttpMethod.Get ? null : requestShape.GetProperty("contentType").GetString();
            int timeoutMilliseconds = operation.GetProperty("timeoutMs").GetInt32();
            long maximumRequestBytes = requestShape.GetProperty("maximumBytes").GetInt64();
            long maximumResponseBytes = responseShape.GetProperty("maximumBytes").GetInt64();
            if (timeoutMilliseconds is < 100 or > 120_000 || maximumRequestBytes is < 1 or > 16 * 1024 * 1024 || maximumResponseBytes is < 1 or > 16 * 1024 * 1024)
                throw OpaqueSessionHttpFailures.Rejected();

            string headerName = authentication.GetProperty("headerName").GetString()!;
            OpaqueSessionHttpHeaderValueFormat valueFormat = authentication.GetProperty("valueFormat").GetString() switch
            {
                "rawOpaqueValue" => OpaqueSessionHttpHeaderValueFormat.RawOpaqueValue,
                "fixedSchemeAndOpaqueValue" => OpaqueSessionHttpHeaderValueFormat.FixedSchemeAndOpaqueValue,
                _ => throw OpaqueSessionHttpFailures.Rejected()
            };
            string? fixedScheme = authentication.TryGetProperty("fixedScheme", out JsonElement scheme) ? scheme.GetString() : null;
            _ = new HttpRequestHeaderOpaqueSessionPlacement(headerName, valueFormat, fixedScheme);
            string profileId = authentication.GetProperty("sessionProfileId").GetString()!;

            string fingerprintInput = string.Join('\n', snapshot.Version.Id, snapshot.Version.Version, Convert.ToHexString(snapshot.Version.ChecksumSha256),
                snapshot.Bindings.Id, snapshot.Bindings.Revision, snapshot.Bindings.ChecksumSha256, snapshot.Stamp.ResourceStampSha256,
                invocation.OperationId, request.PolicyId, profileId, dependencies.EndpointBindingId, baseEndpoint.AbsoluteUri, endpoint.AbsoluteUri, method.Method,
                contentType ?? string.Empty, headerName, valueFormat, fixedScheme ?? string.Empty, credentialBinding, credential.ProviderId, credential.ResourceId,
                credential.Version ?? string.Empty, credential.CatalogRevision, credential.CatalogChecksumSha256, timeoutMilliseconds, maximumRequestBytes, maximumResponseBytes);
            string fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintInput)));
            return new(profileId, endpoint, method, contentType, credential, headerName, valueFormat, fixedScheme,
                TimeSpan.FromMilliseconds(timeoutMilliseconds), maximumRequestBytes, maximumResponseBytes, fingerprint);
        }
        catch (OpaqueSessionAuthException) { throw; }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or ArgumentException or KeyNotFoundException or FormatException or OverflowException)
        {
            throw OpaqueSessionHttpFailures.Rejected();
        }
    }

    private sealed record ResolvedPolicy(
        string ProfileId,
        Uri Endpoint,
        HttpMethod Method,
        string? ContentType,
        ProviderResourceBinding Credential,
        string HeaderName,
        OpaqueSessionHttpHeaderValueFormat ValueFormat,
        string? FixedScheme,
        TimeSpan Timeout,
        long MaximumRequestBytes,
        long MaximumResponseBytes,
        string SecurityFingerprint);
}

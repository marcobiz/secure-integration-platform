using System.Collections.Frozen;
using System.Net.Http.Headers;
using System.Text.Json;
using SecureIntegration.Authentication.CertificateSigning;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.Api;

/// <summary>
/// Host-owned composition of the existing signing and mTLS primitives for one exact authorized
/// Connector invocation. Connector modules receive only the narrow invocation bridge.
/// </summary>
internal sealed class AuthorizedVerticalCapabilityRuntime : IAuthorizedVerticalCapabilityRuntime
{
    private readonly IConnectorConfigurationStore store;
    private readonly IKeyOperationProvider? keyOperations;
    private readonly IClientCertificateProvider certificates;
    private readonly ICertificateMetadataProvider? certificateMetadata;
    private readonly ICertificatePublicMaterialProvider? certificatePublicMaterial;
    private readonly IHostResolver hostResolver;
    private readonly IRestrictedTransport transport;
    private readonly AuthenticationClockAdapter clock;
    private readonly IJwtReplayStore replayStore;
    private readonly AuthenticationPrivateDestinationAllowanceAdapter? privateDestinationAllowance;

    internal AuthorizedVerticalCapabilityRuntime(
        IConnectorConfigurationStore store,
        IKeyOperationProvider? keyOperations,
        IClientCertificateProvider certificates,
        ICertificateMetadataProvider? certificateMetadata,
        ICertificatePublicMaterialProvider? certificatePublicMaterial,
        IHostResolver hostResolver,
        IRestrictedTransport transport,
        IGatewayClock clock,
        IPrivateDestinationAllowance? privateDestinationAllowance)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        this.keyOperations = keyOperations;
        this.certificates = certificates ?? throw new ArgumentNullException(nameof(certificates));
        this.certificateMetadata = certificateMetadata;
        this.certificatePublicMaterial = certificatePublicMaterial;
        this.hostResolver = hostResolver ?? throw new ArgumentNullException(nameof(hostResolver));
        this.transport = transport ?? throw new ArgumentNullException(nameof(transport));
        this.clock = new(clock ?? throw new ArgumentNullException(nameof(clock)));
        replayStore = new InMemoryJwtReplayStore(100_000, this.clock);
        this.privateDestinationAllowance = privateDestinationAllowance is null ? null : new(privateDestinationAllowance);
    }

    public async Task<string> CreateSignedTokenAsync(
        AuthorizedConnectorExecution execution,
        IReadOnlyDictionary<string, JsonElement> claims,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentNullException.ThrowIfNull(claims);
        try
        {
            PublishedVerticalAuthority authority = new(store, execution);
            VerticalProfile profile = await authority.ResolveProfileAsync(cancellationToken).ConfigureAwait(false);
            AuthenticationExecutionContext context = authority.Context(profile.SigningProfileId);
            Rs256JwtSigner signer = new(
                authority,
                authority,
                keyOperations,
                replayStore,
                clock,
                certificatePublicMaterial: certificatePublicMaterial);
            JwtBoundClaim[] boundedClaims = claims.OrderBy(value => value.Key, StringComparer.Ordinal)
                .Select(value => new JwtBoundClaim(value.Key, value.Value.Clone())).ToArray();
            return await signer.SignJwtAsync(context, profile.SigningProfileId, boundedClaims, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (AuthenticationPrimitiveException exception)
        {
            throw Map(exception);
        }
    }

    public async Task<QualifiedGatewayExecutionResult> ExecuteRestrictedTransportAsync(
        AuthorizedConnectorExecution execution,
        AuthorizedConnectorRestrictedTransportRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            PublishedVerticalAuthority authority = new(store, execution);
            VerticalProfile profile = await authority.ResolveProfileAsync(cancellationToken).ConfigureAwait(false);
            AuthenticationExecutionContext context = authority.Context(profile.TransportProfileId);
            using HttpRequestMessage outbound = new(execution.Operation.Method, execution.Operation.Endpoint)
            {
                Content = new ByteArrayContent(request.Body.ToArray())
            };
            outbound.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(execution.Operation.RequestContentType);
            outbound.Headers.Authorization = new AuthenticationHeaderValue("Bearer", request.SignedToken.CompactToken);
            outbound.Headers.TryAddWithoutValidation("X-Correlation-ID", execution.CorrelationId.ToString("D"));

            PurposeBoundMutualTlsSender sender = new(
                authority,
                authority,
                certificates,
                certificateMetadata,
                new AuthenticationHostResolverAdapter(hostResolver),
                new PurposeBoundMutualTlsTransportAdapter(transport),
                clock,
                privateDestinationAllowance);
            MutualTlsAuthenticatedResponse response = await sender.SendAsync(
                context,
                profile.TransportProfileId,
                outbound,
                cancellationToken).ConfigureAwait(false);
            return new(response.Response.StatusCode, response.Response.ContentType, response.Response.Body);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (AuthenticationPrimitiveException exception)
        {
            throw Map(exception);
        }
    }

    private static GatewayException Map(AuthenticationPrimitiveException exception)
    {
        if (exception.Code.Contains("STALE", StringComparison.Ordinal))
            return new GatewayException("BGW-CONNECTOR-CONFIGURATION-STALE", 503, true);
        if (exception.Code.Contains("UNAVAILABLE", StringComparison.Ordinal) ||
            exception.Code.Contains("OPERATION-FAILED", StringComparison.Ordinal))
            return new GatewayException("BGW-EGRESS-UPSTREAM-REJECTED", 502, exception.Retryable);
        return new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
    }

    private sealed class AuthenticationClockAdapter(IGatewayClock inner) : IAuthenticationClock
    {
        public DateTimeOffset UtcNow => inner.UtcNow;
    }

    private sealed class AuthenticationPrivateDestinationAllowanceAdapter(IPrivateDestinationAllowance inner) : IAuthenticationPrivateDestinationAllowance
    {
        public bool IsAllowed(string host, System.Net.IPAddress address) => inner.IsAllowed(host, address);
    }

    private sealed class PublishedVerticalAuthority(
        IConnectorConfigurationStore store,
        AuthorizedConnectorExecution execution) : IAuthenticationPolicySource, IAuthenticationResourceBindingResolver
    {
        internal AuthenticationExecutionContext Context(string profileId) => new(
            execution.TenantId,
            execution.InstallationId,
            execution.ApplicationId,
            execution.EnvironmentId,
            execution.PublishedAuthority.VersionId,
            execution.ConnectorId,
            execution.OperationId,
            profileId,
            execution.Operation.Endpoint,
            execution.CorrelationId);

        internal async Task<VerticalProfile> ResolveProfileAsync(CancellationToken cancellationToken) =>
            (await CurrentAsync(cancellationToken).ConfigureAwait(false)).Profile;

        public async Task<ServerOwnedRs256PolicySnapshot> ResolveRs256Async(
            AuthenticationExecutionContext context,
            string policyId,
            CancellationToken cancellationToken)
        {
            CurrentPublished current = await CurrentAsync(cancellationToken).ConfigureAwait(false);
            EnsureContext(context, current.Profile.SigningProfileId, policyId);
            return SigningPolicy(current);
        }

        public async Task<ServerOwnedMutualTlsPolicySnapshot> ResolveMutualTlsAsync(
            AuthenticationExecutionContext context,
            string policyId,
            CancellationToken cancellationToken)
        {
            CurrentPublished current = await CurrentAsync(cancellationToken).ConfigureAwait(false);
            EnsureContext(context, current.Profile.TransportProfileId, policyId);
            return MutualTlsPolicy(current);
        }

        public async Task<BoundAuthenticationResource> ResolveAsync(
            AuthenticationExecutionContext context,
            string logicalBindingId,
            AuthenticationResourcePurpose purpose,
            CancellationToken cancellationToken)
        {
            CurrentPublished current = await CurrentAsync(cancellationToken).ConfigureAwait(false);
            string expectedProfile = purpose == AuthenticationResourcePurpose.JwtSigning
                ? current.Profile.SigningProfileId
                : current.Profile.TransportProfileId;
            EnsureContext(context, expectedProfile, expectedProfile);
            string expectedBinding = purpose == AuthenticationResourcePurpose.JwtSigning
                ? current.Profile.SigningKeyBinding
                : current.Profile.ClientCertificateBinding;
            if (!string.Equals(logicalBindingId, expectedBinding, StringComparison.Ordinal) ||
                !current.Snapshot.Bindings.CertificateResources.TryGetValue(expectedBinding, out ProviderResourceBinding? binding) ||
                !current.Snapshot.CertificateProviderReferences.TryGetValue(expectedBinding, out string? providerReference) ||
                binding.ResourceType != ProviderResourceType.ClientCertificate)
                throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-BOUNDARY");
            CertificatePublicMetadata metadata = binding.CertificateMetadata ??
                throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-METADATA");
            string spkiSha256 = purpose == AuthenticationResourcePurpose.JwtSigning
                ? current.Profile.SigningSpkiSha256
                : current.Profile.ClientCertificateSpkiSha256;
            string policyChecksum = purpose == AuthenticationResourcePurpose.JwtSigning
                ? SigningPolicy(current).PolicyChecksumSha256
                : MutualTlsPolicy(current).PolicyChecksumSha256;
            long policyRevision = purpose == AuthenticationResourcePurpose.JwtSigning
                ? current.Profile.SigningRevision
                : current.Profile.TransportRevision;
            return new(
                expectedBinding,
                purpose,
                AuthenticationResourceStatus.Active,
                current.Snapshot.Version.Id,
                execution.ConnectorId,
                execution.OperationId,
                expectedProfile,
                policyRevision,
                policyChecksum,
                execution.EnvironmentId,
                execution.Operation.Endpoint,
                binding.CatalogRevision,
                binding.CatalogChecksumSha256,
                providerReference,
                new(metadata.FingerprintSha256, spkiSha256, metadata.NotBefore, metadata.NotAfter,
                    metadata.KeyAlgorithm, metadata.PublicKeySize, metadata.Version));
        }

        private async Task<CurrentPublished> CurrentAsync(CancellationToken cancellationToken)
        {
            try
            {
                PublishedConnectorAccessContext access = new(
                    execution.InstallationId,
                    execution.TenantId,
                    execution.ApplicationId,
                    execution.OperationId);
                PublishedConnectorSnapshot snapshot = await store.GetPublishedSnapshotAsync(
                    execution.ConnectorId,
                    execution.EnvironmentId,
                    access,
                    cancellationToken).ConfigureAwait(false) ?? throw Stale();
                if (!execution.PublishedAuthority.Matches(snapshot)) throw Stale();
                using JsonDocument document = JsonDocument.Parse(snapshot.Version.CanonicalJson, new JsonDocumentOptions { MaxDepth = 32 });
                JsonElement operation = document.RootElement.GetProperty("operations").EnumerateArray()
                    .Single(value => string.Equals(value.GetProperty("operationId").GetString(), execution.OperationId, StringComparison.Ordinal));
                Uri endpoint = new(
                    snapshot.Bindings.Endpoints[operation.GetProperty("endpointBinding").GetString()!],
                    operation.GetProperty("path").GetString()!);
                if (endpoint != execution.Operation.Endpoint ||
                    !operation.TryGetProperty("authorizedCapabilities", out JsonElement capabilities))
                    throw Stale();
                return new(snapshot, operation.Clone(), ParseProfile(operation, capabilities));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancellationToken);
            }
            catch (AuthenticationPrimitiveException)
            {
                throw;
            }
            catch (Exception)
            {
                throw Stale();
            }
        }

        private ServerOwnedRs256PolicySnapshot SigningPolicy(CurrentPublished current)
        {
            ProviderResourceBinding binding = RequiredCertificateBinding(current, current.Profile.SigningKeyBinding);
            CertificatePublicMetadata metadata = binding.CertificateMetadata!;
            return ServerOwnedRs256PolicySnapshot.Create(
                current.Profile.SigningProfileId,
                current.Profile.SigningRevision,
                current.Snapshot.Version.Id,
                execution.ConnectorId,
                execution.OperationId,
                execution.EnvironmentId,
                execution.Operation.Endpoint,
                current.Profile.Issuer,
                current.Profile.Audience,
                current.Profile.SubjectPolicy,
                current.Profile.FixedSubject,
                current.Profile.AllowedClaims,
                current.Profile.TokenLifetime,
                current.Profile.ClockSkew,
                current.Profile.SigningKeyBinding,
                metadata.Version,
                binding.CatalogRevision,
                binding.CatalogChecksumSha256,
                current.Profile.MinimumRsaKeySize,
                current.Profile.CertificateHeaderMode,
                current.Profile.TemporalClaimMode);
        }

        private ServerOwnedMutualTlsPolicySnapshot MutualTlsPolicy(CurrentPublished current)
        {
            ProviderResourceBinding binding = RequiredCertificateBinding(current, current.Profile.ClientCertificateBinding);
            CertificatePublicMetadata metadata = binding.CertificateMetadata!;
            return ServerOwnedMutualTlsPolicySnapshot.Create(
                current.Profile.TransportProfileId,
                current.Profile.TransportRevision,
                current.Snapshot.Version.Id,
                execution.ConnectorId,
                execution.OperationId,
                execution.EnvironmentId,
                execution.Operation.Endpoint,
                execution.Operation.Method.Method,
                current.Profile.ClientCertificateBinding,
                metadata.Version,
                binding.CatalogRevision,
                binding.CatalogChecksumSha256,
                current.Profile.NearExpiryWarningWindow,
                TimeSpan.FromMilliseconds(execution.Operation.TimeoutMilliseconds),
                execution.Operation.MaximumResponseBytes);
        }

        private static ProviderResourceBinding RequiredCertificateBinding(CurrentPublished current, string logicalBindingId)
        {
            if (!current.Snapshot.Bindings.CertificateResources.TryGetValue(logicalBindingId, out ProviderResourceBinding? binding) ||
                binding.ResourceType != ProviderResourceType.ClientCertificate || binding.CertificateMetadata is null)
                throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-BOUNDARY");
            return binding;
        }

        private void EnsureContext(AuthenticationExecutionContext context, string profileId, string policyId)
        {
            AuthenticationExecutionContext expected = Context(profileId);
            if (context != expected || !string.Equals(policyId, profileId, StringComparison.Ordinal))
                throw new AuthenticationPrimitiveException("BGW-AUTH-BOUND-CONTEXT-INVALID");
        }

        private static VerticalProfile ParseProfile(JsonElement operation, JsonElement capabilities)
        {
            JsonElement signing = capabilities.GetProperty("signing");
            JsonElement restrictedTransport = capabilities.GetProperty("restrictedTransport");
            JsonElement authentication = operation.GetProperty("authentication");
            if (!string.Equals(authentication.GetProperty("kind").GetString(), "mtls", StringComparison.Ordinal)) throw Stale();
            return new(
                signing.GetProperty("profileId").GetString()!,
                signing.GetProperty("revision").GetInt64(),
                signing.GetProperty("keyBinding").GetString()!,
                signing.GetProperty("publicKeySpkiSha256").GetString()!,
                signing.GetProperty("issuer").GetString()!,
                signing.GetProperty("audience").GetString()!,
                signing.GetProperty("subject").GetString()! switch
                {
                    "installation" => JwtSubjectPolicy.Installation,
                    "application" => JwtSubjectPolicy.Application,
                    "tenant" => JwtSubjectPolicy.Tenant,
                    "fixed" => JwtSubjectPolicy.Fixed,
                    _ => throw Stale()
                },
                signing.TryGetProperty("fixedSubject", out JsonElement fixedSubject) ? fixedSubject.GetString() : null,
                signing.GetProperty("allowedClaims").EnumerateArray().Select(value => value.GetString()!).ToFrozenSet(StringComparer.Ordinal),
                TimeSpan.FromSeconds(signing.GetProperty("tokenLifetimeSeconds").GetInt32()),
                TimeSpan.FromSeconds(signing.GetProperty("clockSkewSeconds").GetInt32()),
                signing.GetProperty("minimumRsaKeySize").GetInt32(),
                signing.GetProperty("certificateHeader").GetString()! switch
                {
                    "none" => JwtCertificateHeaderMode.None,
                    "leaf" => JwtCertificateHeaderMode.Leaf,
                    "chain" => JwtCertificateHeaderMode.Chain,
                    _ => throw Stale()
                },
                signing.GetProperty("temporalClaims").GetString()! switch
                {
                    "iat-exp" => JwtTemporalClaimMode.IssuedAtExpiration,
                    "iat-nbf-exp" => JwtTemporalClaimMode.IssuedAtNotBeforeExpiration,
                    _ => throw Stale()
                },
                restrictedTransport.GetProperty("profileId").GetString()!,
                restrictedTransport.GetProperty("revision").GetInt64(),
                authentication.GetProperty("certificateBinding").GetString()!,
                restrictedTransport.GetProperty("clientCertificateSpkiSha256").GetString()!,
                TimeSpan.FromSeconds(restrictedTransport.GetProperty("nearExpirySeconds").GetInt32()));
        }

        private static AuthenticationPrimitiveException Stale() => new("BGW-AUTH-VERTICAL-AUTHORITY-STALE");
    }

    private sealed record CurrentPublished(
        PublishedConnectorSnapshot Snapshot,
        JsonElement Operation,
        VerticalProfile Profile);

    private sealed record VerticalProfile(
        string SigningProfileId,
        long SigningRevision,
        string SigningKeyBinding,
        string SigningSpkiSha256,
        string Issuer,
        string Audience,
        JwtSubjectPolicy SubjectPolicy,
        string? FixedSubject,
        IReadOnlySet<string> AllowedClaims,
        TimeSpan TokenLifetime,
        TimeSpan ClockSkew,
        int MinimumRsaKeySize,
        JwtCertificateHeaderMode CertificateHeaderMode,
        JwtTemporalClaimMode TemporalClaimMode,
        string TransportProfileId,
        long TransportRevision,
        string ClientCertificateBinding,
        string ClientCertificateSpkiSha256,
        TimeSpan NearExpiryWarningWindow);
}

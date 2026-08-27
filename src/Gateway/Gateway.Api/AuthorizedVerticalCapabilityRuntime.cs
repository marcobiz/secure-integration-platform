using System.Collections.Frozen;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
    private static readonly HashSet<string> SignedTokenHeadersForbidden = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "SOAPAction", "Content-Type", "Cookie", "Set-Cookie", "Host", "Content-Length",
        "Forwarded", "Via", "Expect", "TE", "Trailer", "Proxy-Authorization", "Proxy-Authenticate",
        "Connection", "Transfer-Encoding", "Upgrade", "X-Correlation-ID", "traceparent", "tracestate", "baggage"
    };
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

    public async Task ValidatePublishedOperationExpectationsAsync(
        AuthorizedConnectorExecution execution,
        AuthorizedPublishedOperationExpectations expectations,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentNullException.ThrowIfNull(expectations);
        try
        {
            if (execution.AuthenticationKind != expectations.AuthenticationKind)
                throw PolicyMismatch();

            PublishedVerticalAuthority authority = new(store, execution);
            PublishedCapabilityPresence actualPresence = await authority.ResolveCapabilityPresenceAsync(cancellationToken).ConfigureAwait(false);
            if (expectations.RestrictedTransportRequired != actualPresence.RestrictedTransportPresent ||
                expectations.SigningSlots.Count != actualPresence.SigningSlots.Count ||
                expectations.SigningSlots.Keys.Any(key => !actualPresence.SigningSlots.Contains(key)))
                throw PolicyMismatch();
            if (!actualPresence.RestrictedTransportPresent && actualPresence.SigningSlots.Count == 0)
            {
                execution.AuthorizeRestrictedTransportResponseMode(expectations.RestrictedTransportResponseMode);
                return;
            }

            CurrentPublished current = await authority.ResolveCurrentAsync(cancellationToken).ConfigureAwait(false);
            VerticalProfile profile = current.Profile;
            if (expectations.SigningSlots.Count != profile.SigningSlots.Count ||
                expectations.SigningSlots.Keys.Any(key => !profile.SigningSlots.ContainsKey(key)))
                throw PolicyMismatch();

            foreach ((ConnectorSigningSlotKey key, AuthorizedSigningSlotExpectation expected) in expectations.SigningSlots)
            {
                SigningSlotProfile actual = profile.RequiredSigningSlot(key);
                if (expected.Algorithm != AuthorizedSigningAlgorithm.Rs256 || expected.Required != actual.Required ||
                    !string.Equals(expected.Audience, actual.Audience, StringComparison.Ordinal) ||
                    actual.SubjectPolicy != JwtSubjectPolicy.Fixed ||
                    !string.Equals(expected.FixedSubject, actual.FixedSubject, StringComparison.Ordinal) ||
                    expected.TokenLifetimeSeconds != checked((int)actual.TokenLifetime.TotalSeconds) ||
                    expected.TemporalMode != TemporalMode(actual.TemporalClaimMode) ||
                    !expected.JtiRequired || expected.CertificateHeaderMode != CertificateHeaderMode(actual.CertificateHeaderMode) ||
                    expected.CertificateKeyUsageMode != CertificateKeyUsageMode(actual.CertificateKeyUsageMode) ||
                    expected.AllowedBusinessClaims.Count != actual.AllowedClaims.Count ||
                    expected.AllowedBusinessClaims.Any(claim => !actual.AllowedClaims.Contains(claim)) ||
                    expected.Projection.Kind != ProjectionKind(actual.Projection.Kind) ||
                    !string.Equals(expected.Projection.HeaderName, actual.Projection.HeaderName, StringComparison.Ordinal))
                    throw PolicyMismatch();
            }

            HashSet<ConnectorSigningSlotKey> identitySlots = expectations.SameSigningIdentitySlots
                .Concat(expectations.SigningIdentityDistinctFromMutualTlsSlots)
                .Concat(expectations.SigningSlots.Values
                    .Where(value => value.Issuer.Kind == AuthorizedSigningIssuerExpectationKind.FixedPrefixAndCertificateSubjectCommonName)
                    .Select(value => value.SigningSlot))
                .ToHashSet();
            Dictionary<ConnectorSigningSlotKey, VerifiedCertificateIdentity> identities = [];
            foreach (ConnectorSigningSlotKey key in identitySlots.OrderBy(value => value.Value, StringComparer.Ordinal))
            {
                SigningSlotProfile slot = profile.RequiredSigningSlot(key);
                identities.Add(key, await VerifyCertificateIdentityAsync(
                    current, slot.SigningKeyBinding, slot.SigningSpkiSha256, cancellationToken).ConfigureAwait(false));
                await authority.ResolveCurrentAsync(cancellationToken).ConfigureAwait(false);
            }

            foreach ((ConnectorSigningSlotKey key, AuthorizedSigningSlotExpectation expected) in expectations.SigningSlots)
            {
                SigningSlotProfile actual = profile.RequiredSigningSlot(key);
                string expectedIssuer = expected.Issuer.Kind switch
                {
                    AuthorizedSigningIssuerExpectationKind.Exact => expected.Issuer.Value,
                    AuthorizedSigningIssuerExpectationKind.FixedPrefixAndCertificateSubjectCommonName
                        when identities.TryGetValue(key, out VerifiedCertificateIdentity? identity) =>
                        expected.Issuer.Value + identity.SubjectCommonName,
                    _ => throw PolicyMismatch()
                };
                if (expectedIssuer.Length > 512 || !string.Equals(expectedIssuer, actual.Issuer, StringComparison.Ordinal))
                    throw PolicyMismatch();
            }

            if (expectations.SameSigningIdentitySlots.Count > 0)
            {
                string? first = null;
                foreach (ConnectorSigningSlotKey key in expectations.SameSigningIdentitySlots.OrderBy(value => value.Value, StringComparer.Ordinal))
                {
                    string currentIdentity = identities[key].SubjectPublicKeyInfoSha256;
                    if (first is not null && !FixedHexEquals(first, currentIdentity)) throw PolicyMismatch();
                    first = currentIdentity;
                }
            }
            if (expectations.SigningIdentityDistinctFromMutualTlsSlots.Count > 0)
            {
                VerifiedCertificateIdentity mutualTls = await VerifyCertificateIdentityAsync(
                    current, profile.ClientCertificateBinding, profile.ClientCertificateSpkiSha256, cancellationToken).ConfigureAwait(false);
                await authority.ResolveCurrentAsync(cancellationToken).ConfigureAwait(false);
                foreach (ConnectorSigningSlotKey key in expectations.SigningIdentityDistinctFromMutualTlsSlots)
                    if (FixedHexEquals(identities[key].SubjectPublicKeyInfoSha256, mutualTls.SubjectPublicKeyInfoSha256))
                        throw PolicyMismatch();
            }
            execution.AuthorizeRestrictedTransportResponseMode(expectations.RestrictedTransportResponseMode);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (GatewayException)
        {
            throw;
        }
        catch (AuthenticationPrimitiveException exception)
        {
            throw Map(exception);
        }
        catch (Exception)
        {
            throw PolicyMismatch();
        }
    }

    public async Task<string> CreateSignedTokenAsync(
        AuthorizedConnectorExecution execution,
        ConnectorSigningSlotKey signingSlot,
        IReadOnlyDictionary<string, JsonElement> claims,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentNullException.ThrowIfNull(signingSlot);
        ArgumentNullException.ThrowIfNull(claims);
        try
        {
            PublishedVerticalAuthority authority = new(store, execution, signingSlot);
            VerticalProfile profile = await authority.ResolveProfileAsync(cancellationToken).ConfigureAwait(false);
            SigningSlotProfile slot = profile.RequiredSigningSlot(signingSlot);
            AuthenticationExecutionContext context = authority.Context(slot.SigningProfileId);
            Rs256JwtSigner signer = new(
                authority,
                authority,
                keyOperations,
                replayStore,
                clock,
                certificatePublicMaterial: certificatePublicMaterial);
            JwtBoundClaim[] boundedClaims = claims.OrderBy(value => value.Key, StringComparer.Ordinal)
                .Select(value => new JwtBoundClaim(value.Key, value.Value)).ToArray();
            return await signer.SignJwtAsync(context, slot.SigningProfileId, boundedClaims, cancellationToken).ConfigureAwait(false);
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
        IReadOnlyDictionary<ConnectorSigningSlotKey, AuthorizedConnectorSignedToken> signedTokens,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(signedTokens);
        try
        {
            PublishedVerticalAuthority authority = new(store, execution, request: request);
            VerticalProfile profile = await authority.ResolveProfileAsync(cancellationToken).ConfigureAwait(false);
            ValidateSignedTokens(profile, signedTokens);
            AuthenticationExecutionContext context = authority.Context(profile.TransportProfileId);
            using HttpRequestMessage outbound = new(execution.Operation.Method, authority.EffectiveEndpoint);
            if (profile.BodyMode == PublishedRestrictedTransportBodyMode.Required)
            {
                if (!request.HasBody) throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
                outbound.Content = new ByteArrayContent(request.Body.ToArray());
                outbound.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(execution.Operation.RequestContentType);
            }
            else if (request.HasBody)
            {
                throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
            }
            foreach (SigningSlotProfile slot in profile.SigningSlots.Values.OrderBy(value => value.SigningSlot.Value, StringComparer.Ordinal))
            {
                if (!signedTokens.TryGetValue(slot.SigningSlot, out AuthorizedConnectorSignedToken? signedToken))
                    continue;
                switch (slot.Projection.Kind)
                {
                    case SigningTokenProjectionKind.AuthorizationBearer:
                        outbound.Headers.Authorization = new AuthenticationHeaderValue("Bearer", signedToken.CompactToken);
                        break;
                    case SigningTokenProjectionKind.SignedTokenHeader:
                        if (!outbound.Headers.TryAddWithoutValidation(slot.Projection.HeaderName!, signedToken.CompactToken))
                            throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
                        break;
                    default:
                        throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
                }
            }
            outbound.Headers.TryAddWithoutValidation("X-Correlation-ID", execution.CorrelationId.ToString("D"));
            bool boundedProblemDetails = execution.RestrictedTransportResponseMode ==
                AuthorizedRestrictedTransportResponseMode.BoundedProblemDetails;
            if (boundedProblemDetails)
                outbound.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            PurposeBoundMutualTlsSender sender = new(
                authority,
                authority,
                certificates,
                certificateMetadata,
                new AuthenticationHostResolverAdapter(hostResolver, boundedProblemDetails),
                new PurposeBoundMutualTlsTransportAdapter(transport, boundedProblemDetails),
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
        catch (RestrictedTransportFailureException exception)
        {
            bool retryable = execution.Operation.Idempotent && execution.Operation.MaximumRetries > 0 &&
                exception.Phase == RestrictedTransportFailurePhase.Timeout;
            throw new GatewayException(
                "BGW-EGRESS-UPSTREAM-REJECTED",
                502,
                retryable,
                SafeUpstreamFailureDiagnostics.Transport(exception.Phase));
        }
    }

    private static void ValidateSignedTokens(
        VerticalProfile profile,
        IReadOnlyDictionary<ConnectorSigningSlotKey, AuthorizedConnectorSignedToken> signedTokens)
    {
        if (signedTokens.Count > AuthorizedSigningSlots.MaximumSlots)
            throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
        foreach (SigningSlotProfile required in profile.SigningSlots.Values.Where(value => value.Required))
            if (!signedTokens.ContainsKey(required.SigningSlot))
                throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
        foreach ((ConnectorSigningSlotKey key, AuthorizedConnectorSignedToken token) in signedTokens)
            if (!profile.SigningSlots.ContainsKey(key) || token.SigningSlot != key)
                throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
    }

    private async Task<VerifiedCertificateIdentity> VerifyCertificateIdentityAsync(
        CurrentPublished current,
        string logicalBindingId,
        string expectedSpkiSha256,
        CancellationToken cancellationToken)
    {
        if (certificatePublicMaterial is null ||
            !current.Snapshot.Bindings.CertificateResources.TryGetValue(logicalBindingId, out ProviderResourceBinding? binding) ||
            !current.Snapshot.CertificateProviderReferences.TryGetValue(logicalBindingId, out string? providerReference) ||
            binding.ResourceType != ProviderResourceType.ClientCertificate || binding.CertificateMetadata is null)
            throw PolicyMismatch();

        ProviderCertificatePublicMaterial material;
        try
        {
            material = await certificatePublicMaterial.GetPublicMaterialAsync(providerReference, cancellationToken).ConfigureAwait(false)
                ?? throw new ProviderAccessException("BGW-PROVIDER-PUBLIC-MATERIAL-INVALID");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { throw PolicyMismatch(); }

        try
        {
            byte[] leafDer = material.LeafCertificateDer.ToArray();
            using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(leafDer);
            using RSA? rsa = leaf.GetRSAPublicKey();
            byte[] spki = rsa?.ExportSubjectPublicKeyInfo() ?? [];
            string fingerprint = Convert.ToHexString(SHA256.HashData(leafDer));
            string verifiedSpki = spki.Length == 0 ? string.Empty : Convert.ToHexString(SHA256.HashData(spki));
            ProviderCertificatePublicMetadata providerMetadata = material.Metadata;
            CertificatePublicMetadata approvedMetadata = binding.CertificateMetadata;
            if (spki.Length == 0 || !FixedHexEquals(expectedSpkiSha256, verifiedSpki) ||
                !FixedHexEquals(material.SubjectPublicKeyInfoSha256, verifiedSpki) ||
                !FixedHexEquals(approvedMetadata.FingerprintSha256, fingerprint) ||
                !FixedHexEquals(providerMetadata.FingerprintSha256, fingerprint) ||
                !string.Equals(approvedMetadata.Subject, providerMetadata.Subject, StringComparison.Ordinal) ||
                !string.Equals(approvedMetadata.Issuer, providerMetadata.Issuer, StringComparison.Ordinal) ||
                approvedMetadata.NotBefore != providerMetadata.NotBefore || approvedMetadata.NotAfter != providerMetadata.NotAfter ||
                !string.Equals(approvedMetadata.KeyAlgorithm, providerMetadata.KeyAlgorithm, StringComparison.Ordinal) ||
                approvedMetadata.PublicKeySize != providerMetadata.PublicKeySize ||
                !string.Equals(approvedMetadata.Version, providerMetadata.Version, StringComparison.Ordinal))
                throw PolicyMismatch();
            string commonName = SubjectCommonName(leaf);
            return new(verifiedSpki, commonName);
        }
        catch (GatewayException) { throw; }
        catch (Exception) { throw PolicyMismatch(); }
    }

    private static AuthorizedSigningTemporalMode TemporalMode(JwtTemporalClaimMode value) => value switch
    {
        JwtTemporalClaimMode.IssuedAtExpiration => AuthorizedSigningTemporalMode.IssuedAtExpiration,
        JwtTemporalClaimMode.IssuedAtNotBeforeExpiration => AuthorizedSigningTemporalMode.IssuedAtNotBeforeExpiration,
        _ => throw PolicyMismatch()
    };

    private static AuthorizedSigningCertificateHeaderMode CertificateHeaderMode(JwtCertificateHeaderMode value) => value switch
    {
        JwtCertificateHeaderMode.None => AuthorizedSigningCertificateHeaderMode.None,
        JwtCertificateHeaderMode.Leaf => AuthorizedSigningCertificateHeaderMode.Leaf,
        JwtCertificateHeaderMode.Chain => AuthorizedSigningCertificateHeaderMode.Chain,
        _ => throw PolicyMismatch()
    };

    private static AuthorizedSigningCertificateKeyUsageMode CertificateKeyUsageMode(
        JwtSigningCertificateKeyUsageMode value) => value switch
    {
        JwtSigningCertificateKeyUsageMode.DigitalSignature => AuthorizedSigningCertificateKeyUsageMode.DigitalSignature,
        JwtSigningCertificateKeyUsageMode.ContentCommitment => AuthorizedSigningCertificateKeyUsageMode.ContentCommitment,
        _ => throw PolicyMismatch()
    };

    private static AuthorizedSigningTokenProjectionKind ProjectionKind(SigningTokenProjectionKind value) => value switch
    {
        SigningTokenProjectionKind.AuthorizationBearer => AuthorizedSigningTokenProjectionKind.AuthorizationBearer,
        SigningTokenProjectionKind.SignedTokenHeader => AuthorizedSigningTokenProjectionKind.SignedTokenHeader,
        _ => throw PolicyMismatch()
    };

    private static bool FixedHexEquals(string left, string right)
    {
        try
        {
            return left.Length == 64 && right.Length == 64 &&
                CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));
        }
        catch (FormatException) { return false; }
    }

    private static string SubjectCommonName(X509Certificate2 certificate)
    {
        const string CommonNameObjectIdentifier = "2.5.4.3";
        string? commonName = null;
        foreach (X500RelativeDistinguishedName relativeName in certificate.SubjectName.EnumerateRelativeDistinguishedNames())
        {
            if (relativeName.HasMultipleElements) throw PolicyMismatch();
            if (!string.Equals(relativeName.GetSingleElementType().Value, CommonNameObjectIdentifier, StringComparison.Ordinal))
                continue;
            string? value = relativeName.GetSingleElementValue();
            if (commonName is not null || string.IsNullOrWhiteSpace(value) || value.Length > 256 ||
                !value.IsNormalized(System.Text.NormalizationForm.FormC) || value.Any(char.IsControl))
                throw PolicyMismatch();
            commonName = value;
        }
        return commonName ?? throw PolicyMismatch();
    }

    private static GatewayException PolicyMismatch() => new("BGW-EGRESS-AUTHENTICATION", 409);

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
        AuthorizedConnectorExecution execution,
        ConnectorSigningSlotKey? signingSlot = null,
        AuthorizedConnectorRestrictedTransportRequest? request = null) : IAuthenticationPolicySource, IAuthenticationResourceBindingResolver
    {
        private Uri? effectiveEndpoint;

        internal Uri EffectiveEndpoint => effectiveEndpoint ?? execution.Operation.Endpoint;

        internal AuthenticationExecutionContext Context(string profileId) => new(
            execution.TenantId,
            execution.InstallationId,
            execution.ApplicationId,
            execution.EnvironmentId,
            execution.PublishedAuthority.VersionId,
            execution.ConnectorId,
            execution.OperationId,
            profileId,
            EffectiveEndpoint,
            execution.CorrelationId);

        internal async Task<VerticalProfile> ResolveProfileAsync(CancellationToken cancellationToken)
        {
            CurrentPublished current = await CurrentAsync(cancellationToken).ConfigureAwait(false);
            effectiveEndpoint ??= current.EffectiveEndpoint;
            if (effectiveEndpoint != current.EffectiveEndpoint) throw Stale();
            return current.Profile;
        }

        internal Task<CurrentPublished> ResolveCurrentAsync(CancellationToken cancellationToken) => CurrentAsync(cancellationToken);

        internal async Task<PublishedCapabilityPresence> ResolveCapabilityPresenceAsync(CancellationToken cancellationToken)
        {
            CurrentOperation current = await CurrentOperationAsync(cancellationToken).ConfigureAwait(false);
            if (!current.Operation.TryGetProperty("authorizedCapabilities", out JsonElement capabilities))
                return new(false, new HashSet<ConnectorSigningSlotKey>());
            if (capabilities.ValueKind != JsonValueKind.Object)
                throw Stale();

            bool restrictedTransportPresent = capabilities.TryGetProperty("restrictedTransport", out _);
            bool legacySigningPresent = capabilities.TryGetProperty("signing", out _);
            bool signingSlotsPresent = capabilities.TryGetProperty("signingSlots", out JsonElement signingSlots);
            if (legacySigningPresent && signingSlotsPresent)
                throw Stale();

            HashSet<ConnectorSigningSlotKey> actualSlots = [];
            if (legacySigningPresent)
                actualSlots.Add(ConnectorSigningSlotKeys.Legacy);
            if (signingSlotsPresent)
            {
                if (signingSlots.ValueKind != JsonValueKind.Array ||
                    signingSlots.GetArrayLength() > AuthorizedSigningSlots.MaximumSlots)
                    throw Stale();
                foreach (JsonElement value in signingSlots.EnumerateArray())
                {
                    ConnectorSigningSlotKey key = ConnectorSigningSlotKey.Parse(value.GetProperty("slot").GetString()!);
                    if (!actualSlots.Add(key)) throw Stale();
                }
            }
            return new(restrictedTransportPresent, actualSlots);
        }

        public async Task<ServerOwnedRs256PolicySnapshot> ResolveRs256Async(
            AuthenticationExecutionContext context,
            string policyId,
            CancellationToken cancellationToken)
        {
            CurrentPublished current = await CurrentAsync(cancellationToken).ConfigureAwait(false);
            SigningSlotProfile slot = current.Profile.RequiredSigningSlot(signingSlot);
            EnsureContext(context, slot.SigningProfileId, policyId);
            return SigningPolicy(current, slot);
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
            SigningSlotProfile? slot = purpose == AuthenticationResourcePurpose.JwtSigning
                ? current.Profile.RequiredSigningSlot(signingSlot)
                : null;
            string expectedProfile = purpose == AuthenticationResourcePurpose.JwtSigning
                ? slot!.SigningProfileId
                : current.Profile.TransportProfileId;
            EnsureContext(context, expectedProfile, expectedProfile);
            string expectedBinding = purpose == AuthenticationResourcePurpose.JwtSigning
                ? slot!.SigningKeyBinding
                : current.Profile.ClientCertificateBinding;
            if (!string.Equals(logicalBindingId, expectedBinding, StringComparison.Ordinal) ||
                !current.Snapshot.Bindings.CertificateResources.TryGetValue(expectedBinding, out ProviderResourceBinding? binding) ||
                !current.Snapshot.CertificateProviderReferences.TryGetValue(expectedBinding, out string? providerReference) ||
                binding.ResourceType != ProviderResourceType.ClientCertificate)
                throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-BOUNDARY");
            CertificatePublicMetadata metadata = binding.CertificateMetadata ??
                throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-METADATA");
            string spkiSha256 = purpose == AuthenticationResourcePurpose.JwtSigning
                ? slot!.SigningSpkiSha256
                : current.Profile.ClientCertificateSpkiSha256;
            string policyChecksum = purpose == AuthenticationResourcePurpose.JwtSigning
                ? SigningPolicy(current, slot!).PolicyChecksumSha256
                : MutualTlsPolicy(current).PolicyChecksumSha256;
            long policyRevision = purpose == AuthenticationResourcePurpose.JwtSigning
                ? slot!.SigningRevision
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
                EffectiveEndpoint,
                binding.CatalogRevision,
                binding.CatalogChecksumSha256,
                providerReference,
                new(metadata.FingerprintSha256, spkiSha256, metadata.NotBefore, metadata.NotAfter,
                    metadata.KeyAlgorithm, metadata.PublicKeySize, metadata.Version));
        }

        private async Task<CurrentPublished> CurrentAsync(CancellationToken cancellationToken)
        {
            CurrentOperation currentOperation = await CurrentOperationAsync(cancellationToken).ConfigureAwait(false);
            if (!currentOperation.Operation.TryGetProperty("authorizedCapabilities", out JsonElement capabilities))
                throw Stale();
            VerticalProfile profile = ParseProfile(currentOperation.Operation, capabilities);
            if (request is not null &&
                (profile.BodyMode == PublishedRestrictedTransportBodyMode.Required) != request.HasBody)
                throw new AuthenticationPrimitiveException("BGW-AUTH-RESTRICTED-BODY-MODE-DENIED");
            Uri endpoint = ResolveEffectiveEndpoint(currentOperation, request);
            if (effectiveEndpoint is not null && effectiveEndpoint != endpoint) throw Stale();
            return new(currentOperation.Snapshot, currentOperation.Operation, profile, endpoint);
        }

        private async Task<CurrentOperation> CurrentOperationAsync(CancellationToken cancellationToken)
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
                Uri baseEndpoint = snapshot.Bindings.Endpoints[operation.GetProperty("endpointBinding").GetString()!];
                bool hasTemplate = operation.TryGetProperty("pathTemplate", out _);
                Uri authorizedEndpoint = hasTemplate
                    ? baseEndpoint
                    : new Uri(baseEndpoint, operation.GetProperty("path").GetString()!);
                if (authorizedEndpoint != execution.Operation.Endpoint)
                    throw Stale();
                if (hasTemplate)
                    _ = PublishedPathTemplate.Validate(operation.GetProperty("pathTemplate").GetString()!, "pathTemplate");
                return new(snapshot, operation.Clone(), baseEndpoint);
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

        private static Uri ResolveEffectiveEndpoint(
            CurrentOperation current,
            AuthorizedConnectorRestrictedTransportRequest? transportRequest)
        {
            if (!current.Operation.TryGetProperty("pathTemplate", out JsonElement template))
            {
                if (transportRequest is { PathParameterCount: > 0 })
                    throw new AuthenticationPrimitiveException("BGW-AUTH-RESTRICTED-PATH-DENIED");
                return new Uri(current.BaseEndpoint, current.Operation.GetProperty("path").GetString()!);
            }
            if (transportRequest is null) return current.BaseEndpoint;
            try
            {
                return PublishedPathTemplate.Project(
                    current.BaseEndpoint,
                    template.GetString()!,
                    transportRequest.PathParameters);
            }
            catch (GatewayException)
            {
                throw new AuthenticationPrimitiveException("BGW-AUTH-RESTRICTED-PATH-DENIED");
            }
            catch (ArgumentException)
            {
                throw new AuthenticationPrimitiveException("BGW-AUTH-RESTRICTED-PATH-DENIED");
            }
        }

        private ServerOwnedRs256PolicySnapshot SigningPolicy(CurrentPublished current, SigningSlotProfile slot)
        {
            ProviderResourceBinding binding = RequiredCertificateBinding(current, slot.SigningKeyBinding);
            CertificatePublicMetadata metadata = binding.CertificateMetadata!;
            return ServerOwnedRs256PolicySnapshot.Create(
                slot.SigningProfileId,
                slot.SigningRevision,
                current.Snapshot.Version.Id,
                execution.ConnectorId,
                execution.OperationId,
                execution.EnvironmentId,
                EffectiveEndpoint,
                slot.Issuer,
                slot.Audience,
                slot.SubjectPolicy,
                slot.FixedSubject,
                slot.AllowedClaims,
                slot.TokenLifetime,
                slot.ClockSkew,
                slot.SigningKeyBinding,
                metadata.Version,
                binding.CatalogRevision,
                binding.CatalogChecksumSha256,
                slot.MinimumRsaKeySize,
                slot.CertificateKeyUsageMode,
                slot.CertificateHeaderMode,
                slot.TemporalClaimMode);
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
                EffectiveEndpoint,
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
            JsonElement restrictedTransport = capabilities.GetProperty("restrictedTransport");
            JsonElement authentication = operation.GetProperty("authentication");
            if (!string.Equals(authentication.GetProperty("kind").GetString(), "mtls", StringComparison.Ordinal)) throw Stale();
            Dictionary<ConnectorSigningSlotKey, SigningSlotProfile> signingSlots = [];
            if (capabilities.TryGetProperty("signing", out JsonElement legacySigning))
            {
                if (capabilities.TryGetProperty("signingSlots", out _) ||
                    !string.Equals(restrictedTransport.GetProperty("authorization").GetString(), "signedTokenBearer", StringComparison.Ordinal))
                    throw Stale();
                SigningSlotProfile legacy = ParseSigningSlot(
                    ConnectorSigningSlotKeys.Legacy,
                    legacySigning,
                    required: true,
                    new(SigningTokenProjectionKind.AuthorizationBearer, null));
                signingSlots.Add(legacy.SigningSlot, legacy);
            }
            else
            {
                if (!capabilities.TryGetProperty("signingSlots", out JsonElement slots) ||
                    slots.GetArrayLength() is < 1 or > AuthorizedSigningSlots.MaximumSlots ||
                    restrictedTransport.TryGetProperty("authorization", out _))
                    throw Stale();
                HashSet<string> profileIds = new(StringComparer.Ordinal);
                HashSet<string> headers = new(StringComparer.OrdinalIgnoreCase);
                bool authorizationSeen = false;
                foreach (JsonElement value in slots.EnumerateArray())
                {
                    ConnectorSigningSlotKey key = ConnectorSigningSlotKey.Parse(value.GetProperty("slot").GetString()!);
                    JsonElement projectionValue = value.GetProperty("projection");
                    string projectionKind = projectionValue.GetProperty("kind").GetString()!;
                    SigningTokenProjection projection = projectionKind switch
                    {
                        "authorizationBearer" when !authorizationSeen =>
                            new(SigningTokenProjectionKind.AuthorizationBearer, null),
                        "signedTokenHeader" when IsSafeSignedTokenHeader(projectionValue.GetProperty("headerName").GetString()!) =>
                            new(SigningTokenProjectionKind.SignedTokenHeader, projectionValue.GetProperty("headerName").GetString()!),
                        _ => throw Stale()
                    };
                    authorizationSeen |= projection.Kind == SigningTokenProjectionKind.AuthorizationBearer;
                    if (projection.HeaderName is not null && !headers.Add(projection.HeaderName)) throw Stale();
                    SigningSlotProfile parsed = ParseSigningSlot(
                        key,
                        value.GetProperty("signing"),
                        value.GetProperty("required").GetBoolean(),
                        projection);
                    if (!signingSlots.TryAdd(key, parsed) || !profileIds.Add(parsed.SigningProfileId)) throw Stale();
                }
            }
            return new(
                signingSlots.ToFrozenDictionary(),
                restrictedTransport.GetProperty("profileId").GetString()!,
                restrictedTransport.GetProperty("revision").GetInt64(),
                authentication.GetProperty("certificateBinding").GetString()!,
                restrictedTransport.GetProperty("clientCertificateSpkiSha256").GetString()!,
                TimeSpan.FromSeconds(restrictedTransport.GetProperty("nearExpirySeconds").GetInt32()),
                restrictedTransport.TryGetProperty("bodyMode", out JsonElement bodyMode) &&
                    string.Equals(bodyMode.GetString(), "none", StringComparison.Ordinal)
                    ? PublishedRestrictedTransportBodyMode.None
                    : PublishedRestrictedTransportBodyMode.Required);
        }

        private static SigningSlotProfile ParseSigningSlot(
            ConnectorSigningSlotKey key,
            JsonElement signing,
            bool required,
            SigningTokenProjection projection) => new(
                key,
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
                signing.TryGetProperty("certificateKeyUsage", out JsonElement certificateKeyUsage)
                    ? certificateKeyUsage.GetString()! switch
                    {
                        "digitalSignature" => JwtSigningCertificateKeyUsageMode.DigitalSignature,
                        "contentCommitment" => JwtSigningCertificateKeyUsageMode.ContentCommitment,
                        _ => throw Stale()
                    }
                    : JwtSigningCertificateKeyUsageMode.DigitalSignature,
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
                required,
                projection);

        private static AuthenticationPrimitiveException Stale() => new("BGW-AUTH-VERTICAL-AUTHORITY-STALE");
    }

    private static bool IsSafeSignedTokenHeader(string value) =>
        value.Length is >= 1 and <= 64 &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~') &&
        !SignedTokenHeadersForbidden.Contains(value) &&
        !value.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase) &&
        !value.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase);

    private sealed record CurrentPublished(
        PublishedConnectorSnapshot Snapshot,
        JsonElement Operation,
        VerticalProfile Profile,
        Uri EffectiveEndpoint);

    private sealed record CurrentOperation(
        PublishedConnectorSnapshot Snapshot,
        JsonElement Operation,
        Uri BaseEndpoint);

    private sealed record PublishedCapabilityPresence(
        bool RestrictedTransportPresent,
        IReadOnlySet<ConnectorSigningSlotKey> SigningSlots);

    private sealed record VerticalProfile(
        IReadOnlyDictionary<ConnectorSigningSlotKey, SigningSlotProfile> SigningSlots,
        string TransportProfileId,
        long TransportRevision,
        string ClientCertificateBinding,
        string ClientCertificateSpkiSha256,
        TimeSpan NearExpiryWarningWindow,
        PublishedRestrictedTransportBodyMode BodyMode)
    {
        internal SigningSlotProfile RequiredSigningSlot(ConnectorSigningSlotKey? key)
        {
            if (key is null || !SigningSlots.TryGetValue(key, out SigningSlotProfile? slot))
                throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-SLOT-DENIED");
            return slot;
        }
    }

    private sealed record SigningSlotProfile(
        ConnectorSigningSlotKey SigningSlot,
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
        JwtSigningCertificateKeyUsageMode CertificateKeyUsageMode,
        JwtCertificateHeaderMode CertificateHeaderMode,
        JwtTemporalClaimMode TemporalClaimMode,
        bool Required,
        SigningTokenProjection Projection);

    private sealed record SigningTokenProjection(SigningTokenProjectionKind Kind, string? HeaderName);

    private enum SigningTokenProjectionKind
    {
        AuthorizationBearer,
        SignedTokenHeader
    }

    private enum PublishedRestrictedTransportBodyMode
    {
        Required,
        None
    }

    private sealed record VerifiedCertificateIdentity(
        string SubjectPublicKeyInfoSha256,
        string SubjectCommonName);
}

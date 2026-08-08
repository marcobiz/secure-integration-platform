using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Authentication.CertificateSigning;

/// <summary>Creates policy-bound compact JWTs through a provider-side RS256 operation.</summary>
public sealed class Rs256JwtSigner(
    IAuthenticationPolicySource policySource,
    IAuthenticationResourceBindingResolver bindingResolver,
    IKeyOperationProvider? keyOperations,
    IJwtReplayStore replayStore,
    IAuthenticationClock clock,
    IJwtIdentifierSource? identifierSource = null,
    ICertificatePublicMaterialProvider? certificatePublicMaterial = null,
    ITrustedRuntimeClaimValueResolver? trustedRuntimeClaimValues = null)
{
    private static readonly HashSet<string> ReservedClaims = new(StringComparer.Ordinal)
    {
        "alg", "typ", "kid", "crit", "cty", "jku", "jwk", "x5u", "x5c", "x5t", "x5t#S256",
        "iss", "aud", "sub", "iat", "nbf", "exp", "jti"
    };
    private readonly IJwtIdentifierSource identifiers = identifierSource ?? new RandomJwtIdentifierSource();

    /// <summary>
    /// Resolves the immutable server-owned policy and signs only its allowlisted business claims.
    /// The caller supplies no issuer, audience, subject, lifetime, key, algorithm or provider reference.
    /// </summary>
    public async Task<string> SignJwtAsync(
        AuthenticationExecutionContext context,
        string policyId,
        IReadOnlyList<JwtBoundClaim> claims,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(policyId);
        ArgumentNullException.ThrowIfNull(claims);
        BindingPolicy.ValidateContext(context);

        ServerOwnedRs256PolicySnapshot policy = await ResolvePolicyAsync(context, policyId, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<JwtBoundClaim> validatedClaims = ValidateClaims(policy, claims);
        if (keyOperations is null) throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CAPABILITY-UNAVAILABLE");

        BoundAuthenticationResource resource = await ResolveBindingAsync(context, policy, cancellationToken).ConfigureAwait(false);
        if (policy.CertificateHeaderMode != JwtCertificateHeaderMode.None && certificatePublicMaterial is null)
            throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-CAPABILITY-UNAVAILABLE");
        IReadOnlyList<ResolvedTrustedRuntimeValue> trustedRuntimeValues =
            await ResolveTrustedRuntimeValuesAsync(context, policy, resource, cancellationToken).ConfigureAwait(false);

        ProviderSigningKeyPublicMetadata metadata;
        try
        {
            metadata = await keyOperations.GetSigningKeyMetadataAsync(resource.ProviderReference, cancellationToken).ConfigureAwait(false)
                ?? throw new ProviderAccessException("BGW-PROVIDER-METADATA-INVALID");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (ProviderAccessException exception) { throw ProviderFailure("BGW-AUTH-SIGNING-METADATA-UNAVAILABLE", exception.Retryable); }
        catch (Exception) { throw ProviderFailure("BGW-AUTH-SIGNING-METADATA-UNAVAILABLE"); }

        byte[] verificationKey;
        try { verificationKey = ValidateKeyMetadata(resource.PublicMetadata, metadata, policy, clock.UtcNow); }
        catch (AuthenticationPrimitiveException) { throw; }
        catch (Exception) { throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-KEY-DENIED"); }
        IReadOnlyList<byte[]> certificateHeaderValues = [];
        if (policy.CertificateHeaderMode != JwtCertificateHeaderMode.None)
        {
            ProviderCertificatePublicMaterial material;
            try
            {
                material = await certificatePublicMaterial!.GetPublicMaterialAsync(resource.ProviderReference, cancellationToken).ConfigureAwait(false)
                    ?? throw new ProviderAccessException("BGW-PROVIDER-CERTIFICATE-MATERIAL-INVALID");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (ProviderAccessException exception) { throw ProviderFailure("BGW-AUTH-SIGNING-CERTIFICATE-MATERIAL-UNAVAILABLE", exception.Retryable); }
            catch (Exception) { throw ProviderFailure("BGW-AUTH-SIGNING-CERTIFICATE-MATERIAL-UNAVAILABLE"); }

            try
            {
                ValidatedCertificateHeader validated = ValidateCertificatePublicMaterial(resource.PublicMetadata, metadata, material, policy, clock.UtcNow);
                verificationKey = validated.VerificationSubjectPublicKeyInfo;
                certificateHeaderValues = validated.Certificates;
            }
            catch (AuthenticationPrimitiveException) { throw; }
            catch (Exception) { throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-DENIED"); }
        }

        // Close rotation, disable and policy-substitution windows after provider reads and
        // immediately before the signing operation. The connector never receives this capability.
        ServerOwnedRs256PolicySnapshot currentPolicy = await ResolvePolicyAsync(context, policyId, cancellationToken).ConfigureAwait(false);
        BoundAuthenticationResource currentResource = await ResolveBindingAsync(context, currentPolicy, cancellationToken).ConfigureAwait(false);
        if (!SameAuthorization(policy, currentPolicy, resource, currentResource))
            throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-AUTHORIZATION-STALE");
        ResolvedRs256SigningContext resolved = new(currentPolicy, currentResource, verificationKey);

        DateTimeOffset issuedAt = clock.UtcNow;
        DateTimeOffset expiresAt = issuedAt.Add(resolved.Policy.Lifetime);
        string jwtIdentifier = identifiers.Create();
        if (string.IsNullOrWhiteSpace(jwtIdentifier) || jwtIdentifier.Length > 256)
            throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-IDENTIFIER");
        byte[] identifierDigest = SHA256.HashData(Encoding.UTF8.GetBytes(jwtIdentifier));
        if (!await replayStore.TryReserveAsync(identifierDigest, expiresAt.Add(resolved.Policy.AllowedClockSkew), cancellationToken).ConfigureAwait(false))
            throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-REPLAY");

        string encodedHeader = Base64Url(BuildProtectedHeader(resolved.Policy.CertificateHeaderMode, certificateHeaderValues));
        byte[] payload = BuildPayload(context, resolved.Policy, validatedClaims, trustedRuntimeValues, issuedAt, expiresAt, jwtIdentifier);
        string encodedPayload = Base64Url(payload);
        byte[] signingInput = Encoding.ASCII.GetBytes(encodedHeader + "." + encodedPayload);
        byte[] digest = SHA256.HashData(signingInput);
        byte[] signature;
        try
        {
            signature = await keyOperations.SignDigestAsync(resolved.Resource.ProviderReference, "RS256", digest, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (ProviderAccessException exception) { throw ProviderFailure("BGW-AUTH-SIGNING-OPERATION-FAILED", exception.Retryable); }
        catch (Exception) { throw ProviderFailure("BGW-AUTH-SIGNING-OPERATION-FAILED"); }

        if (signature is null || signature.Length is < 256 or > 1024 || !VerifySignature(resolved.VerificationSubjectPublicKeyInfo, digest, signature))
            throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-RESULT-INVALID");
        // A provider-side sign can be asynchronous. Revalidate once more before releasing token
        // material so a concurrent rotate/disable cannot return stale x5c or an authorized JWT.
        ServerOwnedRs256PolicySnapshot finalPolicy = await ResolvePolicyAsync(context, policyId, cancellationToken).ConfigureAwait(false);
        BoundAuthenticationResource finalResource = await ResolveBindingAsync(context, finalPolicy, cancellationToken).ConfigureAwait(false);
        if (!SameAuthorization(resolved.Policy, finalPolicy, resolved.Resource, finalResource))
            throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-AUTHORIZATION-STALE");
        return encodedHeader + "." + encodedPayload + "." + Base64Url(signature);
    }

    internal static bool IsReservedClaim(string claim) => ReservedClaims.Contains(claim);

    private static IReadOnlyList<JwtBoundClaim> ValidateClaims(ServerOwnedRs256PolicySnapshot policy, IReadOnlyList<JwtBoundClaim> claims)
    {
        if (claims.Count > 32) throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-CLAIMS");
        HashSet<string> names = new(StringComparer.Ordinal);
        foreach (JwtBoundClaim claim in claims)
        {
            if (!BindingPolicy.ValidClaimName(claim.Name) || ReservedClaims.Contains(claim.Name) || !policy.AllowedClaims.Contains(claim.Name))
                throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-CLAIM-DENIED");
            if (!names.Add(claim.Name)) throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-CLAIM-DUPLICATE");
            if (claim.Value.ValueKind is JsonValueKind.Array or JsonValueKind.Object or JsonValueKind.Undefined || claim.Value.GetRawText().Length > 4096 ||
                (claim.Value.ValueKind == JsonValueKind.String && claim.Value.GetString()!.Length > 1024))
                throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-CLAIM-VALUE");
        }
        return claims;
    }

    private static byte[] BuildPayload(
        AuthenticationExecutionContext context,
        ServerOwnedRs256PolicySnapshot policy,
        IReadOnlyList<JwtBoundClaim> claims,
        IReadOnlyList<ResolvedTrustedRuntimeValue> trustedRuntimeValues,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        string jwtIdentifier)
    {
        using MemoryStream output = new();
        using (Utf8JsonWriter writer = new(output))
        {
            writer.WriteStartObject();
            writer.WriteString("iss", policy.Issuer);
            writer.WriteString("aud", policy.Audience);
            writer.WriteString("sub", policy.SubjectPolicy switch
            {
                JwtSubjectPolicy.Installation => context.InstallationId.ToString("D"),
                JwtSubjectPolicy.Application => context.ApplicationId.ToString("D"),
                JwtSubjectPolicy.Fixed => policy.FixedSubject!,
                JwtSubjectPolicy.Tenant => context.TenantId.ToString("D"),
                JwtSubjectPolicy.TrustedRuntimeValue => TrustedValue(context, policy.TrustedSubjectSource!.Value, trustedRuntimeValues),
                _ => throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-POLICY-DENIED")
            });
            writer.WriteNumber("iat", issuedAt.ToUnixTimeSeconds());
            if (policy.TemporalClaimMode == JwtTemporalClaimMode.IssuedAtNotBeforeExpiration)
                writer.WriteNumber("nbf", issuedAt.ToUnixTimeSeconds());
            writer.WriteNumber("exp", expiresAt.ToUnixTimeSeconds());
            writer.WriteString("jti", jwtIdentifier);
            foreach (JwtTrustedClaimBinding claim in policy.TrustedClaims.OrderBy(value => value.Name, StringComparer.Ordinal))
                writer.WriteString(claim.Name, TrustedValue(context, claim.Source, trustedRuntimeValues));
            foreach (JwtBoundClaim claim in claims.OrderBy(value => value.Name, StringComparer.Ordinal))
            {
                writer.WritePropertyName(claim.Name);
                claim.Value.WriteTo(writer);
            }
            writer.WriteEndObject();
        }
        return output.ToArray();
    }

    private static byte[] BuildProtectedHeader(JwtCertificateHeaderMode mode, IReadOnlyList<byte[]> certificates)
    {
        using MemoryStream output = new();
        using (Utf8JsonWriter writer = new(output))
        {
            writer.WriteStartObject();
            writer.WriteString("alg", "RS256");
            writer.WriteString("typ", "JWT");
            if (mode != JwtCertificateHeaderMode.None)
            {
                writer.WriteStartArray("x5c");
                foreach (byte[] certificate in certificates) writer.WriteStringValue(Convert.ToBase64String(certificate));
                writer.WriteEndArray();
            }
            writer.WriteEndObject();
        }
        return output.ToArray();
    }

    private static string TrustedValue(
        AuthenticationExecutionContext context,
        JwtTrustedValueSource source,
        IReadOnlyList<ResolvedTrustedRuntimeValue> trustedRuntimeValues)
    {
        string? builtIn = source switch
        {
            JwtTrustedValueSource.AuthenticatedTenantId => context.TenantId.ToString("D"),
            JwtTrustedValueSource.AuthenticatedApplicationId => context.ApplicationId.ToString("D"),
            JwtTrustedValueSource.AuthenticatedInstallationId => context.InstallationId.ToString("D"),
            _ => null
        };
        if (builtIn is not null) return builtIn;
        ResolvedTrustedRuntimeValue? runtime = trustedRuntimeValues.SingleOrDefault(value => value.Source == source);
        return runtime?.Value ?? throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-POLICY-DENIED");
    }

    private async Task<IReadOnlyList<ResolvedTrustedRuntimeValue>> ResolveTrustedRuntimeValuesAsync(
        AuthenticationExecutionContext context,
        ServerOwnedRs256PolicySnapshot policy,
        BoundAuthenticationResource resource,
        CancellationToken cancellationToken)
    {
        HashSet<JwtTrustedValueSource> sources = [];
        if (policy.TrustedSubjectSource is JwtTrustedValueSource subjectSource) sources.Add(subjectSource);
        foreach (JwtTrustedClaimBinding claim in policy.TrustedClaims)
        {
            if (BindingPolicy.IsTrustedRuntimeSource(claim.Source)) sources.Add(claim.Source);
        }
        if (sources.Count == 0) return [];
        if (trustedRuntimeClaimValues is null)
            throw new AuthenticationPrimitiveException("BGW-AUTH-TRUSTED-RUNTIME-CAPABILITY-UNAVAILABLE");

        TrustedRuntimeClaimInvocationBinding expectedBinding = new(
            context.TenantId,
            context.ApplicationId,
            context.InstallationId,
            context.EnvironmentId,
            context.ConnectorVersionId,
            context.ConnectorId,
            context.OperationId,
            context.ProfileId,
            context.Endpoint,
            context.CorrelationId,
            policy.PolicyId,
            policy.PolicyRevision,
            policy.PolicyChecksumSha256,
            resource.CatalogRevision,
            resource.CatalogChecksumSha256,
            resource.PublicMetadata.Version);
        List<ResolvedTrustedRuntimeValue> resolved = [];
        foreach (JwtTrustedValueSource source in sources.Order())
        {
            TrustedRuntimeClaimValue value;
            try
            {
                TrustedRuntimeClaimResolutionRequest request = new(source, expectedBinding);
                value = await trustedRuntimeClaimValues.ResolveAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception) { throw new AuthenticationPrimitiveException("BGW-AUTH-TRUSTED-RUNTIME-VALUE-UNAVAILABLE"); }

            if (value is null || value.Source != source || value.Provenance != TrustedRuntimeClaimValueProvenance.RegisteredServerResolver ||
                string.IsNullOrWhiteSpace(value.Value) || value.Value.Length > 512 || value.Value.Any(char.IsControl) ||
                !BindingPolicy.IsIdentifier(value.AuthorizationEvidenceReference) ||
                !SameInvocationBinding(expectedBinding, value.InvocationBinding))
                throw new AuthenticationPrimitiveException("BGW-AUTH-TRUSTED-RUNTIME-VALUE-DENIED");
            resolved.Add(new(source, value.Value));
        }
        return resolved;
    }

    private static bool SameInvocationBinding(
        TrustedRuntimeClaimInvocationBinding expected,
        TrustedRuntimeClaimInvocationBinding? actual) =>
        actual is not null &&
        expected.TenantId == actual.TenantId &&
        expected.ApplicationId == actual.ApplicationId &&
        expected.InstallationId == actual.InstallationId &&
        expected.EnvironmentId == actual.EnvironmentId &&
        expected.ConnectorVersionId == actual.ConnectorVersionId &&
        string.Equals(expected.ConnectorId, actual.ConnectorId, StringComparison.Ordinal) &&
        string.Equals(expected.OperationId, actual.OperationId, StringComparison.Ordinal) &&
        string.Equals(expected.ProfileId, actual.ProfileId, StringComparison.Ordinal) &&
        expected.Endpoint == actual.Endpoint &&
        expected.CorrelationId == actual.CorrelationId &&
        string.Equals(expected.PolicyId, actual.PolicyId, StringComparison.Ordinal) &&
        expected.PolicyRevision == actual.PolicyRevision &&
        FixedHexEquals(expected.PolicyChecksumSha256, actual.PolicyChecksumSha256) &&
        expected.CatalogRevision == actual.CatalogRevision &&
        FixedHexEquals(expected.CatalogChecksumSha256, actual.CatalogChecksumSha256) &&
        string.Equals(expected.ResourceVersion, actual.ResourceVersion, StringComparison.Ordinal);

    private static byte[] ValidateKeyMetadata(BoundResourcePublicMetadata expected, ProviderSigningKeyPublicMetadata actual, ServerOwnedRs256PolicySnapshot policy, DateTimeOffset now)
    {
        BindingPolicy.MatchMetadata(expected, actual.FingerprintSha256, actual.NotBefore, actual.NotAfter, actual.KeyAlgorithm, actual.PublicKeySize, actual.Version);
        if (actual.SubjectPublicKeyInfo is null || actual.SubjectPublicKeyInfo.Length is < 256 or > 4096 ||
            !FixedDigestEquals(expected.SubjectPublicKeyInfoSha256, SHA256.HashData(actual.SubjectPublicKeyInfo)) ||
            !string.Equals(actual.KeyAlgorithm, "RSA", StringComparison.Ordinal) || actual.PublicKeySize < policy.MinimumRsaKeySize ||
            actual.NotBefore > now.Add(policy.AllowedClockSkew) || actual.NotAfter <= now.Add(policy.Lifetime))
            throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-KEY-DENIED");
        try
        {
            using RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(actual.SubjectPublicKeyInfo, out int read);
            if (read != actual.SubjectPublicKeyInfo.Length || rsa.KeySize != actual.PublicKeySize)
                throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-KEY-DENIED");
            return actual.SubjectPublicKeyInfo.ToArray();
        }
        catch (CryptographicException) { throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-KEY-DENIED"); }
    }

    private static ValidatedCertificateHeader ValidateCertificatePublicMaterial(
        BoundResourcePublicMetadata expected,
        ProviderSigningKeyPublicMetadata signingMetadata,
        ProviderCertificatePublicMaterial material,
        ServerOwnedRs256PolicySnapshot policy,
        DateTimeOffset now)
    {
        if (material.LeafCertificateDer.Length is < 256 or > ProviderCertificatePublicMaterial.MaximumCertificateDerBytes ||
            material.CertificateChainDer.Count > ProviderCertificatePublicMaterial.MaximumCertificateChainCount)
            throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-DENIED");
        long encodedBytes = material.LeafCertificateDer.Length + material.CertificateChainDer.Sum(value => (long)value.Length);
        if (encodedBytes > ProviderCertificatePublicMaterial.MaximumTotalCertificateDerBytes ||
            material.CertificateChainDer.Any(value => value.Length is < 256 or > ProviderCertificatePublicMaterial.MaximumCertificateDerBytes))
            throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-DENIED");

        byte[] leafDer = material.LeafCertificateDer.ToArray();
        try
        {
            using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(leafDer);
            using RSA? rsa = leaf.GetRSAPublicKey();
            if (rsa is null || rsa.KeySize < policy.MinimumRsaKeySize)
                throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-DENIED");

            byte[] subjectPublicKeyInfo = rsa.ExportSubjectPublicKeyInfo();
            string fingerprint = Convert.ToHexString(SHA256.HashData(leaf.RawData));
            DateTimeOffset notBefore = leaf.NotBefore.ToUniversalTime();
            DateTimeOffset notAfter = leaf.NotAfter.ToUniversalTime();
            ProviderCertificatePublicMetadata publicMetadata = material.Metadata;
            BindingPolicy.MatchMetadata(expected, fingerprint, notBefore, notAfter, "RSA", rsa.KeySize, publicMetadata.Version);
            if (!FixedHexEquals(fingerprint, publicMetadata.FingerprintSha256) ||
                !FixedHexEquals(fingerprint, signingMetadata.FingerprintSha256) ||
                !FixedDigestEquals(expected.SubjectPublicKeyInfoSha256, SHA256.HashData(subjectPublicKeyInfo)) ||
                !FixedHexEquals(expected.SubjectPublicKeyInfoSha256, material.SubjectPublicKeyInfoSha256) ||
                !FixedBytesEquals(subjectPublicKeyInfo, signingMetadata.SubjectPublicKeyInfo) ||
                !string.Equals(publicMetadata.Subject, leaf.Subject, StringComparison.Ordinal) ||
                !string.Equals(publicMetadata.Issuer, leaf.Issuer, StringComparison.Ordinal) ||
                publicMetadata.NotBefore != notBefore || publicMetadata.NotAfter != notAfter ||
                !string.Equals(publicMetadata.KeyAlgorithm, "RSA", StringComparison.Ordinal) || publicMetadata.PublicKeySize != rsa.KeySize ||
                !string.Equals(publicMetadata.Version, signingMetadata.Version, StringComparison.Ordinal) ||
                notBefore > now.Add(policy.AllowedClockSkew) || notAfter <= now.Add(policy.Lifetime))
                throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-DENIED");

            if (leaf.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault() is X509KeyUsageExtension keyUsage &&
                (keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0)
                throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-DENIED");

            if (policy.CertificateHeaderMode == JwtCertificateHeaderMode.Leaf)
                return new(subjectPublicKeyInfo, [leafDer]);
            if (policy.CertificateHeaderMode != JwtCertificateHeaderMode.Chain || material.CertificateChainDer.Count == 0)
                throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-DENIED");

            byte[][] issuerDer = material.CertificateChainDer.Select(value => value.ToArray()).ToArray();
            ValidateCertificationOrder(leaf, issuerDer, now);
            return new(subjectPublicKeyInfo, [leafDer, .. issuerDer]);
        }
        catch (AuthenticationPrimitiveException) { throw; }
        catch (Exception) { throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-DENIED"); }
    }

    private static void ValidateCertificationOrder(X509Certificate2 leaf, IReadOnlyList<byte[]> issuerDer, DateTimeOffset now)
    {
        List<X509Certificate2> issuers = [];
        try
        {
            issuers.AddRange(issuerDer.Select(X509CertificateLoader.LoadCertificate));
            X509Certificate2 child = leaf;
            foreach (X509Certificate2 issuer in issuers)
            {
                if (!FixedBytesEquals(child.IssuerName.RawData, issuer.SubjectName.RawData))
                    throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-DENIED");
                child = issuer;
            }

            using X509Chain chain = new();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.VerificationTime = now.UtcDateTime;
            foreach (X509Certificate2 issuer in issuers) chain.ChainPolicy.ExtraStore.Add(issuer);
            X509Certificate2 last = issuers[^1];
            if (FixedBytesEquals(last.SubjectName.RawData, last.IssuerName.RawData))
            {
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(last);
            }
            else
            {
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            }
            if (!chain.Build(leaf) || chain.ChainElements.Count != issuers.Count + 1 ||
                !FixedBytesEquals(chain.ChainElements[0].Certificate.RawData, leaf.RawData))
                throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-DENIED");
            for (int index = 0; index < issuers.Count; index++)
            {
                if (!FixedBytesEquals(chain.ChainElements[index + 1].Certificate.RawData, issuers[index].RawData))
                    throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CERTIFICATE-DENIED");
            }
        }
        finally
        {
            foreach (X509Certificate2 issuer in issuers) issuer.Dispose();
        }
    }

    private async Task<ServerOwnedRs256PolicySnapshot> ResolvePolicyAsync(AuthenticationExecutionContext context, string policyId, CancellationToken cancellationToken)
    {
        ServerOwnedRs256PolicySnapshot policy = await policySource.ResolveRs256Async(context, policyId, cancellationToken).ConfigureAwait(false)
            ?? throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-POLICY-DENIED");
        BindingPolicy.ValidateRs256Policy(context, policyId, policy);
        return policy;
    }

    private async Task<BoundAuthenticationResource> ResolveBindingAsync(AuthenticationExecutionContext context, ServerOwnedRs256PolicySnapshot policy, CancellationToken cancellationToken)
    {
        BoundAuthenticationResource resource = await bindingResolver.ResolveAsync(context, policy.LogicalKeyBindingId, AuthenticationResourcePurpose.JwtSigning, cancellationToken).ConfigureAwait(false)
            ?? throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-BOUNDARY");
        BindingPolicy.ValidateBinding(context, resource, policy.LogicalKeyBindingId, AuthenticationResourcePurpose.JwtSigning);
        BindingPolicy.ValidateExactPolicyBinding(resource, policy.PolicyRevision, policy.PolicyChecksumSha256, policy.CatalogRevision, policy.CatalogChecksumSha256, policy.ResourceVersion);
        return resource;
    }

    private static bool SameAuthorization(
        ServerOwnedRs256PolicySnapshot expectedPolicy,
        ServerOwnedRs256PolicySnapshot actualPolicy,
        BoundAuthenticationResource expectedResource,
        BoundAuthenticationResource actualResource) =>
        expectedPolicy.PolicyRevision == actualPolicy.PolicyRevision &&
        FixedHexEquals(expectedPolicy.PolicyChecksumSha256, actualPolicy.PolicyChecksumSha256) &&
        expectedResource.CatalogRevision == actualResource.CatalogRevision &&
        FixedHexEquals(expectedResource.CatalogChecksumSha256, actualResource.CatalogChecksumSha256) &&
        string.Equals(expectedResource.ProviderReference, actualResource.ProviderReference, StringComparison.Ordinal) &&
        string.Equals(expectedResource.PublicMetadata.Version, actualResource.PublicMetadata.Version, StringComparison.Ordinal) &&
        FixedHexEquals(expectedResource.PublicMetadata.FingerprintSha256, actualResource.PublicMetadata.FingerprintSha256) &&
        FixedHexEquals(expectedResource.PublicMetadata.SubjectPublicKeyInfoSha256, actualResource.PublicMetadata.SubjectPublicKeyInfoSha256);

    private static bool VerifySignature(byte[] subjectPublicKeyInfo, byte[] digest, byte[] signature)
    {
        try
        {
            using RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out int read);
            return read == subjectPublicKeyInfo.Length && rsa.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException) { return false; }
    }

    private static bool FixedDigestEquals(string expectedHex, byte[] actual) =>
        BindingPolicy.IsSha256(expectedHex) && CryptographicOperations.FixedTimeEquals(Convert.FromHexString(expectedHex), actual);

    private static bool FixedHexEquals(string left, string right) => BindingPolicy.IsSha256(left) && BindingPolicy.IsSha256(right) &&
        CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));

    private static bool FixedBytesEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static AuthenticationPrimitiveException ProviderFailure(string code, bool retryable = false) => new(code, retryable);
    private static string Base64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>Bounded in-memory replay guard for generated JWT identifiers.</summary>
public sealed class InMemoryJwtReplayStore(int maximumEntries, IAuthenticationClock clock) : IJwtReplayStore
{
    private readonly Dictionary<string, DateTimeOffset> entries = new(StringComparer.Ordinal);
    private readonly object sync = new();

    /// <inheritdoc />
    public Task<bool> TryReserveAsync(ReadOnlyMemory<byte> identifierSha256, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (identifierSha256.Length != 32 || maximumEntries is < 1 or > 1_000_000 || expiresAt <= clock.UtcNow)
            return Task.FromResult(false);
        lock (sync)
        {
            foreach (string key in entries.Where(entry => entry.Value <= clock.UtcNow).Select(entry => entry.Key).ToArray()) entries.Remove(key);
            if (entries.Count >= maximumEntries) return Task.FromResult(false);
            return Task.FromResult(entries.TryAdd(Convert.ToHexString(identifierSha256.Span), expiresAt));
        }
    }
}

/// <summary>Cryptographically random 128-bit JWT identifier source.</summary>
public sealed class RandomJwtIdentifierSource : IJwtIdentifierSource
{
    /// <inheritdoc />
    public string Create() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
}

internal sealed class ResolvedRs256SigningContext
{
    internal ResolvedRs256SigningContext(ServerOwnedRs256PolicySnapshot policy, BoundAuthenticationResource resource, byte[] verificationSubjectPublicKeyInfo)
    {
        Policy = policy;
        Resource = resource;
        VerificationSubjectPublicKeyInfo = verificationSubjectPublicKeyInfo.ToArray();
    }

    internal ServerOwnedRs256PolicySnapshot Policy { get; }
    internal BoundAuthenticationResource Resource { get; }
    internal byte[] VerificationSubjectPublicKeyInfo { get; }
}

internal sealed class ValidatedCertificateHeader(byte[] verificationSubjectPublicKeyInfo, IReadOnlyList<byte[]> certificates)
{
    internal byte[] VerificationSubjectPublicKeyInfo { get; } = verificationSubjectPublicKeyInfo.ToArray();
    internal IReadOnlyList<byte[]> Certificates { get; } = certificates.Select(value => value.ToArray()).ToArray();
}

internal sealed record ResolvedTrustedRuntimeValue(JwtTrustedValueSource Source, string Value);

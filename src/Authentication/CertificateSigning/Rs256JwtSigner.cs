using System.Security.Cryptography;
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
    IJwtIdentifierSource? identifierSource = null)
{
    private static readonly HashSet<string> ReservedClaims = new(StringComparer.Ordinal)
    {
        "alg", "typ", "kid", "x5c", "iss", "aud", "sub", "iat", "nbf", "exp", "jti"
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

        ServerOwnedRs256PolicySnapshot policy = await policySource.ResolveRs256Async(context, policyId, cancellationToken).ConfigureAwait(false)
            ?? throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-POLICY-DENIED");
        BindingPolicy.ValidateRs256Policy(context, policyId, policy);
        IReadOnlyList<JwtBoundClaim> validatedClaims = ValidateClaims(policy, claims);
        if (keyOperations is null) throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CAPABILITY-UNAVAILABLE");

        BoundAuthenticationResource resource = await bindingResolver.ResolveAsync(context, policy.LogicalKeyBindingId, AuthenticationResourcePurpose.JwtSigning, cancellationToken).ConfigureAwait(false)
            ?? throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-BOUNDARY");
        BindingPolicy.ValidateBinding(context, resource, policy.LogicalKeyBindingId, AuthenticationResourcePurpose.JwtSigning);
        BindingPolicy.ValidateExactPolicyBinding(resource, policy.PolicyRevision, policy.PolicyChecksumSha256, policy.CatalogRevision, policy.CatalogChecksumSha256, policy.ResourceVersion);

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
        ResolvedRs256SigningContext resolved = new(policy, resource, verificationKey);

        DateTimeOffset issuedAt = clock.UtcNow;
        DateTimeOffset expiresAt = issuedAt.Add(resolved.Policy.Lifetime);
        string jwtIdentifier = identifiers.Create();
        if (string.IsNullOrWhiteSpace(jwtIdentifier) || jwtIdentifier.Length > 256)
            throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-IDENTIFIER");
        byte[] identifierDigest = SHA256.HashData(Encoding.UTF8.GetBytes(jwtIdentifier));
        if (!await replayStore.TryReserveAsync(identifierDigest, expiresAt.Add(resolved.Policy.AllowedClockSkew), cancellationToken).ConfigureAwait(false))
            throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-REPLAY");

        string encodedHeader = Base64Url(Encoding.UTF8.GetBytes("{\"alg\":\"RS256\",\"typ\":\"JWT\"}"));
        byte[] payload = BuildPayload(context, resolved.Policy, validatedClaims, issuedAt, expiresAt, jwtIdentifier);
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

    private static byte[] BuildPayload(AuthenticationExecutionContext context, ServerOwnedRs256PolicySnapshot policy, IReadOnlyList<JwtBoundClaim> claims, DateTimeOffset issuedAt, DateTimeOffset expiresAt, string jwtIdentifier)
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
                _ => throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-POLICY-DENIED")
            });
            writer.WriteNumber("iat", issuedAt.ToUnixTimeSeconds());
            writer.WriteNumber("nbf", issuedAt.ToUnixTimeSeconds());
            writer.WriteNumber("exp", expiresAt.ToUnixTimeSeconds());
            writer.WriteString("jti", jwtIdentifier);
            foreach (JwtBoundClaim claim in claims.OrderBy(value => value.Name, StringComparer.Ordinal))
            {
                writer.WritePropertyName(claim.Name);
                claim.Value.WriteTo(writer);
            }
            writer.WriteEndObject();
        }
        return output.ToArray();
    }

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

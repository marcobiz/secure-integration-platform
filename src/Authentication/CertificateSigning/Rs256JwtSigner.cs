using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Authentication.CertificateSigning;

/// <summary>Creates policy-bound compact JWTs through a provider-side RS256 operation.</summary>
public sealed class Rs256JwtSigner(
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
    /// Signs claims already derived by the Connector runtime. The algorithm, authority, subject,
    /// lifetime and key are fixed by <paramref name="profile"/> and cannot be overridden by claims.
    /// </summary>
    public async Task<string> SignJwtAsync(
        AuthenticationExecutionContext context,
        Rs256JwtProfile profile,
        IReadOnlyList<JwtBoundClaim> claims,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(claims);
        BindingPolicy.ValidateContext(context);
        ValidateProfile(context, profile);
        IReadOnlyList<JwtBoundClaim> validatedClaims = ValidateClaims(profile, claims);
        if (keyOperations is null) throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-CAPABILITY-UNAVAILABLE");

        BoundAuthenticationResource resource = await bindingResolver.ResolveAsync(context, profile.LogicalKeyBindingId, AuthenticationResourcePurpose.JwtSigning, cancellationToken).ConfigureAwait(false)
            ?? throw new AuthenticationPrimitiveException("BGW-AUTH-RESOURCE-BOUNDARY");
        BindingPolicy.ValidateBinding(context, resource, profile.LogicalKeyBindingId, AuthenticationResourcePurpose.JwtSigning);

        ProviderSigningKeyPublicMetadata metadata;
        try { metadata = await keyOperations.GetSigningKeyMetadataAsync(resource.ProviderReference, cancellationToken).ConfigureAwait(false) ?? throw new ProviderAccessException("BGW-PROVIDER-METADATA-INVALID"); }
        catch (ProviderAccessException exception) { throw ProviderFailure("BGW-AUTH-SIGNING-METADATA-UNAVAILABLE", exception); }
        ValidateKeyMetadata(resource.PublicMetadata, metadata, profile, clock.UtcNow);

        DateTimeOffset issuedAt = clock.UtcNow;
        DateTimeOffset expiresAt = issuedAt.Add(profile.Lifetime);
        string jwtIdentifier = identifiers.Create();
        if (string.IsNullOrWhiteSpace(jwtIdentifier) || jwtIdentifier.Length > 256)
            throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-IDENTIFIER");
        byte[] identifierDigest = SHA256.HashData(Encoding.UTF8.GetBytes(jwtIdentifier));
        if (!await replayStore.TryReserveAsync(identifierDigest, expiresAt.Add(profile.AllowedClockSkew), cancellationToken).ConfigureAwait(false))
            throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-REPLAY");

        string encodedHeader = Base64Url(Encoding.UTF8.GetBytes("{\"alg\":\"RS256\",\"typ\":\"JWT\"}"));
        byte[] payload = BuildPayload(context, profile, validatedClaims, issuedAt, expiresAt, jwtIdentifier);
        string encodedPayload = Base64Url(payload);
        byte[] signingInput = Encoding.ASCII.GetBytes(encodedHeader + "." + encodedPayload);
        byte[] digest = SHA256.HashData(signingInput);
        byte[] signature;
        try { signature = await keyOperations.SignDigestAsync(resource.ProviderReference, "RS256", digest, cancellationToken).ConfigureAwait(false); }
        catch (ProviderAccessException exception) { throw ProviderFailure("BGW-AUTH-SIGNING-OPERATION-FAILED", exception); }
        if (signature.Length is < 256 or > 1024 || !VerifySignature(metadata.SubjectPublicKeyInfo, digest, signature))
            throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-RESULT-INVALID");
        return encodedHeader + "." + encodedPayload + "." + Base64Url(signature);
    }

    private static void ValidateProfile(AuthenticationExecutionContext context, Rs256JwtProfile profile)
    {
        if (!BindingPolicy.IsIdentifier(profile.ProfileId) || !string.Equals(profile.ProfileId, context.ProfileId, StringComparison.Ordinal) ||
            !SafeAuthority(profile.Issuer) || !SafeAuthority(profile.Audience) || !BindingPolicy.IsIdentifier(profile.LogicalKeyBindingId) ||
            profile.Lifetime <= TimeSpan.Zero || profile.Lifetime > TimeSpan.FromHours(1) ||
            profile.AllowedClockSkew < TimeSpan.Zero || profile.AllowedClockSkew > TimeSpan.FromMinutes(5) ||
            profile.MinimumRsaKeySize < 2048 || profile.MinimumRsaKeySize > 16384 || profile.AllowedClaims is null || profile.AllowedClaims.Count > 32 ||
            profile.AllowedClaims.Any(name => !ValidClaimName(name) || ReservedClaims.Contains(name)) ||
            (profile.SubjectPolicy == JwtSubjectPolicy.Fixed) != !string.IsNullOrWhiteSpace(profile.FixedSubject) ||
            profile.FixedSubject?.Length > 512)
            throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-PROFILE");
    }

    private static IReadOnlyList<JwtBoundClaim> ValidateClaims(Rs256JwtProfile profile, IReadOnlyList<JwtBoundClaim> claims)
    {
        if (claims.Count > 32) throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-CLAIMS");
        HashSet<string> names = new(StringComparer.Ordinal);
        foreach (JwtBoundClaim claim in claims)
        {
            if (!ValidClaimName(claim.Name) || ReservedClaims.Contains(claim.Name) || !profile.AllowedClaims.Contains(claim.Name))
                throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-CLAIM-DENIED");
            if (!names.Add(claim.Name)) throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-CLAIM-DUPLICATE");
            if (claim.Value.ValueKind is JsonValueKind.Array or JsonValueKind.Object or JsonValueKind.Undefined || claim.Value.GetRawText().Length > 4096 ||
                (claim.Value.ValueKind == JsonValueKind.String && claim.Value.GetString()!.Length > 1024))
                throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-CLAIM-VALUE");
        }
        return claims;
    }

    private static byte[] BuildPayload(AuthenticationExecutionContext context, Rs256JwtProfile profile, IReadOnlyList<JwtBoundClaim> claims, DateTimeOffset issuedAt, DateTimeOffset expiresAt, string jwtIdentifier)
    {
        using MemoryStream output = new();
        using (Utf8JsonWriter writer = new(output))
        {
            writer.WriteStartObject();
            writer.WriteString("iss", profile.Issuer);
            writer.WriteString("aud", profile.Audience);
            writer.WriteString("sub", profile.SubjectPolicy switch
            {
                JwtSubjectPolicy.Installation => context.InstallationId.ToString("D"),
                JwtSubjectPolicy.Application => context.ApplicationId.ToString("D"),
                JwtSubjectPolicy.Fixed => profile.FixedSubject!,
                _ => throw new AuthenticationPrimitiveException("BGW-AUTH-JWT-PROFILE")
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

    private static void ValidateKeyMetadata(BoundResourcePublicMetadata expected, ProviderSigningKeyPublicMetadata actual, Rs256JwtProfile profile, DateTimeOffset now)
    {
        BindingPolicy.MatchMetadata(expected, actual.FingerprintSha256, actual.NotBefore, actual.NotAfter, actual.KeyAlgorithm, actual.PublicKeySize, actual.Version);
        if (!string.Equals(actual.KeyAlgorithm, "RSA", StringComparison.Ordinal) || actual.PublicKeySize < profile.MinimumRsaKeySize ||
            actual.NotBefore > now.Add(profile.AllowedClockSkew) || actual.NotAfter <= now.Add(profile.Lifetime) || actual.SubjectPublicKeyInfo.Length is < 256 or > 4096)
            throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-KEY-DENIED");
        try
        {
            using RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(actual.SubjectPublicKeyInfo, out int read);
            if (read != actual.SubjectPublicKeyInfo.Length || rsa.KeySize != actual.PublicKeySize)
                throw new AuthenticationPrimitiveException("BGW-AUTH-SIGNING-KEY-DENIED");
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

    private static AuthenticationPrimitiveException ProviderFailure(string code, ProviderAccessException exception) => new(code, exception.Retryable);
    private static string Base64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static bool ValidClaimName(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 64 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    private static bool SafeAuthority(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(character => char.IsControl(character));
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

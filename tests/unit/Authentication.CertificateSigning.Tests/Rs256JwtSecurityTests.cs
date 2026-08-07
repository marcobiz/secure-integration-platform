using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.Authentication.CertificateSigning.Tests;

public sealed class Rs256JwtSecurityTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 7, 10, 0, 0, TimeSpan.Zero);
    private static readonly string[] ClaimDenialCodes = ["BGW-AUTH-JWT-PROFILE", "BGW-AUTH-JWT-CLAIM-DENIED"];

    [Fact]
    public async Task M6_RS256_positive_is_policy_bound_and_remote_signed()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        TrackingKeyProvider tracking = new(provider);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1"));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(bindings, tracking, new InMemoryJwtReplayStore(100, clock), clock);

        string token = await signer.SignJwtAsync(context, AuthenticationTestData.JwtProfile(),
            [new("role", JsonSerializer.SerializeToElement("synthetic-pharmacy"))], TestContext.Current.CancellationToken);

        string[] segments = token.Split('.');
        Assert.Equal(3, segments.Length);
        using JsonDocument header = JsonDocument.Parse(Decode(segments[0]));
        using JsonDocument payload = JsonDocument.Parse(Decode(segments[1]));
        Assert.Equal("RS256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal("JWT", header.RootElement.GetProperty("typ").GetString());
        Assert.Equal("https://issuer.example.test", payload.RootElement.GetProperty("iss").GetString());
        Assert.Equal("https://audience.example.test", payload.RootElement.GetProperty("aud").GetString());
        Assert.Equal(context.InstallationId.ToString("D"), payload.RootElement.GetProperty("sub").GetString());
        Assert.Equal(300, payload.RootElement.GetProperty("exp").GetInt64() - payload.RootElement.GetProperty("iat").GetInt64());
        Assert.Equal("synthetic-pharmacy", payload.RootElement.GetProperty("role").GetString());
        AssertSignature(material.SigningKeyRevision1, segments);
        Assert.Equal(["sign-r1"], tracking.MetadataReferences);
        Assert.Equal([("sign-r1", "RS256")], tracking.Signatures);
    }

    [Theory]
    [InlineData("alg")]
    [InlineData("kid")]
    [InlineData("iss")]
    [InlineData("aud")]
    [InlineData("sub")]
    [InlineData("nbf")]
    [InlineData("exp")]
    [InlineData("jti")]
    public async Task M6_JWT_security_sensitive_claim_override_is_denied_before_key_use(string claim)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        TrackingKeyProvider tracking = new(provider);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1"));
        FixedClock clock = new(Now);
        Rs256JwtProfile profile = AuthenticationTestData.JwtProfile() with { AllowedClaims = new HashSet<string>(StringComparer.Ordinal) { claim } };
        Rs256JwtSigner signer = new(bindings, tracking, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(
            context, profile, [new(claim, JsonSerializer.SerializeToElement("hostile"))], TestContext.Current.CancellationToken));

        Assert.Contains(failure.Code, ClaimDenialCodes);
        Assert.Empty(tracking.MetadataReferences);
        Assert.Empty(tracking.Signatures);
    }

    [Fact]
    public async Task M6_JWT_duplicate_and_unsafe_claim_injection_are_denied()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1"));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(bindings, provider, new InMemoryJwtReplayStore(100, clock), clock);
        JwtBoundClaim duplicate = new("role", JsonSerializer.SerializeToElement("one"));

        AuthenticationPrimitiveException duplicateFailure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(
            context, AuthenticationTestData.JwtProfile(), [duplicate, duplicate with { Value = JsonSerializer.SerializeToElement("two") }], TestContext.Current.CancellationToken));
        AuthenticationPrimitiveException injectionFailure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(
            context, AuthenticationTestData.JwtProfile(), [new("unapproved", JsonSerializer.SerializeToElement("value"))], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-JWT-CLAIM-DUPLICATE", duplicateFailure.Code);
        Assert.Equal("BGW-AUTH-JWT-CLAIM-DENIED", injectionFailure.Code);
    }

    [Fact]
    public async Task M6_JWT_excessive_lifetime_is_denied_before_binding_or_provider()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        TrackingKeyProvider tracking = new(AuthenticationTestData.Provider(material));
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1"));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(bindings, tracking, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(
            context, AuthenticationTestData.JwtProfile(TimeSpan.FromHours(2)), [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-JWT-PROFILE", failure.Code);
        Assert.Equal(0, bindings.Calls);
        Assert.Empty(tracking.Signatures);
    }

    [Fact]
    public async Task M6_JWT_disabled_key_denies_with_zero_provider_invocations()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        TrackingKeyProvider tracking = new(AuthenticationTestData.Provider(material));
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", status: AuthenticationResourceStatus.Disabled));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(bindings, tracking, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(context, AuthenticationTestData.JwtProfile(), [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-RESOURCE-DISABLED", failure.Code);
        Assert.Empty(tracking.MetadataReferences);
        Assert.Empty(tracking.Signatures);
    }

    [Fact]
    public async Task M6_JWT_rotation_uses_revision_two_and_never_reuses_revision_one()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        TrackingKeyProvider tracking = new(AuthenticationTestData.Provider(material));
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1"));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(bindings, tracking, new InMemoryJwtReplayStore(100, clock), clock);
        _ = await signer.SignJwtAsync(context, AuthenticationTestData.JwtProfile(), [], TestContext.Current.CancellationToken);

        bindings.Current = AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision2, "sign-r2", revision: 2);
        string rotated = await signer.SignJwtAsync(context, AuthenticationTestData.JwtProfile(), [], TestContext.Current.CancellationToken);

        Assert.Equal(["sign-r1", "sign-r2"], tracking.MetadataReferences);
        Assert.Equal([("sign-r1", "RS256"), ("sign-r2", "RS256")], tracking.Signatures);
        AssertSignature(material.SigningKeyRevision2, rotated.Split('.'));
        Assert.ThrowsAny<CryptographicException>(() => AssertSignature(material.SigningKeyRevision1, rotated.Split('.')));
    }

    [Fact]
    public async Task M6_JWT_wrong_key_result_is_rejected_after_remote_operation()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        InMemoryProvider correct = AuthenticationTestData.Provider(material);
        IKeyOperationProvider wrong = new WrongSigningResultProvider(correct, material.SigningKeyRevision2);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1"));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(bindings, wrong, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(context, AuthenticationTestData.JwtProfile(), [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-SIGNING-RESULT-INVALID", failure.Code);
    }

    [Fact]
    public async Task M6_JWT_replayed_identifier_and_missing_capability_fail_closed()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1"));
        FixedClock clock = new(Now);
        InMemoryJwtReplayStore replay = new(100, clock);
        Rs256JwtSigner signer = new(bindings, provider, replay, clock, new FixedIdentifierSource("same-jti"));
        _ = await signer.SignJwtAsync(context, AuthenticationTestData.JwtProfile(), [], TestContext.Current.CancellationToken);

        AuthenticationPrimitiveException replayFailure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(context, AuthenticationTestData.JwtProfile(), [], TestContext.Current.CancellationToken));
        Rs256JwtSigner unavailable = new(bindings, null, replay, clock);
        AuthenticationPrimitiveException capabilityFailure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => unavailable.SignJwtAsync(context, AuthenticationTestData.JwtProfile(), [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-JWT-REPLAY", replayFailure.Code);
        Assert.Equal("BGW-AUTH-SIGNING-CAPABILITY-UNAVAILABLE", capabilityFailure.Code);
    }

    [Fact]
    public async Task M6_JWT_replay_cache_is_bounded_and_expiry_aware()
    {
        FixedClock clock = new(Now);
        InMemoryJwtReplayStore replay = new(1, clock);
        byte[] first = SHA256.HashData("first"u8);
        byte[] second = SHA256.HashData("second"u8);

        Assert.True(await replay.TryReserveAsync(first, Now.AddMinutes(5), TestContext.Current.CancellationToken));
        Assert.False(await replay.TryReserveAsync(second, Now.AddMinutes(5), TestContext.Current.CancellationToken));
        clock.UtcNow = Now.AddMinutes(6);
        Assert.True(await replay.TryReserveAsync(second, clock.UtcNow.AddMinutes(5), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M6_JWT_binding_scope_purpose_and_metadata_mismatch_deny_before_signing()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        TrackingKeyProvider tracking = new(AuthenticationTestData.Provider(material));
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        BoundAuthenticationResource hostile = AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1") with
        {
            OperationId = "other-operation",
            Purpose = AuthenticationResourcePurpose.MutualTlsClientAuthentication
        };
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(new MutableBindingResolver(hostile), tracking, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(context, AuthenticationTestData.JwtProfile(), [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-RESOURCE-BOUNDARY", failure.Code);
        Assert.Empty(tracking.MetadataReferences);
        Assert.Empty(tracking.Signatures);
    }

    [Fact]
    public async Task M6_JWT_stale_public_metadata_is_denied_before_signing()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        TrackingKeyProvider tracking = new(AuthenticationTestData.Provider(material));
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        BoundAuthenticationResource stale = AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1") with
        {
            PublicMetadata = AuthenticationTestData.Metadata(material.SigningKeyRevision2)
        };
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(new MutableBindingResolver(stale), tracking, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(context, AuthenticationTestData.JwtProfile(), [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-RESOURCE-METADATA-STALE", failure.Code);
        Assert.Empty(tracking.Signatures);
    }

    [Fact]
    public async Task M6_JWT_provider_failure_is_redacted_and_private_key_is_not_in_the_capability_surface()
    {
        const string canary = "m6-provider-locator-and-claim-canary";
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        BoundAuthenticationResource binding = AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, canary);
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(new MutableBindingResolver(binding), new FailingKeyProvider(canary), new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(
            context, AuthenticationTestData.JwtProfile(), [new("role", JsonSerializer.SerializeToElement(canary))], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-SIGNING-METADATA-UNAVAILABLE", failure.Code);
        Assert.Equal(failure.Code, failure.Message);
        Assert.DoesNotContain(canary, failure.ToString(), StringComparison.Ordinal);
        string[] capabilityMethods = typeof(IKeyOperationProvider).GetMethods().Select(method => method.Name).OrderBy(value => value, StringComparer.Ordinal).ToArray();
        Assert.Equal(["GetSigningKeyMetadataAsync", "SignDigestAsync"], capabilityMethods);
        Assert.DoesNotContain(capabilityMethods, method => method.Contains("Private", StringComparison.Ordinal) || method.Contains("Secret", StringComparison.Ordinal));
        Assert.DoesNotContain(typeof(Rs256JwtProfile).GetProperties(), property => property.Name.Contains("Algorithm", StringComparison.Ordinal) || property.Name.Contains("Provider", StringComparison.Ordinal) || property.Name.Contains("Locator", StringComparison.Ordinal));
    }

    private static byte[] Decode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/').PadRight((value.Length + 3) / 4 * 4, '=');
        return Convert.FromBase64String(padded);
    }

    private static void AssertSignature(X509Certificate2 certificate, string[] segments)
    {
        using RSA rsa = certificate.GetRSAPublicKey()!;
        byte[] digest = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]));
        if (!rsa.VerifyHash(digest, Decode(segments[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            throw new CryptographicException("Signature did not match the expected synthetic key.");
    }

    private sealed class WrongSigningResultProvider(IKeyOperationProvider metadataProvider, X509Certificate2 wrongCertificate) : IKeyOperationProvider
    {
        public Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken) => metadataProvider.GetSigningKeyMetadataAsync(logicalReference, cancellationToken);

        public Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken)
        {
            using RSA rsa = wrongCertificate.GetRSAPrivateKey()!;
            return Task.FromResult(rsa.SignHash(digest.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
    }

    private sealed class FailingKeyProvider(string canary) : IKeyOperationProvider
    {
        public Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken) =>
            throw new ProviderAccessException("BGW-PROVIDER-UNAVAILABLE", true, new InvalidOperationException(canary + logicalReference));

        public Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken) =>
            throw new ProviderAccessException("BGW-PROVIDER-UNAVAILABLE", true, new InvalidOperationException(canary + logicalReference));
    }
}

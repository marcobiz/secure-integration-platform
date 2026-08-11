using System.Collections;
using System.Reflection;
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

    [Fact]
    public async Task M6_RS256_positive_resolves_server_owned_policy_and_remote_signs()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        TrackingKeyProvider tracking = new(AuthenticationTestData.Provider(material));
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, tracking, new InMemoryJwtReplayStore(100, clock), clock);

        string token = await signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId,
            [new("role", JsonSerializer.SerializeToElement("synthetic-operator"))], TestContext.Current.CancellationToken);

        string[] segments = token.Split('.');
        Assert.Equal(3, segments.Length);
        using JsonDocument header = JsonDocument.Parse(Decode(segments[0]));
        using JsonDocument payload = JsonDocument.Parse(Decode(segments[1]));
        Assert.Equal("RS256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal("JWT", header.RootElement.GetProperty("typ").GetString());
        Assert.False(header.RootElement.TryGetProperty("x5c", out _));
        Assert.Equal("https://issuer.example.test", payload.RootElement.GetProperty("iss").GetString());
        Assert.Equal("https://audience.example.test", payload.RootElement.GetProperty("aud").GetString());
        Assert.Equal(context.InstallationId.ToString("D"), payload.RootElement.GetProperty("sub").GetString());
        Assert.Equal(300, payload.RootElement.GetProperty("exp").GetInt64() - payload.RootElement.GetProperty("iat").GetInt64());
        Assert.Equal(payload.RootElement.GetProperty("iat").GetInt64(), payload.RootElement.GetProperty("nbf").GetInt64());
        Assert.Equal("synthetic-operator", payload.RootElement.GetProperty("role").GetString());
        AssertSignature(material.SigningKeyRevision1, segments);
        Assert.Equal(["sign-r1"], tracking.MetadataReferences);
        Assert.Equal([("sign-r1", "RS256")], tracking.Signatures);
    }

    [Theory]
    [InlineData("alg")]
    [InlineData("kid")]
    [InlineData("x5c")]
    [InlineData("iss")]
    [InlineData("aud")]
    [InlineData("sub")]
    [InlineData("nbf")]
    [InlineData("exp")]
    [InlineData("jti")]
    public async Task M6_JWT_security_sensitive_claim_override_is_denied_before_key_use(string claim)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot hostilePolicy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, allowedClaims: new HashSet<string>(StringComparer.Ordinal) { claim });
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = hostilePolicy;
        TrackingKeyProvider tracking = new(AuthenticationTestData.Provider(material));
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", hostilePolicy));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, tracking, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(
            context, AuthenticationTestData.JwtProfileId, [new(claim, JsonSerializer.SerializeToElement("hostile"))], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-JWT-POLICY-DENIED", failure.Code);
        Assert.Empty(tracking.MetadataReferences);
        Assert.Empty(tracking.Signatures);
    }

    [Fact]
    public async Task M6_JWT_duplicate_and_unsafe_claim_injection_are_denied()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, AuthenticationTestData.Provider(material), new InMemoryJwtReplayStore(100, clock), clock);
        JwtBoundClaim duplicate = new("role", JsonSerializer.SerializeToElement("one"));

        AuthenticationPrimitiveException duplicateFailure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(
            context, AuthenticationTestData.JwtProfileId, [duplicate, duplicate with { Value = JsonSerializer.SerializeToElement("two") }], TestContext.Current.CancellationToken));
        AuthenticationPrimitiveException injectionFailure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(
            context, AuthenticationTestData.JwtProfileId, [new("unapproved", JsonSerializer.SerializeToElement("value"))], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-JWT-CLAIM-DUPLICATE", duplicateFailure.Code);
        Assert.Equal("BGW-AUTH-JWT-CLAIM-DENIED", injectionFailure.Code);
    }

    [Fact]
    public async Task Wave1_JWT_actual_enumerated_claim_limit_denies_dishonest_count_before_key_use()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        HashSet<string> allowed = Enumerable.Range(0, 32).Select(index => $"claim-{index:D2}").ToHashSet(StringComparer.Ordinal);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(
            context, material.SigningKeyRevision1, allowedClaims: allowed);
        MutablePolicySource policies = AuthenticationTestData.Policies(
            context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = policy;
        TrackingKeyProvider tracking = new(AuthenticationTestData.Provider(material));
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(
            context, material.SigningKeyRevision1, "sign-r1", policy));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, tracking, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(
            context, AuthenticationTestData.JwtProfileId, new DishonestClaimList(), TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-JWT-CLAIMS", failure.Code);
        Assert.Empty(tracking.MetadataReferences);
        Assert.Empty(tracking.Signatures);
    }

    [Fact]
    public async Task M6_JWT_excessive_server_policy_lifetime_is_denied_before_binding_or_provider()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, lifetime: TimeSpan.FromHours(2));
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = policy;
        TrackingKeyProvider tracking = new(AuthenticationTestData.Provider(material));
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, tracking, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(
            context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-JWT-POLICY-DENIED", failure.Code);
        Assert.Equal(0, bindings.Calls);
        Assert.Empty(tracking.MetadataReferences);
    }

    [Fact]
    public async Task M6_JWT_disabled_key_denies_with_zero_provider_invocations()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        TrackingKeyProvider tracking = new(AuthenticationTestData.Provider(material));
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy, status: AuthenticationResourceStatus.Disabled));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, tracking, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-RESOURCE-DISABLED", failure.Code);
        Assert.Empty(tracking.MetadataReferences);
        Assert.Empty(tracking.Signatures);
    }

    [Fact]
    public async Task M6_JWT_rotation_resolves_revision_two_and_never_reuses_revision_one()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot revision1 = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1);
        ServerOwnedRs256PolicySnapshot revision2 = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision2, revision: 2);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        TrackingKeyProvider tracking = new(AuthenticationTestData.Provider(material));
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", revision1));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, tracking, new InMemoryJwtReplayStore(100, clock), clock);

        await signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken);
        policies.Rs256 = revision2;
        bindings.Current = AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision2, "sign-r2", revision2);
        await signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken);

        Assert.Equal([("sign-r1", "RS256"), ("sign-r2", "RS256")], tracking.Signatures);
    }

    [Fact]
    public async Task M6_JWT_wrong_key_result_and_HS_RS_confusion_are_rejected()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        IKeyOperationProvider wrong = new WrongSigningResultProvider(AuthenticationTestData.Provider(material), material.SigningKeyRevision2);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, wrong, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-SIGNING-RESULT-INVALID", failure.Code);
    }

    [Fact]
    public async Task M6_JWT_replayed_identifier_and_missing_capability_fail_closed()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy));
        FixedClock clock = new(Now);
        InMemoryJwtReplayStore replay = new(10, clock);
        Rs256JwtSigner signer = new(policies, bindings, AuthenticationTestData.Provider(material), replay, clock, new FixedIdentifierSource("fixed-jti"));

        await signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken);
        AuthenticationPrimitiveException replayFailure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));
        Rs256JwtSigner missing = new(policies, bindings, null, replay, clock);
        AuthenticationPrimitiveException capabilityFailure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => missing.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-JWT-REPLAY", replayFailure.Code);
        Assert.Equal("BGW-AUTH-SIGNING-CAPABILITY-UNAVAILABLE", capabilityFailure.Code);
    }

    [Fact]
    public async Task M6_JWT_replay_cache_is_bounded_and_expiry_aware()
    {
        FixedClock clock = new(Now);
        InMemoryJwtReplayStore store = new(1, clock);
        byte[] first = SHA256.HashData([1]);
        byte[] second = SHA256.HashData([2]);

        Assert.True(await store.TryReserveAsync(first, Now.AddMinutes(1), TestContext.Current.CancellationToken));
        Assert.False(await store.TryReserveAsync(second, Now.AddMinutes(1), TestContext.Current.CancellationToken));
        clock.UtcNow = Now.AddMinutes(2);
        Assert.True(await store.TryReserveAsync(second, Now.AddMinutes(3), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M6_JWT_binding_scope_purpose_and_metadata_mismatch_deny_before_signing()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        TrackingKeyProvider tracking = new(AuthenticationTestData.Provider(material));
        BoundAuthenticationResource hostile = AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy) with { OperationId = "other", Purpose = AuthenticationResourcePurpose.MutualTlsClientAuthentication };
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, new MutableBindingResolver(hostile), tracking, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-RESOURCE-BOUNDARY", failure.Code);
        Assert.Empty(tracking.MetadataReferences);
        Assert.Empty(tracking.Signatures);
    }

    [Fact]
    public async Task M6_JWT_stale_public_metadata_is_denied_before_signing()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        TrackingKeyProvider tracking = new(AuthenticationTestData.Provider(material));
        BoundAuthenticationResource stale = AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy) with
        {
            PublicMetadata = AuthenticationTestData.Metadata(material.SigningKeyRevision1) with { Version = "stale" }
        };
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, new MutableBindingResolver(stale), tracking, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-POLICY-BINDING-STALE", failure.Code);
        Assert.Empty(tracking.Signatures);
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("audience")]
    [InlineData("subject")]
    [InlineData("lifetime")]
    [InlineData("allowlist")]
    [InlineData("x5c")]
    [InlineData("temporal")]
    [InlineData("trusted-claim")]
    public async Task M6_JWT_policy_substitution_with_same_policy_id_is_denied_before_provider(string substitution)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot approved = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1);
        ServerOwnedRs256PolicySnapshot substituted = substitution switch
        {
            "issuer" => AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, issuer: "https://attacker.example.test"),
            "audience" => AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, audience: "https://attacker.example.test"),
            "subject" => AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, subjectPolicy: JwtSubjectPolicy.Application),
            "lifetime" => AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, lifetime: TimeSpan.FromMinutes(10)),
            "allowlist" => AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, allowedClaims: new HashSet<string>(StringComparer.Ordinal) { "attacker" }),
            "x5c" => AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, certificateHeaderMode: JwtCertificateHeaderMode.Leaf),
            "temporal" => AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, temporalClaimMode: JwtTemporalClaimMode.IssuedAtExpiration),
            "trusted-claim" => AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1,
                trustedClaims: [new("tenant_ref", JwtTrustedValueSource.AuthenticatedTenantId)]),
            _ => throw new ArgumentOutOfRangeException(nameof(substitution))
        };
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = substituted;
        TrackingKeyProvider tracking = new(AuthenticationTestData.Provider(material));
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", approved));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, tracking, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-POLICY-BINDING-STALE", failure.Code);
        Assert.Empty(tracking.MetadataReferences);
        Assert.Empty(tracking.Signatures);
    }

    [Fact]
    public async Task M6_JWT_approved_scalar_fingerprint_with_substituted_SPKI_is_denied_before_sign()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        IKeyOperationProvider malicious = new SubstitutedSpkiProvider(AuthenticationTestData.Provider(material), material.SigningKeyRevision2);
        TrackingKeyProvider tracking = new(malicious);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, tracking, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-SIGNING-KEY-DENIED", failure.Code);
        Assert.Single(tracking.MetadataReferences);
        Assert.Empty(tracking.Signatures);
    }

    [Theory]
    [InlineData("metadata", "BGW-AUTH-SIGNING-METADATA-UNAVAILABLE")]
    [InlineData("sign", "BGW-AUTH-SIGNING-OPERATION-FAILED")]
    public async Task M6_JWT_unexpected_provider_exceptions_are_sanitized(string boundary, string expectedCode)
    {
        const string canary = "locator=hidden token=hidden secret=hidden";
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        IKeyOperationProvider provider = new UnexpectedFailingKeyProvider(AuthenticationTestData.Provider(material), boundary, canary);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, provider, new InMemoryJwtReplayStore(100, clock), clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

        Assert.Equal(expectedCode, failure.Code);
        Assert.Equal(expectedCode, failure.Message);
        Assert.Null(failure.InnerException);
        Assert.DoesNotContain(canary, failure.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("hidden", failure.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task M6_JWT_provider_cancellation_preserves_cancellation_semantics()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy));
        FixedClock clock = new(Now);
        using CancellationTokenSource cancellation = new();
        Rs256JwtSigner signer = new(policies, bindings, new CancelingKeyProvider(cancellation), new InMemoryJwtReplayStore(100, clock), clock);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], cancellation.Token));
    }

    [Fact]
    public void M6_public_signing_API_accepts_only_policy_id_and_business_claims()
    {
        MethodInfo method = Assert.Single(typeof(Rs256JwtSigner).GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly));
        Type[] parameters = method.GetParameters().Select(value => value.ParameterType).ToArray();

        Assert.Equal("SignJwtAsync", method.Name);
        Assert.Equal([typeof(AuthenticationExecutionContext), typeof(string), typeof(IReadOnlyList<JwtBoundClaim>), typeof(CancellationToken)], parameters);
        Assert.Null(typeof(Rs256JwtSigner).Assembly.GetType("SecureIntegration.Authentication.CertificateSigning.Rs256JwtProfile"));
        Assert.DoesNotContain(typeof(IKeyOperationProvider).GetMethods(), value => value.Name.Contains("Export", StringComparison.OrdinalIgnoreCase) || value.Name.Contains("Private", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(method.GetParameters(), value => value.ParameterType == typeof(X509Certificate2) || value.ParameterType.Name.Contains("Dictionary", StringComparison.Ordinal));
    }

    private sealed class DishonestClaimList : IReadOnlyList<JwtBoundClaim>
    {
        public int Count => 1;
        public JwtBoundClaim this[int index] => Claim(index);

        public IEnumerator<JwtBoundClaim> GetEnumerator()
        {
            for (int index = 0; index < 33; index++) yield return Claim(index);
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        private static JwtBoundClaim Claim(int index) => new(
            $"claim-{index % 32:D2}", JsonSerializer.SerializeToElement(index));
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
        Assert.True(rsa.VerifyHash(digest, Decode(segments[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
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

    private sealed class SubstitutedSpkiProvider(IKeyOperationProvider approvedMetadataProvider, X509Certificate2 substitutedCertificate) : IKeyOperationProvider
    {
        public async Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken)
        {
            ProviderSigningKeyPublicMetadata approved = await approvedMetadataProvider.GetSigningKeyMetadataAsync(logicalReference, cancellationToken);
            using RSA rsa = substitutedCertificate.GetRSAPublicKey()!;
            return approved with { SubjectPublicKeyInfo = rsa.ExportSubjectPublicKeyInfo(), PublicKeySize = rsa.KeySize };
        }

        public Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken)
        {
            using RSA rsa = substitutedCertificate.GetRSAPrivateKey()!;
            return Task.FromResult(rsa.SignHash(digest.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
    }

    private sealed class UnexpectedFailingKeyProvider(IKeyOperationProvider valid, string boundary, string canary) : IKeyOperationProvider
    {
        public Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken) =>
            boundary == "metadata" ? throw new InvalidOperationException(canary) : valid.GetSigningKeyMetadataAsync(logicalReference, cancellationToken);

        public Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken) =>
            throw new InvalidOperationException(canary);
    }

    private sealed class CancelingKeyProvider(CancellationTokenSource cancellation) : IKeyOperationProvider
    {
        public Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken)
        {
            cancellation.Cancel();
            return Task.FromCanceled<ProviderSigningKeyPublicMetadata>(cancellationToken);
        }
        public Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken) => Task.FromCanceled<byte[]>(cancellationToken);
    }
}

using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.Authentication.CertificateSigning.Tests;

public sealed class JwtX509ExtensionSecurityTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 8, 10, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(JwtCertificateHeaderMode.Leaf, 1)]
    [InlineData(JwtCertificateHeaderMode.Chain, 2)]
    public async Task Wave1_x5c_leaf_and_chain_are_verified_leaf_first_and_standard_base64(
        JwtCertificateHeaderMode mode,
        int expectedCertificates)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, certificateHeaderMode: mode);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = policy;
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        TrackingKeyProvider keys = new(provider);
        TrackingPublicMaterialProvider publicMaterial = new(provider);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, keys, new InMemoryJwtReplayStore(100, clock), clock, certificatePublicMaterial: publicMaterial);

        string token = await signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken);

        string[] segments = token.Split('.');
        using JsonDocument header = JsonDocument.Parse(Decode(segments[0]));
        JsonElement x5c = header.RootElement.GetProperty("x5c");
        Assert.Equal(expectedCertificates, x5c.GetArrayLength());
        Assert.Equal(Convert.ToBase64String(material.SigningKeyRevision1.RawData), x5c[0].GetString());
        Assert.Equal(material.SigningKeyRevision1.RawData, Convert.FromBase64String(x5c[0].GetString()!));
        if (mode == JwtCertificateHeaderMode.Chain)
            Assert.Equal(Convert.ToBase64String(material.RootCertificate.RawData), x5c[1].GetString());
        Assert.Equal(["alg", "typ", "x5c"], header.RootElement.EnumerateObject().Select(value => value.Name).ToArray());
        AssertSignature(material.SigningKeyRevision1, segments);
        Assert.Equal(["sign-r1"], publicMaterial.References);
        Assert.Equal([("sign-r1", "RS256")], keys.Signatures);
        Assert.Equal(3, bindings.Calls);
    }

    [Fact]
    public async Task Wave1_temporal_mode_omits_nbf_and_trusted_sources_derive_only_authenticated_identity()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(
            context,
            material.SigningKeyRevision1,
            subjectPolicy: JwtSubjectPolicy.Tenant,
            temporalClaimMode: JwtTemporalClaimMode.IssuedAtExpiration,
            trustedClaims:
            [
                new("application_ref", JwtTrustedValueSource.AuthenticatedApplicationId),
                new("installation_ref", JwtTrustedValueSource.AuthenticatedInstallationId)
            ]);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = policy;
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, AuthenticationTestData.Provider(material), new InMemoryJwtReplayStore(100, clock), clock);

        string token = await signer.SignJwtAsync(
            context,
            AuthenticationTestData.JwtProfileId,
            [new("role", JsonSerializer.SerializeToElement("operator"))],
            TestContext.Current.CancellationToken);

        using JsonDocument payload = JsonDocument.Parse(Decode(token.Split('.')[1]));
        Assert.Equal(context.TenantId.ToString("D"), payload.RootElement.GetProperty("sub").GetString());
        Assert.Equal(context.ApplicationId.ToString("D"), payload.RootElement.GetProperty("application_ref").GetString());
        Assert.Equal(context.InstallationId.ToString("D"), payload.RootElement.GetProperty("installation_ref").GetString());
        Assert.Equal("operator", payload.RootElement.GetProperty("role").GetString());
        Assert.True(payload.RootElement.TryGetProperty("iat", out _));
        Assert.True(payload.RootElement.TryGetProperty("exp", out _));
        Assert.False(payload.RootElement.TryGetProperty("nbf", out _));
    }

    [Fact]
    public async Task Wave1_invalid_temporal_or_trusted_claim_policy_fails_before_provider_use()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot[] deniedPolicies =
        [
            AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, temporalClaimMode: (JwtTemporalClaimMode)99),
            AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, trustedClaims: [new("iss", JwtTrustedValueSource.AuthenticatedTenantId)]),
            AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, trustedClaims: [new("role", JwtTrustedValueSource.AuthenticatedTenantId)]),
            AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, trustedClaims: [new("tenant_ref", (JwtTrustedValueSource)99)]),
            AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, subjectPolicy: JwtSubjectPolicy.TrustedRuntimeValue),
            AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, trustedSubjectSource: JwtTrustedValueSource.ExternalActorId),
            AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, subjectPolicy: JwtSubjectPolicy.TrustedRuntimeValue,
                trustedSubjectSource: JwtTrustedValueSource.AuthenticatedTenantId),
            AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1,
                trustedClaims: [new("tenant_ref", JwtTrustedValueSource.AuthenticatedTenantId), new("tenant_ref", JwtTrustedValueSource.AuthenticatedApplicationId)])
        ];

        foreach (ServerOwnedRs256PolicySnapshot policy in deniedPolicies)
        {
            MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
            policies.Rs256 = policy;
            TrackingKeyProvider keys = new(AuthenticationTestData.Provider(material));
            MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy));
            FixedClock clock = new(Now);
            Rs256JwtSigner signer = new(policies, bindings, keys, new InMemoryJwtReplayStore(100, clock), clock);

            AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() =>
                signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

            Assert.Equal("BGW-AUTH-JWT-POLICY-DENIED", failure.Code);
            Assert.Equal(0, bindings.Calls);
            Assert.Empty(keys.MetadataReferences);
        }
    }

    [Theory]
    [InlineData("substituted-leaf", "BGW-AUTH-RESOURCE-METADATA-STALE")]
    [InlineData("substituted-chain", "BGW-AUTH-SIGNING-CERTIFICATE-DENIED")]
    [InlineData("fingerprint", "BGW-AUTH-SIGNING-CERTIFICATE-DENIED")]
    [InlineData("spki", "BGW-AUTH-SIGNING-KEY-DENIED")]
    public async Task Wave1_substituted_certificate_identity_is_denied_before_sign(
        string substitution,
        string expectedCode)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        using SyntheticAuthenticationMaterial attacker = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        JwtCertificateHeaderMode mode = substitution == "substituted-chain" ? JwtCertificateHeaderMode.Chain : JwtCertificateHeaderMode.Leaf;
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, certificateHeaderMode: mode);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = policy;
        InMemoryProvider approvedProvider = AuthenticationTestData.Provider(material);
        IKeyOperationProvider keyProvider = substitution switch
        {
            "substituted-leaf" => new SubstitutedSigningProvider(approvedProvider, material.SigningKeyRevision2),
            "spki" => new SubstitutedSpkiMetadataProvider(approvedProvider, material.SigningKeyRevision2),
            _ => approvedProvider
        };
        TrackingKeyProvider keys = new(keyProvider);
        ICertificatePublicMaterialProvider publicMaterial = substitution switch
        {
            "substituted-leaf" => new FixedPublicMaterialProvider(Material(material.SigningKeyRevision2, material.RootCertificate)),
            "substituted-chain" => new FixedPublicMaterialProvider(Material(material.SigningKeyRevision1, attacker.RootCertificate)),
            "fingerprint" => new FixedPublicMaterialProvider(Material(
                material.SigningKeyRevision1,
                material.RootCertificate,
                Metadata(material.SigningKeyRevision1) with { FingerprintSha256 = new string('0', 64) })),
            _ => approvedProvider
        };
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, keys, new InMemoryJwtReplayStore(100, clock), clock, certificatePublicMaterial: publicMaterial);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() =>
            signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

        Assert.Equal(expectedCode, failure.Code);
        Assert.Empty(keys.Signatures);
    }

    [Fact]
    public async Task Wave1_retained_revision_one_public_material_cannot_authenticate_revision_two()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision2, revision: 2, certificateHeaderMode: JwtCertificateHeaderMode.Leaf);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = policy;
        TrackingKeyProvider keys = new(AuthenticationTestData.Provider(material));
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision2, "sign-r2", policy));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(
            policies,
            bindings,
            keys,
            new InMemoryJwtReplayStore(100, clock),
            clock,
            certificatePublicMaterial: new FixedPublicMaterialProvider(Material(material.SigningKeyRevision1, material.RootCertificate)));

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() =>
            signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-RESOURCE-METADATA-STALE", failure.Code);
        Assert.Empty(keys.Signatures);
    }

    [Theory]
    [InlineData(2, 0)]
    [InlineData(3, 1)]
    public async Task Wave1_disable_during_public_material_flow_never_returns_a_token(int disableAtResolve, int expectedSignatures)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, certificateHeaderMode: JwtCertificateHeaderMode.Leaf);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = policy;
        BoundAuthenticationResource active = AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy);
        MutableBindingResolver bindings = new(active)
        {
            OnResolve = call => call == disableAtResolve ? active with { Status = AuthenticationResourceStatus.Disabled } : active
        };
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        TrackingKeyProvider keys = new(provider);
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, keys, new InMemoryJwtReplayStore(100, clock), clock, certificatePublicMaterial: provider);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() =>
            signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-RESOURCE-DISABLED", failure.Code);
        Assert.Equal(expectedSignatures, keys.Signatures.Count);
    }

    [Fact]
    public async Task Wave1_rotation_emits_only_the_current_revision_x5c()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot revision1 = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, certificateHeaderMode: JwtCertificateHeaderMode.Leaf);
        ServerOwnedRs256PolicySnapshot revision2 = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision2, revision: 2, certificateHeaderMode: JwtCertificateHeaderMode.Leaf);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = revision1;
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", revision1));
        InMemoryProvider provider = AuthenticationTestData.Provider(material);
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(policies, bindings, provider, new InMemoryJwtReplayStore(100, clock), clock, certificatePublicMaterial: provider);

        string token1 = await signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken);
        policies.Rs256 = revision2;
        bindings.Current = AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision2, "sign-r2", revision2);
        string token2 = await signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken);

        Assert.Equal(Convert.ToBase64String(material.SigningKeyRevision1.RawData), X5cLeaf(token1));
        Assert.Equal(Convert.ToBase64String(material.SigningKeyRevision2.RawData), X5cLeaf(token2));
        Assert.NotEqual(X5cLeaf(token1), X5cLeaf(token2));
    }

    [Fact]
    public async Task Wave1_public_material_provider_failure_is_sanitized_and_cancellation_is_preserved()
    {
        const string canary = "locator=hidden token=hidden credential=hidden";
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, certificateHeaderMode: JwtCertificateHeaderMode.Leaf);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = policy;
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy));
        FixedClock clock = new(Now);
        Rs256JwtSigner failing = new(
            policies,
            bindings,
            AuthenticationTestData.Provider(material),
            new InMemoryJwtReplayStore(100, clock),
            clock,
            certificatePublicMaterial: new UnexpectedPublicMaterialProvider(canary));

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() =>
            failing.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-SIGNING-CERTIFICATE-MATERIAL-UNAVAILABLE", failure.Code);
        Assert.Equal(failure.Code, failure.Message);
        Assert.Null(failure.InnerException);
        Assert.DoesNotContain("hidden", failure.ToString(), StringComparison.OrdinalIgnoreCase);

        using CancellationTokenSource cancellation = new();
        Rs256JwtSigner canceling = new(
            policies,
            bindings,
            AuthenticationTestData.Provider(material),
            new InMemoryJwtReplayStore(100, clock),
            clock,
            certificatePublicMaterial: new CancelingPublicMaterialProvider(cancellation));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            canceling.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], cancellation.Token));
    }

    [Fact]
    public async Task Wave1_x5c_missing_capability_empty_chain_and_expired_material_fail_closed()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        FixedClock clock = new(Now);

        ServerOwnedRs256PolicySnapshot leafPolicy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, certificateHeaderMode: JwtCertificateHeaderMode.Leaf);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = leafPolicy;
        MutableBindingResolver leafBinding = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", leafPolicy));
        Rs256JwtSigner missing = new(policies, leafBinding, AuthenticationTestData.Provider(material), new InMemoryJwtReplayStore(100, clock), clock);
        AuthenticationPrimitiveException missingFailure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() =>
            missing.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));
        Assert.Equal("BGW-AUTH-SIGNING-CERTIFICATE-CAPABILITY-UNAVAILABLE", missingFailure.Code);
        Assert.Equal(1, leafBinding.Calls);

        ServerOwnedRs256PolicySnapshot chainPolicy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1, certificateHeaderMode: JwtCertificateHeaderMode.Chain);
        policies.Rs256 = chainPolicy;
        MutableBindingResolver chainBinding = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", chainPolicy));
        Rs256JwtSigner emptyChain = new(
            policies,
            chainBinding,
            AuthenticationTestData.Provider(material),
            new InMemoryJwtReplayStore(100, clock),
            clock,
            certificatePublicMaterial: new FixedPublicMaterialProvider(Material(material.SigningKeyRevision1)));
        AuthenticationPrimitiveException chainFailure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() =>
            emptyChain.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));
        Assert.Equal("BGW-AUTH-SIGNING-CERTIFICATE-DENIED", chainFailure.Code);

        ServerOwnedRs256PolicySnapshot expiredPolicy = AuthenticationTestData.JwtPolicy(context, material.ExpiredSigningCertificate, certificateHeaderMode: JwtCertificateHeaderMode.Leaf);
        policies.Rs256 = expiredPolicy;
        MutableBindingResolver expiredBinding = new(AuthenticationTestData.SigningBinding(context, material.ExpiredSigningCertificate, "sign-expired", expiredPolicy));
        TrackingKeyProvider expiredKeys = new(AuthenticationTestData.Provider(material));
        Rs256JwtSigner expired = new(policies, expiredBinding, expiredKeys, new InMemoryJwtReplayStore(100, clock), clock, certificatePublicMaterial: AuthenticationTestData.Provider(material));
        AuthenticationPrimitiveException expiredFailure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() =>
            expired.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));
        Assert.Equal("BGW-AUTH-SIGNING-KEY-DENIED", expiredFailure.Code);
        Assert.Empty(expiredKeys.Signatures);
    }

    [Fact]
    public void Wave1_public_material_and_signing_APIs_expose_no_private_or_caller_header_surface()
    {
        MethodInfo method = Assert.Single(typeof(ICertificatePublicMaterialProvider).GetMethods());
        Assert.Equal("GetPublicMaterialAsync", method.Name);
        Assert.Equal([typeof(string), typeof(CancellationToken)], method.GetParameters().Select(value => value.ParameterType).ToArray());
        Assert.Equal(typeof(Task<ProviderCertificatePublicMaterial>), method.ReturnType);
        string[] forbidden = ["Private", "Pfx", "Pkcs12", "Password", "Secret", "Credential", "Locator"];
        Assert.DoesNotContain(typeof(ProviderCertificatePublicMaterial).GetProperties(), property => forbidden.Any(token => property.Name.Contains(token, StringComparison.OrdinalIgnoreCase)));
        Assert.DoesNotContain(typeof(Rs256JwtSigner).GetMethods(BindingFlags.Instance | BindingFlags.Public), candidate =>
            candidate.GetParameters().Any(parameter => parameter.ParameterType == typeof(X509Certificate2) || parameter.ParameterType.Name.Contains("Dictionary", StringComparison.Ordinal)));
    }

    private static ProviderCertificatePublicMaterial Material(
        X509Certificate2 leaf,
        X509Certificate2? issuer = null,
        ProviderCertificatePublicMetadata? metadata = null) => new(
            leaf.RawData,
            issuer is null ? [] : [(ReadOnlyMemory<byte>)issuer.RawData],
            metadata ?? Metadata(leaf));

    private static ProviderCertificatePublicMetadata Metadata(X509Certificate2 certificate)
    {
        using RSA? rsa = certificate.GetRSAPublicKey();
        X509KeyUsageFlags? keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault()?.KeyUsages;
        IReadOnlyList<string>? usages = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault()?.EnhancedKeyUsages
            .Cast<Oid>().Select(value => value.Value ?? string.Empty).ToArray();
        return new(
            Convert.ToHexString(SHA256.HashData(certificate.RawData)),
            certificate.Subject,
            certificate.Issuer,
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            "RSA",
            rsa!.KeySize,
            certificate.SerialNumber,
            usages,
            keyUsage);
    }

    private static byte[] Decode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/').PadRight((value.Length + 3) / 4 * 4, '=');
        return Convert.FromBase64String(padded);
    }

    private static string X5cLeaf(string token)
    {
        using JsonDocument header = JsonDocument.Parse(Decode(token.Split('.')[0]));
        return header.RootElement.GetProperty("x5c")[0].GetString()!;
    }

    private static void AssertSignature(X509Certificate2 certificate, string[] segments)
    {
        using RSA rsa = certificate.GetRSAPublicKey()!;
        byte[] digest = SHA256.HashData(Encoding.ASCII.GetBytes(segments[0] + "." + segments[1]));
        Assert.True(rsa.VerifyHash(digest, Decode(segments[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    private sealed class FixedPublicMaterialProvider(ProviderCertificatePublicMaterial material) : ICertificatePublicMaterialProvider
    {
        public Task<ProviderCertificatePublicMaterial> GetPublicMaterialAsync(string logicalReference, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(material);
        }
    }

    private sealed class SubstitutedSigningProvider(IKeyOperationProvider approved, X509Certificate2 substituted) : IKeyOperationProvider
    {
        public Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken) =>
            approved.GetSigningKeyMetadataAsync(logicalReference, cancellationToken);

        public Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken)
        {
            using RSA rsa = substituted.GetRSAPrivateKey()!;
            return Task.FromResult(rsa.SignHash(digest.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
    }

    private sealed class SubstitutedSpkiMetadataProvider(IKeyOperationProvider approved, X509Certificate2 substituted) : IKeyOperationProvider
    {
        public async Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken)
        {
            ProviderSigningKeyPublicMetadata metadata = await approved.GetSigningKeyMetadataAsync(logicalReference, cancellationToken);
            using RSA rsa = substituted.GetRSAPublicKey()!;
            return metadata with { SubjectPublicKeyInfo = rsa.ExportSubjectPublicKeyInfo() };
        }

        public Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken) =>
            approved.SignDigestAsync(logicalReference, algorithm, digest, cancellationToken);
    }

    private sealed class UnexpectedPublicMaterialProvider(string canary) : ICertificatePublicMaterialProvider
    {
        public Task<ProviderCertificatePublicMaterial> GetPublicMaterialAsync(string logicalReference, CancellationToken cancellationToken) =>
            throw new InvalidOperationException(canary);
    }

    private sealed class CancelingPublicMaterialProvider(CancellationTokenSource cancellation) : ICertificatePublicMaterialProvider
    {
        public Task<ProviderCertificatePublicMaterial> GetPublicMaterialAsync(string logicalReference, CancellationToken cancellationToken)
        {
            cancellation.Cancel();
            return Task.FromCanceled<ProviderCertificatePublicMaterial>(cancellationToken);
        }
    }
}

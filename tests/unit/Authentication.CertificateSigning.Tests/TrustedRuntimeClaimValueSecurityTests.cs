using System.Reflection;
using System.Text.Json;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.Authentication.CertificateSigning.Tests;

public sealed class TrustedRuntimeClaimValueSecurityTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 8, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Wave1_generic_Published_policy_resolves_typed_runtime_subject_without_caller_override()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(
            context,
            material.SigningKeyRevision1,
            subjectPolicy: JwtSubjectPolicy.TrustedRuntimeValue,
            trustedClaims: [new("delegated_ref", JwtTrustedValueSource.DelegatedSubjectId)],
            trustedSubjectSource: JwtTrustedValueSource.ExternalActorId);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = policy;
        TrackingKeyProvider keys = new(AuthenticationTestData.Provider(material));
        EchoTrustedRuntimeResolver resolver = new(request => request.Source switch
        {
            JwtTrustedValueSource.ExternalActorId => "external-actor-42",
            JwtTrustedValueSource.DelegatedSubjectId => "delegated-subject-7",
            _ => throw new InvalidOperationException()
        });
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(
            policies,
            new MutableBindingResolver(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy)),
            keys,
            new InMemoryJwtReplayStore(100, clock),
            clock,
            trustedRuntimeClaimValues: resolver);

        string token = await signer.SignJwtAsync(
            context,
            AuthenticationTestData.JwtProfileId,
            [new("role", JsonSerializer.SerializeToElement("operator"))],
            TestContext.Current.CancellationToken);

        using JsonDocument payload = JsonDocument.Parse(Decode(token.Split('.')[1]));
        Assert.Equal("external-actor-42", payload.RootElement.GetProperty("sub").GetString());
        Assert.Equal("delegated-subject-7", payload.RootElement.GetProperty("delegated_ref").GetString());
        Assert.Equal("operator", payload.RootElement.GetProperty("role").GetString());
        Assert.Equal([JwtTrustedValueSource.ExternalActorId, JwtTrustedValueSource.DelegatedSubjectId], resolver.Requests.Select(value => value.Source).Order().ToArray());
        Assert.Single(keys.Signatures);
    }

    [Fact]
    public async Task Wave1_business_value_cannot_be_promoted_to_reserved_subject_without_authorized_runtime_source()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(context, material.SigningKeyRevision1);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = policy;
        TrackingKeyProvider keys = new(AuthenticationTestData.Provider(material));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(
            policies,
            new MutableBindingResolver(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy)),
            keys,
            new InMemoryJwtReplayStore(100, clock),
            clock);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() => signer.SignJwtAsync(
            context,
            AuthenticationTestData.JwtProfileId,
            [new("sub", JsonSerializer.SerializeToElement("caller-value-x"))],
            TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-JWT-CLAIM-DENIED", failure.Code);
        Assert.Empty(keys.MetadataReferences);
        Assert.Empty(keys.Signatures);
    }

    [Fact]
    public async Task Wave1_policy_authorized_source_cannot_be_substituted_by_resolver()
    {
        AuthenticationPrimitiveException failure = await DeniedResolverResultAsync(request => WithSource(ValidValue(request), JwtTrustedValueSource.DelegatedSubjectId));

        Assert.Equal("BGW-AUTH-TRUSTED-RUNTIME-VALUE-DENIED", failure.Code);

        static TrustedRuntimeClaimValue WithSource(TrustedRuntimeClaimValue original, JwtTrustedValueSource source) => new(
            source,
            original.Value,
            original.Provenance,
            original.InvocationBinding,
            original.AuthorizationEvidenceReference);
    }

    [Fact]
    public async Task Wave1_missing_or_failing_runtime_resolver_is_sanitized_before_provider_use()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(
            context,
            material.SigningKeyRevision1,
            subjectPolicy: JwtSubjectPolicy.TrustedRuntimeValue,
            trustedSubjectSource: JwtTrustedValueSource.ExternalActorId);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = policy;
        TrackingKeyProvider keys = new(AuthenticationTestData.Provider(material));
        FixedClock clock = new(Now);
        MutableBindingResolver bindings = new(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy));
        Rs256JwtSigner missing = new(policies, bindings, keys, new InMemoryJwtReplayStore(100, clock), clock);
        Rs256JwtSigner failing = new(
            policies,
            bindings,
            keys,
            new InMemoryJwtReplayStore(100, clock),
            clock,
            trustedRuntimeClaimValues: new FailingTrustedRuntimeResolver());

        AuthenticationPrimitiveException missingFailure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() =>
            missing.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));
        AuthenticationPrimitiveException resolverFailure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() =>
            failing.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));

        Assert.Equal("BGW-AUTH-TRUSTED-RUNTIME-CAPABILITY-UNAVAILABLE", missingFailure.Code);
        Assert.Equal("BGW-AUTH-TRUSTED-RUNTIME-VALUE-UNAVAILABLE", resolverFailure.Code);
        Assert.DoesNotContain("hidden", resolverFailure.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Empty(keys.MetadataReferences);
        Assert.Empty(keys.Signatures);
    }

    [Fact]
    public async Task Wave1_runtime_value_from_invocation_A_is_denied_for_invocation_B()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext invocationA = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        AuthenticationExecutionContext invocationB = invocationA with { CorrelationId = Guid.Parse("77777777-7777-7777-7777-777777777777") };
        TrustedRuntimeClaimValue? captured = null;
        EchoTrustedRuntimeResolver resolverA = new(request =>
        {
            captured = ValidValue(request);
            return captured.Value;
        });
        await SignWithResolverAsync(material, invocationA, resolverA);
        ReplayTrustedRuntimeResolver resolverB = new(captured!);

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() =>
            SignWithResolverAsync(material, invocationB, resolverB));

        Assert.Equal("BGW-AUTH-TRUSTED-RUNTIME-VALUE-DENIED", failure.Code);
        Assert.Equal(invocationA.CorrelationId, captured!.InvocationBinding.CorrelationId);
        Assert.Equal(invocationB.CorrelationId, Assert.Single(resolverB.Requests).InvocationBinding.CorrelationId);
    }

    [Theory]
    [InlineData("provenance")]
    [InlineData("policy-revision")]
    [InlineData("catalog-revision")]
    [InlineData("resource-version")]
    [InlineData("connector-version")]
    [InlineData("operation")]
    [InlineData("tenant")]
    [InlineData("application")]
    [InlineData("installation")]
    public async Task Wave1_wrong_provenance_or_stale_runtime_binding_is_denied_before_provider(string mismatch)
    {
        AuthenticationPrimitiveException failure = await DeniedResolverResultAsync(request =>
        {
            TrustedRuntimeClaimValue valid = ValidValue(request);
            if (mismatch == "provenance")
                return new(valid.Source, valid.Value, TrustedRuntimeClaimValueProvenance.CallerBusinessData, valid.InvocationBinding, valid.AuthorizationEvidenceReference);
            TrustedRuntimeClaimInvocationBinding stale = mismatch switch
            {
                "policy-revision" => valid.InvocationBinding with { PolicyRevision = valid.InvocationBinding.PolicyRevision + 1 },
                "catalog-revision" => valid.InvocationBinding with { CatalogRevision = valid.InvocationBinding.CatalogRevision + 1 },
                "resource-version" => valid.InvocationBinding with { ResourceVersion = "stale-resource" },
                "connector-version" => valid.InvocationBinding with { ConnectorVersionId = Guid.NewGuid() },
                "operation" => valid.InvocationBinding with { OperationId = "other-operation" },
                "tenant" => valid.InvocationBinding with { TenantId = Guid.NewGuid() },
                "application" => valid.InvocationBinding with { ApplicationId = Guid.NewGuid() },
                "installation" => valid.InvocationBinding with { InstallationId = Guid.NewGuid() },
                _ => throw new ArgumentOutOfRangeException(nameof(mismatch))
            };
            return new(valid.Source, valid.Value, valid.Provenance, stale, valid.AuthorizationEvidenceReference);
        });

        Assert.Equal("BGW-AUTH-TRUSTED-RUNTIME-VALUE-DENIED", failure.Code);
    }

    [Fact]
    public async Task Wave1_trusted_claim_snapshot_cannot_flip_during_provider_await_or_after_checksum()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        JwtTrustedClaimBinding[] callerBindings = [new("actor_ref", JwtTrustedValueSource.ExternalActorId)];
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(
            context,
            material.SigningKeyRevision1,
            trustedClaims: callerBindings);
        string checksum = policy.PolicyChecksumSha256;
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = policy;
        BlockingSigningProvider keys = new(AuthenticationTestData.Provider(material));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(
            policies,
            new MutableBindingResolver(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy)),
            keys,
            new InMemoryJwtReplayStore(100, clock),
            clock,
            trustedRuntimeClaimValues: new EchoTrustedRuntimeResolver(_ => "actor-a"));

        Task<string> signing = signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken);
        await keys.SigningStarted.Task.WaitAsync(TestContext.Current.CancellationToken);
        callerBindings[0] = new("actor_ref", JwtTrustedValueSource.DelegatedSubjectId);
        callerBindings[0] = new("actor_ref", JwtTrustedValueSource.ExternalActorId);
        Assert.False(policy.TrustedClaims is JwtTrustedClaimBinding[]);
        Assert.Throws<NotSupportedException>(() => ((IList<JwtTrustedClaimBinding>)policy.TrustedClaims)[0] = new("actor_ref", JwtTrustedValueSource.DelegatedSubjectId));
        Assert.Equal(checksum, policy.PolicyChecksumSha256);
        Assert.Equal(checksum, AuthenticationPolicyDigest.Rs256(policy));
        keys.ReleaseSigning.TrySetResult();

        string token = await signing;

        using JsonDocument payload = JsonDocument.Parse(Decode(token.Split('.')[1]));
        Assert.Equal("actor-a", payload.RootElement.GetProperty("actor_ref").GetString());
    }

    [Fact]
    public void Wave1_runtime_resolution_request_is_server_constructed_and_signing_API_stays_small()
    {
        Assert.Empty(typeof(TrustedRuntimeClaimResolutionRequest).GetConstructors(BindingFlags.Instance | BindingFlags.Public));
        Assert.Empty(typeof(TrustedRuntimeClaimValue).GetConstructors(BindingFlags.Instance | BindingFlags.Public));
        MethodInfo valueFactory = Assert.Single(typeof(TrustedRuntimeClaimValue).GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.DeclaredOnly));
        Assert.Equal("FromRegisteredResolver", valueFactory.Name);
        MethodInfo signing = Assert.Single(typeof(Rs256JwtSigner).GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly));
        Assert.Equal(
            [typeof(AuthenticationExecutionContext), typeof(string), typeof(IReadOnlyList<JwtBoundClaim>), typeof(CancellationToken)],
            signing.GetParameters().Select(value => value.ParameterType).ToArray());
        Assert.Null(typeof(Rs256JwtSigner).Assembly.GetType("SecureIntegration.Authentication.CertificateSigning.GatewayUser"));
        Assert.Null(typeof(Rs256JwtSigner).Assembly.GetType("SecureIntegration.Authentication.CertificateSigning.GenericHumanPrincipal"));
    }

    private static async Task<AuthenticationPrimitiveException> DeniedResolverResultAsync(
        Func<TrustedRuntimeClaimResolutionRequest, TrustedRuntimeClaimValue> result)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(Now);
        AuthenticationExecutionContext context = AuthenticationTestData.Context(AuthenticationTestData.JwtProfileId);
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(
            context,
            material.SigningKeyRevision1,
            subjectPolicy: JwtSubjectPolicy.TrustedRuntimeValue,
            trustedSubjectSource: JwtTrustedValueSource.ExternalActorId);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = policy;
        TrackingKeyProvider keys = new(AuthenticationTestData.Provider(material));
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(
            policies,
            new MutableBindingResolver(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy)),
            keys,
            new InMemoryJwtReplayStore(100, clock),
            clock,
            trustedRuntimeClaimValues: new DirectTrustedRuntimeResolver(result));

        AuthenticationPrimitiveException failure = await Assert.ThrowsAsync<AuthenticationPrimitiveException>(() =>
            signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken));
        Assert.Empty(keys.MetadataReferences);
        Assert.Empty(keys.Signatures);
        return failure;
    }

    private static Task<string> SignWithResolverAsync(
        SyntheticAuthenticationMaterial material,
        AuthenticationExecutionContext context,
        ITrustedRuntimeClaimValueResolver resolver)
    {
        ServerOwnedRs256PolicySnapshot policy = AuthenticationTestData.JwtPolicy(
            context,
            material.SigningKeyRevision1,
            subjectPolicy: JwtSubjectPolicy.TrustedRuntimeValue,
            trustedSubjectSource: JwtTrustedValueSource.ExternalActorId);
        MutablePolicySource policies = AuthenticationTestData.Policies(context, material.SigningKeyRevision1, material.ClientCertificateRevision1);
        policies.Rs256 = policy;
        FixedClock clock = new(Now);
        Rs256JwtSigner signer = new(
            policies,
            new MutableBindingResolver(AuthenticationTestData.SigningBinding(context, material.SigningKeyRevision1, "sign-r1", policy)),
            AuthenticationTestData.Provider(material),
            new InMemoryJwtReplayStore(100, clock),
            clock,
            trustedRuntimeClaimValues: resolver);
        return signer.SignJwtAsync(context, AuthenticationTestData.JwtProfileId, [], TestContext.Current.CancellationToken);
    }

    private static TrustedRuntimeClaimValue ValidValue(TrustedRuntimeClaimResolutionRequest request) => new(
        request.Source,
        "external-actor-42",
        TrustedRuntimeClaimValueProvenance.RegisteredServerResolver,
        request.InvocationBinding,
        "authorization-grant-42");

    private static byte[] Decode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/').PadRight((value.Length + 3) / 4 * 4, '=');
        return Convert.FromBase64String(padded);
    }

    private sealed class EchoTrustedRuntimeResolver(Func<TrustedRuntimeClaimResolutionRequest, string> value) : ITrustedRuntimeClaimValueResolver
    {
        public List<TrustedRuntimeClaimResolutionRequest> Requests { get; } = [];

        public Task<TrustedRuntimeClaimValue> ResolveAsync(TrustedRuntimeClaimResolutionRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(request);
            TrustedRuntimeClaimValue result = TrustedRuntimeClaimValue.FromRegisteredResolver(
                request,
                value(request),
                "authorization-grant-42");
            return Task.FromResult(result);
        }
    }

    private sealed class DirectTrustedRuntimeResolver(Func<TrustedRuntimeClaimResolutionRequest, TrustedRuntimeClaimValue> value) : ITrustedRuntimeClaimValueResolver
    {
        public Task<TrustedRuntimeClaimValue> ResolveAsync(TrustedRuntimeClaimResolutionRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(value(request));
        }
    }

    private sealed class ReplayTrustedRuntimeResolver(TrustedRuntimeClaimValue value) : ITrustedRuntimeClaimValueResolver
    {
        public List<TrustedRuntimeClaimResolutionRequest> Requests { get; } = [];

        public Task<TrustedRuntimeClaimValue> ResolveAsync(TrustedRuntimeClaimResolutionRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(request);
            return Task.FromResult(value);
        }
    }

    private sealed class FailingTrustedRuntimeResolver : ITrustedRuntimeClaimValueResolver
    {
        public Task<TrustedRuntimeClaimValue> ResolveAsync(TrustedRuntimeClaimResolutionRequest request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("hidden resolver authorization detail");
    }

    private sealed class BlockingSigningProvider(IKeyOperationProvider inner) : IKeyOperationProvider
    {
        public TaskCompletionSource SigningStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseSigning { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken) =>
            inner.GetSigningKeyMetadataAsync(logicalReference, cancellationToken);

        public async Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken)
        {
            SigningStarted.TrySetResult();
            await ReleaseSigning.Task.WaitAsync(cancellationToken);
            return await inner.SignDigestAsync(logicalReference, algorithm, digest, cancellationToken);
        }
    }
}

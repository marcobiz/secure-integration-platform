using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using System.Globalization;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class TypedSessionHandshakeTests
{
    private const string ProtocolNamespace = "urn:synthetic:typed-session";
    private const string Soap11Namespace = "http://schemas.xmlsoap.org/soap/envelope/";

    [Fact]
    public async Task Wave1_UT_Published_profile_selects_exact_compiled_adapters_and_nested_request()
    {
        Fixture fixture = new(HandshakeResponse.Issued("issued-session", fixtureTime: null));
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();

        TypedSessionHandshakeResult result = await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken);

        Assert.Equal(TypedSessionHandshakeResultKind.Issued, result.Kind);
        Assert.NotNull(result.Session);
        string request = Assert.Single(fixture.Transport.RequestBodies);
        XDocument document = XDocument.Parse(request);
        XNamespace protocol = ProtocolNamespace;
        XElement payload = document.Descendants(protocol + "CreateSessionRequest").Single();
        Assert.Equal([protocol + "ClientContext"], payload.Elements().Select(element => element.Name));
        XElement clientContext = payload.Element(protocol + "ClientContext")!;
        Assert.Equal([protocol + "Identity", protocol + "Policy"], clientContext.Elements().Select(element => element.Name));
        Assert.Equal([protocol + "Tenant", protocol + "Installation", protocol + "Application"],
            clientContext.Element(protocol + "Identity")!.Elements().Select(element => element.Name));
        Assert.Equal("typed-session", clientContext.Element(protocol + "Policy")!.Element(protocol + "Profile")!.Value);
        Assert.DoesNotContain("Dictionary", request, StringComparison.Ordinal);
        Assert.Equal("urn:synthetic:CreateSession", fixture.Transport.SoapActions.Single());
        Assert.DoesNotContain("issued-session", result.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Wave1_UT_Typed_nested_response_issues_and_reuses_existing_session_lifecycle()
    {
        Fixture fixture = new(HandshakeResponse.Issued("typed-upstream-session", fixtureTime: At("2026-08-09T12:20:00Z")));
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        TypedSessionHandshakeResult acquired = await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken);

        SoapSessionProfile businessProfile = Fixture.BusinessProfile();
        SoapBusinessResult business = await fixture.Client.InvokeAsync(resolved.State.ExecutionContext, resolved.State.Endpoint, businessProfile,
            new Dictionary<string, string> { ["payload"] = "safe-business-input" }, acquired.Session, TestContext.Current.CancellationToken);

        Assert.Equal("accepted", business.Values["result"]);
        Assert.Contains(fixture.Transport.RequestBodies, body => SessionValue(body) == "typed-upstream-session");
        TypedSessionHandshakeResult reused = await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken);
        Assert.Equal(acquired.Session!.Value, reused.Session!.Value);
        Assert.Equal(2, fixture.Transport.RequestBodies.Count);
    }

    [Fact]
    public async Task Wave1_UT_External_handoff_validates_and_atomically_promotes_into_existing_cache()
    {
        CapturingValidator validator = new(_ => ExternalSessionValidationResult.Valid(At("2026-08-09T12:10:00Z")));
        Fixture fixture = new(HandshakeResponse.ExternalAdmissionRequired(), validator);
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        TypedSessionHandshakeResult bootstrap = await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken);
        Assert.Equal(TypedSessionHandshakeResultKind.ExternalAdmissionRequired, bootstrap.Kind);
        Assert.Equal(ExternalSessionProvenance.InteractiveHandoff, bootstrap.AdmissionIntent!.Provenance);

        ExternalSessionCandidate candidate = ExternalSessionCandidate.Create(Encoding.UTF8.GetBytes("presented-session"));
        ExternalAdmissionPresentation presentation = fixture.Client.ResolveAdmissionPresentation(fixture.Principal(), bootstrap.AdmissionIntent.Reference);
        TypedSessionHandshakeResult admitted = await fixture.Client.CompleteExternalAdmissionAsync(
            resolved, presentation, candidate, TestContext.Current.CancellationToken);

        Assert.Equal(TypedSessionHandshakeResultKind.Issued, admitted.Kind);
        Assert.Equal(ExternalSessionProvenance.InteractiveHandoff, admitted.Provenance);
        Assert.Equal(At("2026-08-09T12:10:00Z"), admitted.ExpiresAt);
        Assert.Equal("presented-session", Assert.Single(validator.Candidates));
        Assert.Throws<ObjectDisposedException>(() => _ = candidate.SensitiveValue);

        SoapBusinessResult business = await fixture.Client.InvokeAsync(resolved.State.ExecutionContext, resolved.State.Endpoint, Fixture.BusinessProfile(),
            new Dictionary<string, string> { ["payload"] = "safe" }, admitted.Session, TestContext.Current.CancellationToken);
        Assert.Equal("accepted", business.Values["result"]);
        Assert.Contains(fixture.Transport.RequestBodies, body => SessionValue(body) == "presented-session");
    }

    [Fact]
    public async Task Wave1_SEC_Admission_intent_wrong_reference_reuse_and_expiry_are_denied()
    {
        Fixture fixture = new(HandshakeResponse.ExternalAdmissionRequired(), CapturingValidator.Valid());
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        TypedSessionHandshakeResult first = await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken);
        ExternalSessionAdmissionIntent intent = first.AdmissionIntent!;

        await AssertCodeAsync("SOAP-ADMISSION-INTENT-INVALID", () => fixture.CompleteAsync(resolved,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "candidate"u8.ToArray()));

        TypedSessionHandshakeResult admitted = await fixture.CompleteAsync(resolved, intent.Reference, "candidate"u8.ToArray());
        Assert.Equal(TypedSessionHandshakeResultKind.Issued, admitted.Kind);
        await AssertCodeAsync("SOAP-ADMISSION-INTENT-INVALID", () => fixture.CompleteAsync(resolved, intent.Reference, "candidate"u8.ToArray()));

        Fixture expiryFixture = new(HandshakeResponse.ExternalAdmissionRequired(), CapturingValidator.Valid());
        ResolvedTypedSessionHandshake expiryResolved = await expiryFixture.ResolveAsync();
        ExternalSessionAdmissionIntent expiring = (await expiryFixture.Client.AcquireTypedSessionAsync(expiryResolved, TestContext.Current.CancellationToken)).AdmissionIntent!;
        expiryFixture.Clock.UtcNow = expiring.ExpiresAt.AddTicks(1);
        await AssertCodeAsync("SOAP-ADMISSION-INTENT-INVALID", () => expiryFixture.CompleteAsync(expiryResolved, expiring.Reference, "candidate"u8.ToArray()));
    }

    [Fact]
    public async Task Wave1_SEC_Admission_intent_is_bound_to_exact_tenant_application_installation_and_lifecycle_key()
    {
        Fixture fixture = new(HandshakeResponse.ExternalAdmissionRequired(), CapturingValidator.Valid());
        ResolvedTypedSessionHandshake original = await fixture.ResolveAsync();
        ExternalSessionAdmissionIntent intent = (await fixture.Client.AcquireTypedSessionAsync(original, TestContext.Current.CancellationToken)).AdmissionIntent!;

        foreach (PrincipalDimension dimension in Enum.GetValues<PrincipalDimension>().Where(value => value != PrincipalDimension.None))
        {
            await AssertCodeAsync("SOAP-ADMISSION-INTENT-INVALID", () => fixture.CompleteAsync(original, intent.Reference, "candidate"u8.ToArray(), dimension));
        }
    }

    [Theory]
    [InlineData(ExternalSessionValidationStatus.Rejected, "SOAP-ADMISSION-VALIDATION-REJECTED")]
    [InlineData(ExternalSessionValidationStatus.MalformedResponse, "SOAP-ADMISSION-VALIDATION-FAILED")]
    [InlineData(ExternalSessionValidationStatus.Unavailable, "SOAP-ADMISSION-VALIDATION-FAILED")]
    public async Task Wave1_SEC_Validator_nonvalid_outcomes_consume_intent_without_promotion(ExternalSessionValidationStatus status, string code)
    {
        CapturingValidator validator = new(_ => ExternalSessionValidationResult.Invalid(status));
        Fixture fixture = new(HandshakeResponse.ExternalAdmissionRequired(), validator);
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        ExternalSessionAdmissionIntent intent = (await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken)).AdmissionIntent!;

        await AssertCodeAsync(code, () => fixture.CompleteAsync(resolved, intent.Reference, "remote-canary"u8.ToArray()));
        await AssertCodeAsync("SOAP-ADMISSION-INTENT-INVALID", () => fixture.CompleteAsync(resolved, intent.Reference, "candidate"u8.ToArray()));
        Assert.Single(validator.Candidates);
    }

    [Fact]
    public async Task Wave1_SEC_Remote_expiry_is_mandatory_future_and_capped_by_server_policy()
    {
        CapturingValidator expired = new(_ => ExternalSessionValidationResult.Valid(At("2026-08-09T11:59:59Z")));
        Fixture invalidFixture = new(HandshakeResponse.ExternalAdmissionRequired(), expired);
        ResolvedTypedSessionHandshake invalidResolved = await invalidFixture.ResolveAsync();
        ExternalSessionAdmissionIntent invalidIntent = (await invalidFixture.Client.AcquireTypedSessionAsync(invalidResolved, TestContext.Current.CancellationToken)).AdmissionIntent!;
        await AssertCodeAsync("SOAP-ADMISSION-REMOTE-EXPIRY-INVALID", () => invalidFixture.CompleteAsync(invalidResolved, invalidIntent.Reference, "candidate"u8.ToArray()));

        CapturingValidator longRemote = new(_ => ExternalSessionValidationResult.Valid(At("2026-08-12T12:00:00Z")));
        Fixture cappedFixture = new(HandshakeResponse.ExternalAdmissionRequired(), longRemote);
        ResolvedTypedSessionHandshake cappedResolved = await cappedFixture.ResolveAsync();
        ExternalSessionAdmissionIntent cappedIntent = (await cappedFixture.Client.AcquireTypedSessionAsync(cappedResolved, TestContext.Current.CancellationToken)).AdmissionIntent!;
        TypedSessionHandshakeResult result = await cappedFixture.CompleteAsync(cappedResolved, cappedIntent.Reference, "candidate"u8.ToArray());
        Assert.Equal(cappedFixture.Clock.UtcNow.AddHours(1), result.ExpiresAt);
    }

    [Theory]
    [InlineData("duplicate")]
    [InlineData("wrong-order")]
    [InlineData("unexpected")]
    [InlineData("mixed")]
    [InlineData("nested-invalid")]
    [InlineData("domain-invalid")]
    public async Task Wave1_SEC_Typed_response_adapter_denies_order_cardinality_domains_nested_unexpected_and_mixed_content(string mutation)
    {
        Fixture fixture = new(HandshakeResponse.Malformed(mutation));
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        await AssertCodeAsync("SOAP-TYPED-ADAPTER-REJECTED", () => fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("dtd", "SOAP-XML-MALFORMED")]
    [InlineData("wrong-qname", "SOAP-RESPONSE-NAMESPACE")]
    [InlineData("two-payloads", "SOAP-BODY-STRUCTURE")]
    [InlineData("body-attribute", "SOAP-BODY-STRUCTURE")]
    public async Task Wave1_SEC_Typed_response_keeps_hardened_outer_XML_boundary(string mutation, string code)
    {
        Fixture fixture = new(HandshakeResponse.MalformedOuter(mutation));
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        await AssertCodeAsync(code, () => fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("text")]
    [InlineData("cdata")]
    [InlineData("attribute")]
    public async Task Wave1_SEC_Per_value_XML_bound_fails_before_the_typed_adapter_is_invoked(string valueKind)
    {
        CountingResponseAdapter adapter = new();
        Fixture fixture = new(HandshakeResponse.OversizedIndividualValue(valueKind), responseAdapter: adapter);
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();

        await AssertCodeAsync("SOAP-XML-VALUE-TOO-LARGE", () => fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken));
        Assert.Equal(0, adapter.Calls);
    }

    [Theory]
    [InlineData("text")]
    [InlineData("cdata")]
    [InlineData("attribute")]
    public async Task Wave1_SEC_Per_value_XML_bound_accepts_values_immediately_below_the_boundary(string valueKind)
    {
        CountingResponseAdapter adapter = new();
        Fixture fixture = new(HandshakeResponse.IndividualValue(valueKind, 16_384), responseAdapter: adapter);
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();

        await AssertCodeAsync("SOAP-TYPED-ADAPTER-REJECTED", () => fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken));
        Assert.Equal(1, adapter.Calls);
    }

    [Fact]
    public async Task Wave1_SEC_Aggregate_XML_bound_fails_before_the_typed_adapter_is_invoked()
    {
        CountingResponseAdapter adapter = new();
        Fixture fixture = new(HandshakeResponse.AggregateOversizedValues(), responseAdapter: adapter);
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();

        await AssertCodeAsync("SOAP-RESPONSE-TOO-LARGE", () => fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken));
        Assert.Equal(0, adapter.Calls);
    }

    [Fact]
    public async Task Wave1_SEC_Core_stops_typed_request_adapter_at_the_Published_byte_bound_before_transport()
    {
        Fixture fixture = new(HandshakeResponse.Issued("unused", null), requestAdapter: new OversizedRequestAdapter());
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        await AssertCodeAsync("SOAP-REQUEST-TOO-LARGE", () => fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken));
        Assert.Empty(fixture.Transport.RequestBodies);
    }

    [Fact]
    public async Task Wave1_SEC_Adapter_cancellation_is_preserved_only_for_the_actual_token_and_otherwise_sanitized()
    {
        const string canary = "adapter-cancellation-extension-canary";
        Fixture requestFailure = new(HandshakeResponse.Issued("unused", null), requestAdapter: new CancelingRequestAdapter(canary, null));
        ResolvedTypedSessionHandshake requestResolved = await requestFailure.ResolveAsync();
        SoapAuthException requestError = await Assert.ThrowsAsync<SoapAuthException>(() => requestFailure.Client.AcquireTypedSessionAsync(requestResolved, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-TYPED-ADAPTER-REJECTED", requestError.Code);
        Assert.Null(requestError.InnerException);
        Assert.DoesNotContain(canary, requestError.ToString(), StringComparison.Ordinal);

        Fixture responseFailure = new(HandshakeResponse.Issued("unused", null), responseAdapter: new CancelingResponseAdapter(canary));
        ResolvedTypedSessionHandshake responseResolved = await responseFailure.ResolveAsync();
        SoapAuthException responseError = await Assert.ThrowsAsync<SoapAuthException>(() => responseFailure.Client.AcquireTypedSessionAsync(responseResolved, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-TYPED-ADAPTER-REJECTED", responseError.Code);
        Assert.Null(responseError.InnerException);
        Assert.DoesNotContain(canary, responseError.ToString(), StringComparison.Ordinal);

        Fixture validationFailure = new(HandshakeResponse.ExternalAdmissionRequired(), new CancelingValidationAdapter(canary));
        ResolvedTypedSessionHandshake validationResolved = await validationFailure.ResolveAsync();
        ExternalSessionAdmissionIntent intent = (await validationFailure.Client.AcquireTypedSessionAsync(validationResolved, TestContext.Current.CancellationToken)).AdmissionIntent!;
        SoapAuthException validationError = await Assert.ThrowsAsync<SoapAuthException>(() => validationFailure.CompleteAsync(validationResolved, intent.Reference, "candidate"u8.ToArray()));
        Assert.Equal("SOAP-ADMISSION-VALIDATION-FAILED", validationError.Code);
        Assert.Null(validationError.InnerException);
        Assert.DoesNotContain(canary, validationError.ToString(), StringComparison.Ordinal);

        using CancellationTokenSource canceled = new();
        Fixture realCancellation = new(HandshakeResponse.Issued("unused", null), requestAdapter: new CancelingRequestAdapter(canary, canceled));
        ResolvedTypedSessionHandshake realResolved = await realCancellation.ResolveAsync();
        OperationCanceledException actual = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => realCancellation.Client.AcquireTypedSessionAsync(realResolved, canceled.Token));
        Assert.Equal(canceled.Token, actual.CancellationToken);
        Assert.Null(actual.InnerException);
        Assert.DoesNotContain(canary, actual.Message, StringComparison.Ordinal);

        using CancellationTokenSource validationCanceled = new();
        Fixture realValidationCancellation = new(HandshakeResponse.ExternalAdmissionRequired(), new CancelingValidationAdapter(canary, validationCanceled));
        ResolvedTypedSessionHandshake realValidationResolved = await realValidationCancellation.ResolveAsync();
        ExternalSessionAdmissionIntent realValidationIntent = (await realValidationCancellation.Client.AcquireTypedSessionAsync(realValidationResolved, TestContext.Current.CancellationToken)).AdmissionIntent!;
        ExternalAdmissionPresentation realValidationPresentation = realValidationCancellation.Client.ResolveAdmissionPresentation(realValidationCancellation.Principal(), realValidationIntent.Reference);
        OperationCanceledException actualValidation = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => realValidationCancellation.Client.CompleteExternalAdmissionAsync(
            realValidationResolved, realValidationPresentation, ExternalSessionCandidate.Create("candidate"u8), validationCanceled.Token));
        Assert.Equal(validationCanceled.Token, actualValidation.CancellationToken);
        Assert.Null(actualValidation.InnerException);
        Assert.DoesNotContain(canary, actualValidation.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Wave1_SEC_Published_adapter_ID_and_type_mismatch_fail_before_transport()
    {
        Fixture[] fixtures =
        [
            new(HandshakeResponse.Issued("unused", null), requestAdapter: new MismatchedRequestAdapter()),
            new(HandshakeResponse.Issued("unused", null), responseAdapter: new MismatchedResponseAdapter()),
            new(HandshakeResponse.Issued("unused", null), validator: new MismatchedValidationAdapter())
        ];
        foreach (Fixture fixture in fixtures)
        {
            await AssertCodeAsync("SOAP-TYPED-ADAPTER-UNAVAILABLE", () => fixture.ResolveAsync());
            Assert.Empty(fixture.Transport.RequestBodies);
        }
    }

    [Fact]
    public async Task Wave1_SEC_Unknown_or_future_external_provenance_is_rejected_at_the_adapter_boundary()
    {
        Fixture fixture = new(HandshakeResponse.ExternalAdmissionRequired(), responseAdapter: new UnknownProvenanceResponseAdapter());
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();

        await AssertCodeAsync("SOAP-TYPED-ADAPTER-REJECTED", () => fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Wave1_SEC_Rotate_or_disable_during_remote_validation_prevents_promotion(bool disable)
    {
        Fixture? fixture = null;
        CapturingValidator validator = new(_ =>
        {
            if (disable) fixture!.Snapshots.Disable(); else fixture!.Snapshots.Rotate();
            return ExternalSessionValidationResult.Valid(At("2026-08-09T12:10:00Z"));
        });
        fixture = new(HandshakeResponse.ExternalAdmissionRequired(), validator);
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        ExternalSessionAdmissionIntent intent = (await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken)).AdmissionIntent!;

        SoapAuthException failure = await Assert.ThrowsAsync<SoapAuthException>(() => fixture.CompleteAsync(resolved, intent.Reference, "candidate"u8.ToArray()));
        Assert.True(failure.Code is "SOAP-TYPED-AUTHORITY-STALE" or "SOAP-TYPED-AUTHORITY-REJECTED");
        Assert.Equal(2, fixture.Transport.RequestBodies.Count);
    }

    [Fact]
    public async Task Wave1_SEC_Final_window_mutation_after_every_async_check_fails_the_generation_CAS()
    {
        TaskCompletionSource<bool> enteredFinalWindow = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> resumePromotion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Fixture fixture = new(HandshakeResponse.ExternalAdmissionRequired(), CapturingValidator.Valid(), beforeAdmissionPromotion: async cancellationToken =>
        {
            enteredFinalWindow.TrySetResult(true);
            await resumePromotion.Task.WaitAsync(cancellationToken);
        });
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        ExternalSessionAdmissionIntent intent = (await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken)).AdmissionIntent!;

        Task<TypedSessionHandshakeResult> completion = fixture.CompleteAsync(resolved, intent.Reference, "candidate"u8.ToArray());
        await enteredFinalWindow.Task.WaitAsync(TestContext.Current.CancellationToken);
        fixture.MutateAuthorityAfterFinalChecks();
        resumePromotion.TrySetResult(true);

        await AssertCodeAsync("SOAP-TYPED-AUTHORITY-STALE", async () => await completion);
        Assert.Equal(0, fixture.Client.CachedSessionCount);
    }

    [Fact]
    public async Task Wave1_SEC_Concurrent_same_intent_completion_has_exactly_one_success_without_timing_assumptions()
    {
        TaskCompletionSource<bool> firstReserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource<bool> releaseFirst = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Fixture fixture = new(HandshakeResponse.ExternalAdmissionRequired(), CapturingValidator.Valid(), beforeAdmissionPromotion: async cancellationToken =>
        {
            firstReserved.TrySetResult(true);
            await releaseFirst.Task.WaitAsync(cancellationToken);
        });
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        ExternalSessionAdmissionIntent intent = (await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken)).AdmissionIntent!;

        Task<TypedSessionHandshakeResult> first = fixture.CompleteAsync(resolved, intent.Reference, "candidate"u8.ToArray());
        await firstReserved.Task.WaitAsync(TestContext.Current.CancellationToken);
        await AssertCodeAsync("SOAP-ADMISSION-INTENT-INVALID", () => fixture.CompleteAsync(resolved, intent.Reference, "candidate"u8.ToArray()));
        releaseFirst.TrySetResult(true);
        TypedSessionHandshakeResult winner = await first;

        Assert.Equal(TypedSessionHandshakeResultKind.Issued, winner.Kind);
        Assert.Equal(1, fixture.Client.CachedSessionCount);
    }

    [Fact]
    public void Wave1_SEC_Validation_proof_is_bound_to_candidate_intent_profile_context_and_generation_and_is_single_use()
    {
        DateTimeOffset now = At("2026-08-09T12:00:00Z");
        Guid tenant = Guid.NewGuid();
        Guid installation = Guid.NewGuid();
        Guid application = Guid.NewGuid();
        Guid environment = Guid.NewGuid();
        SoapSessionCache cache = new();
        SoapSessionCacheKey key = new(tenant, installation, application, environment, "connector", "1.0.0", 1, 1, 1, "profile-a");
        GatewayClientPrincipal principal = PrincipalForCache(tenant, installation, application, environment, now);
        ExternalSessionAdmissionIntent intent = cache.StoreAdmissionIntent(key, "authority-a", "operation-a", "profile-a",
            ExternalSessionProvenance.InteractiveHandoff, now, now.AddMinutes(1));
        ExternalAdmissionPresentation presentation = cache.ResolveAdmissionPresentation(intent.Reference, principal, now);
        AdmissionCompletion completion = cache.BeginAdmission(presentation, "authority-a", now);
        AdmissionValidationProof proof = new(completion, SHA256.HashData("candidate-a"u8.ToArray()));

        OpaqueSoapSessionReference issued = cache.CompleteAdmission(proof, "candidate-a", now, now.AddMinutes(5));
        Assert.NotNull(issued);
        AssertCode("SOAP-ADMISSION-INTENT-INVALID", () => cache.CompleteAdmission(proof, "candidate-a", now, now.AddMinutes(5)));
        AssertCode("SOAP-ADMISSION-INTENT-INVALID", () => cache.CompleteAdmission(proof, "candidate-b", now, now.AddMinutes(5)));

        cache.Invalidate(key);
        ExternalSessionAdmissionIntent later = cache.StoreAdmissionIntent(key, "authority-a", "operation-a", "profile-a",
            ExternalSessionProvenance.InteractiveHandoff, now, now.AddMinutes(1));
        _ = cache.BeginAdmission(cache.ResolveAdmissionPresentation(later.Reference, principal, now), "authority-a", now);
        AssertCode("SOAP-ADMISSION-INTENT-INVALID", () => cache.CompleteAdmission(proof, "candidate-a", now, now.AddMinutes(5)));

        SoapSessionCacheKey otherProfile = key with { ProfileId = "profile-b" };
        ExternalSessionAdmissionIntent other = cache.StoreAdmissionIntent(otherProfile, "authority-b", "operation-a", "profile-b",
            ExternalSessionProvenance.InteractiveHandoff, now, now.AddMinutes(1));
        _ = cache.BeginAdmission(cache.ResolveAdmissionPresentation(other.Reference, principal, now), "authority-b", now);
        AssertCode("SOAP-ADMISSION-INTENT-INVALID", () => cache.CompleteAdmission(proof, "candidate-a", now, now.AddMinutes(5)));
    }

    [Fact]
    public async Task Wave1_SEC_Authoritative_store_mutations_invalidate_binding_publication_and_resource_promotion_generations()
    {
        InMemoryConnectorConfigurationStore store = new();
        PublishedConnectorMutationAuthority authority = store.RuntimeMutationAuthority;
        Guid environmentId = Guid.NewGuid();
        const string connectorSlug = "typed-mutation-authority";
        DateTimeOffset now = At("2026-08-09T12:00:00Z");

        PublishedConnectorAuthorityGeneration beforeResource = authority.Capture(connectorSlug, environmentId);
        _ = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic", "synthetic", "credential", ProviderResourceType.Secret,
            "Credential", environmentId, connectorSlug, "session-bootstrap", "synthetic://credential", ProviderResourceStatus.Active, null, 0,
            null, null, string.Empty, now), TestContext.Current.CancellationToken);
        Assert.False(authority.TryPromoteIfCurrent(beforeResource, () => true, out _));

        using JsonDocument definition = JsonDocument.Parse(PublishedDefinition("synthetic-create-session-request").Replace("synthetic-typed-session", connectorSlug, StringComparison.Ordinal));
        ValidatedConnectorDefinition validatedDefinition = new ConnectorDefinitionValidator().ValidateRequired(definition.RootElement);
        ConnectorVersionRecord draft = await store.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, connectorSlug, "1.0.0", "1.0", ConnectorVersionState.Draft,
            validatedDefinition.CanonicalJson, Convert.FromHexString(validatedDefinition.ChecksumSha256), "editor", now, 0, null, null), TestContext.Current.CancellationToken);
        ConnectorVersionRecord validated = await store.MarkValidatedAsync(draft.Id, draft.RowVersion, now, TestContext.Current.CancellationToken);
        Dictionary<string, Uri> endpoints = new()
        {
            ["handshake-endpoint"] = new("https://handshake.example.test/"),
            ["validation-endpoint"] = new("https://validation.example.test/")
        };
        string checksum = ConnectorBindingDigests.Revision(validated.Id, environmentId, endpoints,
            new Dictionary<string, ProviderResourceBinding>(), new Dictionary<string, ProviderResourceBinding>());
        PublishedConnectorAuthorityGeneration beforeBinding = authority.Capture(connectorSlug, environmentId);
        _ = await store.PutBindingsAsync(new(Guid.NewGuid(), validated.ConnectorId, validated.Id, environmentId, endpoints,
            new Dictionary<string, ProviderResourceBinding>(), new Dictionary<string, ProviderResourceBinding>(), 0, checksum,
            ConnectorBindingState.Draft, now, "editor"), null, Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.False(authority.TryPromoteIfCurrent(beforeBinding, () => true, out _));

        PublishedConnectorAuthorityGeneration beforePublication = authority.Capture(connectorSlug, environmentId);
        _ = await store.PublishAsync(validated.Id, validated.RowVersion, 0, "approver", now, TestContext.Current.CancellationToken);
        Assert.False(authority.TryPromoteIfCurrent(beforePublication, () => true, out _));
    }

    [Fact]
    public void Wave1_SEC_Promotion_is_rejected_for_the_entire_in_progress_mutation_window_even_when_captured_after_begin()
    {
        PublishedConnectorMutationAuthority authority = new();
        Guid environmentId = Guid.NewGuid();
        const string connectorId = "typed-in-progress-mutation";
        PublishedConnectorAuthorityGeneration before = authority.Capture(connectorId, environmentId);
        PublishedConnectorAuthorityGeneration during;

        using (authority.BeginMutation(connectorId, environmentId))
        {
            during = authority.Capture(connectorId, environmentId);
            Assert.False(authority.TryPromoteIfCurrent(before, () => true, out _));
            Assert.False(authority.TryPromoteIfCurrent(during, () => true, out _));
        }

        Assert.False(authority.TryPromoteIfCurrent(during, () => true, out _));
        PublishedConnectorAuthorityGeneration after = authority.Capture(connectorId, environmentId);
        Assert.True(authority.TryPromoteIfCurrent(after, () => true, out bool? promoted));
        Assert.True(promoted);
    }

    [Fact]
    public async Task Wave1_SEC_Admission_state_reuses_256_cap_and_lazy_TTL_sweep()
    {
        Fixture fixture = new(HandshakeResponse.ExternalAdmissionRequired(), CapturingValidator.Valid());
        for (int index = 0; index < SoapSessionCache.MaximumEntries; index++)
        {
            ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync(PrincipalDimension.None, index + 1);
            TypedSessionHandshakeResult result = await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken);
            Assert.Equal(TypedSessionHandshakeResultKind.ExternalAdmissionRequired, result.Kind);
        }
        ResolvedTypedSessionHandshake overflow = await fixture.ResolveAsync(PrincipalDimension.None, SoapSessionCache.MaximumEntries + 1);
        await AssertCodeAsync("SOAP-CACHE-CAPACITY", () => fixture.Client.AcquireTypedSessionAsync(overflow, TestContext.Current.CancellationToken));

        fixture.Clock.UtcNow = fixture.Clock.UtcNow.AddMinutes(2);
        TypedSessionHandshakeResult afterSweep = await fixture.Client.AcquireTypedSessionAsync(overflow, TestContext.Current.CancellationToken);
        Assert.Equal(TypedSessionHandshakeResultKind.ExternalAdmissionRequired, afterSweep.Kind);
    }

    [Fact]
    public async Task Wave1_SEC_Candidate_session_raw_XML_and_validator_diagnostics_are_redacted()
    {
        const string canary = "candidate-validator-raw-xml-canary";
        CapturingValidator validator = new(_ => throw new InvalidOperationException(canary));
        Fixture fixture = new(HandshakeResponse.ExternalAdmissionRequired(), validator);
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        ExternalSessionAdmissionIntent intent = (await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken)).AdmissionIntent!;
        ExternalSessionCandidate candidate = ExternalSessionCandidate.Create(Encoding.UTF8.GetBytes(canary));
        ExternalAdmissionPresentation presentation = fixture.Client.ResolveAdmissionPresentation(fixture.Principal(), intent.Reference);

        SoapAuthException failure = await Assert.ThrowsAsync<SoapAuthException>(() => fixture.Client.CompleteExternalAdmissionAsync(
            resolved, presentation, candidate, TestContext.Current.CancellationToken));
        string diagnostic = string.Join('\n', failure.ToString(), intent.ToString(), resolved.ToString(), validator.ToString(), JsonSerializer.Serialize(intent), JsonSerializer.Serialize(candidate));
        Assert.DoesNotContain(canary, diagnostic, StringComparison.Ordinal);
        Assert.DoesNotContain("<soap", diagnostic, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("SOAP-ADMISSION-VALIDATION-FAILED", failure.Code);
    }

    [Fact]
    public void Wave1_CT_Public_API_exposes_only_authenticated_presentation_and_keeps_legacy_scalar_path_optional()
    {
        Type client = typeof(SoapSessionClient);
        Assert.Contains(client.GetMethods(), method => method.Name == nameof(SoapSessionClient.AcquireSessionAsync));
        Assert.Contains(client.GetMethods(), method => method.Name == nameof(SoapSessionClient.AcquireTypedSessionAsync) &&
            method.GetParameters().Select(parameter => parameter.ParameterType).SequenceEqual([typeof(ResolvedTypedSessionHandshake), typeof(CancellationToken)]));
        Assert.DoesNotContain(client.GetMethods(), method => method.Name.Contains("CompleteExternalAdmission", StringComparison.Ordinal));
        Type runtime = typeof(TypedSessionHandshakeRuntime);
        System.Reflection.MethodInfo completion = Assert.Single(runtime.GetMethods(), method => method.Name == nameof(TypedSessionHandshakeRuntime.CompleteExternalAdmissionAsync));
        Assert.Equal([typeof(GatewayClientPrincipal), typeof(string), typeof(ReadOnlyMemory<byte>), typeof(CancellationToken)],
            completion.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.False(typeof(ExternalSessionCandidate).IsPublic);
        Assert.DoesNotContain(client.GetMethods(), method => method.Name.Contains("PutSession", StringComparison.Ordinal) ||
            method.Name.Contains("SetCachedToken", StringComparison.Ordinal) || method.Name.Contains("PromoteSession", StringComparison.Ordinal));
        Assert.Single(typeof(TypedSessionHandshakeAuthorityRequest).GetConstructors());
        Assert.Equal([typeof(string)], typeof(TypedSessionHandshakeAuthorityRequest).GetConstructors().Single().GetParameters().Select(value => value.ParameterType));
    }

    [Fact]
    public void Wave1_UT_Typed_profile_is_schema_valid_and_adapter_QName_validator_endpoint_changes_are_four_eyes_digest_bound()
    {
        ConnectorDefinitionValidator validator = new();
        using JsonDocument definition = JsonDocument.Parse(PublishedDefinition("synthetic-create-session-request"));
        ValidatedConnectorDefinition validated = validator.ValidateRequired(definition.RootElement, null);
        Guid connectorId = Guid.NewGuid();
        Guid versionId = Guid.NewGuid();
        Guid environmentId = Guid.NewGuid();
        ConnectorVersionRecord version = new(versionId, connectorId, "synthetic-typed-session", "1.0.0", "1.0", ConnectorVersionState.Published,
            validated.CanonicalJson, Convert.FromHexString(validated.ChecksumSha256), "publisher", At("2026-08-09T11:00:00Z"), 1,
            At("2026-08-09T11:10:00Z"), At("2026-08-09T11:20:00Z"));
        ConnectorBindingSet bindings = new(Guid.NewGuid(), connectorId, versionId, environmentId,
            new Dictionary<string, Uri> { ["handshake-endpoint"] = new("https://handshake.example.test/"), ["validation-endpoint"] = new("https://validation.example.test/") },
            new Dictionary<string, ProviderResourceBinding>(), new Dictionary<string, ProviderResourceBinding>(), 3, "binding-checksum",
            ConnectorBindingState.Active, At("2026-08-09T11:15:00Z"), "publisher");
        ApprovalReviewResult review = ConnectorApprovalArtifacts.Create(version, [bindings]);
        ApprovalOperationReview operation = Assert.Single(review.Artifact.Operations);
        ApprovalAuthorityEndpointReview validation = Assert.Single(operation.AuthorityEndpoints);
        Assert.Equal("session-admission-validation", validation.Role);
        Assert.Equal("validation-endpoint", validation.Endpoint.LogicalBindingId);
        Assert.Contains("validation-endpoint", operation.BindingDependencies.AuthorityEndpointBindingIds);

        using JsonDocument changedDefinition = JsonDocument.Parse(PublishedDefinition("synthetic-create-session-request-v2"));
        ValidatedConnectorDefinition changed = validator.ValidateRequired(changedDefinition.RootElement, null);
        ConnectorVersionRecord changedVersion = version with { CanonicalJson = changed.CanonicalJson, ChecksumSha256 = Convert.FromHexString(changed.ChecksumSha256) };
        ApprovalReviewResult changedReview = ConnectorApprovalArtifacts.Create(changedVersion, [bindings]);
        Assert.NotEqual(review.DigestSha256, changedReview.DigestSha256);
    }

    private static async Task AssertCodeAsync(string expected, Func<Task> action)
    {
        SoapAuthException exception = await Assert.ThrowsAsync<SoapAuthException>(action);
        Assert.Equal(expected, exception.Code);
    }

    private static void AssertCode(string expected, Action action)
    {
        SoapAuthException exception = Assert.Throws<SoapAuthException>(action);
        Assert.Equal(expected, exception.Code);
    }

    private static GatewayClientPrincipal PrincipalForCache(Guid tenant, Guid installation, Guid application, Guid environment, DateTimeOffset now)
    {
        RegisteredInstallationIdentity identity = new(installation, tenant, application, environment, TenantStatus.Active, ApplicationStatus.Active,
            InstallationStatus.Active, Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], now.AddMinutes(-1), now.AddHours(1), "1.0.0", null);
        return new(identity, Guid.NewGuid());
    }

    private static DateTimeOffset At(string value) => DateTimeOffset.ParseExact(value, "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);

    private static string? SessionValue(string xml) => XDocument.Parse(xml).Descendants(XName.Get("Session", ProtocolNamespace)).SingleOrDefault()?.Value;

    private static string PublishedDefinition(string requestAdapterId) => $$"""
        {
          "schemaVersion":"1.0",
          "connectorId":"synthetic-typed-session",
          "version":"1.0.0",
          "displayName":"Synthetic Typed Session",
          "bindings":{
            "endpoints":[{"name":"handshake-endpoint"},{"name":"validation-endpoint"}],
            "secrets":[]
          },
          "operations":[{
            "operationId":"session-bootstrap",
            "endpointBinding":"handshake-endpoint",
            "method":"POST",
            "path":"/session/create",
            "request":{"contentType":"text/xml","maximumBytes":32768},
            "response":{"maximumBytes":32768},
            "authentication":{"kind":"none"},
            "typedSessionHandshake":{
              "profileId":"typed-session",
              "soapVersion":"1.1",
              "action":"urn:synthetic:CreateSession",
              "requestElement":{"localName":"CreateSessionRequest","namespaceUri":"urn:synthetic:typed-session"},
              "responseElement":{"localName":"CreateSessionResponse","namespaceUri":"urn:synthetic:typed-session"},
              "requestAdapter":{"id":"{{requestAdapterId}}","type":"compiled-typed-request"},
              "responseAdapter":{"id":"synthetic-create-session-response","type":"compiled-typed-response"},
              "sessionLifetimeSeconds":3600,
              "externalAdmission":{
                "validator":{"id":"synthetic-session-validator","type":"compiled-typed-validator"},
                "endpointBinding":"validation-endpoint",
                "path":"/session/validate",
                "soapVersion":"1.1",
                "action":"urn:synthetic:ValidateSession",
                "requestElement":{"localName":"ValidateSessionRequest","namespaceUri":"urn:synthetic:typed-session"},
                "responseElement":{"localName":"ValidateSessionResponse","namespaceUri":"urn:synthetic:typed-session"},
                "intentLifetimeSeconds":60,
                "timeoutMs":5000,
                "maximumRequestBytes":32768,
                "maximumResponseBytes":32768
              }
            },
            "timeoutMs":5000,
            "redirectPolicy":"deny",
            "allowedClientHeaders":[],
            "idempotent":false,
            "maximumRetries":0
          }]
        }
        """;

    private enum PrincipalDimension { None, Tenant, Application, Installation }

    private sealed class Fixture
    {
        private readonly Guid connectorId = Guid.NewGuid();
        private readonly Guid versionId = Guid.NewGuid();
        private readonly Guid environmentId = Guid.NewGuid();
        private readonly Guid tenantId = Guid.NewGuid();
        private readonly Guid applicationId = Guid.NewGuid();
        private readonly Guid installationId = Guid.NewGuid();
        private readonly PublishedTypedSessionHandshakeResolver authority;

        internal Fixture(
            HandshakeResponse response,
            ITypedExternalSessionValidationAdapter? validator = null,
            ITypedSessionHandshakeRequestAdapter? requestAdapter = null,
            ITypedSessionHandshakeResponseAdapter? responseAdapter = null,
            Func<CancellationToken, Task>? beforeAdmissionPromotion = null)
        {
            Clock = new();
            MutationAuthority = new();
            Transport = new(response);
            requestAdapter ??= new RequestAdapter();
            responseAdapter ??= new ResponseAdapter();
            validator ??= CapturingValidator.Valid();
            TypedSessionHandshakeAdapterRegistry registry = new([requestAdapter], [responseAdapter], [validator]);
            Snapshots = new(CreateSnapshot());
            authority = new(Snapshots.ResolveAsync, registry, Clock, MutationAuthority);
            Client = new(new FixedSecrets(), new FixedResolver(), Transport, Clock, new MatchingStampProvider(), null, beforeAdmissionPromotion);
        }

        internal MutableClock Clock { get; }
        internal PublishedConnectorMutationAuthority MutationAuthority { get; }
        internal TypedTransport Transport { get; }
        internal MutableSnapshotSource Snapshots { get; }
        internal SoapSessionClient Client { get; }

        internal async Task<ResolvedTypedSessionHandshake> ResolveAsync(PrincipalDimension changed = PrincipalDimension.None, int salt = 0)
        {
            GatewayClientPrincipal principal = Principal(changed, salt);
            AuthorizedGatewayInvocation invocation = new(principal, "synthetic-typed-session", "session-bootstrap");
            return await authority.ResolveAsync(invocation, new("typed-session"), TestContext.Current.CancellationToken);
        }

        internal Task<TypedSessionHandshakeResult> CompleteAsync(
            ResolvedTypedSessionHandshake resolved,
            string intentReference,
            ReadOnlyMemory<byte> candidate,
            PrincipalDimension changed = PrincipalDimension.None,
            int salt = 0)
        {
            ExternalAdmissionPresentation presentation = Client.ResolveAdmissionPresentation(Principal(changed, salt), intentReference);
            return Client.CompleteExternalAdmissionAsync(resolved, presentation, ExternalSessionCandidate.Create(candidate.Span), TestContext.Current.CancellationToken);
        }

        internal GatewayClientPrincipal Principal(PrincipalDimension changed = PrincipalDimension.None, int salt = 0)
        {
            Guid tenant = changed == PrincipalDimension.Tenant ? Guid.NewGuid() : Salt(tenantId, salt);
            Guid application = changed == PrincipalDimension.Application ? Guid.NewGuid() : applicationId;
            Guid installation = changed == PrincipalDimension.Installation ? Guid.NewGuid() : installationId;
            RegisteredInstallationIdentity identity = new(installation, tenant, application, environmentId, TenantStatus.Active, ApplicationStatus.Active,
                InstallationStatus.Active, Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], Clock.UtcNow.AddMinutes(-1), Clock.UtcNow.AddHours(1), "1.0.0", null);
            return new(identity, Guid.NewGuid());
        }

        internal void MutateAuthorityAfterFinalChecks()
        {
            Snapshots.Rotate();
            MutationAuthority.Invalidate("synthetic-typed-session", environmentId);
        }

        internal static SoapSessionProfile BusinessProfile()
        {
            SoapOperationProfile login = new("unused-login", SoapEnvelopeVersion.Soap11, "urn:synthetic:unused",
                new("Unused", ProtocolNamespace), new("UnusedResponse", ProtocolNamespace));
            SoapOperationProfile business = new("session-bootstrap", SoapEnvelopeVersion.Soap11, "urn:synthetic:Business",
                new("BusinessRequest", ProtocolNamespace), new("BusinessResponse", ProtocolNamespace),
                [new("payload", new("Payload", ProtocolNamespace))], [new("result", new("Result", ProtocolNamespace))]);
            return new("typed-session", new("provider/user", "provider/password"), login, new("SessionValue", ProtocolNamespace),
                new("Session", ProtocolNamespace), [business], TimeSpan.FromHours(1), []);
        }

        private PublishedConnectorSnapshot CreateSnapshot()
        {
            object definition = new
            {
                connectorId = "synthetic-typed-session",
                version = "1.0.0",
                operations = new[]
                {
                    new
                    {
                        operationId = "session-bootstrap",
                        endpointBinding = "handshake-endpoint",
                        method = "POST",
                        path = "/handshake",
                        request = new { contentType = "text/xml", maximumBytes = 32_768 },
                        response = new { maximumBytes = 32_768 },
                        authentication = new { kind = "none" },
                        timeoutMs = 5_000,
                        typedSessionHandshake = new
                        {
                            profileId = "typed-session",
                            soapVersion = "1.1",
                            action = "urn:synthetic:CreateSession",
                            requestElement = new { localName = "CreateSessionRequest", namespaceUri = ProtocolNamespace },
                            responseElement = new { localName = "CreateSessionResponse", namespaceUri = ProtocolNamespace },
                            requestAdapter = new { id = "synthetic-create-session-request", type = "compiled-typed-request" },
                            responseAdapter = new { id = "synthetic-create-session-response", type = "compiled-typed-response" },
                            sessionLifetimeSeconds = 3_600,
                            externalAdmission = new
                            {
                                validator = new { id = "synthetic-session-validator", type = "compiled-typed-validator" },
                                endpointBinding = "validation-endpoint",
                                path = "/validate",
                                soapVersion = "1.1",
                                action = "urn:synthetic:ValidateSession",
                                requestElement = new { localName = "ValidateSessionRequest", namespaceUri = ProtocolNamespace },
                                responseElement = new { localName = "ValidateSessionResponse", namespaceUri = ProtocolNamespace },
                                intentLifetimeSeconds = 60,
                                timeoutMs = 5_000,
                                maximumRequestBytes = 32_768,
                                maximumResponseBytes = 32_768
                            }
                        }
                    }
                }
            };
            string canonical = JsonSerializer.Serialize(definition);
            ConnectorVersionRecord version = new(versionId, connectorId, "synthetic-typed-session", "1.0.0", "1.0", ConnectorVersionState.Published,
                canonical, SHA256.HashData(Encoding.UTF8.GetBytes(canonical)), "publisher", Clock.UtcNow.AddMinutes(-10), 1,
                Clock.UtcNow.AddMinutes(-5), Clock.UtcNow.AddMinutes(-4));
            Dictionary<string, Uri> endpoints = new(StringComparer.Ordinal)
            {
                ["handshake-endpoint"] = new("https://soap.example.test/"),
                ["validation-endpoint"] = new("https://validation.example.test/")
            };
            ConnectorBindingSet bindings = new(Guid.NewGuid(), connectorId, versionId, environmentId, endpoints,
                new Dictionary<string, ProviderResourceBinding>(StringComparer.Ordinal), new Dictionary<string, ProviderResourceBinding>(StringComparer.Ordinal),
                7, "binding-checksum", ConnectorBindingState.Active, Clock.UtcNow.AddMinutes(-5), "publisher");
            PublishedConnectorStamp stamp = new(versionId, 3, 7, "binding-checksum", "resource-stamp-7");
            return new(version, bindings, stamp, new Dictionary<string, string>(StringComparer.Ordinal), new Dictionary<string, string>(StringComparer.Ordinal));
        }

        private static Guid Salt(Guid original, int salt)
        {
            if (salt == 0) return original;
            byte[] bytes = original.ToByteArray();
            BitConverter.GetBytes(salt).CopyTo(bytes, 0);
            return new(bytes);
        }
    }

    private sealed class RequestAdapter : ITypedSessionHandshakeRequestAdapter
    {
        public string AdapterId => "synthetic-create-session-request";
        public string AdapterType => "compiled-typed-request";

        public void WriteRequest(XmlWriter writer, TypedSessionHandshakeRequestContext context)
        {
            writer.WriteStartElement("s", "ClientContext", ProtocolNamespace);
            writer.WriteStartElement("s", "Identity", ProtocolNamespace);
            writer.WriteElementString("s", "Tenant", ProtocolNamespace, context.TenantId.ToString("D"));
            writer.WriteElementString("s", "Installation", ProtocolNamespace, context.InstallationId.ToString("D"));
            writer.WriteElementString("s", "Application", ProtocolNamespace, context.ApplicationId.ToString("D"));
            writer.WriteEndElement();
            writer.WriteStartElement("s", "Policy", ProtocolNamespace);
            writer.WriteElementString("s", "Profile", ProtocolNamespace, context.ProfileId);
            writer.WriteElementString("s", "PublishedChecksum", ProtocolNamespace, context.PublishedPolicyChecksum);
            writer.WriteEndElement();
            writer.WriteEndElement();
        }
    }

    private sealed class OversizedRequestAdapter : ITypedSessionHandshakeRequestAdapter
    {
        public string AdapterId => "synthetic-create-session-request";
        public string AdapterType => "compiled-typed-request";
        public void WriteRequest(XmlWriter writer, TypedSessionHandshakeRequestContext context) =>
            writer.WriteElementString("s", "Oversized", ProtocolNamespace, new string('x', 65_536));
    }

    private sealed class MismatchedRequestAdapter : ITypedSessionHandshakeRequestAdapter
    {
        public string AdapterId => "synthetic-create-session-request-other";
        public string AdapterType => "compiled-typed-request";
        public void WriteRequest(XmlWriter writer, TypedSessionHandshakeRequestContext context) => throw new InvalidOperationException();
    }

    private sealed class MismatchedResponseAdapter : ITypedSessionHandshakeResponseAdapter
    {
        public string AdapterId => "synthetic-create-session-response-other";
        public string AdapterType => "compiled-typed-response";
        public TypedSessionHandshakeAdapterOutcome ReadResponse(XmlReader payload, TypedSessionHandshakeResponseContext context) => throw new InvalidOperationException();
    }

    private sealed class MismatchedValidationAdapter : ITypedExternalSessionValidationAdapter
    {
        public string AdapterId => "synthetic-session-validator-other";
        public string AdapterType => "compiled-typed-validator";
        public void WriteValidationRequest(XmlWriter writer, ExternalSessionValidationRequestContext context) => throw new InvalidOperationException();
        public ExternalSessionValidationResult ReadValidationResponse(XmlReader payload, ExternalSessionValidationResponseContext context) => throw new InvalidOperationException();
    }

    private sealed class CancelingRequestAdapter(string canary, CancellationTokenSource? cancellation) : ITypedSessionHandshakeRequestAdapter
    {
        public string AdapterId => "synthetic-create-session-request";
        public string AdapterType => "compiled-typed-request";

        public void WriteRequest(XmlWriter writer, TypedSessionHandshakeRequestContext context)
        {
            cancellation?.Cancel();
            throw new OperationCanceledException(canary, new InvalidOperationException(canary), cancellation?.Token ?? CancellationToken.None);
        }
    }

    private sealed class CancelingResponseAdapter(string canary) : ITypedSessionHandshakeResponseAdapter
    {
        public string AdapterId => "synthetic-create-session-response";
        public string AdapterType => "compiled-typed-response";

        public TypedSessionHandshakeAdapterOutcome ReadResponse(XmlReader payload, TypedSessionHandshakeResponseContext context) =>
            throw new OperationCanceledException(canary, new InvalidOperationException(canary), CancellationToken.None);
    }

    private sealed class CountingResponseAdapter : ITypedSessionHandshakeResponseAdapter
    {
        public string AdapterId => "synthetic-create-session-response";
        public string AdapterType => "compiled-typed-response";
        internal int Calls { get; private set; }

        public TypedSessionHandshakeAdapterOutcome ReadResponse(XmlReader payload, TypedSessionHandshakeResponseContext context)
        {
            Calls++;
            throw new InvalidOperationException("Adapter must not receive an XML value rejected by the initial scan.");
        }
    }

    private sealed class UnknownProvenanceResponseAdapter : ITypedSessionHandshakeResponseAdapter
    {
        public string AdapterId => "synthetic-create-session-response";
        public string AdapterType => "compiled-typed-response";

        public TypedSessionHandshakeAdapterOutcome ReadResponse(XmlReader payload, TypedSessionHandshakeResponseContext context) =>
            TypedSessionHandshakeAdapterOutcome.ExternalAdmissionRequired((ExternalSessionProvenance)int.MaxValue);
    }

    private sealed class CancelingValidationAdapter(string canary, CancellationTokenSource? cancellation = null) : ITypedExternalSessionValidationAdapter
    {
        public string AdapterId => "synthetic-session-validator";
        public string AdapterType => "compiled-typed-validator";

        public void WriteValidationRequest(XmlWriter writer, ExternalSessionValidationRequestContext context)
        {
            writer.WriteElementString("s", "Candidate", ProtocolNamespace, Encoding.UTF8.GetString(context.SensitiveCandidate.Span));
        }

        public ExternalSessionValidationResult ReadValidationResponse(XmlReader payload, ExternalSessionValidationResponseContext context)
        {
            cancellation?.Cancel();
            throw new OperationCanceledException(canary, new InvalidOperationException(canary), cancellation?.Token ?? CancellationToken.None);
        }
    }

    private sealed class ResponseAdapter : ITypedSessionHandshakeResponseAdapter
    {
        public string AdapterId => "synthetic-create-session-response";
        public string AdapterType => "compiled-typed-response";

        public TypedSessionHandshakeAdapterOutcome ReadResponse(XmlReader reader, TypedSessionHandshakeResponseContext context)
        {
            RequireStart(reader, "CreateSessionResponse");
            reader.ReadStartElement("CreateSessionResponse", ProtocolNamespace);
            RequireStart(reader, "Result");
            reader.ReadStartElement("Result", ProtocolNamespace);
            string status = ReadSimple(reader, "Status");
            TypedSessionHandshakeAdapterOutcome outcome = status switch
            {
                "issued" => ReadIssued(reader),
                "external_admission_required" => ReadAdmission(reader),
                "rejected" => TypedSessionHandshakeAdapterOutcome.Rejected(TypedSessionHandshakeRejection.Rejected),
                _ => throw new XmlException("invalid status")
            };
            reader.ReadEndElement();
            reader.ReadEndElement();
            if (reader.Read() && reader.MoveToContent() != XmlNodeType.None) throw new XmlException("unexpected trailing content");
            return outcome;
        }

        private static TypedSessionHandshakeAdapterOutcome ReadIssued(XmlReader reader)
        {
            RequireStart(reader, "Session");
            reader.ReadStartElement("Session", ProtocolNamespace);
            string value = ReadSimple(reader, "Value");
            string expiry = ReadSimple(reader, "ExpiresAt");
            reader.ReadEndElement();
            return TypedSessionHandshakeAdapterOutcome.Issued(value, DateTimeOffset.ParseExact(expiry, "O", null));
        }

        private static TypedSessionHandshakeAdapterOutcome ReadAdmission(XmlReader reader)
        {
            RequireStart(reader, "Admission");
            reader.ReadStartElement("Admission", ProtocolNamespace);
            string provenance = ReadSimple(reader, "Provenance");
            reader.ReadEndElement();
            if (!string.Equals(provenance, "interactive_handoff", StringComparison.Ordinal)) throw new XmlException("invalid provenance");
            return TypedSessionHandshakeAdapterOutcome.ExternalAdmissionRequired(ExternalSessionProvenance.InteractiveHandoff);
        }

        private static string ReadSimple(XmlReader reader, string localName)
        {
            RequireStart(reader, localName);
            return reader.ReadElementContentAsString(localName, ProtocolNamespace);
        }

        private static void RequireStart(XmlReader reader, string localName)
        {
            if (reader.MoveToContent() != XmlNodeType.Element || !string.Equals(reader.LocalName, localName, StringComparison.Ordinal) ||
                !string.Equals(reader.NamespaceURI, ProtocolNamespace, StringComparison.Ordinal)) throw new XmlException("unexpected element");
            if (reader.HasAttributes)
            {
                while (reader.MoveToNextAttribute())
                    if (!string.Equals(reader.Prefix, "xmlns", StringComparison.Ordinal) && !string.Equals(reader.Name, "xmlns", StringComparison.Ordinal))
                        throw new XmlException("unexpected attribute");
                reader.MoveToElement();
            }
        }
    }

    private sealed class CapturingValidator(Func<ExternalSessionValidationResponseContext, ExternalSessionValidationResult> behavior)
        : ITypedExternalSessionValidationAdapter
    {
        public string AdapterId => "synthetic-session-validator";
        public string AdapterType => "compiled-typed-validator";
        internal List<string> Candidates { get; } = [];

        public void WriteValidationRequest(XmlWriter writer, ExternalSessionValidationRequestContext context)
        {
            string candidate = Encoding.UTF8.GetString(context.SensitiveCandidate.Span);
            Candidates.Add(candidate);
            writer.WriteStartElement("s", "Candidate", ProtocolNamespace);
            writer.WriteElementString("s", "Provenance", ProtocolNamespace, "interactive_handoff");
            writer.WriteElementString("s", "OpaqueValue", ProtocolNamespace, candidate);
            writer.WriteEndElement();
        }

        public ExternalSessionValidationResult ReadValidationResponse(XmlReader payload, ExternalSessionValidationResponseContext context)
        {
            payload.ReadStartElement("ValidateSessionResponse", ProtocolNamespace);
            payload.ReadStartElement("Validation", ProtocolNamespace);
            string status = payload.ReadElementContentAsString("Status", ProtocolNamespace);
            payload.ReadEndElement();
            payload.ReadEndElement();
            if (!string.Equals(status, "valid", StringComparison.Ordinal)) throw new XmlException();
            return behavior(context);
        }

        internal static CapturingValidator Valid() => new(_ => ExternalSessionValidationResult.Valid(At("2026-08-09T12:10:00Z")));

        public override string ToString() => "CapturingValidator(Redacted=True)";
    }

    private sealed class TypedTransport(HandshakeResponse response) : IRestrictedTransport
    {
        internal List<string> RequestBodies { get; } = [];
        internal List<string> SoapActions { get; } = [];

        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses,
            System.Security.Cryptography.X509Certificates.X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken) =>
            SendSoapAsync(request, approvedAddresses, timeout, maximumResponseBytes, cancellationToken);

        public async Task<ExternalResponse> SendSoapAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses,
            TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            string body = await request.Content!.ReadAsStringAsync(cancellationToken);
            RequestBodies.Add(body);
            SoapActions.Add(request.Headers.TryGetValues("SOAPAction", out IEnumerable<string>? values) ? values.Single().Trim('"') : string.Empty);
            if (body.Contains("BusinessRequest", StringComparison.Ordinal))
                return XmlResponse($"<s:BusinessResponse xmlns:s=\"{ProtocolNamespace}\"><s:Result>accepted</s:Result></s:BusinessResponse>");
            if (body.Contains("ValidateSessionRequest", StringComparison.Ordinal))
                return XmlResponse($"<s:ValidateSessionResponse xmlns:s=\"{ProtocolNamespace}\"><s:Validation><s:Status>valid</s:Status></s:Validation></s:ValidateSessionResponse>");
            return new(200, "text/xml; charset=utf-8", Encoding.UTF8.GetBytes(response.Xml));
        }
    }

    private sealed record HandshakeResponse(string Xml)
    {
        internal static HandshakeResponse Issued(string session, DateTimeOffset? fixtureTime) => Payload(
            $"<s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"><s:Result><s:Status>issued</s:Status><s:Session><s:Value>{session}</s:Value><s:ExpiresAt>{(fixtureTime ?? At("2026-08-09T12:30:00Z")):O}</s:ExpiresAt></s:Session></s:Result></s:CreateSessionResponse>");

        internal static HandshakeResponse ExternalAdmissionRequired() => Payload(
            $"<s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"><s:Result><s:Status>external_admission_required</s:Status><s:Admission><s:Provenance>interactive_handoff</s:Provenance></s:Admission></s:Result></s:CreateSessionResponse>");

        internal static HandshakeResponse OversizedIndividualValue(string kind) => IndividualValue(kind, 16_385);

        internal static HandshakeResponse IndividualValue(string kind, int length)
        {
            string value = new('x', length);
            string result = kind switch
            {
                "text" => $"<s:Result>{value}</s:Result>",
                "cdata" => $"<s:Result><![CDATA[{value}]]></s:Result>",
                "attribute" => $"<s:Result a=\"{value}\"/>",
                _ => throw new ArgumentOutOfRangeException(nameof(kind))
            };
            return Payload($"<s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\">{result}</s:CreateSessionResponse>");
        }

        internal static HandshakeResponse AggregateOversizedValues()
        {
            string value = new('x', 12_000);
            return Payload($"<s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"><s:A>{value}</s:A><s:B>{value}</s:B><s:C>{value}</s:C></s:CreateSessionResponse>");
        }

        internal static HandshakeResponse Malformed(string mutation) => mutation switch
        {
            "duplicate" => Payload($"<s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"><s:Result><s:Status>rejected</s:Status><s:Status>rejected</s:Status></s:Result></s:CreateSessionResponse>"),
            "wrong-order" => Payload($"<s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"><s:Result><s:Session/><s:Status>issued</s:Status></s:Result></s:CreateSessionResponse>"),
            "unexpected" => Payload($"<s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"><s:Result><s:Status>rejected</s:Status><s:Unexpected/></s:Result></s:CreateSessionResponse>"),
            "mixed" => Payload($"<s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"><s:Result>mixed<s:Status>rejected</s:Status></s:Result></s:CreateSessionResponse>"),
            "nested-invalid" => Payload($"<s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"><s:Result><s:Status><s:Nested/></s:Status></s:Result></s:CreateSessionResponse>"),
            _ => Payload($"<s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"><s:Result><s:Status>unknown-domain</s:Status></s:Result></s:CreateSessionResponse>")
        };

        internal static HandshakeResponse MalformedOuter(string mutation) => mutation switch
        {
            "dtd" => new($"<!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM \"file:///forbidden\">]><soap:Envelope xmlns:soap=\"{Soap11Namespace}\"><soap:Body><s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"><s:Result><s:Status>rejected</s:Status></s:Result></s:CreateSessionResponse></soap:Body></soap:Envelope>"),
            "wrong-qname" => new(Envelope($"<s:WrongResponse xmlns:s=\"{ProtocolNamespace}\"/>")),
            "two-payloads" => new(Envelope($"<s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"/><s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"/>")),
            _ => new($"<soap:Envelope xmlns:soap=\"{Soap11Namespace}\"><soap:Body injected=\"true\"><s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"/></soap:Body></soap:Envelope>")
        };

        private static HandshakeResponse Payload(string payload) => new(Envelope(payload));
    }

    private sealed class MutableSnapshotSource(PublishedConnectorSnapshot snapshot)
    {
        internal PublishedConnectorSnapshot Snapshot { get; private set; } = snapshot;

        internal Task<PublishedConnectorSnapshot?> ResolveAsync(string connectorId, Guid environmentId, PublishedConnectorAccessContext access, CancellationToken cancellationToken) =>
            Task.FromResult<PublishedConnectorSnapshot?>(Snapshot);

        internal void Rotate() => Snapshot = Snapshot with { Stamp = Snapshot.Stamp with { ResourceStampSha256 = "resource-stamp-rotated" } };
        internal void Disable() => Snapshot = Snapshot with { Bindings = Snapshot.Bindings with { State = ConnectorBindingState.Retired } };
    }

    private sealed class MutableClock : IGatewayClock
    {
        public DateTimeOffset UtcNow { get; set; } = At("2026-08-09T12:00:00Z");
    }

    private sealed class FixedResolver : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { IPAddress.Parse("8.8.8.8") });
    }

    private sealed class FixedSecrets : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) =>
            Task.FromResult(logicalReference.Contains("user", StringComparison.Ordinal) ? "synthetic-user" : "synthetic-password");
    }

    private sealed class MatchingStampProvider : ISoapSessionResourceStampProvider
    {
        public Task<SoapSessionResourceStamp?> GetCurrentAsync(ConnectorAuthExecutionContext context, CancellationToken cancellationToken) =>
            Task.FromResult<SoapSessionResourceStamp?>(new(context.CredentialRevision, SoapCredentialResourceStatus.Active, context.BindingRevision, context.EndpointRevision));
    }

    private static ExternalResponse XmlResponse(string payload) => new(200, "text/xml; charset=utf-8", Encoding.UTF8.GetBytes(Envelope(payload)));
    private static string Envelope(string payload) => $"<soap:Envelope xmlns:soap=\"{Soap11Namespace}\"><soap:Body>{payload}</soap:Body></soap:Envelope>";
}

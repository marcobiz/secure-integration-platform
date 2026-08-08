using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class SoapAuthenticationTests
{
    private const string OperationNamespace = "urn:synthetic:session";
    private const string FaultNamespace = "urn:synthetic:fault";
    private static readonly Uri EndpointUri = new("https://soap.vendor.example/service");

    [Fact]
    public async Task M6_UT_Basic_is_resolved_only_at_use_applied_once_and_redacted()
    {
        RecordingSecrets secrets = new("synthetic-user-canary", "synthetic-password-canary");
        ServerBoundBasicAuthentication basic = new(secrets);
        ResolvedBasicCredentialBinding binding = new("provider/user-sensitive", "provider/password-sensitive");
        using HttpRequestMessage request = new(HttpMethod.Post, EndpointUri);

        Assert.Equal(0, secrets.Calls);
        await basic.ApplyAsync(request, binding, TestContext.Current.CancellationToken);
        Assert.Equal(2, secrets.Calls);
        Assert.Equal("Basic", request.Headers.Authorization?.Scheme);
        Assert.Equal(Convert.ToBase64String(Encoding.UTF8.GetBytes("synthetic-user-canary:synthetic-password-canary")), request.Headers.Authorization?.Parameter);
        Assert.DoesNotContain("provider/", binding.ToString(), StringComparison.Ordinal);

        SoapAuthException duplicate = await Assert.ThrowsAsync<SoapAuthException>(() => basic.ApplyAsync(request, binding, TestContext.Current.CancellationToken));
        Assert.Equal("BASIC-AUTHORIZATION-ALREADY-PRESENT", duplicate.Code);
        Assert.DoesNotContain("canary", duplicate.ToString(), StringComparison.OrdinalIgnoreCase);

        RecordingSecrets failing = new(new InvalidOperationException("provider leaked synthetic-password-canary"));
        SoapAuthException unavailable = await Assert.ThrowsAsync<SoapAuthException>(() => new ServerBoundBasicAuthentication(failing).ApplyAsync(new HttpRequestMessage(HttpMethod.Post, EndpointUri), binding, TestContext.Current.CancellationToken));
        Assert.Equal("BASIC-CREDENTIAL-UNAVAILABLE", unavailable.Code);
        Assert.DoesNotContain("canary", unavailable.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(SoapEnvelopeVersion.Soap11, "text/xml", true)]
    [InlineData(SoapEnvelopeVersion.Soap12, "application/soap+xml", false)]
    public void M6_UT_SOAP_11_12_serialization_and_HTTP_policy_are_deterministic(SoapEnvelopeVersion version, string mediaType, bool soapActionHeader)
    {
        SoapOperationProfile operation = BusinessOperation(version);
        Dictionary<string, string> values = new(StringComparer.Ordinal) { ["payload"] = "<sensitive>&value" };
        byte[] first = SoapXmlBoundary.SerializeRequest(operation, values, new SoapElementRule("Session", OperationNamespace), "opaque-upstream-session");
        byte[] second = SoapXmlBoundary.SerializeRequest(operation, values, new SoapElementRule("Session", OperationNamespace), "opaque-upstream-session");
        Assert.Equal(first, second);
        string xml = Encoding.UTF8.GetString(first);
        Assert.Contains("&lt;sensitive&gt;&amp;value", xml, StringComparison.Ordinal);
        Assert.DoesNotContain("<?xml", xml, StringComparison.Ordinal);

        using HttpRequestMessage request = new(HttpMethod.Post, EndpointUri);
        SoapXmlBoundary.ApplyHttpHeaders(request, operation, first);
        Assert.Equal(mediaType, request.Content?.Headers.ContentType?.MediaType);
        Assert.Equal(soapActionHeader, request.Headers.Contains("SOAPAction"));
        if (soapActionHeader) Assert.Equal('"' + operation.Action + '"', request.Headers.GetValues("SOAPAction").Single());
        else Assert.Contains("action=", request.Content?.Headers.ContentType?.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void M6_SEC_XML_boundary_rejects_DTD_XXE_external_entity_complexity_malformed_oversize_namespace_and_content_type()
    {
        SoapOperationProfile operation = BusinessOperation(SoapEnvelopeVersion.Soap11, maximumResponseBytes: 512);
        string validPayload = $"<op:BusinessOperationResponse xmlns:op=\"{OperationNamespace}\"><op:Result>accepted</op:Result></op:BusinessOperationResponse>";
        SoapDecodedResponse valid = SoapXmlBoundary.ParseResponse(operation, Response(SoapEnvelopeVersion.Soap11, Envelope(SoapEnvelopeVersion.Soap11, validPayload)), null, null, new Dictionary<(string, string), SoapFaultCategory>(), TestContext.Current.CancellationToken);
        Assert.Equal("accepted", valid.Values["result"]);

        AssertCode("SOAP-XML-MALFORMED", () => SoapXmlBoundary.ParseResponse(operation,
            Response(SoapEnvelopeVersion.Soap11, $"<!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM \"file:///sensitive\">]><soap:Envelope xmlns:soap=\"{EnvelopeNamespace(SoapEnvelopeVersion.Soap11)}\"><soap:Body>&xxe;</soap:Body></soap:Envelope>"), null, null, new Dictionary<(string, string), SoapFaultCategory>(), TestContext.Current.CancellationToken));
        AssertCode("SOAP-XML-MALFORMED", () => SoapXmlBoundary.ParseResponse(operation,
            Response(SoapEnvelopeVersion.Soap11, $"<soap:Envelope xmlns:soap=\"{EnvelopeNamespace(SoapEnvelopeVersion.Soap11)}\"><soap:Body><broken></soap:Body></soap:Envelope>"), null, null, new Dictionary<(string, string), SoapFaultCategory>(), TestContext.Current.CancellationToken));
        AssertCode("SOAP-RESPONSE-TOO-LARGE", () => SoapXmlBoundary.ParseResponse(operation,
            Response(SoapEnvelopeVersion.Soap11, new string('x', 513)), null, null, new Dictionary<(string, string), SoapFaultCategory>(), TestContext.Current.CancellationToken));
        AssertCode("SOAP-RESPONSE-NAMESPACE", () => SoapXmlBoundary.ParseResponse(operation,
            Response(SoapEnvelopeVersion.Soap11, Envelope(SoapEnvelopeVersion.Soap11, "<op:BusinessOperationResponse xmlns:op=\"urn:attacker\"><op:Result>accepted</op:Result></op:BusinessOperationResponse>")), null, null, new Dictionary<(string, string), SoapFaultCategory>(), TestContext.Current.CancellationToken));
        AssertCode("SOAP-CONTENT-TYPE", () => SoapXmlBoundary.ParseResponse(operation,
            Response(SoapEnvelopeVersion.Soap11, Envelope(SoapEnvelopeVersion.Soap11, validPayload), contentType: "application/json"), null, null, new Dictionary<(string, string), SoapFaultCategory>(), TestContext.Current.CancellationToken));

        string deep = string.Concat(Enumerable.Repeat("<x>", 40)) + "value" + string.Concat(Enumerable.Repeat("</x>", 40));
        AssertCode("SOAP-XML-COMPLEXITY", () => SoapXmlBoundary.ParseResponse(BusinessOperation(SoapEnvelopeVersion.Soap11, maximumResponseBytes: 4096),
            Response(SoapEnvelopeVersion.Soap11, Envelope(SoapEnvelopeVersion.Soap11, deep)), null, null, new Dictionary<(string, string), SoapFaultCategory>(), TestContext.Current.CancellationToken));
        string attributes = string.Join(' ', Enumerable.Range(0, 33).Select(index => $"a{index}=\"x\""));
        AssertCode("SOAP-XML-COMPLEXITY", () => SoapXmlBoundary.ParseResponse(BusinessOperation(SoapEnvelopeVersion.Soap11, maximumResponseBytes: 4096),
            Response(SoapEnvelopeVersion.Soap11, Envelope(SoapEnvelopeVersion.Soap11, $"<op:BusinessOperationResponse xmlns:op=\"{OperationNamespace}\"><op:Result {attributes}>accepted</op:Result></op:BusinessOperationResponse>")), null, null, new Dictionary<(string, string), SoapFaultCategory>(), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M6_UT_Session_cache_expiry_rotation_disable_logout_and_controlled_reacquisition()
    {
        MutableClock clock = new();
        StatefulSoapTransport transport = new(SoapEnvelopeVersion.Soap11);
        SoapSessionClient client = Client(clock, transport);
        SoapSessionProfile profile = Profile(SoapEnvelopeVersion.Soap11, retryAfterReacquisition: true);
        ConnectorAuthExecutionContext context = Context(clock);
        SoapEndpointBinding endpoint = new(EndpointUri, 7);

        OpaqueSoapSessionReference first = await client.AcquireSessionAsync(context, endpoint, profile, TestContext.Current.CancellationToken);
        OpaqueSoapSessionReference cached = await client.AcquireSessionAsync(context, endpoint, profile, TestContext.Current.CancellationToken);
        Assert.Equal(first.Value, cached.Value);
        Assert.Equal(1, transport.LoginCount);
        Assert.NotEqual(transport.LastUpstreamSession, first.Value);

        transport.ExpireNextBusinessCall = true;
        SoapBusinessResult recovered = await client.InvokeAsync(context, endpoint, profile, new Dictionary<string, string> { ["payload"] = "request" }, first, TestContext.Current.CancellationToken);
        Assert.Equal("accepted", recovered.Values["result"]);
        Assert.Equal(2, transport.LoginCount);
        Assert.Equal(2, transport.BusinessCount);

        ConnectorAuthExecutionContext rotated = context with { CredentialRevision = 12, CorrelationId = Guid.NewGuid() };
        SoapAuthException stale = await Assert.ThrowsAsync<SoapAuthException>(() => client.InvokeAsync(rotated, endpoint, profile, new Dictionary<string, string> { ["payload"] = "request" }, first, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-SESSION-INVALID", stale.Code);

        OpaqueSoapSessionReference rotatedSession = await client.AcquireSessionAsync(rotated, endpoint, profile, TestContext.Current.CancellationToken);
        client.InvalidateSession(rotated, endpoint, profile, rotatedSession);
        SoapAuthException disabled = await Assert.ThrowsAsync<SoapAuthException>(() => client.InvokeAsync(rotated, endpoint, profile, new Dictionary<string, string> { ["payload"] = "request" }, rotatedSession, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-SESSION-INVALID", disabled.Code);

        OpaqueSoapSessionReference logoutSession = await client.AcquireSessionAsync(rotated, endpoint, profile, TestContext.Current.CancellationToken);
        await client.LogoutAsync(rotated, endpoint, profile, logoutSession, TestContext.Current.CancellationToken);
        Assert.Equal(1, transport.LogoutCount);
        SoapAuthException loggedOut = await Assert.ThrowsAsync<SoapAuthException>(() => client.InvokeAsync(rotated, endpoint, profile, new Dictionary<string, string> { ["payload"] = "request" }, logoutSession, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-SESSION-INVALID", loggedOut.Code);

        clock.UtcNow = clock.UtcNow.AddHours(17);
        ConnectorAuthExecutionContext renewedDeadline = rotated with { Deadline = clock.UtcNow.AddMinutes(2), CorrelationId = Guid.NewGuid() };
        _ = await client.AcquireSessionAsync(renewedDeadline, endpoint, profile, TestContext.Current.CancellationToken);
        Assert.True(transport.LoginCount >= 5);
    }

    [Fact]
    public async Task M6_REG_Session_cache_remains_shared_across_compatible_operations_without_reacquisition()
    {
        MutableClock clock = new();
        StatefulSoapTransport transport = new(SoapEnvelopeVersion.Soap11);
        SoapSessionClient client = Client(clock, transport);
        SoapSessionProfile profile = MultiOperationProfile(SoapEnvelopeVersion.Soap11);
        ConnectorAuthExecutionContext operationA = Context(clock);
        ConnectorAuthExecutionContext operationB = operationA with { OperationId = "business-b", CorrelationId = Guid.NewGuid() };
        SoapEndpointBinding endpoint = new(EndpointUri, 7);

        OpaqueSoapSessionReference acquiredByA = await client.AcquireSessionAsync(operationA, endpoint, profile, TestContext.Current.CancellationToken);
        OpaqueSoapSessionReference reusedByB = await client.AcquireSessionAsync(operationB, endpoint, profile, TestContext.Current.CancellationToken);
        SoapBusinessResult result = await client.InvokeAsync(operationB, endpoint, profile, new Dictionary<string, string> { ["payload"] = "request" }, reusedByB, TestContext.Current.CancellationToken);

        Assert.Equal(acquiredByA.Value, reusedByB.Value);
        Assert.Equal("accepted-b", result.Values["result"]);
        Assert.Equal(1, transport.LoginCount);
        Assert.Equal(1, transport.BusinessCount);
    }

    [Fact]
    public async Task M6_SEC_Interactive_challenge_is_opaque_single_use_cross_context_bound_and_fixation_safe()
    {
        MutableClock clock = new();
        StatefulSoapTransport transport = new(SoapEnvelopeVersion.Soap12) { RequireChallenge = true };
        SoapSessionClient client = Client(clock, transport);
        SoapSessionProfile profile = Profile(SoapEnvelopeVersion.Soap12, retryAfterReacquisition: true);
        ConnectorAuthExecutionContext context = Context(clock);
        SoapEndpointBinding endpoint = new(EndpointUri, 7);

        SoapInteractionRequiredException required = await Assert.ThrowsAsync<SoapInteractionRequiredException>(() => client.AcquireSessionAsync(context, endpoint, profile, TestContext.Current.CancellationToken));
        Assert.NotEqual(transport.LastUpstreamSession, required.Challenge.InteractionReference);
        Assert.DoesNotContain("session", required.Challenge.ToString(), StringComparison.OrdinalIgnoreCase);

        ConnectorAuthExecutionContext crossContext = context with { InstallationId = Guid.NewGuid(), CorrelationId = Guid.NewGuid() };
        SoapAuthException crossDenied = await Assert.ThrowsAsync<SoapAuthException>(() => client.CompleteInteractiveChallengeAsync(crossContext, endpoint, profile, required.Challenge.InteractionReference, "123456", TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-INTERACTION-INVALID", crossDenied.Code);

        OpaqueSoapSessionReference session = await client.CompleteInteractiveChallengeAsync(context, endpoint, profile, required.Challenge.InteractionReference, "123456", TestContext.Current.CancellationToken);
        Assert.NotEqual("upstream-session-1", session.Value);
        SoapAuthException replay = await Assert.ThrowsAsync<SoapAuthException>(() => client.CompleteInteractiveChallengeAsync(context, endpoint, profile, required.Challenge.InteractionReference, "123456", TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-INTERACTION-INVALID", replay.Code);
        SoapAuthException fixation = await Assert.ThrowsAsync<SoapAuthException>(() => client.InvokeAsync(context, endpoint, profile, new Dictionary<string, string> { ["payload"] = "request" }, new OpaqueSoapSessionReference("upstream-session-1"), TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-OPAQUE-REFERENCE-INVALID", fixation.Code);
    }

    [Theory]
    [InlineData(100)]
    [InlineData(1000)]
    public void M6_SEC_Pending_interactions_are_bounded_per_key_and_globally_with_lazy_expiry_eviction(int challengeCount)
    {
        DateTimeOffset now = new(2026, 8, 7, 12, 0, 0, TimeSpan.Zero);
        SoapSessionCache perKey = new();
        SoapSessionCacheKey oneKey = CacheKey();
        for (int index = 0; index < challengeCount; index++)
            _ = perKey.StoreInteraction(oneKey, "challenge-" + index, now, now.AddMinutes(5));
        Assert.Equal(1, perKey.EntryCount);
        Assert.Equal(1, perKey.PendingInteractionCount);

        SoapSessionCache global = new();
        int accepted = 0;
        int rejected = 0;
        for (int index = 0; index < challengeCount; index++)
        {
            try
            {
                _ = global.StoreInteraction(CacheKey(), "challenge-" + index, now, now.AddMinutes(1));
                accepted++;
            }
            catch (SoapAuthException exception)
            {
                Assert.Equal("SOAP-CACHE-CAPACITY", exception.Code);
                rejected++;
            }
        }
        Assert.Equal(Math.Min(challengeCount, SoapSessionCache.MaximumEntries), accepted);
        Assert.Equal(Math.Max(0, challengeCount - SoapSessionCache.MaximumEntries), rejected);
        Assert.InRange(global.EntryCount, 0, SoapSessionCache.MaximumEntries);
        Assert.Equal(global.EntryCount, global.PendingInteractionCount);

        _ = global.StoreInteraction(CacheKey(), "replacement", now.AddMinutes(2), now.AddMinutes(3));
        Assert.Equal(1, global.EntryCount);
        Assert.Equal(1, global.PendingInteractionCount);
    }

    [Fact]
    public async Task M6_SEC_Concurrent_completion_promotes_one_generation_and_denies_the_old_digest()
    {
        DateTimeOffset now = new(2026, 8, 7, 12, 0, 0, TimeSpan.Zero);
        SoapSessionCache cache = new();
        SoapSessionCacheKey key = CacheKey();
        OpaqueSoapSessionReference old = cache.Store(key, "upstream-old", now, now.AddHours(1));
        SoapInteractiveChallenge challenge = cache.StoreInteraction(key, "upstream-challenge", now, now.AddMinutes(5));
        TaskCompletionSource<bool> start = new(TaskCreationOptions.RunContinuationsAsynchronously);
        ConcurrentBag<InteractionCompletion> completions = [];
        ConcurrentBag<SoapAuthException> denials = [];

        Task[] attempts = Enumerable.Range(0, 2).Select(async _ =>
        {
            await start.Task;
            try { completions.Add(cache.BeginInteractionCompletion(key, challenge.InteractionReference, now)); }
            catch (SoapAuthException exception) { denials.Add(exception); }
        }).ToArray();
        start.SetResult(true);
        await Task.WhenAll(attempts);

        InteractionCompletion completion = Assert.Single(completions);
        Assert.Equal("SOAP-INTERACTION-INVALID", Assert.Single(denials).Code);
        OpaqueSoapSessionReference current = cache.CompleteInteraction(completion, "upstream-current", now, now.AddHours(1));
        Assert.Null(cache.Resolve(key, old, now));
        Assert.Equal("upstream-current", cache.Resolve(key, current, now));
        Assert.Equal(1, cache.CurrentSessionCount);
        Assert.Equal(0, cache.PendingInteractionCount);
    }

    [Fact]
    public async Task M6_SEC_Current_resource_stamp_denies_real_disable_rotate_binding_and_endpoint_changes_before_provider_or_transport_use()
    {
        MutableClock clock = new();
        RecordingSecrets secrets = new("synthetic-user", "synthetic-password");
        TrackingResolver resolver = new(IPAddress.Parse("8.8.8.8"));
        StatefulSoapTransport transport = new(SoapEnvelopeVersion.Soap11);
        MutableStampProvider stamps = new(new(11, SoapCredentialResourceStatus.Active, 5, 7));
        SoapSessionClient client = new(secrets, resolver, transport, clock, stamps);
        SoapSessionProfile profile = Profile(SoapEnvelopeVersion.Soap11, retryAfterReacquisition: true);
        ConnectorAuthExecutionContext context = Context(clock);
        SoapEndpointBinding endpoint = new(EndpointUri, 7);
        OpaqueSoapSessionReference session = await client.AcquireSessionAsync(context, endpoint, profile, TestContext.Current.CancellationToken);
        Assert.Equal(1, transport.LoginCount);
        Assert.Equal(2, secrets.Calls);

        stamps.Current = stamps.Current with { CredentialStatus = SoapCredentialResourceStatus.Disabled };
        SoapAuthException disabled = await Assert.ThrowsAsync<SoapAuthException>(() => client.InvokeAsync(context, endpoint, profile, new Dictionary<string, string> { ["payload"] = "request" }, session, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-CREDENTIAL-INACTIVE", disabled.Code);
        Assert.Equal(1, transport.LoginCount);
        Assert.Equal(0, transport.BusinessCount);
        Assert.Equal(2, secrets.Calls);

        stamps.Current = new(12, SoapCredentialResourceStatus.Active, 5, 7);
        SoapAuthException rotated = await Assert.ThrowsAsync<SoapAuthException>(() => client.InvokeAsync(context, endpoint, profile, new Dictionary<string, string> { ["payload"] = "request" }, session, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-RESOURCE-STAMP-STALE", rotated.Code);
        Assert.Equal(0, transport.BusinessCount);
        Assert.Equal(2, secrets.Calls);

        stamps.Current = stamps.Current with { CredentialResourceRevision = 11, BindingRevision = 6 };
        Assert.Equal("SOAP-RESOURCE-STAMP-STALE", (await Assert.ThrowsAsync<SoapAuthException>(() => client.InvokeAsync(context, endpoint, profile, new Dictionary<string, string> { ["payload"] = "request" }, session, TestContext.Current.CancellationToken))).Code);
        stamps.Current = stamps.Current with { BindingRevision = 5, EndpointRevision = 8 };
        Assert.Equal("SOAP-RESOURCE-STAMP-STALE", (await Assert.ThrowsAsync<SoapAuthException>(() => client.InvokeAsync(context, endpoint, profile, new Dictionary<string, string> { ["payload"] = "request" }, session, TestContext.Current.CancellationToken))).Code);
        Assert.Equal(0, transport.BusinessCount);
        Assert.Equal(2, secrets.Calls);

        ConnectorAuthExecutionContext revisionTwo = context with { CredentialRevision = 12, CorrelationId = Guid.NewGuid() };
        stamps.Current = new(12, SoapCredentialResourceStatus.Active, 5, 7);
        SoapAuthException oldGeneration = await Assert.ThrowsAsync<SoapAuthException>(() => client.InvokeAsync(revisionTwo, endpoint, profile, new Dictionary<string, string> { ["payload"] = "request" }, session, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-SESSION-INVALID", oldGeneration.Code);
        Assert.Equal(0, transport.BusinessCount);
    }

    [Theory]
    [InlineData(SoapEnvelopeVersion.Soap11)]
    [InlineData(SoapEnvelopeVersion.Soap12)]
    public void M6_SEC_Ambiguous_duplicate_mixed_and_unexpected_SOAP_Fault_structures_are_sanitized_and_never_classified_for_relogin(SoapEnvelopeVersion version)
    {
        SoapOperationProfile operation = BusinessOperation(version, maximumResponseBytes: 16_384);
        string soapNamespace = EnvelopeNamespace(version);
        string validBusiness = $"<op:BusinessOperationResponse xmlns:op=\"{OperationNamespace}\"><op:Result>accepted</op:Result></op:BusinessOperationResponse>";
        string[] ambiguousFaults = version == SoapEnvelopeVersion.Soap11
            ?
            [
                $"<soap:Fault xmlns:soap=\"{soapNamespace}\" xmlns:f=\"{FaultNamespace}\"><faultcode>f:SessionExpired</faultcode><faultcode>f:SessionExpired</faultcode><faultstring>x</faultstring></soap:Fault>",
                $"<soap:Fault xmlns:soap=\"{soapNamespace}\" xmlns:f=\"{FaultNamespace}\"><faultcode>f:SessionExpired</faultcode><faultstring>x</faultstring><soap:Code><soap:Value>f:SessionExpired</soap:Value></soap:Code></soap:Fault>",
                $"<soap:Fault xmlns:soap=\"{soapNamespace}\" xmlns:f=\"{FaultNamespace}\"><evil:faultcode xmlns:evil=\"urn:attacker\">f:SessionExpired</evil:faultcode><faultstring>x</faultstring></soap:Fault>"
            ]
            :
            [
                $"<soap:Fault xmlns:soap=\"{soapNamespace}\" xmlns:f=\"{FaultNamespace}\"><soap:Code><soap:Value>f:SessionExpired</soap:Value></soap:Code><soap:Code><soap:Value>f:SessionExpired</soap:Value></soap:Code><soap:Reason><soap:Text xml:lang=\"en\">x</soap:Text></soap:Reason></soap:Fault>",
                $"<soap:Fault xmlns:soap=\"{soapNamespace}\" xmlns:f=\"{FaultNamespace}\"><soap:Code><soap:Value>f:SessionExpired</soap:Value><soap:Value>f:SessionExpired</soap:Value></soap:Code><soap:Reason><soap:Text xml:lang=\"en\">x</soap:Text></soap:Reason></soap:Fault>",
                $"<soap:Fault xmlns:soap=\"{soapNamespace}\" xmlns:f=\"{FaultNamespace}\"><faultcode>f:SessionExpired</faultcode><soap:Reason><soap:Text xml:lang=\"en\">x</soap:Text></soap:Reason></soap:Fault>"
            ];
        IReadOnlyDictionary<(string, string), SoapFaultCategory> rules = new Dictionary<(string, string), SoapFaultCategory> { [("SessionExpired", FaultNamespace)] = SoapFaultCategory.SessionExpired };
        foreach (string fault in ambiguousFaults)
            AssertCode("SOAP-FAULT-STRUCTURE", () => SoapXmlBoundary.ParseResponse(operation, Response(version, Envelope(version, fault), 500), null, null, rules, TestContext.Current.CancellationToken));

        string duplicateBodies = $"<soap:Envelope xmlns:soap=\"{soapNamespace}\"><soap:Body>{validBusiness}</soap:Body><soap:Body>{validBusiness}</soap:Body></soap:Envelope>";
        AssertCode("SOAP-ENVELOPE-STRUCTURE", () => SoapXmlBoundary.ParseResponse(operation, Response(version, duplicateBodies), null, null, rules, TestContext.Current.CancellationToken));
        string faultAndBusiness = Envelope(version, ambiguousFaults[0] + validBusiness);
        AssertCode("SOAP-BODY-STRUCTURE", () => SoapXmlBoundary.ParseResponse(operation, Response(version, faultAndBusiness, 500), null, null, rules, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task M6_SEC_Binding_mismatch_and_SSRF_fail_before_transport_and_caller_has_no_endpoint_override()
    {
        MutableClock clock = new();
        StatefulSoapTransport transport = new(SoapEnvelopeVersion.Soap11);
        TrackingResolver resolver = new(IPAddress.Loopback);
        SoapSessionClient client = new(new RecordingSecrets("user", "password"), resolver, transport, clock, new MatchingStampProvider());
        SoapSessionProfile profile = Profile(SoapEnvelopeVersion.Soap11, retryAfterReacquisition: true);
        SoapEndpointBinding endpoint = new(EndpointUri, 7);
        ConnectorAuthExecutionContext mismatched = Context(clock) with { EndpointRevision = 8 };

        SoapAuthException binding = await Assert.ThrowsAsync<SoapAuthException>(() => client.AcquireSessionAsync(mismatched, endpoint, profile, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-CONTEXT-BINDING-MISMATCH", binding.Code);
        Assert.Equal(0, resolver.Calls);
        Assert.Equal(0, transport.Calls);

        SoapAuthException ssrf = await Assert.ThrowsAsync<SoapAuthException>(() => client.AcquireSessionAsync(Context(clock), endpoint, profile, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-EGRESS-DESTINATION-DENIED", ssrf.Code);
        Assert.Equal(0, transport.Calls);
        Assert.DoesNotContain(typeof(SoapSessionClient).GetMethods(), method => method.GetParameters().Any(parameter => parameter.Name?.Contains("uri", StringComparison.OrdinalIgnoreCase) == true));
    }

    [Fact]
    public async Task M6_SEC_Timeout_and_cancellation_are_distinct_and_sanitized()
    {
        MutableClock clock = new();
        SoapSessionProfile profile = Profile(SoapEnvelopeVersion.Soap11, retryAfterReacquisition: true);
        ConnectorAuthExecutionContext context = Context(clock);
        SoapEndpointBinding endpoint = new(EndpointUri, 7);

        SoapSessionClient timeoutClient = Client(clock, new CancellationTransport(cancelFromCaller: false));
        SoapAuthException timeout = await Assert.ThrowsAsync<SoapAuthException>(() => timeoutClient.AcquireSessionAsync(context, endpoint, profile, TestContext.Current.CancellationToken));
        Assert.Equal("SOAP-TIMEOUT", timeout.Code);

        using CancellationTokenSource canceled = new();
        canceled.Cancel();
        SoapSessionClient cancellationClient = Client(clock, new CancellationTransport(cancelFromCaller: true));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancellationClient.AcquireSessionAsync(context, endpoint, profile, canceled.Token));
    }

    private static SoapSessionClient Client(MutableClock clock, IRestrictedTransport transport) =>
        new(new RecordingSecrets("synthetic-user", "synthetic-password"), new TrackingResolver(IPAddress.Parse("8.8.8.8")), transport, clock, new MatchingStampProvider());

    private static ConnectorAuthExecutionContext Context(MutableClock clock) => new(
        Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "synthetic-soap", "1.0.0", "business", 5, 7, 11, "basic-session", Guid.NewGuid(), clock.UtcNow.AddMinutes(2));

    private static SoapSessionCacheKey CacheKey() => new(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "synthetic-soap", "1.0.0", 5, 7, 11, "basic-session");

    private static SoapSessionProfile Profile(SoapEnvelopeVersion version, bool retryAfterReacquisition)
    {
        SoapElementRule session = new("SessionId", OperationNamespace);
        SoapElementRule challenge = new("Challenge", OperationNamespace);
        SoapOperationProfile login = new("login", version, "urn:synthetic:Login", new("Login", OperationNamespace), new("LoginResponse", OperationNamespace));
        SoapOperationProfile complete = new("complete", version, "urn:synthetic:CompleteChallenge", new("CompleteChallenge", OperationNamespace), new("CompleteChallengeResponse", OperationNamespace),
            [new("challengeState", new("Challenge", OperationNamespace), 128), new("artifact", new("Artifact", OperationNamespace), 16)]);
        SoapOperationProfile logout = new("logout", version, "urn:synthetic:Logout", new("Logout", OperationNamespace), new("LogoutResponse", OperationNamespace));
        return new SoapSessionProfile("basic-session", new("provider/user", "provider/password"), login, session, new("Session", OperationNamespace),
            [BusinessOperation(version, retryAfterReacquisition)], TimeSpan.FromHours(16),
            [new(new("SessionExpired", FaultNamespace), SoapFaultCategory.SessionExpired), new(new("InvalidSession", FaultNamespace), SoapFaultCategory.InvalidSession)],
            challenge, complete, "artifact", "challengeState", TimeSpan.FromMinutes(5), logout);
    }

    private static SoapSessionProfile MultiOperationProfile(SoapEnvelopeVersion version)
    {
        SoapSessionProfile original = Profile(version, retryAfterReacquisition: false);
        SoapOperationProfile operationB = new("business-b", version, "urn:synthetic:BusinessOperationB", new("BusinessOperationB", OperationNamespace), new("BusinessOperationBResponse", OperationNamespace),
            [new("payload", new("Payload", OperationNamespace), 4096)], [new("result", new("Result", OperationNamespace), 4096)]);
        return new(original.ProfileId, original.BasicCredential, original.LoginOperation, original.SessionElement, original.SessionHeaderElement,
            original.BusinessOperations.Values.Append(operationB), original.SessionLifetime, original.FaultRules.Select(value => new SoapFaultRule(new(value.Key.LocalName, value.Key.NamespaceUri), value.Value)),
            original.ChallengeElement, original.ChallengeCompletionOperation, original.ChallengeArtifactField, original.ChallengeStateField, original.InteractionLifetime, original.LogoutOperation);
    }

    private static SoapOperationProfile BusinessOperation(SoapEnvelopeVersion version, bool retryAfterReacquisition = false, long maximumResponseBytes = 1_048_576) =>
        new("business", version, "urn:synthetic:BusinessOperation", new("BusinessOperation", OperationNamespace), new("BusinessOperationResponse", OperationNamespace),
            [new("payload", new("Payload", OperationNamespace), 4096)], [new("result", new("Result", OperationNamespace), 4096)], maximumResponseBytes: maximumResponseBytes, retryAfterSessionReacquisition: retryAfterReacquisition);

    private static ExternalResponse Response(SoapEnvelopeVersion version, string body, int status = 200, string? contentType = null) =>
        new(status, contentType ?? (version == SoapEnvelopeVersion.Soap11 ? "text/xml; charset=utf-8" : "application/soap+xml; charset=utf-8"), Encoding.UTF8.GetBytes(body));

    private static string Envelope(SoapEnvelopeVersion version, string payload) =>
        $"<soap:Envelope xmlns:soap=\"{EnvelopeNamespace(version)}\"><soap:Body>{payload}</soap:Body></soap:Envelope>";

    private static string EnvelopeNamespace(SoapEnvelopeVersion version) => version == SoapEnvelopeVersion.Soap11
        ? "http://schemas.xmlsoap.org/soap/envelope/"
        : "http://www.w3.org/2003/05/soap-envelope";

    private static void AssertCode(string expected, Action action)
    {
        SoapAuthException exception = Assert.Throws<SoapAuthException>(action);
        Assert.Equal(expected, exception.Code);
    }

    private sealed class RecordingSecrets : ISecretValueProvider
    {
        private readonly string username;
        private readonly string password;
        private readonly Exception? exception;

        public RecordingSecrets(string username, string password) { this.username = username; this.password = password; }
        public RecordingSecrets(Exception exception) { username = string.Empty; password = string.Empty; this.exception = exception; }
        public int Calls { get; private set; }
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            if (exception is not null) throw exception;
            return Task.FromResult(logicalReference.Contains("user", StringComparison.Ordinal) ? username : password);
        }
    }

    private sealed class MutableClock : IGatewayClock
    {
        public DateTimeOffset UtcNow { get; set; } = new(2026, 8, 7, 12, 0, 0, TimeSpan.Zero);
    }

    private sealed class TrackingResolver(IPAddress address) : IHostResolver
    {
        public int Calls { get; private set; }
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) { Calls++; return Task.FromResult(new[] { address }); }
    }

    private sealed class MatchingStampProvider : ISoapSessionResourceStampProvider
    {
        public Task<SoapSessionResourceStamp?> GetCurrentAsync(ConnectorAuthExecutionContext context, CancellationToken cancellationToken) =>
            Task.FromResult<SoapSessionResourceStamp?>(new(context.CredentialRevision, SoapCredentialResourceStatus.Active, context.BindingRevision, context.EndpointRevision));
    }

    private sealed class MutableStampProvider(SoapSessionResourceStamp current) : ISoapSessionResourceStampProvider
    {
        public SoapSessionResourceStamp Current { get; set; } = current;
        public Task<SoapSessionResourceStamp?> GetCurrentAsync(ConnectorAuthExecutionContext context, CancellationToken cancellationToken) => Task.FromResult<SoapSessionResourceStamp?>(Current);
    }

    private sealed class StatefulSoapTransport(SoapEnvelopeVersion version) : IRestrictedTransport
    {
        public int Calls { get; private set; }
        public int LoginCount { get; private set; }
        public int ChallengeCount { get; private set; }
        public int BusinessCount { get; private set; }
        public int LogoutCount { get; private set; }
        public bool RequireChallenge { get; set; }
        public bool ExpireNextBusinessCall { get; set; }
        public string? LastUpstreamSession { get; private set; }

        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, System.Security.Cryptography.X509Certificates.X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken) =>
            SendSoapAsync(request, approvedAddresses, timeout, maximumResponseBytes, cancellationToken);

        public async Task<ExternalResponse> SendSoapAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            Calls++;
            string xml = await request.Content!.ReadAsStringAsync(cancellationToken);
            Assert.Equal("Basic", request.Headers.Authorization?.Scheme);
            if (xml.Contains("<op:Login", StringComparison.Ordinal))
            {
                LoginCount++;
                if (RequireChallenge)
                {
                    RequireChallenge = false;
                    return Response(version, Envelope(version, $"<op:LoginResponse xmlns:op=\"{OperationNamespace}\"><op:Challenge>challenge-{LoginCount}</op:Challenge></op:LoginResponse>"));
                }
                LastUpstreamSession = "upstream-session-" + LoginCount;
                return Response(version, Envelope(version, $"<op:LoginResponse xmlns:op=\"{OperationNamespace}\"><op:SessionId>{LastUpstreamSession}</op:SessionId></op:LoginResponse>"));
            }
            if (xml.Contains("<op:CompleteChallenge", StringComparison.Ordinal))
            {
                ChallengeCount++;
                LastUpstreamSession = "upstream-session-challenge";
                return Response(version, Envelope(version, $"<op:CompleteChallengeResponse xmlns:op=\"{OperationNamespace}\"><op:SessionId>{LastUpstreamSession}</op:SessionId></op:CompleteChallengeResponse>"));
            }
            if (xml.Contains("<op:BusinessOperationB", StringComparison.Ordinal))
            {
                BusinessCount++;
                return Response(version, Envelope(version, $"<op:BusinessOperationBResponse xmlns:op=\"{OperationNamespace}\"><op:Result>accepted-b</op:Result></op:BusinessOperationBResponse>"));
            }
            if (xml.Contains("<op:BusinessOperation", StringComparison.Ordinal))
            {
                BusinessCount++;
                if (ExpireNextBusinessCall)
                {
                    ExpireNextBusinessCall = false;
                    string fault = version == SoapEnvelopeVersion.Soap11
                        ? $"<soap:Fault xmlns:soap=\"{EnvelopeNamespace(version)}\" xmlns:f=\"{FaultNamespace}\"><faultcode>f:SessionExpired</faultcode><faultstring>redacted</faultstring></soap:Fault>"
                        : $"<soap:Fault xmlns:soap=\"{EnvelopeNamespace(version)}\" xmlns:f=\"{FaultNamespace}\"><soap:Code><soap:Value>f:SessionExpired</soap:Value></soap:Code><soap:Reason><soap:Text xml:lang=\"en\">redacted</soap:Text></soap:Reason></soap:Fault>";
                    return Response(version, Envelope(version, fault), 500);
                }
                return Response(version, Envelope(version, $"<op:BusinessOperationResponse xmlns:op=\"{OperationNamespace}\"><op:Result>accepted</op:Result></op:BusinessOperationResponse>"));
            }
            LogoutCount++;
            return Response(version, Envelope(version, $"<op:LogoutResponse xmlns:op=\"{OperationNamespace}\"/>"));
        }
    }

    private sealed class CancellationTransport(bool cancelFromCaller) : IRestrictedTransport
    {
        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, System.Security.Cryptography.X509Certificates.X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<ExternalResponse> SendSoapAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken) =>
            cancelFromCaller ? Task.FromCanceled<ExternalResponse>(cancellationToken) : Task.FromException<ExternalResponse>(new TaskCanceledException("synthetic upstream detail"));
    }
}

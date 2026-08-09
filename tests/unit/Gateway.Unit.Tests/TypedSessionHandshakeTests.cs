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
        CapturingValidator validator = new((_, _, _) => Task.FromResult(ExternalSessionValidationResult.Valid(At("2026-08-09T12:10:00Z"))));
        Fixture fixture = new(HandshakeResponse.ExternalAdmissionRequired(), validator);
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        TypedSessionHandshakeResult bootstrap = await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken);
        Assert.Equal(TypedSessionHandshakeResultKind.ExternalAdmissionRequired, bootstrap.Kind);
        Assert.Equal(ExternalSessionProvenance.InteractiveHandoff, bootstrap.AdmissionIntent!.Provenance);

        ExternalSessionCandidate candidate = ExternalSessionCandidate.FromPresentation(Encoding.UTF8.GetBytes("presented-session"));
        TypedSessionHandshakeResult admitted = await fixture.Client.CompleteExternalAdmissionAsync(
            resolved, bootstrap.AdmissionIntent, candidate, TestContext.Current.CancellationToken);

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
    public async Task Wave1_SEC_Admission_intent_wrong_reused_expired_and_wrong_profile_are_denied()
    {
        Fixture fixture = new(HandshakeResponse.ExternalAdmissionRequired(), CapturingValidator.Valid());
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        TypedSessionHandshakeResult first = await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken);
        ExternalSessionAdmissionIntent intent = first.AdmissionIntent!;

        ExternalSessionAdmissionIntent wrongReference = new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", intent.ProfileId, intent.Provenance, intent.ExpiresAt, intent.AuthorityFingerprint);
        await AssertCodeAsync("SOAP-ADMISSION-INTENT-INVALID", () => fixture.Client.CompleteExternalAdmissionAsync(resolved, wrongReference,
            ExternalSessionCandidate.FromPresentation("candidate"u8), TestContext.Current.CancellationToken));

        ExternalSessionAdmissionIntent wrongProfile = new(intent.Reference, "wrong-profile", intent.Provenance, intent.ExpiresAt, intent.AuthorityFingerprint);
        await AssertCodeAsync("SOAP-ADMISSION-INTENT-INVALID", () => fixture.Client.CompleteExternalAdmissionAsync(resolved, wrongProfile,
            ExternalSessionCandidate.FromPresentation("candidate"u8), TestContext.Current.CancellationToken));

        TypedSessionHandshakeResult admitted = await fixture.Client.CompleteExternalAdmissionAsync(resolved, intent,
            ExternalSessionCandidate.FromPresentation("candidate"u8), TestContext.Current.CancellationToken);
        Assert.Equal(TypedSessionHandshakeResultKind.Issued, admitted.Kind);
        await AssertCodeAsync("SOAP-ADMISSION-INTENT-INVALID", () => fixture.Client.CompleteExternalAdmissionAsync(resolved, intent,
            ExternalSessionCandidate.FromPresentation("candidate"u8), TestContext.Current.CancellationToken));

        Fixture expiryFixture = new(HandshakeResponse.ExternalAdmissionRequired(), CapturingValidator.Valid());
        ResolvedTypedSessionHandshake expiryResolved = await expiryFixture.ResolveAsync();
        ExternalSessionAdmissionIntent expiring = (await expiryFixture.Client.AcquireTypedSessionAsync(expiryResolved, TestContext.Current.CancellationToken)).AdmissionIntent!;
        expiryFixture.Clock.UtcNow = expiring.ExpiresAt.AddTicks(1);
        await AssertCodeAsync("SOAP-ADMISSION-INTENT-INVALID", () => expiryFixture.Client.CompleteExternalAdmissionAsync(expiryResolved, expiring,
            ExternalSessionCandidate.FromPresentation("candidate"u8), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Wave1_SEC_Admission_intent_is_bound_to_exact_tenant_application_installation_and_lifecycle_key()
    {
        Fixture fixture = new(HandshakeResponse.ExternalAdmissionRequired(), CapturingValidator.Valid());
        ResolvedTypedSessionHandshake original = await fixture.ResolveAsync();
        ExternalSessionAdmissionIntent intent = (await fixture.Client.AcquireTypedSessionAsync(original, TestContext.Current.CancellationToken)).AdmissionIntent!;

        foreach (PrincipalDimension dimension in Enum.GetValues<PrincipalDimension>().Where(value => value != PrincipalDimension.None))
        {
            ResolvedTypedSessionHandshake wrong = await fixture.ResolveAsync(dimension);
            await AssertCodeAsync("SOAP-ADMISSION-INTENT-INVALID", () => fixture.Client.CompleteExternalAdmissionAsync(wrong, intent,
                ExternalSessionCandidate.FromPresentation("candidate"u8), TestContext.Current.CancellationToken));
        }
    }

    [Theory]
    [InlineData(ExternalSessionValidationStatus.Rejected, "SOAP-ADMISSION-VALIDATION-REJECTED")]
    [InlineData(ExternalSessionValidationStatus.MalformedResponse, "SOAP-ADMISSION-VALIDATION-FAILED")]
    [InlineData(ExternalSessionValidationStatus.Unavailable, "SOAP-ADMISSION-VALIDATION-FAILED")]
    public async Task Wave1_SEC_Validator_nonvalid_outcomes_consume_intent_without_promotion(ExternalSessionValidationStatus status, string code)
    {
        CapturingValidator validator = new((_, _, _) => Task.FromResult(ExternalSessionValidationResult.Invalid(status)));
        Fixture fixture = new(HandshakeResponse.ExternalAdmissionRequired(), validator);
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        ExternalSessionAdmissionIntent intent = (await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken)).AdmissionIntent!;

        await AssertCodeAsync(code, () => fixture.Client.CompleteExternalAdmissionAsync(resolved, intent,
            ExternalSessionCandidate.FromPresentation("remote-canary"u8), TestContext.Current.CancellationToken));
        await AssertCodeAsync("SOAP-ADMISSION-INTENT-INVALID", () => fixture.Client.CompleteExternalAdmissionAsync(resolved, intent,
            ExternalSessionCandidate.FromPresentation("candidate"u8), TestContext.Current.CancellationToken));
        Assert.Single(validator.Candidates);
    }

    [Fact]
    public async Task Wave1_SEC_Remote_expiry_is_mandatory_future_and_capped_by_server_policy()
    {
        CapturingValidator expired = new((_, _, _) => Task.FromResult(ExternalSessionValidationResult.Valid(At("2026-08-09T11:59:59Z"))));
        Fixture invalidFixture = new(HandshakeResponse.ExternalAdmissionRequired(), expired);
        ResolvedTypedSessionHandshake invalidResolved = await invalidFixture.ResolveAsync();
        ExternalSessionAdmissionIntent invalidIntent = (await invalidFixture.Client.AcquireTypedSessionAsync(invalidResolved, TestContext.Current.CancellationToken)).AdmissionIntent!;
        await AssertCodeAsync("SOAP-ADMISSION-REMOTE-EXPIRY-INVALID", () => invalidFixture.Client.CompleteExternalAdmissionAsync(invalidResolved, invalidIntent,
            ExternalSessionCandidate.FromPresentation("candidate"u8), TestContext.Current.CancellationToken));

        CapturingValidator longRemote = new((_, _, _) => Task.FromResult(ExternalSessionValidationResult.Valid(At("2026-08-12T12:00:00Z"))));
        Fixture cappedFixture = new(HandshakeResponse.ExternalAdmissionRequired(), longRemote);
        ResolvedTypedSessionHandshake cappedResolved = await cappedFixture.ResolveAsync();
        ExternalSessionAdmissionIntent cappedIntent = (await cappedFixture.Client.AcquireTypedSessionAsync(cappedResolved, TestContext.Current.CancellationToken)).AdmissionIntent!;
        TypedSessionHandshakeResult result = await cappedFixture.Client.CompleteExternalAdmissionAsync(cappedResolved, cappedIntent,
            ExternalSessionCandidate.FromPresentation("candidate"u8), TestContext.Current.CancellationToken);
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

    [Fact]
    public async Task Wave1_SEC_Core_stops_typed_request_adapter_at_the_Published_byte_bound_before_transport()
    {
        Fixture fixture = new(HandshakeResponse.Issued("unused", null), requestAdapter: new OversizedRequestAdapter());
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        await AssertCodeAsync("SOAP-REQUEST-TOO-LARGE", () => fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken));
        Assert.Empty(fixture.Transport.RequestBodies);
    }

    [Fact]
    public async Task Wave1_SEC_Published_adapter_ID_and_type_mismatch_fail_before_transport()
    {
        Fixture fixture = new(HandshakeResponse.Issued("unused", null), requestAdapter: new MismatchedRequestAdapter());
        await AssertCodeAsync("SOAP-TYPED-ADAPTER-UNAVAILABLE", () => fixture.ResolveAsync());
        Assert.Empty(fixture.Transport.RequestBodies);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Wave1_SEC_Rotate_or_disable_during_remote_validation_prevents_promotion(bool disable)
    {
        Fixture? fixture = null;
        CapturingValidator validator = new((_, _, _) =>
        {
            if (disable) fixture!.Snapshots.Disable(); else fixture!.Snapshots.Rotate();
            return Task.FromResult(ExternalSessionValidationResult.Valid(At("2026-08-09T12:10:00Z")));
        });
        fixture = new(HandshakeResponse.ExternalAdmissionRequired(), validator);
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        ExternalSessionAdmissionIntent intent = (await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken)).AdmissionIntent!;

        SoapAuthException failure = await Assert.ThrowsAsync<SoapAuthException>(() => fixture.Client.CompleteExternalAdmissionAsync(resolved, intent,
            ExternalSessionCandidate.FromPresentation("candidate"u8), TestContext.Current.CancellationToken));
        Assert.True(failure.Code is "SOAP-TYPED-AUTHORITY-STALE" or "SOAP-TYPED-AUTHORITY-REJECTED");
        Assert.Single(fixture.Transport.RequestBodies);
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
        CapturingValidator validator = new((_, _, _) => throw new InvalidOperationException(canary));
        Fixture fixture = new(HandshakeResponse.ExternalAdmissionRequired(), validator);
        ResolvedTypedSessionHandshake resolved = await fixture.ResolveAsync();
        ExternalSessionAdmissionIntent intent = (await fixture.Client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken)).AdmissionIntent!;
        ExternalSessionCandidate candidate = ExternalSessionCandidate.FromPresentation(Encoding.UTF8.GetBytes(canary));

        SoapAuthException failure = await Assert.ThrowsAsync<SoapAuthException>(() => fixture.Client.CompleteExternalAdmissionAsync(
            resolved, intent, candidate, TestContext.Current.CancellationToken));
        string diagnostic = string.Join('\n', failure.ToString(), intent.ToString(), resolved.ToString(), validator.ToString(), JsonSerializer.Serialize(intent), JsonSerializer.Serialize(candidate));
        Assert.DoesNotContain(canary, diagnostic, StringComparison.Ordinal);
        Assert.DoesNotContain("<soap", diagnostic, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("SOAP-ADMISSION-VALIDATION-FAILED", failure.Code);
    }

    [Fact]
    public void Wave1_CT_Public_API_has_dedicated_candidate_boundary_and_keeps_legacy_scalar_path_optional()
    {
        Type client = typeof(SoapSessionClient);
        Assert.Contains(client.GetMethods(), method => method.Name == nameof(SoapSessionClient.AcquireSessionAsync));
        Assert.Contains(client.GetMethods(), method => method.Name == nameof(SoapSessionClient.AcquireTypedSessionAsync) &&
            method.GetParameters().Select(parameter => parameter.ParameterType).SequenceEqual([typeof(ResolvedTypedSessionHandshake), typeof(CancellationToken)]));
        Assert.Contains(client.GetMethods(), method => method.Name == nameof(SoapSessionClient.CompleteExternalAdmissionAsync) &&
            method.GetParameters().Any(parameter => parameter.ParameterType == typeof(ExternalSessionCandidate)));
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
                "intentLifetimeSeconds":60,
                "timeoutMs":5000,
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

        internal Fixture(HandshakeResponse response, CapturingValidator? validator = null, ITypedSessionHandshakeRequestAdapter? requestAdapter = null)
        {
            Clock = new();
            Transport = new(response);
            requestAdapter ??= new RequestAdapter();
            ResponseAdapter responseAdapter = new();
            validator ??= CapturingValidator.Valid();
            TypedSessionHandshakeAdapterRegistry registry = new([requestAdapter], [responseAdapter], [validator]);
            Snapshots = new(CreateSnapshot());
            authority = new(Snapshots.ResolveAsync, registry, Clock);
            Client = new(new FixedSecrets(), new FixedResolver(), Transport, Clock, new MatchingStampProvider());
        }

        internal MutableClock Clock { get; }
        internal TypedTransport Transport { get; }
        internal MutableSnapshotSource Snapshots { get; }
        internal SoapSessionClient Client { get; }

        internal async Task<ResolvedTypedSessionHandshake> ResolveAsync(PrincipalDimension changed = PrincipalDimension.None, int salt = 0)
        {
            Guid tenant = changed == PrincipalDimension.Tenant ? Guid.NewGuid() : Salt(tenantId, salt);
            Guid application = changed == PrincipalDimension.Application ? Guid.NewGuid() : applicationId;
            Guid installation = changed == PrincipalDimension.Installation ? Guid.NewGuid() : installationId;
            RegisteredInstallationIdentity identity = new(installation, tenant, application, environmentId, TenantStatus.Active, ApplicationStatus.Active,
                InstallationStatus.Active, Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], Clock.UtcNow.AddMinutes(-1), Clock.UtcNow.AddHours(1), "1.0.0", null);
            GatewayClientPrincipal principal = new(identity, Guid.NewGuid());
            AuthorizedGatewayInvocation invocation = new(principal, "synthetic-typed-session", "session-bootstrap");
            return await authority.ResolveAsync(invocation, new("typed-session"), TestContext.Current.CancellationToken);
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
                                intentLifetimeSeconds = 60,
                                timeoutMs = 5_000,
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

    private sealed class CapturingValidator(
        Func<ExternalSessionValidationContext, ExternalSessionCandidate, CancellationToken, Task<ExternalSessionValidationResult>> behavior)
        : IAuthorizedExternalSessionValidator
    {
        public string ValidatorId => "synthetic-session-validator";
        public string ValidatorType => "compiled-typed-validator";
        internal List<string> Candidates { get; } = [];

        public async Task<ExternalSessionValidationResult> ValidateAsync(ExternalSessionValidationContext context, ExternalSessionCandidate candidate, CancellationToken cancellationToken)
        {
            Candidates.Add(Encoding.UTF8.GetString(candidate.SensitiveValue.Span));
            return await behavior(context, candidate, cancellationToken);
        }

        internal static CapturingValidator Valid() => new((_, _, _) =>
            Task.FromResult(ExternalSessionValidationResult.Valid(At("2026-08-09T12:10:00Z"))));

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
            return new(200, "text/xml; charset=utf-8", Encoding.UTF8.GetBytes(response.Xml));
        }
    }

    private sealed record HandshakeResponse(string Xml)
    {
        internal static HandshakeResponse Issued(string session, DateTimeOffset? fixtureTime) => Payload(
            $"<s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"><s:Result><s:Status>issued</s:Status><s:Session><s:Value>{session}</s:Value><s:ExpiresAt>{(fixtureTime ?? At("2026-08-09T12:30:00Z")):O}</s:ExpiresAt></s:Session></s:Result></s:CreateSessionResponse>");

        internal static HandshakeResponse ExternalAdmissionRequired() => Payload(
            $"<s:CreateSessionResponse xmlns:s=\"{ProtocolNamespace}\"><s:Result><s:Status>external_admission_required</s:Status><s:Admission><s:Provenance>interactive_handoff</s:Provenance></s:Admission></s:Result></s:CreateSessionResponse>");

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

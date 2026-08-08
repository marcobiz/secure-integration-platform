using System.Reflection;
using System.Text.Json;
using SecureIntegration.ConnectorPacks.Healthcare.RegionalEPrescription;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.RegionalEPrescription.Tests;

public sealed class RegionalEPrescriptionFoundationTests
{
    [Fact]
    public void HC_W1_COMMON_model_contains_only_lookup_dispense_and_bounded_scalar_extensions()
    {
        Assert.Equal([RegionalEPrescriptionOperation.Lookup, RegionalEPrescriptionOperation.Dispense], Enum.GetValues<RegionalEPrescriptionOperation>());
        RegionalExtensionSet extensions = RegionalExtensionSet.Create(new Dictionary<string, string>
        {
            ["regional-sequence"] = "42",
            ["workflow-date"] = "2026-08-08"
        });

        Assert.Equal("42", extensions.Values["regional-sequence"]);
        Assert.Throws<ArgumentException>(() => RegionalExtensionSet.Create(
            Enumerable.Range(0, 33).ToDictionary(index => $"field-{index}", index => index.ToString(System.Globalization.CultureInfo.InvariantCulture))));
        Assert.Throws<ArgumentException>(() => RegionalExtensionSet.Create(new Dictionary<string, string> { ["bad name"] = "value" }));
        Assert.Equal("RX-17", new RegionalSafeCode("RX-17").Value);
        Assert.Throws<ArgumentException>(() => new RegionalSafeCode("raw response: value"));
    }

    [Fact]
    public void HC_W1_SEC_caller_contract_has_no_profile_region_endpoint_auth_or_credential_selector()
    {
        string[] prohibited = ["Profile", "Region", "Endpoint", "Auth", "Credential", "Secret", "Route", "Tenant"];
        Type[] requestTypes = [typeof(RegionalEPrescriptionCommand), typeof(PrescriptionLookupRequest), typeof(DispenseRequest)];
        foreach (Type type in requestTypes)
        {
            string[] propertyNames = type.GetProperties(BindingFlags.Instance | BindingFlags.Public).Select(property => property.Name).ToArray();
            Assert.DoesNotContain(propertyNames, name => prohibited.Any(word => name.Contains(word, StringComparison.OrdinalIgnoreCase)));
        }

        MethodInfo create = Assert.Single(typeof(RegionalExtensionSet).GetMethods(BindingFlags.Public | BindingFlags.Static), method => method.Name == nameof(RegionalExtensionSet.Create));
        Assert.DoesNotContain(create.GetParameters(), parameter => parameter.ParameterType.Name.Contains("Schema", StringComparison.OrdinalIgnoreCase) || typeof(IEnumerable<RegionalExtensionField>).IsAssignableFrom(parameter.ParameterType));
    }

    [Fact]
    public async Task HC_W1_SEC_extension_schema_is_server_owned_and_revalidated_after_profile_resolution()
    {
        GatewayClientPrincipal principal = Principal(Guid.NewGuid(), Guid.NewGuid());
        RegionalEPrescriptionProfileBinding binding = ActiveBinding(principal, "profile-a", "endpoint-a", "auth-a", ["secret-a"], "stamp-a");
        InMemoryPublishedSource source = new(binding);
        RecordingDispatcher dispatcher = new();
        RegionalEPrescriptionRouter router = Router(source, dispatcher, Compiled("profile-a", "endpoint-a", "auth-a", ["secret-a"],
            [new("regional-sequence", RegionalExtensionValueKind.WholeNumber, Required: true, MaximumLength: 8)]));

        RegionalExtensionSet callerFields = RegionalExtensionSet.Create(new Dictionary<string, string> { ["undeclared"] = "value" });
        RegionalEPrescriptionException error = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            router.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", new PrescriptionLookupRequest(new("012345678901234"), callerFields), TestContext.Current.CancellationToken));

        Assert.Equal(RegionalEPrescriptionErrorCategory.Rejected, error.Category);
        Assert.Equal("PROFILE-EXTENSION-INVALID", error.SafeRegionalCode?.Value);
        Assert.Empty(dispatcher.Executions);
    }

    [Fact]
    public async Task HC_W1_SEC_real_Published_adapter_and_credential_independent_authorization_fail_closed()
    {
        GatewayClientPrincipal principal = Principal(Guid.NewGuid(), Guid.NewGuid());
        const string json = """
            {
              "schemaVersion":"1.0","connectorId":"healthcare-regional-rx","version":"1.0.0",
              "displayName":"Synthetic regional foundation","description":"No regional wire semantics.",
              "bindings":{"endpoints":[{"name":"regional-endpoint"}],"secrets":[]},
              "operations":[{
                "operationId":"prescription.lookup","endpointBinding":"regional-endpoint","method":"POST","path":"/synthetic",
                "request":{"contentType":"application/json","maximumBytes":1024},"response":{"maximumBytes":1024},
                "authentication":{"kind":"none"},"timeoutMs":1000,"redirectPolicy":"deny","allowedClientHeaders":[],
                "idempotent":false,"maximumRetries":0
              }]
            }
            """;
        using JsonDocument document = JsonDocument.Parse(json);
        string canonical = ConnectorCanonicalJson.Canonicalize(document.RootElement);
        Guid connectorId = Guid.NewGuid();
        Guid versionId = Guid.NewGuid();
        ConnectorVersionRecord version = new(versionId, connectorId, "healthcare-regional-rx", "1.0.0", "1.0", ConnectorVersionState.Published,
            canonical, Convert.FromHexString(ConnectorCanonicalJson.Checksum(canonical)), "synthetic-author", DateTimeOffset.UtcNow, 3, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
        ConnectorBindingSet bindings = new(Guid.NewGuid(), connectorId, versionId, principal.Identity.EnvironmentId,
            new Dictionary<string, Uri> { ["regional-endpoint"] = new("https://synthetic.invalid/") },
            new Dictionary<string, ProviderResourceBinding>(), new Dictionary<string, ProviderResourceBinding>(), 4, "binding-checksum", ConnectorBindingState.Active,
            DateTimeOffset.UtcNow, "synthetic-approver");
        PublishedConnectorSnapshot snapshot = new(version, bindings, new(versionId, 3, 4, "binding-checksum", "resource-stamp"),
            new Dictionary<string, string>(), new Dictionary<string, string>());
        PublishedConnectorAccessContext? observedAccess = null;
        int snapshotCalls = 0;
        PublishedConnectorRegionalEPrescriptionConfigurationSource source = new(
            (requestedConnector, environment, access, _) =>
            {
                Assert.Equal("healthcare-regional-rx", requestedConnector);
                Assert.Equal(principal.Identity.EnvironmentId, environment);
                observedAccess = access;
                snapshotCalls++;
                return Task.FromResult<PublishedConnectorSnapshot?>(snapshot);
            },
            new ConnectorDefinitionValidator());

        RegionalEPrescriptionProfileBinding resolved = await source.ResolveAsync(new(
            principal.TenantId, principal.ApplicationId, principal.InstallationId, principal.Identity.EnvironmentId,
            "healthcare-regional-rx", "prescription.lookup"), TestContext.Current.CancellationToken);

        Assert.NotNull(observedAccess);
        Assert.Equal(principal.InstallationId, observedAccess.InstallationId);
        Assert.Equal(principal.TenantId, observedAccess.TenantId);
        Assert.Equal(principal.ApplicationId, observedAccess.ApplicationId);
        Assert.Equal("regional-endpoint", resolved.EndpointBindingId);
        Assert.Empty(resolved.CredentialBindingIds);
        Assert.Equal(3, resolved.ProfileRevision);
        Assert.Equal(4, resolved.EndpointRevision);
        Assert.StartsWith("published-profile-sha256:", resolved.ProfileId, StringComparison.Ordinal);
        Assert.StartsWith("published-auth-sha256:", resolved.AuthPolicyReference, StringComparison.Ordinal);

        bool grantAllowed = true;
        TestClock clock = new() { UtcNow = DateTimeOffset.UtcNow };
        GatewayInvocationAuthorizer invocationAuthorizer = new(
            (installation, tenant, connector, operation, _, _) =>
            {
                bool exactAuthority = installation == principal.InstallationId && tenant == principal.TenantId &&
                    connector == "healthcare-regional-rx" && operation == "prescription.lookup";
                return Task.FromResult(grantAllowed && exactAuthority);
            },
            clock);
        RecordingDispatcher dispatcher = new();
        RegionalEPrescriptionRouter router = new(
            invocationAuthorizer,
            new PublishedRegionalEPrescriptionProfileResolver(source),
            new RegionalEPrescriptionCompiledProfileCatalog([new(resolved.ProfileId, resolved.OperationId, resolved.EndpointBindingId, resolved.AuthPolicyReference, [], [])]),
            dispatcher);
        await router.InvokeAsync(principal, "healthcare-regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken);
        Assert.Single(dispatcher.Executions);

        int authorizedSnapshotCalls = snapshotCalls;
        grantAllowed = false;
        await AssertAuthorizationDeniedAsync(router, principal);
        Assert.Equal(authorizedSnapshotCalls, snapshotCalls);

        grantAllowed = true;
        GatewayClientPrincipal wrongTenant = Principal(Guid.NewGuid(), principal.ApplicationId);
        await AssertAuthorizationDeniedAsync(router, wrongTenant);
        GatewayClientPrincipal suspended = new(principal.Identity with { InstallationStatus = InstallationStatus.Suspended }, principal.CorrelationId);
        await AssertAuthorizationDeniedAsync(router, suspended);
        Assert.Equal(authorizedSnapshotCalls, snapshotCalls);
    }

    [Fact]
    public async Task HC_W1_SEC_null_nested_command_and_response_values_fail_sanitized()
    {
        GatewayClientPrincipal principal = Principal(Guid.NewGuid(), Guid.NewGuid());
        InMemoryPublishedSource source = new(ActiveBinding(principal, "profile-a", "endpoint-a", "auth-a", [], "stamp-a"));
        RecordingDispatcher dispatcher = new();
        RegionalEPrescriptionRouter router = Router(source, dispatcher, Compiled("profile-a", "endpoint-a", "auth-a", []));

        RegionalEPrescriptionException commandError = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            router.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", new PrescriptionLookupRequest(null!, null!), TestContext.Current.CancellationToken));
        Assert.Equal("PROFILE-COMMAND-INVALID", commandError.SafeRegionalCode?.Value);
        Assert.Empty(dispatcher.Executions);

        RegionalEPrescriptionRouter responseRouter = Router(source, new NullNestedResponseDispatcher(), Compiled("profile-a", "endpoint-a", "auth-a", []));
        RegionalEPrescriptionException responseError = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            responseRouter.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal("PROFILE-RESPONSE-MISMATCH", responseError.SafeRegionalCode?.Value);
        Assert.Null(responseError.InnerException);
    }

    [Fact]
    public async Task HC_W1_SEC_profile_A_cannot_use_endpoint_auth_or_credential_B_and_lookup_authority_is_server_derived()
    {
        GatewayClientPrincipal principal = Principal(Guid.NewGuid(), Guid.NewGuid());
        RegionalEPrescriptionProfileBinding mixed = ActiveBinding(principal, "profile-a", "endpoint-b", "auth-b", ["secret-b"], "stamp-mixed");
        InMemoryPublishedSource source = new(mixed);
        RecordingDispatcher dispatcher = new();
        RegionalEPrescriptionRouter router = Router(source, dispatcher,
            Compiled("profile-a", "endpoint-a", "auth-a", ["secret-a"]),
            Compiled("profile-b", "endpoint-b", "auth-b", ["secret-b"]));

        RegionalEPrescriptionException substitution = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            router.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal("PROFILE-RESOURCE-SUBSTITUTION", substitution.SafeRegionalCode?.Value);
        Assert.Empty(dispatcher.Executions);
        Assert.NotNull(source.LastLookup);
        Assert.Equal(principal.TenantId, source.LastLookup.TenantId);
        Assert.Equal(principal.ApplicationId, source.LastLookup.ApplicationId);
        Assert.Equal(principal.InstallationId, source.LastLookup.InstallationId);

        source.Binding = ActiveBinding(principal, "profile-a", "endpoint-a", "auth-a", ["secret-a"], "stamp-a");
        await router.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken);
        RegionalEPrescriptionExecution execution = Assert.Single(dispatcher.Executions);
        Assert.Equal("endpoint-a", execution.Binding.EndpointBindingId);
        Assert.Equal("auth-a", execution.Binding.AuthPolicyReference);
        Assert.Equal(["secret-a"], execution.Binding.CredentialBindingIds);
    }

    [Fact]
    public async Task HC_W1_SEC_tenant_cannot_select_another_profile_and_authority_mismatch_denies_before_dispatch()
    {
        GatewayClientPrincipal principalA = Principal(Guid.NewGuid(), Guid.NewGuid());
        GatewayClientPrincipal principalB = Principal(Guid.NewGuid(), Guid.NewGuid());
        InMemoryPublishedSource source = new(ActiveBinding(principalB, "profile-b", "endpoint-b", "auth-b", ["secret-b"], "stamp-b"));
        RecordingDispatcher dispatcher = new();
        RegionalEPrescriptionRouter router = Router(source, dispatcher, Compiled("profile-b", "endpoint-b", "auth-b", ["secret-b"]));

        RegionalEPrescriptionException error = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            router.InvokeAsync(principalA, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));

        Assert.Equal("PROFILE-AUTHORITY-MISMATCH", error.SafeRegionalCode?.Value);
        Assert.Empty(dispatcher.Executions);
    }

    [Fact]
    public async Task HC_W1_SEC_rotation_disable_and_stale_complete_binding_stamp_fail_closed()
    {
        GatewayClientPrincipal principal = Principal(Guid.NewGuid(), Guid.NewGuid());
        RegionalEPrescriptionProfileBinding binding = ActiveBinding(principal, "profile-a", "endpoint-a", "auth-a", ["secret-a"], "stamp-1");
        InMemoryPublishedSource source = new(binding)
        {
            CurrentStamp = new("stamp-2", binding.BindingFingerprint)
        };
        RecordingDispatcher dispatcher = new();
        RegionalEPrescriptionRouter router = Router(source, dispatcher, Compiled("profile-a", "endpoint-a", "auth-a", ["secret-a"]));

        RegionalEPrescriptionException stale = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            router.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal("PROFILE-RESOURCE-STALE", stale.SafeRegionalCode?.Value);
        Assert.Empty(dispatcher.Executions);

        source.Binding = ActiveBinding(principal, "profile-a", "endpoint-a", "auth-a", ["secret-a"], "stamp-2", RegionalEPrescriptionProfileAvailability.Disabled);
        source.CurrentStamp = null;
        RegionalEPrescriptionException disabled = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            router.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal(RegionalEPrescriptionErrorCategory.ProfileUnavailable, disabled.Category);
        Assert.Empty(dispatcher.Executions);
    }

    [Fact]
    public void HC_W1_SEC_normalized_error_preserves_only_allowlisted_safe_code_and_redacts_reference()
    {
        PrescriptionReference reference = new("sensitive-synthetic-reference");
        RegionalEPrescriptionException error = new(RegionalEPrescriptionErrorCategory.Rejected, "RX-STATE-17");
        Assert.Equal("[PRESCRIPTION_REFERENCE]", reference.ToString());
        Assert.Equal("REGIONAL_EPRESCRIPTION_REJECTED", error.Message);
        Assert.Equal("RX-STATE-17", error.SafeRegionalCode?.Value);
        Assert.DoesNotContain("sensitive", error.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Throws<ArgumentException>(() => new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.Rejected, "raw response: token=synthetic"));
        Assert.Throws<ArgumentOutOfRangeException>(() => new RegionalEPrescriptionException((RegionalEPrescriptionErrorCategory)999));
    }

    [Fact]
    public async Task HC_W1_COMMON_dispense_uses_only_the_matching_published_operation()
    {
        GatewayClientPrincipal principal = Principal(Guid.NewGuid(), Guid.NewGuid());
        RegionalEPrescriptionProfileBinding binding = ActiveBinding(principal, "profile-a", "endpoint-a", "auth-a", ["secret-a"], "stamp-a", operationId: "prescription.dispense");
        InMemoryPublishedSource source = new(binding);
        RecordingDispatcher dispatcher = new();
        RegionalEPrescriptionRouter router = Router(source, dispatcher, Compiled("profile-a", "endpoint-a", "auth-a", ["secret-a"], operationId: "prescription.dispense"));

        RegionalEPrescriptionResponse response = await router.InvokeAsync(principal, "healthcare.regional-rx", "prescription.dispense", new DispenseRequest(new("012345678901234"), RegionalExtensionSet.Empty), TestContext.Current.CancellationToken);
        Assert.Equal("prescription.dispense", Assert.Single(dispatcher.Executions).Binding.OperationId);
        Assert.IsType<DispenseOutcome>(response);
    }

    [Fact]
    public async Task HC_W1_SEC_profile_response_type_or_reference_mismatch_is_denied()
    {
        GatewayClientPrincipal principal = Principal(Guid.NewGuid(), Guid.NewGuid());
        InMemoryPublishedSource source = new(ActiveBinding(principal, "profile-a", "endpoint-a", "auth-a", ["secret-a"], "stamp-a"));
        RegionalEPrescriptionRouter router = Router(source, new MismatchingDispatcher(), Compiled("profile-a", "endpoint-a", "auth-a", ["secret-a"]));

        RegionalEPrescriptionException error = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            router.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal("PROFILE-RESPONSE-MISMATCH", error.SafeRegionalCode?.Value);

        RegionalEPrescriptionRouter extensionRouter = Router(source, new InvalidExtensionResponseDispatcher(), Compiled("profile-a", "endpoint-a", "auth-a", ["secret-a"]));
        RegionalEPrescriptionException extensionError = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            extensionRouter.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal("PROFILE-RESPONSE-MISMATCH", extensionError.SafeRegionalCode?.Value);

        RegionalEPrescriptionRouter unsafeCodeRouter = Router(source, new SafeCodeResponseDispatcher("UPSTREAMTOKEN123"), Compiled("profile-a", "endpoint-a", "auth-a", ["secret-a"]));
        RegionalEPrescriptionException unsafeCode = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            unsafeCodeRouter.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal("PROFILE-RESPONSE-MISMATCH", unsafeCode.SafeRegionalCode?.Value);

        RegionalEPrescriptionRouter allowlistedCodeRouter = Router(source, new SafeCodeResponseDispatcher("RX-17"), Compiled("profile-a", "endpoint-a", "auth-a", ["secret-a"], safeRegionalCodes: ["RX-17"]));
        PrescriptionLookupResult allowlisted = Assert.IsType<PrescriptionLookupResult>(await allowlistedCodeRouter.InvokeAsync(
            principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal("RX-17", allowlisted.SafeRegionalCode?.Value);

        RegionalEPrescriptionRouter invalidEnumRouter = Router(source, new InvalidEnumResponseDispatcher(), Compiled("profile-a", "endpoint-a", "auth-a", ["secret-a"]));
        RegionalEPrescriptionException invalidEnum = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            invalidEnumRouter.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal("PROFILE-RESPONSE-MISMATCH", invalidEnum.SafeRegionalCode?.Value);

        InMemoryPublishedSource dispenseSource = new(ActiveBinding(principal, "profile-a", "endpoint-a", "auth-a", [], "stamp-d", operationId: "prescription.dispense"));
        RegionalEPrescriptionRouter invalidDispositionRouter = Router(dispenseSource, new InvalidEnumResponseDispatcher(), Compiled("profile-a", "endpoint-a", "auth-a", [], operationId: "prescription.dispense"));
        RegionalEPrescriptionException invalidDisposition = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            invalidDispositionRouter.InvokeAsync(principal, "healthcare.regional-rx", "prescription.dispense", new DispenseRequest(new("012345678901234"), RegionalExtensionSet.Empty), TestContext.Current.CancellationToken));
        Assert.Equal("PROFILE-RESPONSE-MISMATCH", invalidDisposition.SafeRegionalCode?.Value);
    }

    [Fact]
    public async Task HC_W1_SEC_unexpected_resolver_and_dispatcher_exceptions_are_redacted_without_inner_details()
    {
        const string canary = "raw-endpoint-token-payload-canary";
        GatewayClientPrincipal principal = Principal(Guid.NewGuid(), Guid.NewGuid());
        RegionalEPrescriptionRouter authorizationRouter = new(
            new ThrowingAuthorizer(canary),
            new PublishedRegionalEPrescriptionProfileResolver(new ThrowingSource(canary)),
            new RegionalEPrescriptionCompiledProfileCatalog([]),
            new RecordingDispatcher());
        RegionalEPrescriptionException authorization = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            authorizationRouter.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal("INVOCATION-AUTHORIZATION-FAILED", authorization.SafeRegionalCode?.Value);
        Assert.Null(authorization.InnerException);
        Assert.DoesNotContain(canary, authorization.ToString(), StringComparison.Ordinal);

        RegionalEPrescriptionRouter resolutionRouter = new(
            new AllowingAuthorizer(),
            new PublishedRegionalEPrescriptionProfileResolver(new ThrowingSource(canary)),
            new RegionalEPrescriptionCompiledProfileCatalog([]),
            new RecordingDispatcher());
        RegionalEPrescriptionException resolution = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            resolutionRouter.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal("PROFILE-RESOLUTION-FAILED", resolution.SafeRegionalCode?.Value);
        Assert.Null(resolution.InnerException);
        Assert.DoesNotContain(canary, resolution.ToString(), StringComparison.Ordinal);

        RegionalEPrescriptionProfileBinding stampBinding = ActiveBinding(principal, "profile-a", "endpoint-a", "auth-a", ["secret-a"], "stamp-a");
        RegionalEPrescriptionRouter stampRouter = new(
            new AllowingAuthorizer(),
            new PublishedRegionalEPrescriptionProfileResolver(new ThrowingStampSource(stampBinding, canary)),
            new RegionalEPrescriptionCompiledProfileCatalog([Compiled("profile-a", "endpoint-a", "auth-a", ["secret-a"])]),
            new RecordingDispatcher());
        RegionalEPrescriptionException stamp = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            stampRouter.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal("PROFILE-STAMP-FAILED", stamp.SafeRegionalCode?.Value);
        Assert.Null(stamp.InnerException);
        Assert.DoesNotContain(canary, stamp.ToString(), StringComparison.Ordinal);

        InMemoryPublishedSource source = new(ActiveBinding(principal, "profile-a", "endpoint-a", "auth-a", ["secret-a"], "stamp-a"));
        RegionalEPrescriptionRouter dispatchRouter = Router(source, new ThrowingDispatcher(canary), Compiled("profile-a", "endpoint-a", "auth-a", ["secret-a"]));
        RegionalEPrescriptionException dispatch = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            dispatchRouter.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal("PROFILE-DISPATCH-FAILED", dispatch.SafeRegionalCode?.Value);
        Assert.Null(dispatch.InnerException);
        Assert.DoesNotContain(canary, dispatch.ToString(), StringComparison.Ordinal);

        RegionalEPrescriptionRouter unsafeErrorRouter = Router(source, new RegionalErrorDispatcher("UPSTREAMTOKEN123"), Compiled("profile-a", "endpoint-a", "auth-a", ["secret-a"]));
        RegionalEPrescriptionException unsafeError = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            unsafeErrorRouter.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal(RegionalEPrescriptionErrorCategory.Rejected, unsafeError.Category);
        Assert.Null(unsafeError.SafeRegionalCode);

        RegionalEPrescriptionRouter allowlistedErrorRouter = Router(source, new RegionalErrorDispatcher("RX-17"), Compiled("profile-a", "endpoint-a", "auth-a", ["secret-a"], safeRegionalCodes: ["RX-17"]));
        RegionalEPrescriptionException allowlistedError = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            allowlistedErrorRouter.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal("RX-17", allowlistedError.SafeRegionalCode?.Value);
    }

    [Fact]
    public void HC_W1_SEC_binding_and_compiled_profile_snapshot_mutable_collections()
    {
        GatewayClientPrincipal principal = Principal(Guid.NewGuid(), Guid.NewGuid());
        List<string> bindingCredentials = ["secret-a"];
        List<string> compiledCredentials = ["secret-a"];
        List<RegionalExtensionField> schema = [new("sequence", RegionalExtensionValueKind.WholeNumber)];
        RegionalEPrescriptionProfileBinding binding = ActiveBinding(principal, "profile-a", "endpoint-a", "auth-a", bindingCredentials, "stamp-a");
        RegionalEPrescriptionCompiledProfile compiled = Compiled("profile-a", "endpoint-a", "auth-a", compiledCredentials, schema);
        string fingerprint = binding.BindingFingerprint;

        bindingCredentials[0] = "secret-b";
        compiledCredentials[0] = "secret-b";
        schema[0] = new("attacker", RegionalExtensionValueKind.Text);

        Assert.Equal(["secret-a"], binding.CredentialBindingIds);
        Assert.Equal(["secret-a"], compiled.CredentialBindingIds);
        Assert.Equal("sequence", Assert.Single(compiled.ExtensionSchema).Name);
        Assert.Equal(fingerprint, binding.BindingFingerprint);

        RegionalEPrescriptionProfileBinding delimiterA = ActiveBinding(principal, "profile-a", "endpoint\nauth", "policy", [], "stamp-a");
        RegionalEPrescriptionProfileBinding delimiterB = ActiveBinding(principal, "profile-a", "endpoint", "auth\npolicy", [], "stamp-a");
        Assert.NotEqual(delimiterA.BindingFingerprint, delimiterB.BindingFingerprint);

        RegionalEPrescriptionCompiledProfile collisionA = Compiled("profile\u001foperation", "endpoint-a", "auth-a", [], operationId: "tail");
        RegionalEPrescriptionCompiledProfile collisionB = Compiled("profile", "endpoint-b", "auth-b", [], operationId: "operation\u001ftail");
        RegionalEPrescriptionCompiledProfileCatalog collisionSafe = new([collisionA, collisionB]);
        Assert.Same(collisionA, collisionSafe.GetRequired(collisionA.ProfileId, collisionA.OperationId));
        Assert.Same(collisionB, collisionSafe.GetRequired(collisionB.ProfileId, collisionB.OperationId));
    }

    internal static GatewayClientPrincipal Principal(Guid tenantId, Guid applicationId) => new(
        new RegisteredInstallationIdentity(
            Guid.NewGuid(), tenantId, applicationId, Guid.NewGuid(), TenantStatus.Active, ApplicationStatus.Active,
            InstallationStatus.Active, Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddHours(1), "1.0.0", null, InstallationKind.Direct, "1.0.0"),
        Guid.NewGuid());

    internal static RegionalEPrescriptionProfileBinding ActiveBinding(
        GatewayClientPrincipal principal,
        string profileId,
        string endpointBindingId,
        string authPolicyReference,
        IEnumerable<string> credentialBindingIds,
        string stamp,
        RegionalEPrescriptionProfileAvailability availability = RegionalEPrescriptionProfileAvailability.Active,
        string operationId = "prescription.lookup",
        string? blockCode = null) => new(
            principal.TenantId, principal.ApplicationId, principal.InstallationId, principal.Identity.EnvironmentId,
            "healthcare.regional-rx", "1.0.0", operationId,
            profileId, availability, endpointBindingId, authPolicyReference, credentialBindingIds,
            1, 1, 1, stamp, blockCode);

    internal static RegionalEPrescriptionCompiledProfile Compiled(
        string profileId,
        string endpointBindingId,
        string authPolicyReference,
        IEnumerable<string> credentialBindingIds,
        IEnumerable<RegionalExtensionField>? schema = null,
        string operationId = "prescription.lookup",
        IEnumerable<string>? safeRegionalCodes = null) =>
        new(profileId, operationId, endpointBindingId, authPolicyReference, credentialBindingIds, schema ?? [], safeRegionalCodes);

    internal static RegionalEPrescriptionRouter Router(
        InMemoryPublishedSource source,
        IRegionalEPrescriptionProfileDispatcher dispatcher,
        params RegionalEPrescriptionCompiledProfile[] profiles) =>
        new(new AllowingAuthorizer(), new PublishedRegionalEPrescriptionProfileResolver(source), new RegionalEPrescriptionCompiledProfileCatalog(profiles), dispatcher);

    internal static PrescriptionLookupRequest Lookup() => new(new("012345678901234"), RegionalExtensionSet.Empty);

    private static async Task AssertAuthorizationDeniedAsync(RegionalEPrescriptionRouter router, GatewayClientPrincipal principal)
    {
        RegionalEPrescriptionException denied = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
            router.InvokeAsync(principal, "healthcare-regional-rx", "prescription.lookup", Lookup(), TestContext.Current.CancellationToken));
        Assert.Equal(RegionalEPrescriptionErrorCategory.Rejected, denied.Category);
        Assert.Equal("INVOCATION-NOT-AUTHORIZED", denied.SafeRegionalCode?.Value);
    }

    internal sealed class InMemoryPublishedSource(RegionalEPrescriptionProfileBinding binding) : IRegionalEPrescriptionPublishedConfigurationSource
    {
        public RegionalEPrescriptionProfileBinding Binding { get; set; } = binding;
        public RegionalEPrescriptionResourceStamp? CurrentStamp { get; set; }
        public RegionalEPrescriptionPublishedLookup? LastLookup { get; private set; }

        public Task<RegionalEPrescriptionProfileBinding> ResolveAsync(RegionalEPrescriptionPublishedLookup lookup, CancellationToken cancellationToken)
        {
            LastLookup = lookup;
            return Task.FromResult(Binding);
        }

        public Task<RegionalEPrescriptionResourceStamp> GetCurrentStampAsync(RegionalEPrescriptionProfileBinding current, CancellationToken cancellationToken) =>
            Task.FromResult(CurrentStamp ?? new RegionalEPrescriptionResourceStamp(current.ResourceStamp, current.BindingFingerprint));
    }

    internal sealed class RecordingDispatcher : IRegionalEPrescriptionProfileDispatcher
    {
        public List<RegionalEPrescriptionExecution> Executions { get; } = [];
        public Task<RegionalEPrescriptionResponse> DispatchAsync(RegionalEPrescriptionExecution execution, RegionalEPrescriptionCommand command, CancellationToken cancellationToken)
        {
            Executions.Add(execution);
            return Task.FromResult<RegionalEPrescriptionResponse>(command switch
            {
                PrescriptionLookupRequest => new PrescriptionLookupResult(command.Prescription, PrescriptionAvailability.Available, null, RegionalExtensionSet.Empty),
                DispenseRequest => new DispenseOutcome(command.Prescription, DispenseDisposition.Accepted, null, RegionalExtensionSet.Empty),
                _ => throw new InvalidOperationException("Unsupported synthetic command.")
            });
        }
    }

    internal sealed class AllowingAuthorizer : IGatewayInvocationAuthorizer
    {
        public Task<AuthorizedGatewayInvocation> AuthorizeAsync(GatewayClientPrincipal principal, string connectorId, string operationId, CancellationToken cancellationToken) =>
            Task.FromResult(new AuthorizedGatewayInvocation(principal, connectorId, operationId));
    }

    private sealed class MismatchingDispatcher : IRegionalEPrescriptionProfileDispatcher
    {
        public Task<RegionalEPrescriptionResponse> DispatchAsync(RegionalEPrescriptionExecution execution, RegionalEPrescriptionCommand command, CancellationToken cancellationToken) =>
            Task.FromResult<RegionalEPrescriptionResponse>(new DispenseOutcome(new("different-reference"), DispenseDisposition.Accepted, null, RegionalExtensionSet.Empty));
    }

    private sealed class InvalidExtensionResponseDispatcher : IRegionalEPrescriptionProfileDispatcher
    {
        public Task<RegionalEPrescriptionResponse> DispatchAsync(RegionalEPrescriptionExecution execution, RegionalEPrescriptionCommand command, CancellationToken cancellationToken) =>
            Task.FromResult<RegionalEPrescriptionResponse>(new PrescriptionLookupResult(
                command.Prescription,
                PrescriptionAvailability.Available,
                null,
                RegionalExtensionSet.Create(new Dictionary<string, string> { ["undeclared"] = "raw" })));
    }

    private sealed class InvalidEnumResponseDispatcher : IRegionalEPrescriptionProfileDispatcher
    {
        public Task<RegionalEPrescriptionResponse> DispatchAsync(RegionalEPrescriptionExecution execution, RegionalEPrescriptionCommand command, CancellationToken cancellationToken) =>
            Task.FromResult<RegionalEPrescriptionResponse>(command switch
            {
                PrescriptionLookupRequest => new PrescriptionLookupResult(command.Prescription, (PrescriptionAvailability)999, null, RegionalExtensionSet.Empty),
                DispenseRequest => new DispenseOutcome(command.Prescription, (DispenseDisposition)999, null, RegionalExtensionSet.Empty),
                _ => throw new InvalidOperationException("Unsupported synthetic command.")
            });
    }

    private sealed class NullNestedResponseDispatcher : IRegionalEPrescriptionProfileDispatcher
    {
        public Task<RegionalEPrescriptionResponse> DispatchAsync(RegionalEPrescriptionExecution execution, RegionalEPrescriptionCommand command, CancellationToken cancellationToken) =>
            Task.FromResult<RegionalEPrescriptionResponse>(new PrescriptionLookupResult(null!, PrescriptionAvailability.Available, null, null!));
    }

    private sealed class SafeCodeResponseDispatcher(string safeCode) : IRegionalEPrescriptionProfileDispatcher
    {
        public Task<RegionalEPrescriptionResponse> DispatchAsync(RegionalEPrescriptionExecution execution, RegionalEPrescriptionCommand command, CancellationToken cancellationToken) =>
            Task.FromResult<RegionalEPrescriptionResponse>(new PrescriptionLookupResult(
                command.Prescription,
                PrescriptionAvailability.Available,
                new RegionalSafeCode(safeCode),
                RegionalExtensionSet.Empty));
    }

    private sealed class ThrowingSource(string canary) : IRegionalEPrescriptionPublishedConfigurationSource
    {
        public Task<RegionalEPrescriptionProfileBinding> ResolveAsync(RegionalEPrescriptionPublishedLookup lookup, CancellationToken cancellationToken) =>
            throw new InvalidOperationException(canary, new InvalidDataException(canary));
        public Task<RegionalEPrescriptionResourceStamp> GetCurrentStampAsync(RegionalEPrescriptionProfileBinding binding, CancellationToken cancellationToken) =>
            throw new InvalidOperationException(canary);
    }

    private sealed class ThrowingStampSource(RegionalEPrescriptionProfileBinding binding, string canary) : IRegionalEPrescriptionPublishedConfigurationSource
    {
        public Task<RegionalEPrescriptionProfileBinding> ResolveAsync(RegionalEPrescriptionPublishedLookup lookup, CancellationToken cancellationToken) =>
            Task.FromResult(binding);
        public Task<RegionalEPrescriptionResourceStamp> GetCurrentStampAsync(RegionalEPrescriptionProfileBinding current, CancellationToken cancellationToken) =>
            throw new InvalidOperationException(canary, new InvalidDataException(canary));
    }

    private sealed class ThrowingDispatcher(string canary) : IRegionalEPrescriptionProfileDispatcher
    {
        public Task<RegionalEPrescriptionResponse> DispatchAsync(RegionalEPrescriptionExecution execution, RegionalEPrescriptionCommand command, CancellationToken cancellationToken) =>
            throw new InvalidOperationException(canary, new InvalidDataException(canary));
    }

    private sealed class RegionalErrorDispatcher(string safeCode) : IRegionalEPrescriptionProfileDispatcher
    {
        public Task<RegionalEPrescriptionResponse> DispatchAsync(RegionalEPrescriptionExecution execution, RegionalEPrescriptionCommand command, CancellationToken cancellationToken) =>
            throw new RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory.Rejected, safeCode);
    }

    private sealed class ThrowingAuthorizer(string canary) : IGatewayInvocationAuthorizer
    {
        public Task<AuthorizedGatewayInvocation> AuthorizeAsync(GatewayClientPrincipal principal, string connectorId, string operationId, CancellationToken cancellationToken) =>
            throw new InvalidOperationException(canary, new InvalidDataException(canary));
    }

    private sealed class TestClock : IGatewayClock
    {
        public DateTimeOffset UtcNow { get; set; }
    }
}

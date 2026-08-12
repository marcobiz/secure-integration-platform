using System.Collections.Frozen;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class RuntimeExecutionStrategyTests
{
    [Theory]
    [InlineData(GatewayAuthenticationKind.SoapBasicOpaqueSession)]
    [InlineData(GatewayAuthenticationKind.OpaqueSessionHttp)]
    public async Task Wave1_UT_runtime_selects_the_exact_qualified_strategy_only_after_principal_grant_and_operation_resolution(GatewayAuthenticationKind kind)
    {
        RuntimeFixture fixture = await RuntimeFixture.CreateAsync(kind, grant: true);
        RecordingStrategy exact = new(Key(kind));
        RecordingStrategy wrong = new(Key(kind == GatewayAuthenticationKind.SoapBasicOpaqueSession ? GatewayAuthenticationKind.OpaqueSessionHttp : GatewayAuthenticationKind.SoapBasicOpaqueSession));
        RestrictedEgressService runtime = fixture.Runtime([wrong, exact]);

        GatewayInvokeResponse response = await runtime.InvokeAsync(fixture.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId, fixture.Request, TestContext.Current.CancellationToken);

        Assert.Equal(1, exact.Calls);
        Assert.Equal(0, wrong.Calls);
        Assert.Equal(0, fixture.Transport.Calls);
        Assert.Equal("qualified", System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(response.Result.Data)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Wave1_SEC_invalid_grant_and_missing_strategy_deny_before_strategy_or_network(bool grant)
    {
        RuntimeFixture fixture = await RuntimeFixture.CreateAsync(GatewayAuthenticationKind.SoapBasicOpaqueSession, grant);
        RecordingStrategy wrong = new(ConnectorExecutionStrategyKey.Parse("other-strategy"));
        RestrictedEgressService runtime = fixture.Runtime([wrong]);

        GatewayException failure = await Assert.ThrowsAsync<GatewayException>(() => runtime.InvokeAsync(fixture.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId,
            fixture.Request, TestContext.Current.CancellationToken));

        Assert.Equal(grant ? "BGW-EGRESS-AUTHENTICATION" : "BGW-AUTHZ-OPERATION-DENIED", failure.Code);
        Assert.Equal(0, wrong.Calls);
        Assert.Equal(0, fixture.Transport.Calls);
    }

    [Fact]
    public async Task Wave1_SEC_external_strategy_requires_authoritative_Published_provider_and_dispatcher_before_scope_entry()
    {
        ConnectorExecutionStrategyKey key = ConnectorExecutionStrategyKey.Parse("synthetic-authoritative-preflight");

        RuntimeFixture nonAuthoritative = await RuntimeFixture.CreateAsync(GatewayAuthenticationKind.None, grant: true, key);
        RecordingStrategy nonAuthoritativeStrategy = new(key);
        RecordingExpectationProvider nonAuthoritativeProvider = new(new HashSet<ConnectorExecutionStrategyKey> { key });
        RecordingExpectationDispatcher nonAuthoritativeDispatcher = new();
        GatewayException missingAuthority = await Assert.ThrowsAsync<GatewayException>(() => nonAuthoritative.RuntimeConfigured(
            [nonAuthoritativeStrategy], nonAuthoritative.NonAuthoritativeCatalog, [nonAuthoritativeProvider], nonAuthoritativeDispatcher).InvokeAsync(
                nonAuthoritative.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId, nonAuthoritative.Request,
                TestContext.Current.CancellationToken));
        Assert.Equal("BGW-EGRESS-AUTHENTICATION", missingAuthority.Code);
        Assert.Equal(0, nonAuthoritativeProvider.Calls);
        Assert.Equal(0, nonAuthoritativeDispatcher.ValidationCalls);
        Assert.Equal(0, nonAuthoritativeStrategy.Calls);
        Assert.Equal(0, nonAuthoritative.Transport.Calls);

        RuntimeFixture missingProvider = await RuntimeFixture.CreateAsync(GatewayAuthenticationKind.None, grant: true, key);
        RecordingStrategy missingProviderStrategy = new(key);
        RecordingExpectationDispatcher missingProviderDispatcher = new();
        GatewayException providerFailure = await Assert.ThrowsAsync<GatewayException>(() => missingProvider.RuntimeConfigured(
            [missingProviderStrategy], missingProvider.AuthoritativeCatalog, [], missingProviderDispatcher).InvokeAsync(
                missingProvider.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId, missingProvider.Request,
                TestContext.Current.CancellationToken));
        Assert.Equal("BGW-EGRESS-AUTHENTICATION", providerFailure.Code);
        Assert.Equal(0, missingProviderDispatcher.ValidationCalls);
        Assert.Equal(0, missingProviderStrategy.Calls);
        Assert.Equal(0, missingProvider.Transport.Calls);

        RuntimeFixture missingDispatcher = await RuntimeFixture.CreateAsync(GatewayAuthenticationKind.None, grant: true, key);
        RecordingStrategy missingDispatcherStrategy = new(key);
        RecordingExpectationProvider presentProvider = new(new HashSet<ConnectorExecutionStrategyKey> { key });
        GatewayException dispatcherFailure = await Assert.ThrowsAsync<GatewayException>(() => missingDispatcher.RuntimeConfigured(
            [missingDispatcherStrategy], missingDispatcher.AuthoritativeCatalog, [presentProvider], null).InvokeAsync(
                missingDispatcher.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId, missingDispatcher.Request,
                TestContext.Current.CancellationToken));
        Assert.Equal("BGW-EGRESS-AUTHENTICATION", dispatcherFailure.Code);
        Assert.Equal(0, presentProvider.Calls);
        Assert.Equal(0, missingDispatcherStrategy.Calls);
        Assert.Equal(0, missingDispatcher.Transport.Calls);

        RuntimeFixture complete = await RuntimeFixture.CreateAsync(GatewayAuthenticationKind.None, grant: true, key);
        RecordingStrategy completeStrategy = new(key);
        RecordingExpectationProvider completeProvider = new(new HashSet<ConnectorExecutionStrategyKey> { key });
        RecordingExpectationDispatcher completeDispatcher = new();
        GatewayInvokeResponse response = await complete.RuntimeConfigured(
            [completeStrategy], complete.AuthoritativeCatalog, [completeProvider], completeDispatcher).InvokeAsync(
                complete.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId, complete.Request,
                TestContext.Current.CancellationToken);
        Assert.Equal("qualified", System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(response.Result.Data)));
        Assert.Equal(1, completeProvider.Calls);
        Assert.Equal(1, completeDispatcher.ValidationCalls);
        Assert.Equal(1, completeStrategy.Calls);
        Assert.Equal(0, complete.Transport.Calls);
    }

    [Fact]
    public async Task Wave1_SEC_duplicate_strategy_key_fails_during_composition()
    {
        RuntimeFixture fixture = await RuntimeFixture.CreateAsync(GatewayAuthenticationKind.SoapBasicOpaqueSession, grant: true);
        ConnectorExecutionStrategyKey key = Key(GatewayAuthenticationKind.SoapBasicOpaqueSession);
        InvalidOperationException failure = Assert.Throws<InvalidOperationException>(() => fixture.Runtime([new RecordingStrategy(key), new RecordingStrategy(key)]));
        Assert.Equal("Duplicate Connector execution strategy key.", failure.Message);
        Assert.Equal(0, fixture.Transport.Calls);
    }

    [Fact]
    public void Wave1_SEC_expectation_provider_registry_is_exact_one_bounded_and_snapshotted()
    {
        ConnectorExecutionStrategyKey key = ConnectorExecutionStrategyKey.Parse("synthetic-expectation");
        HashSet<ConnectorExecutionStrategyKey> advertised = [key];
        RecordingExpectationProvider first = new(advertised);
        AuthorizedPublishedOperationExpectationProviderRegistry registry = new([first]);

        advertised.Clear();

        Assert.Same(first, registry.Required(key));
        Assert.Throws<InvalidOperationException>(() => new AuthorizedPublishedOperationExpectationProviderRegistry(
            [new RecordingExpectationProvider(new HashSet<ConnectorExecutionStrategyKey> { key }),
                new RecordingExpectationProvider(new HashSet<ConnectorExecutionStrategyKey> { key })]));
        Assert.Throws<InvalidOperationException>(() => new AuthorizedPublishedOperationExpectationProviderRegistry(
            [new RecordingExpectationProvider(new HashSet<ConnectorExecutionStrategyKey>())]));
    }

    [Fact]
    public void Wave1_CT_qualified_execution_handoff_is_non_forgeable_and_hides_payload_and_operation_authority()
    {
        Assert.Empty(typeof(AuthorizedConnectorExecution).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(typeof(AuthorizedConnectorExecution).GetProperties(BindingFlags.Public | BindingFlags.Instance), property =>
            property.Name is "Payload" or "Operation" or "Principal" or "Endpoint");
        Assert.All(typeof(AuthorizedConnectorExecution).GetProperties(BindingFlags.Public | BindingFlags.Instance), property => Assert.False(property.CanWrite));
        Assert.DoesNotContain(typeof(AuthorizedConnectorExecution).GetMethods(BindingFlags.Public | BindingFlags.Static), method => method.Name.Contains("Create", StringComparison.Ordinal));
        Assert.Equal(typeof(IAuthorizedConnectorCapabilityBridge), typeof(AuthorizedConnectorExecution).GetProperty(nameof(AuthorizedConnectorExecution.Capabilities))!.PropertyType);
        Assert.Equal(
            [nameof(IAuthorizedConnectorCapabilityBridge.CreateSignedTokenAsync), nameof(IAuthorizedConnectorCapabilityBridge.CreateSignedTokenAsync),
                nameof(IAuthorizedConnectorCapabilityBridge.ExecuteComposedSoapAsync),
                nameof(IAuthorizedConnectorCapabilityBridge.ExecuteRestrictedTransportAsync), nameof(IAuthorizedConnectorCapabilityBridge.ExecuteTypedSessionHandshakeAsync)],
            typeof(IAuthorizedConnectorCapabilityBridge).GetMethods().Select(method => method.Name).Order(StringComparer.Ordinal).ToArray());
        MethodInfo slotSigning = Assert.Single(typeof(IAuthorizedConnectorCapabilityBridge).GetMethods(), method =>
            method.Name == nameof(IAuthorizedConnectorCapabilityBridge.CreateSignedTokenAsync) &&
            method.GetParameters().Length == 3);
        Assert.Equal([typeof(ConnectorSigningSlotKey), typeof(IReadOnlyDictionary<string, JsonElement>), typeof(CancellationToken)],
            slotSigning.GetParameters().Select(value => value.ParameterType));
        Assert.Equal(typeof(Task<AuthorizedConnectorSignedToken>), slotSigning.ReturnType);
        Assert.Equal(typeof(Task<QualifiedGatewayExecutionResult>), typeof(IAuthorizedConnectorCapabilityBridge).GetMethod(nameof(IAuthorizedConnectorCapabilityBridge.ExecuteRestrictedTransportAsync))!.ReturnType);
        Assert.Empty(typeof(ConnectorSigningSlotKey).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Equal([nameof(ConnectorSigningSlotKey.Value)],
            typeof(ConnectorSigningSlotKey).GetProperties(BindingFlags.Public | BindingFlags.Instance).Select(value => value.Name));
        Assert.Empty(typeof(AuthorizedConnectorSignedToken).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(AuthorizedConnectorSignedToken).GetProperties(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(AuthorizedPublishedExtensionConfiguration).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Equal([nameof(AuthorizedPublishedExtensionConfiguration.JsonLength)],
            typeof(AuthorizedPublishedExtensionConfiguration).GetProperties(BindingFlags.Public | BindingFlags.Instance).Select(value => value.Name));
        Assert.Equal([nameof(AuthorizedPublishedExtensionConfiguration.OpenJsonStream), nameof(AuthorizedPublishedExtensionConfiguration.ToString)],
            typeof(AuthorizedPublishedExtensionConfiguration).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Where(value => !value.IsSpecialName).Select(value => value.Name).Order(StringComparer.Ordinal));
        ConstructorInfo[] transportRequests = typeof(AuthorizedConnectorRestrictedTransportRequest)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance);
        Assert.Equal(6, transportRequests.Length);
        Assert.Contains(transportRequests, constructor => constructor.GetParameters().Length == 0);
        Assert.Contains(transportRequests, constructor => constructor.GetParameters().Select(value => value.ParameterType)
            .SequenceEqual([typeof(IReadOnlyCollection<AuthorizedConnectorPathParameter>)]));
        Assert.Contains(transportRequests, constructor => constructor.GetParameters().Select(value => value.ParameterType)
            .SequenceEqual([typeof(ReadOnlyMemory<byte>)]));
        Assert.Contains(transportRequests, constructor => constructor.GetParameters().Select(value => value.ParameterType)
            .SequenceEqual([typeof(ReadOnlyMemory<byte>), typeof(IReadOnlyCollection<AuthorizedConnectorPathParameter>)]));
        Assert.Contains(transportRequests, constructor => constructor.GetParameters().Select(value => value.ParameterType)
            .SequenceEqual([typeof(ReadOnlyMemory<byte>), typeof(AuthorizedConnectorSignedToken)]));
        Assert.Contains(transportRequests, constructor => constructor.GetParameters().Select(value => value.ParameterType)
            .SequenceEqual([typeof(ReadOnlyMemory<byte>), typeof(AuthorizedConnectorSignedToken), typeof(IReadOnlyCollection<AuthorizedConnectorPathParameter>)]));
        Assert.Equal([nameof(AuthorizedConnectorRestrictedTransportRequest.BodyLength), nameof(AuthorizedConnectorRestrictedTransportRequest.PathParameterCount)],
            typeof(AuthorizedConnectorRestrictedTransportRequest).GetProperties(BindingFlags.Public | BindingFlags.Instance).Select(value => value.Name));
        Assert.Equal([nameof(AuthorizedConnectorPathParameter.Name), nameof(AuthorizedConnectorPathParameter.Value)],
            typeof(AuthorizedConnectorPathParameter).GetProperties(BindingFlags.Public | BindingFlags.Instance).Select(value => value.Name));
        Assert.Empty(typeof(AuthorizedPublishedOperationExpectationContext).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Equal(
            [nameof(AuthorizedPublishedOperationExpectationContext.AuthenticationKind),
                nameof(AuthorizedPublishedOperationExpectationContext.ConnectorId),
                nameof(AuthorizedPublishedOperationExpectationContext.ConnectorVersion),
                nameof(AuthorizedPublishedOperationExpectationContext.ExecutionStrategyKey),
                nameof(AuthorizedPublishedOperationExpectationContext.OperationId)],
            typeof(AuthorizedPublishedOperationExpectationContext).GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Select(value => value.Name).Order(StringComparer.Ordinal));
        MethodInfo expectationFactory = typeof(IAuthorizedPublishedOperationExpectationProvider)
            .GetMethod(nameof(IAuthorizedPublishedOperationExpectationProvider.CreateExpectations))!;
        Assert.Equal([typeof(AuthorizedPublishedOperationExpectationContext)],
            expectationFactory.GetParameters().Select(value => value.ParameterType));
        Assert.Equal(typeof(AuthorizedPublishedOperationExpectations), expectationFactory.ReturnType);
        Type[] expectationSurface =
        [
            typeof(AuthorizedPublishedOperationExpectationContext),
            typeof(AuthorizedPublishedOperationExpectations),
            typeof(AuthorizedSigningSlotExpectation),
            typeof(AuthorizedSigningIssuerExpectation),
            typeof(AuthorizedSigningTokenProjectionExpectation)
        ];
        Assert.DoesNotContain(expectationSurface.SelectMany(type => type.GetProperties(BindingFlags.Public | BindingFlags.Instance)), property =>
            property.PropertyType == typeof(Uri) || property.PropertyType == typeof(JsonElement) ||
            typeof(IAuthorizedConnectorCapabilityBridge).IsAssignableFrom(property.PropertyType) ||
            property.PropertyType.Namespace?.StartsWith("SecureIntegration.Providers", StringComparison.Ordinal) == true ||
            property.Name.Contains("Secret", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("CertificateMaterial", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("Store", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("Provider", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(typeof(AuthorizedConnectorExecution).Assembly.GetExportedTypes()
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)),
            method => method.Name.Contains("ValidatePublishedOperationExpectations", StringComparison.Ordinal));
        Assert.Empty(typeof(AuthorizedConnectorBindingInputs).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Equal([nameof(AuthorizedConnectorBindingInputs.Count)],
            typeof(AuthorizedConnectorBindingInputs).GetProperties(BindingFlags.Public | BindingFlags.Instance).Select(value => value.Name));
        Assert.Equal([nameof(AuthorizedConnectorBindingInputs.Contains), nameof(AuthorizedConnectorBindingInputs.ToString), nameof(AuthorizedConnectorBindingInputs.WriteRequiredXmlValue)],
            typeof(AuthorizedConnectorBindingInputs).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Where(value => !value.IsSpecialName).Select(value => value.Name).Order(StringComparer.Ordinal));
        MethodInfo bindingWrite = typeof(AuthorizedConnectorBindingInputs).GetMethod(nameof(AuthorizedConnectorBindingInputs.WriteRequiredXmlValue))!;
        Assert.Equal([typeof(string)], bindingWrite.GetParameters().Select(value => value.ParameterType));
        Assert.DoesNotContain(bindingWrite.GetParameters(), value => typeof(System.Xml.XmlWriter).IsAssignableFrom(value.ParameterType));
        Assert.DoesNotContain(typeof(IAuthorizedConnectorCapabilityBridge).GetMethods().SelectMany(method => method.GetParameters()), parameter =>
            parameter.Name is "endpoint" or "provider" or "key" or "certificate" or "profileId");
        Assert.DoesNotContain(typeof(AuthorizedConnectorExecution).Assembly.GetExportedTypes(), type =>
            type != typeof(IAuthorizedConnectorCapabilityBridge) && typeof(IAuthorizedConnectorCapabilityBridge).IsAssignableFrom(type));
    }

    [Theory]
    [InlineData("")]
    [InlineData("UpperCase")]
    [InlineData("-leading")]
    [InlineData("trailing-")]
    [InlineData("contains space")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void Wave1_UT_execution_strategy_key_is_bounded_exact_lower_case_and_canonical(string invalid)
    {
        Assert.False(ConnectorExecutionStrategyKey.TryParse(invalid, out ConnectorExecutionStrategyKey? parsed));
        Assert.Null(parsed);
        Assert.Throws<ArgumentException>(() => ConnectorExecutionStrategyKey.Parse(invalid));

        ConnectorExecutionStrategyKey key = ConnectorExecutionStrategyKey.Parse("synthetic-execution.v1");
        Assert.Equal("synthetic-execution.v1", key.Value);
        Assert.Equal(key, ConnectorExecutionStrategyKey.Parse(key.ToString()));
    }

    [Theory]
    [InlineData("")]
    [InlineData("UpperCase")]
    [InlineData("-leading")]
    [InlineData("trailing-")]
    [InlineData("contains space")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void Wave1_UT_signing_slot_key_is_bounded_exact_lower_case_and_canonical(string invalid)
    {
        Assert.False(ConnectorSigningSlotKey.TryParse(invalid, out ConnectorSigningSlotKey? parsed));
        Assert.Null(parsed);
        Assert.Throws<ArgumentException>(() => ConnectorSigningSlotKey.Parse(invalid));

        ConnectorSigningSlotKey key = ConnectorSigningSlotKey.Parse("secondary-signing.v1");
        Assert.Equal("secondary-signing.v1", key.Value);
        Assert.Equal(key, ConnectorSigningSlotKey.Parse(key.ToString()));
    }

    [Fact]
    public async Task Wave1_UT_explicit_execution_key_is_independent_from_authentication_kind()
    {
        ConnectorExecutionStrategyKey explicitKey = ConnectorExecutionStrategyKey.Parse("synthetic-echo");
        RuntimeFixture fixture = await RuntimeFixture.CreateAsync(GatewayAuthenticationKind.None, grant: true, explicitKey);
        RecordingStrategy selected = new(explicitKey);
        RestrictedEgressService runtime = fixture.Runtime([selected]);

        _ = await runtime.InvokeAsync(fixture.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId, fixture.Request, TestContext.Current.CancellationToken);

        Assert.Equal(1, selected.Calls);
        Assert.Equal(0, fixture.Transport.Calls);
    }

    [Theory]
    [InlineData(GatewayAuthenticationKind.OpaqueSessionHttp)]
    [InlineData(GatewayAuthenticationKind.SoapBasicOpaqueSession)]
    public async Task Wave1_SEC_basic_strategy_cannot_execute_incompatible_session_or_composed_mode(
        GatewayAuthenticationKind publishedAuthenticationKind)
    {
        ConnectorExecutionStrategyKey key = ConnectorExecutionStrategyKey.Parse("synthetic-incompatible");
        RuntimeFixture fixture = await RuntimeFixture.CreateAsync(publishedAuthenticationKind, grant: true, key);
        IncompatibleStrategy strategy = new(key);

        GatewayException failure = await Assert.ThrowsAsync<GatewayException>(() => fixture.Runtime([strategy]).InvokeAsync(
            fixture.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId, fixture.Request,
            TestContext.Current.CancellationToken));

        Assert.Equal("BGW-EGRESS-AUTHENTICATION", failure.Code);
        Assert.Equal(0, strategy.Calls);
        Assert.Equal(0, fixture.Transport.Calls);
    }

    [Fact]
    public async Task Wave1_SEC_explicit_unknown_key_never_falls_back_to_default_HTTP()
    {
        RuntimeFixture fixture = await RuntimeFixture.CreateAsync(
            GatewayAuthenticationKind.None, grant: true, ConnectorExecutionStrategyKey.Parse("not-installed"));
        RestrictedEgressService runtime = fixture.Runtime([]);

        GatewayException failure = await Assert.ThrowsAsync<GatewayException>(() => runtime.InvokeAsync(
            fixture.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId, fixture.Request, TestContext.Current.CancellationToken));

        Assert.Equal("BGW-EGRESS-AUTHENTICATION", failure.Code);
        Assert.Equal(0, fixture.Transport.Calls);
    }

    [Fact]
    public async Task Wave1_SEC_strategy_exception_and_fake_cancellation_are_sanitized_but_real_cancellation_is_preserved()
    {
        ConnectorExecutionStrategyKey key = ConnectorExecutionStrategyKey.Parse("synthetic-boundary");
        RuntimeFixture fixture = await RuntimeFixture.CreateAsync(GatewayAuthenticationKind.None, grant: true, key);

        GatewayException unexpected = await Assert.ThrowsAsync<GatewayException>(() => fixture.Runtime([new ThrowingStrategy(key)]).InvokeAsync(
            fixture.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId, fixture.Request, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-EGRESS-UPSTREAM-REJECTED", unexpected.Code);
        Assert.Equal("BGW-EGRESS-UPSTREAM-REJECTED", unexpected.Message);
        Assert.Null(unexpected.InnerException);

        GatewayException forgedProviderFailure = await Assert.ThrowsAsync<GatewayException>(() => fixture.Runtime([new ForgedProviderFailureStrategy(key)]).InvokeAsync(
            fixture.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId, fixture.Request, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-EGRESS-UPSTREAM-REJECTED", forgedProviderFailure.Code);
        Assert.Equal(502, forgedProviderFailure.StatusCode);
        Assert.False(forgedProviderFailure.Retryable);

        GatewayException fakeCancellation = await Assert.ThrowsAsync<GatewayException>(() => fixture.Runtime([new FakeCancellationStrategy(key)]).InvokeAsync(
            fixture.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId, fixture.Request, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-EGRESS-UPSTREAM-REJECTED", fakeCancellation.Code);
        Assert.DoesNotContain("synthetic-fake-cancellation-canary", fakeCancellation.ToString(), StringComparison.Ordinal);

        using CancellationTokenSource callerCancellation = new();
        OperationCanceledException realCancellation = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Runtime([new CallerCancellationStrategy(key, callerCancellation)]).InvokeAsync(
            fixture.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId, fixture.Request, callerCancellation.Token));
        Assert.Equal(callerCancellation.Token, realCancellation.CancellationToken);
    }

    [Fact]
    public async Task Wave1_REG_default_HTTP_preserves_sanitized_provider_unavailability()
    {
        RuntimeFixture fixture = await RuntimeFixture.CreateAsync(GatewayAuthenticationKind.ApiKey, grant: true);

        ProviderAccessException failure = await Assert.ThrowsAsync<ProviderAccessException>(() => fixture.RuntimeConfigured(
            [], fixture.NonAuthoritativeCatalog, [], null, new UnavailableSecrets()).InvokeAsync(
            fixture.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId, fixture.Request, TestContext.Current.CancellationToken));

        Assert.Equal("BGW-PROVIDER-UNAVAILABLE", failure.Code);
        Assert.True(failure.Retryable);
        Assert.Null(failure.InnerException);
        Assert.Equal(0, fixture.Transport.Calls);
    }

    [Fact]
    public async Task Wave1_SEC_authorized_payload_is_an_owned_read_only_snapshot()
    {
        ConnectorExecutionStrategyKey key = ConnectorExecutionStrategyKey.Parse("synthetic-payload");
        RuntimeFixture fixture = await RuntimeFixture.CreateAsync(GatewayAuthenticationKind.None, grant: true, key);
        byte[] callerBuffer = "authorized-snapshot"u8.ToArray();
        AuthorizedConnectorExecution execution = new(
            new AuthorizedGatewayInvocation(fixture.Principal, RuntimeFixture.ConnectorId, RuntimeFixture.OperationId),
            fixture.Operation,
            key,
            callerBuffer);
        callerBuffer.AsSpan().Fill((byte)'X');

        await using Stream first = execution.OpenPayloadStream();
        Assert.False(first.CanWrite);
        Assert.Throws<NotSupportedException>(() => first.WriteByte((byte)'Y'));
        Assert.False(Assert.IsType<MemoryStream>(first).TryGetBuffer(out _));
        using MemoryStream copy = new();
        await first.CopyToAsync(copy, TestContext.Current.CancellationToken);
        Assert.Equal("authorized-snapshot", System.Text.Encoding.UTF8.GetString(copy.ToArray()));
    }

    [Fact]
    public void Wave1_SEC_execution_strategy_registry_is_bounded_and_not_runtime_growing()
    {
        IConnectorExecutionStrategy[] strategies = Enumerable.Range(0, ConnectorExecutionStrategyRegistry.MaximumStrategies + 1)
            .Select(index => (IConnectorExecutionStrategy)new RecordingStrategy(ConnectorExecutionStrategyKey.Parse($"strategy-{index:D3}")))
            .ToArray();
        Assert.Throws<InvalidOperationException>(() => new ConnectorExecutionStrategyRegistry(strategies));
    }

    [Fact]
    public void Wave1_SEC_strategy_authentication_metadata_is_validated_and_snapshotted_at_startup()
    {
        ConnectorExecutionStrategyKey key = ConnectorExecutionStrategyKey.Parse("mutable-compatibility");
        MutableCompatibilityStrategy strategy = new(key);
        ConnectorExecutionStrategyRegistry registry = new([strategy]);

        strategy.AuthenticationKinds.Clear();
        strategy.AuthenticationKinds.Add(GatewayAuthenticationKind.OpaqueSessionHttp);

        Assert.Same(strategy, registry.Required(key, GatewayAuthenticationKind.None).Strategy);
        GatewayException mismatch = Assert.Throws<GatewayException>(() => registry.Required(key, GatewayAuthenticationKind.OpaqueSessionHttp));
        Assert.Equal("BGW-EGRESS-AUTHENTICATION", mismatch.Code);
        Assert.Throws<InvalidOperationException>(() => new ConnectorExecutionStrategyRegistry([new EmptyCompatibilityStrategy(key)]));
    }

    private sealed class RuntimeFixture
    {
        internal const string ConnectorId = "qualified-runtime";
        internal const string OperationId = "dispatch";
        private readonly InMemoryGatewayRegistry registry;
        private readonly GatewayOperationCatalog nonAuthoritativeCatalog;
        private readonly TestAuthorizedOperationCatalog authoritativeCatalog;

        private RuntimeFixture(
            InMemoryGatewayRegistry registry,
            GatewayOperationCatalog nonAuthoritativeCatalog,
            TestAuthorizedOperationCatalog authoritativeCatalog,
            GatewayOperationDefinition operation,
            GatewayClientPrincipal principal,
            GatewayInvokeRequest request)
        {
            this.registry = registry;
            this.nonAuthoritativeCatalog = nonAuthoritativeCatalog;
            this.authoritativeCatalog = authoritativeCatalog;
            Operation = operation;
            Principal = principal;
            Request = request;
        }

        internal RecordingTransport Transport { get; } = new();
        internal GatewayClientPrincipal Principal { get; }
        internal GatewayInvokeRequest Request { get; }
        internal GatewayOperationDefinition Operation { get; }
        internal IGatewayOperationCatalog NonAuthoritativeCatalog => nonAuthoritativeCatalog;
        internal IGatewayOperationCatalog AuthoritativeCatalog => authoritativeCatalog;

        internal RestrictedEgressService Runtime(IEnumerable<IConnectorExecutionStrategy> strategies, ISecretValueProvider? secrets = null)
        {
            IConnectorExecutionStrategy[] configured = strategies.ToArray();
            ConnectorExecutionStrategyKey[] keys = configured.Select(value => value.Key).Distinct().ToArray();
            IEnumerable<IAuthorizedPublishedOperationExpectationProvider> providers = keys.Length == 0
                ? []
                : [new RecordingExpectationProvider(keys.ToHashSet())];
            return RuntimeConfigured(configured, authoritativeCatalog, providers, new RecordingExpectationDispatcher(), secrets);
        }

        internal RestrictedEgressService RuntimeConfigured(
            IEnumerable<IConnectorExecutionStrategy> strategies,
            IGatewayOperationCatalog selectedCatalog,
            IEnumerable<IAuthorizedPublishedOperationExpectationProvider> expectationProviders,
            IAuthorizedConnectorCapabilityDispatcher? dispatcher,
            ISecretValueProvider? secrets = null) =>
            new(registry, selectedCatalog, secrets ?? new NeverSecrets(), new NeverCertificates(), new PublicResolver(),
                Transport, new FixedClock(), null, strategies, expectationProviders, dispatcher);

        internal static async Task<RuntimeFixture> CreateAsync(
            GatewayAuthenticationKind kind,
            bool grant,
            ConnectorExecutionStrategyKey? executionStrategy = null)
        {
            DateTimeOffset now = FixedClock.Now;
            Guid tenantId = Guid.NewGuid(); Guid applicationId = Guid.NewGuid(); Guid environmentId = Guid.NewGuid(); Guid installationId = Guid.NewGuid();
            InMemoryGatewayRegistry registry = new();
            await registry.AddTenantAsync(new(tenantId, "qualified", "Qualified", TenantStatus.Active, now), TestContext.Current.CancellationToken);
            await registry.AddApplicationAsync(new(applicationId, "qualified", "Qualified", ApplicationStatus.Active, "3.0.0", null, now), TestContext.Current.CancellationToken);
            await registry.AddEnvironmentAsync(new(environmentId, "qualified", "Qualified", false), TestContext.Current.CancellationToken);
            await registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "3.0.0", now), TestContext.Current.CancellationToken);
            if (grant) await registry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, ConnectorId, OperationId, true, now.AddMinutes(-1)), TestContext.Current.CancellationToken);
            GatewayOperationDefinition operation = new(ConnectorId, OperationId, "1.0.0", new("https://vendor.example.test/dispatch"), HttpMethod.Post,
                kind == GatewayAuthenticationKind.SoapBasicOpaqueSession ? "text/xml" : "application/json", kind,
                kind == GatewayAuthenticationKind.SoapBasicOpaqueSession ? "user-ref" : null,
                kind == GatewayAuthenticationKind.SoapBasicOpaqueSession ? "password-ref" : null,
                "session-ref", "X-Session-Reference", null, 5_000, 4096, 4096, false, 0, "qualified-policy", "qualified-session", executionStrategy);
            RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
                Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], now.AddMinutes(-1), now.AddHours(1), "3.0.0", null);
            GatewayInvokeRequest request = new("1.0", new(kind == GatewayAuthenticationKind.SoapBasicOpaqueSession ? "text/xml" : "application/json", "utf8", "<request/>"), Guid.NewGuid());
            GatewayOperationCatalog nonAuthoritative = new([operation]);
            TestAuthorizedOperationCatalog authoritative = new(nonAuthoritative, operation, environmentId);
            return new(registry, nonAuthoritative, authoritative, operation, new(identity, request.CorrelationId), request);
        }
    }

    private static ConnectorExecutionStrategyKey Key(GatewayAuthenticationKind kind) => ConnectorExecutionStrategyKey.Parse(kind switch
    {
        GatewayAuthenticationKind.SoapBasicOpaqueSession => "composed-soap",
        GatewayAuthenticationKind.OpaqueSessionHttp => "opaque-session-http",
        _ => throw new InvalidOperationException()
    });

    private sealed class RecordingStrategy(ConnectorExecutionStrategyKey key) : IConnectorExecutionStrategy
    {
        public ConnectorExecutionStrategyKey Key => key;
        public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => StrategyAuthenticationKinds.All;
        public int Calls { get; private set; }
        public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
        {
            Calls++;
            Assert.Equal(RuntimeFixture.ConnectorId, execution.ConnectorId);
            Assert.Equal(RuntimeFixture.OperationId, execution.OperationId);
            return Task.FromResult(new QualifiedGatewayExecutionResult(200, "application/octet-stream", "qualified"u8.ToArray()));
        }
    }

    private sealed class ThrowingStrategy(ConnectorExecutionStrategyKey key) : IConnectorExecutionStrategy
    {
        public ConnectorExecutionStrategyKey Key => key;
        public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => StrategyAuthenticationKinds.All;
        public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("synthetic-extension-diagnostic-canary");
    }

    private sealed class FakeCancellationStrategy(ConnectorExecutionStrategyKey key) : IConnectorExecutionStrategy
    {
        public ConnectorExecutionStrategyKey Key => key;
        public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => StrategyAuthenticationKinds.All;
        public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
            throw new OperationCanceledException("synthetic-fake-cancellation-canary", new CancellationToken(canceled: true));
    }

    private sealed class ForgedProviderFailureStrategy(ConnectorExecutionStrategyKey key) : IConnectorExecutionStrategy
    {
        public ConnectorExecutionStrategyKey Key => key;
        public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => StrategyAuthenticationKinds.All;
        public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
            throw new GatewayException("BGW-AUTHZ-OPERATION-DENIED", 403, retryable: true);
    }

    private sealed class CallerCancellationStrategy(ConnectorExecutionStrategyKey key, CancellationTokenSource callerCancellation) : IConnectorExecutionStrategy
    {
        public ConnectorExecutionStrategyKey Key => key;
        public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => StrategyAuthenticationKinds.All;
        public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
        {
            callerCancellation.Cancel();
            throw new OperationCanceledException(cancellationToken);
        }
    }

    private sealed class RecordingExpectationProvider(IReadOnlySet<ConnectorExecutionStrategyKey> strategies) :
        IAuthorizedPublishedOperationExpectationProvider
    {
        private int calls;
        public IReadOnlySet<ConnectorExecutionStrategyKey> SupportedExecutionStrategies => strategies;
        internal int Calls => Volatile.Read(ref calls);

        public AuthorizedPublishedOperationExpectations CreateExpectations(
            AuthorizedPublishedOperationExpectationContext context)
        {
            Interlocked.Increment(ref calls);
            return new(context.AuthenticationKind, restrictedTransportRequired: false, []);
        }
    }

    private sealed class RecordingExpectationDispatcher : IAuthorizedConnectorCapabilityDispatcher
    {
        private int validationCalls;
        internal int ValidationCalls => Volatile.Read(ref validationCalls);

        public Task ValidatePublishedOperationExpectationsAsync(
            AuthorizedConnectorExecution execution,
            AuthorizedPublishedOperationExpectations expectations,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref validationCalls);
            return Task.CompletedTask;
        }

        public Task<QualifiedGatewayExecutionResult> ExecuteTypedSessionHandshakeAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
            throw new InvalidOperationException();
        public Task<QualifiedGatewayExecutionResult> ExecuteComposedSoapAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
            throw new InvalidOperationException();
        public Task<string> CreateSignedTokenAsync(AuthorizedConnectorExecution execution, ConnectorSigningSlotKey signingSlot, IReadOnlyDictionary<string, JsonElement> claims, CancellationToken cancellationToken) =>
            throw new InvalidOperationException();
        public Task<QualifiedGatewayExecutionResult> ExecuteRestrictedTransportAsync(AuthorizedConnectorExecution execution, AuthorizedConnectorRestrictedTransportRequest request, IReadOnlyDictionary<ConnectorSigningSlotKey, AuthorizedConnectorSignedToken> signedTokens, CancellationToken cancellationToken) =>
            throw new InvalidOperationException();
    }

    private sealed class TestAuthorizedOperationCatalog(
        GatewayOperationCatalog inner,
        GatewayOperationDefinition operation,
        Guid environmentId) : IGatewayOperationCatalog, IAuthorizedPublishedOperationCatalog
    {
        private readonly AuthorizedPublishedOperation authorized = new(
            operation,
            new(
                operation.ConnectorId,
                operation.OperationId,
                environmentId,
                operation.Version,
                Guid.NewGuid(),
                1,
                new string('A', 64),
                Guid.NewGuid(),
                1,
                new string('B', 64),
                new string('C', 64),
                new string('D', 64),
                operation.Authentication,
                ConnectorExecutionStrategyKeys.Resolve(operation)),
            AuthorizedPublishedExtensionConfiguration.Empty());

        public Task<GatewayOperationDefinition> GetRequiredAsync(string connectorId, string operationId, Guid environment, CancellationToken cancellationToken) =>
            inner.GetRequiredAsync(connectorId, operationId, environment, cancellationToken);

        public void Invalidate(string connectorId) => inner.Invalidate(connectorId);

        public Task<AuthorizedPublishedOperation> GetRequiredAuthorizedAsync(
            string connectorId,
            string operationId,
            Guid environment,
            PublishedConnectorAccessContext accessContext,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(authorized);
        }
    }

    private sealed class IncompatibleStrategy(ConnectorExecutionStrategyKey key) : IConnectorExecutionStrategy
    {
        public ConnectorExecutionStrategyKey Key => key;
        public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => StrategyAuthenticationKinds.Basic;
        public int Calls { get; private set; }
        public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new QualifiedGatewayExecutionResult(200, "application/json", []));
        }
    }

    private static class StrategyAuthenticationKinds
    {
        internal static readonly FrozenSet<GatewayAuthenticationKind> All = Enum.GetValues<GatewayAuthenticationKind>().ToFrozenSet();
        internal static readonly FrozenSet<GatewayAuthenticationKind> None = new[] { GatewayAuthenticationKind.None }.ToFrozenSet();
        internal static readonly FrozenSet<GatewayAuthenticationKind> Basic = new[] { GatewayAuthenticationKind.Basic }.ToFrozenSet();
    }

    private sealed class MutableCompatibilityStrategy(ConnectorExecutionStrategyKey key) : IConnectorExecutionStrategy
    {
        internal HashSet<GatewayAuthenticationKind> AuthenticationKinds { get; } = [GatewayAuthenticationKind.None];
        public ConnectorExecutionStrategyKey Key => key;
        public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds => AuthenticationKinds;
        public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
            Task.FromResult(new QualifiedGatewayExecutionResult(200, "application/json", []));
    }

    private sealed class EmptyCompatibilityStrategy(ConnectorExecutionStrategyKey key) : IConnectorExecutionStrategy
    {
        public ConnectorExecutionStrategyKey Key => key;
        public IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds { get; } = new HashSet<GatewayAuthenticationKind>();
        public Task<QualifiedGatewayExecutionResult> ExecuteAsync(AuthorizedConnectorExecution execution, CancellationToken cancellationToken) =>
            Task.FromResult(new QualifiedGatewayExecutionResult(200, "application/json", []));
    }

    private sealed class RecordingTransport : IRestrictedTransport
    {
        public int Calls { get; private set; }
        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout,
            long maximumResponseBytes, CancellationToken cancellationToken)
        {
            Calls++;
            throw new InvalidOperationException("Qualified modes must not fall back to the ordinary transport path.");
        }
    }

    private sealed class NeverSecrets : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) => throw new InvalidOperationException();
    }

    private sealed class UnavailableSecrets : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) =>
            throw new ProviderAccessException("BGW-PROVIDER-UNAVAILABLE", retryable: true, new InvalidOperationException("synthetic-provider-diagnostic"));
    }

    private sealed class NeverCertificates : IClientCertificateProvider
    {
        public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken) => throw new InvalidOperationException();
    }

    private sealed class PublicResolver : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { IPAddress.Parse("8.8.8.8") });
    }

    private sealed class FixedClock : IGatewayClock
    {
        internal static readonly DateTimeOffset Now = new(2026, 8, 9, 12, 0, 0, TimeSpan.Zero);
        public DateTimeOffset UtcNow => Now;
    }
}

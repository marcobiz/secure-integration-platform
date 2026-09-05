using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using SecureIntegration.Broker.Core;
using SecureIntegration.Broker.Infrastructure.Windows;
using SecureIntegration.Broker.Sdk;
using SecureIntegration.Contracts;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.Broker.VerticalSlice.Tests;

public sealed class BrokerGatewayContinuityTests
{
    [Fact]
    public async Task Broker_Gateway_continuity_enrolls_once_invokes_Published_synthetic_operation_and_restart_reuses_Installation()
    {
        await using ContinuityGateway fixture = await ContinuityGateway.CreateAsync(grantEnabled: true);
        Guid firstInstallation;
        using (ProductionGatewayInvoker first = fixture.CreateInvoker())
        {
            InvokeGatewayResult result = await InvokeThroughBrokerAsync(first, TestContext.Current.CancellationToken);
            Assert.Equal("1.0.0", result.ConnectorVersion);
            Assert.Contains("accepted", Encoding.UTF8.GetString(Convert.FromBase64String(result.PayloadBase64)), StringComparison.Ordinal);
            firstInstallation = fixture.LastInvokedInstallationId;
        }

        Assert.Equal(1, fixture.ActivationCount);
        Assert.Equal(1, fixture.ExternalDispatchCount);
        Assert.Null(Environment.GetEnvironmentVariable(fixture.Options.ActivationCodeEnvironmentVariable, EnvironmentVariableTarget.Process));

        using (ProductionGatewayInvoker restarted = fixture.CreateInvoker())
        {
            InvokeGatewayResult result = await InvokeThroughBrokerAsync(restarted, TestContext.Current.CancellationToken);
            Assert.Equal("1.0.0", result.ConnectorVersion);
        }

        Assert.Equal(1, fixture.ActivationCount);
        Assert.Equal(2, fixture.ExternalDispatchCount);
        Assert.Equal(firstInstallation, fixture.LastInvokedInstallationId);
        Assert.Equal(fixture.InstallationId, fixture.LastInvokedInstallationId);
        string statePath = Path.Combine(fixture.DataDirectory, "gateway-installation-state.json");
        using JsonDocument state = JsonDocument.Parse(await File.ReadAllBytesAsync(statePath, TestContext.Current.CancellationToken));
        Assert.Equal(
            ["credentialExpiresAt", "credentialId", "currentCertificateThumbprint", "currentKeyName", "formatVersion", "installationId", "renewalStartsAt"],
            state.RootElement.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData(HttpRequestError.ResponseEnded)]
    [InlineData(HttpRequestError.ConnectionError)]
    public async Task Renewal_response_loss_is_nonretryable_and_restart_recovers_authoritatively_without_reenrollment_or_resend(HttpRequestError responseError)
    {
        await using ContinuityGateway fixture = await ContinuityGateway.CreateAsync(grantEnabled: true);
        using (ProductionGatewayInvoker enrolled = fixture.CreateInvoker())
        {
            _ = await InvokeDirectAsync(enrolled, TestContext.Current.CancellationToken);
        }
        fixture.Clock.Advance(TimeSpan.FromDays(61));
        fixture.NextRenewalResponseError = responseError;

        using (ProductionGatewayInvoker interrupted = fixture.CreateInvoker())
        {
            BrokerException ambiguous = await Assert.ThrowsAsync<BrokerException>(() => InvokeDirectAsync(interrupted, TestContext.Current.CancellationToken));
            Assert.Equal("gateway_renewal_outcome_ambiguous", ambiguous.Code);
            Assert.False(ambiguous.Retryable);
        }

        Assert.Equal(1, fixture.RenewalCount);
        Assert.Equal(1, fixture.ExternalDispatchCount);
        Assert.True(fixture.PendingCredentialAccepted);
        string statePath = Path.Combine(fixture.DataDirectory, "gateway-installation-state.json");
        using JsonDocument pendingState = JsonDocument.Parse(await File.ReadAllBytesAsync(statePath, TestContext.Current.CancellationToken));
        string pendingThumbprint = pendingState.RootElement.GetProperty("pending").GetProperty("certificateThumbprint").GetString()!;
        Assert.NotEqual(pendingThumbprint, pendingState.RootElement.GetProperty("currentCertificateThumbprint").GetString());

        using (ProductionGatewayInvoker recovered = fixture.CreateInvoker())
        {
            GatewayInvocationResult result = await InvokeDirectAsync(recovered, TestContext.Current.CancellationToken);
            Assert.Equal("1.0.0", result.ConnectorVersion);
        }

        Assert.Equal(1, fixture.ActivationCount);
        Assert.Equal(1, fixture.RenewalCount);
        Assert.Equal(2, fixture.ExternalDispatchCount);
        Assert.Equal(fixture.InstallationId, fixture.LastInvokedInstallationId);
        using JsonDocument state = JsonDocument.Parse(await File.ReadAllBytesAsync(statePath, TestContext.Current.CancellationToken));
        Assert.False(state.RootElement.TryGetProperty("pending", out _));
        Assert.Equal(pendingThumbprint, state.RootElement.GetProperty("currentCertificateThumbprint").GetString());
    }

    [Fact]
    public async Task Concurrent_calls_start_one_renewal_and_unavailable_Gateway_recovers_only_on_a_new_explicit_call()
    {
        await using ContinuityGateway fixture = await ContinuityGateway.CreateAsync(grantEnabled: true);
        using ProductionGatewayInvoker invoker = fixture.CreateInvoker();
        _ = await InvokeDirectAsync(invoker, TestContext.Current.CancellationToken);
        fixture.Clock.Advance(TimeSpan.FromDays(61));

        Task<GatewayInvocationResult>[] concurrent = Enumerable.Range(0, 8)
            .Select(_ => InvokeDirectAsync(invoker, TestContext.Current.CancellationToken))
            .ToArray();
        await Task.WhenAll(concurrent);

        Assert.Equal(1, fixture.RenewalCount);
        Assert.Equal(9, fixture.ExternalDispatchCount);
        Assert.All(concurrent, task => Assert.Equal("1.0.0", task.Result.ConnectorVersion));

        fixture.UnavailableError = HttpRequestError.ConnectionError;
        BrokerException unavailable = await Assert.ThrowsAsync<BrokerException>(() => InvokeDirectAsync(invoker, TestContext.Current.CancellationToken));
        Assert.Equal("gateway_outcome_ambiguous", unavailable.Code);
        Assert.False(unavailable.Retryable);
        Assert.Equal(9, fixture.ExternalDispatchCount);

        using (ProductionGatewayInvoker restarted = fixture.CreateInvoker())
        {
            BrokerException policyUnavailable = await Assert.ThrowsAsync<BrokerException>(() => InvokeDirectAsync(restarted, TestContext.Current.CancellationToken));
            Assert.Equal("gateway_transport_failed", policyUnavailable.Code);
            Assert.True(policyUnavailable.Retryable);
            Assert.Equal(9, fixture.ExternalDispatchCount);
        }

        foreach (HttpRequestError preDispatchError in new[] { HttpRequestError.NameResolutionError, HttpRequestError.SecureConnectionError })
        {
            fixture.UnavailableError = preDispatchError;
            BrokerException preDispatch = await Assert.ThrowsAsync<BrokerException>(() => InvokeDirectAsync(invoker, TestContext.Current.CancellationToken));
            Assert.Equal("gateway_transport_failed", preDispatch.Code);
            Assert.True(preDispatch.Retryable);
            Assert.Equal(9, fixture.ExternalDispatchCount);
        }

        fixture.UnavailableError = null;
        _ = await InvokeDirectAsync(invoker, TestContext.Current.CancellationToken);
        Assert.Equal(10, fixture.ExternalDispatchCount);
        Assert.Equal(1, fixture.ActivationCount);
        Assert.Equal(1, fixture.RenewalCount);
    }

    [Theory]
    [InlineData(HttpRequestError.ResponseEnded)]
    [InlineData(HttpRequestError.ConnectionError)]
    public async Task Lost_invoke_response_is_ambiguous_and_never_automatically_replays_the_upstream_effect(HttpRequestError responseError)
    {
        await using ContinuityGateway fixture = await ContinuityGateway.CreateAsync(grantEnabled: true);
        using ProductionGatewayInvoker invoker = fixture.CreateInvoker();
        _ = await InvokeDirectAsync(invoker, TestContext.Current.CancellationToken);
        fixture.NextInvokeResponseError = responseError;

        BrokerException ambiguous = await Assert.ThrowsAsync<BrokerException>(() => InvokeDirectAsync(invoker, TestContext.Current.CancellationToken));
        Assert.Equal("gateway_outcome_ambiguous", ambiguous.Code);
        Assert.False(ambiguous.Retryable);
        Assert.Equal(2, fixture.ExternalDispatchCount);

        fixture.ReturnUnavailableAfterNextInvokeEffect = true;
        BrokerException upstreamAmbiguous = await Assert.ThrowsAsync<BrokerException>(() => InvokeDirectAsync(invoker, TestContext.Current.CancellationToken));
        Assert.Equal("gateway_outcome_ambiguous", upstreamAmbiguous.Code);
        Assert.False(upstreamAmbiguous.Retryable);
        Assert.Equal(3, fixture.ExternalDispatchCount);

        _ = await InvokeDirectAsync(invoker, TestContext.Current.CancellationToken);
        Assert.Equal(4, fixture.ExternalDispatchCount);
    }

    [Fact]
    public async Task Revoked_expired_and_ungranted_Installations_are_denied_before_the_synthetic_effect()
    {
        await using (ContinuityGateway revoked = await ContinuityGateway.CreateAsync(grantEnabled: true))
        {
            using ProductionGatewayInvoker invoker = revoked.CreateInvoker();
            _ = await InvokeDirectAsync(invoker, TestContext.Current.CancellationToken);
            await revoked.RevokeAsync(TestContext.Current.CancellationToken);
            BrokerException denied = await Assert.ThrowsAsync<BrokerException>(() => InvokeDirectAsync(invoker, TestContext.Current.CancellationToken));
            Assert.Equal("gateway_authorization_denied", denied.Code);
            Assert.Equal(1, revoked.ExternalDispatchCount);
        }

        await using (ContinuityGateway expired = await ContinuityGateway.CreateAsync(grantEnabled: true))
        {
            using ProductionGatewayInvoker invoker = expired.CreateInvoker();
            _ = await InvokeDirectAsync(invoker, TestContext.Current.CancellationToken);
            expired.Clock.Advance(TimeSpan.FromDays(91));
            BrokerException denied = await Assert.ThrowsAsync<BrokerException>(() => InvokeDirectAsync(invoker, TestContext.Current.CancellationToken));
            Assert.Equal("gateway_authorization_denied", denied.Code);
            Assert.Equal(1, expired.ExternalDispatchCount);
        }

        await using (ContinuityGateway ungranted = await ContinuityGateway.CreateAsync(grantEnabled: false))
        {
            using ProductionGatewayInvoker invoker = ungranted.CreateInvoker();
            BrokerException denied = await Assert.ThrowsAsync<BrokerException>(() => InvokeDirectAsync(invoker, TestContext.Current.CancellationToken));
            Assert.Equal("gateway_authorization_denied", denied.Code);
            Assert.Equal(0, ungranted.ExternalDispatchCount);
        }
    }

    [Fact]
    public async Task Missing_state_recovers_only_the_registered_identity_while_corrupt_or_fully_lost_state_fails_closed()
    {
        await using ContinuityGateway fixture = await ContinuityGateway.CreateAsync(grantEnabled: true);
        using (ProductionGatewayInvoker enrolled = fixture.CreateInvoker())
        {
            _ = await InvokeDirectAsync(enrolled, TestContext.Current.CancellationToken);
        }
        string statePath = Path.Combine(fixture.DataDirectory, "gateway-installation-state.json");
        string markerPath = Path.Combine(fixture.DataDirectory, "gateway-installation-certificate.thumbprint");
        File.Delete(statePath);

        using (ProductionGatewayInvoker recovered = fixture.CreateInvoker())
        {
            _ = await InvokeDirectAsync(recovered, TestContext.Current.CancellationToken);
        }
        Assert.Equal(1, fixture.ActivationCount);
        Assert.Equal(fixture.InstallationId, fixture.LastInvokedInstallationId);

        await File.WriteAllTextAsync(statePath, "{\"formatVersion\":1,\"currentCertificateThumbprint\":\"foreign\"}", TestContext.Current.CancellationToken);
        using (ProductionGatewayInvoker corrupt = fixture.CreateInvoker())
        {
            BrokerException denied = await Assert.ThrowsAsync<BrokerException>(() => InvokeDirectAsync(corrupt, TestContext.Current.CancellationToken));
            Assert.Equal("gateway_credential_state_invalid", denied.Code);
        }

        File.Delete(statePath);
        File.Delete(markerPath);
        using (ProductionGatewayInvoker lost = fixture.CreateInvoker())
        {
            BrokerException denied = await Assert.ThrowsAsync<BrokerException>(() => InvokeDirectAsync(lost, TestContext.Current.CancellationToken));
            Assert.Equal("gateway_credential_state_unavailable", denied.Code);
        }
        Assert.Equal(1, fixture.ActivationCount);
    }

    private static Task<GatewayInvocationResult> InvokeDirectAsync(ProductionGatewayInvoker invoker, CancellationToken cancellationToken) =>
        invoker.InvokeAsync("legacy-continuity", "sample-secure-service", "submit", "application/json", "{\"message\":\"continuity\"}"u8.ToArray(), Guid.NewGuid(), cancellationToken);

    private static async Task<InvokeGatewayResult> InvokeThroughBrokerAsync(ProductionGatewayInvoker invoker, CancellationToken cancellationToken)
    {
        using TestDirectory brokerData = new();
        string pipeName = "SecureIntegration.Continuity." + Guid.NewGuid().ToString("N");
        string executable = Environment.ProcessPath ?? throw new InvalidOperationException("Test host path unavailable.");
        string executableHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(executable, cancellationToken)));
        ApplicationPolicy policy = new()
        {
            RegistrationId = "legacy-continuity",
            AllowedUserSids = [WindowsIdentity.GetCurrent().User!.Value],
            ExecutablePaths = [executable],
            ExecutableSha256 = [executableHash],
            AllowedOperations = [BrokerOperations.InvokeGateway],
            GatewayGrants = ["sample-secure-service:submit"]
        };
        BrokerOptions options = new() { PipeName = pipeName, InstallationId = "continuity-test", DataDirectory = brokerData.Path, Applications = [policy] };
        WindowsDpapiProtectionProvider protection = new();
        using FileLocalSecretRepository secrets = new(brokerData.Path);
        using FileDataKeyRepository keys = new(brokerData.Path, protection);
        BrokerApplicationService service = new(secrets, protection, new AeadDataProtector(keys, options.InstallationId), new NullAudit(), options.InstallationId, invoker);
        await using NamedPipeBrokerServer server = new(options, new ApplicationAuthorizer(options.Applications), new BrokerRequestDispatcher(service));
        using CancellationTokenSource stopped = new();
        Task running = server.RunAsync(stopped.Token);
        SecurityIdentifier owner = WindowsIdentity.GetCurrent().Owner!;
        byte[] ownerBytes = new byte[owner.BinaryLength];
        owner.GetBinaryForm(ownerBytes, 0);
        BrokerClient client = new(new BrokerClientOptions
        {
            PipeName = pipeName,
            ApplicationRegistrationId = policy.RegistrationId,
            OperationTimeout = TimeSpan.FromSeconds(30)
        }, () => new NamedPipeServerIdentity((uint)Environment.ProcessId, ownerBytes));
        try
        {
            return await client.InvokeGatewayAsync(new InvokeGatewayRequest
            {
                ConnectorId = "sample-secure-service",
                OperationId = "submit",
                ContentType = "application/json",
                PayloadBase64 = Convert.ToBase64String("{\"message\":\"continuity\"}"u8)
            }, cancellationToken);
        }
        finally
        {
            stopped.Cancel();
            await running;
        }
    }

    private sealed class ContinuityGateway : IAsyncDisposable
    {
        private static readonly JsonSerializerOptions WireJson = new(JsonSerializerDefaults.Web);
        private readonly byte[] activationHmacKey = RandomNumberGenerator.GetBytes(32);
        private readonly TestDirectory data = new();
        private readonly InMemoryGatewayRegistry registry;
        private readonly InstallationEnrollmentService enrollment;
        private readonly RuntimeIdentityService identity;
        private RestrictedEgressService runtime = null!;
        private readonly EnrollmentSecurityOptions enrollmentOptions;
        private readonly X509Certificate2 providerCertificate;

        private ContinuityGateway(bool grantEnabled)
        {
            Clock = new MutableGatewayClock(DateTimeOffset.UtcNow);
            registry = new InMemoryGatewayRegistry(Clock);
            enrollmentOptions = new EnrollmentSecurityOptions { ActivationHmacKey = activationHmacKey };
            enrollment = new InstallationEnrollmentService(registry, new InMemoryEnrollmentChallengeStore(), Clock, enrollmentOptions);
            identity = new RuntimeIdentityService(registry, Clock);
            providerCertificate = CreateProviderCertificate();
            GrantEnabled = grantEnabled;
        }

        public MutableGatewayClock Clock { get; }
        public GatewayInstallationOptions Options { get; private set; } = null!;
        public Guid InstallationId { get; private set; }
        public string DataDirectory => data.Path;
        public bool GrantEnabled { get; }
        public HttpRequestError? UnavailableError { get; set; }
        public HttpRequestError? NextRenewalResponseError { get; set; }
        public HttpRequestError? NextInvokeResponseError { get; set; }
        public bool ReturnUnavailableAfterNextInvokeEffect { get; set; }
        public bool PendingCredentialAccepted { get; private set; }
        public int ActivationCount { get; private set; }
        public int RenewalCount { get; private set; }
        public int ExternalDispatchCount { get; private set; }
        public Guid LastInvokedInstallationId { get; private set; }

        public static async Task<ContinuityGateway> CreateAsync(bool grantEnabled)
        {
            ContinuityGateway fixture = new(grantEnabled);
            Guid tenantId = Guid.NewGuid();
            Guid applicationId = Guid.NewGuid();
            Guid environmentId = Guid.NewGuid();
            fixture.InstallationId = Guid.NewGuid();
            GatewayProvisioningService provisioning = new(fixture.registry, fixture.Clock, fixture.enrollmentOptions);
            ProvisionedActivation activation = await provisioning.CreateInstallationAsync(
                new(tenantId, "continuity-tenant", "Continuity tenant", TenantStatus.Active, fixture.Clock.UtcNow),
                new(applicationId, "continuity-app", "Continuity app", ApplicationStatus.Active, "1.0.0", null, fixture.Clock.UtcNow),
                new(environmentId, "continuity", "Continuity", false),
                fixture.InstallationId,
                "continuity-test",
                TestContext.Current.CancellationToken);
            if (grantEnabled)
                await fixture.registry.AddGrantAsync(new(Guid.NewGuid(), fixture.InstallationId, tenantId, "sample-secure-service", "submit", true, fixture.Clock.UtcNow), TestContext.Current.CancellationToken);
            fixture.runtime = BuildRuntime(fixture.registry, fixture.Clock, fixture.providerCertificate, new CapturingTransport(fixture), environmentId);
            fixture.Options = new GatewayInstallationOptions
            {
                Enabled = true,
                BaseAddress = "https://continuity-gateway.example.test/",
                ActivationCodeId = activation.ActivationCodeId.ToString("D"),
                ActivationCodeEnvironmentVariable = "BROKER_CONTINUITY_ACTIVATION_" + Guid.NewGuid().ToString("N"),
                CngKeyName = "SecureIntegration.Broker.Continuity." + Guid.NewGuid().ToString("N"),
                BrokerVersion = "1.0.0",
                TimeoutSeconds = 5
            };
            Environment.SetEnvironmentVariable(fixture.Options.ActivationCodeEnvironmentVariable, activation.ActivationCode, EnvironmentVariableTarget.Process);
            return fixture;
        }

        public ProductionGatewayInvoker CreateInvoker() => new(Options, data.Path, certificate => new GatewayHandler(this, certificate), Clock);

        public Task RevokeAsync(CancellationToken cancellationToken) => enrollment.RevokeAsync(InstallationId, "continuity test revocation", cancellationToken);

        private static RestrictedEgressService BuildRuntime(InMemoryGatewayRegistry registry, MutableGatewayClock clock, X509Certificate2 providerCertificate, CapturingTransport transport, Guid environmentId)
        {
            InMemoryConnectorConfigurationStore connectorStore = new();
            CertificatePublicMetadata publicMetadata = new(
                Convert.ToHexString(SHA256.HashData(providerCertificate.RawData)),
                providerCertificate.Subject,
                providerCertificate.Issuer,
                providerCertificate.NotBefore,
                providerCertificate.NotAfter,
                "ECDSA",
                256,
                providerCertificate.SerialNumber);
            connectorStore.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", "vendor-key", ProviderResourceType.Secret, "Vendor key", environmentId, "sample-secure-service", "submit", "synthetic://vendor-key", ProviderResourceStatus.Active, null, 0, null, null, string.Empty, clock.UtcNow), CancellationToken.None).GetAwaiter().GetResult();
            connectorStore.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", "vendor-certificate", ProviderResourceType.ClientCertificate, "Vendor certificate", environmentId, "sample-secure-service", "submit", "synthetic://vendor-certificate", ProviderResourceStatus.Active, null, 0, 1, publicMetadata, string.Empty, clock.UtcNow), CancellationToken.None).GetAwaiter().GetResult();
            ConnectorDefinitionValidator validator = new();
            PublishedConnectorCatalog catalog = new(connectorStore, validator, clock, TimeSpan.FromMinutes(5));
            ConnectorAdministrationService admin = new(connectorStore, validator, catalog, registry, clock, new DevelopmentConnectorApprovalPolicy());
            using JsonDocument sample = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Samples", "sample-secure-service.connector.json")));
            ConnectorVersionResource imported = admin.ImportAsync(sample.RootElement, null, "continuity-test", Guid.NewGuid(), CancellationToken.None).GetAwaiter().GetResult();
            ConnectorVersionResource validated = admin.ValidateStoredAsync(imported.ConnectorId, imported.Version, imported.RowVersion, "continuity-test", Guid.NewGuid(), CancellationToken.None).GetAwaiter().GetResult();
            admin.PutBindingsAsync("sample-secure-service", new(environmentId,
                new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://synthetic.example.test/vendor/orders" },
                new Dictionary<string, ProviderResourceReference> { ["sample-vendor-api-key"] = new("synthetic", "vendor-key", ProviderResourceType.Secret) }, null,
                new Dictionary<string, ProviderResourceReference> { ["sample-vendor-client-certificate"] = new("synthetic", "vendor-certificate", ProviderResourceType.ClientCertificate, PublicMetadataRevision: 1) }),
                "continuity-test", Guid.NewGuid(), CancellationToken.None).GetAwaiter().GetResult();
            admin.PublishAsync(validated.ConnectorId, validated.Version, validated.RowVersion, 0, "continuity-test", Guid.NewGuid(), CancellationToken.None).GetAwaiter().GetResult();
            InMemoryProvider provider = new(
                new Dictionary<string, string> { ["synthetic://vendor-key"] = "continuity-vendor-key" },
                new Dictionary<string, byte[]> { ["synthetic://vendor-certificate"] = providerCertificate.Export(X509ContentType.Pkcs12) });
            return new RestrictedEgressService(registry, catalog, provider, provider, new SyntheticResolver(), transport, clock, new SyntheticDestinationAllowance());
        }

        private static X509Certificate2 CreateProviderCertificate()
        {
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            CertificateRequest request = new("CN=continuity-provider", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.2") }, true));
            using X509Certificate2 created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
            return X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);
        }

        public ValueTask DisposeAsync()
        {
            Environment.SetEnvironmentVariable(Options.ActivationCodeEnvironmentVariable, null, EnvironmentVariableTarget.Process);
            HashSet<string> keyNames = new(StringComparer.Ordinal);
            using (X509Store store = new(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadWrite);
                foreach (X509Certificate2 certificate in store.Certificates.Cast<X509Certificate2>().Where(item => string.Equals(item.Subject, $"CN=SecureIntegration Installation {Options.ActivationCodeId}", StringComparison.Ordinal)).ToArray())
                {
                    try
                    {
                        using ECDsa? key = certificate.GetECDsaPrivateKey();
                        if (key is ECDsaCng cng && cng.Key.KeyName is { Length: > 0 } name && name.StartsWith(Options.CngKeyName[..Math.Min(Options.CngKeyName.Length, 159)], StringComparison.Ordinal)) keyNames.Add(name);
                    }
                    catch (CryptographicException) { }
                    store.Remove(certificate);
                    certificate.Dispose();
                }
            }
            foreach (string keyName in keyNames)
            {
                if (!CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider)) continue;
                using CngKey key = CngKey.Open(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
                key.Delete();
            }
            CryptographicOperations.ZeroMemory(activationHmacKey);
            providerCertificate.Dispose();
            data.Dispose();
            return ValueTask.CompletedTask;
        }

        private sealed class GatewayHandler(ContinuityGateway fixture, X509Certificate2? certificate) : HttpMessageHandler
        {
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                if (fixture.UnavailableError is { } unavailableError) throw new HttpRequestException(unavailableError, "Synthetic Gateway is unavailable.");
                byte[] body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
                string path = request.RequestUri!.AbsolutePath;
                try
                {
                    if (path == "/v1/enrollments/challenges")
                        return Json(await fixture.enrollment.CreateChallengeAsync(Deserialize<EnrollmentChallengeRequest>(body), cancellationToken));
                    if (path == "/v1/enrollments:activate")
                    {
                        EnrollmentResult result = await fixture.enrollment.ActivateAsync(Deserialize<SecureIntegration.Gateway.Application.ActivationRequest>(body), cancellationToken);
                        fixture.ActivationCount++;
                        return Json(result);
                    }

                    Guid correlationId = Guid.NewGuid();
                    GatewayInvokeRequest? invoke = null;
                    if (path.StartsWith("/v1/connectors/", StringComparison.Ordinal))
                    {
                        invoke = Deserialize<GatewayInvokeRequest>(body);
                        correlationId = invoke.CorrelationId;
                    }
                    GatewayClientPrincipal principal = await AuthenticateAsync(request, body, correlationId, cancellationToken);
                    if (path == "/v1/broker-policy")
                    {
                        return Json(fixture.enrollment.GetBrokerPolicy(principal.Identity));
                    }
                    if (path == "/v1/enrollments:renew")
                    {
                        EnrollmentResult result = await fixture.enrollment.RenewAsync(principal.Identity, Deserialize<RenewalRequest>(body), cancellationToken);
                        fixture.RenewalCount++;
                        fixture.PendingCredentialAccepted = true;
                        if (fixture.NextRenewalResponseError is { } renewalError)
                        {
                            fixture.NextRenewalResponseError = null;
                            throw new HttpRequestException(renewalError, "Synthetic response was lost after commit.");
                        }
                        return Json(result);
                    }
                    if (invoke is not null)
                    {
                        string[] segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
                        string connectorId = segments[2];
                        string operationId = segments[4][..^":invoke".Length];
                        GatewayInvokeResponse result = await fixture.runtime.InvokeAsync(principal, connectorId, operationId, invoke, cancellationToken);
                        fixture.LastInvokedInstallationId = principal.InstallationId;
                        if (fixture.NextInvokeResponseError is { } invokeError)
                        {
                            fixture.NextInvokeResponseError = null;
                            throw new HttpRequestException(invokeError, "Synthetic response was lost after dispatch.");
                        }
                        if (fixture.ReturnUnavailableAfterNextInvokeEffect)
                        {
                            fixture.ReturnUnavailableAfterNextInvokeEffect = false;
                            return Json(new { code = "BGW-EGRESS-UPSTREAM-REJECTED", retryable = true }, HttpStatusCode.ServiceUnavailable);
                        }
                        return Json(result);
                    }
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
                }
                catch (GatewayException failure)
                {
                    return Json(new { code = failure.Code }, (HttpStatusCode)failure.StatusCode);
                }
            }

            private Task<GatewayClientPrincipal> AuthenticateAsync(HttpRequestMessage request, byte[] body, Guid correlationId, CancellationToken cancellationToken)
            {
                RuntimeSignatureHeaders headers = new(
                    Header(request, "X-BG-Timestamp"),
                    Header(request, "X-BG-Nonce"),
                    Header(request, "X-BG-Content-SHA256"),
                    Header(request, "X-BG-Signature"));
                return fixture.identity.AuthenticateAsync(certificate, request.Method.Method, request.RequestUri!.PathAndQuery, headers, body, correlationId, cancellationToken);
            }

            private static string Header(HttpRequestMessage request, string name) => request.Headers.TryGetValues(name, out IEnumerable<string>? values) ? values.Single() : string.Empty;
            private static T Deserialize<T>(byte[] body) => JsonSerializer.Deserialize<T>(body, WireJson) ?? throw new InvalidOperationException("Synthetic request was empty.");
            private static HttpResponseMessage Json<T>(T value, HttpStatusCode status = HttpStatusCode.OK) => new(status)
            {
                Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value, WireJson)) { Headers = { ContentType = new("application/json") } }
            };
        }

        private sealed class CapturingTransport(ContinuityGateway fixture) : IRestrictedTransport
        {
            public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
            {
                Assert.Equal("continuity-vendor-key", request.Headers.GetValues("X-Vendor-Api-Key").Single());
                Assert.NotNull(clientCertificate);
                fixture.ExternalDispatchCount++;
                return Task.FromResult(new ExternalResponse(200, "application/json", "{\"accepted\":true}"u8.ToArray()));
            }
        }

        private sealed class SyntheticResolver : IHostResolver
        {
            public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { IPAddress.Parse("203.0.113.10") });
        }

        private sealed class SyntheticDestinationAllowance : IPrivateDestinationAllowance
        {
            public bool IsAllowed(string host, IPAddress address) => string.Equals(host, "synthetic.example.test", StringComparison.Ordinal) && address.Equals(IPAddress.Parse("203.0.113.10"));
        }
    }

    private sealed class MutableGatewayClock(DateTimeOffset now) : TimeProvider, IGatewayClock
    {
        public DateTimeOffset UtcNow { get; private set; } = now;
        public override DateTimeOffset GetUtcNow() => UtcNow;
        public void Advance(TimeSpan value) => UtcNow = UtcNow.Add(value);
    }

    private sealed class NullAudit : IBrokerAuditSink
    {
        public Task WriteAsync(string operation, string applicationId, Guid correlationId, bool succeeded, string? errorCode, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class TestDirectory : IDisposable
    {
        public TestDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "broker-gateway-continuity", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }
        public string Path { get; }
        public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true); }
    }
}

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.M6.SyntheticSoapServer;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests.ConnectorRuntime.Auth.Soap;

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class ProductionComposedSoapRuntimeIntegrationTests
{
    [Fact]
    public async Task Wave1_E2E_PostgreSQL18_schema_four_eyes_publish_authenticated_grant_strategy_and_real_HTTPS_composed_dispatch_when_configured()
    {
        await using ProductionFixture fixture = await ProductionFixture.CreateAsync("success");

        GatewayInvokeResponse response = await fixture.InvokeAsync();

        Assert.Equal("1.0.0", response.ConnectorVersion);
        Assert.Equal(1, fixture.Transport.SoapCalls);
        Assert.Equal(0, fixture.Transport.GenericCalls);
        Assert.Equal(1, fixture.Server.Counters.Composed);
        Assert.Equal(1, fixture.Server.Counters.ComposedAccepted);
        Assert.Equal(2, fixture.Secrets.Calls);
        Assert.Contains("BusinessOperationResponse", Encoding.UTF8.GetString(Convert.FromBase64String(response.Result.Data)), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("invalid-grant")]
    [InlineData("basic-disabled")]
    [InlineData("basic-rotated")]
    [InlineData("stale-session")]
    [InlineData("policy-update")]
    [InlineData("endpoint-substitution")]
    [InlineData("wrong-soap-action")]
    [InlineData("wrong-capability-mode")]
    [InlineData("ssrf")]
    [InlineData("rotate-final-window")]
    public async Task Wave1_E2E_security_mutations_deny_on_the_real_store_runtime_path_before_network(string mutation)
    {
        await using ProductionFixture fixture = await ProductionFixture.CreateAsync(mutation);

        GatewayException failure = await Assert.ThrowsAsync<GatewayException>(() => fixture.InvokeAsync());

        string expected = mutation switch
        {
            "invalid-grant" => "BGW-AUTHZ-OPERATION-DENIED",
            "ssrf" => "BGW-EGRESS-DESTINATION-DENIED",
            "basic-disabled" or "basic-rotated" => "BGW-PROVIDER-RESOURCE-REVISION-STALE",
            _ => "BGW-EGRESS-AUTHENTICATION"
        };
        Assert.Equal(expected, failure.Code);
        Assert.Equal(0, fixture.Transport.SoapCalls);
        Assert.Equal(0, fixture.Transport.GenericCalls);
        Assert.Equal(0, fixture.Server.Counters.Composed);
    }

    private sealed class ProductionFixture : IAsyncDisposable
    {
        internal const string Username = "production-e2e-user";
        internal const string Password = "synthetic-production-e2e-password";
        private const string UpstreamSession = "production-e2e-opaque-session";
        private const string ConnectorOperation = "dispatch";
        private const string Policy = "production-composed-policy";
        private const string Profile = "production-session-profile";
        private const string Action = "urn:synthetic:BusinessOperation";
        private readonly SoapSessionCacheKey sessionKey;
        private readonly GatewayClientPrincipal principal;
        private readonly RestrictedEgressService runtime;
        private readonly AdminPostgresDataSource adminPool;
        private readonly NpgsqlDataSource runtimePool;
        private readonly AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole;
        private readonly CertificateFixture certificates;

        private ProductionFixture(
            SoapSessionCacheKey sessionKey,
            GatewayClientPrincipal principal,
            RestrictedEgressService runtime,
            AdminPostgresDataSource adminPool,
            NpgsqlDataSource runtimePool,
            AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole,
            CertificateFixture certificates,
            SyntheticSoapServerInstance server,
            CountingRestrictedTransport transport,
            ProductionSecrets secrets)
        {
            this.sessionKey = sessionKey;
            this.principal = principal;
            this.runtime = runtime;
            this.adminPool = adminPool;
            this.runtimePool = runtimePool;
            this.runtimeRole = runtimeRole;
            this.certificates = certificates;
            Server = server;
            Transport = transport;
            Secrets = secrets;
        }

        internal SyntheticSoapServerInstance Server { get; }
        internal CountingRestrictedTransport Transport { get; }
        internal ProductionSecrets Secrets { get; }

        internal static async Task<ProductionFixture> CreateAsync(string mutation)
        {
            string? adminConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
            if (string.IsNullOrWhiteSpace(adminConnection)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
            string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
            if (string.IsNullOrWhiteSpace(migrationConnection)) Assert.Skip("PostgreSQL migration connection is not configured; the dedicated PostgreSQL gate must provide it.");
            await PostgresIsolationTests.ApplyMigrationAsync();

            CertificateFixture certificates = CertificateFixture.Create();
            SyntheticSoapServerInstance? server = null;
            AdminPostgresDataSource? adminPool = null;
            NpgsqlDataSource? runtimePool = null;
            AdminApiSecurityTests.PostgresRuntimeRoleLease? runtimeRole = null;
            try
            {
                server = await SyntheticSoapServerHost.StartAsync(new(Username, Password, false, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(2))
                {
                    OpaqueSessionHeaderName = "X-Session-Reference",
                    OpaqueSessionValue = UpstreamSession
                }, certificates.Server, TestContext.Current.CancellationToken);
                Uri publishedEndpoint = new UriBuilder(server.Endpoint) { Host = "composed.synthetic.test" }.Uri;

                adminPool = new(adminConnection);
                runtimeRole = await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(
                    adminConnection, migrationConnection, TestContext.Current.CancellationToken);
                runtimePool = NpgsqlDataSource.Create(runtimeRole.ConnectionString);
                RoutingConnectorConfigurationStore store = new(adminPool, runtimePool);
                PostgresGatewayRegistry registry = new(adminPool.Value);
                PostgresAdminSecurityStore security = new(adminPool);
                RuntimeClock clock = new(DateTimeOffset.UtcNow);
                ConnectorDefinitionValidator validator = new();
                PublishedConnectorCatalog catalog = new(store, validator, clock, TimeSpan.FromMinutes(5));
                ConnectorAdministrationService admin = new(store, validator, catalog, registry, clock, new FourEyesConnectorApprovalPolicy(security));

                string suffix = Guid.NewGuid().ToString("N");
                string connectorId = "composed-e2e-" + suffix;
                Guid tenantId = Guid.NewGuid(); Guid applicationId = Guid.NewGuid(); Guid environmentId = Guid.NewGuid(); Guid installationId = Guid.NewGuid();
                await registry.AddTenantAsync(new(tenantId, "cw1-t-" + suffix, "Composed E2E", TenantStatus.Active, clock.UtcNow), TestContext.Current.CancellationToken);
                await registry.AddApplicationAsync(new(applicationId, "cw1-a-" + suffix, "Composed E2E", ApplicationStatus.Active, "3.0.0", null, clock.UtcNow), TestContext.Current.CancellationToken);
                await registry.AddEnvironmentAsync(new(environmentId, "cw1-e-" + suffix[..20], "Composed E2E", false), TestContext.Current.CancellationToken);
                await registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "3.0.0", clock.UtcNow), TestContext.Current.CancellationToken);
                if (mutation != "invalid-grant")
                    await registry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, connectorId, ConnectorOperation, true, clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);

                ProviderResourceCatalogRecord username = await ResourceAsync(store, environmentId, connectorId, suffix, "basic-username", "provider://username-" + suffix, clock.UtcNow);
                ProviderResourceCatalogRecord password = await ResourceAsync(store, environmentId, connectorId, suffix, "basic-password", "provider://password-" + suffix, clock.UtcNow);
                ProviderResourceCatalogRecord session = await ResourceAsync(store, environmentId, connectorId, suffix, "session-secret", "provider://session-" + suffix, clock.UtcNow);
                AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new("https://composed-e2e.invalid", "editor-" + suffix, "Editor", null), TestContext.Current.CancellationToken);
                AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new("https://composed-e2e.invalid", "approver-" + suffix, "Approver", null), TestContext.Current.CancellationToken);

                const string initialKind = "soapBasicOpaqueSession";
                PublishedVersion initial = await ImportApprovePublishAsync(store, security, admin, editor, approver, connectorId, "1.0.0", 0, environmentId,
                    publishedEndpoint, initialKind, Policy, Action, username, password, session, clock.UtcNow, publish: true);

                PublishedConnectorAccessContext? access = mutation == "invalid-grant" ? null : new(installationId, tenantId, applicationId, ConnectorOperation);
                PublishedConnectorSnapshot snapshot = await store.GetPublishedSnapshotAsync(connectorId, environmentId, access, TestContext.Current.CancellationToken)
                    ?? throw new InvalidOperationException("Published composed snapshot missing.");
                SoapSessionCache cache = new();
                SoapSessionCacheKey sessionKey = new(tenantId, installationId, applicationId, environmentId, connectorId, "1.0.0", snapshot.Bindings.Revision,
                    snapshot.Bindings.Revision, session.Revision, Profile);
                OpaqueSoapSessionReference sessionReference = cache.Store(sessionKey, UpstreamSession, clock.UtcNow, clock.UtcNow.AddMinutes(10));

                Func<CancellationToken, Task>? finalHook = null;
                if (mutation is "policy-update" or "endpoint-substitution" or "wrong-soap-action")
                {
                    Uri nextEndpoint = mutation == "endpoint-substitution" ? new("https://substituted.example.test/") : publishedEndpoint;
                    string nextPolicy = mutation == "policy-update" ? "changed-composed-policy" : Policy;
                    string nextAction = mutation == "wrong-soap-action" ? "urn:synthetic:ChangedAction" : Action;
                    PublishedVersion next = await ImportApprovePublishAsync(store, security, admin, editor, approver, connectorId, "2.0.0", 1, environmentId,
                        nextEndpoint, "soapBasicOpaqueSession", nextPolicy, nextAction, username, password, session, clock.UtcNow.AddSeconds(1), publish: false);
                    finalHook = token => admin.PublishAsync(connectorId, "2.0.0", next.ValidatedRowVersion, 1, approver.Id.ToString("D"), Guid.NewGuid(), token);
                }
                else if (mutation == "rotate-final-window")
                {
                    finalHook = async token => _ = await store.RegisterProviderResourceAsync(username with
                    {
                        Id = Guid.NewGuid(), ProviderReference = "provider://username-final-rotated-" + suffix, Revision = 0,
                        ChecksumSha256 = string.Empty, CreatedAt = clock.UtcNow.AddSeconds(2)
                    }, token);
                }

                if (mutation == "stale-session") cache.Invalidate(sessionKey, sessionReference);
                if (mutation is "basic-disabled" or "basic-rotated")
                    _ = await store.RegisterProviderResourceAsync(username with
                    {
                        Id = Guid.NewGuid(), ProviderReference = "provider://username-pre-rotated-" + suffix,
                        Status = mutation == "basic-disabled" ? ProviderResourceStatus.Disabled : ProviderResourceStatus.Active,
                        Revision = 0, ChecksumSha256 = string.Empty, CreatedAt = clock.UtcNow.AddSeconds(2)
                    }, TestContext.Current.CancellationToken);

                ProductionSecrets secrets = new(username.ProviderReference, password.ProviderReference);
                SystemRestrictedTransport systemTransport = new(new X509Certificate2Collection(certificates.Root), Convert.ToHexString(SHA256.HashData(certificates.Server.RawData)));
                CountingRestrictedTransport transport = new(systemTransport);
                LoopbackResolver resolver = new();
                IPrivateDestinationAllowance? allowance = mutation == "ssrf" ? null : new ExactLoopbackAllowance(publishedEndpoint.DnsSafeHost);
                OpaqueSessionLeaseProvider leases = new SoapOpaqueSessionLeaseProvider(cache);
                ComposedSoapExecutionStrategy composed = new(store, secrets, leases, resolver, transport, clock, allowance, finalHook);
                IConnectorExecutionStrategy[] strategies = mutation == "wrong-capability-mode"
                    ? [new OpaqueSessionHttpExecutionStrategy(store, leases, resolver, transport, clock, allowance)]
                    : [composed];
                RestrictedEgressService runtime = new(registry, catalog, secrets, new NeverCertificates(), resolver, transport, clock, allowance, strategies);
                RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
                    Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddHours(1), "3.0.0", null);
                GatewayClientPrincipal principal = new(identity, Guid.NewGuid());
                return new(sessionKey, principal, runtime,
                    adminPool, runtimePool, runtimeRole, certificates, server, transport, secrets);
            }
            catch
            {
                if (runtimePool is not null) await runtimePool.DisposeAsync();
                if (runtimeRole is not null) await runtimeRole.DisposeAsync();
                if (adminPool is not null) await adminPool.DisposeAsync();
                if (server is not null) await server.DisposeAsync();
                certificates.Dispose();
                throw;
            }
        }

        internal Task<GatewayInvokeResponse> InvokeAsync()
        {
            string envelope = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><op:BusinessOperation xmlns:op=\"urn:synthetic:session\"><op:Payload>production</op:Payload></op:BusinessOperation></soap:Body></soap:Envelope>";
            GatewayInvokeRequest request = new("1.0", new("text/xml", "utf8", envelope), principal.CorrelationId);
            return runtime.InvokeAsync(principal, sessionKey.ConnectorId, ConnectorOperation, request, TestContext.Current.CancellationToken);
        }

        public async ValueTask DisposeAsync()
        {
            await Server.DisposeAsync();
            await runtimePool.DisposeAsync();
            await runtimeRole.DisposeAsync();
            await adminPool.DisposeAsync();
            certificates.Dispose();
        }

        private static async Task<ProviderResourceCatalogRecord> ResourceAsync(
            RoutingConnectorConfigurationStore store, Guid environmentId, string connectorId, string suffix, string resourceId, string providerReference, DateTimeOffset now)
        {
            return await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", resourceId + "-" + suffix,
                ProviderResourceType.Secret, resourceId, environmentId, connectorId, ConnectorOperation, providerReference, ProviderResourceStatus.Active, null, 0, null, null,
                string.Empty, now), TestContext.Current.CancellationToken);
        }

        private static async Task<PublishedVersion> ImportApprovePublishAsync(
            RoutingConnectorConfigurationStore store,
            PostgresAdminSecurityStore security,
            ConnectorAdministrationService admin,
            AdminPrincipalRecord editor,
            AdminPrincipalRecord approver,
            string connectorId,
            string version,
            long publicationRevision,
            Guid environmentId,
            Uri endpoint,
            string authenticationKind,
            string policyId,
            string action,
            ProviderResourceCatalogRecord username,
            ProviderResourceCatalogRecord password,
            ProviderResourceCatalogRecord session,
            DateTimeOffset now,
            bool publish)
        {
            string auth = authenticationKind == "soapBasicOpaqueSession"
                ? $$$"""{"kind":"soapBasicOpaqueSession","policyId":"{{{policyId}}}","sessionProfileId":"{{{Profile}}}","usernameBinding":"basic-username","passwordBinding":"basic-password","secretBinding":"session-secret","headerName":"X-Session-Reference","valueFormat":"rawOpaqueValue","soapHttp":{"version":"1.1","action":"{{{action}}}"}}"""
                : $$$"""{"kind":"opaqueSessionHttp","policyId":"{{{policyId}}}","sessionProfileId":"{{{Profile}}}","secretBinding":"session-secret","headerName":"X-Session-Reference","valueFormat":"rawOpaqueValue"}""";
            string contentType = authenticationKind == "soapBasicOpaqueSession" ? "text/xml" : "application/json";
            using JsonDocument definition = JsonDocument.Parse($$$"""
            {
              "schemaVersion":"1.0","connectorId":"{{{connectorId}}}","version":"{{{version}}}","displayName":"Production composed E2E",
              "bindings":{"endpoints":[{"name":"service"}],"secrets":[{"name":"basic-username","kind":"username"},{"name":"basic-password","kind":"password"},{"name":"session-secret","kind":"opaque"}]},
              "operations":[{"operationId":"{{{ConnectorOperation}}}","endpointBinding":"service","method":"POST","path":"/composed","request":{"contentType":"{{{contentType}}}","maximumBytes":1048576},"response":{"maximumBytes":1048576},"authentication":{{{auth}}},"timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[]}]
            }
            """);
            ConnectorVersionResource imported = await admin.ImportAsync(definition.RootElement, null, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
            ConnectorVersionResource validated = await admin.ValidateStoredAsync(connectorId, version, imported.RowVersion, editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
            string endpointBase = endpoint.GetLeftPart(UriPartial.Authority) + "/";
            _ = await admin.PutBindingsAsync(connectorId, new(environmentId, new Dictionary<string, string> { ["service"] = endpointBase },
                new Dictionary<string, ProviderResourceReference>
                {
                    ["basic-username"] = new(username.ProviderId, username.ResourceId, username.ResourceType, username.Version),
                    ["basic-password"] = new(password.ProviderId, password.ResourceId, password.ResourceType, password.Version),
                    ["session-secret"] = new(session.ProviderId, session.ResourceId, session.ResourceType, session.Version)
                }, null, null, version), editor.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
            ConnectorVersionRecord stored = await store.GetVersionAsync(connectorId, version, TestContext.Current.CancellationToken) ?? throw new InvalidOperationException();
            byte[] digest = await store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
            ConnectorApprovalRecord request = await security.RequestApprovalAsync(stored, digest, editor.Id, Guid.NewGuid(), now, TestContext.Current.CancellationToken);
            _ = await store.ApproveCanonicalAsync(security, request.Id, stored.Id, Convert.ToHexString(digest), stored.CreatedBy, approver.Id, null, Guid.NewGuid(), now.AddMilliseconds(1), TestContext.Current.CancellationToken);
            if (publish) _ = await admin.PublishAsync(connectorId, version, validated.RowVersion, publicationRevision, approver.Id.ToString("D"), Guid.NewGuid(), TestContext.Current.CancellationToken);
            return new(validated.RowVersion);
        }
    }

    private sealed record PublishedVersion(long ValidatedRowVersion);

    private sealed class ProductionSecrets(string usernameReference, string passwordReference) : ISecretValueProvider
    {
        public int Calls { get; private set; }
        public Task<string> GetSecretAsync(string providerReference, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            if (string.Equals(providerReference, usernameReference, StringComparison.Ordinal)) return Task.FromResult(ProductionFixture.Username);
            if (string.Equals(providerReference, passwordReference, StringComparison.Ordinal)) return Task.FromResult(ProductionFixture.Password);
            throw new InvalidOperationException("Unexpected provider reference.");
        }
    }

    private sealed class NeverCertificates : IClientCertificateProvider
    {
        public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken) => throw new InvalidOperationException();
    }

    private sealed class LoopbackResolver : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { IPAddress.Loopback });
    }

    private sealed class ExactLoopbackAllowance(string host) : IPrivateDestinationAllowance
    {
        public bool IsAllowed(string candidateHost, IPAddress address) => string.Equals(host, candidateHost, StringComparison.OrdinalIgnoreCase) && IPAddress.IsLoopback(address);
    }

    private sealed class CountingRestrictedTransport(IRestrictedTransport inner) : IRestrictedTransport
    {
        public int GenericCalls { get; private set; }
        public int SoapCalls { get; private set; }

        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate,
            TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            GenericCalls++;
            return inner.SendAsync(request, approvedAddresses, clientCertificate, timeout, maximumResponseBytes, cancellationToken);
        }

        public Task<ExternalResponse> SendSoapAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, TimeSpan timeout,
            long maximumResponseBytes, CancellationToken cancellationToken)
        {
            SoapCalls++;
            return inner.SendSoapAsync(request, approvedAddresses, timeout, maximumResponseBytes, cancellationToken);
        }
    }

    private sealed class RuntimeClock(DateTimeOffset now) : IGatewayClock
    {
        public DateTimeOffset UtcNow { get; } = now;
    }

    private sealed class CertificateFixture(X509Certificate2 root, X509Certificate2 server) : IDisposable
    {
        internal X509Certificate2 Root { get; } = root;
        internal X509Certificate2 Server { get; } = server;

        internal static CertificateFixture Create()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            using RSA rootKey = RSA.Create(2048);
            CertificateRequest rootRequest = new("CN=Production Composed E2E Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            X509Certificate2 root = rootRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
            using RSA serverKey = RSA.Create(2048);
            CertificateRequest serverRequest = new("CN=127.0.0.1", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true));
            SubjectAlternativeNameBuilder san = new();
            san.AddIpAddress(IPAddress.Loopback);
            san.AddDnsName("composed.synthetic.test");
            serverRequest.CertificateExtensions.Add(san.Build());
            using X509Certificate2 publicServer = serverRequest.Create(root, now.AddMinutes(-1), now.AddMinutes(30), RandomNumberGenerator.GetBytes(16));
            using X509Certificate2 serverWithKey = publicServer.CopyWithPrivateKey(serverKey);
            X509Certificate2 server = X509CertificateLoader.LoadPkcs12(serverWithKey.Export(X509ContentType.Pkcs12), null,
                X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
            return new(root, server);
        }

        public void Dispose() { Server.Dispose(); Root.Dispose(); }
    }
}

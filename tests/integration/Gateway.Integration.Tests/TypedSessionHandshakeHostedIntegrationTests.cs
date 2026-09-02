using System.Collections;
using System.Globalization;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.M6.SyntheticSoapServer;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class TypedSessionHandshakeHostedIntegrationTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task Wave1_IT_PRODUCTION_HOST_authenticated_routes_store_registry_admission_replay_and_session_use()
    {
        string? adminConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(adminConnection)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(migrationConnection)) Assert.Skip("PostgreSQL migration connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await PostgresIsolationTests.ApplyMigrationAsync();
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole =
            await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(adminConnection, migrationConnection, TestContext.Current.CancellationToken);

        const string candidate = "hosted-external-candidate-canary";
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(candidate, runtimeConnection: runtimeRole.ConnectionString,
            adminConnection: adminConnection);
        Assert.IsType<RoutingConnectorConfigurationStore>(fixture.Store);
        Assert.Same(fixture.Sessions.OpaqueSessionLeases, fixture.Factory.Services.GetRequiredService<OpaqueSessionLeaseProvider>());
        string connectorId = "typed-hosted-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantA = await fixture.CreateTenantAsync("tenant-a");
        Guid tenantB = await fixture.CreateTenantAsync("tenant-b");
        Guid applicationA = await fixture.CreateApplicationAsync("application-a");
        Guid applicationB = await fixture.CreateApplicationAsync("application-b");

        HostedConnectorAuthority approved = await fixture.PrepareConnectorVersionAsync(connectorId, "1.0.0", environmentId);
        await fixture.PublishAsync(approved, expectedPublicationRevision: 0);
        HostedIdentity identityA = await fixture.EnrollIdentityAsync(tenantA, applicationA, environmentId, "identity-a");
        HostedIdentity crossTenant = await fixture.EnrollIdentityAsync(tenantB, applicationA, environmentId, "identity-cross-tenant");
        HostedIdentity crossApplication = await fixture.EnrollIdentityAsync(tenantA, applicationB, environmentId, "identity-cross-application");
        HostedIdentity crossInstallation = await fixture.EnrollIdentityAsync(tenantA, applicationA, environmentId, "identity-cross-installation");
        await fixture.GrantAsync(connectorId, identityA, crossTenant, crossApplication, crossInstallation);
        foreach (HostedIdentity granted in new[] { identityA, crossTenant, crossApplication, crossInstallation })
            Assert.True(await fixture.Factory.Services.GetRequiredService<IGatewayRegistry>().IsGrantedAsync(
                granted.Identity.InstallationId, granted.Identity.TenantId, connectorId, "session-bootstrap", fixture.Factory.Clock.UtcNow,
                TestContext.Current.CancellationToken));

        TypedSessionHandshakeAdapterRegistry adapters = fixture.Factory.Services.GetRequiredService<TypedSessionHandshakeAdapterRegistry>();
        Assert.Equal("SyntheticTypedSessionRequestAdapter", adapters.Request("synthetic-create-session-request", "compiled-typed-request").Adapter.GetType().Name);
        Assert.Equal("SyntheticTypedSessionResponseAdapter", adapters.Response("synthetic-create-session-response", "compiled-typed-response").GetType().Name);
        Assert.Equal("SyntheticExternalSessionValidationAdapter", adapters.Validation("synthetic-session-validator", "compiled-typed-validator")!.Adapter.GetType().Name);

        using HttpResponseMessage acquireResponse = await fixture.SendSignedAsync(identityA, HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/session-bootstrap/session-handshakes/typed-session:acquire", []);
        string acquireBody = await acquireResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, acquireResponse.StatusCode);
        Assert.True(acquireResponse.Headers.Contains("X-Correlation-ID"));
        HostedHandshakeResult acquired = HostedHandshakeResult.Parse(acquireBody);
        Assert.Equal("ExternalAdmissionRequired", acquired.Kind);
        Assert.False(string.IsNullOrWhiteSpace(acquired.IntentReference));
        Assert.DoesNotContain(candidate, acquireBody, StringComparison.Ordinal);
        Assert.Equal(1, fixture.Transport.TotalSoapRequests);
        Assert.Equal(0, fixture.Transport.ValidationRequests);
        Assert.Equal(1, fixture.Server.Counters.CreateSession);
        Assert.Equal(0, fixture.Server.Counters.ValidateSession);

        foreach (HostedIdentity mismatch in new[] { crossTenant, crossApplication, crossInstallation })
        {
            using HttpResponseMessage denied = await fixture.SendSignedAsync(mismatch, HttpMethod.Post,
                $"/v1/session-admissions/{acquired.IntentReference}:complete", Encoding.UTF8.GetBytes(candidate));
            string deniedBody = await denied.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.InternalServerError, denied.StatusCode);
            Assert.Contains("BGW-INTERNAL", deniedBody, StringComparison.Ordinal);
            Assert.DoesNotContain(candidate, deniedBody, StringComparison.Ordinal);
            Assert.Equal(0, fixture.Transport.ValidationRequests);
            Assert.Equal(0, fixture.Server.Counters.ValidateSession);
            Assert.Equal(0, fixture.Sessions.CachedSessionCount);
        }

        using HttpResponseMessage completionResponse = await fixture.SendSignedAsync(identityA, HttpMethod.Post,
            $"/v1/session-admissions/{acquired.IntentReference}:complete", Encoding.UTF8.GetBytes(candidate));
        string completionBody = await completionResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, completionResponse.StatusCode);
        HostedHandshakeResult completed = HostedHandshakeResult.Parse(completionBody);
        Assert.Equal("Issued", completed.Kind);
        Assert.False(string.IsNullOrWhiteSpace(completed.SessionReference));
        Assert.DoesNotContain(candidate, completionBody, StringComparison.Ordinal);
        Assert.Equal(1, fixture.Transport.ValidationRequests);
        Assert.Equal(1, fixture.Server.Counters.ValidateSession);
        Assert.Equal(1, fixture.Sessions.CachedSessionCount);

        long promotedGeneration = fixture.CaptureCurrentSessionGeneration();
        int acquisitionBeforeBusiness = fixture.Transport.AcquisitionRequests;
        int validationBeforeBusiness = fixture.Transport.ValidationRequests;
        int businessBefore = fixture.Transport.BusinessRequests;
        int genericBefore = fixture.Transport.GenericRequests;
        int secretResolutionsBefore = fixture.Factory.Secrets.TotalRequests;

        int outboundBeforeReuse = fixture.Transport.TotalSoapRequests;
        using HttpResponseMessage reuseResponse = await fixture.SendSignedAsync(identityA, HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/session-bootstrap/session-handshakes/typed-session:acquire", []);
        string reuseBody = await reuseResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, reuseResponse.StatusCode);
        HostedHandshakeResult reused = HostedHandshakeResult.Parse(reuseBody);
        Assert.Equal(completed.SessionReference, reused.SessionReference);
        Assert.Equal(outboundBeforeReuse, fixture.Transport.TotalSoapRequests);

        byte[] businessRequest = HostedTypedSessionFixture.BusinessInvocationBody();
        using HttpResponseMessage businessResponse = await fixture.SendSignedAsync(identityA, HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/{HostedTypedSessionFixture.BusinessOperationId}:invoke", businessRequest);
        string businessBody = await businessResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        string businessProblemCode = businessResponse.StatusCode == HttpStatusCode.OK
            ? "none"
            : JsonDocument.Parse(businessBody).RootElement.GetProperty("code").GetString() ?? "missing";
        Assert.True(businessResponse.StatusCode == HttpStatusCode.OK,
            $"Hosted business invocation failed safely: status={(int)businessResponse.StatusCode}, code={businessProblemCode}, " +
            $"acquisition={fixture.Transport.AcquisitionRequests}, validation={fixture.Transport.ValidationRequests}, " +
            $"business={fixture.Transport.BusinessRequests}, generic={fixture.Transport.GenericRequests}, secretResolutions={fixture.Factory.Secrets.TotalRequests}.");
        GatewayInvokeResponse business = JsonSerializer.Deserialize<GatewayInvokeResponse>(businessBody, WebJson)
            ?? throw new InvalidOperationException("Hosted business response was empty.");
        Assert.Equal("1.0.0", business.ConnectorVersion);
        Assert.Contains("BusinessOperationResponse", Encoding.UTF8.GetString(Convert.FromBase64String(business.Result.Data)), StringComparison.Ordinal);
        Assert.Equal(promotedGeneration, fixture.CaptureCurrentSessionGeneration());
        Assert.Equal(acquisitionBeforeBusiness, fixture.Transport.AcquisitionRequests);
        Assert.Equal(validationBeforeBusiness, fixture.Transport.ValidationRequests);
        Assert.Equal(businessBefore + 1, fixture.Transport.BusinessRequests);
        Assert.Equal(genericBefore, fixture.Transport.GenericRequests);
        Assert.Equal(secretResolutionsBefore + 2, fixture.Factory.Secrets.TotalRequests);
        Assert.Equal(1, fixture.Factory.AuthenticatedBusinessRequests);
        Assert.Equal(1, fixture.Server.Counters.Composed);
        Assert.Equal(1, fixture.Server.Counters.ComposedAccepted);
        Assert.Equal(0, fixture.Server.Counters.BasicRejected);
        Assert.Equal(0, fixture.Server.Counters.OpaqueSessionRejected);
        Assert.Equal(0, fixture.Server.Counters.SoapPolicyRejected);
        Assert.Equal(0, fixture.Server.Counters.Business);
        Assert.DoesNotContain(candidate, businessBody, StringComparison.Ordinal);
        Assert.DoesNotContain(HostedTypedSessionFixture.SyntheticUsername, businessBody, StringComparison.Ordinal);
        Assert.DoesNotContain(HostedTypedSessionFixture.SyntheticPassword, businessBody, StringComparison.Ordinal);

        string unknownConnectorId = "typed-hosted-unknown-" + Guid.NewGuid().ToString("N");
        string unknownDefinition = HostedTypedSessionFixture.Definition(unknownConnectorId, "1.0.0")
            .Replace("synthetic-create-session-request", "unregistered-request-adapter", StringComparison.Ordinal);
        HostedConnectorAuthority unknown = await fixture.PrepareConnectorVersionAsync(unknownConnectorId, "1.0.0", environmentId, unknownDefinition);
        await fixture.PublishAsync(unknown, expectedPublicationRevision: 0);
        await fixture.GrantAsync(unknownConnectorId, identityA);
        int outboundBeforeUnknown = fixture.Transport.TotalSoapRequests;
        using HttpResponseMessage unknownResponse = await fixture.SendSignedAsync(identityA, HttpMethod.Post,
            $"/v1/connectors/{unknownConnectorId}/operations/session-bootstrap/session-handshakes/typed-session:acquire", []);
        string unknownBody = await unknownResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.InternalServerError, unknownResponse.StatusCode);
        Assert.Contains("BGW-INTERNAL", unknownBody, StringComparison.Ordinal);
        Assert.Equal(outboundBeforeUnknown, fixture.Transport.TotalSoapRequests);

        string logs = string.Join('\n', fixture.Factory.Logs);
        string audit = await fixture.SerializeAuditAsync(tenantA);
        Assert.DoesNotContain(candidate, logs, StringComparison.Ordinal);
        Assert.DoesNotContain(candidate, audit, StringComparison.Ordinal);
        Assert.DoesNotContain(candidate, unknownBody, StringComparison.Ordinal);
        Assert.DoesNotContain(HostedTypedSessionFixture.SyntheticUsername, logs, StringComparison.Ordinal);
        Assert.DoesNotContain(HostedTypedSessionFixture.SyntheticPassword, logs, StringComparison.Ordinal);
        Assert.DoesNotContain(HostedTypedSessionFixture.SyntheticUsername, audit, StringComparison.Ordinal);
        Assert.DoesNotContain(HostedTypedSessionFixture.SyntheticPassword, audit, StringComparison.Ordinal);
        Assert.True(fixture.Factory.AuthenticatedBoundaryRequests >= fixture.Factory.AuthenticatedBusinessRequests);
    }
}

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class TypedSessionHandshakePostgresRaceIntegrationTests
{
    [Theory]
    [InlineData("publish")]
    [InlineData("disable-resource")]
    public async Task Wave1_IT_PRODUCTION_STORE_final_race_uses_same_PostgreSQL_authority_and_denies_promotion(string mutation)
    {
        string? adminConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(adminConnection)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(migrationConnection)) Assert.Skip("PostgreSQL migration connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await PostgresIsolationTests.ApplyMigrationAsync();
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole =
            await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(adminConnection, migrationConnection, TestContext.Current.CancellationToken);

        TaskCompletionSource promotionReached = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releasePromotion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task BeforePromotion(CancellationToken cancellationToken)
        {
            promotionReached.TrySetResult();
            await releasePromotion.Task.WaitAsync(cancellationToken);
        }

        const string candidate = "postgres-final-race-candidate-canary";
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(candidate, BeforePromotion,
            runtimeRole.ConnectionString, adminConnection);
        Assert.IsType<RoutingConnectorConfigurationStore>(fixture.Store);
        string connectorId = "typed-pg-race-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("race-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("race-application");
        HostedConnectorAuthority first = await fixture.PrepareConnectorVersionAsync(connectorId, "1.0.0", environmentId);
        await fixture.PublishAsync(first, expectedPublicationRevision: 0);
        HostedConnectorAuthority? second = mutation == "publish"
            ? await fixture.PrepareConnectorVersionAsync(connectorId, "2.0.0", environmentId)
            : null;
        HostedIdentity identity = await fixture.EnrollIdentityAsync(tenantId, applicationId, environmentId, "race-identity");
        await fixture.GrantAsync(connectorId, identity);

        IPublishedConnectorMutationAuthoritySource authoritySource = Assert.IsAssignableFrom<IPublishedConnectorMutationAuthoritySource>(fixture.Store);
        PublishedConnectorAuthorityGeneration before = authoritySource.RuntimeMutationAuthority.Capture(connectorId, environmentId);
        using HttpResponseMessage acquireResponse = await fixture.SendSignedAsync(identity, HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/session-bootstrap/session-handshakes/typed-session:acquire", []);
        HostedHandshakeResult acquired = HostedHandshakeResult.Parse(await acquireResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal(HttpStatusCode.OK, acquireResponse.StatusCode);

        Task<HttpResponseMessage> completion = fixture.SendSignedAsync(identity, HttpMethod.Post,
            $"/v1/session-admissions/{acquired.IntentReference}:complete", Encoding.UTF8.GetBytes(candidate));
        await promotionReached.Task.WaitAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, fixture.Transport.ValidationRequests);
        Assert.Equal(1, fixture.Server.Counters.ValidateSession);

        try
        {
            if (second is not null)
            {
                await fixture.PublishAsync(second, expectedPublicationRevision: 1);
            }
            else
            {
                await fixture.DisableUsernameResourceAsync(first);
            }
        }
        finally
        {
            releasePromotion.TrySetResult();
        }

        PublishedConnectorAuthorityGeneration after = authoritySource.RuntimeMutationAuthority.Capture(connectorId, environmentId);
        Assert.Equal(before.Stripe, after.Stripe);
        Assert.True(after.Value > before.Value);
        using HttpResponseMessage completionResponse = await completion;
        string completionBody = await completionResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.InternalServerError, completionResponse.StatusCode);
        Assert.Contains("BGW-INTERNAL", completionBody, StringComparison.Ordinal);
        Assert.DoesNotContain(candidate, completionBody, StringComparison.Ordinal);
        Assert.Equal(0, fixture.Sessions.CachedSessionCount);
        Assert.Equal(1, fixture.Transport.ValidationRequests);
        Assert.Equal(1, fixture.Server.Counters.ValidateSession);
        Assert.Equal(0, fixture.Server.Counters.Business);

        int outboundAfterRace = fixture.Transport.TotalSoapRequests;
        using HttpResponseMessage replay = await fixture.SendSignedAsync(identity, HttpMethod.Post,
            $"/v1/session-admissions/{acquired.IntentReference}:complete", Encoding.UTF8.GetBytes(candidate));
        string replayBody = await replay.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.InternalServerError, replay.StatusCode);
        Assert.DoesNotContain(candidate, replayBody, StringComparison.Ordinal);
        Assert.Equal(outboundAfterRace, fixture.Transport.TotalSoapRequests);
        Assert.Equal(0, fixture.Sessions.CachedSessionCount);

        GatewayClientPrincipal principal = await fixture.AuthenticateForInternalUseAsync(identity);
        AuthorizedGatewayInvocation authorized = await fixture.Factory.Services.GetRequiredService<IGatewayInvocationAuthorizer>()
            .AuthorizeAsync(principal, connectorId, "session-bootstrap", TestContext.Current.CancellationToken);
        if (mutation == "publish")
        {
            ResolvedTypedSessionHandshake resolved = await fixture.Factory.Services.GetRequiredService<PublishedTypedSessionHandshakeResolver>()
                .ResolveAsync(authorized, new("typed-session"), TestContext.Current.CancellationToken);
            Assert.Same(authoritySource.RuntimeMutationAuthority, resolved.State.MutationAuthority);
            Assert.Equal("2.0.0", resolved.State.ExecutionContext.ConnectorVersion);
        }

        Assert.DoesNotContain(candidate, string.Join('\n', fixture.Factory.Logs), StringComparison.Ordinal);
        Assert.DoesNotContain(candidate, await fixture.SerializeAuditAsync(tenantId), StringComparison.Ordinal);
    }
}

internal sealed record HostedConnectorAuthority(
    string ConnectorId,
    string Version,
    Guid EnvironmentId,
    ConnectorVersionResource Validated,
    AdminAccessContext Approver,
    ProviderResourceCatalogRecord Username,
    ProviderResourceCatalogRecord Password,
    ProviderResourceCatalogRecord Session);

public sealed record HostedCapabilityAuthority(
    string ConnectorId,
    string Version,
    Guid EnvironmentId,
    ConnectorVersionResource Validated,
    AdminAccessContext Approver,
    ProviderResourceCatalogRecord SigningCertificate,
    ProviderResourceCatalogRecord ClientCertificate);

public sealed record HostedExecutionModuleConfiguration(
    string ModuleId,
    string AssemblyPath,
    string AssemblyFullName,
    string ModuleType);

public static class HostedPostgresTestSupport
{
    public static Task ApplyMigrationAsync() => PostgresIsolationTests.ApplyMigrationAsync();
}

public sealed record HostedCapabilityProvider(
    IClientCertificateProvider ClientCertificates,
    IKeyOperationProvider KeyOperations,
    ICertificateMetadataProvider CertificateMetadata,
    ICertificatePublicMaterialProvider CertificatePublicMaterial,
    X509Certificate2 RootCertificate)
{
    public HostedCapabilityProvider(InMemoryProvider provider, X509Certificate2 rootCertificate)
        : this(provider, provider, provider, provider, rootCertificate) { }
}

internal sealed record HostedHandshakeResult(string Kind, string? IntentReference, string? SessionReference)
{
    internal static HostedHandshakeResult Parse(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        string kind = root.GetProperty("kind").GetString()!;
        string? intent = root.TryGetProperty("admissionIntent", out JsonElement admission) && admission.ValueKind != JsonValueKind.Null
            ? admission.GetProperty("reference").GetString()
            : null;
        string? session = root.TryGetProperty("session", out JsonElement sessionElement) && sessionElement.ValueKind != JsonValueKind.Null
            ? sessionElement.GetProperty("value").GetString()
            : null;
        return new(kind, intent, session);
    }
}

public sealed class HostedIdentity(X509Certificate2 certificate, RegisteredInstallationIdentity identity) : IDisposable
{
    public X509Certificate2 Certificate { get; } = certificate;
    public RegisteredInstallationIdentity Identity { get; } = identity;
    public void Dispose() => Certificate.Dispose();
}

public sealed class HostedTypedSessionFixture : IAsyncDisposable
{
    private const string SyntheticHost = "typed-session.synthetic.test";
    internal const string SyntheticUsername = "synthetic-user";
    internal const string SyntheticPassword = "synthetic-password";
    internal const string SyntheticOrganizationCode = "core-owned<&organization";
    internal const string BusinessOperationId = "session-business";
    private readonly HostedServerCertificates certificates;
    private readonly HttpClient api;
    private readonly List<HostedIdentity> identities = [];
    private readonly Dictionary<string, (ProviderResourceCatalogRecord Username, ProviderResourceCatalogRecord Password, ProviderResourceCatalogRecord Session, ProviderResourceCatalogRecord Organization)> resources = new(StringComparer.Ordinal);

    private HostedTypedSessionFixture(HostedServerCertificates certificates, SyntheticSoapServerInstance server, TypedSessionHostFactory factory)
    {
        this.certificates = certificates;
        Server = server;
        Factory = factory;
        api = factory.CreateClient();
        Store = factory.Services.GetRequiredService<IConnectorConfigurationStore>();
        Sessions = factory.Services.GetRequiredService<SoapSessionClient>();
        Endpoint = new Uri($"https://{SyntheticHost}:{server.Endpoint.Port}/", UriKind.Absolute);
    }

    internal TypedSessionHostFactory Factory { get; }
    internal SyntheticSoapServerInstance Server { get; }
    internal CountingRestrictedTransport Transport => Factory.Transport;
    public int HostResolutionCount => Factory.HostResolutionCount;
    internal IConnectorConfigurationStore Store { get; }
    internal SoapSessionClient Sessions { get; }
    internal Uri Endpoint { get; }
    public bool UsesPostgreSql => Store is RoutingConnectorConfigurationStore;
    public int GenericTransportRequests => Transport.GenericRequests;

    public HttpClient CreateAdminClient() => Factory.CreateClient(new()
    {
        BaseAddress = new Uri("https://localhost")
    });

    public static async Task<HostedTypedSessionFixture> CreateAsync(
        string candidate,
        Func<CancellationToken, Task>? beforePromotion = null,
        string? runtimeConnection = null,
        string? adminConnection = null,
        HostedExecutionModuleConfiguration? executionModule = null,
        Func<CancellationToken, Task>? beforeHandshakeFinalAuthorization = null,
        Func<CancellationToken, Task>? beforeComposedFinalAuthorization = null,
        HostedCapabilityProvider? capabilityProvider = null,
        IRestrictedTransport? restrictedTransport = null,
        IReadOnlySet<string>? privateDestinationHosts = null,
        string? serverOwnedOrganizationCode = null,
        bool enableDevelopmentAdmin = false)
    {
        string organizationCode = serverOwnedOrganizationCode ?? SyntheticOrganizationCode;
        HostedServerCertificates certificates = HostedServerCertificates.Create(SyntheticHost);
        try
        {
            SyntheticSoapServerInstance server = await SyntheticSoapServerHost.StartAsync(
                new(SyntheticUsername, SyntheticPassword, false, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(2), true, candidate)
                {
                    OpaqueSessionHeaderName = "X-Session-Reference",
                    OpaqueSessionValue = candidate,
                    ServerOwnedOrganizationCode = executionModule is null ? null : organizationCode
                },
                certificates.Server, TestContext.Current.CancellationToken);
            try
            {
                TypedSessionHostFactory factory = new(certificates.Root, certificates.Server, SyntheticHost, beforePromotion, runtimeConnection, adminConnection,
                    executionModule, beforeHandshakeFinalAuthorization, beforeComposedFinalAuthorization, capabilityProvider,
                    restrictedTransport, privateDestinationHosts, organizationCode, enableDevelopmentAdmin);
                return new(certificates, server, factory);
            }
            catch
            {
                await server.DisposeAsync();
                throw;
            }
        }
        catch
        {
            certificates.Dispose();
            throw;
        }
    }

    internal static string Definition(string connectorId, string version) => $$$"""
        {
          "schemaVersion":"1.0","connectorId":"{{{connectorId}}}","version":"{{{version}}}","displayName":"Typed hosted production path",
          "bindings":{"endpoints":[{"name":"soap"}],"secrets":[{"name":"username","kind":"username"},{"name":"password","kind":"password"},{"name":"session","kind":"opaque"}]},
          "operations":[
            {
              "operationId":"session-bootstrap","endpointBinding":"soap","method":"POST","path":"/service",
              "request":{"contentType":"text/xml","maximumBytes":32768},"response":{"maximumBytes":32768},
              "authentication":{"kind":"basic","usernameBinding":"username","passwordBinding":"password"},
              "typedSessionHandshake":{
                "profileId":"typed-session","soapVersion":"1.1","action":"urn:synthetic:CreateSession",
                "requestElement":{"localName":"CreateSessionRequest","namespaceUri":"urn:synthetic:typed-session"},
                "responseElement":{"localName":"CreateSessionResponse","namespaceUri":"urn:synthetic:typed-session"},
                "requestAdapter":{"id":"synthetic-create-session-request","type":"compiled-typed-request"},
                "responseAdapter":{"id":"synthetic-create-session-response","type":"compiled-typed-response"},
                "sessionLifetimeSeconds":300,
                "externalAdmission":{
                  "validator":{"id":"synthetic-session-validator","type":"compiled-typed-validator"},"endpointBinding":"soap","path":"/service",
                  "soapVersion":"1.1","action":"urn:synthetic:ValidateSession",
                  "requestElement":{"localName":"ValidateSessionRequest","namespaceUri":"urn:synthetic:typed-session"},
                  "responseElement":{"localName":"ValidateSessionResponse","namespaceUri":"urn:synthetic:typed-session"},
                  "intentLifetimeSeconds":60,"timeoutMs":5000,"maximumRequestBytes":32768,"maximumResponseBytes":32768
                }
              },
              "timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0
            },
            {
              "operationId":"session-business","endpointBinding":"soap","method":"POST","path":"/composed",
              "request":{"contentType":"text/xml","maximumBytes":32768},"response":{"maximumBytes":32768},
              "authentication":{"kind":"soapBasicOpaqueSession","policyId":"typed-session-business-policy","sessionProfileId":"typed-session","usernameBinding":"username","passwordBinding":"password","secretBinding":"session","headerName":"X-Session-Reference","valueFormat":"rawOpaqueValue","soapHttp":{"version":"1.1","action":"urn:synthetic:BusinessOperation"}},
              "timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0
            }
          ]
        }
        """;

    public async Task<Guid> CreateEnvironmentAsync()
    {
        Guid id = Guid.NewGuid();
        await Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddEnvironmentAsync(
            new(id, "hosted-e-" + id.ToString("N")[..20], "Hosted typed environment", false), TestContext.Current.CancellationToken);
        return id;
    }

    public async Task<Guid> CreateTenantAsync(string marker)
    {
        Guid id = Guid.NewGuid();
        await Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddTenantAsync(
            new(id, marker + "-" + id.ToString("N"), marker, TenantStatus.Active, Factory.Clock.UtcNow), TestContext.Current.CancellationToken);
        return id;
    }

    public async Task<Guid> CreateApplicationAsync(string marker)
    {
        Guid id = Guid.NewGuid();
        await Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddApplicationAsync(
            new(id, marker + "-" + id.ToString("N"), marker, ApplicationStatus.Active, "1.0.0", null, Factory.Clock.UtcNow), TestContext.Current.CancellationToken);
        return id;
    }

    public async Task<HostedIdentity> EnrollIdentityAsync(Guid tenantId, Guid applicationId, Guid environmentId, string marker)
    {
        IAdminGatewayRegistry adminRegistry = Factory.Services.GetRequiredService<IAdminGatewayRegistry>();
        Guid installationId = Guid.NewGuid();
        await adminRegistry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Pending, null,
            Factory.Clock.UtcNow, InstallationKind: InstallationKind.Direct, UpdatedAt: Factory.Clock.UtcNow), TestContext.Current.CancellationToken);
        GatewayProvisioningService provisioning = new(adminRegistry, Factory.Clock, Factory.Services.GetRequiredService<EnrollmentSecurityOptions>());
        ProvisionedActivation activation = await provisioning.CreateActivationCodeAsync(installationId, "hosted-fixture", TestContext.Current.CancellationToken);

        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new($"CN={marker}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.2") }, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        X509Certificate2 certificate = request.CreateSelfSigned(Factory.Clock.UtcNow.AddMinutes(-1), Factory.Clock.UtcNow.AddDays(30));
        key.Dispose();
        try
        {
            using ECDsa signingKey = certificate.GetECDsaPrivateKey() ?? throw new InvalidOperationException("Synthetic client key missing.");
            byte[] spki = signingKey.ExportSubjectPublicKeyInfo();
            InstallationEnrollmentService enrollment = Factory.Services.GetRequiredService<InstallationEnrollmentService>();
            EnrollmentChallengeResponse challenge = await enrollment.CreateChallengeAsync(new(activation.ActivationCodeId, Convert.ToBase64String(spki)), TestContext.Current.CancellationToken);
            EnrollmentChallenge proof = new(challenge.ChallengeId, activation.ActivationCodeId, Base64Url.Decode(challenge.Challenge), spki, challenge.ExpiresAt);
            byte[] signature = signingKey.SignData(InstallationEnrollmentService.BuildActivationProof(proof), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            _ = await enrollment.ActivateAsync(new(challenge.ChallengeId, activation.ActivationCode, Convert.ToBase64String(certificate.RawData),
                Base64Url.Encode(signature), ClientVersion: "1.0.0"), TestContext.Current.CancellationToken);
            RegisteredInstallationIdentity identity = await Factory.Services.GetRequiredService<IGatewayRegistry>()
                .FindIdentityByCertificateAsync(SHA256.HashData(certificate.RawData), TestContext.Current.CancellationToken)
                ?? throw new InvalidOperationException("Synthetic authenticated identity was not registered.");
            HostedIdentity result = new(certificate, identity);
            identities.Add(result);
            return result;
        }
        catch
        {
            certificate.Dispose();
            throw;
        }
    }

    internal async Task GrantAsync(string connectorId, params HostedIdentity[] grantedIdentities)
    {
        IAdminGatewayRegistry registry = Factory.Services.GetRequiredService<IAdminGatewayRegistry>();
        foreach (HostedIdentity identity in grantedIdentities)
        {
            await registry.AddGrantAsync(new(Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
                "session-bootstrap", true, Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
            await registry.AddGrantAsync(new(Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
                BusinessOperationId, true, Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
        }
    }

    internal async Task<HostedConnectorAuthority> PrepareConnectorVersionAsync(
        string connectorId,
        string version,
        Guid environmentId,
        string? definition = null,
        string? sessionOperationScope = null)
    {
        if (!resources.TryGetValue(connectorId, out var connectorResources))
        {
            string suffix = Guid.NewGuid().ToString("N");
            ProviderResourceCatalogRecord username = await Store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic",
                "typed-user-" + suffix, ProviderResourceType.Secret, "Typed username", environmentId, connectorId, "*",
                "synthetic://typed-user-" + suffix, ProviderResourceStatus.Active, null, 0, null, null, string.Empty, Factory.Clock.UtcNow), TestContext.Current.CancellationToken);
            ProviderResourceCatalogRecord password = await Store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic",
                "typed-password-" + suffix, ProviderResourceType.Secret, "Typed password", environmentId, connectorId, "*",
                "synthetic://typed-password-" + suffix, ProviderResourceStatus.Active, null, 0, null, null, string.Empty, Factory.Clock.UtcNow), TestContext.Current.CancellationToken);
            ProviderResourceCatalogRecord session = await Store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic",
                "typed-session-" + suffix, ProviderResourceType.Secret, "Typed opaque session authority", environmentId, connectorId, sessionOperationScope ?? BusinessOperationId,
                "synthetic://typed-session-" + suffix, ProviderResourceStatus.Active, null, 0, null, null, string.Empty, Factory.Clock.UtcNow), TestContext.Current.CancellationToken);
            ProviderResourceCatalogRecord organization = await Store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic",
                "typed-organization-" + suffix, ProviderResourceType.Secret, "Typed server-owned organization", environmentId, connectorId, "*",
                "synthetic://typed-organization-" + suffix, ProviderResourceStatus.Active, null, 0, null, null, string.Empty, Factory.Clock.UtcNow), TestContext.Current.CancellationToken);
            Assert.Equal(username.Revision, password.Revision);
            Assert.Equal(username.Revision, session.Revision);
            Assert.Equal(username.Revision, organization.Revision);
            resources.Add(connectorId, connectorResources = (username, password, session, organization));
        }

        ConnectorAdministrationService administration = Factory.Services.GetRequiredService<ConnectorAdministrationService>();
        IAdminSecurityStore security = Factory.Services.GetRequiredService<IAdminSecurityStore>();
        ConnectorApprovalService approvals = Factory.Services.GetRequiredService<ConnectorApprovalService>();
        string actorSuffix = Guid.NewGuid().ToString("N");
        AdminPrincipalRecord editorPrincipal = await security.EnsurePrincipalAsync(new("https://hosted-typed.invalid", "editor-" + actorSuffix, "Editor", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord approverPrincipal = await security.EnsurePrincipalAsync(new("https://hosted-typed.invalid", "approver-" + actorSuffix, "Approver", null), TestContext.Current.CancellationToken);
        _ = await security.AssignRoleAsync(editorPrincipal.Id, AdminRole.ConnectorEditor, null, editorPrincipal.Id, Guid.NewGuid(), Factory.Clock.UtcNow, TestContext.Current.CancellationToken);
        _ = await security.AssignRoleAsync(approverPrincipal.Id, AdminRole.ConnectorApprover, null, approverPrincipal.Id, Guid.NewGuid(), Factory.Clock.UtcNow, TestContext.Current.CancellationToken);
        AdminAccessContext editor = new(editorPrincipal, await security.GetAssignmentsAsync(editorPrincipal.Id, TestContext.Current.CancellationToken));
        AdminAccessContext approver = new(approverPrincipal, await security.GetAssignmentsAsync(approverPrincipal.Id, TestContext.Current.CancellationToken));

        using JsonDocument document = JsonDocument.Parse(definition ?? Definition(connectorId, version));
        bool requiresOrganization = document.RootElement.GetProperty("bindings").GetProperty("secrets").EnumerateArray()
            .Any(value => string.Equals(value.GetProperty("name").GetString(), "organization", StringComparison.Ordinal));
        ConnectorVersionResource imported = await administration.ImportAsync(document.RootElement, null, editor.ActorId, Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionResource validated = await administration.ValidateStoredAsync(connectorId, version, imported.RowVersion, editor.ActorId, Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await administration.PutBindingsAsync(connectorId, new(environmentId,
            new Dictionary<string, string> { ["soap"] = Endpoint.AbsoluteUri },
            new Dictionary<string, ProviderResourceReference>
            {
                ["username"] = new(connectorResources.Username.ProviderId, connectorResources.Username.ResourceId, connectorResources.Username.ResourceType),
                ["password"] = new(connectorResources.Password.ProviderId, connectorResources.Password.ResourceId, connectorResources.Password.ResourceType),
                ["session"] = new(connectorResources.Session.ProviderId, connectorResources.Session.ResourceId, connectorResources.Session.ResourceType)
            }.Concat(requiresOrganization
                ? new Dictionary<string, ProviderResourceReference>
                {
                    ["organization"] = new(connectorResources.Organization.ProviderId, connectorResources.Organization.ResourceId, connectorResources.Organization.ResourceType)
                }
                : []).ToDictionary(value => value.Key, value => value.Value, StringComparer.Ordinal), null, null, version), editor.ActorId, Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorApprovalRecord requested = await approvals.RequestAsync(connectorId, version, editor, Guid.NewGuid(), TestContext.Current.CancellationToken);
        ApprovalReviewResult review = await approvals.ReviewAsync(connectorId, version, approver, TestContext.Current.CancellationToken);
        ConnectorApprovalRecord approved = await approvals.ApproveAsync(connectorId, version,
            new(requested.Id, review.DigestSha256, "synthetic hosted approval"), approver, Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal(ConnectorApprovalStatus.Approved, approved.Status);
        Assert.NotEqual(editor.Principal.Id, approved.ApprovedBy);
        return new(connectorId, version, environmentId, validated, approver, connectorResources.Username, connectorResources.Password, connectorResources.Session);
    }

    internal async Task PublishAsync(HostedConnectorAuthority authority, long expectedPublicationRevision)
    {
        ConnectorVersionResource published = await Factory.Services.GetRequiredService<ConnectorAdministrationService>().PublishAsync(
            authority.ConnectorId, authority.Version, authority.Validated.RowVersion, expectedPublicationRevision,
            authority.Approver.ActorId, Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal(ConnectorVersionState.Published, published.State);
    }

    public async Task<HostedCapabilityAuthority> PrepareCapabilityConnectorVersionAsync(
        string connectorId,
        string version,
        Guid environmentId,
        Uri endpoint,
        string definition,
        ICertificateMetadataProvider provider,
        string signingProviderReference,
        string clientCertificateProviderReference,
        int expectedCertificateBindingCount = 2,
        string operationId = "signed-submit",
        int expectedOperationCount = 1,
        string endpointBinding = "service",
        string signingCertificateBinding = "signing-certificate",
        string clientCertificateBinding = "mtls-certificate")
    {
        ProviderResourceCatalogRecord signing = await RegisterCertificateAsync(
            "capability-signing-" + Guid.NewGuid().ToString("N"), "Synthetic signing certificate", signingProviderReference);
        ProviderResourceCatalogRecord clientCertificate = await RegisterCertificateAsync(
            "capability-mtls-" + Guid.NewGuid().ToString("N"), "Synthetic mTLS certificate", clientCertificateProviderReference);

        ConnectorAdministrationService administration = Factory.Services.GetRequiredService<ConnectorAdministrationService>();
        IAdminSecurityStore security = Factory.Services.GetRequiredService<IAdminSecurityStore>();
        ConnectorApprovalService approvals = Factory.Services.GetRequiredService<ConnectorApprovalService>();
        string actorSuffix = Guid.NewGuid().ToString("N");
        AdminPrincipalRecord editorPrincipal = await security.EnsurePrincipalAsync(
            new("https://hosted-capability.invalid", "editor-" + actorSuffix, "Editor", null), TestContext.Current.CancellationToken);
        AdminPrincipalRecord approverPrincipal = await security.EnsurePrincipalAsync(
            new("https://hosted-capability.invalid", "approver-" + actorSuffix, "Approver", null), TestContext.Current.CancellationToken);
        _ = await security.AssignRoleAsync(editorPrincipal.Id, AdminRole.ConnectorEditor, null, editorPrincipal.Id, Guid.NewGuid(), Factory.Clock.UtcNow, TestContext.Current.CancellationToken);
        _ = await security.AssignRoleAsync(approverPrincipal.Id, AdminRole.ConnectorApprover, null, approverPrincipal.Id, Guid.NewGuid(), Factory.Clock.UtcNow, TestContext.Current.CancellationToken);
        AdminAccessContext editor = new(editorPrincipal, await security.GetAssignmentsAsync(editorPrincipal.Id, TestContext.Current.CancellationToken));
        AdminAccessContext approver = new(approverPrincipal, await security.GetAssignmentsAsync(approverPrincipal.Id, TestContext.Current.CancellationToken));

        using JsonDocument document = JsonDocument.Parse(definition);
        ConnectorVersionResource imported = await administration.ImportAsync(document.RootElement, null, editor.ActorId, Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionResource validated = await administration.ValidateStoredAsync(connectorId, version, imported.RowVersion, editor.ActorId, Guid.NewGuid(), TestContext.Current.CancellationToken);
        Dictionary<string, ProviderResourceReference> certificateBindings = new(StringComparer.Ordinal)
        {
            [clientCertificateBinding] = new(clientCertificate.ProviderId, clientCertificate.ResourceId, clientCertificate.ResourceType, clientCertificate.Version, clientCertificate.PublicMetadataRevision)
        };
        if (expectedCertificateBindingCount == 2)
            certificateBindings.Add(signingCertificateBinding, new(signing.ProviderId, signing.ResourceId, signing.ResourceType, signing.Version, signing.PublicMetadataRevision));
        _ = await administration.PutBindingsAsync(connectorId, new(
            environmentId,
            new Dictionary<string, string> { [endpointBinding] = endpoint.AbsoluteUri },
            new Dictionary<string, ProviderResourceReference>(),
            CertificateResources: certificateBindings,
            ConnectorVersion: version), editor.ActorId, Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorApprovalRecord requested = await approvals.RequestAsync(connectorId, version, editor, Guid.NewGuid(), TestContext.Current.CancellationToken);
        ApprovalReviewResult review = await approvals.ReviewAsync(connectorId, version, approver, TestContext.Current.CancellationToken);
        Assert.Equal(expectedOperationCount, review.Artifact.Operations.Count);
        Assert.All(review.Artifact.Operations,
            operation => Assert.Equal(expectedCertificateBindingCount, operation.CertificateBindings.Count));
        ConnectorApprovalRecord approved = await approvals.ApproveAsync(connectorId, version,
            new(requested.Id, review.DigestSha256, "synthetic capability approval"), approver, Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal(ConnectorApprovalStatus.Approved, approved.Status);
        Assert.NotEqual(editor.Principal.Id, approved.ApprovedBy);
        return new(connectorId, version, environmentId, validated, approver, signing, clientCertificate);

        async Task<ProviderResourceCatalogRecord> RegisterCertificateAsync(
            string resourceId,
            string displayName,
            string providerReference)
        {
            ProviderCertificatePublicMetadata metadata = await provider.GetPublicMetadataAsync(providerReference, TestContext.Current.CancellationToken);
            CertificatePublicMetadata publicMetadata = new(metadata.FingerprintSha256, metadata.Subject, metadata.Issuer,
                metadata.NotBefore, metadata.NotAfter, metadata.KeyAlgorithm, metadata.PublicKeySize, metadata.Version);
            return await Store.RegisterProviderResourceAsync(new(
                Guid.NewGuid(), "synthetic-capability", "Synthetic capability provider", "synthetic", resourceId,
                ProviderResourceType.ClientCertificate, displayName, environmentId, connectorId, operationId,
                providerReference, ProviderResourceStatus.Active, metadata.Version, 0, 1, publicMetadata,
                string.Empty, Factory.Clock.UtcNow), TestContext.Current.CancellationToken);
        }
    }

    public async Task<ConnectorVersionResource> PublishAsync(HostedCapabilityAuthority authority, long expectedPublicationRevision)
    {
        ConnectorVersionResource published = await Factory.Services.GetRequiredService<ConnectorAdministrationService>().PublishAsync(
            authority.ConnectorId, authority.Version, authority.Validated.RowVersion, expectedPublicationRevision,
            authority.Approver.ActorId, Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal(ConnectorVersionState.Published, published.State);
        return published;
    }

    public async Task<ConnectorVersionResource> RollbackAsync(
        HostedCapabilityAuthority activeAuthority,
        string targetVersion,
        long expectedActiveRowVersion)
    {
        ConnectorVersionResource rolledBack = await Factory.Services.GetRequiredService<ConnectorAdministrationService>().RollbackAsync(
            activeAuthority.ConnectorId,
            new(targetVersion, expectedActiveRowVersion),
            activeAuthority.Approver.ActorId,
            Guid.NewGuid(),
            TestContext.Current.CancellationToken);
        Assert.Equal(ConnectorVersionState.Published, rolledBack.State);
        Assert.Equal(targetVersion, rolledBack.Version);
        return rolledBack;
    }

    internal async Task DisableUsernameResourceAsync(HostedConnectorAuthority authority)
    {
        _ = await Store.RegisterProviderResourceAsync(authority.Username with
        {
            Id = Guid.NewGuid(),
            Status = ProviderResourceStatus.Disabled,
            Revision = 0,
            ChecksumSha256 = string.Empty,
            CreatedAt = Factory.Clock.UtcNow.AddMilliseconds(1)
        }, TestContext.Current.CancellationToken);
    }

    internal async Task MutatePublishedBindingRevisionAsync(HostedConnectorAuthority authority, HostedIdentity identity)
    {
        PublishedConnectorSnapshot snapshot = await Store.GetPublishedSnapshotAsync(
            authority.ConnectorId,
            authority.EnvironmentId,
            new(identity.Identity.InstallationId, identity.Identity.TenantId, identity.Identity.ApplicationId, BusinessOperationId),
            TestContext.Current.CancellationToken)
            ?? throw new InvalidOperationException("Published binding mutation authority was unavailable.");
        ConnectorBindingSet binding = snapshot.Bindings;
        _ = await Store.PutBindingsAsync(binding with
        {
            Id = Guid.NewGuid(),
            Revision = 0,
            UpdatedAt = Factory.Clock.UtcNow.AddMilliseconds(1),
            UpdatedBy = "synthetic-binding-race"
        }, binding.Revision, Guid.NewGuid(), TestContext.Current.CancellationToken);
    }

    internal async Task RotateOrganizationResourceAsync(HostedConnectorAuthority authority)
    {
        ProviderResourceCatalogRecord organization = resources[authority.ConnectorId].Organization;
        _ = await Store.RegisterProviderResourceAsync(organization with
        {
            Id = Guid.NewGuid(),
            ProviderReference = organization.ProviderReference + "-rotated",
            Revision = 0,
            ChecksumSha256 = string.Empty,
            CreatedAt = Factory.Clock.UtcNow.AddMilliseconds(1)
        }, TestContext.Current.CancellationToken);
    }

    public async Task<HttpResponseMessage> SendSignedAsync(
        HostedIdentity identity,
        HttpMethod method,
        string target,
        byte[] body,
        IReadOnlyDictionary<string, string>? additionalHeaders = null)
    {
        using HttpRequestMessage request = new(method, target) { Content = new ByteArrayContent(body) };
        RuntimeSignatureHeaders headers = Sign(identity.Certificate, method.Method, target, body);
        request.Headers.TryAddWithoutValidation(TypedSessionHostFactory.ClientCertificateHeader, Convert.ToBase64String(identity.Certificate.RawData));
        request.Headers.TryAddWithoutValidation("X-BG-Timestamp", headers.Timestamp);
        request.Headers.TryAddWithoutValidation("X-BG-Nonce", headers.Nonce);
        request.Headers.TryAddWithoutValidation("X-BG-Content-SHA256", headers.ContentSha256);
        request.Headers.TryAddWithoutValidation("X-BG-Signature", headers.Signature);
        if (target.Split('?', 2)[0].EndsWith(":invoke", StringComparison.Ordinal))
            request.Headers.TryAddWithoutValidation("traceparent", "00-11111111111111111111111111111111-2222222222222222-01");
        if (additionalHeaders is not null)
            foreach ((string name, string value) in additionalHeaders) request.Headers.TryAddWithoutValidation(name, value);
        return await api.SendAsync(request, TestContext.Current.CancellationToken);
    }

    public Task AddOperationGrantAsync(HostedIdentity identity, string connectorId, string operationId) =>
        Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddGrantAsync(new(
            Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
            operationId, true, Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);

    internal static byte[] BusinessInvocationBody()
    {
        const string envelope = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><op:BusinessOperation xmlns:op=\"urn:synthetic:session\"><op:Payload>normal</op:Payload></op:BusinessOperation></soap:Body></soap:Envelope>";
        return JsonSerializer.SerializeToUtf8Bytes(new GatewayInvokeRequest("1.0", new("text/xml", "utf8", envelope), Guid.NewGuid()));
    }

    internal long CaptureCurrentSessionGeneration()
    {
        FieldInfo cacheField = typeof(SoapSessionClient).GetField("cache", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("SOAP cache field unavailable to the test evidence harness.");
        object cache = cacheField.GetValue(Sessions) ?? throw new InvalidOperationException("SOAP cache unavailable to the test evidence harness.");
        FieldInfo entriesField = cache.GetType().GetField("entries", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("SOAP cache entries unavailable to the test evidence harness.");
        IEnumerable entries = (IEnumerable)(entriesField.GetValue(cache) ?? throw new InvalidOperationException("SOAP cache entries unavailable to the test evidence harness."));
        List<long> currentGenerations = [];
        foreach (object entry in entries)
        {
            object state = entry.GetType().GetProperty("Value")?.GetValue(entry)
                ?? throw new InvalidOperationException("SOAP cache state unavailable to the test evidence harness.");
            object? current = state.GetType().GetProperty("Current")?.GetValue(state);
            if (current is not null)
                currentGenerations.Add((long)(current.GetType().GetProperty("Generation")?.GetValue(current)
                    ?? throw new InvalidOperationException("SOAP session generation unavailable to the test evidence harness.")));
        }
        return Assert.Single(currentGenerations);
    }

    internal async Task<GatewayClientPrincipal> AuthenticateForInternalUseAsync(HostedIdentity identity)
    {
        const string target = "/test-only/typed-session-business-use";
        RuntimeSignatureHeaders headers = Sign(identity.Certificate, "POST", target, []);
        return await Factory.Services.GetRequiredService<RuntimeIdentityService>().AuthenticateAsync(identity.Certificate, "POST", target, headers, ReadOnlyMemory<byte>.Empty,
            Guid.NewGuid(), TestContext.Current.CancellationToken);
    }

    public async Task<string> SerializeAuditAsync(Guid tenantId)
    {
        if (Factory.Services.GetRequiredService<IGatewayRegistry>() is InMemoryGatewayRegistry inMemory)
            return JsonSerializer.Serialize(inMemory.SnapshotAuditEvents());
        AdminPage<GatewayAuditEvent> audit = await Factory.Services.GetRequiredService<IAdminDirectoryStore>()
            .ListAuditAsync(tenantId, 0, 100, TestContext.Current.CancellationToken);
        return JsonSerializer.Serialize(audit.Items);
    }

    private static RuntimeSignatureHeaders Sign(X509Certificate2 certificate, string method, string target, byte[] body)
    {
        string timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
        string nonce = Base64Url.Encode(RandomNumberGenerator.GetBytes(16));
        string contentHash = Base64Url.Encode(SHA256.HashData(body));
        string input = RuntimeIdentityService.BuildSigningInput(method, target, timestamp, nonce, contentHash);
        using ECDsa privateKey = certificate.GetECDsaPrivateKey() ?? throw new InvalidOperationException("Synthetic client key missing.");
        string signature = Base64Url.Encode(privateKey.SignData(Encoding.UTF8.GetBytes(input), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        return new(timestamp, nonce, contentHash, signature);
    }

    public async ValueTask DisposeAsync()
    {
        api.Dispose();
        await Factory.DisposeAsync();
        await Server.DisposeAsync();
        foreach (HostedIdentity identity in identities) identity.Dispose();
        certificates.Dispose();
    }
}

internal sealed class TypedSessionHostFactory : WebApplicationFactory<Program>
{
    internal const string ClientCertificateHeader = "X-Test-Client-Certificate";
    private readonly string syntheticHost;
    private readonly Func<CancellationToken, Task>? beforePromotion;
    private readonly string? runtimeConnection;
    private readonly string? adminConnection;
    private readonly HostedExecutionModuleConfiguration? executionModule;
    private readonly Func<CancellationToken, Task>? beforeHandshakeFinalAuthorization;
    private readonly Func<CancellationToken, Task>? beforeComposedFinalAuthorization;
    private readonly HostedCapabilityProvider? capabilityProvider;
    private readonly IReadOnlySet<string> privateDestinationHosts;
    private readonly bool enableDevelopmentAdmin;
    private readonly RecordingLoggerProvider logger = new();
    private readonly TestClientCertificateStartupFilter certificateFilter = new();
    private readonly FixedSecrets secrets;

    internal TypedSessionHostFactory(
        X509Certificate2 root,
        X509Certificate2 server,
        string syntheticHost,
        Func<CancellationToken, Task>? beforePromotion,
        string? runtimeConnection,
        string? adminConnection,
        HostedExecutionModuleConfiguration? executionModule,
        Func<CancellationToken, Task>? beforeHandshakeFinalAuthorization,
        Func<CancellationToken, Task>? beforeComposedFinalAuthorization,
        HostedCapabilityProvider? capabilityProvider,
        IRestrictedTransport? restrictedTransport,
        IReadOnlySet<string>? privateDestinationHosts,
        string organizationCode,
        bool enableDevelopmentAdmin)
    {
        this.syntheticHost = syntheticHost;
        this.beforePromotion = beforePromotion;
        this.runtimeConnection = runtimeConnection;
        this.adminConnection = adminConnection;
        this.executionModule = executionModule;
        this.beforeHandshakeFinalAuthorization = beforeHandshakeFinalAuthorization;
        this.beforeComposedFinalAuthorization = beforeComposedFinalAuthorization;
        this.capabilityProvider = capabilityProvider;
        this.enableDevelopmentAdmin = enableDevelopmentAdmin;
        this.privateDestinationHosts = privateDestinationHosts ?? (capabilityProvider is null
            ? new HashSet<string>([syntheticHost], StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>([syntheticHost, "localhost"], StringComparer.OrdinalIgnoreCase));
        secrets = new(organizationCode);
        X509Certificate2Collection trust = new(root);
        if (capabilityProvider is not null) trust.Add(capabilityProvider.RootCertificate);
        Transport = new(restrictedTransport ?? new SystemRestrictedTransport(trust,
            capabilityProvider is null ? Convert.ToHexString(SHA256.HashData(server.RawData)) : null));
    }

    internal CountingRestrictedTransport Transport { get; }
    internal IReadOnlyCollection<string> Logs => logger.Messages;
    internal int AuthenticatedBoundaryRequests => certificateFilter.Requests;
    internal int AuthenticatedBusinessRequests => certificateFilter.BusinessRequests;
    internal int HostResolutionCount => Services.GetRequiredService<LoopbackResolver>().Calls;
    internal FixedSecrets Secrets => secrets;
    internal Func<CancellationToken, Task>? BeforeHostResolution { get; set; }
    internal IGatewayClock Clock => Services.GetRequiredService<IGatewayClock>();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Gateway:Admin:Mode", runtimeConnection is null || enableDevelopmentAdmin ? "DevelopmentAuth" : "Disabled");
        builder.UseSetting("Gateway:Admin:RequireFourEyes", runtimeConnection is null ? "false" : "true");
        if (runtimeConnection is not null) builder.UseSetting("ConnectionStrings:GatewayDatabase", runtimeConnection);
        if (adminConnection is not null) builder.UseSetting("ConnectionStrings:GatewayAdminDatabase", adminConnection);
        if (executionModule is not null)
        {
            builder.UseSetting("Gateway:ExecutionModules:0:ModuleId", executionModule.ModuleId);
            builder.UseSetting("Gateway:ExecutionModules:0:AssemblyPath", executionModule.AssemblyPath);
            builder.UseSetting("Gateway:ExecutionModules:0:AssemblyFullName", executionModule.AssemblyFullName);
            builder.UseSetting("Gateway:ExecutionModules:0:ModuleType", executionModule.ModuleType);
        }
        builder.ConfigureTestServices(services =>
        {
            if (runtimeConnection is null)
            {
                services.RemoveAll<IConnectorWorkflowContextStore>();
                services.AddSingleton<IConnectorWorkflowContextStore, TestConnectorWorkflowContextStore>();
            }
            services.RemoveAll<IHostResolver>();
            services.AddSingleton<LoopbackResolver>(_ => new LoopbackResolver(cancellationToken =>
                BeforeHostResolution?.Invoke(cancellationToken) ?? Task.CompletedTask));
            services.AddSingleton<IHostResolver>(serviceProvider => serviceProvider.GetRequiredService<LoopbackResolver>());
            services.RemoveAll<IRestrictedTransport>();
            services.AddSingleton<IRestrictedTransport>(Transport);
            services.RemoveAll<ISecretValueProvider>();
            services.AddSingleton<ISecretValueProvider>(secrets);
            if (capabilityProvider is not null)
            {
                services.RemoveAll<IClientCertificateProvider>();
                services.AddSingleton(capabilityProvider.ClientCertificates);
                services.RemoveAll<IKeyOperationProvider>();
                services.AddSingleton(capabilityProvider.KeyOperations);
                services.RemoveAll<ICertificateMetadataProvider>();
                services.AddSingleton(capabilityProvider.CertificateMetadata);
                services.RemoveAll<ICertificatePublicMaterialProvider>();
                services.AddSingleton(capabilityProvider.CertificatePublicMaterial);
            }
            services.AddSingleton<IPrivateDestinationAllowance>(new LoopbackAllowance(privateDestinationHosts));
            services.AddSingleton<IStartupFilter>(certificateFilter);
            services.AddSingleton<ILoggerProvider>(logger);
            services.RemoveAll<SoapSessionClient>();
            services.AddSingleton(serviceProvider => new SoapSessionClient(
                serviceProvider.GetRequiredService<ISecretValueProvider>(),
                serviceProvider.GetRequiredService<IHostResolver>(),
                serviceProvider.GetRequiredService<IRestrictedTransport>(),
                serviceProvider.GetRequiredService<IGatewayClock>(),
                serviceProvider.GetRequiredService<ISoapSessionResourceStampProvider>(),
                serviceProvider.GetRequiredService<IPrivateDestinationAllowance>(),
                beforePromotion,
                beforeHandshakeFinalAuthorization));
            services.RemoveAll<ComposedSoapExecutionStrategy>();
            services.AddSingleton(serviceProvider => new ComposedSoapExecutionStrategy(
                serviceProvider.GetRequiredService<IConnectorConfigurationStore>(),
                serviceProvider.GetRequiredService<ISecretValueProvider>(),
                serviceProvider.GetRequiredService<OpaqueSessionLeaseProvider>(),
                serviceProvider.GetRequiredService<IHostResolver>(),
                serviceProvider.GetRequiredService<IRestrictedTransport>(),
                serviceProvider.GetRequiredService<IGatewayClock>(),
                serviceProvider.GetRequiredService<IPrivateDestinationAllowance>(),
                serviceProvider.GetServices<ITypedComposedSoapRequestAdapter>(),
                beforeComposedFinalAuthorization));
        });
    }

    private sealed class LoopbackResolver(Func<CancellationToken, Task> beforeReturn) : IHostResolver
    {
        private int calls;
        internal int Calls => Volatile.Read(ref calls);

        public async Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref calls);
            await beforeReturn(cancellationToken).ConfigureAwait(false);
            return [IPAddress.Loopback];
        }
    }

    private sealed class LoopbackAllowance(IReadOnlySet<string> hosts) : IPrivateDestinationAllowance
    {
        public bool IsAllowed(string candidateHost, IPAddress address) =>
            hosts.Contains(candidateHost) && IPAddress.IsLoopback(address);
    }

    internal sealed class FixedSecrets(string organizationCode) : ISecretValueProvider
    {
        private int totalRequests;
        internal int TotalRequests => Volatile.Read(ref totalRequests);
        internal Func<CancellationToken, Task>? BeforeOrganizationReturn { get; set; }

        public async Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref totalRequests);
            if (logicalReference.Contains("user", StringComparison.OrdinalIgnoreCase))
                return HostedTypedSessionFixture.SyntheticUsername;
            if (logicalReference.Contains("password", StringComparison.OrdinalIgnoreCase))
                return HostedTypedSessionFixture.SyntheticPassword;
            if (logicalReference.Contains("organization", StringComparison.OrdinalIgnoreCase))
            {
                if (BeforeOrganizationReturn is not null)
                    await BeforeOrganizationReturn(cancellationToken).ConfigureAwait(false);
                return organizationCode;
            }
            throw new InvalidOperationException("Unexpected synthetic secret binding.");
        }
    }
}

internal sealed class TestClientCertificateStartupFilter : IStartupFilter
{
    private int requests;
    private int businessRequests;
    internal int Requests => Volatile.Read(ref requests);
    internal int BusinessRequests => Volatile.Read(ref businessRequests);

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => application =>
    {
        application.Use(async (context, continuation) =>
        {
            if (!context.Request.Headers.TryGetValue(TypedSessionHostFactory.ClientCertificateHeader, out var encoded) || encoded.Count != 1)
            {
                await continuation();
                return;
            }

            context.Request.Headers.Remove(TypedSessionHostFactory.ClientCertificateHeader);
            X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(encoded[0]!));
            context.Connection.ClientCertificate = certificate;
            Interlocked.Increment(ref requests);
            bool businessRequest = context.Request.Path.StartsWithSegments("/v1/connectors", StringComparison.Ordinal) &&
                context.Request.Path.Value?.EndsWith(":invoke", StringComparison.Ordinal) == true;
            try
            {
                await continuation();
                if (businessRequest && context.Response.StatusCode is >= 200 and < 300)
                    Interlocked.Increment(ref businessRequests);
            }
            finally
            {
                context.Connection.ClientCertificate = null;
                certificate.Dispose();
            }
        });
        next(application);
    };
}

internal sealed class CountingRestrictedTransport(IRestrictedTransport inner) : IRestrictedTransport
{
    private int totalSoapRequests;
    private int acquisitionRequests;
    private int validationRequests;
    private int businessRequests;
    private int genericRequests;
    internal int TotalSoapRequests => Volatile.Read(ref totalSoapRequests);
    internal int AcquisitionRequests => Volatile.Read(ref acquisitionRequests);
    internal int ValidationRequests => Volatile.Read(ref validationRequests);
    internal int BusinessRequests => Volatile.Read(ref businessRequests);
    internal int GenericRequests => Volatile.Read(ref genericRequests);
    internal string? LastBusinessEnvelope { get; private set; }
    internal string? LastBusinessContentType { get; private set; }
    internal string? LastBusinessSoapAction { get; private set; }
    internal string? LastBusinessAuthorizationScheme { get; private set; }
    internal int LastBusinessSessionHeaderCount { get; private set; }

    public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate,
        TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref genericRequests);
        return inner.SendAsync(request, approvedAddresses, clientCertificate, timeout, maximumResponseBytes, cancellationToken);
    }

    public Task<ExternalResponse> SendProblemDetailsAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate,
        TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref genericRequests);
        return inner.SendProblemDetailsAsync(request, approvedAddresses, clientCertificate, timeout, maximumResponseBytes, cancellationToken);
    }

    public Task<ExternalResponse> SendSoapAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, TimeSpan timeout,
        long maximumResponseBytes, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref totalSoapRequests);
        string action = request.Headers.TryGetValues("SOAPAction", out IEnumerable<string>? values) ? string.Join(',', values) : string.Empty;
        if (action.Contains("CreateSession", StringComparison.Ordinal)) Interlocked.Increment(ref acquisitionRequests);
        if (action.Contains("ValidateSession", StringComparison.Ordinal)) Interlocked.Increment(ref validationRequests);
        if (action.Contains("BusinessOperation", StringComparison.Ordinal))
        {
            Interlocked.Increment(ref businessRequests);
            LastBusinessEnvelope = request.Content is null
                ? null
                : Encoding.UTF8.GetString(request.Content.ReadAsByteArrayAsync(cancellationToken).GetAwaiter().GetResult());
            LastBusinessContentType = request.Content?.Headers.ContentType?.ToString();
            LastBusinessSoapAction = action;
            LastBusinessAuthorizationScheme = request.Headers.Authorization?.Scheme;
            LastBusinessSessionHeaderCount = request.Headers.TryGetValues("X-Session-Reference", out IEnumerable<string>? sessionValues)
                ? sessionValues.Count()
                : 0;
        }
        return inner.SendSoapAsync(request, approvedAddresses, timeout, maximumResponseBytes, cancellationToken);
    }
}

internal sealed class HostedServerCertificates(X509Certificate2 root, X509Certificate2 server) : IDisposable
{
    internal X509Certificate2 Root { get; } = root;
    internal X509Certificate2 Server { get; } = server;

    internal static HostedServerCertificates Create(string host)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using RSA rootKey = RSA.Create(2048);
        CertificateRequest rootRequest = new("CN=Hosted Typed Session Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        X509Certificate2 root = rootRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(2));
        using RSA serverKey = RSA.Create(2048);
        CertificateRequest serverRequest = new($"CN={host}", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        SubjectAlternativeNameBuilder san = new();
        san.AddDnsName(host);
        serverRequest.CertificateExtensions.Add(san.Build());
        using X509Certificate2 publicServer = serverRequest.Create(root, now.AddMinutes(-1), now.AddHours(1), RandomNumberGenerator.GetBytes(16));
        using X509Certificate2 serverWithKey = publicServer.CopyWithPrivateKey(serverKey);
        X509Certificate2 server = X509CertificateLoader.LoadPkcs12(serverWithKey.Export(X509ContentType.Pkcs12), null,
            X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
        return new(root, server);
    }

    public void Dispose()
    {
        Server.Dispose();
        Root.Dispose();
    }
}

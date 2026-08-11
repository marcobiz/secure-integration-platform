using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;
using SecureIntegration.Synthetic.ConnectorExecutionModule;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

[Collection(PostgreSqlSharedDatabaseGroup.Name)]
public sealed class AuthorizedVerticalCapabilityHostedIntegrationTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    [Fact]
    public Task Wave1_IT_PRODUCTION_HOST_in_memory_Published_profile_signs_x5c_and_dispatches_real_mTLS() =>
        RunAsync(runtimeConnection: null, adminConnection: null, requirePostgres: false);

    [Fact]
    public async Task Wave1_IT_PRODUCTION_HOST_PostgreSQL18_Published_profile_signs_x5c_and_dispatches_real_mTLS()
    {
        string? adminConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(adminConnection)) Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(migrationConnection)) Assert.Skip("PostgreSQL migration connection is not configured; the dedicated PostgreSQL gate must provide it.");
        await PostgresIsolationTests.ApplyMigrationAsync();
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole =
            await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(adminConnection, migrationConnection, TestContext.Current.CancellationToken);
        await RunAsync(runtimeRole.ConnectionString, adminConnection, requirePostgres: true);
    }

    [Fact]
    public Task Wave1_IT_PRODUCTION_HOST_in_memory_authorized_operation_projects_Published_paths_and_body_modes() =>
        RunAuthorizedOperationAsync(runtimeConnection: null, adminConnection: null, requirePostgres: false);

    [Fact]
    public async Task Wave1_IT_PRODUCTION_HOST_PostgreSQL18_authorized_operation_projects_Published_paths_and_body_modes()
    {
        bool gateRequired = string.Equals(
            Environment.GetEnvironmentVariable("GATEWAY_REQUIRE_AUTHORIZED_OPERATION_POSTGRES_GATE"),
            "true",
            StringComparison.OrdinalIgnoreCase);
        string? adminConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        if (string.IsNullOrWhiteSpace(adminConnection))
        {
            Assert.False(gateRequired, "The required authorized-operation PostgreSQL gate did not provide the admin connection.");
            Assert.Skip("PostgreSQL admin connection is not configured; the dedicated PostgreSQL gate must provide it.");
        }

        string? migrationConnection = Environment.GetEnvironmentVariable("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        if (string.IsNullOrWhiteSpace(migrationConnection))
        {
            Assert.False(gateRequired, "The required authorized-operation PostgreSQL gate did not provide the migration connection.");
            Assert.Skip("PostgreSQL migration connection is not configured; the dedicated PostgreSQL gate must provide it.");
        }

        await PostgresIsolationTests.ApplyMigrationAsync();
        await using AdminApiSecurityTests.PostgresRuntimeRoleLease runtimeRole =
            await AdminApiSecurityTests.PostgresRuntimeRoleLease.CreateAsync(adminConnection, migrationConnection, TestContext.Current.CancellationToken);
        await RunAuthorizedOperationAsync(runtimeRole.ConnectionString, adminConnection, requirePostgres: true);
    }

    [Fact]
    public void Wave1_SEC_synthetic_mTLS_server_requires_the_exact_trusted_client_certificate()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        using SyntheticAuthenticationMaterial attacker = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);

        Assert.True(SyntheticSignedMutualTlsServer.ValidateClientCertificate(
            material.ClientCertificateRevision1,
            material.ClientCertificateRevision1,
            material.RootCertificate));
        Assert.False(SyntheticSignedMutualTlsServer.ValidateClientCertificate(
            material.ClientCertificateRevision2,
            material.ClientCertificateRevision1,
            material.RootCertificate));
        Assert.False(SyntheticSignedMutualTlsServer.ValidateClientCertificate(
            material.ClientCertificateRevision1,
            material.ClientCertificateRevision1,
            attacker.RootCertificate));
    }

    [Fact]
    public async Task Wave1_SEC_Published_A_to_B_during_signing_public_material_returns_no_token_and_performs_no_transport()
    {
        TaskCompletionSource publicMaterialEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releasePublicMaterial = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        InMemoryProvider inner = new(
            new Dictionary<string, string>(),
            certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["mtls-r1"] = material.ClientCertificateRevision1
            },
            signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["sign-r1"] = material.SigningKeyRevision1
            },
            certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal)
            {
                ["sign-r1"] = [material.RootCertificate]
            });
        BlockingPublicMaterialProvider provider = new(inner, async cancellationToken =>
        {
            publicMaterialEntered.TrySetResult();
            await releasePublicMaterial.Task.WaitAsync(cancellationToken);
        }, blockOnPublicMaterialCall: 2);
        await using SyntheticSignedMutualTlsServer server = await SyntheticSignedMutualTlsServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-signing-race-candidate",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));
        string connectorId = "synthetic-signing-race-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("signing-race-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("signing-race-application");
        string signingSpki = SpkiSha256(material.SigningKeyRevision1);
        string clientSpki = SpkiSha256(material.ClientCertificateRevision1);
        HostedCapabilityAuthority authorityA = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            DualSlotDefinition(connectorId, "1.0.0", signingSpki, clientSpki),
            provider,
            "sign-r1",
            "mtls-r1");
        await fixture.PublishAsync(authorityA, expectedPublicationRevision: 0);
        HostedCapabilityAuthority authorityB = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "2.0.0",
            environmentId,
            server.Endpoint,
            DualSlotDefinition(connectorId, "2.0.0", signingSpki, clientSpki).Replace(
                "synthetic-secondary-issuer",
                "synthetic-secondary-issuer-v2",
                StringComparison.Ordinal),
            provider,
            "sign-r1",
            "mtls-r1");
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId,
            applicationId,
            environmentId,
            "signing-race-identity");
        await fixture.Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddGrantAsync(new(
            Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
            "signed-submit", true, fixture.Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
        GatewayInvokeRequest request = new(
            "1.0",
            new("application/octet-stream", "utf8", "caller-body"),
            Guid.NewGuid());
        Task<HttpResponseMessage> pending = fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
            JsonSerializer.SerializeToUtf8Bytes(request, WebJson));
        await publicMaterialEntered.Task.WaitAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, provider.SignDigestCalls);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.Transport.GenericRequests);

        try
        {
            await fixture.PublishAsync(authorityB, expectedPublicationRevision: 1);
        }
        finally
        {
            releasePublicMaterial.TrySetResult();
        }

        using HttpResponseMessage response = await pending;
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("BGW-CONNECTOR-CONFIGURATION-STALE", body, StringComparison.Ordinal);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.Transport.GenericRequests);
        Assert.Equal(1, provider.SignDigestCalls);
    }

    [Fact]
    public async Task Wave1_SEC_Published_A_to_B_during_policy_preflight_denies_before_signing_and_network()
    {
        TaskCompletionSource publicMaterialEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releasePublicMaterial = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        InMemoryProvider inner = new(
            new Dictionary<string, string>(),
            certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["mtls-r1"] = material.ClientCertificateRevision1
            },
            signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["sign-r1"] = material.SigningKeyRevision1
            },
            certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal)
            {
                ["sign-r1"] = [material.RootCertificate]
            });
        BlockingPublicMaterialProvider provider = new(inner, async cancellationToken =>
        {
            publicMaterialEntered.TrySetResult();
            await releasePublicMaterial.Task.WaitAsync(cancellationToken);
        });
        await using SyntheticSignedMutualTlsServer server = await SyntheticSignedMutualTlsServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-preflight-race-candidate",
            executionModule: Module(),
            capabilityProvider: new(provider, provider, provider, provider, material.RootCertificate));
        string connectorId = "synthetic-preflight-race-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("preflight-race-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("preflight-race-application");
        string signingSpki = SpkiSha256(material.SigningKeyRevision1);
        string clientSpki = SpkiSha256(material.ClientCertificateRevision1);
        string subjectCn = material.SigningKeyRevision1.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        string definitionA = AuthorizedOperationDefinition(
            connectorId, "1.0.0", signingSpki, clientSpki, subjectCn, "POST",
            "\"pathTemplate\":\"/bounded/{tenant}\"", "required",
            "[{\"name\":\"tenant\",\"value\":\"north\"}]");
        HostedCapabilityAuthority authorityA = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId, "1.0.0", environmentId, server.Endpoint, definitionA, provider, "sign-r1", "mtls-r1");
        await fixture.PublishAsync(authorityA, 0);
        string definitionB = AuthorizedOperationDefinition(
            connectorId, "2.0.0", signingSpki, clientSpki, subjectCn, "POST",
            "\"pathTemplate\":\"/bounded/{region}\"", "required",
            "[{\"name\":\"region\",\"value\":\"south\"}]");
        HostedCapabilityAuthority authorityB = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId, "2.0.0", environmentId, server.Endpoint, definitionB, provider, "sign-r1", "mtls-r1");
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "preflight-race-identity");
        await fixture.Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddGrantAsync(new(
            Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
            "signed-submit", true, fixture.Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
        Task<HttpResponseMessage> pending = fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
            JsonSerializer.SerializeToUtf8Bytes(new GatewayInvokeRequest(
                "1.0", new("application/octet-stream", "utf8", "caller-body"), Guid.NewGuid()), WebJson));
        await publicMaterialEntered.Task.WaitAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, provider.SignDigestCalls);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.Transport.GenericRequests);

        try
        {
            await fixture.PublishAsync(authorityB, 1);
        }
        finally
        {
            releasePublicMaterial.TrySetResult();
        }

        using HttpResponseMessage response = await pending;
        string responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("BGW-CONNECTOR-CONFIGURATION-STALE", responseBody, StringComparison.Ordinal);
        Assert.Equal(0, provider.SignDigestCalls);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.Transport.GenericRequests);
    }

    [Fact]
    public async Task Wave1_SEC_Published_A_to_B_after_DNS_denies_before_restricted_transport()
    {
        TaskCompletionSource dnsEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource releaseDns = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        InMemoryProvider provider = new(
            new Dictionary<string, string>(),
            certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["mtls-r1"] = material.ClientCertificateRevision1
            },
            signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["sign-r1"] = material.SigningKeyRevision1
            },
            certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal)
            {
                ["sign-r1"] = [material.RootCertificate]
            });
        TrackingCapabilityProvider trackingProvider = new(provider);
        await using SyntheticSignedMutualTlsServer server = await SyntheticSignedMutualTlsServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-transport-race-candidate",
            executionModule: Module(),
            capabilityProvider: new(trackingProvider, trackingProvider, trackingProvider, trackingProvider, material.RootCertificate));
        string connectorId = "synthetic-transport-race-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("transport-race-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("transport-race-application");
        string signingSpki = SpkiSha256(material.SigningKeyRevision1);
        string clientSpki = SpkiSha256(material.ClientCertificateRevision1);
        string signingSubjectCn = material.SigningKeyRevision1.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        HostedCapabilityAuthority authorityA = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            AuthorizedOperationDefinition(
                connectorId, "1.0.0", signingSpki, clientSpki, signingSubjectCn, "POST",
                "\"pathTemplate\":\"/bounded/{tenant}\"", "required",
                "[{\"name\":\"tenant\",\"value\":\"north\"}]"),
            trackingProvider,
            "sign-r1",
            "mtls-r1");
        await fixture.PublishAsync(authorityA, expectedPublicationRevision: 0);
        HostedCapabilityAuthority authorityB = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "2.0.0",
            environmentId,
            server.Endpoint,
            AuthorizedOperationDefinition(
                connectorId, "2.0.0", signingSpki, clientSpki, signingSubjectCn, "POST",
                "\"pathTemplate\":\"/bounded/{region}\"", "required",
                "[{\"name\":\"region\",\"value\":\"south\"}]"),
            provider,
            "sign-r1",
            "mtls-r1");
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId,
            applicationId,
            environmentId,
            "transport-race-identity");
        await fixture.Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddGrantAsync(new(
            Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
            "signed-submit", true, fixture.Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
        fixture.Factory.BeforeHostResolution = async cancellationToken =>
        {
            dnsEntered.TrySetResult();
            await releaseDns.Task.WaitAsync(cancellationToken);
        };
        GatewayInvokeRequest request = new(
            "1.0",
            new("application/octet-stream", "utf8", "caller-body"),
            Guid.NewGuid());
        Task<HttpResponseMessage> pending = fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
            JsonSerializer.SerializeToUtf8Bytes(request, WebJson));
        await dnsEntered.Task.WaitAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.Transport.GenericRequests);

        try
        {
            await fixture.PublishAsync(authorityB, expectedPublicationRevision: 1);
        }
        finally
        {
            releaseDns.TrySetResult();
        }

        using HttpResponseMessage response = await pending;
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("BGW-CONNECTOR-CONFIGURATION-STALE", body, StringComparison.Ordinal);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.Transport.GenericRequests);
    }

    [Fact]
    public async Task Wave1_SEC_authorized_operation_policy_mismatches_deny_before_signing_and_network()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        InMemoryProvider provider = new(
            new Dictionary<string, string>(),
            certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["mtls-r1"] = material.ClientCertificateRevision1
            },
            signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["sign-r1"] = material.SigningKeyRevision1
            },
            certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal)
            {
                ["sign-r1"] = [material.RootCertificate]
            });
        TrackingCapabilityProvider trackingProvider = new(provider);
        await using SyntheticSignedMutualTlsServer server = await SyntheticSignedMutualTlsServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-policy-negative-candidate",
            executionModule: Module(),
            capabilityProvider: new(trackingProvider, trackingProvider, trackingProvider, trackingProvider, material.RootCertificate));
        string connectorId = "synthetic-policy-negative-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("policy-negative-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("policy-negative-application");
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "policy-negative-identity");
        await fixture.Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddGrantAsync(new(
            Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
            "signed-submit", true, fixture.Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
        string signingSpki = SpkiSha256(material.SigningKeyRevision1);
        string clientSpki = SpkiSha256(material.ClientCertificateRevision1);
        string signingSubjectCn = material.SigningKeyRevision1.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        List<(string Name, Action<JsonObject> Mutate)> cases =
        [
            ("slot-missing", root => ActualSlots(root).RemoveAt(1)),
            ("slot-extra", root =>
            {
                JsonObject tertiary = ActualSlots(root)[1]!.DeepClone().AsObject();
                tertiary["slot"] = "tertiary";
                tertiary["signing"]!["profileId"] = "synthetic-tertiary-signing";
                tertiary["projection"]!["headerName"] = "X-Synthetic-Tertiary";
                ActualSlots(root).Add(tertiary);
            }),
            ("wrong-projection", root =>
            {
                JsonNode first = ActualSlots(root)[0]!["projection"]!.DeepClone();
                ActualSlots(root)[0]!["projection"] = ActualSlots(root)[1]!["projection"]!.DeepClone();
                ActualSlots(root)[1]!["projection"] = first;
            }),
            ("wrong-required", root => ActualSlots(root)[1]!["required"] = false),
            ("wrong-algorithm", root => Policy(root)["algorithm"] = "RS512"),
            ("wrong-fixed-subject", root => ActualSigning(root, 0)["fixedSubject"] = "wrong-fixed-subject"),
            ("wrong-audience", root => ActualSigning(root, 0)["audience"] = "wrong-audience"),
            ("wrong-issuer", root => ActualSigning(root, 0)["issuer"] = "wrong-primary-issuer"),
            ("wrong-issuer-cn-relation", root => ActualSigning(root, 1)["issuer"] = "synthetic-cn-wrong"),
            ("wrong-lifetime", root => ActualSigning(root, 0)["tokenLifetimeSeconds"] = 61),
            ("wrong-temporal-expectation", root => ExpectedSlot(root, 0)["temporalMode"] = "iat-nbf-exp"),
            ("nbf-enabled-against-iat-exp", root => ActualSigning(root, 0)["temporalClaims"] = "iat-nbf-exp"),
            ("jti-not-required", root => ExpectedSlot(root, 0)["jtiRequired"] = false),
            ("x5c-absent", root => ActualSigning(root, 0)["certificateHeader"] = "none"),
            ("wrong-allowed-claims", root => ActualSigning(root, 0)["allowedClaims"]!.AsArray().Add("other-claim")),
            ("signing-identities-different", root =>
            {
                ActualSigning(root, 1)["keyBinding"] = "mtls-certificate";
                ActualSigning(root, 1)["publicKeySpkiSha256"] = clientSpki;
                Policy(root)["signingIdentityDistinctFromMutualTlsSlots"] = new JsonArray("primary");
            }),
            ("signing-identity-equals-mtls", root =>
            {
                Operation(root)["authorizedCapabilities"]!["restrictedTransport"]!["clientCertificateSpkiSha256"] = signingSpki;
            }),
            ("wrong-authentication-kind", root => Policy(root)["authenticationKind"] = "none")
        ];

        for (int index = 0; index < cases.Count; index++)
        {
            string version = $"{index + 1}.0.0";
            JsonObject definition = JsonNode.Parse(AuthorizedOperationDefinition(
                connectorId,
                version,
                signingSpki,
                clientSpki,
                signingSubjectCn,
                "POST",
                "\"path\":\"/bounded/static\"",
                "required",
                "[]"))!.AsObject();
            cases[index].Mutate(definition);
            HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
                connectorId,
                version,
                environmentId,
                server.Endpoint,
                definition.ToJsonString(),
                trackingProvider,
                "sign-r1",
                string.Equals(cases[index].Name, "signing-identity-equals-mtls", StringComparison.Ordinal)
                    ? "sign-r1"
                    : "mtls-r1");
            await fixture.PublishAsync(authority, index);
            int signingBefore = trackingProvider.SignDigestCalls;
            int networkBefore = server.Requests;
            int transportBefore = fixture.Transport.GenericRequests;
            GatewayInvokeRequest request = new(
                "1.0",
                new("application/octet-stream", "utf8", "caller-controlled-body"),
                Guid.NewGuid());
            using HttpResponseMessage response = await fixture.SendSignedAsync(
                identity,
                HttpMethod.Post,
                $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
                JsonSerializer.SerializeToUtf8Bytes(request, WebJson));
            string responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

            Assert.True(response.StatusCode == HttpStatusCode.Conflict,
                $"{cases[index].Name}: {response.StatusCode}: {responseBody}");
            Assert.Contains("BGW-EGRESS-AUTHENTICATION", responseBody, StringComparison.Ordinal);
            Assert.Equal(signingBefore, trackingProvider.SignDigestCalls);
            Assert.Equal(networkBefore, server.Requests);
            Assert.Equal(transportBefore, fixture.Transport.GenericRequests);
        }

        static JsonObject Operation(JsonObject root) => root["operations"]![0]!.AsObject();
        static JsonObject Policy(JsonObject root) => Operation(root)["extensionConfiguration"]!["policyExpectations"]!.AsObject();
        static JsonArray ActualSlots(JsonObject root) => Operation(root)["authorizedCapabilities"]!["signingSlots"]!.AsArray();
        static JsonObject ActualSigning(JsonObject root, int index) => ActualSlots(root)[index]!["signing"]!.AsObject();
        static JsonObject ExpectedSlot(JsonObject root, int index) => Policy(root)["signingSlots"]![index]!.AsObject();
    }

    [Fact]
    public async Task Wave1_SEC_false_empty_expectations_verify_exact_Published_absence_before_scope_signing_DNS_and_network()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        InMemoryProvider provider = new(
            new Dictionary<string, string>(),
            certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["mtls-r1"] = material.ClientCertificateRevision1
            },
            signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["sign-r1"] = material.SigningKeyRevision1
            },
            certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal)
            {
                ["sign-r1"] = [material.RootCertificate]
            });
        TrackingCapabilityProvider trackingProvider = new(provider);
        await using SyntheticSignedMutualTlsServer server = await SyntheticSignedMutualTlsServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-exact-absence-candidate",
            executionModule: Module(),
            capabilityProvider: new(trackingProvider, trackingProvider, trackingProvider, trackingProvider, material.RootCertificate));
        string connectorId = "synthetic-exact-absence-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("exact-absence-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("exact-absence-application");
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "exact-absence-identity");
        await fixture.Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddGrantAsync(new(
            Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
            "signed-submit", true, fixture.Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);

        string signingSpki = SpkiSha256(material.SigningKeyRevision1);
        string clientSpki = SpkiSha256(material.ClientCertificateRevision1);
        JsonObject unexpectedActualPolicy = JsonNode.Parse(DualSlotDefinition(
            connectorId, "1.0.0", signingSpki, clientSpki))!.AsObject();
        JsonObject unexpectedActualOperation = unexpectedActualPolicy["operations"]![0]!.AsObject();
        unexpectedActualOperation["executionStrategy"] = "synthetic-expectation-probe";
        unexpectedActualOperation["extensionConfiguration"]!.AsObject().Remove("policyExpectations");

        List<(string Version, string Definition, int CertificateBindings, bool Pass)> cases =
        [
            ("1.0.0", unexpectedActualPolicy.ToJsonString(), 2, false),
            ("2.0.0", ExpectationProbeDefinition(connectorId, "2.0.0", expectationProfile: null), 1, true),
            ("3.0.0", ExpectationProbeDefinition(connectorId, "3.0.0", EmptySlotExpectationProfile()), 1, false),
            ("4.0.0", ExpectationProbeDefinition(connectorId, "4.0.0", OneSlotExpectationProfile()), 1, false)
        ];

        for (int index = 0; index < cases.Count; index++)
        {
            (string version, string definition, int certificateBindings, bool pass) = cases[index];
            HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
                connectorId,
                version,
                environmentId,
                server.Endpoint,
                definition,
                trackingProvider,
                "sign-r1",
                "mtls-r1",
                certificateBindings);
            await fixture.PublishAsync(authority, index);
            int signingBefore = trackingProvider.SignDigestCalls;
            int dnsBefore = fixture.HostResolutionCount;
            int networkBefore = fixture.Transport.GenericRequests;
            int httpsBefore = server.Requests;
            SyntheticExpectationProbe.Reset();

            using HttpResponseMessage response = await fixture.SendSignedAsync(
                identity,
                HttpMethod.Post,
                $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
                JsonSerializer.SerializeToUtf8Bytes(new GatewayInvokeRequest(
                    "1.0", new("application/octet-stream", "utf8", "caller-body"), Guid.NewGuid()), WebJson));
            string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

            Assert.Equal(1, SyntheticExpectationProbe.ProviderInvocations);
            Assert.Equal(pass ? HttpStatusCode.OK : HttpStatusCode.Conflict, response.StatusCode);
            Assert.Equal(pass ? 1 : 0, SyntheticExpectationProbe.CapabilityScopeEntries);
            if (!pass) Assert.Contains("BGW-EGRESS-AUTHENTICATION", body, StringComparison.Ordinal);
            Assert.Equal(signingBefore, trackingProvider.SignDigestCalls);
            Assert.Equal(dnsBefore, fixture.HostResolutionCount);
            Assert.Equal(networkBefore, fixture.Transport.GenericRequests);
            Assert.Equal(httpsBefore, server.Requests);
        }

        static JsonObject EmptySlotExpectationProfile() => new()
        {
            ["algorithm"] = "RS256",
            ["authenticationKind"] = "mtls",
            ["restrictedTransportRequired"] = true,
            ["signingSlots"] = new JsonArray(),
            ["sameSigningIdentitySlots"] = new JsonArray(),
            ["signingIdentityDistinctFromMutualTlsSlots"] = new JsonArray()
        };

        static JsonObject OneSlotExpectationProfile()
        {
            JsonObject profile = EmptySlotExpectationProfile();
            profile["signingSlots"] = new JsonArray(new JsonObject
            {
                ["slot"] = "primary",
                ["required"] = true,
                ["projection"] = new JsonObject { ["kind"] = "authorizationBearer" },
                ["audience"] = "synthetic-upstream",
                ["fixedSubject"] = "synthetic-fixed-subject",
                ["allowedClaims"] = new JsonArray("transaction-id"),
                ["tokenLifetimeSeconds"] = 60,
                ["temporalMode"] = "iat-exp",
                ["jtiRequired"] = true,
                ["certificateHeader"] = "chain",
                ["issuer"] = new JsonObject { ["kind"] = "exact", ["value"] = "synthetic-primary-issuer" }
            });
            return profile;
        }
    }

    [Fact]
    public async Task Wave1_SEC_authorized_operation_missing_expectation_provider_denies_before_signing_and_network()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        InMemoryProvider provider = new(
            new Dictionary<string, string>(),
            certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["mtls-r1"] = material.ClientCertificateRevision1
            },
            signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["sign-r1"] = material.SigningKeyRevision1
            },
            certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal)
            {
                ["sign-r1"] = [material.RootCertificate]
            });
        TrackingCapabilityProvider trackingProvider = new(provider);
        await using SyntheticSignedMutualTlsServer server = await SyntheticSignedMutualTlsServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-missing-expectation-candidate",
            executionModule: MissingExpectationModule(),
            capabilityProvider: new(trackingProvider, trackingProvider, trackingProvider, trackingProvider, material.RootCertificate));
        string connectorId = "synthetic-missing-expectation-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("missing-expectation-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("missing-expectation-application");
        HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            AuthorizedOperationDefinition(
                connectorId,
                "1.0.0",
                SpkiSha256(material.SigningKeyRevision1),
                SpkiSha256(material.ClientCertificateRevision1),
                material.SigningKeyRevision1.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
                "POST",
                "\"path\":\"/bounded/static\"",
                "required",
                "[]"),
            trackingProvider,
            "sign-r1",
            "mtls-r1");
        await fixture.PublishAsync(authority, 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "missing-expectation-identity");
        await fixture.Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddGrantAsync(new(
            Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
            "signed-submit", true, fixture.Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
        int signingBefore = trackingProvider.SignDigestCalls;
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
            JsonSerializer.SerializeToUtf8Bytes(new GatewayInvokeRequest(
                "1.0", new("application/octet-stream", "utf8", "caller-body"), Guid.NewGuid()), WebJson));
        string responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Contains("BGW-EGRESS-AUTHENTICATION", responseBody, StringComparison.Ordinal);
        Assert.Equal(signingBefore, trackingProvider.SignDigestCalls);
        Assert.Equal(0, server.Requests);
        Assert.Equal(0, fixture.Transport.GenericRequests);
    }

    [Fact]
    public async Task Wave1_SEC_authorized_operation_path_and_body_mismatches_deny_before_network()
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        InMemoryProvider provider = new(
            new Dictionary<string, string>(),
            certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["mtls-r1"] = material.ClientCertificateRevision1
            },
            signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["sign-r1"] = material.SigningKeyRevision1
            },
            certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal)
            {
                ["sign-r1"] = [material.RootCertificate]
            });
        TrackingCapabilityProvider trackingProvider = new(provider);
        await using SyntheticSignedMutualTlsServer server = await SyntheticSignedMutualTlsServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-shape-negative-candidate",
            executionModule: Module(),
            capabilityProvider: new(trackingProvider, trackingProvider, trackingProvider, trackingProvider, material.RootCertificate));
        string connectorId = "synthetic-shape-negative-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("shape-negative-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("shape-negative-application");
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "shape-negative-identity");
        await fixture.Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddGrantAsync(new(
            Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
            "signed-submit", true, fixture.Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
        string signingSpki = SpkiSha256(material.SigningKeyRevision1);
        string clientSpki = SpkiSha256(material.ClientCertificateRevision1);
        string subjectCn = material.SigningKeyRevision1.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        List<(string Name, string Method, string PathMember, string PublishedBodyMode, string RequestBodyMode, string Parameters)> cases =
        [
            ("missing-path-value", "POST", "\"pathTemplate\":\"/bounded/{tenant}\"", "required", "required", "[]"),
            ("unknown-extra-path-value", "POST", "\"pathTemplate\":\"/bounded/{tenant}\"", "required", "required", "[{\"name\":\"tenant\",\"value\":\"north\"},{\"name\":\"unknown\",\"value\":\"extra\"}]"),
            ("template-not-Published", "POST", "\"path\":\"/bounded/static\"", "required", "required", "[{\"name\":\"tenant\",\"value\":\"north\"}]"),
            ("REQUIRED-without-body", "POST", "\"path\":\"/bounded/static\"", "required", "none", "[]"),
            ("body-with-NONE", "GET", "\"path\":\"/bounded/static\"", "none", "required", "[]")
        ];

        for (int index = 0; index < cases.Count; index++)
        {
            (string name, string method, string pathMember, string publishedBodyMode, string requestBodyMode, string parameters) = cases[index];
            string version = $"{index + 1}.0.0";
            JsonObject definition = JsonNode.Parse(AuthorizedOperationDefinition(
                connectorId, version, signingSpki, clientSpki, subjectCn, method, pathMember,
                publishedBodyMode, parameters))!.AsObject();
            definition["operations"]![0]!["extensionConfiguration"]!["requestProjection"]!["bodyMode"] = requestBodyMode;
            HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
                connectorId, version, environmentId, server.Endpoint, definition.ToJsonString(), trackingProvider,
                "sign-r1", "mtls-r1");
            await fixture.PublishAsync(authority, index);
            int signingBefore = trackingProvider.SignDigestCalls;
            int networkBefore = server.Requests;
            int transportBefore = fixture.Transport.GenericRequests;
            using HttpResponseMessage response = await fixture.SendSignedAsync(
                identity,
                HttpMethod.Post,
                $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
                JsonSerializer.SerializeToUtf8Bytes(new GatewayInvokeRequest(
                    "1.0", new("application/octet-stream", "utf8", "caller-body"), Guid.NewGuid()), WebJson));
            string responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

            Assert.True(response.StatusCode == HttpStatusCode.Conflict,
                $"{name}: {response.StatusCode}: {responseBody}");
            Assert.Contains("BGW-EGRESS-AUTHENTICATION", responseBody, StringComparison.Ordinal);
            Assert.Equal(signingBefore + 2, trackingProvider.SignDigestCalls);
            Assert.Equal(networkBefore, server.Requests);
            Assert.Equal(transportBefore, fixture.Transport.GenericRequests);
        }
    }

    private static async Task RunAsync(string? runtimeConnection, string? adminConnection, bool requirePostgres)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        InMemoryProvider provider = new(
            new Dictionary<string, string>(),
            certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["mtls-r1"] = material.ClientCertificateRevision1
            },
            signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["sign-r1"] = material.SigningKeyRevision1
            },
            certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal)
            {
                ["sign-r1"] = [material.RootCertificate]
            });
        TrackingCapabilityProvider trackingProvider = new(provider);
        await using SyntheticSignedMutualTlsServer server = await SyntheticSignedMutualTlsServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        HostedExecutionModuleConfiguration module = Module();
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-capability-candidate",
            runtimeConnection: runtimeConnection,
            adminConnection: adminConnection,
            executionModule: module,
            capabilityProvider: new(trackingProvider, trackingProvider, trackingProvider, trackingProvider, material.RootCertificate));
        Assert.Equal(requirePostgres, fixture.Store is RoutingConnectorConfigurationStore);

        string connectorId = "synthetic-capability-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("capability-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("capability-application");
        string definition = DualSlotDefinition(
            connectorId,
            "1.0.0",
            SpkiSha256(material.SigningKeyRevision1),
            SpkiSha256(material.ClientCertificateRevision1));
        HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "1.0.0",
            environmentId,
            server.Endpoint,
            definition,
            trackingProvider,
            "sign-r1",
            "mtls-r1");
        await fixture.PublishAsync(authority, expectedPublicationRevision: 0);
        HostedIdentity identity = await fixture.EnrollIdentityAsync(tenantId, applicationId, environmentId, "capability-identity");
        await fixture.Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddGrantAsync(new(
            Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
            "signed-submit", true, fixture.Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);

        GatewayInvokeRequest request = new(
            "1.0",
            new("application/octet-stream", "utf8", "caller-controlled-body"),
            Guid.NewGuid(),
            Metadata: new Dictionary<string, JsonElement>
            {
                ["endpoint"] = JsonSerializer.SerializeToElement("https://attacker.invalid/collect"),
                ["keyBinding"] = JsonSerializer.SerializeToElement("attacker-key"),
                ["certificateBinding"] = JsonSerializer.SerializeToElement("attacker-certificate"),
                ["profileId"] = JsonSerializer.SerializeToElement("attacker-profile")
            },
            Extensions: new Dictionary<string, JsonElement>
            {
                ["transaction-id"] = JsonSerializer.SerializeToElement("caller-claim")
            });
        using HttpResponseMessage response = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
            JsonSerializer.SerializeToUtf8Bytes(request, WebJson));
        string responseJson = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.True(response.StatusCode == HttpStatusCode.OK, responseJson);
        GatewayInvokeResponse gateway = JsonSerializer.Deserialize<GatewayInvokeResponse>(responseJson, WebJson)
            ?? throw new InvalidOperationException("Capability response was empty.");
        Assert.Contains("accepted", Encoding.UTF8.GetString(Convert.FromBase64String(gateway.Result.Data)), StringComparison.Ordinal);
        Assert.Equal(1, server.Requests);
        Assert.True(server.ExpectedClientCertificateObserved);
        Assert.True(server.ValidSignedTokenObserved);
        Assert.True(server.X5cChainObserved);
        Assert.True(server.PublishedClaimObserved);
        Assert.True(server.PublishedBodyObserved);
        Assert.True(server.DualSlotTokensObserved);
        Assert.True(server.DualSlotTokensDistinct);
        Assert.True(server.DistinctServerOwnedIssuersObserved);
        Assert.True(server.SameSigningIdentityObserved);
        Assert.Equal(1, fixture.Transport.GenericRequests);
        Assert.Equal(2, trackingProvider.SignDigestCalls);

        (HttpStatusCode deniedStatus, string deniedBody, _, _) = await PublishAndInvokeNegativeAsync(
            "2.0.0", 1, "synthetic-denied-signing-claim");
        Assert.Equal(HttpStatusCode.Conflict, deniedStatus);
        Assert.Contains("BGW-EGRESS-AUTHENTICATION", deniedBody, StringComparison.Ordinal);
        Assert.Equal(2, trackingProvider.SignDigestCalls);

        (HttpStatusCode unknownStatus, string unknownBody, int providerCallsBeforeUnknown, _) = await PublishAndInvokeNegativeAsync(
            "3.0.0", 2, "synthetic-unknown-slot");
        Assert.Equal(HttpStatusCode.Conflict, unknownStatus);
        Assert.Contains("BGW-EGRESS-AUTHENTICATION", unknownBody, StringComparison.Ordinal);
        Assert.Equal(providerCallsBeforeUnknown, trackingProvider.TotalCalls);

        (HttpStatusCode repeatStatus, string repeatBody, _, int signingBeforeRepeat) = await PublishAndInvokeNegativeAsync(
            "4.0.0", 3, "synthetic-repeat-slot");
        Assert.Equal(HttpStatusCode.Conflict, repeatStatus);
        Assert.Contains("BGW-EGRESS-AUTHENTICATION", repeatBody, StringComparison.Ordinal);
        Assert.Equal(signingBeforeRepeat + 1, trackingProvider.SignDigestCalls);

        (HttpStatusCode missingStatus, string missingBody, _, int signingBeforeMissing) = await PublishAndInvokeNegativeAsync(
            "5.0.0", 4, "synthetic-missing-slot");
        Assert.Equal(HttpStatusCode.Conflict, missingStatus);
        Assert.Contains("BGW-EGRESS-AUTHENTICATION", missingBody, StringComparison.Ordinal);
        Assert.Equal(signingBeforeMissing + 1, trackingProvider.SignDigestCalls);
        Assert.Equal(1, server.Requests);
        Assert.Equal(1, fixture.Transport.GenericRequests);

        string legacyDefinition = Definition(
            connectorId,
            "6.0.0",
            SpkiSha256(material.SigningKeyRevision1),
            SpkiSha256(material.ClientCertificateRevision1));
        HostedCapabilityAuthority legacyAuthority = await fixture.PrepareCapabilityConnectorVersionAsync(
            connectorId,
            "6.0.0",
            environmentId,
            server.Endpoint,
            legacyDefinition,
            trackingProvider,
            "sign-r1",
            "mtls-r1");
        await fixture.PublishAsync(legacyAuthority, expectedPublicationRevision: 5);
        int signingBeforeLegacy = trackingProvider.SignDigestCalls;
        using HttpResponseMessage legacyResponse = await fixture.SendSignedAsync(
            identity,
            HttpMethod.Post,
            $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
            JsonSerializer.SerializeToUtf8Bytes(request with { CorrelationId = Guid.NewGuid() }, WebJson));
        string legacyBody = await legacyResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.True(legacyResponse.StatusCode == HttpStatusCode.OK, legacyBody);
        Assert.Equal(signingBeforeLegacy + 1, trackingProvider.SignDigestCalls);
        Assert.True(server.LegacyBearerObserved);
        Assert.Equal(2, server.Requests);
        Assert.Equal(2, fixture.Transport.GenericRequests);

        async Task<(HttpStatusCode Status, string Body, int ProviderCallsBeforeInvoke, int SigningCallsBeforeInvoke)> PublishAndInvokeNegativeAsync(
            string version,
            long expectedPublicationRevision,
            string strategy)
        {
            string negativeDefinition = DualSlotDefinition(
                connectorId,
                version,
                SpkiSha256(material.SigningKeyRevision1),
                SpkiSha256(material.ClientCertificateRevision1)).Replace(
                    "\"executionStrategy\":\"synthetic-dual-slot\"",
                    $"\"executionStrategy\":\"{strategy}\"",
                    StringComparison.Ordinal);
            HostedCapabilityAuthority negativeAuthority = await fixture.PrepareCapabilityConnectorVersionAsync(
                connectorId,
                version,
                environmentId,
                server.Endpoint,
                negativeDefinition,
                trackingProvider,
                "sign-r1",
                "mtls-r1");
            await fixture.PublishAsync(negativeAuthority, expectedPublicationRevision);
            int providerCallsBeforeInvoke = trackingProvider.TotalCalls;
            int signingCallsBeforeInvoke = trackingProvider.SignDigestCalls;
            using HttpResponseMessage negativeResponse = await fixture.SendSignedAsync(
                identity,
                HttpMethod.Post,
                $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
                JsonSerializer.SerializeToUtf8Bytes(request with { CorrelationId = Guid.NewGuid() }, WebJson));
            return (negativeResponse.StatusCode,
                await negativeResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken),
                providerCallsBeforeInvoke,
                signingCallsBeforeInvoke);
        }
    }

    private static async Task RunAuthorizedOperationAsync(string? runtimeConnection, string? adminConnection, bool requirePostgres)
    {
        using SyntheticAuthenticationMaterial material = SyntheticAuthenticationMaterial.Create(DateTimeOffset.UtcNow);
        InMemoryProvider provider = new(
            new Dictionary<string, string>(),
            certificateHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["mtls-r1"] = material.ClientCertificateRevision1
            },
            signingKeyHandles: new Dictionary<string, X509Certificate2>(StringComparer.Ordinal)
            {
                ["sign-r1"] = material.SigningKeyRevision1
            },
            certificateChains: new Dictionary<string, IReadOnlyList<X509Certificate2>>(StringComparer.Ordinal)
            {
                ["sign-r1"] = [material.RootCertificate]
            });
        TrackingCapabilityProvider trackingProvider = new(provider);
        await using SyntheticSignedMutualTlsServer server = await SyntheticSignedMutualTlsServer.StartAsync(
            material.ServerCertificate,
            material.ClientCertificateRevision1,
            material.SigningKeyRevision1,
            material.RootCertificate,
            TestContext.Current.CancellationToken);
        await using HostedTypedSessionFixture fixture = await HostedTypedSessionFixture.CreateAsync(
            "unused-authorized-operation-candidate",
            runtimeConnection: runtimeConnection,
            adminConnection: adminConnection,
            executionModule: Module(),
            capabilityProvider: new(trackingProvider, trackingProvider, trackingProvider, trackingProvider, material.RootCertificate));
        Assert.Equal(requirePostgres, fixture.Store is RoutingConnectorConfigurationStore);

        string connectorId = "synthetic-authorized-operation-" + Guid.NewGuid().ToString("N");
        Guid environmentId = await fixture.CreateEnvironmentAsync();
        Guid tenantId = await fixture.CreateTenantAsync("authorized-operation-tenant");
        Guid applicationId = await fixture.CreateApplicationAsync("authorized-operation-application");
        HostedIdentity identity = await fixture.EnrollIdentityAsync(
            tenantId, applicationId, environmentId, "authorized-operation-identity");
        await fixture.Factory.Services.GetRequiredService<IAdminGatewayRegistry>().AddGrantAsync(new(
            Guid.NewGuid(), identity.Identity.InstallationId, identity.Identity.TenantId, connectorId,
            "signed-submit", true, fixture.Factory.Clock.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
        string signingSpki = SpkiSha256(material.SigningKeyRevision1);
        string clientSpki = SpkiSha256(material.ClientCertificateRevision1);
        string signingSubjectCn = material.SigningKeyRevision1.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

        await PublishInvokeAndAssertAsync(
            "1.0.0", 0, "POST", "\"path\":\"/bounded/static\"", "required", "[]",
            "/bounded/static", "published-body", "application/octet-stream");
        await PublishInvokeAndAssertAsync(
            "2.0.0", 1, "POST", "\"pathTemplate\":\"/bounded/{tenant}\"", "required",
            "[{\"name\":\"tenant\",\"value\":\"north west\"}]",
            "/bounded/north%20west", "published-body", "application/octet-stream");
        await PublishInvokeAndAssertAsync(
            "3.0.0", 2, "GET", "\"pathTemplate\":\"/bounded/{tenant}/documents/{document}\"", "none",
            "[{\"name\":\"tenant\",\"value\":\"acme\"},{\"name\":\"document\",\"value\":\"caffè+2026\"}]",
            "/bounded/acme/documents/caff%C3%A8%2B2026", string.Empty, null);
        await PublishInvokeAndAssertAsync(
            "4.0.0", 3, "DELETE", "\"pathTemplate\":\"/bounded/{tenant}\"", "none",
            "[{\"name\":\"tenant\",\"value\":\"south\"}]",
            "/bounded/south", string.Empty, null);

        Assert.Equal(4, server.Requests);
        Assert.Equal(8, trackingProvider.SignDigestCalls);
        Assert.True(server.ExpectedClientCertificateObserved);
        Assert.True(server.ValidSignedTokenObserved);
        Assert.True(server.DualSlotTokensObserved);
        Assert.True(server.SameSigningIdentityObserved);

        async Task PublishInvokeAndAssertAsync(
            string version,
            long expectedPublicationRevision,
            string method,
            string pathMember,
            string bodyMode,
            string pathParameters,
            string expectedRawTarget,
            string expectedBody,
            string? expectedContentType)
        {
            string definition = AuthorizedOperationDefinition(
                connectorId,
                version,
                signingSpki,
                clientSpki,
                signingSubjectCn,
                method,
                pathMember,
                bodyMode,
                pathParameters);
            HostedCapabilityAuthority authority = await fixture.PrepareCapabilityConnectorVersionAsync(
                connectorId,
                version,
                environmentId,
                server.Endpoint,
                definition,
                trackingProvider,
                "sign-r1",
                "mtls-r1");
            await fixture.PublishAsync(authority, expectedPublicationRevision);
            GatewayInvokeRequest request = new(
                "1.0",
                new("application/octet-stream", "utf8", "caller-controlled-body"),
                Guid.NewGuid());
            using HttpResponseMessage response = await fixture.SendSignedAsync(
                identity,
                HttpMethod.Post,
                $"/v1/connectors/{connectorId}/operations/signed-submit:invoke",
                JsonSerializer.SerializeToUtf8Bytes(request, WebJson));
            string responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

            Assert.True(response.StatusCode == HttpStatusCode.OK, responseBody);
            Assert.Equal(method, server.LastMethod);
            Assert.Equal(expectedRawTarget, server.LastRawTarget);
            Assert.Equal(expectedBody, server.LastBody);
            Assert.Equal(expectedContentType, server.LastContentType);
        }
    }

    private static HostedExecutionModuleConfiguration Module()
    {
        string path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "SecureIntegration.Synthetic.ConnectorExecutionModule.dll"));
        string fullName = System.Reflection.AssemblyName.GetAssemblyName(path).FullName
            ?? throw new InvalidOperationException("Synthetic execution module identity is unavailable.");
        return new("synthetic-execution", path, fullName, "SecureIntegration.Synthetic.ConnectorExecutionModule.SyntheticExecutionModule");
    }

    private static HostedExecutionModuleConfiguration MissingExpectationModule()
    {
        string path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "SecureIntegration.Synthetic.ConnectorExecutionModule.dll"));
        string fullName = System.Reflection.AssemblyName.GetAssemblyName(path).FullName
            ?? throw new InvalidOperationException("Synthetic execution module identity is unavailable.");
        return new(
            "synthetic-missing-expectation",
            path,
            fullName,
            "SecureIntegration.Synthetic.ConnectorExecutionModule.SyntheticMissingExpectationProviderModule");
    }

    private static string SpkiSha256(X509Certificate2 certificate)
    {
        using RSA rsa = certificate.GetRSAPublicKey() ?? throw new InvalidOperationException("Synthetic RSA public key is unavailable.");
        return Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()));
    }

    private static string Definition(string connectorId, string version, string signingSpki, string clientSpki) => $$$"""
        {
          "schemaVersion":"1.0","connectorId":"{{{connectorId}}}","version":"{{{version}}}","displayName":"Synthetic authorized capabilities",
          "bindings":{"endpoints":[{"name":"service"}],"secrets":[{"name":"signing-certificate","kind":"clientCertificate"},{"name":"mtls-certificate","kind":"clientCertificate"}]},
          "operations":[{
            "operationId":"signed-submit","endpointBinding":"service","method":"POST","path":"/submit",
            "request":{"contentType":"application/octet-stream","maximumBytes":4096},"response":{"maximumBytes":4096},
            "authentication":{"kind":"mtls","certificateBinding":"mtls-certificate"},"executionStrategy":"synthetic-signed-mtls",
            "extensionConfiguration":{
              "claimName":"transaction-id","claimValue":"published-claim","body":"published-body",
              "policyExpectations":{
                "algorithm":"RS256","authenticationKind":"mtls","restrictedTransportRequired":true,
                "signingSlots":[
                  {"slot":"legacy","required":true,"projection":{"kind":"authorizationBearer"},"audience":"synthetic-upstream","fixedSubject":"synthetic-fixed-subject","allowedClaims":["transaction-id"],"tokenLifetimeSeconds":60,"temporalMode":"iat-nbf-exp","jtiRequired":true,"certificateHeader":"chain","issuer":{"kind":"exact","value":"synthetic-gateway"}}
                ],
                "sameSigningIdentitySlots":[],"signingIdentityDistinctFromMutualTlsSlots":[]
              }
            },
            "authorizedCapabilities":{
              "signing":{"profileId":"synthetic-signing","revision":1,"keyBinding":"signing-certificate","publicKeySpkiSha256":"{{{signingSpki}}}","issuer":"synthetic-gateway","audience":"synthetic-upstream","subject":"fixed","fixedSubject":"synthetic-fixed-subject","allowedClaims":["transaction-id"],"tokenLifetimeSeconds":60,"clockSkewSeconds":5,"certificateHeader":"chain","temporalClaims":"iat-nbf-exp","minimumRsaKeySize":2048},
              "restrictedTransport":{"profileId":"synthetic-transport","revision":1,"clientCertificateSpkiSha256":"{{{clientSpki}}}","authorization":"signedTokenBearer","nearExpirySeconds":30}
            },
            "timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0
          }]
        }
        """;

    private static string DualSlotDefinition(string connectorId, string version, string signingSpki, string clientSpki) => $$$"""
        {
          "schemaVersion":"1.0","connectorId":"{{{connectorId}}}","version":"{{{version}}}","displayName":"Synthetic authorized signing slots",
          "bindings":{"endpoints":[{"name":"service"}],"secrets":[{"name":"signing-certificate","kind":"clientCertificate"},{"name":"mtls-certificate","kind":"clientCertificate"}]},
          "operations":[{
            "operationId":"signed-submit","endpointBinding":"service","method":"POST","path":"/submit",
            "request":{"contentType":"application/octet-stream","maximumBytes":4096},"response":{"maximumBytes":4096},
            "authentication":{"kind":"mtls","certificateBinding":"mtls-certificate"},"executionStrategy":"synthetic-dual-slot",
            "extensionConfiguration":{
              "claimName":"transaction-id","claimValue":"published-claim","body":"published-body",
              "policyExpectations":{
                "algorithm":"RS256","authenticationKind":"mtls","restrictedTransportRequired":true,
                "signingSlots":[
                  {"slot":"primary","required":true,"projection":{"kind":"authorizationBearer"},"audience":"synthetic-upstream","fixedSubject":"synthetic-fixed-subject","allowedClaims":["transaction-id"],"tokenLifetimeSeconds":60,"temporalMode":"iat-nbf-exp","jtiRequired":true,"certificateHeader":"chain","issuer":{"kind":"exact","value":"synthetic-primary-issuer"}},
                  {"slot":"secondary","required":true,"projection":{"kind":"signedTokenHeader","headerName":"X-Synthetic-Signature"},"audience":"synthetic-upstream","fixedSubject":"synthetic-fixed-subject","allowedClaims":["transaction-id"],"tokenLifetimeSeconds":60,"temporalMode":"iat-nbf-exp","jtiRequired":true,"certificateHeader":"chain","issuer":{"kind":"exact","value":"synthetic-secondary-issuer"}}
                ],
                "sameSigningIdentitySlots":[],"signingIdentityDistinctFromMutualTlsSlots":[]
              }
            },
            "authorizedCapabilities":{
              "signingSlots":[
                {
                  "slot":"primary","required":true,
                  "signing":{"profileId":"synthetic-primary-signing","revision":1,"keyBinding":"signing-certificate","publicKeySpkiSha256":"{{{signingSpki}}}","issuer":"synthetic-primary-issuer","audience":"synthetic-upstream","subject":"fixed","fixedSubject":"synthetic-fixed-subject","allowedClaims":["transaction-id"],"tokenLifetimeSeconds":60,"clockSkewSeconds":5,"certificateHeader":"chain","temporalClaims":"iat-nbf-exp","minimumRsaKeySize":2048},
                  "projection":{"kind":"authorizationBearer"}
                },
                {
                  "slot":"secondary","required":true,
                  "signing":{"profileId":"synthetic-secondary-signing","revision":1,"keyBinding":"signing-certificate","publicKeySpkiSha256":"{{{signingSpki}}}","issuer":"synthetic-secondary-issuer","audience":"synthetic-upstream","subject":"fixed","fixedSubject":"synthetic-fixed-subject","allowedClaims":["transaction-id"],"tokenLifetimeSeconds":60,"clockSkewSeconds":5,"certificateHeader":"chain","temporalClaims":"iat-nbf-exp","minimumRsaKeySize":2048},
                  "projection":{"kind":"signedTokenHeader","headerName":"X-Synthetic-Signature"}
                }
              ],
              "restrictedTransport":{"profileId":"synthetic-transport","revision":1,"clientCertificateSpkiSha256":"{{{clientSpki}}}","nearExpirySeconds":30}
            },
            "timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0
          }]
        }
        """;

    private static string AuthorizedOperationDefinition(
        string connectorId,
        string version,
        string signingSpki,
        string clientSpki,
        string signingSubjectCn,
        string method,
        string pathMember,
        string bodyMode,
        string pathParameters) => $$$"""
        {
          "schemaVersion":"1.0","connectorId":"{{{connectorId}}}","version":"{{{version}}}","displayName":"Synthetic authorized operation",
          "bindings":{"endpoints":[{"name":"service"}],"secrets":[{"name":"signing-certificate","kind":"clientCertificate"},{"name":"mtls-certificate","kind":"clientCertificate"}]},
          "operations":[{
            "operationId":"signed-submit","endpointBinding":"service","method":"{{{method}}}",{{{pathMember}}},
            "request":{"contentType":"application/octet-stream","maximumBytes":4096},"response":{"maximumBytes":4096},
            "authentication":{"kind":"mtls","certificateBinding":"mtls-certificate"},"executionStrategy":"synthetic-authorized-operation",
            "extensionConfiguration":{
              "policyExpectations":{
                "algorithm":"RS256","authenticationKind":"mtls",
                "signingSlots":[
                  {"slot":"primary","required":true,"projection":{"kind":"authorizationBearer"},"audience":"synthetic-upstream","fixedSubject":"synthetic-fixed-subject","allowedClaims":["transaction-id"],"tokenLifetimeSeconds":60,"temporalMode":"iat-exp","jtiRequired":true,"certificateHeader":"chain","issuer":{"kind":"exact","value":"synthetic-primary-issuer"}},
                  {"slot":"secondary","required":true,"projection":{"kind":"signedTokenHeader","headerName":"X-Synthetic-Signature"},"audience":"synthetic-upstream","fixedSubject":"synthetic-fixed-subject","allowedClaims":["transaction-id"],"tokenLifetimeSeconds":60,"temporalMode":"iat-exp","jtiRequired":true,"certificateHeader":"chain","issuer":{"kind":"prefixAndCertificateSubjectCn","value":"synthetic-cn-"}}
                ],
                "sameSigningIdentitySlots":["primary","secondary"],
                "signingIdentityDistinctFromMutualTlsSlots":["primary","secondary"]
              },
              "requestProjection":{"claimName":"transaction-id","claimValue":"published-claim","bodyMode":"{{{bodyMode}}}","body":"published-body","pathParameters":{{{pathParameters}}}}
            },
            "authorizedCapabilities":{
              "signingSlots":[
                {"slot":"primary","required":true,"signing":{"profileId":"synthetic-primary-signing","revision":1,"keyBinding":"signing-certificate","publicKeySpkiSha256":"{{{signingSpki}}}","issuer":"synthetic-primary-issuer","audience":"synthetic-upstream","subject":"fixed","fixedSubject":"synthetic-fixed-subject","allowedClaims":["transaction-id"],"tokenLifetimeSeconds":60,"clockSkewSeconds":5,"certificateHeader":"chain","temporalClaims":"iat-exp","minimumRsaKeySize":2048},"projection":{"kind":"authorizationBearer"}},
                {"slot":"secondary","required":true,"signing":{"profileId":"synthetic-secondary-signing","revision":1,"keyBinding":"signing-certificate","publicKeySpkiSha256":"{{{signingSpki}}}","issuer":"synthetic-cn-{{{signingSubjectCn}}}","audience":"synthetic-upstream","subject":"fixed","fixedSubject":"synthetic-fixed-subject","allowedClaims":["transaction-id"],"tokenLifetimeSeconds":60,"clockSkewSeconds":5,"certificateHeader":"chain","temporalClaims":"iat-exp","minimumRsaKeySize":2048},"projection":{"kind":"signedTokenHeader","headerName":"X-Synthetic-Signature"}}
              ],
              "restrictedTransport":{"profileId":"synthetic-transport","revision":1,"clientCertificateSpkiSha256":"{{{clientSpki}}}","nearExpirySeconds":30,"bodyMode":"{{{bodyMode}}}"}
            },
            "timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0
          }]
        }
        """;

    private static string ExpectationProbeDefinition(
        string connectorId,
        string version,
        JsonObject? expectationProfile) => $$$"""
        {
          "schemaVersion":"1.0","connectorId":"{{{connectorId}}}","version":"{{{version}}}","displayName":"Synthetic exact absence probe",
          "bindings":{"endpoints":[{"name":"service"}],"secrets":[{"name":"mtls-certificate","kind":"clientCertificate"}]},
          "operations":[{
            "operationId":"signed-submit","endpointBinding":"service","method":"POST","path":"/unused",
            "request":{"contentType":"application/octet-stream","maximumBytes":4096},"response":{"maximumBytes":4096},
            "authentication":{"kind":"mtls","certificateBinding":"mtls-certificate"},"executionStrategy":"synthetic-expectation-probe",
            "extensionConfiguration":{{{(expectationProfile is null ? "{}" : new JsonObject { ["policyExpectations"] = expectationProfile }.ToJsonString())}}},
            "timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0
          }]
        }
        """;
}

internal sealed class BlockingPublicMaterialProvider(
    InMemoryProvider inner,
    Func<CancellationToken, Task> beforeBlockedPublicMaterial,
    int blockOnPublicMaterialCall = 1) :
    IClientCertificateProvider,
    IKeyOperationProvider,
    ICertificateMetadataProvider,
    ICertificatePublicMaterialProvider
{
    private int publicMaterialCalls;
    private int signDigestCalls;

    internal int SignDigestCalls => Volatile.Read(ref signDigestCalls);

    public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken) =>
        inner.GetClientCertificateAsync(logicalReference, cancellationToken);

    public Task<ProviderCertificatePublicMetadata> GetPublicMetadataAsync(string logicalReference, CancellationToken cancellationToken) =>
        inner.GetPublicMetadataAsync(logicalReference, cancellationToken);

    public Task<byte[]> SignDigestAsync(string logicalReference, string algorithm, ReadOnlyMemory<byte> digest, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref signDigestCalls);
        return inner.SignDigestAsync(logicalReference, algorithm, digest, cancellationToken);
    }

    public Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(string logicalReference, CancellationToken cancellationToken) =>
        inner.GetSigningKeyMetadataAsync(logicalReference, cancellationToken);

    public async Task<ProviderCertificatePublicMaterial> GetPublicMaterialAsync(string logicalReference, CancellationToken cancellationToken)
    {
        if (Interlocked.Increment(ref publicMaterialCalls) == blockOnPublicMaterialCall)
            await beforeBlockedPublicMaterial(cancellationToken).ConfigureAwait(false);
        return await inner.GetPublicMaterialAsync(logicalReference, cancellationToken).ConfigureAwait(false);
    }
}

internal sealed class TrackingCapabilityProvider(InMemoryProvider inner) :
    IClientCertificateProvider,
    IKeyOperationProvider,
    ICertificateMetadataProvider,
    ICertificatePublicMaterialProvider
{
    private int totalCalls;
    private int signDigestCalls;

    internal int TotalCalls => Volatile.Read(ref totalCalls);
    internal int SignDigestCalls => Volatile.Read(ref signDigestCalls);

    public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref totalCalls);
        return inner.GetClientCertificateAsync(logicalReference, cancellationToken);
    }

    public Task<ProviderCertificatePublicMetadata> GetPublicMetadataAsync(string logicalReference, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref totalCalls);
        return inner.GetPublicMetadataAsync(logicalReference, cancellationToken);
    }

    public Task<ProviderCertificatePublicMaterial> GetPublicMaterialAsync(string logicalReference, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref totalCalls);
        return inner.GetPublicMaterialAsync(logicalReference, cancellationToken);
    }

    public Task<byte[]> SignDigestAsync(
        string logicalReference,
        string algorithm,
        ReadOnlyMemory<byte> digest,
        CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref totalCalls);
        Interlocked.Increment(ref signDigestCalls);
        return inner.SignDigestAsync(logicalReference, algorithm, digest, cancellationToken);
    }

    public Task<ProviderSigningKeyPublicMetadata> GetSigningKeyMetadataAsync(
        string logicalReference,
        CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref totalCalls);
        return inner.GetSigningKeyMetadataAsync(logicalReference, cancellationToken);
    }
}

internal sealed class SyntheticSignedMutualTlsServer : IAsyncDisposable
{
    private readonly WebApplication application;
    private readonly string expectedClientFingerprint;
    private readonly string expectedSigningFingerprint;
    private readonly string expectedDerivedIssuer;
    private int requests;
    private int expectedClientCertificateObserved;
    private int validSignedTokenObserved;
    private int x5cChainObserved;
    private int publishedClaimObserved;
    private int publishedBodyObserved;
    private int dualSlotTokensObserved;
    private int dualSlotTokensDistinct;
    private int distinctServerOwnedIssuersObserved;
    private int sameSigningIdentityObserved;
    private int legacyBearerObserved;
    private string? lastMethod;
    private string? lastRawTarget;
    private string? lastBody;
    private string? lastContentType;

    private SyntheticSignedMutualTlsServer(
        WebApplication application,
        Uri endpoint,
        string expectedClientFingerprint,
        string expectedSigningFingerprint,
        string expectedDerivedIssuer)
    {
        this.application = application;
        Endpoint = endpoint;
        this.expectedClientFingerprint = expectedClientFingerprint;
        this.expectedSigningFingerprint = expectedSigningFingerprint;
        this.expectedDerivedIssuer = expectedDerivedIssuer;
    }

    internal Uri Endpoint { get; }
    internal int Requests => Volatile.Read(ref requests);
    internal bool ExpectedClientCertificateObserved => Volatile.Read(ref expectedClientCertificateObserved) == 1;
    internal bool ValidSignedTokenObserved => Volatile.Read(ref validSignedTokenObserved) == 1;
    internal bool X5cChainObserved => Volatile.Read(ref x5cChainObserved) == 1;
    internal bool PublishedClaimObserved => Volatile.Read(ref publishedClaimObserved) == 1;
    internal bool PublishedBodyObserved => Volatile.Read(ref publishedBodyObserved) == 1;
    internal bool DualSlotTokensObserved => Volatile.Read(ref dualSlotTokensObserved) == 1;
    internal bool DualSlotTokensDistinct => Volatile.Read(ref dualSlotTokensDistinct) == 1;
    internal bool DistinctServerOwnedIssuersObserved => Volatile.Read(ref distinctServerOwnedIssuersObserved) == 1;
    internal bool SameSigningIdentityObserved => Volatile.Read(ref sameSigningIdentityObserved) == 1;
    internal bool LegacyBearerObserved => Volatile.Read(ref legacyBearerObserved) == 1;
    internal string? LastMethod => Volatile.Read(ref lastMethod);
    internal string? LastRawTarget => Volatile.Read(ref lastRawTarget);
    internal string? LastBody => Volatile.Read(ref lastBody);
    internal string? LastContentType => Volatile.Read(ref lastContentType);

    internal static async Task<SyntheticSignedMutualTlsServer> StartAsync(
        X509Certificate2 serverCertificate,
        X509Certificate2 expectedClientCertificate,
        X509Certificate2 expectedSigningCertificate,
        X509Certificate2 trustedRootCertificate,
        CancellationToken cancellationToken)
    {
        string expectedFingerprint = Convert.ToHexString(SHA256.HashData(expectedClientCertificate.RawData));
        string expectedSigner = Convert.ToHexString(SHA256.HashData(expectedSigningCertificate.RawData));
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(https =>
        {
            https.ServerCertificate = serverCertificate;
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation = (certificate, _, _) =>
                ValidateClientCertificate(certificate, expectedClientCertificate, trustedRootCertificate);
        })));
        WebApplication app = builder.Build();
        SyntheticSignedMutualTlsServer? server = null;
        app.MapPost("/submit", async context =>
        {
            Interlocked.Increment(ref server!.requests);
            X509Certificate2? clientCertificate = await context.Connection.GetClientCertificateAsync(context.RequestAborted);
            if (clientCertificate is not null && string.Equals(
                Convert.ToHexString(SHA256.HashData(clientCertificate.RawData)), server.expectedClientFingerprint, StringComparison.Ordinal))
                Interlocked.Exchange(ref server.expectedClientCertificateObserved, 1);
            string authorization = context.Request.Headers.Authorization.ToString();
            string secondaryHeader = context.Request.Headers["X-Synthetic-Signature"].ToString();
            if (authorization.StartsWith("Bearer ", StringComparison.Ordinal))
            {
                string primaryToken = authorization[7..];
                string expectedPrimaryIssuer = string.IsNullOrEmpty(secondaryHeader)
                    ? "synthetic-gateway"
                    : "synthetic-primary-issuer";
                TokenObservation? primary = ValidateSignedToken(server, primaryToken, expectedPrimaryIssuer);
                TokenObservation? secondary = string.IsNullOrEmpty(secondaryHeader)
                    ? null
                    : ValidateSignedToken(server, secondaryHeader, "synthetic-secondary-issuer");
                if (primary is not null)
                {
                    Interlocked.Exchange(ref server.validSignedTokenObserved, 1);
                    if (secondary is null)
                        Interlocked.Exchange(ref server.legacyBearerObserved, 1);
                    if (primary.PublishedClaim && (secondary is null || secondary.PublishedClaim))
                        Interlocked.Exchange(ref server.publishedClaimObserved, 1);
                    if (secondary is not null)
                    {
                        Interlocked.Exchange(ref server.dualSlotTokensObserved, 1);
                        if (!string.Equals(primary.CompactToken, secondary.CompactToken, StringComparison.Ordinal))
                            Interlocked.Exchange(ref server.dualSlotTokensDistinct, 1);
                        if (!string.Equals(primary.Issuer, secondary.Issuer, StringComparison.Ordinal))
                            Interlocked.Exchange(ref server.distinctServerOwnedIssuersObserved, 1);
                        if (string.Equals(primary.SigningFingerprint, secondary.SigningFingerprint, StringComparison.Ordinal))
                            Interlocked.Exchange(ref server.sameSigningIdentityObserved, 1);
                    }
                }
            }
            using StreamReader reader = new(context.Request.Body, Encoding.UTF8);
            string body = await reader.ReadToEndAsync(context.RequestAborted);
            if (string.Equals(body, "published-body", StringComparison.Ordinal))
                Interlocked.Exchange(ref server.publishedBodyObserved, 1);
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"accepted\":true}", context.RequestAborted);
        });
        app.MapMethods("/bounded/{**remainder}", ["GET", "DELETE", "POST"], async context =>
        {
            Interlocked.Increment(ref server!.requests);
            Volatile.Write(ref server.lastMethod, context.Request.Method);
            Volatile.Write(ref server.lastRawTarget,
                context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? context.Request.Path.Value);
            Volatile.Write(ref server.lastContentType, context.Request.ContentType);
            X509Certificate2? clientCertificate = await context.Connection.GetClientCertificateAsync(context.RequestAborted);
            if (clientCertificate is not null && string.Equals(
                Convert.ToHexString(SHA256.HashData(clientCertificate.RawData)), server.expectedClientFingerprint, StringComparison.Ordinal))
                Interlocked.Exchange(ref server.expectedClientCertificateObserved, 1);
            string authorization = context.Request.Headers.Authorization.ToString();
            string secondaryHeader = context.Request.Headers["X-Synthetic-Signature"].ToString();
            if (authorization.StartsWith("Bearer ", StringComparison.Ordinal) && !string.IsNullOrEmpty(secondaryHeader))
            {
                TokenObservation? primary = ValidateSignedToken(server, authorization[7..], "synthetic-primary-issuer");
                TokenObservation? secondary = ValidateSignedToken(server, secondaryHeader, server.expectedDerivedIssuer);
                if (primary is not null && secondary is not null)
                {
                    Interlocked.Exchange(ref server.validSignedTokenObserved, 1);
                    Interlocked.Exchange(ref server.dualSlotTokensObserved, 1);
                    if (string.Equals(primary.SigningFingerprint, secondary.SigningFingerprint, StringComparison.Ordinal))
                        Interlocked.Exchange(ref server.sameSigningIdentityObserved, 1);
                }
            }
            using StreamReader reader = new(context.Request.Body, Encoding.UTF8);
            Volatile.Write(ref server.lastBody, await reader.ReadToEndAsync(context.RequestAborted));
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"accepted\":true}", context.RequestAborted);
        });
        await app.StartAsync(cancellationToken);
        string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        Uri listening = new(address, UriKind.Absolute);
        server = new(
            app,
            new Uri($"https://localhost:{listening.Port}/", UriKind.Absolute),
            expectedFingerprint,
            expectedSigner,
            "synthetic-cn-" + expectedSigningCertificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false));
        return server;
    }

    internal static bool ValidateClientCertificate(
        X509Certificate2 certificate,
        X509Certificate2 expectedCertificate,
        X509Certificate2 trustedRootCertificate)
    {
        if (!CryptographicOperations.FixedTimeEquals(certificate.RawData, expectedCertificate.RawData))
            return false;

        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(trustedRootCertificate);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        return chain.Build(certificate);
    }

    private static TokenObservation? ValidateSignedToken(
        SyntheticSignedMutualTlsServer server,
        string compactToken,
        string expectedIssuer)
    {
        string[] parts = compactToken.Split('.');
        if (parts.Length != 3) return null;
        try
        {
            using JsonDocument header = JsonDocument.Parse(Decode(parts[0]));
            using JsonDocument payload = JsonDocument.Parse(Decode(parts[1]));
            if (!header.RootElement.TryGetProperty("x5c", out JsonElement chain) ||
                chain.ValueKind != JsonValueKind.Array || chain.GetArrayLength() != 2)
                return null;
            byte[] leafDer = Convert.FromBase64String(chain[0].GetString()!);
            using X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(leafDer);
            using RSA rsa = leaf.GetRSAPublicKey() ?? throw new CryptographicException();
            string fingerprint = Convert.ToHexString(SHA256.HashData(leaf.RawData));
            bool expectedLeaf = string.Equals(fingerprint, server.expectedSigningFingerprint, StringComparison.Ordinal);
            bool signatureValid = rsa.VerifyData(
                Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]),
                Decode(parts[2]),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            string issuer = payload.RootElement.GetProperty("iss").GetString()!;
            bool fixedClaims = string.Equals(issuer, expectedIssuer, StringComparison.Ordinal) &&
                string.Equals(payload.RootElement.GetProperty("aud").GetString(), "synthetic-upstream", StringComparison.Ordinal);
            if (!expectedLeaf || !signatureValid || !fixedClaims) return null;
            Interlocked.Exchange(ref server.x5cChainObserved, 1);
            bool publishedClaim = payload.RootElement.TryGetProperty("transaction-id", out JsonElement claim) &&
                string.Equals(claim.GetString(), "published-claim", StringComparison.Ordinal);
            return new(compactToken, issuer, fingerprint, publishedClaim);
        }
        catch (Exception exception) when (exception is JsonException or FormatException or CryptographicException or KeyNotFoundException)
        {
            return null;
        }
    }

    private static byte[] Decode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }

    private sealed record TokenObservation(
        string CompactToken,
        string Issuer,
        string SigningFingerprint,
        bool PublishedClaim);

    public async ValueTask DisposeAsync()
    {
        await application.StopAsync();
        await application.DisposeAsync();
    }
}

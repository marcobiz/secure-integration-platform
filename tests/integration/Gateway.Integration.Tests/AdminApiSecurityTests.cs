using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.Http.Json;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SecureIntegration.Gateway.Api;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

public sealed class AdminApiSecurityTests
{
    private static readonly JsonSerializerOptions WireJson = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    [Fact]
    public async Task M5_E2E_Admin_approval_publish_runtime_provider_transport_prevents_credential_exfiltration()
    {
        await using AntiExfiltrationFactory factory = new();
        using HttpClient editor = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        using HttpClient approver = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string editorCsrf = await LoginAsync(editor, "security-admin", TestContext.Current.CancellationToken);
        string canary = "m5-e2e-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        string syntheticConnectionString = $"Host=db.invalid;Password={Convert.ToHexString(RandomNumberGenerator.GetBytes(24))}";
        using CertificateSet certificates = CertificateSet.Create("approved.vendor.example", DateTimeOffset.UtcNow.AddDays(5));
        X509Certificate2 created = certificates.ClientCertificate;
        byte[] pfx = created.Export(X509ContentType.Pkcs12);
        string privatePem = certificates.ClientPrivateKeyPem;
        string pfxBase64 = Convert.ToBase64String(pfx);
        CertificatePublicMetadata publicMetadata = new(Convert.ToHexString(SHA256.HashData(created.RawData)), created.Subject, created.Issuer, created.NotBefore, created.NotAfter, "RSA", 2048, created.SerialNumber);

        Guid environmentId = Guid.NewGuid(); Guid tenantId = Guid.NewGuid(); Guid applicationId = Guid.NewGuid(); Guid installationId = Guid.NewGuid();
        InMemoryGatewayRegistry registry = factory.Services.GetRequiredService<InMemoryGatewayRegistry>();
        await registry.AddEnvironmentAsync(new(environmentId, "m5-e2e", "M5 E2E", false), TestContext.Current.CancellationToken);
        await registry.AddTenantAsync(new(tenantId, "m5-e2e", "M5 E2E", TenantStatus.Active, DateTimeOffset.UtcNow), TestContext.Current.CancellationToken);
        await registry.AddApplicationAsync(new(applicationId, "m5-e2e", "M5 E2E", ApplicationStatus.Active, "3.0.0", null, DateTimeOffset.UtcNow), TestContext.Current.CancellationToken);
        await registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Active, "3.0.0", DateTimeOffset.UtcNow), TestContext.Current.CancellationToken);

        ConnectorVersionResource version = await ImportAndValidateSampleAsync(editor, editorCsrf, TestContext.Current.CancellationToken);
        await registry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, version.ConnectorId, "submit", true, DateTimeOffset.UtcNow.AddMinutes(-1)), TestContext.Current.CancellationToken);
        IConnectorConfigurationStore store = factory.Services.GetRequiredService<IConnectorConfigurationStore>();
        ProviderResourceCatalogRecord secret = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "instrumented", "Instrumented provider", "synthetic", "api-key", ProviderResourceType.Secret, "Vendor API key", environmentId, version.ConnectorId, "submit", "instrumented://api-key", ProviderResourceStatus.Active, "api-v1", 0, null, null, string.Empty, DateTimeOffset.UtcNow), TestContext.Current.CancellationToken);
        _ = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "instrumented", "Instrumented provider", "synthetic", "certificate", ProviderResourceType.ClientCertificate, "Vendor certificate", environmentId, version.ConnectorId, "submit", "instrumented://certificate", ProviderResourceStatus.Active, "cert-resource-v1", 0, 1, publicMetadata, string.Empty, DateTimeOffset.UtcNow), TestContext.Current.CancellationToken);
        string syntheticPassword = "m5-password-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(18));
        string[] hostileResourceIds = [canary, syntheticPassword, privatePem, pfxBase64, syntheticConnectionString, "https://attacker.example/credential", "missing-resource"];
        foreach (string hostileResourceId in hostileResourceIds)
        {
            ProviderResourceReference hostileReference = new("instrumented", hostileResourceId, ProviderResourceType.Secret, "api-v1");
            try
            {
                ProviderResourceReferenceValidator.Validate(hostileReference);
                GatewayException absent = await Assert.ThrowsAsync<GatewayException>(() => store.ResolveProviderResourceAsync(hostileReference, environmentId, version.ConnectorId, ["submit"], TestContext.Current.CancellationToken));
                Assert.Equal("BGW-PROVIDER-RESOURCE-NOT-FOUND", absent.Code);
            }
            catch (GatewayException denied)
            {
                Assert.Equal("BGW-PROVIDER-RESOURCE-REFERENCE-DENIED", denied.Code);
            }
        }

        await using RealVendorMock vendor = await RealVendorMock.StartAsync(certificates, canary, publicMetadata.FingerprintSha256, TestContext.Current.CancellationToken);
        object binding = new
        {
            environmentId,
            connectorVersion = version.Version,
            endpoints = new Dictionary<string, string> { ["sample-vendor-endpoint"] = $"https://approved.vendor.example:{vendor.Port}/" },
            secretResources = new Dictionary<string, object> { ["sample-vendor-api-key"] = new { providerId = "instrumented", resourceId = "api-key", resourceType = "Secret", version = "api-v1" } },
            certificateResources = new Dictionary<string, object> { ["sample-vendor-client-certificate"] = new { providerId = "instrumented", resourceId = "certificate", resourceType = "ClientCertificate", version = "cert-resource-v1", publicMetadataRevision = 1 } }
        };
        using (HttpResponseMessage response = await PutBindingAsync(editor, version.ConnectorId, binding, editorCsrf, null)) response.EnsureSuccessStatusCode();

        InstrumentedProvider provider = new(canary, pfx);
        CountingRestrictedTransport transport = new(new SystemRestrictedTransport(new X509Certificate2Collection(certificates.RootCertificate), Convert.ToHexString(SHA256.HashData(certificates.ServerCertificate.RawData))));
        PublishedConnectorCatalog runtimeCatalog = new(store, new ConnectorDefinitionValidator(), new SystemGatewayClock(), TimeSpan.FromMinutes(5));
        RestrictedEgressService runtime = new(registry, runtimeCatalog, provider, provider, new LoopbackResolver(), transport, new SystemGatewayClock(), new ExactLoopbackAllowance("approved.vendor.example"));
        RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active, Guid.NewGuid(), CredentialStatus.Active, created.RawData, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1), "3.0.0", null);
        GatewayInvokeRequest invocation = new("1.0", new("application/json", "utf8", "{\"synthetic\":true}"), Guid.NewGuid());

        await Assert.ThrowsAsync<GatewayException>(() => runtime.InvokeAsync(new(identity, invocation.CorrelationId), version.ConnectorId, "submit", invocation, TestContext.Current.CancellationToken));
        Assert.Equal(0, provider.SecretInvocations); Assert.Equal(0, transport.Invocations); Assert.Equal(0, vendor.Requests);

        using HttpRequestMessage requestApproval = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}/approval-requests");
        requestApproval.Headers.Add("X-CSRF-TOKEN", editorCsrf);
        using HttpResponseMessage requested = await editor.SendAsync(requestApproval, TestContext.Current.CancellationToken); requested.EnsureSuccessStatusCode();
        JsonElement approvalRequest = await requested.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        string approvalId = approvalRequest.GetProperty("id").GetString()!;
        using HttpResponseMessage reviewResponse = await editor.GetAsync($"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}/approval-review", TestContext.Current.CancellationToken); reviewResponse.EnsureSuccessStatusCode();
        string reviewJson = await reviewResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        using JsonDocument review = JsonDocument.Parse(reviewJson);
        string digest = review.RootElement.GetProperty("digestSha256").GetString()!;
        JsonElement certificateReview = review.RootElement.GetProperty("artifact").GetProperty("operations")[0].GetProperty("certificateBindings")[0];
        Assert.Equal("cert-resource-v1", certificateReview.GetProperty("resourceVersion").GetString());
        Assert.Equal(created.SerialNumber, certificateReview.GetProperty("certificateVersion").GetString());
        Assert.Equal(1, certificateReview.GetProperty("publicMetadataRevision").GetInt64());
        Assert.DoesNotContain(canary, reviewJson, StringComparison.Ordinal); Assert.DoesNotContain(privatePem, reviewJson, StringComparison.Ordinal); Assert.DoesNotContain(pfxBase64, reviewJson, StringComparison.Ordinal); Assert.DoesNotContain(syntheticConnectionString, reviewJson, StringComparison.Ordinal);

        string approverCsrf = await LoginAsync(approver, "approver", TestContext.Current.CancellationToken);
        using HttpRequestMessage approve = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}/approvals") { Content = JsonContent.Create(new { approvalRequestId = approvalId, expectedDigestSha256 = digest }) };
        approve.Headers.Add("X-CSRF-TOKEN", approverCsrf);
        using (HttpResponseMessage approved = await approver.SendAsync(approve, TestContext.Current.CancellationToken)) approved.EnsureSuccessStatusCode();
        await Assert.ThrowsAsync<GatewayException>(() => runtime.InvokeAsync(new(identity, invocation.CorrelationId), version.ConnectorId, "submit", invocation, TestContext.Current.CancellationToken));
        Assert.Equal(0, provider.SecretInvocations); Assert.Equal(0, transport.Invocations); Assert.Equal(0, vendor.Requests);

        using HttpRequestMessage publish = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}:publish") { Content = JsonContent.Create(new { expectedRowVersion = version.RowVersion, expectedPublicationRevision = 0 }) };
        publish.Headers.Add("X-CSRF-TOKEN", approverCsrf); publish.Headers.TryAddWithoutValidation("If-Match", $"\"{version.RowVersion}\"");
        using (HttpResponseMessage published = await approver.SendAsync(publish, TestContext.Current.CancellationToken))
            Assert.True(published.IsSuccessStatusCode, $"{published.StatusCode}: {await published.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)}");
        GatewayInvokeResponse result = await runtime.InvokeAsync(new(identity, invocation.CorrelationId), version.ConnectorId, "submit", invocation, TestContext.Current.CancellationToken);
        Assert.Equal(1, provider.SecretInvocations); Assert.Equal(1, provider.CertificateInvocations); Assert.Equal(1, transport.Invocations);
        Assert.Equal(1, vendor.Requests); Assert.True(vendor.ApiKeyMatched); Assert.True(vendor.ClientCertificateMatched); Assert.Equal(invocation.CorrelationId, vendor.CorrelationId);
        Assert.Contains("accepted", Encoding.UTF8.GetString(Convert.FromBase64String(result.Result.Data)), StringComparison.Ordinal);
        Assert.DoesNotContain(canary, JsonSerializer.Serialize(result), StringComparison.Ordinal);

        int secretCount = provider.SecretInvocations; int transportCount = transport.Invocations;
        GatewayException attacker = await Assert.ThrowsAsync<GatewayException>(() => runtime.InvokeAsync(new(identity, Guid.NewGuid()), version.ConnectorId, "attacker-operation", invocation with { CorrelationId = Guid.NewGuid() }, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-AUTHZ-OPERATION-DENIED", attacker.Code); Assert.Equal(secretCount, provider.SecretInvocations); Assert.Equal(transportCount, transport.Invocations); Assert.Equal(1, vendor.Requests);

        ProviderResourceCatalogRecord rotatedResource = await store.RegisterProviderResourceAsync(secret with { Id = Guid.NewGuid(), ProviderReference = "instrumented://rotated", Revision = 0, ChecksumSha256 = string.Empty, CreatedAt = DateTimeOffset.UtcNow.AddSeconds(1) }, TestContext.Current.CancellationToken);
        GatewayException stale = await Assert.ThrowsAsync<GatewayException>(() => runtime.InvokeAsync(new(identity, Guid.NewGuid()), version.ConnectorId, "submit", invocation with { CorrelationId = Guid.NewGuid() }, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-RESOURCE-REVISION-STALE", stale.Code); Assert.Equal(secretCount, provider.SecretInvocations); Assert.Equal(transportCount, transport.Invocations);
        Assert.Equal(1, vendor.Requests);

        string rotatedCanary = "m5-e2e-rotated-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        provider.Register("instrumented://rotated", rotatedCanary); vendor.ExpectedApiKey = rotatedCanary;
        ConnectorVersionResource version2 = await ImportAndValidateSampleAsync(editor, editorCsrf, TestContext.Current.CancellationToken, "2.0.0");
        object binding2 = new
        {
            environmentId, connectorVersion = version2.Version,
            endpoints = new Dictionary<string, string> { ["sample-vendor-endpoint"] = $"https://approved.vendor.example:{vendor.Port}/" },
            secretResources = new Dictionary<string, object> { ["sample-vendor-api-key"] = new { providerId = "instrumented", resourceId = "api-key", resourceType = "Secret", version = "api-v1" } },
            certificateResources = new Dictionary<string, object> { ["sample-vendor-client-certificate"] = new { providerId = "instrumented", resourceId = "certificate", resourceType = "ClientCertificate", version = "cert-resource-v1", publicMetadataRevision = 1 } }
        };
        using (HttpResponseMessage response = await PutBindingAsync(editor, version2.ConnectorId, binding2, editorCsrf, null)) response.EnsureSuccessStatusCode();
        using HttpRequestMessage requestApproval2 = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version2.ConnectorId}/versions/{version2.Version}/approval-requests"); requestApproval2.Headers.Add("X-CSRF-TOKEN", editorCsrf);
        using HttpResponseMessage requested2 = await editor.SendAsync(requestApproval2, TestContext.Current.CancellationToken); requested2.EnsureSuccessStatusCode();
        JsonElement approvalRequest2 = await requested2.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        using HttpResponseMessage reviewResponse2 = await editor.GetAsync($"/admin/api/v1/connectors/{version2.ConnectorId}/versions/{version2.Version}/approval-review", TestContext.Current.CancellationToken); reviewResponse2.EnsureSuccessStatusCode();
        JsonElement review2 = await reviewResponse2.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        using HttpRequestMessage approve2 = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version2.ConnectorId}/versions/{version2.Version}/approvals") { Content = JsonContent.Create(new { approvalRequestId = approvalRequest2.GetProperty("id").GetString(), expectedDigestSha256 = review2.GetProperty("digestSha256").GetString() }) }; approve2.Headers.Add("X-CSRF-TOKEN", approverCsrf);
        using (HttpResponseMessage approved2 = await approver.SendAsync(approve2, TestContext.Current.CancellationToken)) approved2.EnsureSuccessStatusCode();
        using HttpRequestMessage publish2 = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version2.ConnectorId}/versions/{version2.Version}:publish") { Content = JsonContent.Create(new { expectedRowVersion = version2.RowVersion, expectedPublicationRevision = 1 }) }; publish2.Headers.Add("X-CSRF-TOKEN", approverCsrf); publish2.Headers.TryAddWithoutValidation("If-Match", $"\"{version2.RowVersion}\"");
        using (HttpResponseMessage published2 = await approver.SendAsync(publish2, TestContext.Current.CancellationToken)) published2.EnsureSuccessStatusCode();
        GatewayInvokeRequest rotatedInvocation = invocation with { CorrelationId = Guid.NewGuid() };
        _ = await runtime.InvokeAsync(new(identity, rotatedInvocation.CorrelationId), version2.ConnectorId, "submit", rotatedInvocation, TestContext.Current.CancellationToken);
        Assert.Equal(2, provider.SecretInvocations); Assert.Equal(2, transport.Invocations); Assert.Equal(2, vendor.Requests); Assert.Equal(rotatedInvocation.CorrelationId, vendor.CorrelationId);

        _ = await store.RegisterProviderResourceAsync(rotatedResource with { Id = Guid.NewGuid(), Status = ProviderResourceStatus.Disabled, Revision = 0, ChecksumSha256 = string.Empty, CreatedAt = DateTimeOffset.UtcNow.AddSeconds(2) }, TestContext.Current.CancellationToken);
        GatewayException disabled = await Assert.ThrowsAsync<GatewayException>(() => runtime.InvokeAsync(new(identity, Guid.NewGuid()), version2.ConnectorId, "submit", invocation with { CorrelationId = Guid.NewGuid() }, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-RESOURCE-REVISION-STALE", disabled.Code); Assert.Equal(2, provider.SecretInvocations); Assert.Equal(2, transport.Invocations); Assert.Equal(2, vendor.Requests);
        Assert.DoesNotContain(canary, JsonSerializer.Serialize(registry.SnapshotAuditEvents()), StringComparison.Ordinal);
        Assert.DoesNotContain(rotatedCanary, JsonSerializer.Serialize(registry.SnapshotAuditEvents()), StringComparison.Ordinal);
        Assert.DoesNotContain(canary, reviewJson, StringComparison.Ordinal);
    }
    [Fact]
    public async Task M5_IT_Anonymous_is_denied_and_security_headers_are_present()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        using HttpResponseMessage response = await client.GetAsync("/admin/api/v1/dashboard", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Contains("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task M5_IT_Middleware_denial_is_fail_closed_when_persistent_audit_fails()
    {
        await using DenialAuditFailureFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        using HttpResponseMessage response = await client.GetAsync("/admin/api/v1/dashboard", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Empty(factory.Services.GetRequiredService<InMemoryGatewayRegistry>().SnapshotAuditEvents());
    }

    [Fact]
    public async Task M5_IT_Mutation_without_CSRF_is_denied()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        using HttpResponseMessage response = await client.PostAsJsonAsync("/admin/api/v1/tenants", new { code = "missing-csrf", displayName = "Missing CSRF" }, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("BGW-ADMIN-CSRF", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
        GatewayAuditEvent denial = Assert.Single(factory.Services.GetRequiredService<InMemoryGatewayRegistry>().SnapshotAuditEvents(), value => value.Outcome == "denied");
        Assert.Equal("BGW-ADMIN-CSRF", denial.ReasonCode);
        Assert.Equal("admin.request.denied", denial.Action);
        Assert.Equal("method", Assert.Single(denial.Metadata.Keys));
        Assert.DoesNotContain("missing-csrf", System.Text.Json.JsonSerializer.Serialize(denial), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task M5_IT_Viewer_cannot_mutate_but_can_read()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "viewer", TestContext.Current.CancellationToken);
        using HttpResponseMessage read = await client.GetAsync("/admin/api/v1/tenants", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
        using HttpRequestMessage mutation = new(HttpMethod.Post, "/admin/api/v1/tenants") { Content = JsonContent.Create(new { code = "viewer-denied", displayName = "Viewer denied" }) };
        mutation.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage denied = await client.SendAsync(mutation, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        GatewayAuditEvent audit = Assert.Single(factory.Services.GetRequiredService<InMemoryGatewayRegistry>().SnapshotAuditEvents(), value => value.Outcome == "denied");
        Assert.Equal("BGW-ADMIN-AUTHORIZATION", audit.ReasonCode);
        Assert.Equal(denied.Headers.GetValues("X-Correlation-ID").Single(), audit.CorrelationId.ToString("D"));
    }

    [Fact]
    public async Task M5_IT_Security_admin_creates_resources_and_activation_is_returned_once()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        Guid tenantId = await CreateAndGetIdAsync(client, "/admin/api/v1/tenants", new { code = "tenant-m5", displayName = "Tenant M5" }, csrf);
        Guid applicationId = await CreateAndGetIdAsync(client, "/admin/api/v1/applications", new { code = "app-m5", displayName = "App M5", minimumBrokerVersion = "3.0.0", maximumBrokerVersion = (string?)null }, csrf);
        using (HttpRequestMessage updateTenant = new(HttpMethod.Put, $"/admin/api/v1/tenants/{tenantId:D}") { Content = JsonContent.Create(new { displayName = "Tenant M5 updated" }) })
        {
            updateTenant.Headers.Add("X-CSRF-TOKEN", csrf);
            updateTenant.Headers.TryAddWithoutValidation("If-Match", "\"1\"");
            using HttpResponseMessage updated = await client.SendAsync(updateTenant, TestContext.Current.CancellationToken);
            updated.EnsureSuccessStatusCode();
        }
        using (HttpRequestMessage disableApplication = new(HttpMethod.Post, $"/admin/api/v1/applications/{applicationId:D}:disable"))
        {
            disableApplication.Headers.Add("X-CSRF-TOKEN", csrf);
            disableApplication.Headers.TryAddWithoutValidation("If-Match", "\"1\"");
            using HttpResponseMessage disabled = await client.SendAsync(disableApplication, TestContext.Current.CancellationToken);
            disabled.EnsureSuccessStatusCode();
        }
        GatewayAuditEvent[] atomicAudit = factory.Services.GetRequiredService<InMemoryGatewayRegistry>().SnapshotAuditEvents().ToArray();
        Assert.Single(atomicAudit, value => value.Action == "tenant.update" && value.TargetId == tenantId.ToString("D"));
        Assert.Single(atomicAudit, value => value.Action == "application.disable" && value.TargetId == applicationId.ToString("D"));

        // Development catalogue is seeded only with resources explicitly created by this test.
        Guid environmentId = Guid.NewGuid();
        InMemoryGatewayRegistry registry = factory.Services.GetRequiredService<InMemoryGatewayRegistry>();
        await registry.AddEnvironmentAsync(new(environmentId, "local", "Local", false), TestContext.Current.CancellationToken);
        using HttpRequestMessage create = new(HttpMethod.Post, "/admin/api/v1/installations") { Content = JsonContent.Create(new { tenantId, applicationId, environmentId }) };
        create.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage response = await client.SendAsync(create, TestContext.Current.CancellationToken);
        string body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Contains("activationCode", body, StringComparison.Ordinal);
        using HttpResponseMessage listed = await client.GetAsync($"/admin/api/v1/installations?tenantId={tenantId:D}", TestContext.Current.CancellationToken);
        string listBody = await listed.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
        Assert.DoesNotContain("activationCode", listBody, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task M5_IT_Tenant_and_application_require_current_IfMatch_without_lost_updates()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        Guid tenantId = await CreateAndGetIdAsync(client, "/admin/api/v1/tenants", new { code = "etag-tenant", displayName = "Original tenant" }, csrf);
        Guid applicationId = await CreateAndGetIdAsync(client, "/admin/api/v1/applications", new { code = "etag-app", displayName = "Original app", minimumBrokerVersion = "3.0.0", maximumBrokerVersion = (string?)null }, csrf);

        using HttpResponseMessage tenantGet = await client.GetAsync($"/admin/api/v1/tenants/{tenantId:D}", TestContext.Current.CancellationToken);
        Assert.Equal("\"1\"", tenantGet.Headers.ETag?.Tag);
        using HttpRequestMessage missing = new(HttpMethod.Put, $"/admin/api/v1/tenants/{tenantId:D}") { Content = JsonContent.Create(new { displayName = "Missing precondition" }) };
        missing.Headers.Add("X-CSRF-TOKEN", csrf); using HttpResponseMessage missingResponse = await client.SendAsync(missing, TestContext.Current.CancellationToken); Assert.Equal((HttpStatusCode)428, missingResponse.StatusCode);
        using HttpRequestMessage tenantA = new(HttpMethod.Put, $"/admin/api/v1/tenants/{tenantId:D}") { Content = JsonContent.Create(new { displayName = "Admin A" }) };
        tenantA.Headers.Add("X-CSRF-TOKEN", csrf); tenantA.Headers.TryAddWithoutValidation("If-Match", "\"1\""); using HttpResponseMessage tenantAResponse = await client.SendAsync(tenantA, TestContext.Current.CancellationToken); tenantAResponse.EnsureSuccessStatusCode();
        using HttpRequestMessage tenantB = new(HttpMethod.Put, $"/admin/api/v1/tenants/{tenantId:D}") { Content = JsonContent.Create(new { displayName = "Admin B" }) };
        tenantB.Headers.Add("X-CSRF-TOKEN", csrf); tenantB.Headers.TryAddWithoutValidation("If-Match", "\"1\""); using HttpResponseMessage tenantBResponse = await client.SendAsync(tenantB, TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.Conflict, tenantBResponse.StatusCode);
        JsonElement currentTenant = await tenantAResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken); Assert.Equal("Admin A", currentTenant.GetProperty("displayName").GetString()); Assert.Equal(2, currentTenant.GetProperty("rowVersion").GetInt64());

        using HttpResponseMessage applicationGet = await client.GetAsync($"/admin/api/v1/applications/{applicationId:D}", TestContext.Current.CancellationToken); Assert.Equal("\"1\"", applicationGet.Headers.ETag?.Tag);
        using HttpRequestMessage applicationA = new(HttpMethod.Put, $"/admin/api/v1/applications/{applicationId:D}") { Content = JsonContent.Create(new { displayName = "Admin A", minimumBrokerVersion = "3.1.0", maximumBrokerVersion = (string?)null }) };
        applicationA.Headers.Add("X-CSRF-TOKEN", csrf); applicationA.Headers.TryAddWithoutValidation("If-Match", "\"1\""); using HttpResponseMessage applicationAResponse = await client.SendAsync(applicationA, TestContext.Current.CancellationToken); applicationAResponse.EnsureSuccessStatusCode();
        using HttpRequestMessage applicationB = new(HttpMethod.Post, $"/admin/api/v1/applications/{applicationId:D}:disable");
        applicationB.Headers.Add("X-CSRF-TOKEN", csrf); applicationB.Headers.TryAddWithoutValidation("If-Match", "\"1\""); using HttpResponseMessage applicationBResponse = await client.SendAsync(applicationB, TestContext.Current.CancellationToken); Assert.Equal(HttpStatusCode.Conflict, applicationBResponse.StatusCode);
        Assert.Equal(2, factory.Services.GetRequiredService<InMemoryGatewayRegistry>().SnapshotAuditEvents().Count(value => value.Action is "tenant.update" or "application.update"));
    }

    [Fact]
    public async Task M5_IT_Logout_invalidates_cookie_session()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "viewer", TestContext.Current.CancellationToken);
        using HttpRequestMessage logout = new(HttpMethod.Post, "/admin/auth/logout"); logout.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage signedOut = await client.SendAsync(logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, signedOut.StatusCode);
        client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        using HttpResponseMessage me = await client.GetAsync("/admin/auth/me", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [Fact]
    public async Task M5_IT_Captured_cookie_cannot_be_replayed_after_logout()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        (string csrf, string capturedCookie) = await LoginAndCaptureCookieAsync(client, "viewer", TestContext.Current.CancellationToken);
        using HttpRequestMessage logout = new(HttpMethod.Post, "/admin/auth/logout");
        logout.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage signedOut = await client.SendAsync(logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, signedOut.StatusCode);

        using HttpClient replay = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = false });
        using HttpRequestMessage request = new(HttpMethod.Get, "/admin/auth/me");
        request.Headers.Add("Cookie", capturedCookie);
        request.Headers.Accept.ParseAdd("application/json");
        using HttpResponseMessage denied = await replay.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
    }

    [Fact]
    public async Task M5_IT_Reauthentication_rotates_session_and_invalidates_the_previous_cookie()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        (_, string firstCookie) = await LoginAndCaptureCookieAsync(client, "viewer", TestContext.Current.CancellationToken);
        (_, string secondCookie) = await LoginAndCaptureCookieAsync(client, "viewer", TestContext.Current.CancellationToken);
        Assert.NotEqual(firstCookie, secondCookie);

        using HttpClient replay = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = false });
        using HttpRequestMessage oldRequest = new(HttpMethod.Get, "/admin/auth/me");
        oldRequest.Headers.Add("Cookie", firstCookie);
        oldRequest.Headers.Accept.ParseAdd("application/json");
        using HttpResponseMessage oldResponse = await replay.SendAsync(oldRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, oldResponse.StatusCode);

        using HttpRequestMessage currentRequest = new(HttpMethod.Get, "/admin/auth/me");
        currentRequest.Headers.Add("Cookie", secondCookie);
        currentRequest.Headers.Accept.ParseAdd("application/json");
        using HttpResponseMessage currentResponse = await replay.SendAsync(currentRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, currentResponse.StatusCode);
    }

    [Fact]
    public async Task M5_IT_Role_revocation_immediately_invalidates_all_target_sessions()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient viewer = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        _ = await LoginAsync(viewer, "viewer", TestContext.Current.CancellationToken);

        using HttpClient administrator = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string adminCsrf = await LoginAsync(administrator, "security-admin", TestContext.Current.CancellationToken);
        using HttpRequestMessage assign = new(HttpMethod.Post, "/admin/api/v1/role-assignments")
        {
            Content = JsonContent.Create(new { principal = new { issuer = "https://development.invalid", subject = "viewer", displayName = "viewer" }, role = "Operator", tenantId = (Guid?)null })
        };
        assign.Headers.Add("X-CSRF-TOKEN", adminCsrf);
        using HttpResponseMessage assignedResponse = await administrator.SendAsync(assign, TestContext.Current.CancellationToken);
        assignedResponse.EnsureSuccessStatusCode();
        System.Text.Json.JsonElement assigned = await assignedResponse.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>(cancellationToken: TestContext.Current.CancellationToken);

        (_, string refreshedViewerCookie) = await LoginAndCaptureCookieAsync(viewer, "viewer", TestContext.Current.CancellationToken);
        using HttpRequestMessage revoke = new(HttpMethod.Delete, $"/admin/api/v1/role-assignments/{assigned.GetProperty("id").GetGuid():D}");
        revoke.Headers.Add("X-CSRF-TOKEN", adminCsrf);
        using HttpResponseMessage revoked = await administrator.SendAsync(revoke, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);

        using HttpClient replay = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = false });
        using HttpRequestMessage request = new(HttpMethod.Get, "/admin/auth/me");
        request.Headers.Add("Cookie", refreshedViewerCookie);
        request.Headers.Accept.ParseAdd("application/json");
        using HttpResponseMessage response = await replay.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task M5_IT_Role_assignment_is_server_authorized_and_audited()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        using HttpRequestMessage request = new(HttpMethod.Post, "/admin/api/v1/role-assignments")
        {
            Content = JsonContent.Create(new { principal = new { issuer = "https://issuer.example.invalid", subject = "audited-viewer", displayName = "Audited viewer", email = (string?)null }, role = "Viewer", tenantId = (Guid?)null })
        };
        request.Headers.Add("X-CSRF-TOKEN", csrf);

        using HttpResponseMessage response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        InMemoryGatewayRegistry registry = factory.Services.GetRequiredService<InMemoryGatewayRegistry>();
        GatewayAuditEvent audit = Assert.Single(registry.SnapshotAuditEvents(), value => value.Action == "admin.role.assign" && value.TargetId != value.ActorId);
        Assert.Equal("success", audit.Outcome);
        Assert.DoesNotContain("issuer.example.invalid", System.Text.Json.JsonSerializer.Serialize(audit), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task M5_IT_Canonical_connector_sample_is_served_validated_and_imported_as_Draft()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);

        using HttpResponseMessage schema = await client.GetAsync("/admin/api/v1/connectors/schema", TestContext.Current.CancellationToken);
        using HttpResponseMessage sample = await client.GetAsync("/admin/api/v1/connectors/sample", TestContext.Current.CancellationToken);
        schema.EnsureSuccessStatusCode();
        sample.EnsureSuccessStatusCode();
        using System.Text.Json.JsonDocument definition = await System.Text.Json.JsonDocument.ParseAsync(await sample.Content.ReadAsStreamAsync(TestContext.Current.CancellationToken), cancellationToken: TestContext.Current.CancellationToken);

        using HttpRequestMessage validate = new(HttpMethod.Post, "/admin/api/v1/connectors:validate") { Content = JsonContent.Create(new ConnectorImportRequest(definition.RootElement.Clone())) };
        validate.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage validationResponse = await client.SendAsync(validate, TestContext.Current.CancellationToken);
        ConnectorValidationResult result = (await validationResponse.Content.ReadFromJsonAsync<ConnectorValidationResult>(cancellationToken: TestContext.Current.CancellationToken))!;
        Assert.True(result.Valid);
        Assert.Empty(result.Issues);

        using HttpRequestMessage import = new(HttpMethod.Post, "/admin/api/v1/connectors:import") { Content = JsonContent.Create(new ConnectorImportRequest(definition.RootElement.Clone(), result.ChecksumSha256)) };
        import.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage importResponse = await client.SendAsync(import, TestContext.Current.CancellationToken);
        string importJson = await importResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("\"state\":\"Draft\"", importJson, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Created, importResponse.StatusCode);
    }

    [Fact]
    public async Task M5_IT_Binding_update_requires_current_IfMatch_and_precondition_failures_do_not_mutate()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        Guid environmentId = Guid.NewGuid();
        await factory.Services.GetRequiredService<InMemoryGatewayRegistry>().AddEnvironmentAsync(new(environmentId, "binding-test", "Binding test", false), TestContext.Current.CancellationToken);
        ConnectorVersionResource version = await ImportAndValidateSampleAsync(client, csrf, TestContext.Current.CancellationToken);
        await RegisterCatalogResourcesAsync(factory, environmentId, version.ConnectorId);
        object body = new
        {
            environmentId,
            connectorVersion = version.Version,
            endpoints = new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://vendor.example.test/" },
            secretResources = new Dictionary<string, object> { ["sample-vendor-api-key"] = new { providerId = "synthetic", resourceId = "api-key", resourceType = "Secret" } },
            certificateResources = new Dictionary<string, object> { ["sample-vendor-client-certificate"] = new { providerId = "synthetic", resourceId = "certificate", resourceType = "ClientCertificate", publicMetadataRevision = 1 } }
        };

        using HttpResponseMessage created = await PutBindingAsync(client, version.ConnectorId, body, csrf, null);
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        Assert.Equal(1, (await created.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>(cancellationToken: TestContext.Current.CancellationToken)).GetProperty("revision").GetInt64());

        using HttpResponseMessage missing = await PutBindingAsync(client, version.ConnectorId, body, csrf, null);
        Assert.Equal((HttpStatusCode)428, missing.StatusCode);
        using HttpResponseMessage stale = await PutBindingAsync(client, version.ConnectorId, body, csrf, "\"99\"");
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        GatewayAuditEvent[] denials = factory.Services.GetRequiredService<InMemoryGatewayRegistry>().SnapshotAuditEvents().Where(value => value.Outcome == "denied").ToArray();
        Assert.Single(denials, value => value.ReasonCode == "BGW-CONCURRENCY-PRECONDITION");
        Assert.Single(denials, value => value.ReasonCode == "BGW-CONCURRENCY-CONFLICT");

        IConnectorConfigurationStore store = factory.Services.GetRequiredService<IConnectorConfigurationStore>();
        ConnectorVersionRecord stored = (await store.GetVersionAsync(version.ConnectorId, version.Version, TestContext.Current.CancellationToken))!;
        Assert.Equal(1, (await store.ListBindingsPageAsync(stored.Id, 0, 50, environmentId, TestContext.Current.CancellationToken)).Total);

        using HttpResponseMessage updated = await PutBindingAsync(client, version.ConnectorId, body, csrf, "\"1\"");
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        Assert.Equal(2, (await updated.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>(cancellationToken: TestContext.Current.CancellationToken)).GetProperty("revision").GetInt64());
    }

    [Fact]
    public async Task M5_IT_Security_denials_for_binding_policy_self_approval_and_bootstrap_are_redacted_once()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        Guid environmentId = Guid.NewGuid();
        await factory.Services.GetRequiredService<InMemoryGatewayRegistry>().AddEnvironmentAsync(new(environmentId, "denial-test", "Denial test", false), TestContext.Current.CancellationToken);
        ConnectorVersionResource version = await ImportAndValidateSampleAsync(client, csrf, TestContext.Current.CancellationToken);
        await RegisterCatalogResourcesAsync(factory, environmentId, version.ConnectorId);
        object invalidBinding = new
        {
            environmentId,
            connectorVersion = version.Version,
            endpoints = new Dictionary<string, string> { ["attacker-endpoint"] = "https://controlled.example.test/" },
            secretResources = new Dictionary<string, object> { ["attacker-secret"] = new { providerId = "synthetic", resourceId = "ACTUAL_API_KEY_CANARY", resourceType = "Secret" } }
        };
        using HttpResponseMessage bindingDenied = await PutBindingAsync(client, version.ConnectorId, invalidBinding, csrf, null);
        Assert.Equal(HttpStatusCode.BadRequest, bindingDenied.StatusCode);

        object validBinding = new
        {
            environmentId,
            connectorVersion = version.Version,
            endpoints = new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://vendor.example.test/" },
            secretResources = new Dictionary<string, object> { ["sample-vendor-api-key"] = new { providerId = "synthetic", resourceId = "api-key", resourceType = "Secret" } },
            certificateResources = new Dictionary<string, object> { ["sample-vendor-client-certificate"] = new { providerId = "synthetic", resourceId = "certificate", resourceType = "ClientCertificate", publicMetadataRevision = 1 } }
        };
        using HttpResponseMessage bindingCreated = await PutBindingAsync(client, version.ConnectorId, validBinding, csrf, null);
        bindingCreated.EnsureSuccessStatusCode();
        using HttpRequestMessage approvalRequest = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}/approval-requests");
        approvalRequest.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage requested = await client.SendAsync(approvalRequest, TestContext.Current.CancellationToken);
        requested.EnsureSuccessStatusCode();
        using JsonDocument requestedBody = JsonDocument.Parse(await requested.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        using HttpResponseMessage reviewResponse = await client.GetAsync($"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}/approval-review", TestContext.Current.CancellationToken);
        reviewResponse.EnsureSuccessStatusCode(); string reviewJson = await reviewResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        using JsonDocument review = JsonDocument.Parse(reviewJson);
        Assert.Equal("vendor.example.test", review.RootElement.GetProperty("artifact").GetProperty("operations")[0].GetProperty("endpoint").GetProperty("hostname").GetString());
        Assert.Equal(requestedBody.RootElement.GetProperty("bindingDigestSha256").GetString(), review.RootElement.GetProperty("digestSha256").GetString());
        Assert.Contains("api-key", reviewJson, StringComparison.Ordinal); Assert.DoesNotContain("secretValue", reviewJson, StringComparison.OrdinalIgnoreCase);
        Guid approvalRequestId = requestedBody.RootElement.GetProperty("id").GetGuid();
        using HttpRequestMessage staleApprove = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}/approvals") { Content = JsonContent.Create(new { approvalRequestId, expectedDigestSha256 = new string('A', 64) }) };
        staleApprove.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage staleApproval = await client.SendAsync(staleApprove, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Conflict, staleApproval.StatusCode);
        using HttpRequestMessage approve = new(HttpMethod.Post, $"/admin/api/v1/connectors/{version.ConnectorId}/versions/{version.Version}/approvals") { Content = JsonContent.Create(new { approvalRequestId, expectedDigestSha256 = requestedBody.RootElement.GetProperty("bindingDigestSha256").GetString() }) };
        approve.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage selfApproval = await client.SendAsync(approve, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, selfApproval.StatusCode);

        using HttpRequestMessage bootstrap = new(HttpMethod.Post, "/admin/api/v1/bootstrap");
        bootstrap.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage bootstrapDenied = await client.SendAsync(bootstrap, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, bootstrapDenied.StatusCode);

        GatewayAuditEvent[] denials = factory.Services.GetRequiredService<InMemoryGatewayRegistry>().SnapshotAuditEvents().Where(value => value.Outcome == "denied").ToArray();
        Assert.Single(denials, value => value.ReasonCode == "BGW-CONNECTOR-BINDING-SCOPE");
        Assert.Single(denials, value => value.ReasonCode == "BGW-ADMIN-FOUR-EYES");
        Assert.Single(denials, value => value.ReasonCode == "BGW-ADMIN-APPROVAL-STALE");
        Assert.Single(denials, value => value.ReasonCode == "BGW-ADMIN-BOOTSTRAP-DENIED");
        Assert.All(denials, value => { Assert.Equal("admin.request.denied", value.Action); Assert.Equal("method", Assert.Single(value.Metadata.Keys)); });
        Assert.DoesNotContain("canary-not-a-secret", System.Text.Json.JsonSerializer.Serialize(denials), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void M5_IT_DevelopmentAuth_cannot_start_in_Production()
    {
        using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Gateway:Admin:Mode", "DevelopmentAuth");
        });
        Assert.ThrowsAny<Exception>(() => factory.CreateClient());
    }

    [Fact]
    public void M5_IT_Production_cannot_disable_four_eyes()
    {
        using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Gateway:Admin:Mode", "Disabled");
            builder.UseSetting("Gateway:Admin:RequireFourEyes", "false");
        });

        Exception failure = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("four-eyes", failure.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void M5_IT_Oidc_cannot_disable_four_eyes_even_in_test_environment()
    {
        using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("Gateway:Admin:Mode", "Oidc");
            builder.UseSetting("Gateway:Admin:RequireFourEyes", "false");
        });

        Exception failure = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("OIDC requires four-eyes", failure.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task M5_IT_Explicit_loopback_development_can_use_development_publication_policy()
    {
        await using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("Gateway:Admin:Mode", "DevelopmentAuth");
            builder.UseSetting("Gateway:Admin:RequireFourEyes", "false");
        });

        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        using HttpResponseMessage response = await client.GetAsync("/health/live", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();
        Assert.IsType<DevelopmentConnectorApprovalPolicy>(factory.Services.GetRequiredService<IConnectorApprovalPolicy>());
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("192.0.2.25", false)]
    [InlineData("203.0.113.10", false)]
    public void M5_UT_DevelopmentAuth_uses_actual_socket_peer_only(string address, bool expected) =>
        Assert.Equal(expected, DevelopmentAuthenticationBoundary.IsLoopbackPeer(System.Net.IPAddress.Parse(address)));

    [Fact]
    public void M5_UT_Remote_peer_cannot_forge_loopback_with_Host_or_forwarded_headers()
    {
        DefaultHttpContext context = new();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.0.2.25");
        context.Request.Host = new HostString("localhost");
        context.Request.Headers["X-Forwarded-For"] = "127.0.0.1";
        context.Request.Headers["X-Forwarded-Host"] = "localhost";
        Assert.False(DevelopmentAuthenticationBoundary.IsLoopbackPeer(context.Connection.RemoteIpAddress));
    }

    [Fact]
    public void M5_CT_DevelopmentAuth_compose_listener_is_explicitly_loopback_only()
    {
        string compose = File.ReadAllText(Path.Combine(RepositoryRoot(), "deploy", "m5", "docker-compose.m5.yml"));
        Assert.Contains("127.0.0.1:${M5_GATEWAY_PORT:-18443}:8443", compose, StringComparison.Ordinal);
        Assert.DoesNotContain("0.0.0.0", compose, StringComparison.Ordinal);
    }

    [Fact]
    public void M5_CT_Full_stack_runner_precreates_nested_read_only_mount_points()
    {
        string runner = File.ReadAllText(Path.Combine(RepositoryRoot(), "tools", "m5", "Invoke-M5FullStack.ps1"));
        int nodeMount = runner.IndexOf("New-Item -ItemType Directory -Path $nodeMountPoint", StringComparison.Ordinal);
        int resultsMount = runner.IndexOf("New-Item -ItemType Directory -Path $resultsMountPoint", StringComparison.Ordinal);
        int dockerRun = runner.IndexOf("& docker run", StringComparison.Ordinal);

        Assert.True(nodeMount >= 0 && nodeMount < dockerRun);
        Assert.True(resultsMount >= 0 && resultsMount < dockerRun);
        Assert.Contains("$createdNodeMountPoint", runner, StringComparison.Ordinal);
        Assert.Contains("$createdResultsMountPoint", runner, StringComparison.Ordinal);
        Assert.Contains("Remove-Item -LiteralPath $nodeMountPoint -Force", runner, StringComparison.Ordinal);
        Assert.Contains("Remove-Item -LiteralPath $resultsMountPoint -Force", runner, StringComparison.Ordinal);
        Assert.DoesNotContain("--read-only=false", runner, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task M5_IT_Development_login_route_is_unavailable_when_mode_is_disabled()
    {
        await using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("Gateway:Admin:Mode", "Disabled");
        });
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await GetCsrfAsync(client, TestContext.Current.CancellationToken);
        using HttpRequestMessage request = new(HttpMethod.Post, "/admin/auth/development/login") { Content = JsonContent.Create(new { userName = "viewer" }) };
        request.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    private static async Task<string> LoginAsync(HttpClient client, string user, CancellationToken cancellationToken)
    {
        string csrf = await GetCsrfAsync(client, cancellationToken);
        using HttpRequestMessage request = new(HttpMethod.Post, "/admin/auth/development/login") { Content = JsonContent.Create(new { userName = user }) };
        request.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        return await GetCsrfAsync(client, cancellationToken);
    }

    private static async Task<(string Csrf, string Cookie)> LoginAndCaptureCookieAsync(HttpClient client, string user, CancellationToken cancellationToken)
    {
        string csrf = await GetCsrfAsync(client, cancellationToken);
        using HttpRequestMessage request = new(HttpMethod.Post, "/admin/auth/development/login") { Content = JsonContent.Create(new { userName = user }) };
        request.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        string setCookie = Assert.Single(response.Headers.GetValues("Set-Cookie"), value => value.StartsWith("__Host-SecureIntegration.Admin=", StringComparison.Ordinal));
        return (await GetCsrfAsync(client, cancellationToken), setCookie[..setCookie.IndexOf(';')]);
    }

    private static async Task<ConnectorVersionResource> ImportAndValidateSampleAsync(HttpClient client, string csrf, CancellationToken cancellationToken, string? version = null)
    {
        using HttpResponseMessage sample = await client.GetAsync("/admin/api/v1/connectors/sample", cancellationToken);
        sample.EnsureSuccessStatusCode();
        using System.Text.Json.JsonDocument source = await System.Text.Json.JsonDocument.ParseAsync(await sample.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
        using System.Text.Json.JsonDocument definition = version is null ? System.Text.Json.JsonDocument.Parse(source.RootElement.GetRawText()) : System.Text.Json.JsonDocument.Parse(source.RootElement.GetRawText().Replace("\"version\": \"1.0.0\"", $"\"version\": \"{version}\"", StringComparison.Ordinal));
        using HttpRequestMessage validate = new(HttpMethod.Post, "/admin/api/v1/connectors:validate") { Content = JsonContent.Create(new ConnectorImportRequest(definition.RootElement.Clone())) };
        validate.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage validationResponse = await client.SendAsync(validate, cancellationToken);
        ConnectorValidationResult validation = (await validationResponse.Content.ReadFromJsonAsync<ConnectorValidationResult>(cancellationToken: cancellationToken))!;
        using HttpRequestMessage import = new(HttpMethod.Post, "/admin/api/v1/connectors:import") { Content = JsonContent.Create(new ConnectorImportRequest(definition.RootElement.Clone(), validation.ChecksumSha256)) };
        import.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage importResponse = await client.SendAsync(import, cancellationToken);
        ConnectorVersionResource draft = (await importResponse.Content.ReadFromJsonAsync<ConnectorVersionResource>(WireJson, cancellationToken))!;
        using HttpRequestMessage markValidated = new(HttpMethod.Post, $"/admin/api/v1/connectors/{draft.ConnectorId}/versions/{draft.Version}:validate");
        markValidated.Headers.Add("X-CSRF-TOKEN", csrf);
        markValidated.Headers.TryAddWithoutValidation("If-Match", $"\"{draft.RowVersion}\"");
        using HttpResponseMessage validated = await client.SendAsync(markValidated, cancellationToken);
        validated.EnsureSuccessStatusCode();
        return (await validated.Content.ReadFromJsonAsync<ConnectorVersionResource>(WireJson, cancellationToken))!;
    }

    private static Task<HttpResponseMessage> PutBindingAsync(HttpClient client, string connectorId, object body, string csrf, string? etag)
    {
        HttpRequestMessage request = new(HttpMethod.Put, $"/admin/api/v1/connectors/{connectorId}/bindings") { Content = JsonContent.Create(body) };
        request.Headers.Add("X-CSRF-TOKEN", csrf);
        if (etag is not null) request.Headers.TryAddWithoutValidation("If-Match", etag);
        return client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static async Task RegisterCatalogResourcesAsync(AdminDevelopmentFactory factory, Guid environmentId, string connectorId)
    {
        IConnectorConfigurationStore store = factory.Services.GetRequiredService<IConnectorConfigurationStore>();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        _ = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", "api-key", ProviderResourceType.Secret, "Vendor API key", environmentId, connectorId, "submit", "synthetic://api-key", ProviderResourceStatus.Active, null, 0, null, null, string.Empty, now), TestContext.Current.CancellationToken);
        CertificatePublicMetadata metadata = new(new string('A', 64), "CN=Synthetic client", "CN=Synthetic issuer", now.AddDays(-1), now.AddDays(30), "RSA", 2048, "1");
        _ = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic provider", "synthetic", "certificate", ProviderResourceType.ClientCertificate, "Vendor certificate", environmentId, connectorId, "submit", "synthetic://certificate", ProviderResourceStatus.Active, null, 0, 1, metadata, string.Empty, now), TestContext.Current.CancellationToken);
    }

    private static async Task<string> GetCsrfAsync(HttpClient client, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await client.GetAsync("/admin/auth/csrf", cancellationToken);
        response.EnsureSuccessStatusCode();
        using System.Text.Json.JsonDocument json = await System.Text.Json.JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
        return json.RootElement.GetProperty("token").GetString()!;
    }

    private static async Task<Guid> CreateAndGetIdAsync(HttpClient client, string path, object body, string csrf)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, path) { Content = JsonContent.Create(body) }; request.Headers.Add("X-CSRF-TOKEN", csrf);
        using HttpResponseMessage response = await client.SendAsync(request, TestContext.Current.CancellationToken); response.EnsureSuccessStatusCode();
        using System.Text.Json.JsonDocument json = await System.Text.Json.JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(TestContext.Current.CancellationToken), cancellationToken: TestContext.Current.CancellationToken);
        return json.RootElement.GetProperty("id").GetGuid();
    }

    private sealed class InstrumentedProvider(string canary, byte[] pfx) : ISecretValueProvider, IClientCertificateProvider
    {
        private readonly Dictionary<string, string> secrets = new(StringComparer.Ordinal) { ["instrumented://api-key"] = canary };
        public int SecretInvocations { get; private set; }
        public int CertificateInvocations { get; private set; }

        public void Register(string logicalReference, string value) => secrets[logicalReference] = value;

        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SecretInvocations++;
            return Task.FromResult(secrets.TryGetValue(logicalReference, out string? value) ? value : throw new InvalidOperationException("Unknown synthetic secret reference."));
        }

        public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal("instrumented://certificate", logicalReference);
            CertificateInvocations++;
            return Task.FromResult(X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable));
        }
    }

    private sealed class CountingRestrictedTransport(IRestrictedTransport inner) : IRestrictedTransport
    {
        public int Invocations { get; private set; }

        public async Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken)
        {
            Invocations++;
            return await inner.SendAsync(request, approvedAddresses, clientCertificate, timeout, maximumResponseBytes, cancellationToken);
        }
    }

    private sealed class LoopbackResolver : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) =>
            Task.FromResult(new[] { IPAddress.Loopback });
    }

    private sealed class ExactLoopbackAllowance(string host) : IPrivateDestinationAllowance
    {
        public bool IsAllowed(string candidateHost, IPAddress address) =>
            string.Equals(candidateHost, host, StringComparison.OrdinalIgnoreCase) && IPAddress.IsLoopback(address);
    }

    private sealed class CertificateSet : IDisposable
    {
        private readonly RSA rootKey;
        private readonly RSA serverKey;
        private readonly RSA clientKey;

        private CertificateSet(RSA rootKey, RSA serverKey, RSA clientKey, X509Certificate2 root, X509Certificate2 server, X509Certificate2 client)
        {
            this.rootKey = rootKey; this.serverKey = serverKey; this.clientKey = clientKey;
            RootCertificate = root; ServerCertificate = server; ClientCertificate = client;
        }

        public X509Certificate2 RootCertificate { get; }
        public X509Certificate2 ServerCertificate { get; }
        public X509Certificate2 ClientCertificate { get; }
        public string ClientPrivateKeyPem => clientKey.ExportPkcs8PrivateKeyPem();

        public static CertificateSet Create(string serverHost, DateTimeOffset clientExpiry)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            RSA rootKey = RSA.Create(2048); RSA serverKey = RSA.Create(2048); RSA clientKey = RSA.Create(2048);
            CertificateRequest rootRequest = new("CN=M5 Synthetic Test Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            X509Certificate2 root = rootRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(10));

            CertificateRequest serverRequest = new($"CN={serverHost}", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            SubjectAlternativeNameBuilder san = new(); san.AddDnsName(serverHost); serverRequest.CertificateExtensions.Add(san.Build());
            using X509Certificate2 issuedServer = serverRequest.Create(root, now.AddMinutes(-2), now.AddDays(2), RandomNumberGenerator.GetBytes(16));
            using X509Certificate2 serverWithKey = issuedServer.CopyWithPrivateKey(serverKey);
            X509Certificate2 server = X509CertificateLoader.LoadPkcs12(serverWithKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);

            CertificateRequest clientRequest = new("CN=M5 near-expiry client", clientKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            clientRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            clientRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            clientRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.2") }, true));
            using X509Certificate2 issuedClient = clientRequest.Create(root, now.AddMinutes(-2), clientExpiry, RandomNumberGenerator.GetBytes(16));
            using X509Certificate2 clientWithKey = issuedClient.CopyWithPrivateKey(clientKey);
            X509Certificate2 client = X509CertificateLoader.LoadPkcs12(clientWithKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
            return new(rootKey, serverKey, clientKey, root, server, client);
        }

        public void Dispose()
        {
            ClientCertificate.Dispose(); ServerCertificate.Dispose(); RootCertificate.Dispose();
            clientKey.Dispose(); serverKey.Dispose(); rootKey.Dispose();
        }
    }

    private sealed class RealVendorMock : IAsyncDisposable
    {
        private readonly TcpListener listener;
        private readonly CancellationTokenSource cancellation = new();
        private readonly X509Certificate2 serverCertificate;
        private string expectedApiKey;
        private readonly string expectedFingerprint;
        private Task? serverTask;

        private RealVendorMock(TcpListener listener, X509Certificate2 serverCertificate, string expectedApiKey, string expectedFingerprint)
        {
            this.listener = listener; this.serverCertificate = serverCertificate; this.expectedApiKey = expectedApiKey; this.expectedFingerprint = expectedFingerprint;
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        }

        public int Port { get; }
        public int Requests { get; private set; }
        public bool ApiKeyMatched { get; private set; }
        public bool ClientCertificateMatched { get; private set; }
        public Guid? CorrelationId { get; private set; }
        public string ExpectedApiKey { get => expectedApiKey; set => expectedApiKey = value; }

        public static Task<RealVendorMock> StartAsync(CertificateSet certificates, string expectedApiKey, string expectedFingerprint, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            TcpListener listener = new(IPAddress.Loopback, 0); listener.Start();
            RealVendorMock mock = new(listener, certificates.ServerCertificate, expectedApiKey, expectedFingerprint);
            mock.serverTask = mock.RunAsync();
            return Task.FromResult(mock);
        }

        private async Task RunAsync()
        {
            try
            {
                while (!cancellation.IsCancellationRequested)
                {
                    using TcpClient client = await listener.AcceptTcpClientAsync(cancellation.Token);
                    await HandleAsync(client);
                }
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
            catch (SocketException) when (cancellation.IsCancellationRequested) { }
        }

        private async Task HandleAsync(TcpClient client)
        {
                using SslStream tls = new(client.GetStream(), false, (_, certificate, _, _) =>
                {
                    ClientCertificateMatched = certificate is not null && string.Equals(Convert.ToHexString(SHA256.HashData(certificate.GetRawCertData())), expectedFingerprint, StringComparison.Ordinal);
                    return ClientCertificateMatched;
                });
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCertificate,
                    ClientCertificateRequired = true,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, cancellation.Token);
                byte[] terminator = "\r\n\r\n"u8.ToArray();
                using MemoryStream headerBuffer = new();
                int matched = 0;
                while (headerBuffer.Length < 16384)
                {
                    int value = tls.ReadByte(); if (value < 0) throw new IOException("Unexpected end of HTTPS request.");
                    headerBuffer.WriteByte((byte)value);
                    matched = value == terminator[matched] ? matched + 1 : value == terminator[0] ? 1 : 0;
                    if (matched == terminator.Length) break;
                }
                string[] lines = Encoding.ASCII.GetString(headerBuffer.ToArray()).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                Dictionary<string, string> headers = lines.Skip(1).Select(line => line.Split(':', 2)).Where(parts => parts.Length == 2)
                    .ToDictionary(parts => parts[0], parts => parts[1].Trim(), StringComparer.OrdinalIgnoreCase);
                if (headers.TryGetValue("Content-Length", out string? lengthText) && int.TryParse(lengthText, out int length) && length > 0)
                {
                    byte[] body = new byte[length]; await tls.ReadExactlyAsync(body, cancellation.Token);
                }
                Requests++;
                ApiKeyMatched = headers.TryGetValue("X-Vendor-Api-Key", out string? key) && string.Equals(key, expectedApiKey, StringComparison.Ordinal);
                CorrelationId = headers.TryGetValue("X-Correlation-ID", out string? correlationText) && Guid.TryParse(correlationText, out Guid correlation) ? correlation : null;
                string response = ApiKeyMatched && ClientCertificateMatched
                    ? "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 43\r\n\r\n{\"accepted\":true,\"credential\":\"[REDACTED]\"}"
                    : "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                await tls.WriteAsync(Encoding.ASCII.GetBytes(response), cancellation.Token);
                await tls.FlushAsync(cancellation.Token);
        }

        public async ValueTask DisposeAsync()
        {
            cancellation.Cancel(); listener.Stop();
            if (serverTask is not null) { try { await serverTask; } catch (SocketException) when (cancellation.IsCancellationRequested) { } }
            cancellation.Dispose();
        }
    }

    private static string RepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "BrokerGateway.slnx")) && !File.Exists(Path.Combine(directory.FullName, "BrokerGateway.Core.slnx"))) directory = directory.Parent;
        return directory?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }
}

public class AdminDevelopmentFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Gateway:Admin:Mode", "DevelopmentAuth");
    }
}

/// <summary>Deterministic four-eyes host used only for the cross-layer anti-exfiltration test.
/// PostgreSQL tests separately prove the production atomic publication transaction.</summary>
public sealed class AntiExfiltrationFactory : AdminDevelopmentFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<IConnectorApprovalPolicy>();
            services.AddSingleton<IConnectorApprovalPolicy, DeterministicFourEyesApprovalPolicy>();
            services.Configure<RateLimiterOptions>(options => options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ =>
                RateLimitPartition.GetFixedWindowLimiter("anti-exfiltration", _ => new FixedWindowRateLimiterOptions { PermitLimit = 1000, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true })));
        });
    }

    private sealed class DeterministicFourEyesApprovalPolicy(IAdminSecurityStore approvals) : IConnectorApprovalPolicy
    {
        public async Task<ConnectorVersionRecord> PublishAsync(IConnectorConfigurationStore connectorStore, ConnectorVersionRecord version, long expectedRowVersion, long expectedPublicationRevision, string actor, Guid correlationId, DateTimeOffset now, CancellationToken cancellationToken)
        {
            byte[] digest = await connectorStore.GetBindingBundleDigestAsync(version.Id, cancellationToken).ConfigureAwait(false);
            if (!await approvals.HasValidApprovalAsync(version.Id, version.ChecksumSha256, digest, actor, cancellationToken).ConfigureAwait(false))
                throw new GatewayException("BGW-ADMIN-APPROVAL-REQUIRED", 409);
            return await connectorStore.PublishAsync(version.Id, expectedRowVersion, expectedPublicationRevision, actor, now, cancellationToken).ConfigureAwait(false);
        }
    }
}

public sealed class DenialAuditFailureFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Gateway:Admin:Mode", "DevelopmentAuth");
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<IAdminTransactionFaultInjector>();
            services.AddSingleton<IAdminTransactionFaultInjector>(new DenialAuditFaultInjector());
        });
    }

    private sealed class DenialAuditFaultInjector : IAdminTransactionFaultInjector
    {
        public void Check(string boundary)
        {
            if (boundary == "audit.append.before-state") throw new InvalidOperationException("Synthetic audit persistence failure.");
        }
    }
}

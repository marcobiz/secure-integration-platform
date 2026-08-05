using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecureIntegration.Gateway.Infrastructure;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests;

public sealed class AdminApiSecurityTests
{
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
    public async Task M5_IT_Mutation_without_CSRF_is_denied()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        using HttpResponseMessage response = await client.PostAsJsonAsync("/admin/api/v1/tenants", new { code = "missing-csrf", displayName = "Missing CSRF" }, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("BGW-ADMIN-CSRF", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
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
    }

    [Fact]
    public async Task M5_IT_Security_admin_creates_resources_and_activation_is_returned_once()
    {
        await using AdminDevelopmentFactory factory = new();
        using HttpClient client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        string csrf = await LoginAsync(client, "security-admin", TestContext.Current.CancellationToken);
        Guid tenantId = await CreateAndGetIdAsync(client, "/admin/api/v1/tenants", new { code = "tenant-m5", displayName = "Tenant M5" }, csrf);
        Guid applicationId = await CreateAndGetIdAsync(client, "/admin/api/v1/applications", new { code = "app-m5", displayName = "App M5", minimumBrokerVersion = "3.0.0", maximumBrokerVersion = (string?)null }, csrf);

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
    public void M5_IT_DevelopmentAuth_cannot_start_in_Production()
    {
        using WebApplicationFactory<Program> factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Gateway:Admin:Mode", "DevelopmentAuth");
        });
        Assert.ThrowsAny<Exception>(() => factory.CreateClient());
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
}

public sealed class AdminDevelopmentFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.UseSetting("Gateway:Admin:Mode", "DevelopmentAuth");
    }
}

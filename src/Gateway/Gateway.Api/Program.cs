using System.Security.Cryptography;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Runtime.Loader;
using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Npgsql;
using SecureIntegration.Gateway.Api;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Providers.Abstractions;
using SecureIntegration.Providers.Synthetic;

if (args is ["--health-probe"])
{
    using HttpClient probe = new() { Timeout = TimeSpan.FromSeconds(3) };
    try
    {
        using HttpResponseMessage response = await probe.GetAsync(Environment.GetEnvironmentVariable("GATEWAY_HEALTH_URL") ?? "http://127.0.0.1:8080/health/live").ConfigureAwait(false);
        Environment.ExitCode = response.IsSuccessStatusCode ? 0 : 1;
    }
    catch (HttpRequestException) { Environment.ExitCode = 1; }
    catch (TaskCanceledException) { Environment.ExitCode = 1; }
    return;
}

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.SerializerOptions.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow;
});
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 16 * 1024 * 1024;
    options.ConfigureHttpsDefaults(https =>
    {
        https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        // Installation credentials are intentionally self-signed. TLS transports the
        // certificate; RuntimeIdentityService owns trust through registry binding, PoP,
        // revocation and signed-request validation.
        https.AllowAnyClientCertificate();
    });
});

GatewayHostOptions hostOptions = builder.Configuration.GetSection("Gateway").Get<GatewayHostOptions>() ?? new();
builder.AddGatewayAdminAuthentication(hostOptions.Admin);
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.User.FindFirst("sub")?.Value ?? context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = context.Request.Path.StartsWithSegments("/admin/auth") ? 20 : 240, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true }));
});
ForwardedHeadersOptions forwardedHeaders = new() { ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto };
foreach (string configuredProxy in hostOptions.Admin.TrustedProxies)
{
    if (!IPAddress.TryParse(configuredProxy, out IPAddress? proxy)) throw new InvalidOperationException("Gateway Admin trusted proxy is invalid.");
    forwardedHeaders.KnownProxies.Add(proxy);
}
bool usePlatformCertificateForwarding = hostOptions.TrustPlatformClientCertificateForwarding;
if (usePlatformCertificateForwarding)
{
    if (!builder.Environment.IsProduction() || !string.Equals(Environment.GetEnvironmentVariable("GATEWAY_TRUSTED_CERTIFICATE_FORWARDING_BOUNDARY"), "true", StringComparison.Ordinal))
        throw new InvalidOperationException("Platform certificate forwarding requires an explicit trusted Production boundary.");
    builder.Services.AddCertificateForwarding(options => options.CertificateHeader = "X-ARR-ClientCert");
}
builder.Services.AddSingleton(hostOptions);
builder.Services.AddSingleton<IGatewayClock, SystemGatewayClock>();
builder.Services.AddSingleton<IEnrollmentChallengeStore, InMemoryEnrollmentChallengeStore>();
builder.Services.AddSingleton<IHostResolver, SystemHostResolver>();
builder.Services.AddSingleton<IRestrictedTransport, SystemRestrictedTransport>();
if ((builder.Environment.IsEnvironment("M3Testing") || builder.Environment.IsEnvironment("M4Testing")) && !string.IsNullOrWhiteSpace(hostOptions.M3PrivateMockHost) && !string.IsNullOrWhiteSpace(hostOptions.M3PrivateMockCidr))
    builder.Services.AddSingleton<IPrivateDestinationAllowance>(new M3PrivateDestinationAllowance(hostOptions.M3PrivateMockHost, hostOptions.M3PrivateMockCidr));
string? connectionString = builder.Configuration.GetConnectionString("GatewayDatabase");
if (string.IsNullOrWhiteSpace(connectionString))
{
    if (!builder.Environment.IsDevelopment() && !builder.Environment.IsEnvironment("Testing"))
        throw new InvalidOperationException("GatewayDatabase is required outside Development/Testing.");
    builder.Services.AddSingleton<InMemoryGatewayRegistry>();
    builder.Services.AddSingleton<IGatewayRegistry>(services => services.GetRequiredService<InMemoryGatewayRegistry>());
    builder.Services.AddSingleton<IAdminDirectoryStore, InMemoryAdminDirectoryStore>();
    builder.Services.AddSingleton<IConnectorConfigurationStore, InMemoryConnectorConfigurationStore>();
    builder.Services.AddSingleton<IAdminSecurityStore, InMemoryAdminSecurityStore>();
}
else
{
    builder.Services.AddSingleton(_ => NpgsqlDataSource.Create(connectionString));
    builder.Services.AddSingleton<PostgresGatewayRegistry>();
    builder.Services.AddSingleton<IGatewayRegistry>(services => services.GetRequiredService<PostgresGatewayRegistry>());
    builder.Services.AddSingleton<IAdminDirectoryStore, PostgresAdminDirectoryStore>();
    builder.Services.AddSingleton<IConnectorConfigurationStore, PostgresConnectorConfigurationStore>();
    builder.Services.AddSingleton<IAdminSecurityStore, PostgresAdminSecurityStore>();
}
builder.Services.AddSingleton<ConnectorDefinitionValidator>();
if (builder.Environment.IsEnvironment("M3Testing") && hostOptions.Operations.Count > 0)
    builder.Services.AddSingleton<IGatewayOperationCatalog>(_ => new GatewayOperationCatalog(hostOptions.Operations.Select(value => value.ToDefinition())));
else
    builder.Services.AddSingleton<IGatewayOperationCatalog>(services => new PublishedConnectorCatalog(
        services.GetRequiredService<IConnectorConfigurationStore>(),
        services.GetRequiredService<ConnectorDefinitionValidator>(),
        services.GetRequiredService<IGatewayClock>(),
        TimeSpan.FromSeconds(hostOptions.ConnectorCacheTtlSeconds is >= 1 and <= 300 ? hostOptions.ConnectorCacheTtlSeconds : throw new InvalidOperationException("Gateway Connector cache TTL must be between 1 and 300 seconds."))));

ProviderServices providerServices = CreateProviderServices(hostOptions.Provider, builder.Environment);
ISecretValueProvider secretProvider = providerServices.SecretValues is CachingSecretValueProvider
    ? providerServices.SecretValues
    : new CachingSecretValueProvider(providerServices.SecretValues, TimeSpan.FromMinutes(5));
builder.Services.AddSingleton(secretProvider);
builder.Services.AddSingleton(providerServices.ClientCertificates);
builder.Services.AddSingleton(providerServices.Health);
builder.Services.AddSingleton(providerServices.CapabilitySource);
if (providerServices.SigningKeys is not null) builder.Services.AddSingleton(providerServices.SigningKeys);
if (providerServices.Mac is not null) builder.Services.AddSingleton(providerServices.Mac);

byte[] activationKey;
string? encodedActivationKey = hostOptions.ActivationHmacKeyBase64;
if (!builder.Environment.IsDevelopment() && !builder.Environment.IsEnvironment("Testing") && !builder.Environment.IsEnvironment("M3Testing") && !builder.Environment.IsEnvironment("M4Testing"))
{
    if (string.IsNullOrWhiteSpace(hostOptions.ActivationHmacSecretReference)) throw new InvalidOperationException("Gateway activation HMAC provider reference is required outside Development/Testing/M3Testing.");
    encodedActivationKey = await secretProvider.GetSecretAsync(hostOptions.ActivationHmacSecretReference, CancellationToken.None).ConfigureAwait(false);
}
try { activationKey = string.IsNullOrWhiteSpace(encodedActivationKey) ? RandomNumberGenerator.GetBytes(32) : Convert.FromBase64String(encodedActivationKey); }
catch (FormatException) { throw new InvalidOperationException("Gateway activation HMAC key is not valid Base64."); }
if (activationKey.Length < 32) throw new InvalidOperationException("Gateway activation HMAC key must contain at least 256 bits.");
builder.Services.AddSingleton(new EnrollmentSecurityOptions { ActivationHmacKey = activationKey });
builder.Services.AddSingleton<GatewayProvisioningService>();
builder.Services.AddSingleton<InstallationEnrollmentService>();
builder.Services.AddSingleton<RuntimeIdentityService>();
builder.Services.AddSingleton<RestrictedEgressService>();
builder.Services.AddSingleton<AdminAccessService>();
builder.Services.AddSingleton<ConnectorApprovalService>();
if (hostOptions.Admin.RequireFourEyes && !string.Equals(hostOptions.Admin.Mode, "DevelopmentApiKey", StringComparison.Ordinal)) builder.Services.AddSingleton<IConnectorApprovalPolicy, FourEyesConnectorApprovalPolicy>();
builder.Services.AddSingleton<ConnectorAdministrationService>();

WebApplication app = builder.Build();
if (app.Environment.IsProduction()) app.UseHsts();
if (forwardedHeaders.KnownProxies.Count > 0) app.UseForwardedHeaders(forwardedHeaders);
if (usePlatformCertificateForwarding) app.UseCertificateForwarding();
ILogger gatewayLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("SecureIntegration.Gateway.Requests");
app.Use(async (context, next) =>
{
    string requestCorrelationId = Guid.NewGuid().ToString("D");
    context.Response.Headers["X-Correlation-ID"] = requestCorrelationId;
    try { await next(context).ConfigureAwait(false); }
    catch (GatewayException exception)
    {
        if (context.Response.HasStarted) throw;
        context.Response.StatusCode = exception.StatusCode;
        context.Response.ContentType = "application/problem+json";
        GatewayLog.RequestRejected(gatewayLogger, exception.Code, requestCorrelationId);
        await context.Response.WriteAsJsonAsync(new { type = "about:blank", title = "Gateway request rejected", status = exception.StatusCode, code = exception.Code, correlationId = requestCorrelationId, retryable = exception.Retryable }).ConfigureAwait(false);
    }
    catch (JsonException)
    {
        if (context.Response.HasStarted) throw;
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "application/problem+json";
        GatewayLog.RequestRejected(gatewayLogger, "BGW-PROTOCOL-JSON", requestCorrelationId);
        await context.Response.WriteAsJsonAsync(new { type = "about:blank", title = "Invalid request", status = 400, code = "BGW-PROTOCOL-JSON", correlationId = requestCorrelationId, retryable = false }).ConfigureAwait(false);
    }
    catch (BadHttpRequestException exception)
    {
        if (context.Response.HasStarted) throw;
        int status = exception.StatusCode is >= 400 and < 500 ? exception.StatusCode : StatusCodes.Status400BadRequest;
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/problem+json";
        GatewayLog.RequestRejected(gatewayLogger, "BGW-PROTOCOL-REQUEST", requestCorrelationId);
        await context.Response.WriteAsJsonAsync(new { type = "about:blank", title = "Invalid request", status, code = "BGW-PROTOCOL-REQUEST", correlationId = requestCorrelationId, retryable = false }).ConfigureAwait(false);
    }
    catch (AntiforgeryValidationException)
    {
        if (context.Response.HasStarted) throw;
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "application/problem+json";
        GatewayLog.RequestRejected(gatewayLogger, "BGW-ADMIN-CSRF", requestCorrelationId);
        await context.Response.WriteAsJsonAsync(new { type = "about:blank", title = "CSRF validation failed", status = 403, code = "BGW-ADMIN-CSRF", correlationId = requestCorrelationId, retryable = false }).ConfigureAwait(false);
    }
    catch (ProviderAccessException exception)
    {
        if (context.Response.HasStarted) throw;
        int status = exception.Retryable ? StatusCodes.Status503ServiceUnavailable : StatusCodes.Status500InternalServerError;
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/problem+json";
        GatewayLog.RequestRejected(gatewayLogger, exception.Code, requestCorrelationId);
        await context.Response.WriteAsJsonAsync(new { type = "about:blank", title = "Provider request failed", status, code = exception.Code, correlationId = requestCorrelationId, retryable = exception.Retryable }).ConfigureAwait(false);
    }
    catch (Exception)
    {
        if (context.Response.HasStarted) throw;
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "application/problem+json";
        GatewayLog.RequestFailed(gatewayLogger, "BGW-INTERNAL", requestCorrelationId);
        await context.Response.WriteAsJsonAsync(new { type = "about:blank", title = "Gateway request failed", status = 500, code = "BGW-INTERNAL", correlationId = requestCorrelationId, retryable = false }).ConfigureAwait(false);
    }
});

app.UseAuthentication();
app.UseRateLimiter();
app.Use(async (context, next) =>
{
    string cspNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18));
    context.Items["AdminCspNonce"] = cspNonce;
    context.Response.OnStarting(() =>
    {
        context.Response.Headers["Content-Security-Policy"] = $"default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'nonce-{cspNonce}'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
        context.Response.Headers["X-Frame-Options"] = "DENY";
        if (context.Request.Path.StartsWithSegments("/admin/auth") || context.Request.Path.StartsWithSegments("/admin/api")) context.Response.Headers.CacheControl = "no-store";
        return Task.CompletedTask;
    });
    bool mutation = context.Request.Method is not ("GET" or "HEAD" or "OPTIONS" or "TRACE");
    if (mutation && context.Request.Path.StartsWithSegments("/admin/api"))
        await context.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(context).ConfigureAwait(false);
    await next(context).ConfigureAwait(false);
});
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = context =>
    {
        context.Context.Response.Headers.CacheControl = context.Context.Request.Path.StartsWithSegments("/admin/assets")
            ? "public,max-age=31536000,immutable"
            : "no-cache";
    }
});
app.UseAuthorization();

app.MapGet("/health/live", () => Results.Ok(new { status = "healthy" }));
app.MapGet("/health/ready", async (IGatewayRegistry registry, IProviderHealthCheck provider, CancellationToken cancellationToken) =>
    await registry.IsReadyAsync(cancellationToken).ConfigureAwait(false) && await provider.IsReadyAsync(cancellationToken).ConfigureAwait(false)
        ? Results.Ok(new { status = "healthy" })
        : Results.Json(new { status = "unhealthy" }, statusCode: 503));

app.MapPost("/v1/enrollments/challenges", async (HttpContext context, InstallationEnrollmentService service, CancellationToken cancellationToken) =>
{
    EnrollmentChallengeRequest request = DeserializeRequired<EnrollmentChallengeRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Ok(await service.CreateChallengeAsync(request, cancellationToken).ConfigureAwait(false));
});
app.MapPost("/v1/enrollments:activate", async (HttpContext context, InstallationEnrollmentService service, CancellationToken cancellationToken) =>
{
    ActivationRequest request = DeserializeRequired<ActivationRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Ok(await service.ActivateAsync(request, cancellationToken).ConfigureAwait(false));
});

app.MapGet("/v1/broker-policy", async (HttpContext context, RuntimeIdentityService identityService, CancellationToken cancellationToken) =>
{
    AuthenticatedInstallation authenticated = await AuthenticateAsync(context, identityService, ReadOnlyMemory<byte>.Empty, Guid.NewGuid(), cancellationToken).ConfigureAwait(false);
    return Results.Ok(new BrokerPolicy(authenticated.Identity.MinimumBrokerVersion, 1, 0, false));
});

app.MapPost("/v1/enrollments:renew", async (HttpContext context, RuntimeIdentityService identityService, InstallationEnrollmentService enrollmentService, CancellationToken cancellationToken) =>
{
    byte[] body = await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false);
    RenewalRequest request = DeserializeRequired<RenewalRequest>(body);
    AuthenticatedInstallation authenticated = await AuthenticateAsync(context, identityService, body, Guid.NewGuid(), cancellationToken).ConfigureAwait(false);
    return Results.Ok(await enrollmentService.RenewAsync(authenticated.Identity, request, cancellationToken).ConfigureAwait(false));
});

app.MapPost("/v1/connectors/{connectorId}/operations/{operationId}:invoke", async (string connectorId, string operationId, HttpContext context, RuntimeIdentityService identityService, RestrictedEgressService egressService, CancellationToken cancellationToken) =>
{
    _ = RequiredHeader(context, "traceparent");
    byte[] body = await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false);
    GatewayInvokeRequest request = DeserializeRequired<GatewayInvokeRequest>(body);
    AuthenticatedInstallation authenticated = await AuthenticateAsync(context, identityService, body, request.CorrelationId, cancellationToken).ConfigureAwait(false);
    return Results.Ok(await egressService.InvokeAsync(authenticated, connectorId, operationId, request, cancellationToken).ConfigureAwait(false));
});

app.MapPost("/admin/v1/connectors:validate", async (HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    _ = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorImportRequest request = DeserializeRequired<ConnectorImportRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Ok(service.Validate(request.Definition));
});
app.MapPost("/admin/v1/connectors:import", async (HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    string actor = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorImportRequest request = DeserializeRequired<ConnectorImportRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Json(await service.ImportAsync(request.Definition, request.ExpectedChecksumSha256, actor, Correlation(context), cancellationToken).ConfigureAwait(false), statusCode: StatusCodes.Status201Created);
});
app.MapGet("/admin/v1/connectors", async (HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    _ = RequireAdmin(context, app.Environment, hostOptions);
    return Results.Ok(await service.ListAsync(cancellationToken).ConfigureAwait(false));
});
app.MapGet("/admin/v1/connectors/{connectorId}/versions", async (string connectorId, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    _ = RequireAdmin(context, app.Environment, hostOptions);
    return Results.Ok(await service.VersionsAsync(connectorId, cancellationToken).ConfigureAwait(false));
});
app.MapGet("/admin/v1/connectors/{connectorId}/versions/{version}", async (string connectorId, string version, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    _ = RequireAdmin(context, app.Environment, hostOptions);
    return Results.Ok(await service.ShowAsync(connectorId, version, cancellationToken).ConfigureAwait(false));
});
app.MapGet("/admin/v1/connectors/{connectorId}/versions/{version}:export", async (string connectorId, string version, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    _ = RequireAdmin(context, app.Environment, hostOptions);
    return Results.Text(await service.ExportAsync(connectorId, version, cancellationToken).ConfigureAwait(false), "application/json", Encoding.UTF8);
});
app.MapPost("/admin/v1/connectors/{connectorId}/versions/{version}:validate", async (string connectorId, string version, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    string actor = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorVersionActionRequest request = DeserializeRequired<ConnectorVersionActionRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Ok(await service.ValidateStoredAsync(connectorId, version, request.ExpectedRowVersion, actor, Correlation(context), cancellationToken).ConfigureAwait(false));
});
app.MapPost("/admin/v1/connectors/{connectorId}/versions/{version}:publish", async (string connectorId, string version, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    string actor = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorVersionActionRequest request = DeserializeRequired<ConnectorVersionActionRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    if (request.ExpectedPublicationRevision is null) throw new GatewayException("BGW-CONCURRENCY-PRECONDITION", 428);
    return Results.Ok(await service.PublishAsync(connectorId, version, request.ExpectedRowVersion, request.ExpectedPublicationRevision.Value, actor, Correlation(context), cancellationToken).ConfigureAwait(false));
});
app.MapPost("/admin/v1/connectors/{connectorId}:rollback", async (string connectorId, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    string actor = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorRollbackRequest request = DeserializeRequired<ConnectorRollbackRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Ok(await service.RollbackAsync(connectorId, request, actor, Correlation(context), cancellationToken).ConfigureAwait(false));
});
app.MapPost("/admin/v1/connectors/{connectorId}/versions/{version}:retire", async (string connectorId, string version, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    string actor = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorVersionActionRequest request = DeserializeRequired<ConnectorVersionActionRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Ok(await service.RetireAsync(connectorId, version, request.ExpectedRowVersion, actor, Correlation(context), cancellationToken).ConfigureAwait(false));
});
app.MapPut("/admin/v1/connectors/{connectorId}/bindings", async (string connectorId, HttpContext context, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    string actor = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorBindingRequest request = DeserializeRequired<ConnectorBindingRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    return Results.Ok(new { revision = await service.PutBindingsAsync(connectorId, request, actor, Correlation(context), cancellationToken).ConfigureAwait(false) });
});
app.MapPost("/admin/v1/connectors/{connectorId}:test", async (string connectorId, HttpContext context, IGatewayOperationCatalog catalog, CancellationToken cancellationToken) =>
{
    _ = RequireAdmin(context, app.Environment, hostOptions);
    ConnectorTestRequest request = DeserializeRequired<ConnectorTestRequest>(await ReadBodyAsync(context.Request, cancellationToken).ConfigureAwait(false));
    GatewayOperationDefinition operation = await catalog.GetRequiredAsync(connectorId, request.OperationId, request.EnvironmentId, cancellationToken).ConfigureAwait(false);
    return Results.Ok(new { status = "valid", connectorId, operationId = operation.OperationId, connectorVersion = operation.Version });
});

app.MapGet("/admin/auth/login", (HttpContext context) =>
{
    if (string.Equals(hostOptions.Admin.Mode, "Oidc", StringComparison.Ordinal))
        return Results.Challenge(new AuthenticationProperties { RedirectUri = "/admin" }, [OpenIdConnectDefaults.AuthenticationScheme]);
    if (string.Equals(hostOptions.Admin.Mode, "DevelopmentAuth", StringComparison.Ordinal))
        return Results.Redirect("/admin/login");
    return Results.NotFound();
});

app.MapGet("/admin/auth/csrf", (HttpContext context, IAntiforgery antiforgery) =>
{
    AntiforgeryTokenSet tokens = antiforgery.GetAndStoreTokens(context);
    context.Response.Headers.CacheControl = "no-store";
    return Results.Ok(new { token = tokens.RequestToken });
});

app.MapPost("/admin/auth/development/login", async (DevelopmentLoginRequest request, HttpContext context, IAntiforgery antiforgery, IAdminSecurityStore securityStore, CancellationToken cancellationToken) =>
{
    await antiforgery.ValidateRequestAsync(context).ConfigureAwait(false);
    if (!app.Environment.IsDevelopment() || !string.Equals(hostOptions.Admin.Mode, "DevelopmentAuth", StringComparison.Ordinal) || !IsLocalDevelopmentHost(context.Request.Host.Host))
        throw new GatewayException("BGW-ADMIN-DEVELOPMENT-AUTH-DISABLED", 404);
    (string Subject, AdminRole[] Roles) user = request.UserName switch
    {
        "viewer" => ("viewer", [AdminRole.Viewer]),
        "editor" => ("editor", [AdminRole.Viewer, AdminRole.ConnectorEditor]),
        "approver" => ("approver", [AdminRole.Viewer, AdminRole.ConnectorApprover]),
        "operator" => ("operator", [AdminRole.Viewer, AdminRole.Operator]),
        "security-admin" => ("security-admin", [AdminRole.Viewer, AdminRole.SecurityAdministrator]),
        _ => throw new GatewayException("BGW-ADMIN-DEVELOPMENT-USER", 401)
    };
    const string issuer = "https://development.invalid";
    AdminPrincipalRecord principal = await securityStore.EnsurePrincipalAsync(new(issuer, user.Subject, user.Subject, user.Subject + "@example.invalid"), cancellationToken).ConfigureAwait(false);
    if (user.Roles.Contains(AdminRole.SecurityAdministrator)) _ = await securityStore.TryBootstrapSecurityAdministratorAsync(principal.Id, DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false);
    foreach (AdminRole role in user.Roles.Where(role => role != AdminRole.SecurityAdministrator))
        _ = await securityStore.AssignRoleAsync(principal.Id, role, null, principal.Id, DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false);
    ClaimsIdentity identity = new([
        new Claim("iss", issuer, ClaimValueTypes.String, issuer),
        new Claim("sub", user.Subject, ClaimValueTypes.String, issuer),
        new Claim("name", user.Subject, ClaimValueTypes.String, issuer),
        new Claim(ClaimTypes.NameIdentifier, user.Subject, ClaimValueTypes.String, issuer)
    ], CookieAuthenticationDefaults.AuthenticationScheme, "name", ClaimTypes.Role);
    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity), new AuthenticationProperties { IsPersistent = false, ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(20) }).ConfigureAwait(false);
    return Results.Ok(new { status = "authenticated" });
});

app.MapPost("/admin/auth/logout", async (HttpContext context, IAntiforgery antiforgery) =>
{
    await antiforgery.ValidateRequestAsync(context).ConfigureAwait(false);
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).ConfigureAwait(false);
    if (string.Equals(hostOptions.Admin.Mode, "Oidc", StringComparison.Ordinal))
    {
        await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties { RedirectUri = "/admin/login" }).ConfigureAwait(false);
        return Results.Empty;
    }
    return Results.Ok(new { status = "signed-out" });
}).RequireAuthorization();

app.MapGet("/admin/auth/me", async (HttpContext context, AdminAccessService access, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    context.Response.Headers.CacheControl = "no-store";
    return Results.Ok(new { id = admin.Principal.Id, displayName = admin.Principal.DisplayName, roles = admin.Assignments.Select(value => new { role = value.Role.ToString(), tenantId = value.TenantId }) });
}).RequireAuthorization();

RouteGroupBuilder adminApi = app.MapGroup("/admin/api/v1").RequireAuthorization();

adminApi.MapGet("/dashboard", async (HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, IGatewayRegistry registry, IProviderHealthCheck provider, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.Operator, AdminRole.SecurityAdministrator);
    AdminPage<TenantRecord> tenants = await directory.ListTenantsAsync(0, 1, cancellationToken).ConfigureAwait(false);
    AdminPage<ApplicationRecord> applications = await directory.ListApplicationsAsync(0, 1, cancellationToken).ConfigureAwait(false);
    bool databaseReady = await registry.IsReadyAsync(cancellationToken).ConfigureAwait(false);
    bool providerReady = await provider.IsReadyAsync(cancellationToken).ConfigureAwait(false);
    return Results.Ok(new { tenants = tenants.Total, applications = applications.Total, database = databaseReady ? "healthy" : "unhealthy", provider = providerReady ? "healthy" : "unhealthy", generatedAtUtc = DateTimeOffset.UtcNow });
});

adminApi.MapGet("/tenants", async (int? offset, int? limit, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.SecurityAdministrator);
    return Results.Ok(await directory.ListTenantsAsync(offset ?? 0, limit ?? 50, cancellationToken).ConfigureAwait(false));
});

adminApi.MapPost("/tenants", async (CreateTenantRequest request, HttpContext context, AdminAccessService access, IGatewayRegistry registry, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.SecurityAdministrator);
    ValidateAdminCode(request.Code, 64); ValidateAdminName(request.DisplayName);
    TenantRecord tenant = new(Guid.NewGuid(), request.Code, request.DisplayName, TenantStatus.Active, DateTimeOffset.UtcNow);
    await registry.AddTenantAsync(tenant, cancellationToken).ConfigureAwait(false);
    await AppendAdminAuditAsync(registry, context, admin, tenant.Id, "tenant.create", "tenant", tenant.Id.ToString("D"), cancellationToken).ConfigureAwait(false);
    return Results.Created($"/admin/api/v1/tenants/{tenant.Id:D}", tenant);
});

adminApi.MapGet("/applications", async (int? offset, int? limit, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.SecurityAdministrator);
    return Results.Ok(await directory.ListApplicationsAsync(offset ?? 0, limit ?? 50, cancellationToken).ConfigureAwait(false));
});

adminApi.MapPost("/applications", async (CreateApplicationRequest request, HttpContext context, AdminAccessService access, IGatewayRegistry registry, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.SecurityAdministrator);
    ValidateAdminCode(request.Code, 100); ValidateAdminName(request.DisplayName);
    if (!Version.TryParse(request.MinimumBrokerVersion, out _) || (request.MaximumBrokerVersion is not null && !Version.TryParse(request.MaximumBrokerVersion, out _))) throw new GatewayException("BGW-ADMIN-BROKER-VERSION", 400);
    ApplicationRecord application = new(Guid.NewGuid(), request.Code, request.DisplayName, ApplicationStatus.Active, request.MinimumBrokerVersion, request.MaximumBrokerVersion, DateTimeOffset.UtcNow);
    await registry.AddApplicationAsync(application, cancellationToken).ConfigureAwait(false);
    await AppendAdminAuditAsync(registry, context, admin, null, "application.create", "application", application.Id.ToString("D"), cancellationToken).ConfigureAwait(false);
    return Results.Created($"/admin/api/v1/applications/{application.Id:D}", application);
});

adminApi.MapGet("/environments", async (int? offset, int? limit, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.SecurityAdministrator);
    return Results.Ok(await directory.ListEnvironmentsAsync(offset ?? 0, limit ?? 50, cancellationToken).ConfigureAwait(false));
});

adminApi.MapGet("/installations", async (Guid tenantId, int? offset, int? limit, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, tenantId, AdminRole.Viewer, AdminRole.Operator, AdminRole.SecurityAdministrator);
    return Results.Ok(await directory.ListInstallationsAsync(tenantId, offset ?? 0, limit ?? 50, cancellationToken).ConfigureAwait(false));
});

adminApi.MapPost("/installations", async (CreateInstallationRequest request, HttpContext context, AdminAccessService access, IGatewayRegistry registry, GatewayProvisioningService provisioning, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, request.TenantId, AdminRole.SecurityAdministrator);
    Guid id = Guid.NewGuid(); DateTimeOffset now = DateTimeOffset.UtcNow;
    await registry.AddInstallationAsync(new(id, request.TenantId, request.ApplicationId, request.EnvironmentId, InstallationStatus.Pending, null, now), cancellationToken).ConfigureAwait(false);
    ProvisionedActivation activation = await provisioning.CreateActivationCodeAsync(id, admin.ActorId, cancellationToken).ConfigureAwait(false);
    await AppendAdminAuditAsync(registry, context, admin, request.TenantId, "installation.create", "installation", id.ToString("D"), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.CacheControl = "no-store";
    return Results.Json(activation, statusCode: StatusCodes.Status201Created);
});

adminApi.MapPost("/installations/{installationId}:revoke", async (Guid installationId, Guid tenantId, RevokeInstallationRequest request, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, InstallationEnrollmentService enrollment, IGatewayRegistry registry, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, tenantId, AdminRole.SecurityAdministrator);
    if (await directory.GetInstallationAsync(tenantId, installationId, cancellationToken).ConfigureAwait(false) is null) throw new GatewayException("BGW-INSTALLATION-NOT-FOUND", 404);
    await enrollment.RevokeAsync(installationId, request.Reason, cancellationToken).ConfigureAwait(false);
    await AppendAdminAuditAsync(registry, context, admin, tenantId, "installation.revoke", "installation", installationId.ToString("D"), cancellationToken).ConfigureAwait(false);
    return Results.Ok(new { status = "revoked" });
});

adminApi.MapGet("/grants", async (Guid tenantId, int? offset, int? limit, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, tenantId, AdminRole.Viewer, AdminRole.SecurityAdministrator);
    return Results.Ok(await directory.ListGrantsAsync(tenantId, offset ?? 0, limit ?? 50, cancellationToken).ConfigureAwait(false));
});

adminApi.MapPost("/grants", async (CreateGrantRequest request, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, IGatewayRegistry registry, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, request.TenantId, AdminRole.SecurityAdministrator);
    if (await directory.GetInstallationAsync(request.TenantId, request.InstallationId, cancellationToken).ConfigureAwait(false) is null) throw new GatewayException("BGW-INSTALLATION-NOT-FOUND", 404);
    ValidateAdminCode(request.ConnectorId, 100); ValidateAdminCode(request.OperationId, 100);
    InstallationGrantRecord grant = new(Guid.NewGuid(), request.InstallationId, request.TenantId, request.ConnectorId, request.OperationId, true, DateTimeOffset.UtcNow, request.ValidUntil);
    await registry.AddGrantAsync(grant, cancellationToken).ConfigureAwait(false);
    await AppendAdminAuditAsync(registry, context, admin, request.TenantId, "grant.create", "installation_grant", grant.Id.ToString("D"), cancellationToken).ConfigureAwait(false);
    return Results.Created($"/admin/api/v1/grants/{grant.Id:D}", grant);
});

adminApi.MapGet("/audit", async (Guid tenantId, int? offset, int? limit, HttpContext context, AdminAccessService access, IAdminDirectoryStore directory, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, tenantId, AdminRole.Viewer, AdminRole.Operator, AdminRole.SecurityAdministrator);
    return Results.Ok(await directory.ListAuditAsync(tenantId, offset ?? 0, limit ?? 50, cancellationToken).ConfigureAwait(false));
});

adminApi.MapPost("/bootstrap", async (HttpContext context, AdminAccessService access, IAdminSecurityStore securityStore, IGatewayRegistry registry, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    string? expected = Environment.GetEnvironmentVariable(hostOptions.Admin.BootstrapTokenEnvironmentVariable, EnvironmentVariableTarget.Process);
    string supplied = context.Request.Headers["X-Bootstrap-Token"].ToString();
    if (!FixedSecretEquals(expected, supplied)) throw new GatewayException("BGW-ADMIN-BOOTSTRAP-DENIED", 403);
    if (!await securityStore.TryBootstrapSecurityAdministratorAsync(admin.Principal.Id, DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false))
        throw new GatewayException("BGW-ADMIN-BOOTSTRAP-COMPLETE", 409);
    await registry.AppendAuditAsync(new GatewayAuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, null, "admin", admin.ActorId, "admin.bootstrap", "admin_principal", admin.ActorId, Correlation(context), "success", "BGW-ADMIN-BOOTSTRAP-COMPLETE", new Dictionary<string, string>()), cancellationToken).ConfigureAwait(false);
    return Results.Ok(new { status = "completed" });
});

adminApi.MapPost("/role-assignments", async (AdminRoleAssignmentRequest request, HttpContext context, AdminAccessService access, IAdminSecurityStore securityStore, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, request.TenantId, AdminRole.SecurityAdministrator);
    AdminPrincipalRecord target = await securityStore.EnsurePrincipalAsync(request.Principal, cancellationToken).ConfigureAwait(false);
    return Results.Ok(await securityStore.AssignRoleAsync(target.Id, request.Role, request.TenantId, admin.Principal.Id, DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false));
});

adminApi.MapGet("/connectors", async (HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.Operator, AdminRole.SecurityAdministrator);
    return Results.Ok(await service.ListAsync(cancellationToken).ConfigureAwait(false));
});

adminApi.MapPost("/connectors:validate", async (ConnectorImportRequest request, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.ConnectorEditor, AdminRole.SecurityAdministrator);
    return Results.Ok(service.Validate(request.Definition));
});

adminApi.MapPost("/connectors:import", async (ConnectorImportRequest request, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.ConnectorEditor, AdminRole.SecurityAdministrator);
    ConnectorVersionResource created = await service.ImportAsync(request.Definition, request.ExpectedChecksumSha256, admin.ActorId, Correlation(context), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(created.RowVersion);
    return Results.Json(created, statusCode: StatusCodes.Status201Created);
});

adminApi.MapGet("/connectors/{connectorId}/versions", async (string connectorId, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.Operator, AdminRole.SecurityAdministrator);
    return Results.Ok(await service.VersionsAsync(connectorId, cancellationToken).ConfigureAwait(false));
});

adminApi.MapGet("/connectors/{connectorId}/versions/{version}", async (string connectorId, string version, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Viewer, AdminRole.ConnectorEditor, AdminRole.ConnectorApprover, AdminRole.Operator, AdminRole.SecurityAdministrator);
    ConnectorVersionResource resource = await service.ShowAsync(connectorId, version, cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(resource.RowVersion);
    return Results.Ok(resource);
});

adminApi.MapPost("/connectors/{connectorId}/versions/{version}:validate", async (string connectorId, string version, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.ConnectorEditor, AdminRole.SecurityAdministrator);
    long rowVersion = RequiredIfMatch(context);
    ConnectorVersionResource resource = await service.ValidateStoredAsync(connectorId, version, rowVersion, admin.ActorId, Correlation(context), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(resource.RowVersion);
    return Results.Ok(resource);
});

adminApi.MapPost("/connectors/{connectorId}/versions/{version}/approval-requests", async (string connectorId, string version, HttpContext context, AdminAccessService access, ConnectorApprovalService approvals, CancellationToken cancellationToken) =>
    Results.Ok(await approvals.RequestAsync(connectorId, version, await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false), cancellationToken).ConfigureAwait(false)));

adminApi.MapPost("/connectors/{connectorId}/versions/{version}/approvals", async (string connectorId, string version, HttpContext context, AdminAccessService access, ConnectorApprovalService approvals, CancellationToken cancellationToken) =>
    Results.Ok(await approvals.ApproveAsync(connectorId, version, await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false), cancellationToken).ConfigureAwait(false)));

adminApi.MapGet("/connectors/{connectorId}/versions/{version}/approvals", async (string connectorId, string version, HttpContext context, AdminAccessService access, ConnectorApprovalService approvals, CancellationToken cancellationToken) =>
    Results.Ok(await approvals.ListAsync(connectorId, version, await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false), cancellationToken).ConfigureAwait(false)));

adminApi.MapPost("/connectors/{connectorId}/versions/{version}:publish", async (string connectorId, string version, ConnectorVersionActionRequest request, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
    long rowVersion = RequiredIfMatch(context);
    if (request.ExpectedPublicationRevision is null) throw new GatewayException("BGW-CONCURRENCY-PRECONDITION", 428);
    ConnectorVersionResource resource = await service.PublishAsync(connectorId, version, rowVersion, request.ExpectedPublicationRevision.Value, admin.ActorId, Correlation(context), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(resource.RowVersion);
    return Results.Ok(resource);
});

adminApi.MapPost("/connectors/{connectorId}:rollback", async (string connectorId, ConnectorRollbackRequest request, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.ConnectorApprover, AdminRole.SecurityAdministrator);
    return Results.Ok(await service.RollbackAsync(connectorId, request, admin.ActorId, Correlation(context), cancellationToken).ConfigureAwait(false));
});

adminApi.MapPost("/connectors/{connectorId}/versions/{version}:retire", async (string connectorId, string version, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.SecurityAdministrator);
    ConnectorVersionResource resource = await service.RetireAsync(connectorId, version, RequiredIfMatch(context), admin.ActorId, Correlation(context), cancellationToken).ConfigureAwait(false);
    context.Response.Headers.ETag = ETag(resource.RowVersion);
    return Results.Ok(resource);
});

adminApi.MapPut("/connectors/{connectorId}/bindings", async (string connectorId, ConnectorBindingRequest request, HttpContext context, AdminAccessService access, ConnectorAdministrationService service, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.SecurityAdministrator);
    return Results.Ok(new { revision = await service.PutBindingsAsync(connectorId, request, admin.ActorId, Correlation(context), cancellationToken).ConfigureAwait(false) });
});

adminApi.MapPost("/connectors/{connectorId}:test", async (string connectorId, ConnectorTestRequest request, HttpContext context, AdminAccessService access, IGatewayOperationCatalog catalog, CancellationToken cancellationToken) =>
{
    AdminAccessContext admin = await access.ResolveAsync(context.User, cancellationToken).ConfigureAwait(false);
    AdminAccessService.Require(admin, null, AdminRole.Operator, AdminRole.SecurityAdministrator);
    GatewayOperationDefinition operation = await catalog.GetRequiredAsync(connectorId, request.OperationId, request.EnvironmentId, cancellationToken).ConfigureAwait(false);
    return Results.Ok(new { status = "valid", connectorId, operationId = operation.OperationId, connectorVersion = operation.Version });
});

app.MapGet("/admin", () => Results.Redirect("/admin/"));
string adminIndexPath = Path.Combine(app.Environment.WebRootPath ?? "wwwroot", "admin", "index.html");
if (File.Exists(adminIndexPath))
{
    app.MapFallback("/admin/{*path:nonfile}", async context =>
    {
        string nonce = context.Items["AdminCspNonce"] as string ?? throw new InvalidOperationException("Admin CSP nonce missing.");
        string index = (await File.ReadAllTextAsync(adminIndexPath, context.RequestAborted).ConfigureAwait(false)).Replace("__CSP_NONCE__", nonce, StringComparison.Ordinal);
        context.Response.ContentType = "text/html; charset=utf-8";
        context.Response.Headers.CacheControl = "no-cache";
        await context.Response.WriteAsync(index, context.RequestAborted).ConfigureAwait(false);
    });
}

app.Run();

static ProviderServices CreateProviderServices(GatewayProviderOptions options, IHostEnvironment environment)
{
    if (string.Equals(options.Kind, "Synthetic", StringComparison.Ordinal))
    {
        if (!environment.IsEnvironment("M3Testing") && !environment.IsEnvironment("M4Testing") && !environment.IsDevelopment() && !environment.IsEnvironment("Testing"))
            throw new InvalidOperationException("Synthetic provider is not allowed in this environment.");
        if (!Uri.TryCreate(options.Endpoint, UriKind.Absolute, out Uri? endpoint) || endpoint.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("Synthetic provider requires an HTTPS endpoint.");
        string? token = Environment.GetEnvironmentVariable(options.AccessTokenEnvironmentVariable, EnvironmentVariableTarget.Process);
        if (string.IsNullOrWhiteSpace(token)) throw new InvalidOperationException("Synthetic provider access token is required.");
        SyntheticProvider provider = new(endpoint, token);
        return new ProviderServices(provider, provider, provider, provider);
    }

    if (string.Equals(options.Kind, "ExternalPack", StringComparison.Ordinal))
    {
        if (!Uri.TryCreate(options.Endpoint, UriKind.Absolute, out Uri? endpoint) || endpoint.Scheme != Uri.UriSchemeHttps || string.IsNullOrWhiteSpace(options.AssemblyPath) || string.IsNullOrWhiteSpace(options.FactoryType))
            throw new InvalidOperationException("External provider pack configuration is incomplete.");
        string assemblyPath = Path.GetFullPath(options.AssemblyPath);
        if (!Path.IsPathFullyQualified(options.AssemblyPath) || !File.Exists(assemblyPath)) throw new InvalidOperationException("External provider pack assembly is unavailable.");
        System.Reflection.Assembly assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(assemblyPath);
        Type factoryType = assembly.GetType(options.FactoryType, throwOnError: true, ignoreCase: false) ?? throw new InvalidOperationException("External provider pack factory type was not found.");
        if (!typeof(IProviderPackFactory).IsAssignableFrom(factoryType) || factoryType.IsAbstract || factoryType.GetConstructor(Type.EmptyTypes) is null)
            throw new InvalidOperationException("External provider pack factory does not implement the required contract.");
        IProviderPackFactory factory = (IProviderPackFactory)Activator.CreateInstance(factoryType)!;
        ProviderServices services = factory.Create(new ProviderPackContext(endpoint, options.ClientIdentity, options.Settings));
        if (!services.CapabilitySource.Capabilities.SecretValues || !services.CapabilitySource.Capabilities.ClientCertificates)
            throw new InvalidOperationException("External provider pack lacks required capabilities.");
        return services;
    }

    if (!string.Equals(options.Kind, "Disabled", StringComparison.Ordinal) && !string.Equals(options.Kind, "InMemory", StringComparison.Ordinal))
        throw new InvalidOperationException("Unknown provider kind.");
    if (!environment.IsDevelopment() && !environment.IsEnvironment("Testing"))
        throw new InvalidOperationException("A configured provider pack is required outside Development/Testing.");
    InMemoryProvider inMemory = new(new Dictionary<string, string>());
    return new ProviderServices(inMemory, inMemory, inMemory, inMemory);
}

static async Task<AuthenticatedInstallation> AuthenticateAsync(HttpContext context, RuntimeIdentityService service, ReadOnlyMemory<byte> body, Guid correlationId, CancellationToken cancellationToken)
{
    X509Certificate2? certificate = await context.Connection.GetClientCertificateAsync(cancellationToken).ConfigureAwait(false);
    if (certificate is null) throw new GatewayException("BGW-AUTHN-CERTIFICATE-REQUIRED", 401);
    RuntimeSignatureHeaders headers = new(RequiredHeader(context, "X-BG-Timestamp"), RequiredHeader(context, "X-BG-Nonce"), RequiredHeader(context, "X-BG-Content-SHA256"), RequiredHeader(context, "X-BG-Signature"));
    return await service.AuthenticateAsync(certificate, context.Request.Method, context.Request.PathBase + context.Request.Path + context.Request.QueryString, headers, body, correlationId, cancellationToken).ConfigureAwait(false);
}

static string RequiredHeader(HttpContext context, string name)
{
    string value = context.Request.Headers[name].ToString();
    if (string.IsNullOrWhiteSpace(value)) throw new GatewayException("BGW-AUTHN-HEADER-REQUIRED", 401);
    return value;
}

static void ValidateAdminCode(string value, int maximumLength)
{
    if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.')))
        throw new GatewayException("BGW-ADMIN-CODE", 400);
}

static void ValidateAdminName(string value)
{
    if (string.IsNullOrWhiteSpace(value) || value.Length > 256 || value.Any(char.IsControl)) throw new GatewayException("BGW-ADMIN-DISPLAY-NAME", 400);
}

static Task AppendAdminAuditAsync(IGatewayRegistry registry, HttpContext context, AdminAccessContext actor, Guid? tenantId, string action, string targetType, string targetId, CancellationToken cancellationToken) =>
    registry.AppendAuditAsync(new GatewayAuditEvent(Guid.NewGuid(), DateTimeOffset.UtcNow, tenantId, "admin", actor.ActorId, action, targetType, targetId, Correlation(context), "success", "BGW-ADMIN-ACTION", new Dictionary<string, string>()), cancellationToken);

static string RequireAdmin(HttpContext context, IHostEnvironment environment, GatewayHostOptions options)
{
    if (!string.Equals(options.Admin.Mode, "DevelopmentApiKey", StringComparison.Ordinal) || (!environment.IsDevelopment() && !environment.IsEnvironment("Testing") && !environment.IsEnvironment("M4Testing")))
        throw new GatewayException("BGW-ADMIN-AUTHENTICATION-DISABLED", 404);
    string? expected = Environment.GetEnvironmentVariable(options.Admin.ApiKeyEnvironmentVariable, EnvironmentVariableTarget.Process);
    string supplied = context.Request.Headers["X-Admin-Key"].ToString();
    if (string.IsNullOrWhiteSpace(expected) || string.IsNullOrWhiteSpace(supplied)) throw new GatewayException("BGW-ADMIN-AUTHENTICATION", 401);
    byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
    byte[] suppliedBytes = Encoding.UTF8.GetBytes(supplied);
    bool valid = expectedBytes.Length == suppliedBytes.Length && CryptographicOperations.FixedTimeEquals(expectedBytes, suppliedBytes);
    CryptographicOperations.ZeroMemory(expectedBytes);
    CryptographicOperations.ZeroMemory(suppliedBytes);
    if (!valid) throw new GatewayException("BGW-ADMIN-AUTHENTICATION", 401);
    string actor = context.Request.Headers["X-Admin-Actor"].ToString();
    return actor.Length is >= 3 and <= 100 && actor.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or '@') ? actor : "development-admin";
}

static Guid Correlation(HttpContext context) => Guid.TryParse(context.Response.Headers["X-Correlation-ID"], out Guid value) ? value : Guid.NewGuid();

static bool IsLocalDevelopmentHost(string host) => string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) || string.Equals(host, "127.0.0.1", StringComparison.Ordinal) || string.Equals(host, "::1", StringComparison.Ordinal);

static bool FixedSecretEquals(string? expected, string supplied)
{
    if (string.IsNullOrWhiteSpace(expected) || string.IsNullOrWhiteSpace(supplied)) return false;
    byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
    byte[] suppliedBytes = Encoding.UTF8.GetBytes(supplied);
    try { return expectedBytes.Length == suppliedBytes.Length && CryptographicOperations.FixedTimeEquals(expectedBytes, suppliedBytes); }
    finally { CryptographicOperations.ZeroMemory(expectedBytes); CryptographicOperations.ZeroMemory(suppliedBytes); }
}

static string ETag(long rowVersion) => FormattableString.Invariant($"\"{rowVersion}\"");

static long RequiredIfMatch(HttpContext context)
{
    string value = context.Request.Headers.IfMatch.ToString();
    if (value.Length < 3 || value[0] != '"' || value[^1] != '"' || !long.TryParse(value.AsSpan(1, value.Length - 2), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long rowVersion) || rowVersion < 1)
        throw new GatewayException("BGW-CONCURRENCY-PRECONDITION", 428);
    return rowVersion;
}

static async Task<byte[]> ReadBodyAsync(HttpRequest request, CancellationToken cancellationToken)
{
    if (request.ContentLength > 16 * 1024 * 1024) throw new GatewayException("BGW-PROTOCOL-PAYLOAD", 413);
    using MemoryStream output = new();
    await request.Body.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
    if (output.Length > 16 * 1024 * 1024) throw new GatewayException("BGW-PROTOCOL-PAYLOAD", 413);
    return output.ToArray();
}

static T DeserializeRequired<T>(byte[] body) => JsonSerializer.Deserialize<T>(body, new JsonSerializerOptions(JsonSerializerDefaults.Web) { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow }) ?? throw new GatewayException("BGW-PROTOCOL-JSON", 400);

/// <summary>Gateway API entry point exposed for in-process integration tests.</summary>
public partial class Program;

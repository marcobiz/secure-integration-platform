using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Identity;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Npgsql;
using SecureIntegration.Gateway.Api;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Infrastructure;

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
bool useAzureCertificateForwarding = hostOptions.TrustAzureAppServiceClientCertificateForwarding;
if (useAzureCertificateForwarding)
{
    if (!builder.Environment.IsProduction() || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID")))
        throw new InvalidOperationException("Azure App Service certificate forwarding is valid only in the Production App Service boundary.");
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
    builder.Services.AddSingleton<IGatewayRegistry, InMemoryGatewayRegistry>();
    builder.Services.AddSingleton<IConnectorConfigurationStore, InMemoryConnectorConfigurationStore>();
}
else
{
    builder.Services.AddSingleton(_ => NpgsqlDataSource.Create(connectionString));
    builder.Services.AddSingleton<IGatewayRegistry, PostgresGatewayRegistry>();
    builder.Services.AddSingleton<IConnectorConfigurationStore, PostgresConnectorConfigurationStore>();
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

ISecretProvider secretProvider;
if ((builder.Environment.IsEnvironment("M3Testing") || builder.Environment.IsEnvironment("M4Testing")) && Uri.TryCreate(hostOptions.SyntheticVaultUri, UriKind.Absolute, out Uri? syntheticVaultUri) && syntheticVaultUri.Scheme == Uri.UriSchemeHttps)
{
    string? token = Environment.GetEnvironmentVariable(hostOptions.SyntheticVaultTokenEnvironmentVariable, EnvironmentVariableTarget.Process);
    if (string.IsNullOrWhiteSpace(token)) throw new InvalidOperationException("The M3 synthetic Vault token is required in M3Testing.");
    secretProvider = new SyntheticVaultSecretProvider(syntheticVaultUri, token);
    builder.Services.AddSingleton(secretProvider);
}
else if (Uri.TryCreate(hostOptions.KeyVaultUri, UriKind.Absolute, out Uri? vaultUri) && vaultUri.Scheme == Uri.UriSchemeHttps)
{
    TokenCredential tokenCredential = string.IsNullOrWhiteSpace(hostOptions.ManagedIdentityClientId)
        ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
        : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(hostOptions.ManagedIdentityClientId));
    secretProvider = new CachingSecretProvider(new AzureKeyVaultSecretProvider(vaultUri, tokenCredential), TimeSpan.FromMinutes(5));
    builder.Services.AddSingleton(tokenCredential);
    builder.Services.AddSingleton(secretProvider);
}
else
{
    if (!builder.Environment.IsDevelopment() && !builder.Environment.IsEnvironment("Testing"))
        throw new InvalidOperationException("An HTTPS Azure Key Vault URI is required outside Development/Testing.");
    secretProvider = new InMemorySecretProvider(new Dictionary<string, string>());
    builder.Services.AddSingleton(secretProvider);
}

byte[] activationKey;
string? encodedActivationKey = hostOptions.ActivationHmacKeyBase64;
if (!builder.Environment.IsDevelopment() && !builder.Environment.IsEnvironment("Testing") && !builder.Environment.IsEnvironment("M3Testing") && !builder.Environment.IsEnvironment("M4Testing"))
{
    if (string.IsNullOrWhiteSpace(hostOptions.ActivationHmacSecretReference)) throw new InvalidOperationException("Gateway activation HMAC Key Vault reference is required outside Development/Testing/M3Testing.");
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
builder.Services.AddSingleton<ConnectorAdministrationService>();

WebApplication app = builder.Build();
if (useAzureCertificateForwarding) app.UseCertificateForwarding();
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
    catch (Exception)
    {
        if (context.Response.HasStarted) throw;
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "application/problem+json";
        GatewayLog.RequestFailed(gatewayLogger, "BGW-INTERNAL", requestCorrelationId);
        await context.Response.WriteAsJsonAsync(new { type = "about:blank", title = "Gateway request failed", status = 500, code = "BGW-INTERNAL", correlationId = requestCorrelationId, retryable = false }).ConfigureAwait(false);
    }
});

app.MapGet("/health/live", () => Results.Ok(new { status = "healthy" }));
app.MapGet("/health/ready", async (IGatewayRegistry registry, ISecretProvider secrets, CancellationToken cancellationToken) =>
    await registry.IsReadyAsync(cancellationToken).ConfigureAwait(false) && await secrets.IsReadyAsync(cancellationToken).ConfigureAwait(false)
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

app.Run();

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

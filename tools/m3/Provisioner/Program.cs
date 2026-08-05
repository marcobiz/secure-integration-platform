using System.Text.Json;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;

string adminConnection = Required("M3_POSTGRES_ADMIN_CONNECTION");
string runtimePassword = Required("M3_POSTGRES_RUNTIME_PASSWORD");
string activationKeyText = Required("M3_ACTIVATION_HMAC_BASE64");
string outputPath = Required("M3_PROVISIONING_OUTPUT");
string? adminApiPassword = Optional("M5_POSTGRES_ADMIN_API_PASSWORD");
byte[] activationKey;
try { activationKey = Convert.FromBase64String(activationKeyText); }
catch (FormatException) { throw new InvalidOperationException("M3 activation HMAC key must be Base64."); }
if (activationKey.Length < 32) throw new InvalidOperationException("M3 activation HMAC key must contain at least 256 bits.");

await EnsureRuntimeRoleAsync(adminConnection, runtimePassword).ConfigureAwait(false);
if (adminApiPassword is not null) await EnsureAdminRoleAsync(adminConnection, adminApiPassword).ConfigureAwait(false);
await using NpgsqlDataSource dataSource = NpgsqlDataSource.Create(adminConnection);
PostgresGatewayRegistry registry = new(dataSource);
SystemGatewayClock clock = new();
GatewayProvisioningService provisioning = new(registry, clock, new EnrollmentSecurityOptions { ActivationHmacKey = activationKey });
Guid tenantId = Guid.NewGuid();
Guid applicationId = Guid.NewGuid();
Guid environmentId = Guid.NewGuid();
Guid installationId = Guid.NewGuid();
ProvisionedActivation activation = await provisioning.CreateInstallationAsync(
    new TenantRecord(tenantId, "m3-tenant", "M3 Synthetic Tenant", TenantStatus.Active, clock.UtcNow),
    new ApplicationRecord(applicationId, "m3-legacy", "M3 Legacy Simulator", ApplicationStatus.Active, "1.0.0", null, clock.UtcNow),
    new GatewayEnvironmentRecord(environmentId, "m3", "M3 Deterministic", false),
    installationId,
    "m3-provisioner",
    CancellationToken.None).ConfigureAwait(false);
await registry.AddGrantAsync(new InstallationGrantRecord(Guid.NewGuid(), installationId, tenantId, "m3-vendor", "submit", true, clock.UtcNow), CancellationToken.None).ConfigureAwait(false);
await registry.AddGrantAsync(new InstallationGrantRecord(Guid.NewGuid(), installationId, tenantId, "sample-secure-service", "submit", true, clock.UtcNow), CancellationToken.None).ConfigureAwait(false);
Guid securityInstallationId = Guid.NewGuid();
Guid securityTenantId = Guid.NewGuid();
Guid securityApplicationId = Guid.NewGuid();
Guid securityEnvironmentId = Guid.NewGuid();
ProvisionedActivation securityActivation = await provisioning.CreateInstallationAsync(
    new TenantRecord(securityTenantId, "m3-security-tenant", "M3 Security Driver Tenant", TenantStatus.Active, clock.UtcNow),
    new ApplicationRecord(securityApplicationId, "m3-security-driver", "M3 Security Driver", ApplicationStatus.Active, "1.0.0", null, clock.UtcNow),
    new GatewayEnvironmentRecord(securityEnvironmentId, "m3-security", "M3 Security Tests", false),
    securityInstallationId,
    "m3-provisioner",
    CancellationToken.None).ConfigureAwait(false);
string[] securityGrantedOperations = ["submit", "loopback", "private", "metadata", "redirect", "wrong-certificate"];
foreach (string operation in securityGrantedOperations)
    await registry.AddGrantAsync(new InstallationGrantRecord(Guid.NewGuid(), securityInstallationId, securityTenantId, "m3-vendor", operation, true, clock.UtcNow), CancellationToken.None).ConfigureAwait(false);

PostgresConnectorConfigurationStore connectorStore = new(dataSource);
ConnectorDefinitionValidator connectorValidator = new();
await PublishConnectorAsync("m3-vendor", "3.0.0-m3", securityOperations: true).ConfigureAwait(false);
await PublishConnectorAsync("sample-secure-service", "1.0.0", securityOperations: false).ConfigureAwait(false);

Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
byte[] document = JsonSerializer.SerializeToUtf8Bytes(new
{
    schemaVersion = 1,
    tenantId,
    applicationId,
    environmentId,
    installationId,
    activationCodeId = activation.ActivationCodeId,
    activationCode = activation.ActivationCode,
    expiresAtUtc = activation.ExpiresAt,
    securityInstallationId,
    securityTenantId,
    securityActivationCodeId = securityActivation.ActivationCodeId,
    securityActivationCode = securityActivation.ActivationCode,
    securityExpiresAtUtc = securityActivation.ExpiresAt
}, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true });
await File.WriteAllBytesAsync(outputPath, document).ConfigureAwait(false);
Console.WriteLine(JsonSerializer.Serialize(new { status = "provisioned", installationId, activationCodeId = activation.ActivationCodeId }));
return 0;

async Task PublishConnectorAsync(string connectorId, string version, bool securityOperations)
{
    object[] operations = securityOperations
        ?
        [
            Operation("submit", "vendor", "/vendor/orders", "apiKeyAndMtls", "vendor-client-certificate"),
            Operation("loopback", "loopback", "/vendor/orders", "none", null),
            Operation("private", "private", "/vendor/orders", "none", null),
            Operation("metadata", "metadata", "/latest/meta-data/", "none", null),
            Operation("redirect", "vendor", "/vendor/redirect", "apiKeyAndMtls", "vendor-client-certificate"),
            Operation("wrong-certificate", "vendor", "/vendor/orders", "apiKeyAndMtls", "vendor-wrong-client-certificate")
        ]
        : [Operation("submit", "vendor", "/vendor/orders", "apiKeyAndMtls", "vendor-client-certificate")];
    JsonElement definition = JsonSerializer.SerializeToElement(new
    {
        schemaVersion = "1.0",
        connectorId,
        version,
        displayName = securityOperations ? "M3 Synthetic Vendor" : "Sample Secure Service",
        bindings = new
        {
            endpoints = new[] { new { name = "vendor" }, new { name = "loopback" }, new { name = "private" }, new { name = "metadata" } },
            secrets = new[] { new { name = "vendor-api-key", kind = "opaque" }, new { name = "vendor-client-certificate", kind = "clientCertificate" }, new { name = "vendor-wrong-client-certificate", kind = "clientCertificate" } }
        },
        operations
    });
    ValidatedConnectorDefinition validated = connectorValidator.ValidateRequired(definition);
    ConnectorVersionRecord draft = await connectorStore.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, connectorId, version, "1.0", ConnectorVersionState.Draft, validated.CanonicalJson, Convert.FromHexString(validated.ChecksumSha256), "m3-provisioner", clock.UtcNow, 1), CancellationToken.None).ConfigureAwait(false);
    ConnectorVersionRecord validatedRecord = await connectorStore.MarkValidatedAsync(draft.Id, draft.RowVersion, clock.UtcNow, CancellationToken.None).ConfigureAwait(false);
    Dictionary<string, Uri> endpoints = new(StringComparer.Ordinal)
    {
        ["vendor"] = new("https://vendor.m3.test:8443/"),
        ["loopback"] = new("https://127.0.0.1/"),
        ["private"] = new("https://172.29.44.7/"),
        ["metadata"] = new("https://169.254.169.254/")
    };
    Dictionary<string, string> secrets = new(StringComparer.Ordinal)
    {
        ["vendor-api-key"] = "synthetic-vault://vault.m3.test/vendor-api-key"
    };
    Dictionary<string, string> certificates = new(StringComparer.Ordinal)
    {
        ["vendor-client-certificate"] = "synthetic-vault://vault.m3.test/vendor-client-certificate",
        ["vendor-wrong-client-certificate"] = "synthetic-vault://vault.m3.test/vendor-wrong-client-certificate"
    };
    string primaryChecksum = ConnectorBindingDigests.Revision(draft.Id, environmentId, endpoints, secrets, certificates);
    string securityChecksum = ConnectorBindingDigests.Revision(draft.Id, securityEnvironmentId, endpoints, secrets, certificates);
    _ = await connectorStore.PutBindingsAsync(new(Guid.NewGuid(), draft.ConnectorId, draft.Id, environmentId, endpoints, secrets, certificates, 0, primaryChecksum, ConnectorBindingState.Draft, clock.UtcNow, "m3-provisioner"), null, CancellationToken.None).ConfigureAwait(false);
    _ = await connectorStore.PutBindingsAsync(new(Guid.NewGuid(), draft.ConnectorId, draft.Id, securityEnvironmentId, endpoints, secrets, certificates, 0, securityChecksum, ConnectorBindingState.Draft, clock.UtcNow, "m3-provisioner"), null, CancellationToken.None).ConfigureAwait(false);
    _ = await connectorStore.PublishAsync(draft.Id, validatedRecord.RowVersion, 0, "m3-provisioner", clock.UtcNow, CancellationToken.None).ConfigureAwait(false);
}

static object Operation(string operationId, string endpointBinding, string path, string authentication, string? certificateBinding)
{
    object auth = authentication == "none"
        ? new { kind = "none" }
        : (object)new { kind = authentication, secretBinding = "vendor-api-key", headerName = "X-Vendor-Api-Key", certificateBinding };
    return new
    {
        operationId,
        endpointBinding,
        method = "POST",
        path,
        request = new { contentType = "application/json", maximumBytes = 1048576 },
        response = new { maximumBytes = 1048576 },
        authentication = auth,
        timeoutMs = 30000,
        redirectPolicy = "deny",
        allowedClientHeaders = Array.Empty<string>(),
        idempotent = false,
        maximumRetries = 0
    };
}

static string Required(string name)
{
    string? value = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);
    if (string.IsNullOrWhiteSpace(value) || value.Any(character => character is '\r' or '\n')) throw new InvalidOperationException($"{name} is required.");
    return value;
}

static string? Optional(string name)
{
    string? value = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);
    if (value is not null && (string.IsNullOrWhiteSpace(value) || value.Any(character => character is '\r' or '\n'))) throw new InvalidOperationException($"{name} is invalid.");
    return value;
}

static async Task EnsureRuntimeRoleAsync(string connectionString, string password)
{
    await using NpgsqlConnection connection = new(connectionString);
    await connection.OpenAsync().ConfigureAwait(false);
    await using NpgsqlCommand quote = new("SELECT quote_literal($1)", connection);
    quote.Parameters.AddWithValue(password);
    string quotedPassword = (string)(await quote.ExecuteScalarAsync().ConfigureAwait(false) ?? throw new InvalidOperationException("Cannot quote runtime credential."));
    string sql = $"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='m3_gateway_runtime') THEN CREATE ROLE m3_gateway_runtime LOGIN; END IF; END $$; ALTER ROLE m3_gateway_runtime NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION LOGIN PASSWORD {quotedPassword}; GRANT gateway_runtime TO m3_gateway_runtime;";
    await using NpgsqlCommand command = new(sql, connection);
    await command.ExecuteNonQueryAsync().ConfigureAwait(false);
}

static async Task EnsureAdminRoleAsync(string connectionString, string password)
{
    await using NpgsqlConnection connection = new(connectionString);
    await connection.OpenAsync().ConfigureAwait(false);
    await using NpgsqlCommand quote = new("SELECT quote_literal($1)", connection);
    quote.Parameters.AddWithValue(password);
    string quotedPassword = (string)(await quote.ExecuteScalarAsync().ConfigureAwait(false) ?? throw new InvalidOperationException("Cannot quote Admin credential."));
    string sql = $"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='m5_gateway_admin') THEN CREATE ROLE m5_gateway_admin LOGIN; END IF; END $$; ALTER ROLE m5_gateway_admin NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION LOGIN PASSWORD {quotedPassword}; GRANT gateway_admin TO m5_gateway_admin;";
    await using NpgsqlCommand command = new(sql, connection);
    await command.ExecuteNonQueryAsync().ConfigureAwait(false);
}

using System.Text.Json;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;

string adminConnection = Required("M3_POSTGRES_ADMIN_CONNECTION");
string runtimePassword = Required("M3_POSTGRES_RUNTIME_PASSWORD");
string activationKeyText = Required("M3_ACTIVATION_HMAC_BASE64");
string outputPath = Required("M3_PROVISIONING_OUTPUT");
byte[] activationKey;
try { activationKey = Convert.FromBase64String(activationKeyText); }
catch (FormatException) { throw new InvalidOperationException("M3 activation HMAC key must be Base64."); }
if (activationKey.Length < 32) throw new InvalidOperationException("M3 activation HMAC key must contain at least 256 bits.");

await EnsureRuntimeRoleAsync(adminConnection, runtimePassword).ConfigureAwait(false);
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

static string Required(string name)
{
    string? value = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);
    if (string.IsNullOrWhiteSpace(value) || value.Any(character => character is '\r' or '\n')) throw new InvalidOperationException($"{name} is required.");
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

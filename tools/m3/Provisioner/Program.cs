using System.Text.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;

string adminConnection = Required("M3_POSTGRES_ADMIN_CONNECTION");
string runtimePassword = Required("M3_POSTGRES_RUNTIME_PASSWORD");
string activationKeyText = Required("M3_ACTIVATION_HMAC_BASE64");
string outputPath = Required("M3_PROVISIONING_OUTPUT");
string? adminApiPassword = Optional("M5_POSTGRES_ADMIN_API_PASSWORD");
using X509Certificate2 vendorCertificate = X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(Required("M3_VENDOR_CLIENT_PFX_BASE64")), null, X509KeyStorageFlags.EphemeralKeySet);
using X509Certificate2 wrongVendorCertificate = X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(Required("M3_WRONG_VENDOR_CLIENT_PFX_BASE64")), null, X509KeyStorageFlags.EphemeralKeySet);
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
Guid environmentId = OptionalGuid("M3_PRIMARY_ENVIRONMENT_ID") ?? Guid.NewGuid();
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
Guid directInstallationId = Guid.NewGuid();
GatewayAuditEvent directInstallationAudit = new(
    Guid.NewGuid(),
    clock.UtcNow,
    tenantId,
    "administrator",
    "m3-provisioner",
    "installation.create",
    "installation",
    directInstallationId.ToString("D"),
    Guid.NewGuid(),
    "success",
    "BGW-INSTALLATION-CREATED",
    new Dictionary<string, string> { ["installationKind"] = InstallationKind.Direct.ToString() });
ProvisionedActivation directActivation = await provisioning.CreateAdminInstallationAsync(
    new InstallationRecord(
        directInstallationId,
        tenantId,
        applicationId,
        environmentId,
        InstallationStatus.Pending,
        null,
        clock.UtcNow,
        InstallationKind: InstallationKind.Direct,
        UpdatedAt: clock.UtcNow),
    "m3-provisioner",
    directInstallationAudit,
    CancellationToken.None).ConfigureAwait(false);
await registry.AddGrantAsync(new InstallationGrantRecord(Guid.NewGuid(), directInstallationId, tenantId, "sample-secure-service", "submit", true, clock.UtcNow), CancellationToken.None).ConfigureAwait(false);
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
await using AdminPostgresDataSource adminDataSource = new(adminConnection);
PostgresAdminSecurityStore adminSecurity = new(adminDataSource);
AdminPrincipalRecord provisionerEditor = await adminSecurity.EnsurePrincipalAsync(
    new("https://provisioner.synthetic.invalid", "m3-editor", "M3 synthetic editor", null),
    CancellationToken.None).ConfigureAwait(false);
AdminPrincipalRecord provisionerApprover = await adminSecurity.EnsurePrincipalAsync(
    new("https://provisioner.synthetic.invalid", "m3-approver", "M3 synthetic approver", null),
    CancellationToken.None).ConfigureAwait(false);
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
    directInstallationId,
    directActivationCodeId = directActivation.ActivationCodeId,
    directActivationCode = directActivation.ActivationCode,
    directExpiresAtUtc = directActivation.ExpiresAt,
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
    string editor = provisionerEditor.Id.ToString("D");
    ConnectorVersionRecord draft = await connectorStore.CreateDraftAsync(new(Guid.NewGuid(), Guid.Empty, connectorId, version, "1.0", ConnectorVersionState.Draft, validated.CanonicalJson, Convert.FromHexString(validated.ChecksumSha256), editor, clock.UtcNow, 1), CancellationToken.None).ConfigureAwait(false);
    ConnectorVersionRecord validatedRecord = await connectorStore.MarkValidatedAsync(draft.Id, draft.RowVersion, clock.UtcNow, CancellationToken.None).ConfigureAwait(false);
    Dictionary<string, Uri> endpoints = new(StringComparer.Ordinal)
    {
        ["vendor"] = new("https://vendor.m3.test:8443/"),
        ["loopback"] = new("https://127.0.0.1/"),
        ["private"] = new("https://172.29.44.7/"),
        ["metadata"] = new("https://169.254.169.254/")
    };
    Guid selectedEnvironment = securityOperations ? securityEnvironmentId : environmentId;
    string catalogPrefix = securityOperations ? "security-" : string.Empty;
    ProviderResourceCatalogRecord secretResource = await RegisterResourceAsync(selectedEnvironment, connectorId, catalogPrefix + "vendor-api-key", ProviderResourceType.Secret, "synthetic-vault://vault.m3.test/vendor-api-key", null, null).ConfigureAwait(false);
    ProviderResourceCatalogRecord certificateResource = await RegisterResourceAsync(selectedEnvironment, connectorId, catalogPrefix + "vendor-client-certificate", ProviderResourceType.ClientCertificate, "synthetic-vault://vault.m3.test/vendor-client-certificate", vendorCertificate, 1).ConfigureAwait(false);
    Dictionary<string, ProviderResourceBinding> secrets = new(StringComparer.Ordinal) { ["vendor-api-key"] = Binding(secretResource) };
    Dictionary<string, ProviderResourceBinding> certificates = new(StringComparer.Ordinal) { ["vendor-client-certificate"] = Binding(certificateResource) };
    if (securityOperations)
    {
        ProviderResourceCatalogRecord wrongCertificate = await RegisterResourceAsync(selectedEnvironment, connectorId, catalogPrefix + "vendor-wrong-client-certificate", ProviderResourceType.ClientCertificate, "synthetic-vault://vault.m3.test/vendor-wrong-client-certificate", wrongVendorCertificate, 1).ConfigureAwait(false);
        certificates.Add("vendor-wrong-client-certificate", Binding(wrongCertificate));
    }
    string checksum = ConnectorBindingDigests.Revision(draft.Id, selectedEnvironment, endpoints, secrets, certificates);
    _ = await connectorStore.PutBindingsAsync(new(Guid.NewGuid(), draft.ConnectorId, draft.Id, selectedEnvironment, endpoints, secrets, certificates, 0, checksum, ConnectorBindingState.Draft, clock.UtcNow, editor), null, Guid.NewGuid(), CancellationToken.None).ConfigureAwait(false);
    if (!securityOperations)
    {
        ProviderResourceCatalogRecord securitySecret = await RegisterResourceAsync(securityEnvironmentId, connectorId, "security-sample-vendor-api-key", ProviderResourceType.Secret, "synthetic-vault://vault.m3.test/vendor-api-key", null, null).ConfigureAwait(false);
        ProviderResourceCatalogRecord securityCertificate = await RegisterResourceAsync(securityEnvironmentId, connectorId, "security-sample-vendor-client-certificate", ProviderResourceType.ClientCertificate, "synthetic-vault://vault.m3.test/vendor-client-certificate", vendorCertificate, 1).ConfigureAwait(false);
        Dictionary<string, ProviderResourceBinding> securitySecrets = new(StringComparer.Ordinal) { ["vendor-api-key"] = Binding(securitySecret) };
        Dictionary<string, ProviderResourceBinding> securityCertificates = new(StringComparer.Ordinal) { ["vendor-client-certificate"] = Binding(securityCertificate) };
        string securityChecksum = ConnectorBindingDigests.Revision(draft.Id, securityEnvironmentId, endpoints, securitySecrets, securityCertificates);
        _ = await connectorStore.PutBindingsAsync(new(Guid.NewGuid(), draft.ConnectorId, draft.Id, securityEnvironmentId, endpoints, securitySecrets, securityCertificates, 0, securityChecksum, ConnectorBindingState.Draft, clock.UtcNow, editor), null, Guid.NewGuid(), CancellationToken.None).ConfigureAwait(false);
    }
    byte[] bindingDigest = await connectorStore.GetBindingBundleDigestAsync(draft.Id, CancellationToken.None).ConfigureAwait(false);
    ConnectorApprovalRecord approvalRequest = await adminSecurity.RequestApprovalAsync(draft, bindingDigest, provisionerEditor.Id, Guid.NewGuid(), clock.UtcNow, CancellationToken.None).ConfigureAwait(false);
    _ = await adminSecurity.ApproveAsync(approvalRequest.Id, draft.Id, draft.ChecksumSha256, bindingDigest, draft.CreatedBy, provisionerApprover.Id, null, Guid.NewGuid(), clock.UtcNow, CancellationToken.None).ConfigureAwait(false);
    _ = await connectorStore.PublishApprovedAsync(draft.Id, bindingDigest, validatedRecord.RowVersion, 0, provisionerApprover.Id.ToString("D"), Guid.NewGuid(), clock.UtcNow, CancellationToken.None).ConfigureAwait(false);
}

async Task<ProviderResourceCatalogRecord> RegisterResourceAsync(Guid environment, string connector, string resourceId, ProviderResourceType type, string providerReference, X509Certificate2? certificate, long? metadataRevision)
{
    CertificatePublicMetadata? metadata = certificate is null ? null : CertificateMetadata(certificate);
    return await connectorStore.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic-vault", "Synthetic vault", "synthetic-vault", resourceId, type, resourceId, environment, connector, "*", providerReference, ProviderResourceStatus.Active, null, 0, metadataRevision, metadata, string.Empty, clock.UtcNow), CancellationToken.None).ConfigureAwait(false);
}

static ProviderResourceBinding Binding(ProviderResourceCatalogRecord resource) => new(resource.ProviderId, resource.ProviderDisplayName, resource.ProviderType, resource.ResourceId, resource.ResourceType, resource.DisplayName, resource.EnvironmentId, resource.ConnectorScope, resource.OperationScope, resource.Version, resource.Revision, resource.PublicMetadataRevision, resource.CertificateMetadata, resource.ChecksumSha256);

static CertificatePublicMetadata CertificateMetadata(X509Certificate2 certificate)
{
    using RSA? rsa = certificate.GetRSAPublicKey(); using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
    return new(Convert.ToHexString(SHA256.HashData(certificate.RawData)), certificate.Subject, certificate.Issuer, certificate.NotBefore, certificate.NotAfter, rsa is not null ? "RSA" : "ECDSA", rsa?.KeySize ?? ecdsa?.KeySize ?? 0, certificate.SerialNumber);
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

static Guid? OptionalGuid(string name)
{
    string? value = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);
    if (value is null || value.Length == 0) return null;
    if (string.IsNullOrWhiteSpace(value) || value.Any(character => character is '\r' or '\n'))
        throw new InvalidOperationException($"{name} is invalid.");
    if (!Guid.TryParseExact(value, "D", out Guid parsed) || parsed == Guid.Empty)
        throw new InvalidOperationException($"{name} must be a non-empty canonical GUID.");
    return parsed;
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

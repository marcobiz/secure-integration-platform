using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.M5.DevelopmentSeed;

if (!DevelopmentSeedBoundary.IsEnabled(
        Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"),
        Environment.GetEnvironmentVariable("M5_ADMIN_DEV_SEED")))
{
    Console.Error.WriteLine("M5_ADMIN_DEV_SEED_DISABLED");
    return 2;
}

string adminConnection = Required("M5_ADMIN_DEV_POSTGRES_ADMIN_CONNECTION");
string runtimePassword = Required("M5_ADMIN_DEV_RUNTIME_PASSWORD");
string adminPassword = Required("M5_ADMIN_DEV_ADMIN_PASSWORD");

await EnsureLoginRoleAsync(adminConnection, "m5_admin_dev_runtime", "gateway_runtime", runtimePassword).ConfigureAwait(false);
await EnsureLoginRoleAsync(adminConnection, "m5_admin_dev_admin", "gateway_admin", adminPassword).ConfigureAwait(false);

await using NpgsqlDataSource dataSource = NpgsqlDataSource.Create(adminConnection);
await using AdminPostgresDataSource adminDataSource = new(adminConnection);
PostgresGatewayRegistry registry = new(dataSource);
PostgresAdminDirectoryStore directory = new(adminDataSource);
PostgresConnectorConfigurationStore connectorStore = new(dataSource);
SystemGatewayClock clock = new();
DateTimeOffset now = clock.UtcNow;

Guid tenantId = Guid.Parse("51000000-0000-0000-0000-000000000001");
Guid applicationId = Guid.Parse("51000000-0000-0000-0000-000000000002");
Guid environmentId = Guid.Parse("51000000-0000-0000-0000-000000000003");
Guid installationId = Guid.Parse("51000000-0000-0000-0000-000000000004");
Guid grantId = Guid.Parse("51000000-0000-0000-0000-000000000005");
Guid connectorVersionId = Guid.Parse("51000000-0000-0000-0000-000000000006");
Guid resourceId = Guid.Parse("51000000-0000-0000-0000-000000000007");
Guid bindingId = Guid.Parse("51000000-0000-0000-0000-000000000008");
Guid draftVersionId = Guid.Parse("51000000-0000-0000-0000-000000000009");
const string connectorSlug = "demo-orders";
const string connectorVersion = "1.0.0-dev";
const string draftVersion = "1.1.0-draft";

if (await directory.GetTenantAsync(tenantId, CancellationToken.None).ConfigureAwait(false) is null)
{
    await registry.AddTenantWithAuditAsync(
        new(tenantId, "demo", "Demo tenant", TenantStatus.Active, now),
        Audit(tenantId, "tenant.create", "tenant", tenantId), CancellationToken.None).ConfigureAwait(false);
}

if (await directory.GetApplicationAsync(applicationId, CancellationToken.None).ConfigureAwait(false) is null)
{
    await registry.AddApplicationWithAuditAsync(
        new(applicationId, "demo-legacy", "Demo legacy application", ApplicationStatus.Active, "1.0.0", null, now),
        Audit(null, "application.create", "application", applicationId), CancellationToken.None).ConfigureAwait(false);
}

AdminPage<GatewayEnvironmentRecord> environments = await directory.ListEnvironmentsAsync(0, 100, CancellationToken.None).ConfigureAwait(false);
if (!environments.Items.Any(value => value.Id == environmentId))
    await registry.AddEnvironmentAsync(new(environmentId, "development", "Local development", false), CancellationToken.None).ConfigureAwait(false);

if (await directory.GetInstallationAsync(tenantId, installationId, CancellationToken.None).ConfigureAwait(false) is null)
{
    await registry.AddInstallationAsync(new(installationId, tenantId, applicationId, environmentId, InstallationStatus.Pending, null, now), CancellationToken.None).ConfigureAwait(false);
    await registry.AppendAuditAsync(Audit(tenantId, "installation.create", "installation", installationId), CancellationToken.None).ConfigureAwait(false);
}

ConnectorVersionRecord? draft = await connectorStore.GetVersionAsync(connectorSlug, connectorVersion, CancellationToken.None).ConfigureAwait(false);
if (draft is null)
{
    JsonElement definition = JsonSerializer.SerializeToElement(new
    {
        schemaVersion = "1.0",
        connectorId = connectorSlug,
        version = connectorVersion,
        displayName = "Demo order connector",
        bindings = new
        {
            endpoints = new[] { new { name = "demo-vendor" } },
            secrets = new[] { new { name = "demo-api-key", kind = "opaque" } }
        },
        operations = new[]
        {
            new
            {
                operationId = "submit",
                endpointBinding = "demo-vendor",
                method = "POST",
                path = "/orders",
                request = new { contentType = "application/json", maximumBytes = 1048576 },
                response = new { maximumBytes = 1048576 },
                authentication = new { kind = "apiKey", secretBinding = "demo-api-key", headerName = "X-Demo-Api-Key" },
                timeoutMs = 30000,
                redirectPolicy = "deny",
                allowedClientHeaders = Array.Empty<string>(),
                idempotent = false,
                maximumRetries = 0
            }
        }
    });
    ValidatedConnectorDefinition validated = new ConnectorDefinitionValidator().ValidateRequired(definition);
    draft = await connectorStore.CreateDraftWithAuditAsync(
        new(connectorVersionId, Guid.Empty, connectorSlug, connectorVersion, "1.0", ConnectorVersionState.Draft,
            validated.CanonicalJson, Convert.FromHexString(validated.ChecksumSha256), "development-seed", now, 1),
        Audit(null, "connector.import", "connector-version", connectorVersionId), CancellationToken.None).ConfigureAwait(false);
}
if (draft.State == ConnectorVersionState.Draft)
{
    draft = await connectorStore.MarkValidatedWithAuditAsync(draft.Id, draft.RowVersion, now,
        Audit(null, "connector.validate", "connector-version", draft.Id), CancellationToken.None).ConfigureAwait(false);
}

if (await connectorStore.GetVersionAsync(connectorSlug, draftVersion, CancellationToken.None).ConfigureAwait(false) is null)
{
    JsonElement draftDefinition = JsonSerializer.SerializeToElement(new
    {
        schemaVersion = "1.0",
        connectorId = connectorSlug,
        version = draftVersion,
        displayName = "Demo order connector - work in progress",
        bindings = new { endpoints = new[] { new { name = "demo-vendor" } }, secrets = Array.Empty<object>() },
        operations = new[]
        {
            new
            {
                operationId = "preview",
                endpointBinding = "demo-vendor",
                method = "GET",
                path = "/orders/preview",
                request = new { contentType = "application/json", maximumBytes = 1048576 },
                response = new { maximumBytes = 1048576 },
                authentication = new { kind = "none" },
                timeoutMs = 30000,
                redirectPolicy = "deny",
                allowedClientHeaders = Array.Empty<string>(),
                idempotent = true,
                maximumRetries = 0
            }
        }
    });
    ValidatedConnectorDefinition validatedDraft = new ConnectorDefinitionValidator().ValidateRequired(draftDefinition);
    _ = await connectorStore.CreateDraftWithAuditAsync(
        new(draftVersionId, Guid.Empty, connectorSlug, draftVersion, "1.0", ConnectorVersionState.Draft,
            validatedDraft.CanonicalJson, Convert.FromHexString(validatedDraft.ChecksumSha256), "development-seed", now, 1),
        Audit(null, "connector.import", "connector-version", draftVersionId), CancellationToken.None).ConfigureAwait(false);
}

AdminPage<ProviderResourceCatalogRecord> resources = await connectorStore.ListProviderResourcesPageAsync(0, 100, environmentId, ProviderResourceType.Secret, CancellationToken.None).ConfigureAwait(false);
ProviderResourceCatalogRecord? resource = resources.Items.SingleOrDefault(value => value.Id == resourceId);
resource ??= await connectorStore.RegisterProviderResourceAsync(new(
    resourceId, "development-synthetic", "Development synthetic provider", "InMemory", "demo-api-key",
    ProviderResourceType.Secret, "Demo API key (logical only)", environmentId, connectorSlug, "submit",
    "development://logical/demo-api-key", ProviderResourceStatus.Active, "dev-1", 0, null, null, string.Empty, now),
    CancellationToken.None).ConfigureAwait(false);

AdminPage<ConnectorBindingSet> bindings = await connectorStore.ListBindingsPageAsync(draft.Id, 0, 100, environmentId, CancellationToken.None).ConfigureAwait(false);
if (!bindings.Items.Any())
{
    Dictionary<string, Uri> endpoints = new(StringComparer.Ordinal) { ["demo-vendor"] = new("https://api.example.invalid/") };
    Dictionary<string, ProviderResourceBinding> secrets = new(StringComparer.Ordinal)
    {
        ["demo-api-key"] = new(resource.ProviderId, resource.ProviderDisplayName, resource.ProviderType, resource.ResourceId,
            resource.ResourceType, resource.DisplayName, resource.EnvironmentId, resource.ConnectorScope, resource.OperationScope,
            resource.Version, resource.Revision, resource.PublicMetadataRevision, resource.CertificateMetadata, resource.ChecksumSha256)
    };
    string checksum = ConnectorBindingDigests.Revision(draft.Id, environmentId, endpoints, secrets, new Dictionary<string, ProviderResourceBinding>());
    _ = await connectorStore.PutBindingsAsync(new(bindingId, draft.ConnectorId, draft.Id, environmentId, endpoints, secrets,
        new Dictionary<string, ProviderResourceBinding>(), 0, checksum, ConnectorBindingState.Draft, now, "development-seed"),
        null, Guid.NewGuid(), CancellationToken.None).ConfigureAwait(false);
}

AdminPage<InstallationGrantRecord> grants = await directory.ListGrantsAsync(tenantId, 0, 100, CancellationToken.None).ConfigureAwait(false);
if (!grants.Items.Any(value => value.Id == grantId))
{
    await registry.AddGrantWithAuditAsync(new(grantId, installationId, tenantId, connectorSlug, "submit", true, now),
        Audit(tenantId, "grant.create", "grant", grantId), CancellationToken.None).ConfigureAwait(false);
}

Console.WriteLine(JsonSerializer.Serialize(new
{
    status = "seeded",
    tenantId,
    applicationId,
    environmentId,
    installationId,
    connectorId = connectorSlug,
    connectorVersion,
    connectorState = draft.State.ToString(),
    draftVersion,
    providerResource = "demo-api-key"
}));
return 0;

GatewayAuditEvent Audit(Guid? tenant, string action, string targetType, Guid targetId) => new(
    Guid.NewGuid(), now, tenant, "DevelopmentSeed", "local-operator", action, targetType, targetId.ToString("D"),
    Guid.NewGuid(), "Success", "DEVELOPMENT-SEED", new Dictionary<string, string> { ["source"] = "m5-admin-local-dev" });

static string Required(string name)
{
    string? value = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);
    if (string.IsNullOrWhiteSpace(value) || value.Any(character => character is '\r' or '\n')) throw new InvalidOperationException($"{name} is required.");
    return value;
}

static async Task EnsureLoginRoleAsync(string connectionString, string roleName, string membership, string password)
{
    await using NpgsqlConnection connection = new(connectionString);
    await connection.OpenAsync().ConfigureAwait(false);
    await using (NpgsqlCommand ensure = new($"DO $block$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{roleName}') THEN CREATE ROLE {roleName} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT; END IF; END $block$;", connection))
        await ensure.ExecuteNonQueryAsync().ConfigureAwait(false);
    await using NpgsqlCommand quote = new("SELECT quote_literal($1)", connection);
    quote.Parameters.AddWithValue(password);
    string quotedPassword = (string)(await quote.ExecuteScalarAsync().ConfigureAwait(false) ?? throw new InvalidOperationException("Cannot quote development credential."));
    await using NpgsqlCommand configure = new($"ALTER ROLE {roleName} INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD {quotedPassword}; GRANT {membership} TO {roleName};", connection);
    await configure.ExecuteNonQueryAsync().ConfigureAwait(false);
}

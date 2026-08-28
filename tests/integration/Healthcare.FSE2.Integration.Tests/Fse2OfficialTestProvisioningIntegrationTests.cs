using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Gateway.Integration.Tests;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Integration.Tests;

public sealed class Fse2OfficialTestProvisioningIntegrationTests
{
    private const string RequirePostgresGateVariable = "REQUIRE_FSE2_POSTGRES_GATE";

    [Fact]
    public async Task FSE2_OFFICIALTEST_supported_provisioner_configures_proposes_approves_and_reads_back_exact_configuration()
    {
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;
        SystemGatewayClock clock = new();
        InMemoryGatewayRegistry registry = new(clock);
        InMemoryConnectorConfigurationStore store = new(registry);
        InMemoryAdminSecurityStore security = new(registry);
        ConnectorDefinitionValidator validator = new();
        PublishedConnectorCatalog catalog = new(store, validator, clock, TimeSpan.FromMinutes(5));
        ConnectorAdministrationService administration = new(store, validator, catalog, registry, clock, new FourEyesConnectorApprovalPolicy(security));
        ConnectorApprovalService approvals = new(security, store, clock);
        AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new(
            "https://synthetic-officialtest.invalid", "editor", "Synthetic Editor", null), cancellationToken);
        AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new(
            "https://synthetic-officialtest.invalid", "approver", "Synthetic Approver", null), cancellationToken);
        await security.AssignRoleAsync(editor.Id, AdminRole.ConnectorEditor, null, editor.Id, Guid.NewGuid(), clock.UtcNow, cancellationToken);
        await security.AssignRoleAsync(editor.Id, AdminRole.ConnectorApprover, null, editor.Id, Guid.NewGuid(), clock.UtcNow, cancellationToken);
        await security.AssignRoleAsync(approver.Id, AdminRole.ConnectorApprover, null, approver.Id, Guid.NewGuid(), clock.UtcNow, cancellationToken);
        AdminAccessContext editorContext = new(editor, await security.GetAssignmentsAsync(editor.Id, cancellationToken));
        AdminAccessContext approverContext = new(approver, await security.GetAssignmentsAsync(approver.Id, cancellationToken));

        Guid environmentId = Guid.NewGuid();
        Fse2OfficialTestProviderReference a1Reference = new("synthetic-provider", "officialtest-a1", "1", 1, 3);
        Fse2OfficialTestProviderReference s1Reference = new("synthetic-provider", "officialtest-s1", "1", 1, 5);
        ProviderResourceCatalogRecord a1 = await RegisterAsync(store, environmentId, a1Reference, "A1 Synthetic Client", 'E', cancellationToken);
        ProviderResourceCatalogRecord s1 = await RegisterAsync(store, environmentId, s1Reference, "S1 Synthetic Signing", 'F', cancellationToken);
        Fse2OfficialTestOperationalPlan plan = Plan(environmentId, a1Reference, s1Reference);
        Fse2OfficialTestCompiledConfiguration compiled = Fse2OfficialTestOperationalization.Compile(
            plan,
            new(a1Reference, new string('A', 64), "A1 Synthetic Client", a1.ChecksumSha256),
            new(s1Reference, new string('B', 64), "S1 Synthetic Signing", s1.ChecksumSha256));

        using JsonDocument definition = JsonDocument.Parse(compiled.CanonicalDefinition);
        ConnectorVersionResource imported = await administration.ImportAsync(
            definition.RootElement, compiled.CanonicalDefinitionSha256, editor.Id.ToString("D"), Guid.NewGuid(), cancellationToken);
        ConnectorVersionResource validated = await administration.ValidateStoredAsync(
            imported.ConnectorId, imported.Version, imported.RowVersion, editor.Id.ToString("D"), Guid.NewGuid(), cancellationToken);
        long bindingRevision = await administration.PutBindingsAsync(
            imported.ConnectorId, compiled.BindingRequest, editor.Id.ToString("D"), Guid.NewGuid(), cancellationToken);
        Assert.Equal(1, bindingRevision);

        ConnectorVersionRecord stored = await store.GetVersionAsync(imported.ConnectorId, imported.Version, cancellationToken)
            ?? throw new InvalidOperationException("Synthetic OfficialTest version missing.");
        Assert.Equal(compiled.CanonicalDefinition, stored.CanonicalJson);
        ConnectorBindingSet binding = Assert.Single((await store.ListBindingsPageAsync(
            stored.Id, 0, 10, environmentId, cancellationToken)).Items);
        Assert.Equal(Fse2OfficialTestCanonicalDefinition.OfficialTestEndpoint,
            binding.Endpoints[Fse2OfficialTestCanonicalDefinition.EndpointBinding].AbsoluteUri);
        Assert.Empty(binding.SecretResources);
        Assert.Equal(a1.ChecksumSha256, binding.CertificateResources[Fse2OfficialTestCanonicalDefinition.MutualTlsBinding].CatalogChecksumSha256);
        Assert.Equal(s1.ChecksumSha256, binding.CertificateResources[Fse2OfficialTestCanonicalDefinition.SigningBinding].CatalogChecksumSha256);

        ApprovalReviewResult review = await approvals.ReviewAsync(imported.ConnectorId, imported.Version, editorContext, cancellationToken);
        ApprovalOperationReview reviewedOperation = Assert.Single(review.Artifact.Operations);
        Assert.Equal(Fse2OfficialTestCanonicalDefinition.OperationId, reviewedOperation.OperationId);
        Assert.Equal([Fse2OfficialTestCanonicalDefinition.MutualTlsBinding, Fse2OfficialTestCanonicalDefinition.SigningBinding],
            reviewedOperation.CertificateBindings.Select(value => value.LogicalBindingId).Order(StringComparer.Ordinal));
        ConnectorApprovalRecord request = await approvals.RequestAsync(imported.ConnectorId, imported.Version, editorContext, Guid.NewGuid(), cancellationToken);

        GatewayException selfApproval = await Assert.ThrowsAsync<GatewayException>(() => approvals.ApproveAsync(
            imported.ConnectorId, imported.Version, new(request.Id, review.DigestSha256), editorContext, Guid.NewGuid(), cancellationToken));
        Assert.Equal("BGW-ADMIN-FOUR-EYES", selfApproval.Code);
        GatewayException wrongChecksum = await Assert.ThrowsAsync<GatewayException>(() => approvals.ApproveAsync(
            imported.ConnectorId, imported.Version, new(request.Id, new string('0', 64)), approverContext, Guid.NewGuid(), cancellationToken));
        Assert.Equal("BGW-ADMIN-APPROVAL-STALE", wrongChecksum.Code);
        long driftedBindingRevision = await administration.PutBindingsAsync(
            imported.ConnectorId, compiled.BindingRequest with { ExpectedRevision = bindingRevision }, editor.Id.ToString("D"), Guid.NewGuid(), cancellationToken);
        Assert.Equal(2, driftedBindingRevision);
        GatewayException staleBindingDigest = await Assert.ThrowsAsync<GatewayException>(() => approvals.ApproveAsync(
            imported.ConnectorId, imported.Version, new(request.Id, review.DigestSha256), approverContext, Guid.NewGuid(), cancellationToken));
        Assert.Equal("BGW-ADMIN-APPROVAL-STALE", staleBindingDigest.Code);
        ApprovalReviewResult currentReview = await approvals.ReviewAsync(imported.ConnectorId, imported.Version, editorContext, cancellationToken);
        ConnectorApprovalRecord currentRequest = await approvals.RequestAsync(imported.ConnectorId, imported.Version, editorContext, Guid.NewGuid(), cancellationToken);
        ConnectorApprovalRecord approved = await approvals.ApproveAsync(
            imported.ConnectorId, imported.Version, new(currentRequest.Id, currentReview.DigestSha256), approverContext, Guid.NewGuid(), cancellationToken);
        Assert.Equal(ConnectorApprovalStatus.Approved, approved.Status);
        Assert.Equal(ConnectorVersionState.Validated, (await store.GetVersionAsync(imported.ConnectorId, imported.Version, cancellationToken))!.State);
        Assert.Equal(ConnectorBindingState.Draft, (await store.ListBindingsPageAsync(
            stored.Id, 0, 10, environmentId, cancellationToken)).Items.OrderByDescending(value => value.Revision).First().State);
    }

    [Fact]
    public async Task FSE2_OFFICIALTEST_PostgreSQL18_four_eyes_publication_readback_immutability_and_second_migration_noop()
    {
        string adminConnection = RequiredPostgresOrSkip("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        _ = RequiredPostgresOrSkip("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        await HostedPostgresTestSupport.ApplyMigrationAsync();
        await using AdminPostgresDataSource adminPool = new(adminConnection);
        PostgresConnectorConfigurationStore store = new(adminPool.Value);
        PostgresGatewayRegistry registry = new(adminPool.Value);
        PostgresAdminSecurityStore security = new(adminPool);
        SystemGatewayClock clock = new();
        ConnectorDefinitionValidator validator = new();
        PublishedConnectorCatalog catalog = new(store, validator, clock, TimeSpan.FromMinutes(5));
        ConnectorAdministrationService administration = new(store, validator, catalog, registry, clock, new FourEyesConnectorApprovalPolicy(security));
        ConnectorApprovalService approvals = new(security, store, clock);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        AdminPrincipalRecord editor = await security.EnsurePrincipalAsync(new(
            "https://synthetic-officialtest.invalid", "postgres-editor", "Synthetic PostgreSQL Editor", null), cancellationToken);
        AdminPrincipalRecord approver = await security.EnsurePrincipalAsync(new(
            "https://synthetic-officialtest.invalid", "postgres-approver", "Synthetic PostgreSQL Approver", null), cancellationToken);
        await security.AssignRoleAsync(editor.Id, AdminRole.ConnectorEditor, null, editor.Id, Guid.NewGuid(), clock.UtcNow, cancellationToken);
        await security.AssignRoleAsync(editor.Id, AdminRole.ConnectorApprover, null, editor.Id, Guid.NewGuid(), clock.UtcNow, cancellationToken);
        await security.AssignRoleAsync(approver.Id, AdminRole.ConnectorApprover, null, approver.Id, Guid.NewGuid(), clock.UtcNow, cancellationToken);
        AdminAccessContext editorContext = new(editor, await security.GetAssignmentsAsync(editor.Id, cancellationToken));
        AdminAccessContext approverContext = new(approver, await security.GetAssignmentsAsync(approver.Id, cancellationToken));

        Guid environmentId = Guid.NewGuid();
        await registry.AddEnvironmentAsync(new(environmentId, "fse2-officialtest", "FSE2 OfficialTest", false), cancellationToken);
        Fse2OfficialTestProviderReference a1Reference = new("synthetic-provider", "officialtest-a1", "1", 1, 3);
        Fse2OfficialTestProviderReference s1Reference = new("synthetic-provider", "officialtest-s1", "1", 1, 5);
        ProviderResourceCatalogRecord a1 = await RegisterAsync(store, environmentId, a1Reference, "A1 Synthetic Client", 'E', cancellationToken);
        ProviderResourceCatalogRecord s1 = await RegisterAsync(store, environmentId, s1Reference, "S1 Synthetic Signing", 'F', cancellationToken);
        Fse2OfficialTestOperationalPlan plan = Plan(environmentId, a1Reference, s1Reference);
        Fse2OfficialTestCompiledConfiguration compiled = Fse2OfficialTestOperationalization.Compile(
            plan,
            new(a1Reference, new string('A', 64), "A1 Synthetic Client", a1.ChecksumSha256),
            new(s1Reference, new string('B', 64), "S1 Synthetic Signing", s1.ChecksumSha256));

        using JsonDocument definition = JsonDocument.Parse(compiled.CanonicalDefinition);
        ConnectorVersionResource imported = await administration.ImportAsync(
            definition.RootElement, compiled.CanonicalDefinitionSha256, editor.Id.ToString("D"), Guid.NewGuid(), cancellationToken);
        ConnectorVersionResource validated = await administration.ValidateStoredAsync(
            imported.ConnectorId, imported.Version, imported.RowVersion, editor.Id.ToString("D"), Guid.NewGuid(), cancellationToken);
        long bindingRevision = await administration.PutBindingsAsync(
            imported.ConnectorId, compiled.BindingRequest, editor.Id.ToString("D"), Guid.NewGuid(), cancellationToken);
        ApprovalReviewResult review = await approvals.ReviewAsync(imported.ConnectorId, imported.Version, editorContext, cancellationToken);
        ConnectorApprovalRecord request = await approvals.RequestAsync(imported.ConnectorId, imported.Version, editorContext, Guid.NewGuid(), cancellationToken);
        GatewayException selfApproval = await Assert.ThrowsAsync<GatewayException>(() => approvals.ApproveAsync(
            imported.ConnectorId, imported.Version, new(request.Id, review.DigestSha256), editorContext, Guid.NewGuid(), cancellationToken));
        Assert.Equal("BGW-ADMIN-FOUR-EYES", selfApproval.Code);
        _ = await approvals.ApproveAsync(
            imported.ConnectorId, imported.Version, new(request.Id, review.DigestSha256), approverContext, Guid.NewGuid(), cancellationToken);

        ConnectorVersionResource published = await administration.PublishAsync(
            imported.ConnectorId, imported.Version, validated.RowVersion, 0, approver.Id.ToString("D"), Guid.NewGuid(), cancellationToken);
        Assert.Equal(ConnectorVersionState.Published, published.State);
        PublishedConnectorSnapshot snapshot = await store.GetPublishedSnapshotAsync(imported.ConnectorId, environmentId, null, cancellationToken)
            ?? throw new InvalidOperationException("Synthetic OfficialTest Published snapshot missing.");
        Assert.Equal(compiled.CanonicalDefinitionSha256, Convert.ToHexString(snapshot.Version.ChecksumSha256));
        Assert.Equal(ConnectorBindingState.Active, snapshot.Bindings.State);
        Assert.Equal(Fse2OfficialTestCanonicalDefinition.OperationId,
            Assert.Single(ConnectorOperationBindings.All(snapshot.Version.CanonicalJson)).OperationId);

        GatewayException immutable = await Assert.ThrowsAsync<GatewayException>(() => administration.PutBindingsAsync(
            imported.ConnectorId, compiled.BindingRequest with { ExpectedRevision = bindingRevision }, approver.Id.ToString("D"), Guid.NewGuid(), cancellationToken));
        Assert.Equal("BGW-CONNECTOR-BINDING-REQUIRES-VALIDATED-VERSION", immutable.Code);
        GatewayException definitionImmutable = await Assert.ThrowsAsync<GatewayException>(() => administration.ImportAsync(
            definition.RootElement, compiled.CanonicalDefinitionSha256, approver.Id.ToString("D"), Guid.NewGuid(), cancellationToken));
        Assert.Equal("BGW-CONNECTOR-VERSION-DUPLICATE", definitionImmutable.Code);
        await HostedPostgresTestSupport.ApplyMigrationAsync();
    }

    private static string RequiredPostgresOrSkip(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        if (!string.IsNullOrWhiteSpace(value)) return value;
        if (string.Equals(Environment.GetEnvironmentVariable(RequirePostgresGateVariable), "1", StringComparison.Ordinal))
            throw new InvalidOperationException($"FSE2_OFFICIALTEST_POSTGRES_GATE_CONFIGURATION_MISSING:{name}");
        Assert.Skip($"{name} is not configured; the dedicated PostgreSQL gate must provide it.");
        throw new InvalidOperationException("FSE2_OFFICIALTEST_POSTGRES_SKIP_DID_NOT_TERMINATE");
    }

    private static async Task<ProviderResourceCatalogRecord> RegisterAsync(
        IConnectorConfigurationStore store,
        Guid environmentId,
        Fse2OfficialTestProviderReference reference,
        string commonName,
        char fingerprint,
        CancellationToken cancellationToken) =>
        await store.RegisterProviderResourceAsync(new(
            Guid.NewGuid(), reference.ProviderId, "Synthetic provider", "synthetic", reference.ResourceId,
            ProviderResourceType.ClientCertificate, commonName, environmentId,
            Fse2OfficialTestCanonicalDefinition.ConnectorId, Fse2OfficialTestCanonicalDefinition.OperationId,
            $"synthetic://{reference.ResourceId}", ProviderResourceStatus.Active, reference.Version, 0,
            reference.PublicMetadataRevision,
            new(new string(fingerprint, 64), $"CN={commonName}", "CN=Synthetic Root",
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), "RSA", 2048, reference.Version!),
            string.Empty, DateTimeOffset.UtcNow), cancellationToken);

    private static Fse2OfficialTestOperationalPlan Plan(
        Guid environmentId,
        Fse2OfficialTestProviderReference a1,
        Fse2OfficialTestProviderReference s1)
    {
        string json = $$"""
            {
              "schemaVersion":"1.0",
              "environmentId":"{{environmentId:D}}",
              "officialTestEndpoint":"https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1/",
              "organization":{"identifier":"12345678903","assigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2","description":"Synthetic Organization","domainId":"synthetic-organization"},
              "locality":{"name":"Synthetic Locality","assigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2","code":"SYNTHETIC"},
              "a1":{"providerId":"{{a1.ProviderId}}","resourceId":"{{a1.ResourceId}}","version":"{{a1.Version}}","catalogRevision":{{a1.CatalogRevision}},"publicMetadataRevision":{{a1.PublicMetadataRevision}}},
              "s1":{"providerId":"{{s1.ProviderId}}","resourceId":"{{s1.ResourceId}}","version":"{{s1.Version}}","catalogRevision":{{s1.CatalogRevision}},"publicMetadataRevision":{{s1.PublicMetadataRevision}}},
              "expectedBindingRevision":null
            }
            """;
        return Fse2OfficialTestOperationalization.ParsePlan(Encoding.UTF8.GetBytes(json));
    }
}

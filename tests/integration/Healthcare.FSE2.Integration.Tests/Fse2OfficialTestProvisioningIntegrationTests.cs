using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
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
        ProviderResourceReference a1GatewayReference = GatewayReference(a1Reference);
        Assert.Equal(a1.Id, Assert.Single(await store.FindExactProviderResourcesAsync(environmentId, a1GatewayReference, a1Reference.CatalogRevision, cancellationToken)).Id);
        Assert.Empty(await store.FindExactProviderResourcesAsync(Guid.NewGuid(), a1GatewayReference, a1Reference.CatalogRevision, cancellationToken));
        Assert.Empty(await store.FindExactProviderResourcesAsync(environmentId, a1GatewayReference with { ResourceType = ProviderResourceType.Secret }, a1Reference.CatalogRevision, cancellationToken));
        Assert.Empty(await store.FindExactProviderResourcesAsync(environmentId, a1GatewayReference with { Version = "wrong" }, a1Reference.CatalogRevision, cancellationToken));
        Assert.Empty(await store.FindExactProviderResourcesAsync(environmentId, a1GatewayReference, a1Reference.CatalogRevision + 1, cancellationToken));
        Assert.Empty(await store.FindExactProviderResourcesAsync(environmentId, a1GatewayReference with { PublicMetadataRevision = a1Reference.PublicMetadataRevision + 1 }, a1Reference.CatalogRevision, cancellationToken));
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
    public async Task FSE2_OFFICIALTEST_PostgreSQL18_D1_approval_is_invalidated_before_D2_distinct_approver_publication_and_replay_is_denied()
    {
        string adminConnection = RequiredPostgresOrSkip("GATEWAY_POSTGRES_ADMIN_CONNECTION");
        string migrationConnection = RequiredPostgresOrSkip("GATEWAY_POSTGRES_MIGRATION_CONNECTION");
        await HostedPostgresTestSupport.ApplyMigrationAsync();
        await using AdminPostgresDataSource adminPool = new(adminConnection);
        await using NpgsqlDataSource integrityPool = NpgsqlDataSource.Create(migrationConnection);
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
        AdminPrincipalRecord approverA = await security.EnsurePrincipalAsync(new(
            "https://synthetic-officialtest.invalid", "postgres-approver-a", "Synthetic PostgreSQL Approver A", null), cancellationToken);
        AdminPrincipalRecord approverB = await security.EnsurePrincipalAsync(new(
            "https://synthetic-officialtest.invalid", "postgres-approver-b", "Synthetic PostgreSQL Approver B", null), cancellationToken);
        await security.AssignRoleAsync(editor.Id, AdminRole.ConnectorEditor, null, editor.Id, Guid.NewGuid(), clock.UtcNow, cancellationToken);
        await security.AssignRoleAsync(editor.Id, AdminRole.ConnectorApprover, null, editor.Id, Guid.NewGuid(), clock.UtcNow, cancellationToken);
        await security.AssignRoleAsync(approverA.Id, AdminRole.ConnectorApprover, null, approverA.Id, Guid.NewGuid(), clock.UtcNow, cancellationToken);
        await security.AssignRoleAsync(approverB.Id, AdminRole.ConnectorApprover, null, approverB.Id, Guid.NewGuid(), clock.UtcNow, cancellationToken);
        AdminAccessContext editorContext = new(editor, await security.GetAssignmentsAsync(editor.Id, cancellationToken));
        AdminAccessContext approverAContext = new(approverA, await security.GetAssignmentsAsync(approverA.Id, cancellationToken));
        AdminAccessContext approverBContext = new(approverB, await security.GetAssignmentsAsync(approverB.Id, cancellationToken));

        Guid environmentId = Guid.NewGuid();
        await registry.AddEnvironmentAsync(new(environmentId, "fse2-officialtest", "FSE2 OfficialTest", false), cancellationToken);
        Fse2OfficialTestProviderReference a1Reference = new("synthetic-provider", "officialtest-a1", "1", 1, 3);
        Fse2OfficialTestProviderReference s1Reference = new("synthetic-provider", "officialtest-s1", "1", 1, 5);
        ProviderResourceCatalogRecord a1 = await RegisterAsync(store, environmentId, a1Reference, "A1 Synthetic Client", 'E', cancellationToken);
        ProviderResourceCatalogRecord s1 = await RegisterAsync(store, environmentId, s1Reference, "S1 Synthetic Signing", 'F', cancellationToken);
        ProviderResourceReference a1GatewayReference = GatewayReference(a1Reference);
        Assert.Equal(a1.Id, Assert.Single(await store.FindExactProviderResourcesAsync(environmentId, a1GatewayReference, a1Reference.CatalogRevision, cancellationToken)).Id);
        Assert.Empty(await store.FindExactProviderResourcesAsync(Guid.NewGuid(), a1GatewayReference, a1Reference.CatalogRevision, cancellationToken));
        Assert.Empty(await store.FindExactProviderResourcesAsync(environmentId, a1GatewayReference with { ResourceType = ProviderResourceType.Secret }, a1Reference.CatalogRevision, cancellationToken));
        Assert.Empty(await store.FindExactProviderResourcesAsync(environmentId, a1GatewayReference with { Version = "wrong" }, a1Reference.CatalogRevision, cancellationToken));
        Assert.Empty(await store.FindExactProviderResourcesAsync(environmentId, a1GatewayReference, a1Reference.CatalogRevision + 1, cancellationToken));
        Assert.Empty(await store.FindExactProviderResourcesAsync(environmentId, a1GatewayReference with { PublicMetadataRevision = a1Reference.PublicMetadataRevision + 1 }, a1Reference.CatalogRevision, cancellationToken));
        await AssertCatalogIntegrityTamperDeniedAsync(integrityPool, store, a1, a1GatewayReference, null, null, cancellationToken);
        await AssertCatalogIntegrityTamperDeniedAsync(integrityPool, store, a1, a1GatewayReference, "SubjectPublicKeyInfoSha256", new string('C', 64), cancellationToken);
        await AssertCatalogIntegrityTamperDeniedAsync(integrityPool, store, a1, a1GatewayReference, "SubjectCommonName", "Wrong Synthetic Common Name", cancellationToken);
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
        ConnectorApprovalRecord approvedD1 = await approvals.ApproveAsync(
            imported.ConnectorId, imported.Version, new(request.Id, review.DigestSha256), approverAContext, Guid.NewGuid(), cancellationToken);
        Assert.True(Fse2OfficialTestOperationalization.IsCurrentPublisher(
            approverA.Id, compiled.CanonicalDefinitionSha256, [ApprovalAuthority(approvedD1)]));

        Fse2OfficialTestProviderReference s1D2Reference = s1Reference with { CatalogRevision = 2 };
        ProviderResourceCatalogRecord s1D2 = await RegisterAsync(
            store, environmentId, s1D2Reference, "S1 Synthetic Signing", 'F', cancellationToken);
        Assert.Equal(2, s1D2.Revision);
        Assert.Empty(await store.FindExactProviderResourcesAsync(environmentId, GatewayReference(s1Reference), s1Reference.CatalogRevision, cancellationToken));
        Assert.Equal(s1D2.Id, Assert.Single(await store.FindExactProviderResourcesAsync(environmentId, GatewayReference(s1D2Reference), s1D2Reference.CatalogRevision, cancellationToken)).Id);
        GatewayException providerDrift = await Assert.ThrowsAsync<GatewayException>(() => administration.PublishAsync(
            imported.ConnectorId, imported.Version, validated.RowVersion, 0, approverA.Id.ToString("D"), Guid.NewGuid(), cancellationToken));
        Assert.Equal("BGW-PROVIDER-RESOURCE-REVISION-STALE", providerDrift.Code);
        Assert.Equal(ConnectorVersionState.Validated, (await store.GetVersionAsync(imported.ConnectorId, imported.Version, cancellationToken))!.State);
        Fse2OfficialTestOperationalPlan d2Plan = plan with { S1 = s1D2Reference };
        Fse2OfficialTestCompiledConfiguration compiledD2 = Fse2OfficialTestOperationalization.Compile(
            d2Plan,
            new(a1Reference, new string('A', 64), "A1 Synthetic Client", a1.ChecksumSha256),
            new(s1D2Reference, new string('B', 64), "S1 Synthetic Signing", s1D2.ChecksumSha256));
        Assert.Equal(compiled.CanonicalDefinitionSha256, compiledD2.CanonicalDefinitionSha256);
        Assert.NotEqual(compiled.BindingConfigurationDigestSha256, compiledD2.BindingConfigurationDigestSha256);

        long d2Revision = await administration.PutBindingsAsync(
            imported.ConnectorId,
            compiledD2.BindingRequest with { ExpectedRevision = bindingRevision },
            editor.Id.ToString("D"),
            Guid.NewGuid(),
            cancellationToken);
        Assert.Equal(2, d2Revision);
        ConnectorApprovalRecord[] afterD2 = (await security.ListApprovalsAsync(
            approvedD1.ConnectorVersionId, cancellationToken)).ToArray();
        Assert.Equal(ConnectorApprovalStatus.Invalidated, Assert.Single(afterD2, value => value.Id == approvedD1.Id).Status);
        Assert.False(Fse2OfficialTestOperationalization.IsCurrentPublisher(
            approverA.Id, compiled.CanonicalDefinitionSha256, afterD2.Select(ApprovalAuthority)));

        ApprovalReviewResult d2Review = await approvals.ReviewAsync(imported.ConnectorId, imported.Version, editorContext, cancellationToken);
        ConnectorApprovalRecord d2Request = await approvals.RequestAsync(
            imported.ConnectorId, imported.Version, editorContext, Guid.NewGuid(), cancellationToken);
        ConnectorApprovalRecord approvedD2 = await approvals.ApproveAsync(
            imported.ConnectorId, imported.Version, new(d2Request.Id, d2Review.DigestSha256), approverBContext, Guid.NewGuid(), cancellationToken);
        ConnectorApprovalRecord[] currentApprovals = (await security.ListApprovalsAsync(
            approvedD2.ConnectorVersionId, cancellationToken)).ToArray();
        Assert.False(Fse2OfficialTestOperationalization.IsCurrentPublisher(
            approverA.Id, compiled.CanonicalDefinitionSha256, currentApprovals.Select(ApprovalAuthority)));
        Assert.True(Fse2OfficialTestOperationalization.IsCurrentPublisher(
            approverB.Id, compiled.CanonicalDefinitionSha256, currentApprovals.Select(ApprovalAuthority)));
        Assert.Equal(Convert.ToHexString(await store.GetBindingBundleDigestAsync(approvedD2.ConnectorVersionId, cancellationToken)), approvedD2.BindingDigestSha256);
        Assert.False(Fse2OfficialTestOperationalization.IsCurrentPublisher(
            approverB.Id, new string('0', 64), currentApprovals.Select(ApprovalAuthority)));

        ConnectorVersionRecord beforeDeniedA = (await store.GetVersionAsync(imported.ConnectorId, imported.Version, cancellationToken))!;
        ConnectorSummary summaryBeforeDeniedA = Assert.Single(await store.ListConnectorsAsync(cancellationToken), value => value.ConnectorId == imported.ConnectorId);
        int approvalCountBeforeDeniedA = currentApprovals.Length;
        GatewayException deniedA = await Assert.ThrowsAsync<GatewayException>(() => administration.PublishAsync(
            imported.ConnectorId, imported.Version, validated.RowVersion, 0, approverA.Id.ToString("D"), Guid.NewGuid(), cancellationToken));
        Assert.Equal("BGW-ADMIN-APPROVAL-REQUIRED", deniedA.Code);
        ConnectorVersionRecord afterDeniedA = (await store.GetVersionAsync(imported.ConnectorId, imported.Version, cancellationToken))!;
        ConnectorSummary summaryAfterDeniedA = Assert.Single(await store.ListConnectorsAsync(cancellationToken), value => value.ConnectorId == imported.ConnectorId);
        Assert.Equal(beforeDeniedA.State, afterDeniedA.State);
        Assert.Equal(beforeDeniedA.RowVersion, afterDeniedA.RowVersion);
        Assert.Equal(summaryBeforeDeniedA.PublicationRevision, summaryAfterDeniedA.PublicationRevision);
        Assert.Equal(summaryBeforeDeniedA.PublishedVersion, summaryAfterDeniedA.PublishedVersion);
        Assert.Equal(approvalCountBeforeDeniedA, (await security.ListApprovalsAsync(approvedD2.ConnectorVersionId, cancellationToken)).Count);

        GatewayException concurrentMismatch = await Assert.ThrowsAsync<GatewayException>(() => administration.PublishAsync(
            imported.ConnectorId, imported.Version, validated.RowVersion, 1, approverB.Id.ToString("D"), Guid.NewGuid(), cancellationToken));
        Assert.Equal("BGW-CONCURRENCY-CONFLICT", concurrentMismatch.Code);
        Assert.Equal(ConnectorVersionState.Validated, (await store.GetVersionAsync(imported.ConnectorId, imported.Version, cancellationToken))!.State);

        ConnectorVersionResource published = await administration.PublishAsync(
            imported.ConnectorId, imported.Version, validated.RowVersion, 0, approverB.Id.ToString("D"), Guid.NewGuid(), cancellationToken);
        Assert.Equal(ConnectorVersionState.Published, published.State);
        _ = await Assert.ThrowsAsync<GatewayException>(() => administration.PublishAsync(
            imported.ConnectorId, imported.Version, published.RowVersion, 1, approverB.Id.ToString("D"), Guid.NewGuid(), cancellationToken));
        PublishedConnectorSnapshot snapshot = await store.GetPublishedSnapshotAsync(imported.ConnectorId, environmentId, null, cancellationToken)
            ?? throw new InvalidOperationException("Synthetic OfficialTest Published snapshot missing.");
        Assert.Equal(compiled.CanonicalDefinitionSha256, Convert.ToHexString(snapshot.Version.ChecksumSha256));
        Assert.Equal(ConnectorBindingState.Active, snapshot.Bindings.State);
        Assert.Equal(Fse2OfficialTestCanonicalDefinition.OperationId,
            Assert.Single(ConnectorOperationBindings.All(snapshot.Version.CanonicalJson)).OperationId);
        GatewayOperationDefinition effectiveOperation = await catalog.GetRequiredAsync(
            imported.ConnectorId, Fse2OfficialTestCanonicalDefinition.OperationId, environmentId, cancellationToken);
        Assert.Equal(
            "https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1/documents/validation",
            effectiveOperation.Endpoint.AbsoluteUri);

        GatewayException immutable = await Assert.ThrowsAsync<GatewayException>(() => administration.PutBindingsAsync(
            imported.ConnectorId, compiled.BindingRequest with { ExpectedRevision = d2Revision }, approverB.Id.ToString("D"), Guid.NewGuid(), cancellationToken));
        Assert.Equal("BGW-CONNECTOR-BINDING-REQUIRES-VALIDATED-VERSION", immutable.Code);
        GatewayException definitionImmutable = await Assert.ThrowsAsync<GatewayException>(() => administration.ImportAsync(
            definition.RootElement, compiled.CanonicalDefinitionSha256, approverB.Id.ToString("D"), Guid.NewGuid(), cancellationToken));
        Assert.Equal("BGW-CONNECTOR-VERSION-DUPLICATE", definitionImmutable.Code);
        await HostedPostgresTestSupport.ApplyMigrationAsync();
    }

    private static Fse2OfficialTestApprovalAuthority ApprovalAuthority(ConnectorApprovalRecord value) => new(
        value.Status.ToString(),
        value.ChecksumSha256,
        value.RequestedBy,
        value.ApprovedBy);

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
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), "RSA", 2048, reference.Version!,
                reference.ResourceId.EndsWith("a1", StringComparison.Ordinal) ? new string('A', 64) : new string('B', 64), commonName),
            string.Empty, DateTimeOffset.UtcNow), cancellationToken);

    private static ProviderResourceReference GatewayReference(Fse2OfficialTestProviderReference value) =>
        new(value.ProviderId, value.ResourceId, ProviderResourceType.ClientCertificate, value.Version, value.PublicMetadataRevision);

    private static async Task AssertCatalogIntegrityTamperDeniedAsync(
        NpgsqlDataSource dataSource,
        PostgresConnectorConfigurationStore store,
        ProviderResourceCatalogRecord resource,
        ProviderResourceReference reference,
        string? metadataProperty,
        string? replacement,
        CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await dataSource.OpenConnectionAsync(cancellationToken);
        string originalMetadata;
        byte[] originalChecksum;
        await using (NpgsqlCommand read = new("SELECT certificate_metadata_json::text,checksum_sha256 FROM gateway.provider_resource_catalog_version WHERE id=$1", connection))
        {
            read.Parameters.AddWithValue(resource.Id);
            await using NpgsqlDataReader reader = await read.ExecuteReaderAsync(cancellationToken);
            Assert.True(await reader.ReadAsync(cancellationToken));
            originalMetadata = reader.GetString(0);
            originalChecksum = reader.GetFieldValue<byte[]>(1);
        }

        try
        {
            if (metadataProperty is null)
            {
                await using NpgsqlCommand tamperChecksum = new("UPDATE gateway.provider_resource_catalog_version SET checksum_sha256=$2 WHERE id=$1", connection);
                tamperChecksum.Parameters.AddWithValue(resource.Id);
                tamperChecksum.Parameters.AddWithValue(new byte[32]);
                Assert.Equal(1, await tamperChecksum.ExecuteNonQueryAsync(cancellationToken));
            }
            else
            {
                JsonObject metadata = JsonNode.Parse(originalMetadata)?.AsObject() ?? throw new InvalidOperationException("Synthetic certificate metadata missing.");
                metadata[metadataProperty] = replacement;
                await using NpgsqlCommand tamperMetadata = new("UPDATE gateway.provider_resource_catalog_version SET certificate_metadata_json=$2::jsonb WHERE id=$1", connection);
                tamperMetadata.Parameters.AddWithValue(resource.Id);
                tamperMetadata.Parameters.AddWithValue(metadata.ToJsonString());
                Assert.Equal(1, await tamperMetadata.ExecuteNonQueryAsync(cancellationToken));
            }

            GatewayException integrity = await Assert.ThrowsAsync<GatewayException>(() => store.FindExactProviderResourcesAsync(
                resource.EnvironmentId, reference, resource.Revision, cancellationToken));
            Assert.Equal("BGW-PROVIDER-RESOURCE-INTEGRITY", integrity.Code);
        }
        finally
        {
            await using NpgsqlCommand restore = new("UPDATE gateway.provider_resource_catalog_version SET certificate_metadata_json=$2::jsonb,checksum_sha256=$3 WHERE id=$1", connection);
            restore.Parameters.AddWithValue(resource.Id);
            restore.Parameters.AddWithValue(originalMetadata);
            restore.Parameters.AddWithValue(originalChecksum);
            Assert.Equal(1, await restore.ExecuteNonQueryAsync(cancellationToken));
        }
    }

    private static Fse2OfficialTestOperationalPlan Plan(
        Guid environmentId,
        Fse2OfficialTestProviderReference a1,
        Fse2OfficialTestProviderReference s1)
    {
        string json = $$"""
            {
              "schemaVersion":"1.0",
              "tenantId":"22222222-2222-2222-2222-222222222222",
              "installationId":"33333333-3333-3333-3333-333333333333",
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

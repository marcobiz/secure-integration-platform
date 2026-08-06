using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class ConnectorConfigurationTests
{
    [Fact]
    public void M4_CT_Sample_conforms_to_Draft_2020_12_and_is_canonical()
    {
        ConnectorDefinitionValidator validator = new();
        using JsonDocument sample = Sample();
        ConnectorValidationResult result = validator.Validate(sample.RootElement);

        Assert.True(result.Valid);
        Assert.Matches("^[0-9A-F]{64}$", result.ChecksumSha256!);
        using JsonDocument reordered = JsonDocument.Parse("""
            {"operations":[],"bindings":{"secrets":[],"endpoints":[]},"displayName":"x","version":"1.0.0","connectorId":"sample-secure-service","schemaVersion":"1.0"}
            """);
        string canonical = ConnectorCanonicalJson.Canonicalize(reordered.RootElement);
        Assert.StartsWith("{\"bindings\":", canonical, StringComparison.Ordinal);
    }

    [Fact]
    public void M4_CT_Invalid_schema_version_binding_header_and_retry_are_rejected()
    {
        ConnectorDefinitionValidator validator = new();
        using JsonDocument sample = Sample();
        string json = sample.RootElement.GetRawText();

        AssertIssue(json.Replace("\"1.0\"", "\"2.0\"", StringComparison.Ordinal), "BGW-CONNECTOR-SCHEMA-VERSION-UNSUPPORTED");
        AssertIssue(json.Replace("sample-vendor-endpoint", "missing-endpoint", 1, StringComparison.Ordinal), "BGW-CONNECTOR-ENDPOINT-BINDING-UNKNOWN");
        AssertIssue(json.Replace("\"allowedClientHeaders\": []", "\"allowedClientHeaders\": [\"Authorization\"]", StringComparison.Ordinal), "BGW-CONNECTOR-HEADER-FORBIDDEN");
        AssertIssue(json.Replace("\"maximumRetries\": 0", "\"maximumRetries\": 1", StringComparison.Ordinal), "BGW-CONNECTOR-RETRY-REQUIRES-IDEMPOTENCY");

        void AssertIssue(string candidate, string expected)
        {
            using JsonDocument document = JsonDocument.Parse(candidate);
            ConnectorValidationResult result = validator.Validate(document.RootElement);
            Assert.False(result.Valid);
            Assert.Contains(result.Issues, issue => issue.Code == expected);
        }
    }

    [Fact]
    public void M4_CT_Checksum_mismatch_is_rejected()
    {
        ConnectorDefinitionValidator validator = new();
        using JsonDocument sample = Sample();
        GatewayException failure = Assert.Throws<GatewayException>(() => validator.ValidateRequired(sample.RootElement, new string('0', 64)));
        Assert.Equal("BGW-CONNECTOR-CHECKSUM", failure.Code);
    }

    [Fact]
    public async Task M4_UT_Lifecycle_is_immutable_concurrent_and_rollback_reactivates_prior_publication()
    {
        Fixture fixture = new();
        ConnectorVersionResource v1 = await fixture.ImportAsync(Sample());
        ConnectorSummary summary = Assert.Single(await fixture.Admin.ListAsync(TestContext.Current.CancellationToken));
        Assert.Equal("Sample Secure Service", summary.DisplayName);
        Assert.Equal(1, summary.Versions);
        Assert.Equal(0, summary.PublicationRevision);
        GatewayException draftPublish = await Assert.ThrowsAsync<GatewayException>(() => fixture.Admin.PublishAsync(v1.ConnectorId, v1.Version, v1.RowVersion, 0, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-CONNECTOR-STATE", draftPublish.Code);
        v1 = await fixture.Admin.ValidateStoredAsync(v1.ConnectorId, v1.Version, v1.RowVersion, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        v1 = await fixture.Admin.PublishAsync(v1.ConnectorId, v1.Version, v1.RowVersion, 0, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal(ConnectorVersionState.Published, v1.State);
        summary = Assert.Single(await fixture.Admin.ListAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, summary.PublicationRevision);
        Assert.Equal("1.0.0", summary.PublishedVersion);

        using JsonDocument second = WithVersion("2.0.0");
        ConnectorVersionResource v2 = await fixture.ImportAsync(second);
        v2 = await fixture.Admin.ValidateStoredAsync(v2.ConnectorId, v2.Version, v2.RowVersion, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        v2 = await fixture.Admin.PublishAsync(v2.ConnectorId, v2.Version, v2.RowVersion, 1, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);

        using JsonDocument third = WithVersion("3.0.0");
        ConnectorVersionResource v3 = await fixture.ImportAsync(third);
        v3 = await fixture.Admin.ValidateStoredAsync(v3.ConnectorId, v3.Version, v3.RowVersion, "racer", Guid.NewGuid(), TestContext.Current.CancellationToken);
        GatewayException stalePublish = await Assert.ThrowsAsync<GatewayException>(() => fixture.Admin.PublishAsync(v3.ConnectorId, v3.Version, v3.RowVersion, 1, "racer", Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-CONCURRENCY-CONFLICT", stalePublish.Code);
        GatewayException invalidRollback = await Assert.ThrowsAsync<GatewayException>(() => fixture.Admin.RollbackAsync(v3.ConnectorId, new(v3.Version, v2.RowVersion), "tester", Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-CONNECTOR-ROLLBACK-TARGET", invalidRollback.Code);

        ConnectorVersionResource supersededV1 = await fixture.Admin.ShowAsync(v1.ConnectorId, v1.Version, TestContext.Current.CancellationToken);
        ConnectorVersionResource rolledBack = await fixture.Admin.RollbackAsync(v1.ConnectorId, new(v1.Version, v2.RowVersion), "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal(ConnectorVersionState.Published, rolledBack.State);
        Assert.Equal(supersededV1.ChecksumSha256, rolledBack.ChecksumSha256);

        GatewayException duplicate = await Assert.ThrowsAsync<GatewayException>(() => fixture.Admin.ImportAsync(Sample().RootElement, null, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-CONNECTOR-VERSION-DUPLICATE", duplicate.Code);
        Assert.DoesNotContain("sample-vendor-api-key", JsonSerializer.Serialize(fixture.Registry.SnapshotAuditEvents()), StringComparison.Ordinal);
    }

    [Fact]
    public async Task M4_UT_Endpoint_bindings_reject_query_IP_and_non_HTTPS_values()
    {
        Fixture fixture = new();
        ConnectorVersionResource version = await fixture.ImportAsync(Sample());
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        foreach (string endpoint in new[] { "https://vendor.example.test/base?override=true", "https://127.0.0.1/", "http://vendor.example.test/" })
        {
            GatewayException rejected = await Assert.ThrowsAsync<GatewayException>(() => fixture.Admin.PutBindingsAsync(version.ConnectorId,
                new(fixture.EnvironmentId, new Dictionary<string, string> { ["sample-vendor-endpoint"] = endpoint }, new Dictionary<string, ProviderResourceReference>()),
                "tester", Guid.NewGuid(), TestContext.Current.CancellationToken));
            Assert.Equal("BGW-CONNECTOR-ENDPOINT-BINDING", rejected.Code);
        }
    }

    [Fact]
    public async Task M4_UT_Runtime_denies_Draft_Validated_Retired_missing_and_missing_bindings()
    {
        Fixture fixture = new();
        ConnectorVersionResource version = await fixture.ImportAsync(Sample());
        await AssertCodeAsync("BGW-CONNECTOR-NOT-PUBLISHED");
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        await AssertCodeAsync("BGW-CONNECTOR-NOT-PUBLISHED");
        version = await fixture.Admin.PublishAsync(version.ConnectorId, version.Version, version.RowVersion, 0, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        await AssertCodeAsync("BGW-CONNECTOR-BINDING-MISSING");
        version = await fixture.Admin.RetireAsync(version.ConnectorId, version.Version, version.RowVersion, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        await AssertCodeAsync("BGW-CONNECTOR-NOT-PUBLISHED");
        GatewayException missing = await Assert.ThrowsAsync<GatewayException>(() => fixture.Catalog.GetRequiredAsync("does-not-exist", "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-CONNECTOR-NOT-PUBLISHED", missing.Code);

        async Task AssertCodeAsync(string code)
        {
            GatewayException error = await Assert.ThrowsAsync<GatewayException>(() => fixture.Catalog.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken));
            Assert.Equal(code, error.Code);
        }
    }

    [Fact]
    public async Task M4_UT_Published_runtime_resolves_only_server_side_bindings_and_rejects_stale_cache()
    {
        Fixture fixture = new();
        ConnectorVersionResource version = await fixture.ImportAsync(Sample());
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        long bindingRevision = await fixture.Admin.PutBindingsAsync(version.ConnectorId, new(fixture.EnvironmentId,
            new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://vendor.example.test/base/" },
            SecretReferences(), null, CertificateReferences()),
            "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal(1, bindingRevision);
        version = await fixture.Admin.PublishAsync(version.ConnectorId, version.Version, version.RowVersion, 0, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);

        GatewayOperationDefinition operation = await fixture.Catalog.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken);
        Assert.Equal(new Uri("https://vendor.example.test/vendor/orders"), operation.Endpoint);
        Assert.Equal("synthetic://api-key", operation.ApiKeySecretReference);
        Assert.Equal("synthetic://client-cert", operation.ClientCertificateReference);

        ConnectorVersionRecord stored = (await fixture.Store.ListVersionsAsync(version.ConnectorId, TestContext.Current.CancellationToken))[0];
        _ = await fixture.Store.RetireAsync(stored.Id, stored.RowVersion, "other-node", Guid.NewGuid(), fixture.Clock.UtcNow, TestContext.Current.CancellationToken);
        GatewayException staleDenied = await Assert.ThrowsAsync<GatewayException>(() => fixture.Catalog.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-CONNECTOR-NOT-PUBLISHED", staleDenied.Code);
    }

    [Fact]
    public async Task M5_UT_Runtime_cache_revalidates_catalog_revision_and_disable_on_every_invocation()
    {
        Fixture fixture = new();
        ConnectorVersionResource version = await fixture.ImportAsync(Sample());
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await fixture.Admin.PutBindingsAsync(version.ConnectorId, BindingRequest(fixture.EnvironmentId, "https://vendor.example.test/"), "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        version = await fixture.Admin.PublishAsync(version.ConnectorId, version.Version, version.RowVersion, 0, "approver", Guid.NewGuid(), TestContext.Current.CancellationToken);

        PublishedConnectorCatalog replicaA = new(fixture.Store, fixture.Validator, fixture.Clock, TimeSpan.FromMinutes(5));
        _ = await replicaA.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken);
        ProviderResourceCatalogRecord current = await fixture.Store.ResolveProviderResourceAsync(SecretReference(), fixture.EnvironmentId, version.ConnectorId, ["submit"], TestContext.Current.CancellationToken);

        _ = await fixture.Store.RegisterProviderResourceAsync(current with
        {
            Id = Guid.NewGuid(), ProviderReference = "synthetic://rotated-api-key", Revision = 0, ChecksumSha256 = string.Empty,
            CreatedAt = fixture.Clock.UtcNow.AddSeconds(1)
        }, TestContext.Current.CancellationToken);

        GatewayException rotated = await Assert.ThrowsAsync<GatewayException>(() => replicaA.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-RESOURCE-REVISION-STALE", rotated.Code);

        ProviderResourceCatalogRecord rotatedResource = await fixture.Store.ResolveProviderResourceAsync(SecretReference(), fixture.EnvironmentId, version.ConnectorId, ["submit"], TestContext.Current.CancellationToken);
        _ = await fixture.Store.RegisterProviderResourceAsync(rotatedResource with
        {
            Id = Guid.NewGuid(), Status = ProviderResourceStatus.Disabled, Revision = 0, ChecksumSha256 = string.Empty,
            CreatedAt = fixture.Clock.UtcNow.AddSeconds(2)
        }, TestContext.Current.CancellationToken);
        GatewayException disabled = await Assert.ThrowsAsync<GatewayException>(() => replicaA.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-RESOURCE-REVISION-STALE", disabled.Code);
    }

    [Fact]
    public async Task M4_UT_Runtime_denies_missing_endpoint_secret_and_operation()
    {
        Fixture fixture = new();
        ConnectorVersionResource version = await fixture.ImportAsync(Sample());
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        GatewayException missingEndpoint = await Assert.ThrowsAsync<GatewayException>(() => fixture.Admin.PutBindingsAsync(version.ConnectorId, new(fixture.EnvironmentId, new Dictionary<string, string>(), SecretReferences(), null, CertificateReferences()), "tester", Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-CONNECTOR-BINDING-SCOPE", missingEndpoint.Code);

        GatewayException missingSecret = await Assert.ThrowsAsync<GatewayException>(() => fixture.Admin.PutBindingsAsync(version.ConnectorId, new(fixture.EnvironmentId, new Dictionary<string, string>
        {
            ["sample-vendor-endpoint"] = "https://vendor.example.test/"
        }, SecretReferences()), "tester", Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-CONNECTOR-BINDING-SCOPE", missingSecret.Code);

        await fixture.Admin.PutBindingsAsync(version.ConnectorId, new(fixture.EnvironmentId, new Dictionary<string, string>
        {
            ["sample-vendor-endpoint"] = "https://vendor.example.test/"
        }, SecretReferences(), null, CertificateReferences()), "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await fixture.Admin.PublishAsync(version.ConnectorId, version.Version, version.RowVersion, 0, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal("BGW-OPERATION-NOT-FOUND", (await Assert.ThrowsAsync<GatewayException>(() => fixture.Catalog.GetRequiredAsync(version.ConnectorId, "missing-operation", fixture.EnvironmentId, TestContext.Current.CancellationToken))).Code);
    }

    [Fact]
    public async Task M5_UT_Binding_revisions_are_immutable_checksum_bound_and_published_behavior_cannot_be_mutated()
    {
        Fixture fixture = new();
        ConnectorVersionResource version = await fixture.ImportAsync(Sample());
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        long first = await fixture.Admin.PutBindingsAsync(version.ConnectorId, BindingRequest(fixture.EnvironmentId, "https://first.example.test/"), "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionRecord stored = (await fixture.Store.ListVersionsAsync(version.ConnectorId, TestContext.Current.CancellationToken)).Single();
        byte[] firstDigest = await fixture.Store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);

        long second = await fixture.Admin.PutBindingsAsync(version.ConnectorId, BindingRequest(fixture.EnvironmentId, "https://second.example.test/", first), "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        byte[] secondDigest = await fixture.Store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken);
        Assert.Equal(1, first);
        Assert.Equal(2, second);
        Assert.NotEqual(Convert.ToHexString(firstDigest), Convert.ToHexString(secondDigest));

        version = await fixture.Admin.PublishAsync(version.ConnectorId, version.Version, version.RowVersion, 0, "approver", Guid.NewGuid(), TestContext.Current.CancellationToken);
        GatewayOperationDefinition operation = await fixture.Catalog.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken);
        Assert.Equal(new Uri("https://second.example.test/vendor/orders"), operation.Endpoint);
        GatewayException mutation = await Assert.ThrowsAsync<GatewayException>(() => fixture.Admin.PutBindingsAsync(version.ConnectorId, BindingRequest(fixture.EnvironmentId, "https://attacker.example.test/", second), "editor", Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-CONNECTOR-BINDING-REQUIRES-VALIDATED-VERSION", mutation.Code);
        Assert.Equal(new Uri("https://second.example.test/vendor/orders"), (await fixture.Catalog.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken)).Endpoint);
    }

    [Fact]
    public async Task M5_UT_Bindings_are_exactly_scoped_to_definition_and_environment()
    {
        Fixture fixture = new();
        ConnectorVersionResource version = await fixture.ImportAsync(Sample());
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorBindingRequest arbitrary = BindingRequest(fixture.EnvironmentId, "https://controlled.example.test/") with
        {
            SecretResources = new Dictionary<string, ProviderResourceReference>
            {
                ["sample-vendor-api-key"] = SecretReference(),
                ["unapproved-operation-secret"] = new("synthetic", "should-never-resolve", ProviderResourceType.Secret)
            }
        };
        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => fixture.Admin.PutBindingsAsync(version.ConnectorId, arbitrary, "editor", Guid.NewGuid(), TestContext.Current.CancellationToken));
        Assert.Equal("BGW-CONNECTOR-BINDING-SCOPE", denied.Code);
        Assert.Equal("BGW-CONNECTOR-NOT-PUBLISHED", (await Assert.ThrowsAsync<GatewayException>(() => fixture.Catalog.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken))).Code);
    }

    [Fact]
    public async Task M5_UT_Approval_review_is_semantic_canonical_and_contains_no_credential_value()
    {
        Fixture fixture = new();
        ConnectorVersionResource version = await fixture.ImportAsync(Sample());
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await fixture.Admin.PutBindingsAsync(version.ConnectorId, new(fixture.EnvironmentId,
            new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://controlled-public.example.test/base/" },
            SecretReferences(), null, CertificateReferences()),
            "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionRecord stored = Assert.Single(await fixture.Store.ListVersionsAsync(version.ConnectorId, TestContext.Current.CancellationToken));
        ConnectorBindingSet binding = Assert.Single((await fixture.Store.ListBindingsPageAsync(stored.Id, 0, 100, null, TestContext.Current.CancellationToken)).Items);

        ApprovalReviewResult review = ConnectorApprovalArtifacts.Create(stored, [binding]);
        ApprovalOperationReview operation = Assert.Single(review.Artifact.Operations);
        ApprovalSecretReview secret = Assert.Single(operation.SecretBindings);
        Assert.Equal("controlled-public.example.test", operation.Endpoint.Hostname);
        Assert.Equal(443, operation.Endpoint.Port);
        Assert.Equal("/vendor/orders", operation.Endpoint.Path);
        Assert.Equal("POST", Assert.Single(operation.Endpoint.AllowedMethods));
        Assert.Equal("Synthetic vault", secret.ProviderDisplayName);
        Assert.Equal("synthetic", secret.ProviderId);
        Assert.Equal("api-key", secret.ResourceLogicalId);
        Assert.Equal(ProviderResourceType.Secret.ToString(), secret.ResourceType);
        Assert.Null(secret.ResourceVersion);
        Assert.Equal(1, secret.CatalogRevision);
        Assert.Null(secret.PublicMetadataRevision);
        Assert.Equal(binding.Revision, secret.BindingRevision);
        Assert.Equal(binding.ChecksumSha256, secret.BindingChecksumSha256);
        Assert.Equal(binding.SecretResources["sample-vendor-api-key"].CatalogChecksumSha256, secret.CatalogChecksumSha256);
        ApprovalCertificateReview certificate = Assert.Single(operation.CertificateBindings);
        Assert.Equal(new string('A', 64), certificate.PublicFingerprintSha256);
        Assert.Equal("CN=synthetic-client", certificate.PublicSubject);
        Assert.Equal("CN=synthetic-ca", certificate.PublicIssuer);
        Assert.Equal(ProviderResourceType.ClientCertificate.ToString(), certificate.ResourceType);
        Assert.Null(certificate.ResourceVersion);
        Assert.Equal(1, certificate.CatalogRevision);
        Assert.Equal(1, certificate.PublicMetadataRevision);
        Assert.Equal("1", certificate.CertificateVersion);
        Assert.Equal(binding.Revision, certificate.BindingRevision);
        Assert.Equal(binding.ChecksumSha256, certificate.BindingChecksumSha256);
        Assert.Equal(binding.CertificateResources["sample-vendor-client-certificate"].CatalogChecksumSha256, certificate.CatalogChecksumSha256);
        Assert.Equal(binding.Revision, operation.Endpoint.BindingRevision);
        Assert.Equal(binding.ChecksumSha256, operation.Endpoint.BindingChecksumSha256);
        Assert.Equal(Convert.ToHexString(await fixture.Store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken)), review.DigestSha256);
        Assert.Contains(review.RiskIndicators, value => value.Code == "PUBLIC_INTERNET_DESTINATION");
        Assert.DoesNotContain("VERY_SECRET_CANARY_VALUE", review.CanonicalJson, StringComparison.Ordinal);
        Assert.DoesNotContain("secretValue", review.CanonicalJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("privateKey", review.CanonicalJson, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task M5_UT_Actual_canary_and_opaque_credential_material_are_denied_by_catalog_before_binding()
    {
        Fixture fixture = new();
        ConnectorVersionResource version = await fixture.ImportAsync(Sample());
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        string[] hostileIds = ["ACTUAL_API_KEY_CANARY", "-----BEGIN-PRIVATE-KEY-----", "base64-PFX-MIIK", "Server-db-Password-secret", "missing-resource"];
        foreach (string hostileId in hostileIds)
        {
            ConnectorBindingRequest request = BindingRequest(fixture.EnvironmentId, "https://controlled.example.test/") with
            {
                SecretResources = new Dictionary<string, ProviderResourceReference> { ["sample-vendor-api-key"] = new("synthetic", hostileId, ProviderResourceType.Secret) }
            };
            GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => fixture.Admin.PutBindingsAsync(version.ConnectorId, request, "editor", Guid.NewGuid(), TestContext.Current.CancellationToken));
            Assert.True(denied.Code is "BGW-PROVIDER-RESOURCE-REFERENCE-DENIED" or "BGW-PROVIDER-RESOURCE-NOT-FOUND", denied.Code);
        }
        Assert.Empty((await fixture.Store.ListBindingsPageAsync((await fixture.Store.ListVersionsAsync(version.ConnectorId, TestContext.Current.CancellationToken)).Single().Id, 0, 100, null, TestContext.Current.CancellationToken)).Items);
        Assert.DoesNotContain("ACTUAL_API_KEY_CANARY", JsonSerializer.Serialize(fixture.Registry.SnapshotAuditEvents()), StringComparison.Ordinal);
    }

    [Fact]
    public async Task M5_UT_Catalog_revision_change_invalidates_review_and_near_expiry_is_real()
    {
        Fixture fixture = new(certificateExpiryDays: 5);
        ConnectorVersionResource version = await fixture.ImportAsync(Sample());
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await fixture.Admin.PutBindingsAsync(version.ConnectorId, BindingRequest(fixture.EnvironmentId, "https://vendor.example.test/"), "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionRecord stored = Assert.Single(await fixture.Store.ListVersionsAsync(version.ConnectorId, TestContext.Current.CancellationToken));
        ConnectorBindingSet binding = Assert.Single((await fixture.Store.ListBindingsPageAsync(stored.Id, 0, 100, null, TestContext.Current.CancellationToken)).Items);
        ApprovalReviewResult review = ConnectorApprovalArtifacts.Create(stored, [binding]);
        Assert.Contains(review.RiskIndicators, value => value.Code == "CERTIFICATE_NEAR_EXPIRY");

        ProviderResourceCatalogRecord current = await fixture.Store.ResolveProviderResourceAsync(CertificateReference(), fixture.EnvironmentId, version.ConnectorId, ["submit"], TestContext.Current.CancellationToken);
        _ = await fixture.Store.RegisterProviderResourceAsync(current with { Id = Guid.NewGuid(), ProviderReference = "synthetic://rotated-client-cert", Revision = 0, ChecksumSha256 = string.Empty, CreatedAt = fixture.Clock.UtcNow.AddMinutes(1) }, TestContext.Current.CancellationToken);
        GatewayException stale = await Assert.ThrowsAsync<GatewayException>(() => fixture.Store.GetBindingBundleDigestAsync(stored.Id, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-RESOURCE-REVISION-STALE", stale.Code);
    }

    [Fact]
    public async Task M5_UT_Approval_digest_covers_every_catalog_and_certificate_revision_dimension()
    {
        Fixture fixture = new();
        ConnectorVersionResource version = await fixture.ImportAsync(Sample());
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await fixture.Admin.PutBindingsAsync(version.ConnectorId, BindingRequest(fixture.EnvironmentId, "https://vendor.example.test/"), "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionRecord stored = Assert.Single(await fixture.Store.ListVersionsAsync(version.ConnectorId, TestContext.Current.CancellationToken));
        ConnectorBindingSet binding = Assert.Single((await fixture.Store.ListBindingsPageAsync(stored.Id, 0, 100, null, TestContext.Current.CancellationToken)).Items);
        string baseline = ConnectorApprovalArtifacts.Create(stored, [binding]).DigestSha256;
        ProviderResourceBinding secret = binding.SecretResources["sample-vendor-api-key"];
        ProviderResourceBinding certificate = binding.CertificateResources["sample-vendor-client-certificate"];
        CertificatePublicMetadata metadata = certificate.CertificateMetadata!;

        ConnectorBindingSet[] changed =
        [
            binding with { SecretResources = new Dictionary<string, ProviderResourceBinding>(binding.SecretResources) { ["sample-vendor-api-key"] = secret with { CatalogRevision = secret.CatalogRevision + 1 } } },
            binding with { SecretResources = new Dictionary<string, ProviderResourceBinding>(binding.SecretResources) { ["sample-vendor-api-key"] = secret with { PublicMetadataRevision = 2 } } },
            binding with { CertificateResources = new Dictionary<string, ProviderResourceBinding>(binding.CertificateResources) { ["sample-vendor-client-certificate"] = certificate with { Version = "catalog-v2" } } },
            binding with { CertificateResources = new Dictionary<string, ProviderResourceBinding>(binding.CertificateResources) { ["sample-vendor-client-certificate"] = certificate with { ResourceType = ProviderResourceType.Secret } } },
            binding with { CertificateResources = new Dictionary<string, ProviderResourceBinding>(binding.CertificateResources) { ["sample-vendor-client-certificate"] = certificate with { PublicMetadataRevision = 2 } } },
            binding with { CertificateResources = new Dictionary<string, ProviderResourceBinding>(binding.CertificateResources) { ["sample-vendor-client-certificate"] = certificate with { CertificateMetadata = metadata with { Subject = "CN=changed", Version = "2" } } } }
        ];
        Assert.All(changed, candidate => Assert.NotEqual(baseline, ConnectorApprovalArtifacts.Create(stored, [candidate]).DigestSha256));
    }

    [Fact]
    public void M4_UT_Corrupted_configuration_is_rejected_fail_closed()
    {
        ConnectorDefinitionValidator validator = new();
        using JsonDocument sample = Sample();
        ValidatedConnectorDefinition definition = validator.ValidateRequired(sample.RootElement);
        GatewayException corrupted = Assert.Throws<GatewayException>(() => validator.ParseStored(definition.CanonicalJson.Replace("submit", "tampered", StringComparison.Ordinal), Convert.FromHexString(definition.ChecksumSha256)));
        Assert.Equal("BGW-CONNECTOR-CONFIGURATION-CORRUPT", corrupted.Code);
    }

    private static JsonDocument Sample() => JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Samples", "sample-secure-service.connector.json")));

    private static JsonDocument WithVersion(string version)
    {
        using JsonDocument sample = Sample();
        return JsonDocument.Parse(sample.RootElement.GetRawText().Replace("\"version\": \"1.0.0\"", $"\"version\": \"{version}\"", StringComparison.Ordinal));
    }

    private static ConnectorBindingRequest BindingRequest(Guid environmentId, string endpoint, long? expectedRevision = null) => new(
        environmentId,
        new Dictionary<string, string> { ["sample-vendor-endpoint"] = endpoint },
        SecretReferences(), expectedRevision, CertificateReferences());

    private static ProviderResourceReference SecretReference() => new("synthetic", "api-key", ProviderResourceType.Secret);
    private static ProviderResourceReference CertificateReference() => new("synthetic", "client-certificate", ProviderResourceType.ClientCertificate, PublicMetadataRevision: 1);
    private static Dictionary<string, ProviderResourceReference> SecretReferences() => new() { ["sample-vendor-api-key"] = SecretReference() };
    private static Dictionary<string, ProviderResourceReference> CertificateReferences() => new() { ["sample-vendor-client-certificate"] = CertificateReference() };

    private sealed class Fixture
    {
        public Fixture(int certificateExpiryDays = 90)
        {
            CertificatePublicMetadata metadata = new(new string('A', 64), "CN=synthetic-client", "CN=synthetic-ca", Clock.UtcNow.AddDays(-1), Clock.UtcNow.AddDays(certificateExpiryDays), "ECDSA", 256, "1");
            _ = Store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic vault", "synthetic", "api-key", ProviderResourceType.Secret, "Vendor API key", EnvironmentId, "sample-secure-service", "submit", "synthetic://api-key", ProviderResourceStatus.Active, null, 0, null, null, string.Empty, Clock.UtcNow), TestContext.Current.CancellationToken).GetAwaiter().GetResult();
            _ = Store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic vault", "synthetic", "client-certificate", ProviderResourceType.ClientCertificate, "Vendor client certificate", EnvironmentId, "sample-secure-service", "submit", "synthetic://client-cert", ProviderResourceStatus.Active, null, 0, 1, metadata, string.Empty, Clock.UtcNow), TestContext.Current.CancellationToken).GetAwaiter().GetResult();
            Catalog = new(Store, Validator, Clock, TimeSpan.FromMinutes(5));
            Admin = new(Store, Validator, Catalog, Registry, Clock, new DevelopmentConnectorApprovalPolicy());
        }

        public Guid EnvironmentId { get; } = Guid.NewGuid();
        public FixedClock Clock { get; } = new();
        public InMemoryConnectorConfigurationStore Store { get; } = new();
        public InMemoryGatewayRegistry Registry { get; } = new();
        public ConnectorDefinitionValidator Validator { get; } = new();
        public PublishedConnectorCatalog Catalog { get; }
        public ConnectorAdministrationService Admin { get; }

        public Task<ConnectorVersionResource> ImportAsync(JsonDocument document) => Admin.ImportAsync(document.RootElement, null, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
    }

    private sealed class FixedClock : IGatewayClock
    {
        public DateTimeOffset UtcNow { get; set; } = new(2026, 8, 5, 10, 0, 0, TimeSpan.Zero);
    }
}

internal static class StringTestExtensions
{
    public static string Replace(this string value, string oldValue, string newValue, int count, StringComparison comparison)
    {
        int index = value.IndexOf(oldValue, comparison);
        return count == 1 && index >= 0 ? string.Concat(value.AsSpan(0, index), newValue, value.AsSpan(index + oldValue.Length)) : value.Replace(oldValue, newValue, comparison);
    }
}

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

        AssertIssue(json.Replace("\"1.0\"", "\"2.0\"", StringComparison.Ordinal), "CONNECTOR_SCHEMA_VERSION_UNSUPPORTED");
        AssertIssue(json.Replace("sample-vendor-endpoint", "missing-endpoint", 1, StringComparison.Ordinal), "CONNECTOR_ENDPOINT_BINDING_UNKNOWN");
        AssertIssue(json.Replace("\"allowedClientHeaders\": []", "\"allowedClientHeaders\": [\"Authorization\"]", StringComparison.Ordinal), "CONNECTOR_HEADER_FORBIDDEN");
        AssertIssue(json.Replace("\"maximumRetries\": 0", "\"maximumRetries\": 1", StringComparison.Ordinal), "CONNECTOR_RETRY_REQUIRES_IDEMPOTENCY");

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
        foreach (string endpoint in new[] { "https://vendor.example.test/base?override=true", "https://127.0.0.1/", "http://vendor.example.test/" })
        {
            GatewayException rejected = await Assert.ThrowsAsync<GatewayException>(() => fixture.Admin.PutBindingsAsync(version.ConnectorId,
                new(fixture.EnvironmentId, new Dictionary<string, string> { ["sample-vendor-endpoint"] = endpoint }, new Dictionary<string, string>()),
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
        version = await fixture.Admin.PublishAsync(version.ConnectorId, version.Version, version.RowVersion, 0, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        long bindingRevision = await fixture.Admin.PutBindingsAsync(version.ConnectorId, new(fixture.EnvironmentId,
            new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://vendor.example.test/base/" },
            new Dictionary<string, string> { ["sample-vendor-api-key"] = "synthetic://api-key", ["sample-vendor-client-certificate"] = "synthetic://client-cert" }),
            "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal(1, bindingRevision);

        GatewayOperationDefinition operation = await fixture.Catalog.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken);
        Assert.Equal(new Uri("https://vendor.example.test/vendor/orders"), operation.Endpoint);
        Assert.Equal("synthetic://api-key", operation.ApiKeySecretReference);
        Assert.Equal("synthetic://client-cert", operation.ClientCertificateReference);

        ConnectorVersionRecord stored = (await fixture.Store.ListVersionsAsync(version.ConnectorId, TestContext.Current.CancellationToken))[0];
        _ = await fixture.Store.RetireAsync(stored.Id, stored.RowVersion, "other-node", fixture.Clock.UtcNow, TestContext.Current.CancellationToken);
        GatewayException staleDenied = await Assert.ThrowsAsync<GatewayException>(() => fixture.Catalog.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-CONNECTOR-NOT-PUBLISHED", staleDenied.Code);
    }

    [Fact]
    public async Task M4_UT_Runtime_denies_missing_endpoint_secret_and_operation()
    {
        Fixture fixture = new();
        ConnectorVersionResource version = await fixture.ImportAsync(Sample());
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await fixture.Admin.PublishAsync(version.ConnectorId, version.Version, version.RowVersion, 0, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);

        await fixture.Admin.PutBindingsAsync(version.ConnectorId, new(fixture.EnvironmentId, new Dictionary<string, string>(), new Dictionary<string, string>
        {
            ["sample-vendor-api-key"] = "synthetic://api-key",
            ["sample-vendor-client-certificate"] = "synthetic://client-cert"
        }), "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal("BGW-CONNECTOR-ENDPOINT-BINDING-MISSING", (await Assert.ThrowsAsync<GatewayException>(() => fixture.Catalog.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken))).Code);

        await fixture.Admin.PutBindingsAsync(version.ConnectorId, new(fixture.EnvironmentId, new Dictionary<string, string>
        {
            ["sample-vendor-endpoint"] = "https://vendor.example.test/"
        }, new Dictionary<string, string>
        {
            ["sample-vendor-api-key"] = "synthetic://api-key"
        }), "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal("BGW-CONNECTOR-SECRET-BINDING-MISSING", (await Assert.ThrowsAsync<GatewayException>(() => fixture.Catalog.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken))).Code);

        await fixture.Admin.PutBindingsAsync(version.ConnectorId, new(fixture.EnvironmentId, new Dictionary<string, string>
        {
            ["sample-vendor-endpoint"] = "https://vendor.example.test/"
        }, new Dictionary<string, string>
        {
            ["sample-vendor-api-key"] = "synthetic://api-key",
            ["sample-vendor-client-certificate"] = "synthetic://client-cert"
        }), "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        Assert.Equal("BGW-OPERATION-NOT-FOUND", (await Assert.ThrowsAsync<GatewayException>(() => fixture.Catalog.GetRequiredAsync(version.ConnectorId, "missing-operation", fixture.EnvironmentId, TestContext.Current.CancellationToken))).Code);
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

    private sealed class Fixture
    {
        public Fixture()
        {
            Catalog = new(Store, Validator, Clock, TimeSpan.FromMinutes(5));
            Admin = new(Store, Validator, Catalog, Registry, Clock);
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

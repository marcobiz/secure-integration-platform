using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class ConnectorConfigurationTests
{
    [Theory]
    [InlineData("https://vendor.example.test/govway/rest/in/FSE/gateway/v1")]
    [InlineData("https://vendor.example.test/govway/rest/in/FSE/gateway/v1/")]
    public async Task FSE2_OFFICIALTEST_UT_rooted_operation_path_preserves_the_complete_server_owned_base_prefix_without_network(string baseEndpoint)
    {
        Fixture fixture = new();
        using JsonDocument original = Sample();
        using JsonDocument sample = JsonDocument.Parse(original.RootElement.GetRawText().Replace(
            "\"path\": \"/vendor/orders\"",
            "\"path\": \"/vendor/orders\", \"pathResolution\": \"appendToBasePath\"",
            StringComparison.Ordinal));
        ConnectorVersionResource version = await fixture.ImportAsync(sample);
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await fixture.Admin.PutBindingsAsync(version.ConnectorId, BindingRequest(fixture.EnvironmentId, baseEndpoint), "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await fixture.Admin.PublishAsync(version.ConnectorId, version.Version, version.RowVersion, 0, "approver", Guid.NewGuid(), TestContext.Current.CancellationToken);

        GatewayOperationDefinition operation = await fixture.Catalog.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, TestContext.Current.CancellationToken);

        Assert.Equal("https://vendor.example.test/govway/rest/in/FSE/gateway/v1/vendor/orders", operation.Endpoint.AbsoluteUri);
    }

    [Theory]
    [InlineData("http://vendor.example.test/govway/rest/in/FSE/gateway/v1/")]
    [InlineData("https://caller@vendor.example.test/govway/rest/in/FSE/gateway/v1/")]
    [InlineData("https://vendor.example.test/govway/rest/in/FSE/gateway/v1/?caller=true")]
    [InlineData("https://vendor.example.test/govway/rest/in/FSE/gateway/v1/#caller")]
    public async Task FSE2_OFFICIALTEST_UT_endpoint_scheme_userinfo_query_and_fragment_overrides_are_denied_before_publication(string baseEndpoint)
    {
        Fixture fixture = new();
        using JsonDocument sample = Sample();
        ConnectorVersionResource version = await fixture.ImportAsync(sample);
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);

        GatewayException denied = await Assert.ThrowsAsync<GatewayException>(() => fixture.Admin.PutBindingsAsync(
            version.ConnectorId, BindingRequest(fixture.EnvironmentId, baseEndpoint), "editor", Guid.NewGuid(), TestContext.Current.CancellationToken));

        Assert.Equal("BGW-CONNECTOR-ENDPOINT-BINDING", denied.Code);
    }

    [Theory]
    [InlineData("/documents/validation?caller=true")]
    [InlineData("/documents/validation#caller")]
    [InlineData("https://caller@attacker.invalid/documents/validation")]
    [InlineData("//attacker.invalid/documents/validation")]
    [InlineData("/documents/../validation")]
    [InlineData("/documents/%2e%2e/validation")]
    [InlineData("/documents\\validation")]
    public void FSE2_OFFICIALTEST_UT_operation_query_fragment_userinfo_authority_and_traversal_are_denied_without_effect(string operationPath)
    {
        GatewayException denied = Assert.Throws<GatewayException>(() => PublishedEndpointUri.Compose(
            new Uri("https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1/"),
            operationPath,
            appendToBasePath: true));

        Assert.Equal("BGW-CONNECTOR-CONFIGURATION-CORRUPT", denied.Code);
    }

    [Fact]
    public async Task FSE2_OFFICIALTEST_UT_exact_provider_lookup_is_bounded_current_and_independent_of_page_size_or_concurrent_catalog_mutation()
    {
        InMemoryConnectorConfigurationStore store = new();
        Guid environmentId = Guid.NewGuid();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        CertificatePublicMetadata metadata = new(new string('A', 64), "CN=synthetic", "CN=synthetic-ca", now.AddDays(-1), now.AddDays(30), "RSA", 2048, "1", new string('B', 64), "Synthetic Authority");
        List<ProviderResourceCatalogRecord> registered = [];
        for (int index = 0; index < 105; index++)
        {
            string version = $"v{index:D3}";
            registered.Add(await store.RegisterProviderResourceAsync(new(
                Guid.NewGuid(), "synthetic-provider", "Synthetic provider", "synthetic", "officialtest-a1", ProviderResourceType.ClientCertificate,
                $"Synthetic A1 {index:D3}", environmentId, "fse2-officialtest-validate-cda", "validate-cda", $"synthetic://a1/{index:D3}",
                ProviderResourceStatus.Active, version, 0, index + 1, metadata, string.Empty, now.AddSeconds(index)), TestContext.Current.CancellationToken));
        }

        AdminPage<ProviderResourceCatalogRecord> firstPage = await store.ListProviderResourcesPageAsync(0, 100, environmentId, ProviderResourceType.ClientCertificate, TestContext.Current.CancellationToken);
        Assert.Equal(105, firstPage.Total);
        Assert.Equal(100, firstPage.Items.Count);

        ProviderResourceCatalogRecord target = registered[104];
        ProviderResourceReference exactReference = new(target.ProviderId, target.ResourceId, target.ResourceType, target.Version, target.PublicMetadataRevision);
        Assert.Equal(target.Id, Assert.Single(await store.FindExactProviderResourcesAsync(environmentId, exactReference, target.Revision, TestContext.Current.CancellationToken)).Id);
        Assert.Empty(await store.FindExactProviderResourcesAsync(Guid.NewGuid(), exactReference, target.Revision, TestContext.Current.CancellationToken));
        Assert.Empty(await store.FindExactProviderResourcesAsync(environmentId, exactReference with { ResourceType = ProviderResourceType.Secret }, target.Revision, TestContext.Current.CancellationToken));
        Assert.Empty(await store.FindExactProviderResourcesAsync(environmentId, exactReference with { Version = "wrong" }, target.Revision, TestContext.Current.CancellationToken));
        Assert.Empty(await store.FindExactProviderResourcesAsync(environmentId, exactReference, target.Revision + 1, TestContext.Current.CancellationToken));
        Assert.Empty(await store.FindExactProviderResourcesAsync(environmentId, exactReference with { PublicMetadataRevision = target.PublicMetadataRevision + 1 }, target.Revision, TestContext.Current.CancellationToken));

        Task<IReadOnlyList<ProviderResourceCatalogRecord>> concurrentLookup = store.FindExactProviderResourcesAsync(environmentId, exactReference, target.Revision, TestContext.Current.CancellationToken);
        Task<ProviderResourceCatalogRecord> concurrentMutation = store.RegisterProviderResourceAsync(target with
        {
            Id = Guid.NewGuid(),
            DisplayName = "Synthetic A1 rotated",
            ProviderReference = "synthetic://a1/rotated",
            Revision = 0,
            ChecksumSha256 = string.Empty,
            CreatedAt = now.AddMinutes(5)
        }, TestContext.Current.CancellationToken);
        await Task.WhenAll(concurrentLookup, concurrentMutation);
        Assert.InRange((await concurrentLookup).Count, 0, 1);
        Assert.Empty(await store.FindExactProviderResourcesAsync(environmentId, exactReference, target.Revision, TestContext.Current.CancellationToken));
        ProviderResourceCatalogRecord rotated = await concurrentMutation;
        Assert.Equal(rotated.Id, Assert.Single(await store.FindExactProviderResourcesAsync(environmentId, exactReference, rotated.Revision, TestContext.Current.CancellationToken)).Id);

        ProviderResourceCatalogRecord inactive = await store.RegisterProviderResourceAsync(new(
            Guid.NewGuid(), "synthetic-provider", "Synthetic provider", "synthetic", "officialtest-disabled", ProviderResourceType.ClientCertificate,
            "Synthetic disabled", environmentId, "fse2-officialtest-validate-cda", "validate-cda", "synthetic://disabled",
            ProviderResourceStatus.Disabled, "v1", 0, 1, metadata, string.Empty, now), TestContext.Current.CancellationToken);
        ProviderResourceReference inactiveReference = new(inactive.ProviderId, inactive.ResourceId, inactive.ResourceType, inactive.Version, inactive.PublicMetadataRevision);
        Assert.Equal(ProviderResourceStatus.Disabled, Assert.Single(await store.FindExactProviderResourcesAsync(environmentId, inactiveReference, inactive.Revision, TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public void AlphaGoldenPath_Provisioner_publishes_and_uses_exact_canonical_sample_connector()
    {
        ConnectorDefinitionValidator validator = new();
        using JsonDocument sample = Sample();
        ValidatedConnectorDefinition canonical = validator.ValidateRequired(sample.RootElement);
        JsonElement bindings = sample.RootElement.GetProperty("bindings");
        Assert.Equal(["sample-vendor-endpoint"], bindings.GetProperty("endpoints").EnumerateArray().Select(value => value.GetProperty("name").GetString()));
        Assert.Equal(
            ["sample-vendor-api-key", "sample-vendor-client-certificate"],
            bindings.GetProperty("secrets").EnumerateArray().Select(value => value.GetProperty("name").GetString()));
        JsonElement operation = Assert.Single(sample.RootElement.GetProperty("operations").EnumerateArray());
        Assert.Equal("submit", operation.GetProperty("operationId").GetString());
        Assert.Equal("sample-vendor-endpoint", operation.GetProperty("endpointBinding").GetString());
        Assert.Equal("sample-vendor-api-key", operation.GetProperty("authentication").GetProperty("secretBinding").GetString());
        Assert.Equal("sample-vendor-client-certificate", operation.GetProperty("authentication").GetProperty("certificateBinding").GetString());

        using JsonDocument mutated = JsonDocument.Parse(sample.RootElement.GetRawText().Replace(
            "sample-vendor-endpoint", "mutated-vendor-endpoint", StringComparison.Ordinal));
        ValidatedConnectorDefinition changed = validator.ValidateRequired(mutated.RootElement);
        Assert.NotEqual(canonical.ChecksumSha256, changed.ChecksumSha256);
        GatewayException mismatch = Assert.Throws<GatewayException>(() => validator.ValidateRequired(mutated.RootElement, canonical.ChecksumSha256));
        Assert.Equal("BGW-CONNECTOR-CHECKSUM", mismatch.Code);

        string repository = FindRepositoryRoot();
        string provisioner = File.ReadAllText(Path.Combine(repository, "tools", "m3", "Provisioner", "Program.cs"));
        string project = File.ReadAllText(Path.Combine(repository, "tools", "m3", "Provisioner", "Provisioner.csproj"));
        string dockerfile = File.ReadAllText(Path.Combine(repository, "tools", "m3", "Provisioner", "Dockerfile"));
        Assert.Contains("Path.Combine(AppContext.BaseDirectory, \"sample-secure-service.connector.json\")", provisioner, StringComparison.Ordinal);
        Assert.Contains("PublishConnectorAsync(sampleConnectorDocument.RootElement", provisioner, StringComparison.Ordinal);
        Assert.Contains("GetPublishedSnapshotAsync(connectorId, selectedEnvironment, null", provisioner, StringComparison.Ordinal);
        Assert.Contains("ConnectorVersionState.Published", provisioner, StringComparison.Ordinal);
        Assert.DoesNotContain("connectorId = \"sample-secure-service\"", provisioner, StringComparison.Ordinal);
        Assert.DoesNotContain("displayName = \"Sample Secure Service\"", provisioner, StringComparison.Ordinal);
        Assert.Equal(1, project.Split("docs/connectors/examples/sample-secure-service.connector.json", StringSplitOptions.None).Length - 1);
        Assert.Contains("COPY docs/connectors/examples/sample-secure-service.connector.json docs/connectors/examples/sample-secure-service.connector.json", dockerfile, StringComparison.Ordinal);
    }

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
    public void Wave1_CT_execution_strategy_key_is_schema_validated_canonical_and_checksum_bound()
    {
        ConnectorDefinitionValidator validator = new();
        using JsonDocument sample = Sample();
        ValidatedConnectorDefinition legacy = validator.ValidateRequired(sample.RootElement);
        string explicitJson = sample.RootElement.GetRawText().Replace(
            "\"timeoutMs\": 30000",
            "\"executionStrategy\": \"synthetic-external\",\r\n      \"timeoutMs\": 30000",
            StringComparison.Ordinal);
        using JsonDocument explicitDefinition = JsonDocument.Parse(explicitJson);
        ValidatedConnectorDefinition validated = validator.ValidateRequired(explicitDefinition.RootElement);

        Assert.NotEqual(legacy.ChecksumSha256, validated.ChecksumSha256);
        Assert.Contains("\"executionStrategy\":\"synthetic-external\"", validated.CanonicalJson, StringComparison.Ordinal);
        AssertInvalid(explicitJson.Replace("synthetic-external", "Synthetic-External", StringComparison.Ordinal));
        AssertInvalid(explicitJson.Replace("synthetic-external", "synthetic/external", StringComparison.Ordinal));

        void AssertInvalid(string candidate)
        {
            using JsonDocument document = JsonDocument.Parse(candidate);
            Assert.False(validator.Validate(document.RootElement).Valid);
        }
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
    public void W1_CT_Published_OAuth_profiles_validate_and_downgrade_or_endpoint_substitution_is_rejected()
    {
        ConnectorDefinitionValidator validator = new();
        const string json = """
        {
          "schemaVersion":"1.0","connectorId":"generic-oauth","version":"1.0.0","displayName":"Generic OAuth",
          "bindings":{"endpoints":[{"name":"protected-api"},{"name":"oauth-authorize"},{"name":"oauth-token"}],"secrets":[{"name":"oauth-interactive-secret","kind":"opaque"},{"name":"oauth-machine-secret","kind":"opaque"}]},
          "operations":[
            {"operationId":"interactive","endpointBinding":"protected-api","method":"GET","path":"/interactive","request":{"contentType":"application/json","maximumBytes":4096},"response":{"maximumBytes":4096},"authentication":{"kind":"oauthAuthorizationCode","profileId":"partner.authorization","authorizationEndpointBinding":"oauth-authorize","tokenEndpointBinding":"oauth-token","clientId":"published-client","clientAuthMethod":"client_secret_basic","secretBinding":"oauth-interactive-secret","scopes":["orders.read"],"audience":"orders-api","redirectUri":"https://gateway.example.test/oauth/callback","pkcePolicy":"S256_REQUIRED"},"timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[]},
            {"operationId":"machine","endpointBinding":"protected-api","method":"POST","path":"/machine","request":{"contentType":"application/json","maximumBytes":4096},"response":{"maximumBytes":4096},"authentication":{"kind":"oauthClientCredentials","profileId":"partner.machine","tokenEndpointBinding":"oauth-token","clientId":"published-client","clientAuthMethod":"client_secret_basic","secretBinding":"oauth-machine-secret","scopes":["orders.write"],"audience":"orders-api","resource":"https://api.example.test/orders"},"timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[]}
          ]
        }
        """;

        using JsonDocument valid = JsonDocument.Parse(json);
        Assert.True(validator.Validate(valid.RootElement).Valid);

        using JsonDocument legacy = JsonDocument.Parse(json.Replace(",\"pkcePolicy\":\"S256_REQUIRED\"", string.Empty, StringComparison.Ordinal));
        Assert.True(validator.Validate(legacy.RootElement).Valid);

        AssertInvalid(json.Replace("S256_REQUIRED", "PLAIN", StringComparison.Ordinal));
        AssertInvalid(json.Replace("client_secret_basic", "client_secret_post", StringComparison.Ordinal));
        AssertInvalid(json.Replace("published-client", "bad\\u000Aid", StringComparison.Ordinal));
        AssertInvalid(json.Replace("published-client", "   ", StringComparison.Ordinal));
        AssertInvalid(json.Replace("published-client", "bad\\u0085id", StringComparison.Ordinal));
        AssertInvalid(json.Replace("orders-api", "bad\\u0000audience", StringComparison.Ordinal));
        AssertInvalid(json.Replace("orders-api", "bad\\u0085audience", StringComparison.Ordinal));
        AssertInvalid(json.Replace("https://gateway.example.test/oauth/callback", "https://user@gateway.example.test/oauth/callback", StringComparison.Ordinal));
        AssertInvalidRedirect(json.Replace("https://gateway.example.test/oauth/callback", "https:// /callback", StringComparison.Ordinal));
        AssertInvalid(json.Replace("https://gateway.example.test/oauth/callback", "https://gateway.example.test/oauth/callback?override=1", StringComparison.Ordinal));
        AssertInvalid(json.Replace("https://gateway.example.test/oauth/callback", "https://gateway.example.test/oauth/callback#fragment", StringComparison.Ordinal));
        using JsonDocument unknownEndpoint = JsonDocument.Parse(json.Replace("\"oauth-token\",\"clientId\"", "\"missing-token\",\"clientId\"", StringComparison.Ordinal));
        ConnectorValidationResult endpointResult = validator.Validate(unknownEndpoint.RootElement);
        Assert.False(endpointResult.Valid);
        Assert.Contains(endpointResult.Issues, issue => issue.Code == "BGW-CONNECTOR-ENDPOINT-BINDING-UNKNOWN");

        void AssertInvalid(string candidate)
        {
            using JsonDocument document = JsonDocument.Parse(candidate);
            Assert.False(validator.Validate(document.RootElement).Valid);
        }

        void AssertInvalidRedirect(string candidate)
        {
            using JsonDocument document = JsonDocument.Parse(candidate);
            ConnectorValidationResult result = validator.Validate(document.RootElement);
            Assert.False(result.Valid);
            Assert.Contains(result.Issues, issue => issue.Code == "BGW-CONNECTOR-OAUTH-REDIRECT-URI-INVALID");
        }
    }

    [Fact]
    public void W1_UT_OAuth_authority_endpoints_are_complete_in_approval_dependencies_digest_and_risks()
    {
        ConnectorDefinitionValidator validator = new();
        using JsonDocument document = JsonDocument.Parse("""
        {
          "schemaVersion":"1.0","connectorId":"generic-oauth","version":"1.0.0","displayName":"Generic OAuth",
          "bindings":{"endpoints":[{"name":"protected-api"},{"name":"oauth-authorize"},{"name":"oauth-token"}],"secrets":[{"name":"oauth-secret","kind":"opaque"}]},
          "operations":[
            {"operationId":"interactive","endpointBinding":"protected-api","method":"GET","path":"/resource","request":{"contentType":"application/json","maximumBytes":4096},"response":{"maximumBytes":4096},"authentication":{"kind":"oauthAuthorizationCode","profileId":"oauth.profile","authorizationEndpointBinding":"oauth-authorize","tokenEndpointBinding":"oauth-token","clientId":"client","clientAuthMethod":"client_secret_basic","secretBinding":"oauth-secret","scopes":["read"],"redirectUri":"https://gateway.example.test/callback","pkcePolicy":"S256_REQUIRED"},"timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[]}
          ]
        }
        """);
        ValidatedConnectorDefinition validated = validator.ValidateRequired(document.RootElement);
        Guid connectorId = Guid.NewGuid();
        Guid versionId = Guid.NewGuid();
        Guid environmentId = Guid.NewGuid();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        ConnectorVersionRecord version = new(versionId, connectorId, "generic-oauth", "1.0.0", "1.0", ConnectorVersionState.Published,
            validated.CanonicalJson, Convert.FromHexString(validated.ChecksumSha256), "test", now, 1, now, now);
        ProviderResourceBinding secret = new("synthetic", "Synthetic", "synthetic", "oauth-client-secret", ProviderResourceType.Secret, "OAuth secret",
            environmentId, "generic-oauth", "interactive", null, 1, null, null, new string('A', 64));
        ConnectorBindingSet binding = new(Guid.NewGuid(), connectorId, versionId, environmentId,
            new Dictionary<string, Uri>(StringComparer.Ordinal)
            {
                ["protected-api"] = new("https://api.example.test/base/"),
                ["oauth-authorize"] = new("https://identity.example.test/authorize?safe=1"),
                ["oauth-token"] = new("https://identity.example.test/token")
            },
            new Dictionary<string, ProviderResourceBinding>(StringComparer.Ordinal) { ["oauth-secret"] = secret },
            new Dictionary<string, ProviderResourceBinding>(StringComparer.Ordinal), 3, "binding-checksum", ConnectorBindingState.Active, now, "test");

        ApprovalReviewResult review = ConnectorApprovalArtifacts.Create(version, [binding]);
        ApprovalOperationReview operation = Assert.Single(review.Artifact.Operations);
        Assert.Equal(["oauth-authorize", "oauth-token"], operation.BindingDependencies.AuthorityEndpointBindingIds);
        Assert.Collection(operation.AuthorityEndpoints.OrderBy(value => value.Role, StringComparer.Ordinal),
            authorization => { Assert.Equal("authorization", authorization.Role); Assert.Equal("identity.example.test", authorization.Endpoint.Hostname); Assert.Equal("?safe=1", authorization.Endpoint.Query); Assert.Equal("GET", Assert.Single(authorization.Endpoint.AllowedMethods)); },
            token => { Assert.Equal("token", token.Role); Assert.Equal("/token", token.Endpoint.Path); Assert.Equal("POST", Assert.Single(token.Endpoint.AllowedMethods)); });
        Assert.Contains(review.RiskIndicators, value => value.Code == "PUBLIC_INTERNET_DESTINATION");

        Dictionary<string, Uri> changedEndpoints = binding.Endpoints.ToDictionary(value => value.Key, value => value.Value, StringComparer.Ordinal);
        changedEndpoints["oauth-token"] = new("https://rotated.example.test/token");
        ApprovalReviewResult changed = ConnectorApprovalArtifacts.Create(version, [binding with { Endpoints = changedEndpoints }], review.Artifact);
        Assert.NotEqual(review.DigestSha256, changed.DigestSha256);
        Assert.Contains(changed.RiskIndicators, value => value.Code == "HOSTNAME_CHANGED" && value.Path.Contains("authorityEndpoints", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Wave1_CT_opaque_and_composed_SOAP_profiles_are_schema_catalog_and_checksum_publishable()
    {
        ConnectorDefinitionValidator validator = new();
        using JsonDocument document = ComposedConnector();
        ValidatedConnectorDefinition validated = validator.ValidateRequired(document.RootElement);
        OperationBindingDependencies composedDependencies = ConnectorOperationBindings.Required(validated.CanonicalJson, "soap-dispatch");
        Assert.Equal(["basic-password", "basic-username", "session-secret"], composedDependencies.SecretBindingIds);
        Assert.Equal("service-endpoint", composedDependencies.EndpointBindingId);

        string actionChangedJson = document.RootElement.GetRawText().Replace("urn:synthetic:soap-dispatch", "urn:synthetic:soap-dispatch-v2", StringComparison.Ordinal);
        using JsonDocument actionChanged = JsonDocument.Parse(actionChangedJson);
        Assert.NotEqual(validated.ChecksumSha256, validator.ValidateRequired(actionChanged.RootElement).ChecksumSha256);

        AssertInvalid(document.RootElement.GetRawText().Replace("X-Session-Reference", "Authorization", StringComparison.Ordinal), "BGW-CONNECTOR-HEADER-FORBIDDEN");
        AssertInvalid(document.RootElement.GetRawText().Replace("\"contentType\":\"text/xml\"", "\"contentType\":\"application/json\"", StringComparison.Ordinal), "BGW-CONNECTOR-SOAP-CONTENT-TYPE-INVALID");
        AssertInvalid(document.RootElement.GetRawText().Replace("\"operationId\":\"soap-dispatch\",\"endpointBinding\":\"service-endpoint\",\"method\":\"POST\"", "\"operationId\":\"soap-dispatch\",\"endpointBinding\":\"service-endpoint\",\"method\":\"GET\"", StringComparison.Ordinal), "BGW-CONNECTOR-SOAP-METHOD-INVALID");
        AssertInvalid(document.RootElement.GetRawText().Replace("urn:synthetic:soap-dispatch", "urn:synthetic:soap-dispatch\\r\\nInjected", StringComparison.Ordinal));
        AssertInvalid(document.RootElement.GetRawText().Replace("urn:synthetic:soap-dispatch", "urn:synthetic:soap\\\"dispatch", StringComparison.Ordinal));
        AssertInvalid(document.RootElement.GetRawText().Replace("urn:synthetic:soap-dispatch", "urn:synthetic:soap\\\\dispatch", StringComparison.Ordinal));
        AssertInvalid(document.RootElement.GetRawText().Replace(",\"action\":\"urn:synthetic:soap-dispatch\"", string.Empty, StringComparison.Ordinal));
        AssertInvalid(document.RootElement.GetRawText().Replace("\"valueFormat\":\"rawOpaqueValue\"", "\"valueFormat\":\"rawOpaqueValue\",\"fixedScheme\":\"Session\"", 1, StringComparison.Ordinal), "BGW-CONNECTOR-SESSION-HEADER-FORMAT-INVALID");
        AssertInvalid(document.RootElement.GetRawText().Replace("soapBasicOpaqueSession", "unknownComposedKind", StringComparison.Ordinal));

        Guid environmentId = Guid.NewGuid();
        FixedClock clock = new();
        InMemoryConnectorConfigurationStore store = new();
        foreach ((string resourceId, string operationScope) in new[]
        {
            ("basic-username", "soap-dispatch"),
            ("basic-password", "soap-dispatch"),
            ("session-secret", "*")
        })
        {
            _ = await store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic vault", "synthetic", resourceId, ProviderResourceType.Secret,
                resourceId, environmentId, "generic-soap", operationScope, "synthetic://" + resourceId, ProviderResourceStatus.Active, null, 0, null, null, string.Empty, clock.UtcNow), TestContext.Current.CancellationToken);
        }
        PublishedConnectorCatalog catalog = new(store, validator, clock, TimeSpan.FromMinutes(5));
        ConnectorAdministrationService admin = new(store, validator, catalog, new InMemoryGatewayRegistry(), clock, new DevelopmentConnectorApprovalPolicy());
        ConnectorVersionResource version = await admin.ImportAsync(document.RootElement, null, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        version = await admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await admin.PutBindingsAsync(version.ConnectorId, new(environmentId,
            new Dictionary<string, string>(StringComparer.Ordinal) { ["service-endpoint"] = "https://soap.example.test/base/" },
            new Dictionary<string, ProviderResourceReference>(StringComparer.Ordinal)
            {
                ["basic-username"] = new("synthetic", "basic-username", ProviderResourceType.Secret),
                ["basic-password"] = new("synthetic", "basic-password", ProviderResourceType.Secret),
                ["session-secret"] = new("synthetic", "session-secret", ProviderResourceType.Secret)
            }), "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorVersionRecord stored = await store.GetVersionAsync(version.ConnectorId, version.Version, TestContext.Current.CancellationToken) ?? throw new InvalidOperationException();
        ConnectorBindingSet publishedBinding = Assert.Single((await store.ListBindingsPageAsync(stored.Id, 0, 10, environmentId, TestContext.Current.CancellationToken)).Items);
        ApprovalReviewResult review = ConnectorApprovalArtifacts.Create(stored, [publishedBinding]);
        Assert.Equal(
            ["opaque-session-http", "composed-soap"],
            review.Artifact.Operations.Select(value => value.ExecutionStrategy).ToArray());
        ValidatedConnectorDefinition changedDefinition = validator.ValidateRequired(actionChanged.RootElement);
        ApprovalReviewResult changedReview = ConnectorApprovalArtifacts.Create(stored with
        {
            CanonicalJson = changedDefinition.CanonicalJson,
            ChecksumSha256 = Convert.FromHexString(changedDefinition.ChecksumSha256)
        }, [publishedBinding], review.Artifact);
        Assert.NotEqual(review.DigestSha256, changedReview.DigestSha256);
        Assert.Contains(changedReview.Diff, change => change.Path.EndsWith("/canonicalDefinitionChecksumSha256", StringComparison.Ordinal));
        version = await admin.PublishAsync(version.ConnectorId, version.Version, version.RowVersion, 0, "tester", Guid.NewGuid(), TestContext.Current.CancellationToken);

        GatewayOperationDefinition opaque = await catalog.GetRequiredAsync("generic-soap", "opaque-http", environmentId, TestContext.Current.CancellationToken);
        GatewayOperationDefinition composed = await catalog.GetRequiredAsync("generic-soap", "soap-dispatch", environmentId, TestContext.Current.CancellationToken);
        Assert.Equal(GatewayAuthenticationKind.OpaqueSessionHttp, opaque.Authentication);
        Assert.Equal(GatewayAuthenticationKind.SoapBasicOpaqueSession, composed.Authentication);
        Assert.Null(opaque.ExecutionStrategy);
        Assert.Null(composed.ExecutionStrategy);
        Assert.Equal("opaque-session-http", ConnectorExecutionStrategyKeys.Resolve(opaque).Value);
        Assert.Equal("composed-soap", ConnectorExecutionStrategyKeys.Resolve(composed).Value);
        Assert.Equal("X-Session-Reference", composed.ApiKeyHeaderName);
        Assert.Equal("1.0.0", version.Version);

        PublishedConnectorAccessContext access = new(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "soap-dispatch");
        AuthorizedPublishedOperation authorized = await ((IAuthorizedPublishedOperationCatalog)catalog).GetRequiredAuthorizedAsync(
            "generic-soap", "soap-dispatch", environmentId, access, TestContext.Current.CancellationToken);
        PublishedConnectorSnapshot snapshot = await store.GetPublishedSnapshotAsync(
            "generic-soap", environmentId, access, TestContext.Current.CancellationToken)
            ?? throw new InvalidOperationException("Published composed snapshot was unavailable.");
        Assert.True(authorized.Authority.Matches(snapshot));
        Assert.Equal(snapshot.Version.Id, authorized.Authority.VersionId);
        Assert.Equal(snapshot.Stamp.PublicationRevision, authorized.Authority.PublicationRevision);
        Assert.Equal(snapshot.Bindings.Revision, authorized.Authority.BindingRevision);
        Assert.Equal(snapshot.Bindings.ChecksumSha256, authorized.Authority.BindingChecksumSha256);
        Assert.Equal(snapshot.Stamp.ResourceStampSha256, authorized.Authority.ResourceStampSha256);
        Assert.Equal(Convert.ToHexString(snapshot.Version.ChecksumSha256), authorized.Authority.CanonicalChecksumSha256);
        Assert.Equal("soap-dispatch", authorized.Authority.OperationId);
        Assert.Equal("composed-soap", authorized.Authority.ExecutionStrategyKey.Value);
        Assert.False(authorized.Authority.Matches(snapshot with
        {
            Stamp = snapshot.Stamp with { PublicationRevision = snapshot.Stamp.PublicationRevision + 1 }
        }));
        Assert.False(authorized.Authority.Matches(snapshot with
        {
            Stamp = snapshot.Stamp with { ResourceStampSha256 = snapshot.Stamp.ResourceStampSha256 + "-rotated" }
        }));
        string strategyChangedCanonical = snapshot.Version.CanonicalJson.Replace(
            "\"operationId\":\"soap-dispatch\",",
            "\"operationId\":\"soap-dispatch\",\"executionStrategy\":\"synthetic-capability-bridge\",",
            StringComparison.Ordinal);
        Assert.False(authorized.Authority.Matches(snapshot with
        {
            Version = snapshot.Version with
            {
                CanonicalJson = strategyChangedCanonical,
                ChecksumSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(strategyChangedCanonical))
            }
        }));

        void AssertInvalid(string candidate, string? expectedCode = null)
        {
            using JsonDocument invalid = JsonDocument.Parse(candidate);
            ConnectorValidationResult result = validator.Validate(invalid.RootElement);
            Assert.False(result.Valid);
            if (expectedCode is not null) Assert.Contains(result.Issues, issue => issue.Code == expectedCode);
        }
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
    public async Task M5_UT_Runtime_cache_and_locator_material_are_scoped_to_invoked_operation()
    {
        Fixture fixture = new();
        DateTimeOffset now = fixture.Clock.UtcNow;
        CertificatePublicMetadata metadata = new(new string('B', 64), "CN=operation-b", "CN=synthetic-ca", now.AddDays(-1), now.AddDays(60), "ECDSA", 256, "2");
        ProviderResourceCatalogRecord secretB = await fixture.Store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic vault", "synthetic", "api-key-b", ProviderResourceType.Secret, "Operation B API key", fixture.EnvironmentId, "sample-secure-service", "check-status", "synthetic://api-key-b", ProviderResourceStatus.Active, null, 0, null, null, string.Empty, now), TestContext.Current.CancellationToken);
        _ = await fixture.Store.RegisterProviderResourceAsync(new(Guid.NewGuid(), "synthetic", "Synthetic vault", "synthetic", "client-certificate-b", ProviderResourceType.ClientCertificate, "Operation B certificate", fixture.EnvironmentId, "sample-secure-service", "check-status", "synthetic://client-cert-b", ProviderResourceStatus.Active, null, 0, 2, metadata, string.Empty, now), TestContext.Current.CancellationToken);

        using JsonDocument definition = CrossOperationSample();
        ConnectorVersionResource version = await fixture.ImportAsync(definition);
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        ConnectorBindingRequest request = new(fixture.EnvironmentId,
            new Dictionary<string, string> { ["sample-vendor-endpoint"] = "https://vendor-a.example.test/", ["status-endpoint"] = "https://vendor-b.example.test/" },
            new Dictionary<string, ProviderResourceReference> { ["sample-vendor-api-key"] = SecretReference(), ["status-api-key"] = new("synthetic", "api-key-b", ProviderResourceType.Secret) },
            CertificateResources: new Dictionary<string, ProviderResourceReference> { ["sample-vendor-client-certificate"] = CertificateReference(), ["status-client-certificate"] = new("synthetic", "client-certificate-b", ProviderResourceType.ClientCertificate, PublicMetadataRevision: 2) });
        _ = await fixture.Admin.PutBindingsAsync(version.ConnectorId, request, "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        version = await fixture.Admin.PublishAsync(version.ConnectorId, version.Version, version.RowVersion, 0, "approver", Guid.NewGuid(), TestContext.Current.CancellationToken);

        PublishedConnectorAccessContext accessA = new(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "submit");
        GatewayOperationDefinition operationA = await fixture.Catalog.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, accessA, TestContext.Current.CancellationToken);
        Assert.Equal("synthetic://api-key", operationA.ApiKeySecretReference);
        Assert.Equal("synthetic://client-cert", operationA.ClientCertificateReference);
        Assert.DoesNotContain("api-key-b", operationA.ApiKeySecretReference, StringComparison.Ordinal);

        PublishedConnectorAccessContext accessB = accessA with { OperationId = "check-status" };
        GatewayOperationDefinition operationB = await fixture.Catalog.GetRequiredAsync(version.ConnectorId, "check-status", fixture.EnvironmentId, accessB, TestContext.Current.CancellationToken);
        Assert.Equal("synthetic://api-key-b", operationB.ApiKeySecretReference);
        Assert.Equal("synthetic://client-cert-b", operationB.ClientCertificateReference);

        Guid tenantId = Guid.NewGuid(); Guid applicationId = Guid.NewGuid(); Guid installationId = accessA.InstallationId;
        await fixture.Registry.AddTenantAsync(new(tenantId, "cross-op", "Cross operation", TenantStatus.Active, now), TestContext.Current.CancellationToken);
        await fixture.Registry.AddApplicationAsync(new(applicationId, "cross-op", "Cross operation", ApplicationStatus.Active, "3.0.0", null, now), TestContext.Current.CancellationToken);
        await fixture.Registry.AddEnvironmentAsync(new(fixture.EnvironmentId, "cross-op", "Cross operation", false), TestContext.Current.CancellationToken);
        await fixture.Registry.AddInstallationAsync(new(installationId, tenantId, applicationId, fixture.EnvironmentId, InstallationStatus.Active, "3.0.0", now), TestContext.Current.CancellationToken);
        await fixture.Registry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, version.ConnectorId, "submit", true, now.AddMinutes(-1)), TestContext.Current.CancellationToken);
        await fixture.Registry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, version.ConnectorId, "check-status", true, now.AddMinutes(-1)), TestContext.Current.CancellationToken);
        CountingProvider provider = new(); CountingTransport transport = new();
        RestrictedEgressService runtime = new(fixture.Registry, fixture.Catalog, provider, provider, new PublicResolver(), transport, fixture.Clock);
        using X509Certificate2 identityCertificate = provider.Certificate;
        RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, fixture.EnvironmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active, Guid.NewGuid(), CredentialStatus.Active, identityCertificate.RawData, now.AddMinutes(-1), now.AddHours(1), "3.0.0", null);
        GatewayInvokeRequest invocation = new("1.0", new("application/json", "utf8", "{}"), Guid.NewGuid());
        _ = await runtime.InvokeAsync(new(identity, invocation.CorrelationId), version.ConnectorId, "submit", invocation, TestContext.Current.CancellationToken);
        Assert.Equal(1, provider.Count("synthetic://api-key")); Assert.Equal(1, provider.Count("synthetic://client-cert"));
        Assert.Equal(0, provider.Count("synthetic://api-key-b")); Assert.Equal(0, provider.Count("synthetic://client-cert-b"));
        GatewayInvokeRequest invocationB = invocation with { CorrelationId = Guid.NewGuid() };
        _ = await runtime.InvokeAsync(new(identity, invocationB.CorrelationId), version.ConnectorId, "check-status", invocationB, TestContext.Current.CancellationToken);
        Assert.Equal(1, provider.Count("synthetic://api-key")); Assert.Equal(1, provider.Count("synthetic://client-cert"));
        Assert.Equal(1, provider.Count("synthetic://api-key-b")); Assert.Equal(1, provider.Count("synthetic://client-cert-b"));

        _ = await fixture.Store.RegisterProviderResourceAsync(secretB with { Id = Guid.NewGuid(), ProviderReference = "synthetic://api-key-b-rotated", Revision = 0, ChecksumSha256 = string.Empty, CreatedAt = now.AddMinutes(1) }, TestContext.Current.CancellationToken);
        Assert.Equal("synthetic://api-key", (await fixture.Catalog.GetRequiredAsync(version.ConnectorId, "submit", fixture.EnvironmentId, accessA, TestContext.Current.CancellationToken)).ApiKeySecretReference);
        GatewayException staleB = await Assert.ThrowsAsync<GatewayException>(() => fixture.Catalog.GetRequiredAsync(version.ConnectorId, "check-status", fixture.EnvironmentId, accessB, TestContext.Current.CancellationToken));
        Assert.Equal("BGW-PROVIDER-RESOURCE-REVISION-STALE", staleB.Code);
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
        Assert.Equal("submit", operation.BindingDependencies.OperationId);
        Assert.Equal("default-http", operation.ExecutionStrategy);
        Assert.Equal("sample-vendor-endpoint", operation.BindingDependencies.EndpointBindingId);
        Assert.Equal(["sample-vendor-api-key"], operation.BindingDependencies.SecretBindingIds);
        Assert.Equal(["sample-vendor-client-certificate"], operation.BindingDependencies.CertificateBindingIds);
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

    [Fact]
    public async Task Wave1_UT_previously_valid_v1_allowed_client_header_still_loads_and_executes_while_new_auth_placement_denies_it()
    {
        Fixture fixture = new();
        using JsonDocument sample = Sample();
        using JsonDocument legacy = JsonDocument.Parse(sample.RootElement.GetRawText().Replace("\"allowedClientHeaders\": []", "\"allowedClientHeaders\": [\"SOAPAction\"]", StringComparison.Ordinal));
        ValidatedConnectorDefinition validatedLegacy = fixture.Validator.ValidateRequired(legacy.RootElement);
        _ = fixture.Validator.ParseStored(validatedLegacy.CanonicalJson, Convert.FromHexString(validatedLegacy.ChecksumSha256));

        ConnectorVersionResource version = await fixture.ImportAsync(legacy);
        version = await fixture.Admin.ValidateStoredAsync(version.ConnectorId, version.Version, version.RowVersion, "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await fixture.Admin.PutBindingsAsync(version.ConnectorId, BindingRequest(fixture.EnvironmentId, "https://vendor.example.test/"), "editor", Guid.NewGuid(), TestContext.Current.CancellationToken);
        _ = await fixture.Admin.PublishAsync(version.ConnectorId, version.Version, version.RowVersion, 0, "approver", Guid.NewGuid(), TestContext.Current.CancellationToken);

        DateTimeOffset now = fixture.Clock.UtcNow;
        Guid tenantId = Guid.NewGuid(); Guid applicationId = Guid.NewGuid(); Guid installationId = Guid.NewGuid();
        await fixture.Registry.AddTenantAsync(new(tenantId, "legacy-v1", "Legacy v1", TenantStatus.Active, now), TestContext.Current.CancellationToken);
        await fixture.Registry.AddApplicationAsync(new(applicationId, "legacy-v1", "Legacy v1", ApplicationStatus.Active, "3.0.0", null, now), TestContext.Current.CancellationToken);
        await fixture.Registry.AddEnvironmentAsync(new(fixture.EnvironmentId, "legacy-v1", "Legacy v1", false), TestContext.Current.CancellationToken);
        await fixture.Registry.AddInstallationAsync(new(installationId, tenantId, applicationId, fixture.EnvironmentId, InstallationStatus.Active, "3.0.0", now), TestContext.Current.CancellationToken);
        await fixture.Registry.AddGrantAsync(new(Guid.NewGuid(), installationId, tenantId, version.ConnectorId, "submit", true, now.AddMinutes(-1)), TestContext.Current.CancellationToken);
        CountingProvider provider = new(); CountingTransport transport = new();
        RestrictedEgressService runtime = new(fixture.Registry, fixture.Catalog, provider, provider, new PublicResolver(), transport, fixture.Clock);
        RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, fixture.EnvironmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
            Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], now.AddMinutes(-1), now.AddHours(1), "3.0.0", null);
        GatewayInvokeRequest invocation = new("1.0", new("application/json", "utf8", "{}"), Guid.NewGuid());
        _ = await runtime.InvokeAsync(new(identity, invocation.CorrelationId), version.ConnectorId, "submit", invocation, TestContext.Current.CancellationToken);
        Assert.Equal(1, transport.CallCount);

        using JsonDocument composed = ComposedConnector();
        using JsonDocument forbiddenPlacement = JsonDocument.Parse(composed.RootElement.GetRawText().Replace(
            "\"usernameBinding\":\"basic-username\",\"passwordBinding\":\"basic-password\",\"secretBinding\":\"session-secret\",\"headerName\":\"X-Session-Reference\"",
            "\"usernameBinding\":\"basic-username\",\"passwordBinding\":\"basic-password\",\"secretBinding\":\"session-secret\",\"headerName\":\"SOAPAction\"", StringComparison.Ordinal));
        ConnectorValidationResult denied = fixture.Validator.Validate(forbiddenPlacement.RootElement);
        Assert.False(denied.Valid);
        Assert.Contains(denied.Issues, issue => issue.Code == "BGW-CONNECTOR-HEADER-FORBIDDEN" && issue.Location.Contains("authentication.headerName", StringComparison.Ordinal));
    }

    private static JsonDocument Sample() => JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Samples", "sample-secure-service.connector.json")));

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "BrokerGateway.slnx")) ||
                File.Exists(Path.Combine(current.FullName, "BrokerGateway.Core.slnx"))) return current.FullName;
            current = current.Parent;
        }
        throw new InvalidOperationException("TEST_REPOSITORY_ROOT_NOT_FOUND");
    }

    private static JsonDocument CrossOperationSample() => JsonDocument.Parse("""
        {
          "schemaVersion":"1.0","connectorId":"sample-secure-service","version":"1.0.0","displayName":"Cross-operation connector","description":"Synthetic least-privilege fixture.",
          "bindings":{"endpoints":[{"name":"sample-vendor-endpoint"},{"name":"status-endpoint"}],"secrets":[
            {"name":"sample-vendor-api-key","kind":"opaque"},{"name":"sample-vendor-client-certificate","kind":"clientCertificate"},
            {"name":"status-api-key","kind":"opaque"},{"name":"status-client-certificate","kind":"clientCertificate"}]},
          "operations":[
            {"operationId":"submit","endpointBinding":"sample-vendor-endpoint","method":"POST","path":"/vendor/orders","request":{"contentType":"application/json","maximumBytes":1048576},"response":{"maximumBytes":1048576},"authentication":{"kind":"apiKeyAndMtls","secretBinding":"sample-vendor-api-key","headerName":"X-Vendor-Api-Key","certificateBinding":"sample-vendor-client-certificate"},"timeoutMs":30000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0},
            {"operationId":"check-status","endpointBinding":"status-endpoint","method":"POST","path":"/vendor/status","request":{"contentType":"application/json","maximumBytes":1048576},"response":{"maximumBytes":1048576},"authentication":{"kind":"apiKeyAndMtls","secretBinding":"status-api-key","headerName":"X-Vendor-Api-Key","certificateBinding":"status-client-certificate"},"timeoutMs":30000,"redirectPolicy":"deny","allowedClientHeaders":[],"idempotent":false,"maximumRetries":0}
          ]
        }
        """);

    private static JsonDocument ComposedConnector() => JsonDocument.Parse("""
        {
          "schemaVersion":"1.0","connectorId":"generic-soap","version":"1.0.0","displayName":"Generic composed SOAP",
          "bindings":{"endpoints":[{"name":"service-endpoint"}],"secrets":[{"name":"basic-username","kind":"username"},{"name":"basic-password","kind":"password"},{"name":"session-secret","kind":"opaque"}]},
          "operations":[
            {"operationId":"opaque-http","endpointBinding":"service-endpoint","method":"POST","path":"/opaque","request":{"contentType":"application/json","maximumBytes":4096},"response":{"maximumBytes":4096},"authentication":{"kind":"opaqueSessionHttp","policyId":"opaque-policy","sessionProfileId":"opaque-session","secretBinding":"session-secret","headerName":"X-Session-Reference","valueFormat":"rawOpaqueValue"},"timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[]},
            {"operationId":"soap-dispatch","endpointBinding":"service-endpoint","method":"POST","path":"/soap","request":{"contentType":"text/xml","maximumBytes":1048576},"response":{"maximumBytes":1048576},"authentication":{"kind":"soapBasicOpaqueSession","policyId":"composed-policy","sessionProfileId":"opaque-session","usernameBinding":"basic-username","passwordBinding":"basic-password","secretBinding":"session-secret","headerName":"X-Session-Reference","valueFormat":"rawOpaqueValue","soapHttp":{"version":"1.1","action":"urn:synthetic:soap-dispatch"}},"timeoutMs":5000,"redirectPolicy":"deny","allowedClientHeaders":[]}
          ]
        }
        """);

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

    private sealed class PublicResolver : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { IPAddress.Parse("203.0.113.10") });
    }

    private sealed class CountingTransport : IRestrictedTransport
    {
        public int CallCount { get; private set; }
        public Task<ExternalResponse> SendAsync(HttpRequestMessage request, IReadOnlyList<IPAddress> approvedAddresses, X509Certificate2? clientCertificate, TimeSpan timeout, long maximumResponseBytes, CancellationToken cancellationToken) =>
            Task.FromResult(Count());

        private ExternalResponse Count()
        {
            CallCount++;
            return new(200, "application/json", "{}"u8.ToArray());
        }
    }

    private sealed class CountingProvider : ISecretValueProvider, IClientCertificateProvider
    {
        private readonly Dictionary<string, int> counts = new(StringComparer.Ordinal);
        private readonly X509Certificate2 certificate;

        public CountingProvider()
        {
            using RSA key = RSA.Create(2048);
            CertificateRequest request = new("CN=operation-scoped", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        }

        public X509Certificate2 Certificate => X509CertificateLoader.LoadCertificate(certificate.RawData);
        public int Count(string reference) => counts.GetValueOrDefault(reference);
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) { counts[logicalReference] = Count(logicalReference) + 1; return Task.FromResult("synthetic"); }
        public Task<X509Certificate2> GetClientCertificateAsync(string logicalReference, CancellationToken cancellationToken) { counts[logicalReference] = Count(logicalReference) + 1; return Task.FromResult(X509CertificateLoader.LoadCertificate(certificate.RawData)); }
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

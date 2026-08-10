using System.Xml.Linq;
using System.Text.RegularExpressions;
using Xunit;

namespace SecureIntegration.Architecture.Tests;

public sealed class HttpOAuthBoundaryTests
{
    private static readonly string Root = FindRepositoryRoot();

    [Fact]
    public void M6_ARCH_HTTP_OAuth_module_remains_outbound_provider_neutral_and_uses_restricted_transport()
    {
        string directory = Path.Combine(Root, "src", "Gateway", "Gateway.ConnectorRuntime.Auth.Http");
        string source = string.Join('\n', Directory.EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories).Select(File.ReadAllText));
        XDocument project = XDocument.Load(Path.Combine(directory, "Gateway.ConnectorRuntime.Auth.Http.csproj"));
        string[] references = project.Descendants("ProjectReference").Select(element => (string?)element.Attribute("Include") ?? string.Empty).ToArray();

        Assert.Contains("IRestrictedTransport", source, StringComparison.Ordinal);
        Assert.Contains("ISecretValueProvider", source, StringComparison.Ordinal);
        Assert.DoesNotContain("new HttpClient", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ILogger", source, StringComparison.Ordinal);
        Assert.DoesNotContain("InstallationKind", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Keycloak", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(references, reference => reference.Contains("Infrastructure", StringComparison.OrdinalIgnoreCase) || reference.Contains("Broker", StringComparison.OrdinalIgnoreCase) || reference.Contains("Admin", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void M6_ARCH_cache_identity_covers_frozen_security_dimensions_and_has_no_Redis_dependency()
    {
        string source = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.ConnectorRuntime.Auth.Http", "OAuth", "OAuthAuthorizationCodeClient.cs"));
        foreach (string dimension in new[] { "TenantId", "InstallationId", "ApplicationId", "EnvironmentId", "ConnectorVersionId", "ConnectorVersion", "AuthBindingRevision", "EndpointRevision", "Policy", "TokenEndpoint", "ClientId", "ClientAuthenticationMethod", "Scopes", "Audience", "Resource", "SecretRevision", "ResourceStamp" })
            Assert.Contains(dimension, source, StringComparison.Ordinal);
        Assert.DoesNotContain("Redis", source, StringComparison.OrdinalIgnoreCase);
        Assert.Single(Regex.Matches(source, @"Dictionary<string, TokenSession>", RegexOptions.CultureInvariant).Cast<Match>());
    }

    [Fact]
    public void M6_ARCH_authority_and_bearer_surface_is_capability_based_destination_bound_and_has_no_server_side_browser_adapter()
    {
        string directory = Path.Combine(Root, "src", "Gateway", "Gateway.ConnectorRuntime.Auth.Http");
        string contracts = File.ReadAllText(Path.Combine(directory, "OAuth", "OAuthContracts.cs"));
        string client = File.ReadAllText(Path.Combine(directory, "OAuth", "OAuthAuthorizationCodeClient.cs"));
        string resolver = File.ReadAllText(Path.Combine(directory, "OAuth", "PublishedOAuthAuthorityResolver.cs"));

        Assert.Contains("internal sealed class OutboundAuthContext", contracts, StringComparison.Ordinal);
        Assert.Contains("internal sealed class OAuthAuthorizationCodeProfile", contracts, StringComparison.Ordinal);
        Assert.Contains("internal sealed class OAuthClientCredentialsProfile", contracts, StringComparison.Ordinal);
        Assert.Contains("OAuthPkcePolicy", contracts, StringComparison.Ordinal);
        Assert.Contains("internal OAuthAuthorizedInvocation(", contracts, StringComparison.Ordinal);
        Assert.Contains("internal OAuthResolvedExecutionContext(", contracts, StringComparison.Ordinal);
        Assert.Contains("PublishedOAuthAuthorityResolver", resolver, StringComparison.Ordinal);
        Assert.Contains("PublishedConnectorSnapshot", resolver, StringComparison.Ordinal);
        Assert.Contains("ScopedOAuthSecretCapability", resolver, StringComparison.Ordinal);
        Assert.Contains("SendAuthenticatedAsync", client, StringComparison.Ordinal);
        Assert.DoesNotContain("ApplyBearerAsync", client, StringComparison.Ordinal);
        Assert.DoesNotMatch(new Regex(@"public\s+(?:async\s+)?[^\r\n(]+\([^)]*HttpRequestMessage", RegexOptions.CultureInvariant), client);
        Assert.Contains("external-user-agent-navigation", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("new HttpClient", client, StringComparison.Ordinal);
    }

    [Fact]
    public void W1_ARCH_PKCE_and_client_credentials_are_server_owned_S256_only_and_share_restricted_token_acquisition()
    {
        string directory = Path.Combine(Root, "src", "Gateway", "Gateway.ConnectorRuntime.Auth.Http", "OAuth");
        string contracts = File.ReadAllText(Path.Combine(directory, "OAuthContracts.cs"));
        string client = File.ReadAllText(Path.Combine(directory, "OAuthAuthorizationCodeClient.cs"));
        string resolver = File.ReadAllText(Path.Combine(directory, "PublishedOAuthAuthorityResolver.cs"));

        Assert.Contains("S256_REQUIRED", resolver, StringComparison.Ordinal);
        Assert.Contains("code_challenge_method", client, StringComparison.Ordinal);
        Assert.Contains("S256", client, StringComparison.Ordinal);
        Assert.Contains("AcquireClientCredentialsAsync", client, StringComparison.Ordinal);
        Assert.Contains("IRestrictedTransport", client, StringComparison.Ordinal);
        Assert.Contains("ScopedOAuthSecretCapability", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("client_secret_post", contracts + client + resolver, StringComparison.Ordinal);
        Assert.DoesNotMatch(new Regex(@"public\s+[^\r\n(]+\([^)]*(?:codeVerifier|codeChallenge|clientSecret|tokenEndpoint|secretReference)", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase), contracts + client + resolver);

        string builtInPipeline = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Application", "OperationServices.cs"));
        int executionKeyResolution = builtInPipeline.IndexOf("ConnectorExecutionStrategyKeys.Resolve(operation)", StringComparison.Ordinal);
        int exactStrategyLookup = builtInPipeline.IndexOf("executionStrategyRegistry.Required(strategyKey)", StringComparison.Ordinal);
        int dnsResolution = builtInPipeline.IndexOf("resolver.ResolveAsync(operation.Endpoint.DnsSafeHost", StringComparison.Ordinal);
        Assert.InRange(executionKeyResolution, 0, exactStrategyLookup - 1);
        Assert.InRange(exactStrategyLookup, executionKeyResolution + 1, dnsResolution - 1);
        Assert.DoesNotContain("oauth-authorization-code", builtInPipeline, StringComparison.Ordinal);
        Assert.DoesNotContain("oauth-client-credentials", builtInPipeline, StringComparison.Ordinal);
    }

    [Fact]
    public void M6_ARCH_Core_export_includes_every_project_added_to_the_Core_solution()
    {
        string allowlist = File.ReadAllText(Path.Combine(Root, "eng", "open-source-core.allowlist"));
        string solution = File.ReadAllText(Path.Combine(Root, "BrokerGateway.Core.slnx"));
        Assert.Contains("tools/m6/SyntheticOAuthServer/", allowlist, StringComparison.Ordinal);
        Assert.Contains("tools/m6/SyntheticOAuthServer/SyntheticOAuthServer.csproj", solution, StringComparison.Ordinal);
        Assert.Contains("src/", allowlist, StringComparison.Ordinal);
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "BrokerGateway.slnx")) || File.Exists(Path.Combine(directory.FullName, "BrokerGateway.Core.slnx"))) return directory.FullName;
            directory = directory.Parent;
        }
        throw new DirectoryNotFoundException("Repository root not found.");
    }
}

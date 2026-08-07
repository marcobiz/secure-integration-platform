using System.Xml.Linq;
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
        foreach (string dimension in new[] { "TenantId", "InstallationId", "ApplicationId", "EnvironmentId", "ConnectorVersionId", "ConnectorVersion", "AuthBindingRevision", "EndpointRevision", "ClientId", "Scopes", "Audience", "SecretRevision", "ResourceStamp" })
            Assert.Contains(dimension, source, StringComparison.Ordinal);
        Assert.DoesNotContain("Redis", source, StringComparison.OrdinalIgnoreCase);
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

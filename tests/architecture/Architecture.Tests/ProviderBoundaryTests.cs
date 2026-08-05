using System.Xml.Linq;
using Xunit;

namespace SecureIntegration.Architecture.Tests;

public sealed class ProviderBoundaryTests
{
    private static readonly string Root = FindRepositoryRoot();

    [Fact]
    public void Core_solution_excludes_deployment_packs_and_cloud_packages()
    {
        string solution = File.ReadAllText(Path.Combine(Root, "BrokerGateway.Core.slnx"));
        Assert.DoesNotContain("packs/deployment", solution, StringComparison.OrdinalIgnoreCase);

        string centralPackages = File.ReadAllText(Path.Combine(Root, "Directory.Packages.props"));
        Assert.DoesNotContain("Azure.", centralPackages, StringComparison.Ordinal);

        foreach (string project in Directory.EnumerateFiles(Path.Combine(Root, "src"), "*.csproj", SearchOption.AllDirectories))
        {
            XDocument document = XDocument.Load(project);
            string[] packageNames = document.Descendants("PackageReference").Select(element => (string?)element.Attribute("Include") ?? string.Empty).ToArray();
            Assert.DoesNotContain(packageNames, name => name.StartsWith("Azure.", StringComparison.Ordinal));
            string[] references = document.Descendants("ProjectReference").Select(element => (string?)element.Attribute("Include") ?? string.Empty).ToArray();
            Assert.DoesNotContain(references, reference => reference.Contains("packs", StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public void Core_source_contains_no_provider_specific_Azure_types_or_generic_IKms()
    {
        string[] forbidden = ["using Azure", "Azure.Security", "Azure.Identity", "ManagedIdentityCredential", "SecretClient", "interface IKms"];
        foreach (string file in Directory.EnumerateFiles(Path.Combine(Root, "src"), "*.cs", SearchOption.AllDirectories).Where(path => !IsGenerated(path)))
        {
            string content = File.ReadAllText(file);
            foreach (string token in forbidden) Assert.DoesNotContain(token, content, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Provider_contracts_are_capability_specific()
    {
        string contracts = File.ReadAllText(Path.Combine(Root, "src", "Providers", "Abstractions", "ProviderContracts.cs"));
        Assert.Contains("ISecretValueProvider", contracts, StringComparison.Ordinal);
        Assert.Contains("IClientCertificateProvider", contracts, StringComparison.Ordinal);
        Assert.Contains("ISigningKeyProvider", contracts, StringComparison.Ordinal);
        Assert.Contains("IMacProvider", contracts, StringComparison.Ordinal);
        Assert.Contains("IProviderHealthCheck", contracts, StringComparison.Ordinal);
        Assert.Contains("IProviderCapabilitySource", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("IKms", contracts, StringComparison.Ordinal);
    }

    private static bool IsGenerated(string path) => path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) || path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase);

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (Directory.Exists(Path.Combine(current.FullName, ".git")) || File.Exists(Path.Combine(current.FullName, "BrokerGateway.Core.slnx"))) return current.FullName;
            current = current.Parent;
        }
        throw new InvalidOperationException("Repository root not found.");
    }
}

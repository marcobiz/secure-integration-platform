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
        Assert.Contains("IKeyOperationProvider", contracts, StringComparison.Ordinal);
        Assert.Contains("IMacProvider", contracts, StringComparison.Ordinal);
        Assert.Contains("IProviderHealthCheck", contracts, StringComparison.Ordinal);
        Assert.Contains("IProviderCapabilitySource", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("IKms", contracts, StringComparison.Ordinal);
    }

    [Fact]
    public void Certificate_signing_module_depends_only_on_provider_neutral_capabilities_and_has_no_handle_API()
    {
        string project = File.ReadAllText(Path.Combine(Root, "src", "Authentication", "CertificateSigning", "Authentication.CertificateSigning.csproj"));
        Assert.Contains("Providers.Abstractions", project, StringComparison.Ordinal);
        Assert.DoesNotContain("Gateway.Application", project, StringComparison.Ordinal);
        Assert.DoesNotContain("Gateway.Infrastructure", project, StringComparison.Ordinal);
        Assert.DoesNotContain("packs", project, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Azure", project, StringComparison.Ordinal);

        string contracts = File.ReadAllText(Path.Combine(Root, "src", "Authentication", "CertificateSigning", "Contracts.cs"));
        Assert.DoesNotContain("PFX", contracts, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PrivateKey", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("X509Certificate2", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("Rs256JwtProfile", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("ResolvedClientCertificate", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("IKms", contracts, StringComparison.Ordinal);

        string signer = File.ReadAllText(Path.Combine(Root, "src", "Authentication", "CertificateSigning", "Rs256JwtSigner.cs"));
        string sender = File.ReadAllText(Path.Combine(Root, "src", "Authentication", "CertificateSigning", "PurposeBoundMutualTlsSender.cs"));
        string transport = File.ReadAllText(Path.Combine(Root, "src", "Authentication", "CertificateSigning", "MutualTlsTransportContracts.cs"));
        Assert.Contains("string policyId", signer, StringComparison.Ordinal);
        Assert.DoesNotContain("Rs256JwtProfile", signer, StringComparison.Ordinal);
        Assert.Contains("string policyId", sender, StringComparison.Ordinal);
        Assert.DoesNotContain("ResolveClientCertificate", sender, StringComparison.Ordinal);
        Assert.Contains("internal X509Certificate2 TakeCertificate", transport, StringComparison.Ordinal);
        Assert.DoesNotContain("public X509Certificate2", transport, StringComparison.Ordinal);
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

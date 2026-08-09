using System.Text.RegularExpressions;
using System.Xml.Linq;
using Xunit;

namespace SecureIntegration.Architecture.Tests;

public sealed class HealthcarePackBoundaryTests
{
    private static readonly string Root = FindRepositoryRoot();

    [Fact]
    public void HC_W1_ARCH_Core_does_not_reference_Healthcare_pack()
    {
        string coreSolutionPath = Path.Combine(Root, "BrokerGateway.Core.slnx");
        string coreSolution = File.ReadAllText(coreSolutionPath);
        Assert.DoesNotContain("ConnectorPacks/Healthcare", coreSolution, StringComparison.OrdinalIgnoreCase);

        XDocument solution = XDocument.Load(coreSolutionPath);
        Queue<string> projects = new(solution.Descendants("Project")
            .Select(project => (string?)project.Attribute("Path"))
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => Path.GetFullPath(Path.Combine(Root, path!))));
        HashSet<string> visited = new(StringComparer.OrdinalIgnoreCase);

        while (projects.TryDequeue(out string? projectFile))
        {
            if (!visited.Add(projectFile)) continue;
            Assert.True(File.Exists(projectFile), $"Core project not found: {projectFile}");
            XDocument project = XDocument.Load(projectFile);
            foreach (XElement reference in project.Descendants("ProjectReference"))
            {
                string include = (string?)reference.Attribute("Include") ?? string.Empty;
                string referencedProject = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(projectFile)!, include));
                Assert.DoesNotContain(
                    $"{Path.DirectorySeparatorChar}ConnectorPacks{Path.DirectorySeparatorChar}Healthcare{Path.DirectorySeparatorChar}",
                    referencedProject,
                    StringComparison.OrdinalIgnoreCase);
                projects.Enqueue(referencedProject);
            }
        }
    }

    [Fact]
    public void HC_W1_ARCH_regional_domain_concepts_are_absent_from_Gateway_Core_source()
    {
        string gatewayRoot = Path.Combine(Root, "src", "Gateway");
        Regex forbiddenIdentifier = new(@"\b(SAR|Region|Prescription|Pharmacy|Lombardia|EmiliaRomagna)\b", RegexOptions.CultureInvariant);
        foreach (string sourceFile in Directory.EnumerateFiles(gatewayRoot, "*.cs", SearchOption.AllDirectories))
        {
            string source = File.ReadAllText(sourceFile);
            Assert.DoesNotMatch(forbiddenIdentifier, source);
        }
    }

    [Fact]
    public void HC_W1_ARCH_FSE2_domain_and_dual_JWT_concepts_are_absent_from_Core_source_and_export()
    {
        string[] coreRoots =
        [
            Path.Combine(Root, "src", "Gateway"),
            Path.Combine(Root, "src", "Broker"),
            Path.Combine(Root, "src", "Shared")
        ];
        Regex forbiddenIdentifier = new(@"\b(FSE2|FSE-JWT-Signature|DualJwt|use_subject_as_author|subject_organization_id)\b", RegexOptions.CultureInvariant);
        foreach (string coreRoot in coreRoots)
        foreach (string sourceFile in Directory.EnumerateFiles(coreRoot, "*.cs", SearchOption.AllDirectories))
            Assert.DoesNotMatch(forbiddenIdentifier, File.ReadAllText(sourceFile));

        string coreSolution = File.ReadAllText(Path.Combine(Root, "BrokerGateway.Core.slnx"));
        Assert.DoesNotContain("Healthcare.FSE2", coreSolution, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HC_W1_ARCH_Healthcare_foundation_depends_only_on_public_Core_application_contract()
    {
        string projectPath = Path.Combine(Root, "src", "ConnectorPacks", "Healthcare", "Healthcare.RegionalEPrescription", "Healthcare.RegionalEPrescription.csproj");
        XDocument project = XDocument.Load(projectPath);
        string[] references = project.Descendants("ProjectReference").Select(element => (string?)element.Attribute("Include") ?? string.Empty).ToArray();

        Assert.Single(references);
        Assert.EndsWith("Gateway.Application.csproj", references[0], StringComparison.Ordinal);
        Assert.DoesNotContain(references, reference => reference.Contains("Infrastructure", StringComparison.OrdinalIgnoreCase) || reference.Contains("Gateway.Api", StringComparison.OrdinalIgnoreCase) || reference.Contains("Broker", StringComparison.OrdinalIgnoreCase) || reference.Contains("Azure", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void HC_W1_ARCH_Healthcare_pack_does_not_reinterpret_inbound_identity()
    {
        string packRoot = Path.Combine(Root, "src", "ConnectorPacks", "Healthcare", "Healthcare.RegionalEPrescription");
        string[] forbidden = ["CertificateDer", "FindIdentityByCertificateAsync", "IGatewayRegistry", "X509Certificate", "RegisteredInstallationIdentity"];
        foreach (string sourceFile in Directory.EnumerateFiles(packRoot, "*.cs", SearchOption.AllDirectories))
        {
            string source = File.ReadAllText(sourceFile);
            foreach (string identifier in forbidden)
                Assert.DoesNotContain(identifier, source, StringComparison.Ordinal);
        }

        string coreAuthorization = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Application", "AuthorizedGatewayInvocation.cs"));
        Assert.Contains("IGatewayInvocationAuthorizer", coreAuthorization, StringComparison.Ordinal);
        Assert.Contains("AuthorizedGatewayInvocation", coreAuthorization, StringComparison.Ordinal);
    }

    [Fact]
    public void HC_W1_ARCH_FSE2_pack_depends_only_on_public_provider_neutral_edges()
    {
        string projectPath = Path.Combine(Root, "src", "ConnectorPacks", "Healthcare", "Healthcare.FSE2", "Healthcare.FSE2.csproj");
        XDocument project = XDocument.Load(projectPath);
        string[] references = project.Descendants("ProjectReference").Select(element => (string?)element.Attribute("Include") ?? string.Empty).ToArray();

        Assert.Equal(3, references.Length);
        Assert.Contains(references, reference => reference.EndsWith("Authentication.CertificateSigning.csproj", StringComparison.Ordinal));
        Assert.Contains(references, reference => reference.EndsWith("Gateway.Application.csproj", StringComparison.Ordinal));
        Assert.Contains(references, reference => reference.EndsWith("Providers.Abstractions.csproj", StringComparison.Ordinal));
        Assert.DoesNotContain(references, reference => reference.Contains("Infrastructure", StringComparison.OrdinalIgnoreCase) ||
            reference.Contains("Gateway.Api", StringComparison.OrdinalIgnoreCase) || reference.Contains("Broker", StringComparison.OrdinalIgnoreCase) ||
            reference.Contains("Azure", StringComparison.OrdinalIgnoreCase) || reference.Contains("AWS", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void HC_W1_ARCH_FSE2_caller_surface_cannot_select_actor_or_authentication_authority()
    {
        string packRoot = Path.Combine(Root, "src", "ConnectorPacks", "Healthcare", "Healthcare.FSE2");
        string contracts = File.ReadAllText(Path.Combine(packRoot, "Fse2Contracts.cs"));
        string requestBlock = contracts[(contracts.IndexOf("public sealed class Fse2Request", StringComparison.Ordinal))..];
        requestBlock = requestBlock[..requestBlock.IndexOf("public sealed record Fse2Response", StringComparison.Ordinal)];
        string[] forbiddenRequestAuthority = ["public string Subject", "public string Role", "public Uri Endpoint", "UseSubjectAsAuthor", "SigningKey", "X5c", "Audience", "Issuer"];
        foreach (string forbidden in forbiddenRequestAuthority)
            Assert.DoesNotContain(forbidden, requestBlock, StringComparison.OrdinalIgnoreCase);

        string connector = File.ReadAllText(Path.Combine(packRoot, "Fse2Connector.cs"));
        Assert.Contains("Authorization", connector, StringComparison.Ordinal);
        Assert.Contains("FSE-JWT-Signature", connector, StringComparison.Ordinal);
        Assert.DoesNotContain("use_subject_as_author", connector, StringComparison.Ordinal);
        Assert.DoesNotContain("new HttpClient", connector, StringComparison.Ordinal);
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "BrokerGateway.Core.slnx"))) return current.FullName;
            current = current.Parent;
        }

        throw new InvalidOperationException("Repository root not found.");
    }
}

using System.Text.RegularExpressions;
using System.Xml.Linq;
using Xunit;

namespace SecureIntegration.Architecture.Tests;

public sealed class HealthcarePackBoundaryTests
{
    private static readonly string Root = FindRepositoryRoot();

    [Fact]
    public void HC_W1_ARCH_Core_export_allowlist_does_not_capture_vertical_integration_tests()
    {
        string allowlist = File.ReadAllText(Path.Combine(Root, "eng", "open-source-core.allowlist"));

        Assert.DoesNotContain("tests/integration/", allowlist.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries));
        Assert.Contains("tests/integration/Broker.Integration.Tests/", allowlist, StringComparison.Ordinal);
        Assert.Contains("tests/integration/Gateway.Integration.Tests/", allowlist, StringComparison.Ordinal);
    }

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
    public void HC_W1_SISTEMATS_ARCH_connector_depends_only_on_qualified_public_capabilities_and_has_no_host_escape()
    {
        string packRoot = Path.Combine(Root, "src", "ConnectorPacks", "Healthcare", "Healthcare.SistemaTs");
        XDocument project = XDocument.Load(Path.Combine(packRoot, "Healthcare.SistemaTs.csproj"));
        string[] references = project.Descendants("ProjectReference")
            .Select(element => Path.GetFileName((string?)element.Attribute("Include") ?? string.Empty)).Order().ToArray();
        Assert.Equal(["Gateway.Application.csproj", "Gateway.ConnectorRuntime.Auth.Soap.csproj"], references);

        string source = string.Join('\n', Directory.EnumerateFiles(packRoot, "*.cs", SearchOption.AllDirectories)
            .Select(File.ReadAllText));
        foreach (string forbidden in new[] { "IServiceProvider", "IConnectorConfigurationStore", "ISecretProvider", "HttpClient", "HttpRequestMessage", "RestrictedTransport", "InternalsVisibleTo", "Gateway.Api", "GetSecret" })
            Assert.DoesNotContain(forbidden, source, StringComparison.Ordinal);

        string apiProject = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Api", "Gateway.Api.csproj"));
        Assert.DoesNotContain("Healthcare.SistemaTs", apiProject, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HC_W1_SISTEMATS_ARCH_unsafe_raw_business_dispatch_is_absent_and_profile_is_fail_closed()
    {
        string packRoot = Path.Combine(Root, "src", "ConnectorPacks", "Healthcare", "Healthcare.SistemaTs");
        string source = string.Join('\n', Directory.EnumerateFiles(packRoot, "*.cs", SearchOption.AllDirectories)
            .Select(File.ReadAllText));
        Assert.DoesNotContain("ExecuteComposedSoapAsync", source, StringComparison.Ordinal);
        Assert.DoesNotContain("OpenPayloadStream", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ssn-erogatore-1.5.1", source, StringComparison.Ordinal);

        string definitionPath = Path.Combine(Root, "docs", "connectors", "healthcare",
            "sistema-ts-eprescription", "sistema-ts.connector.json");
        using System.Text.Json.JsonDocument definition = System.Text.Json.JsonDocument.Parse(File.ReadAllText(definitionPath));
        string[] operations = definition.RootElement.GetProperty("operations").EnumerateArray()
            .Select(operation => operation.GetProperty("operationId").GetString()!).ToArray();
        Assert.Equal(["session-create"], operations);
        Assert.DoesNotContain("authorization2F", File.ReadAllText(definitionPath), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HC_W1_SISTEMATS_ARCH_canonical_PostgreSQL_job_requires_vertical_test_execution()
    {
        string workflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "ci.yml"));
        const string project =
            "tests/integration/Healthcare.SistemaTs.Integration.Tests/Healthcare.SistemaTs.Integration.Tests.csproj";
        const string test =
            "HC_W1_SISTEMATS_IT_PostgreSQL18_four_eyes_Published_admission_and_checkToken_execute_when_required";

        Assert.Contains($"dotnet restore {project} --locked-mode", workflow, StringComparison.Ordinal);
        Assert.Contains($"dotnet build {project} -c Release --no-restore", workflow, StringComparison.Ordinal);
        Assert.Contains($"dotnet test {project}", workflow, StringComparison.Ordinal);
        Assert.Contains("REQUIRE_SISTEMA_TS_POSTGRES_GATE: '1'", workflow, StringComparison.Ordinal);
        Assert.Contains(test, workflow, StringComparison.Ordinal);
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

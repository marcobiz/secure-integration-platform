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
        Assert.DoesNotContain("Healthcare.FSE2.Integration.Tests", coreSolution, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Healthcare.FSE2.Integration.Tests", File.ReadAllText(Path.Combine(Root, "BrokerGateway.slnx")), StringComparison.Ordinal);
        string coreExportAllowlist = File.ReadAllText(Path.Combine(Root, "eng", "open-source-core.allowlist"));
        Assert.DoesNotContain("tests/integration/\n", coreExportAllowlist.Replace("\r\n", "\n", StringComparison.Ordinal), StringComparison.Ordinal);
        Assert.DoesNotContain("Healthcare.FSE2.Integration.Tests", coreExportAllowlist, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("tests/integration/Gateway.Integration.Tests/", coreExportAllowlist, StringComparison.Ordinal);
        Assert.Contains("tests/integration/Broker.Integration.Tests/", coreExportAllowlist, StringComparison.Ordinal);

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
    public void HC_W1_ARCH_FSE2_pack_depends_only_on_the_public_Application_capability_contract()
    {
        string projectPath = Path.Combine(Root, "src", "ConnectorPacks", "Healthcare", "Healthcare.FSE2", "Healthcare.FSE2.csproj");
        XDocument project = XDocument.Load(projectPath);
        string[] references = project.Descendants("ProjectReference").Select(element => (string?)element.Attribute("Include") ?? string.Empty).ToArray();

        Assert.Single(references);
        Assert.EndsWith("Gateway.Application.csproj", references[0], StringComparison.Ordinal);
        Assert.DoesNotContain(references, reference => reference.Contains("Infrastructure", StringComparison.OrdinalIgnoreCase) ||
            reference.Contains("Gateway.Api", StringComparison.OrdinalIgnoreCase) || reference.Contains("Broker", StringComparison.OrdinalIgnoreCase) ||
            reference.Contains("Authentication.CertificateSigning", StringComparison.OrdinalIgnoreCase) ||
            reference.Contains("Providers.Abstractions", StringComparison.OrdinalIgnoreCase) ||
            reference.Contains("Azure", StringComparison.OrdinalIgnoreCase) || reference.Contains("AWS", StringComparison.OrdinalIgnoreCase));
        Assert.Empty(project.Descendants("InternalsVisibleTo"));
    }

    [Fact]
    public void HC_W1_ARCH_FSE2_pack_has_no_direct_store_provider_transport_or_Gateway_internal_bypass()
    {
        string packRoot = Path.Combine(Root, "src", "ConnectorPacks", "Healthcare", "Healthcare.FSE2");
        string source = string.Join(Environment.NewLine, Directory.GetFiles(packRoot, "*.cs").Select(File.ReadAllText));
        string[] forbidden =
        [
            "IConnectorConfigurationStore", "IAdminSecurityStore", "ConnectorDefinitionValidator",
            "IKeyOperationProvider", "ICertificatePublicMaterialProvider", "IClientCertificateProvider",
            "IRestrictedTransport", "PurposeBoundMutualTlsSender", "Rs256JwtSigner", "new HttpClient",
            "HttpRequestMessage", "AuthorizedGatewayInvocation", "GetSecretAsync", "InternalsVisibleTo"
        ];
        foreach (string identifier in forbidden)
            Assert.DoesNotContain(identifier, source, StringComparison.Ordinal);

        string strategy = File.ReadAllText(Path.Combine(packRoot, "Fse2Connector.cs"));
        Assert.Contains("OpenPublishedExtensionConfiguration", strategy, StringComparison.Ordinal);
        Assert.Contains("AddAuthorizedPublishedOperationExpectationProvider", strategy, StringComparison.Ordinal);
        Assert.Contains("CreateSignedTokenAsync", strategy, StringComparison.Ordinal);
        Assert.Contains("ExecuteRestrictedTransportAsync", strategy, StringComparison.Ordinal);
        Assert.Contains("new AuthorizedConnectorRestrictedTransportRequest(exactOutboundBody, pathParameters)", strategy, StringComparison.Ordinal);
        Assert.Contains("new AuthorizedConnectorRestrictedTransportRequest(pathParameters)", strategy, StringComparison.Ordinal);
        Assert.DoesNotContain("Headers", strategy, StringComparison.Ordinal);
    }

    [Fact]
    public void HC_W1_ARCH_FSE2_caller_surface_cannot_select_actor_or_authentication_authority()
    {
        string packRoot = Path.Combine(Root, "src", "ConnectorPacks", "Healthcare", "Healthcare.FSE2");
        string contracts = File.ReadAllText(Path.Combine(packRoot, "Fse2Contracts.cs"));
        string requestBlock = contracts[(contracts.IndexOf("public sealed class Fse2Request", StringComparison.Ordinal))..];
        requestBlock = requestBlock[..requestBlock.IndexOf("public sealed record Fse2Response", StringComparison.Ordinal)];
        string[] forbiddenRequestAuthority =
        [
            "public string Subject", "public string Role", "public Uri Endpoint", "public bool UseSubjectAsAuthor",
            "public string SigningKey", "public string X5c", "public string Audience", "public string Issuer"
        ];
        foreach (string forbidden in forbiddenRequestAuthority)
            Assert.DoesNotContain(forbidden, requestBlock, StringComparison.OrdinalIgnoreCase);

        string connector = File.ReadAllText(Path.Combine(packRoot, "Fse2Connector.cs"));
        Assert.DoesNotContain("Headers.Authorization", connector, StringComparison.Ordinal);
        Assert.DoesNotContain("FSE-JWT-Signature", connector, StringComparison.Ordinal);
        Assert.DoesNotContain("use_subject_as_author", connector, StringComparison.Ordinal);
        Assert.DoesNotContain("new HttpClient", connector, StringComparison.Ordinal);
    }

    [Fact]
    public void HC_W1_ARCH_FSE2_OfficialTest_provisioner_is_vertical_only_and_absent_from_Core_export()
    {
        string projectPath = Path.Combine(Root, "tools", "fse2", "OfficialTestProvisioner", "OfficialTestProvisioner.csproj");
        XDocument project = XDocument.Load(projectPath);
        string reference = Assert.Single(project.Descendants("ProjectReference"))
            .Attribute("Include")?.Value ?? string.Empty;
        Assert.EndsWith("Healthcare.FSE2.csproj", reference, StringComparison.Ordinal);

        string fullSolution = File.ReadAllText(Path.Combine(Root, "BrokerGateway.slnx"));
        string coreSolution = File.ReadAllText(Path.Combine(Root, "BrokerGateway.Core.slnx"));
        string coreExportAllowlist = File.ReadAllText(Path.Combine(Root, "eng", "open-source-core.allowlist"));
        Assert.Contains("OfficialTestProvisioner", fullSolution, StringComparison.Ordinal);
        Assert.DoesNotContain("OfficialTestProvisioner", coreSolution, StringComparison.Ordinal);
        Assert.DoesNotContain("OfficialTestProvisioner", coreExportAllowlist, StringComparison.Ordinal);

        string source = File.ReadAllText(Path.Combine(Path.GetDirectoryName(projectPath)!, "Program.cs"));
        Assert.Contains("FSE2_GATEWAY_URL", source, StringComparison.Ordinal);
        Assert.Contains("gateway.Scheme != Uri.UriSchemeHttps", source, StringComparison.Ordinal);
        Assert.Contains("if (args[0] == \"plan\" && args.Length == 2)", source, StringComparison.Ordinal);
        Assert.DoesNotContain("OfficialTestEndpoint", source, StringComparison.Ordinal);
        Assert.DoesNotContain("CreateSignedToken", source, StringComparison.Ordinal);
        Assert.DoesNotContain("GetSecret", source, StringComparison.Ordinal);
        Assert.DoesNotContain("GetRSAPrivateKey", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ExportPkcs8PrivateKey", source, StringComparison.Ordinal);
        Assert.DoesNotContain("LoadPkcs12", source, StringComparison.Ordinal);
        Assert.DoesNotContain("IRestrictedTransport", source, StringComparison.Ordinal);
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

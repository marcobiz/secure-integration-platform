using System.Xml.Linq;
using System.Text.RegularExpressions;
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
    public void Local_pkcs12_pack_remains_optional_provider_only_and_vertical_neutral()
    {
        string coreSolution = File.ReadAllText(Path.Combine(Root, "BrokerGateway.Core.slnx"));
        Assert.DoesNotContain("LocalPkcs12", coreSolution, StringComparison.OrdinalIgnoreCase);

        string localSolutionPath = Path.Combine(Root, "BrokerGateway.LocalPkcs12.slnx");
        if (!File.Exists(localSolutionPath))
        {
            Assert.False(Directory.Exists(Path.Combine(Root, "packs", "deployment", "local-pkcs12")));
            return;
        }
        string solution = File.ReadAllText(localSolutionPath);
        Assert.Contains("packs/deployment/local-pkcs12", solution, StringComparison.Ordinal);

        string projectPath = Path.Combine(Root, "packs", "deployment", "local-pkcs12", "src", "Providers.LocalPkcs12", "Providers.LocalPkcs12.csproj");
        XDocument project = XDocument.Load(projectPath);
        string[] references = project.Descendants("ProjectReference")
            .Select(element => ((string?)element.Attribute("Include") ?? string.Empty).Replace('\\', '/'))
            .ToArray();
        Assert.Single(references);
        Assert.EndsWith("src/Providers/Abstractions/Providers.Abstractions.csproj", references[0], StringComparison.Ordinal);
        Assert.Empty(project.Descendants("PackageReference"));

        string source = File.ReadAllText(Path.Combine(Path.GetDirectoryName(projectPath)!, "LocalPkcs12Provider.cs"));
        string[] forbidden = ["ConnectorPacks", "Healthcare", "FSE2", "Gateway.", "HttpClient", "GetPrivateKey", "ExportPkcs12", "ExportPfx"];
        foreach (string token in forbidden) Assert.DoesNotContain(token, source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("LocalPkcs12Provider : ISecretValueProvider", source, StringComparison.Ordinal);
        Assert.DoesNotContain("LocalResourceKind.Secret", source, StringComparison.Ordinal);
        Assert.Contains("SecretValues: false", source, StringComparison.Ordinal);
        Assert.Contains("DenyOnlySecretValueProvider", source, StringComparison.Ordinal);

        string gatewayComposition = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Api", "Program.cs"));
        Assert.DoesNotContain("Capabilities.SecretValues ||", gatewayComposition, StringComparison.Ordinal);
        Assert.Contains("!services.CapabilitySource.Capabilities.ClientCertificates", gatewayComposition, StringComparison.Ordinal);

        string workflow = File.ReadAllText(Path.Combine(Root, ".github", "workflows", "ci.yml"));
        string lab = File.ReadAllText(Path.Combine(Root, "tools", "fse2", "Invoke-Fse2LocalProviderLab.ps1"));
        string composeValidator = File.ReadAllText(Path.Combine(Root, "tools", "fse2", "Test-Fse2ComposeConfiguration.ps1"));
        Assert.Contains("Test-Fse2LocalPkcs12Material.ps1", workflow, StringComparison.Ordinal);
        Assert.Contains("-ValidateCompose -StartLab", workflow, StringComparison.Ordinal);
        Assert.Contains("Test-Fse2ComposeConfiguration.ps1", lab, StringComparison.Ordinal);
        Assert.Contains("config --quiet", composeValidator, StringComparison.Ordinal);
        Assert.DoesNotContain("--no-interpolate", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("--no-interpolate", lab, StringComparison.Ordinal);
    }

    [Fact]
    public void Provider_contracts_are_capability_specific()
    {
        string contracts = File.ReadAllText(Path.Combine(Root, "src", "Providers", "Abstractions", "ProviderContracts.cs"));
        Assert.Contains("ISecretValueProvider", contracts, StringComparison.Ordinal);
        Assert.Contains("IClientCertificateProvider", contracts, StringComparison.Ordinal);
        Assert.Contains("ISigningKeyProvider", contracts, StringComparison.Ordinal);
        Assert.Contains("IKeyOperationProvider", contracts, StringComparison.Ordinal);
        Assert.Contains("ICertificatePublicMaterialProvider", contracts, StringComparison.Ordinal);
        Assert.Contains("IMacProvider", contracts, StringComparison.Ordinal);
        Assert.Contains("IProviderHealthCheck", contracts, StringComparison.Ordinal);
        Assert.Contains("IProviderCapabilitySource", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("IKms", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("GetPrivateKey", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("GetPfx", contracts, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("GetSecretLocator", contracts, StringComparison.Ordinal);
    }

    [Fact]
    public void Local_pkcs12_stop_input_cleanup_is_exact_revalidated_and_foreign_uid_safe()
    {
        string toolingDirectory = Path.Combine(Root, "tools", "fse2");
        string selfTestPath = Path.Combine(toolingDirectory, "Test-Fse2LocalPkcs12Material.ps1");
        if (!File.Exists(selfTestPath))
        {
            Assert.False(Directory.Exists(toolingDirectory));
            return;
        }
        string selfTest = File.ReadAllText(selfTestPath);

        Assert.Contains("function Remove-SyntheticStopInput", selfTest, StringComparison.Ordinal);
        Assert.Contains("Get-Fse2PathSnapshot -Path $Path -Kind File", selfTest, StringComparison.Ordinal);
        Assert.Contains("Assert-Fse2PathSnapshot -Snapshot $fileSnapshot", selfTest, StringComparison.Ordinal);
        Assert.Contains("$removeTool = '/bin/rm'", selfTest, StringComparison.Ordinal);
        Assert.Contains("FSE2_LOCAL_FOREIGN_UID_STOP_INPUT_CLEANUP_PASS", selfTest, StringComparison.Ordinal);
        Assert.DoesNotContain("Remove-Item -LiteralPath $manifestForStop", selfTest, StringComparison.Ordinal);
        Assert.DoesNotContain("Remove-Item -LiteralPath $pkcs12ForStop", selfTest, StringComparison.Ordinal);
    }

    [Fact]
    public void Generic_certificate_signing_extensions_have_no_vertical_content_or_arbitrary_header_bag()
    {
        string[] roots =
        [
            Path.Combine(Root, "src", "Authentication", "CertificateSigning"),
            Path.Combine(Root, "src", "Providers", "Abstractions"),
            Path.Combine(Root, "src", "Providers", "Synthetic"),
            Path.Combine(Root, "tests", "unit", "Authentication.CertificateSigning.Tests")
        ];
        string[] forbidden =
        [
            "F" + "SE", "F" + "SE2", "Sistema" + "TS", "farma" + "cia", "health" + "care",
            "C" + "GM", "Winges" + "far", "dr" + "CLOUD"
        ];
        foreach (string file in roots.SelectMany(path => Directory.EnumerateFiles(path, "*.cs", SearchOption.AllDirectories)).Where(path => !IsGenerated(path)))
        {
            string content = File.ReadAllText(file);
            foreach (string token in forbidden)
                Assert.DoesNotMatch(new Regex($@"\b{Regex.Escape(token)}\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), content);
        }

        string signer = File.ReadAllText(Path.Combine(Root, "src", "Authentication", "CertificateSigning", "Rs256JwtSigner.cs"));
        Assert.DoesNotContain("Dictionary<string, object>", signer, StringComparison.Ordinal);
        Assert.DoesNotContain("ExpandoObject", signer, StringComparison.Ordinal);
        Assert.DoesNotContain("JsonNode", signer, StringComparison.Ordinal);
        Assert.DoesNotContain("ClaimsPrincipal", signer, StringComparison.Ordinal);

        string contracts = File.ReadAllText(Path.Combine(Root, "src", "Authentication", "CertificateSigning", "Contracts.cs"));
        Assert.Contains("ITrustedRuntimeClaimValueResolver", contracts, StringComparison.Ordinal);
        Assert.Contains("internal TrustedRuntimeClaimResolutionRequest", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("GatewayUser", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("GenericHumanPrincipal", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("Dictionary<string", contracts, StringComparison.Ordinal);
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

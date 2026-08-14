using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Xunit;

namespace SecureIntegration.Architecture.Tests;

public sealed class AlphaReleaseArtifactTests
{
    private const string ProductVersion = "0.1.0-alpha.1";
    private static readonly string Root = FindRepositoryRoot();

    [Fact]
    public void ALPHA_VER_all_product_surfaces_report_0_1_0_alpha_1()
    {
        XDocument props = XDocument.Load(Path.Combine(Root, "Directory.Build.props"));
        Assert.Equal(ProductVersion, props.Descendants("ProductVersion").Single().Value);
        Assert.Equal("$(ProductVersion)", props.Descendants("Version").Single().Value);
        Assert.Equal("$(ProductVersion)", props.Descendants("PackageVersion").Single().Value);
        Assert.Equal("$(ProductVersion)", props.Descendants("InformationalVersion").Single().Value);
        Assert.Equal("false", props.Descendants("IncludeSourceRevisionInInformationalVersion").Single().Value);

        using JsonDocument package = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "src", "Admin", "Admin.Web", "package.json")));
        using JsonDocument lockFile = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "src", "Admin", "Admin.Web", "package-lock.json")));
        Assert.Equal(ProductVersion, package.RootElement.GetProperty("version").GetString());
        Assert.Equal(ProductVersion, lockFile.RootElement.GetProperty("version").GetString());
        Assert.Equal(ProductVersion, lockFile.RootElement.GetProperty("packages").GetProperty("").GetProperty("version").GetString());

        string openApi = File.ReadAllText(Path.Combine(Root, "docs", "api", "gateway-openapi.yaml"));
        Assert.Matches(new Regex(@"(?m)^info:\s*\r?\n(?:^  .+\r?\n)*?^  version: 0\.1\.0-alpha\.1\s*$", RegexOptions.CultureInvariant), openApi);
    }

    [Fact]
    public void ALPHA_VER_protocol_and_canonical_connector_versions_are_unchanged()
    {
        string contracts = File.ReadAllText(Path.Combine(Root, "src", "Shared", "SecureIntegration.Contracts", "WireContracts.cs"));
        Assert.True(Regex.Count(contracts, "ProtocolVersion \\{ get; set; \\} = \\\"1\\.0\\\";", RegexOptions.CultureInvariant) >= 2);
        using JsonDocument connector = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "docs", "connectors", "examples", "sample-secure-service.connector.json")));
        Assert.Equal("1.0.0", connector.RootElement.GetProperty("version").GetString());
    }

    [Fact]
    public void ALPHA_ART_only_the_existing_alpha_SDK_project_is_explicitly_packable()
    {
        string[] packable = Directory.EnumerateFiles(Root, "*.csproj", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(path => XDocument.Load(path).Descendants("IsPackable").Any(value => value.Value == "true"))
            .Select(path => Path.GetRelativePath(Root, path).Replace('\\', '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(["sdk/dotnet/Broker.Sdk/Broker.Sdk.csproj"], packable);
    }

    [Theory]
    [InlineData("src/Gateway/Gateway.Api/Dockerfile")]
    [InlineData("src/Gateway/Gateway.Migrations/Dockerfile")]
    public void ALPHA_ART_OCI_metadata_is_bound_to_version_and_exact_revision_build_arguments(string relativePath)
    {
        string dockerfile = File.ReadAllText(Path.Combine(Root, relativePath.Replace('/', Path.DirectorySeparatorChar)));
        Assert.Contains("ARG PRODUCT_VERSION", dockerfile, StringComparison.Ordinal);
        Assert.Contains("ARG SOURCE_REVISION", dockerfile, StringComparison.Ordinal);
        Assert.Contains("org.opencontainers.image.version=$PRODUCT_VERSION", dockerfile, StringComparison.Ordinal);
        Assert.Contains("org.opencontainers.image.revision=$SOURCE_REVISION", dockerfile, StringComparison.Ordinal);
    }

    [Fact]
    public void ALPHA_ART_Core_export_excludes_optional_packs_and_contains_release_verifiers()
    {
        string allowlist = File.ReadAllText(Path.Combine(Root, "eng", "open-source-core.allowlist"));
        Assert.DoesNotContain("packs/", allowlist, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Healthcare", allowlist, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("eng/Build-AlphaReleaseArtifacts.ps1", allowlist, StringComparison.Ordinal);
        Assert.Contains("eng/Test-OpenSourceCoreInventory.ps1", allowlist, StringComparison.Ordinal);
        Assert.Contains("eng/CoreExportInventory.psm1", allowlist, StringComparison.Ordinal);
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "BrokerGateway.slnx")) || File.Exists(Path.Combine(current.FullName, "BrokerGateway.Core.slnx"))) return current.FullName;
            current = current.Parent;
        }
        throw new DirectoryNotFoundException("Repository root not found.");
    }
}

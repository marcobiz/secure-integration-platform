using System.Xml.Linq;
using Xunit;

namespace SecureIntegration.Architecture.Tests;

public sealed class SoapAuthBoundaryTests
{
    private static readonly string Root = FindRepositoryRoot();

    [Fact]
    public void M6_CT_SOAP_writer_depends_only_on_public_Core_runtime_and_provider_abstractions()
    {
        string projectPath = Path.Combine(Root, "src", "Gateway", "Gateway.ConnectorRuntime.Auth.Soap", "Gateway.ConnectorRuntime.Auth.Soap.csproj");
        XDocument project = XDocument.Load(projectPath);
        string[] references = project.Descendants("ProjectReference").Select(element => (string?)element.Attribute("Include") ?? string.Empty).ToArray();
        Assert.Contains(references, reference => reference.EndsWith("Gateway.Application.csproj", StringComparison.Ordinal));
        Assert.Contains(references, reference => reference.EndsWith("Providers.Abstractions.csproj", StringComparison.Ordinal));
        Assert.DoesNotContain(references, reference => reference.Contains("Infrastructure", StringComparison.OrdinalIgnoreCase) || reference.Contains("Gateway.Api", StringComparison.OrdinalIgnoreCase) || reference.Contains("Broker", StringComparison.OrdinalIgnoreCase) || reference.Contains("packs", StringComparison.OrdinalIgnoreCase));

        string solution = File.ReadAllText(Path.Combine(Root, "BrokerGateway.Core.slnx"));
        Assert.Contains("Gateway.ConnectorRuntime.Auth.Soap", solution, StringComparison.Ordinal);
        string exportAllowlist = File.ReadAllText(Path.Combine(Root, "eng", "open-source-core.allowlist"));
        Assert.Contains("tools/m6/SyntheticSoapServer/", exportAllowlist, StringComparison.Ordinal);
    }

    [Fact]
    public void M6_CT_SOAP_writer_exposes_no_raw_session_resolver_generic_scripting_or_deferred_auth_framework()
    {
        string sourceRoot = Path.Combine(Root, "src", "Gateway", "Gateway.ConnectorRuntime.Auth.Soap");
        string source = string.Join('\n', Directory.EnumerateFiles(sourceRoot, "*.cs").Select(File.ReadAllText));
        Assert.DoesNotContain("public static class SoapXmlBoundary", source, StringComparison.Ordinal);
        Assert.DoesNotContain("public sealed record SoapDecodedResponse", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ResolveSessionForOutbound", source, StringComparison.Ordinal);
        Assert.DoesNotContain("WS-Security", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SAML", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SignedXml", source, StringComparison.Ordinal);
        Assert.DoesNotContain("OAuth", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Script", source, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Wave1_CT_Core_session_projection_is_vertical_neutral_and_has_no_healthcare_pack_dependency()
    {
        string sourceRoot = Path.Combine(Root, "src", "Gateway", "Gateway.ConnectorRuntime.Auth.Soap");
        string source = string.Join('\n', Directory.EnumerateFiles(sourceRoot, "*.cs").Select(File.ReadAllText));
        string projectionSource = File.ReadAllText(Path.Combine(sourceRoot, "OpaqueSessionHttpProjection.cs"));
        string project = File.ReadAllText(Path.Combine(sourceRoot, "Gateway.ConnectorRuntime.Auth.Soap.csproj"));
        foreach (string forbidden in new[] { "SistemaTS", "SOGEI", "FSE", "farmacia", "CGM", "Wingesfar", "drCLOUD" })
            Assert.DoesNotContain(forbidden, source, StringComparison.Ordinal);
        Assert.DoesNotContain("healthcare", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ConnectorPacks.Healthcare", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ConnectorPacks.Healthcare", project, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("HttpRequestHeader", source, StringComparison.Ordinal);
        Assert.Contains("IRestrictedTransport", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Dictionary<string,string>", projectionSource.Replace(" ", string.Empty, StringComparison.Ordinal), StringComparison.Ordinal);
        Assert.DoesNotContain("ApplySession", source, StringComparison.Ordinal);
        Assert.DoesNotContain("AttachSessionHeader", source, StringComparison.Ordinal);
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

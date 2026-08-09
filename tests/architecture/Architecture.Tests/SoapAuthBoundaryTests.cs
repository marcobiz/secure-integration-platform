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
        Assert.Contains(references, reference => reference.EndsWith("Gateway.ConnectorRuntime.Auth.Http.csproj", StringComparison.Ordinal));
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
        string httpRoot = Path.Combine(Root, "src", "Gateway", "Gateway.ConnectorRuntime.Auth.Http");
        string soapRoot = Path.Combine(Root, "src", "Gateway", "Gateway.ConnectorRuntime.Auth.Soap");
        string source = string.Join('\n', Directory.EnumerateFiles(Path.Combine(httpRoot, "OpaqueSessions"), "*.cs").Select(File.ReadAllText));
        string httpProject = File.ReadAllText(Path.Combine(httpRoot, "Gateway.ConnectorRuntime.Auth.Http.csproj"));
        string soapProject = File.ReadAllText(Path.Combine(soapRoot, "Gateway.ConnectorRuntime.Auth.Soap.csproj"));
        foreach (string forbidden in new[] { "SistemaTS", "SOGEI", "FSE", "farmacia", "CGM", "Wingesfar", "drCLOUD" })
            Assert.DoesNotContain(forbidden, source, StringComparison.Ordinal);
        Assert.DoesNotContain("healthcare", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ConnectorPacks.Healthcare", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ConnectorPacks.Healthcare", httpProject, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Gateway.ConnectorRuntime.Auth.Soap", httpProject, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Gateway.ConnectorRuntime.Auth.Http", soapProject, StringComparison.Ordinal);
        Assert.Contains("HttpRequestHeader", source, StringComparison.Ordinal);
        Assert.Contains("IRestrictedTransport", source, StringComparison.Ordinal);
        Assert.Contains("PublishedOpaqueSessionAuthorityResolver", source, StringComparison.Ordinal);
        Assert.Contains("OpaqueSessionAuthorizedInvocation", source, StringComparison.Ordinal);
        Assert.DoesNotContain("IOpaqueSessionHttpPolicySource", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ServerOwnedOpaqueSessionHttpPolicySnapshot", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ApplySession", source, StringComparison.Ordinal);
        Assert.DoesNotContain("AttachSessionHeader", source, StringComparison.Ordinal);
    }

    [Fact]
    public void Wave1_CT_composed_SOAP_dispatch_is_closed_typed_Published_and_fault_preserving()
    {
        string soapRoot = Path.Combine(Root, "src", "Gateway", "Gateway.ConnectorRuntime.Auth.Soap");
        string client = File.ReadAllText(Path.Combine(soapRoot, "ComposedSoapAuthenticatedClient.cs"));
        string resolver = File.ReadAllText(Path.Combine(soapRoot, "PublishedComposedSoapAuthorityResolver.cs"));
        string contracts = File.ReadAllText(Path.Combine(soapRoot, "ComposedSoapDispatchContracts.cs"));
        string basic = File.ReadAllText(Path.Combine(soapRoot, "ServerBoundBasicAuthentication.cs"));
        string strategy = File.ReadAllText(Path.Combine(soapRoot, "ComposedSoapExecutionStrategy.cs"));
        string host = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Api", "Program.cs"));
        string operationServices = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Application", "OperationServices.cs"));
        string schema = File.ReadAllText(Path.Combine(Root, "docs", "connectors", "connector-definition.schema.json"));

        Assert.Contains("transport.SendSoapAsync", client, StringComparison.Ordinal);
        Assert.DoesNotContain("transport.SendAsync", client, StringComparison.Ordinal);
        Assert.Contains("OpaqueSessionLeaseProvider", client, StringComparison.Ordinal);
        Assert.Contains("AcquireFinalLease", client, StringComparison.Ordinal);
        Assert.Contains("ServerBoundBasicAuthentication", client, StringComparison.Ordinal);
        Assert.Contains("internal sealed class ServerBoundBasicAuthentication", basic, StringComparison.Ordinal);
        Assert.Contains("internal async Task ApplyAsync", basic, StringComparison.Ordinal);
        Assert.Contains("PublishedConnectorSnapshot", resolver, StringComparison.Ordinal);
        Assert.Contains("OperationBindingDependencies", resolver, StringComparison.Ordinal);
        Assert.Contains("SoapHttpRequestMetadata", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("IReadOnlyDictionary<string, string> Headers", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("Dictionary<string, string> headers", client, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"soapBasicOpaqueSession\"", schema, StringComparison.Ordinal);
        Assert.Contains("\"opaqueSessionHttp\"", schema, StringComparison.Ordinal);
        Assert.DoesNotContain("\"headers\"", schema, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ComposedSoapExecutionStrategy", host, StringComparison.Ordinal);
        Assert.Contains("OpaqueSessionHttpExecutionStrategy", host, StringComparison.Ordinal);
        Assert.Contains("IGatewayOperationExecutionStrategy", operationServices, StringComparison.Ordinal);
        Assert.Contains("client.SendAuthorizedAsync", strategy, StringComparison.Ordinal);
        Assert.DoesNotContain("transport.SendAsync", strategy, StringComparison.Ordinal);
    }

    [Fact]
    public void Wave1_CT_Typed_handshake_and_external_admission_are_Published_compiled_vertical_neutral_and_reuse_the_single_cache()
    {
        string soapRoot = Path.Combine(Root, "src", "Gateway", "Gateway.ConnectorRuntime.Auth.Soap");
        string source = string.Join('\n', Directory.EnumerateFiles(soapRoot, "*.cs").Order(StringComparer.Ordinal).Select(File.ReadAllText));
        Assert.DoesNotContain("ConnectorPacks.", source, StringComparison.Ordinal);
        Assert.Contains("PublishedTypedSessionHandshakeResolver", source, StringComparison.Ordinal);
        Assert.Contains("AuthorizedGatewayInvocation", source, StringComparison.Ordinal);
        Assert.Contains("ITypedSessionHandshakeRequestAdapter", source, StringComparison.Ordinal);
        Assert.Contains("XmlWriter writer", source, StringComparison.Ordinal);
        Assert.Contains("ITypedSessionHandshakeResponseAdapter", source, StringComparison.Ordinal);
        Assert.Contains("XmlReader payload", source, StringComparison.Ordinal);
        Assert.Contains("ExternalSessionCandidate candidate", source, StringComparison.Ordinal);
        Assert.Contains("cache.CompleteAdmission", source, StringComparison.Ordinal);
        Assert.Equal(1, source.Split("private readonly SoapSessionCache cache = new();", StringSplitOptions.None).Length - 1);
        Assert.DoesNotContain("Dictionary<string, object", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("XPath", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Xsl", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Activator.CreateInstance", source, StringComparison.Ordinal);
        Assert.DoesNotContain("GetType().Get", source, StringComparison.Ordinal);
        Assert.DoesNotContain("PutSession", source, StringComparison.Ordinal);
        Assert.DoesNotContain("SetCachedToken", source, StringComparison.Ordinal);
        Assert.DoesNotContain("PromoteSession", source, StringComparison.Ordinal);
        Assert.DoesNotContain("raw XElement", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("raw XML", source, StringComparison.OrdinalIgnoreCase);

        string schema = File.ReadAllText(Path.Combine(Root, "docs", "connectors", "connector-definition.schema.json"));
        Assert.Contains("typedSessionHandshake", schema, StringComparison.Ordinal);
        Assert.Contains("compiledAdapter", schema, StringComparison.Ordinal);
        Assert.Contains("externalAdmission", schema, StringComparison.Ordinal);
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

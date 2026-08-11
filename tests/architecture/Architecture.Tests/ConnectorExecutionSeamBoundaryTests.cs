using System.Xml.Linq;
using Xunit;

namespace SecureIntegration.Architecture.Tests;

public sealed class ConnectorExecutionSeamBoundaryTests
{
    private static readonly string Root = FindRepositoryRoot();

    [Fact]
    public void Wave1_CT_external_execution_module_uses_only_public_provider_neutral_contracts_without_friend_access()
    {
        string supportRoot = Path.Combine(Root, "tests", "support", "Synthetic.ConnectorExecutionModule");
        XDocument project = XDocument.Load(Path.Combine(supportRoot, "Synthetic.ConnectorExecutionModule.csproj"));
        string[] references = project.Descendants("ProjectReference")
            .Select(element => (string?)element.Attribute("Include") ?? string.Empty)
            .ToArray();
        Assert.Equal(2, references.Length);
        Assert.Contains(references, value => value.EndsWith("Gateway.Application.csproj", StringComparison.Ordinal));
        Assert.Contains(references, value => value.EndsWith("Gateway.ConnectorRuntime.Auth.Soap.csproj", StringComparison.Ordinal));

        string source = string.Join('\n', Directory.EnumerateFiles(supportRoot, "*.cs").Select(File.ReadAllText));
        Assert.DoesNotContain("InternalsVisibleTo", source, StringComparison.Ordinal);
        Assert.DoesNotContain("System.Reflection", source, StringComparison.Ordinal);
        Assert.DoesNotContain("IServiceCollection", source, StringComparison.Ordinal);
        Assert.DoesNotContain("AuthenticateAsync", source, StringComparison.Ordinal);
        Assert.DoesNotContain("IClientCertificateProvider", source, StringComparison.Ordinal);
        Assert.Contains("execution.Capabilities.ExecuteTypedSessionHandshakeAsync", source, StringComparison.Ordinal);
        Assert.Contains("execution.Capabilities.ExecuteComposedSoapAsync", source, StringComparison.Ordinal);
        Assert.Contains("execution.Capabilities.CreateSignedTokenAsync", source, StringComparison.Ordinal);
        Assert.Contains("execution.Capabilities.ExecuteRestrictedTransportAsync", source, StringComparison.Ordinal);
        Assert.Contains("SyntheticSecretProviderDependencyStrategy", source, StringComparison.Ordinal);
        Assert.Contains("SyntheticServiceProviderDependencyModule", source, StringComparison.Ordinal);
        Assert.Contains("SyntheticStrategyCollectionDependencyModule", source, StringComparison.Ordinal);

        string applicationFriends = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Application", "AssemblyInfo.cs"));
        Assert.DoesNotContain("Synthetic.ConnectorExecutionModule", applicationFriends, StringComparison.Ordinal);
    }

    [Fact]
    public void Wave1_CT_execution_contract_is_narrow_and_does_not_expose_DI_transport_or_provider_authority()
    {
        string contracts = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Application", "ConnectorExecutionContracts.cs"));
        Assert.Contains("public sealed class AuthorizedConnectorExecution", contracts, StringComparison.Ordinal);
        Assert.Contains("internal AuthorizedConnectorExecution(", contracts, StringComparison.Ordinal);
        Assert.Contains("public Stream OpenPayloadStream()", contracts, StringComparison.Ordinal);
        Assert.Contains("new MemoryStream(payload, writable: false)", contracts, StringComparison.Ordinal);
        Assert.Contains("public IAuthorizedConnectorCapabilityBridge Capabilities", contracts, StringComparison.Ordinal);
        Assert.Contains("public interface IAuthorizedConnectorCapabilityBridge", contracts, StringComparison.Ordinal);
        Assert.Contains("IReadOnlySet<GatewayAuthenticationKind> SupportedAuthenticationKinds", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("public AuthorizedConnectorExecution(", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("IServiceCollection", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("IServiceProvider", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("HttpRequestMessage", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("ISecretValueProvider", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("IClientCertificateProvider", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("byte[] Payload", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("public ReadOnlyMemory<byte>", contracts, StringComparison.Ordinal);
        Assert.DoesNotContain("public Memory<byte>", contracts, StringComparison.Ordinal);
    }

    [Fact]
    public void Wave1_CT_runtime_grants_and_resolves_Published_authority_before_exact_key_selection()
    {
        string runtime = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Application", "OperationServices.cs"));
        int grant = runtime.IndexOf("registry.IsGrantedAsync", StringComparison.Ordinal);
        int published = runtime.IndexOf("catalog.GetRequiredAsync", StringComparison.Ordinal);
        int derive = runtime.IndexOf("ConnectorExecutionStrategyKeys.Resolve(operation)", StringComparison.Ordinal);
        int lookup = runtime.IndexOf("executionStrategyRegistry.Required(strategyKey, operation.Authentication)", StringComparison.Ordinal);
        int handoff = runtime.IndexOf("registration.Strategy.ExecuteAsync(execution", StringComparison.Ordinal);

        Assert.True(grant >= 0 && published > grant && derive > published && lookup > derive && handoff > lookup);
        string selection = runtime[grant..handoff];
        Assert.DoesNotContain("GatewayAuthenticationKind.OpaqueSessionHttp", selection, StringComparison.Ordinal);
        Assert.DoesNotContain("GatewayAuthenticationKind.SoapBasicOpaqueSession", selection, StringComparison.Ordinal);
        Assert.DoesNotContain("CanHandle", selection, StringComparison.Ordinal);
    }

    [Fact]
    public void Wave1_CT_module_loading_is_explicit_exact_bounded_and_never_discovers_assemblies()
    {
        string loader = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Api", "ConnectorExecutionModuleLoader.cs"));
        string options = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Api", "GatewayHostOptions.cs"));
        string host = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Api", "Program.cs"));

        Assert.Contains("MaximumModules = 32", loader, StringComparison.Ordinal);
        Assert.Contains("Path.IsPathFullyQualified", loader, StringComparison.Ordinal);
        Assert.Contains("Path.GetFullPath", loader, StringComparison.Ordinal);
        Assert.Contains("DriveType.Fixed", loader, StringComparison.Ordinal);
        Assert.Contains("FileAttributes.ReparsePoint", loader, StringComparison.Ordinal);
        Assert.Contains("GC.AllocateUninitializedArray<byte>", loader, StringComparison.Ordinal);
        Assert.Contains("ReadMetadata(bytes)", loader, StringComparison.Ordinal);
        Assert.Contains("LoadFromStream(exactBytes)", loader, StringComparison.Ordinal);
        Assert.Contains("loaded.ManifestModule.ModuleVersionId", loader, StringComparison.Ordinal);
        Assert.DoesNotContain("AssemblyName.GetAssemblyName(canonicalPath)", loader, StringComparison.Ordinal);
        Assert.DoesNotContain("LoadFromAssemblyPath", loader, StringComparison.Ordinal);
        Assert.DoesNotContain("assembly.Location", loader, StringComparison.Ordinal);
        Assert.Contains("assembly.GetType(configured.ModuleType", loader, StringComparison.Ordinal);
        Assert.Contains("MaximumStrategiesPerModule = 64", loader, StringComparison.Ordinal);
        Assert.Contains("MaximumRegistrationsPerModule = 128", loader, StringComparison.Ordinal);
        Assert.Contains("constructors.Length != 1", loader, StringComparison.Ordinal);
        Assert.Contains("dependency.Assembly != moduleAssembly", loader, StringComparison.Ordinal);
        Assert.Contains("ValidateConstructorGraph", loader, StringComparison.Ordinal);
        Assert.Contains("AssemblyPath", options, StringComparison.Ordinal);
        Assert.Contains("AssemblyFullName", options, StringComparison.Ordinal);
        Assert.Contains("ModuleType", options, StringComparison.Ordinal);
        Assert.Contains("ConnectorExecutionModuleLoader.Register", host, StringComparison.Ordinal);

        foreach (string forbidden in new[]
        {
            "Directory.GetFiles", "Directory.EnumerateFiles", "AppDomain.CurrentDomain", "GetAssemblies(",
            "EnumerateFileSystemEntries", "*.dll", "Assembly.Load(", "LoadFromAssemblyPath"
        })
            Assert.DoesNotContain(forbidden, loader, StringComparison.Ordinal);
    }

    [Fact]
    public void Wave1_CT_authorized_capability_bridge_is_closed_current_invocation_only_and_not_a_host_facade()
    {
        string contracts = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Application", "ConnectorExecutionContracts.cs"));
        string dispatcher = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.ConnectorRuntime.Auth.Soap", "AuthorizedConnectorCapabilityDispatcher.cs"));
        string runtime = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Application", "OperationServices.cs"));

        Assert.Contains("private sealed class AuthorizedConnectorCapabilityBridge", contracts, StringComparison.Ordinal);
        Assert.Contains("lock (synchronization)", contracts, StringComparison.Ordinal);
        Assert.Contains("ReferenceEquals(Current.Value, this)", contracts, StringComparison.Ordinal);
        Assert.Contains("state = 2", contracts, StringComparison.Ordinal);
        Assert.Contains("lifetime?.Cancel()", contracts, StringComparison.Ordinal);
        Assert.Contains("await task.ConfigureAwait(false)", contracts, StringComparison.Ordinal);
        Assert.Contains("HadInFlightOperations", runtime, StringComparison.Ordinal);
        Assert.Contains("execution.Owns(exception)", runtime, StringComparison.Ordinal);
        Assert.Contains("AcquireAuthorizedAsync", dispatcher, StringComparison.Ordinal);
        Assert.Contains("ExecuteAuthorizedCapabilityAsync", dispatcher, StringComparison.Ordinal);
        foreach (string forbidden in new[]
        {
            "IServiceProvider", "IServiceCollection", "ISecretValueProvider", "IClientCertificateProvider",
            "IConnectorConfigurationStore", "IRestrictedTransport", "Uri ", "string profileId", "string endpoint"
        })
            Assert.DoesNotContain(forbidden, contracts, StringComparison.Ordinal);
    }

    [Fact]
    public void Wave1_CT_capability_completion_has_no_token_provider_store_or_authenticated_HTTP_escape()
    {
        string publicContracts = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Application", "AuthorizedVerticalCapabilityContracts.cs"));
        string bindingInputs = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.ConnectorRuntime.Auth.Soap", "AuthorizedConnectorBindingInputs.cs"));
        string hostRuntime = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Api", "AuthorizedVerticalCapabilityRuntime.cs"));
        string executionContracts = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Application", "ConnectorExecutionContracts.cs"));
        string claimBounds = File.ReadAllText(Path.Combine(Root, "src", "Shared", "Security", "BoundedJwtClaimValidation.cs"));
        string migration = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Infrastructure", "Persistence", "Migrations", "0012_connector_capability_locator_scope.sql"));

        Assert.Contains("internal string CompactToken", publicContracts, StringComparison.Ordinal);
        Assert.DoesNotContain("public string CompactToken", publicContracts, StringComparison.Ordinal);
        Assert.Contains("internal ReadOnlyMemory<byte> Body", publicContracts, StringComparison.Ordinal);
        Assert.DoesNotContain("HttpRequestMessage", publicContracts, StringComparison.Ordinal);
        Assert.DoesNotContain("Uri", publicContracts, StringComparison.Ordinal);
        Assert.DoesNotContain("Provider", publicContracts, StringComparison.Ordinal);
        Assert.Contains("public void WriteRequiredXmlValue(string name)", bindingInputs, StringComparison.Ordinal);
        Assert.DoesNotContain("WriteRequiredXmlValue(XmlWriter", bindingInputs, StringComparison.Ordinal);
        Assert.Contains("internal IDisposable BindToCoreWriter(XmlWriter writer)", bindingInputs, StringComparison.Ordinal);
        Assert.DoesNotContain("public string Get", bindingInputs, StringComparison.Ordinal);
        Assert.DoesNotContain("public string ProviderReference", bindingInputs, StringComparison.Ordinal);
        Assert.True(executionContracts.IndexOf("BoundedJwtClaimValidation.ValidateNext", StringComparison.Ordinal) <
            executionContracts.IndexOf("value.Clone()", StringComparison.Ordinal));
        Assert.DoesNotContain("claims.Count", executionContracts, StringComparison.Ordinal);
        Assert.DoesNotContain("GetRawText", claimBounds, StringComparison.Ordinal);
        Assert.Contains("execution.PublishedAuthority.Matches(snapshot)", hostRuntime, StringComparison.Ordinal);
        Assert.Contains("PurposeBoundMutualTlsSender", hostRuntime, StringComparison.Ordinal);
        Assert.Contains("Rs256JwtSigner", hostRuntime, StringComparison.Ordinal);
        Assert.Contains("authorizedCapabilities' -> 'signing' ->> 'keyBinding'", migration, StringComparison.Ordinal);
        Assert.Contains("typedSessionHandshake' -> 'serverOwnedInputs'", migration, StringComparison.Ordinal);
        Assert.Contains("installation_connector_grant", migration, StringComparison.Ordinal);
    }

    [Fact]
    public void Wave1_CT_generic_seam_and_Core_solution_have_no_vertical_dependency_or_logic()
    {
        string[] files =
        [
            Path.Combine(Root, "src", "Gateway", "Gateway.Application", "ConnectorExecutionContracts.cs"),
            Path.Combine(Root, "src", "Gateway", "Gateway.Application", "OperationServices.cs"),
            Path.Combine(Root, "src", "Gateway", "Gateway.Api", "ConnectorExecutionModuleLoader.cs"),
            Path.Combine(Root, "src", "Gateway", "Gateway.Api", "GatewayHostOptions.cs"),
            Path.Combine(Root, "tests", "support", "Synthetic.ConnectorExecutionModule", "SyntheticExecutionModule.cs")
        ];
        string[] forbidden =
        [
            "F" + "SE", "Sistema" + "TS", "SO" + "GEI", "farma" + "cia", "health" + "care",
            "C" + "GM", "Winges" + "far", "dr" + "CLOUD"
        ];
        foreach (string file in files)
        {
            string source = File.ReadAllText(file);
            foreach (string value in forbidden) Assert.DoesNotContain(value, source, StringComparison.OrdinalIgnoreCase);
        }

        string coreSolution = File.ReadAllText(Path.Combine(Root, "BrokerGateway.Core.slnx"));
        string applicationProject = File.ReadAllText(Path.Combine(Root, "src", "Gateway", "Gateway.Application", "Gateway.Application.csproj"));
        string exportAllowlist = File.ReadAllText(Path.Combine(Root, "eng", "open-source-core.allowlist"));
        Assert.DoesNotContain("ConnectorPacks." + "Healthcare", coreSolution, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ConnectorPacks." + "Healthcare", applicationProject, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("tests/support/Synthetic.ConnectorExecutionModule/", exportAllowlist, StringComparison.Ordinal);
        Assert.Contains("ConnectorExecutionSeamBoundaryTests.cs", exportAllowlist, StringComparison.Ordinal);
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

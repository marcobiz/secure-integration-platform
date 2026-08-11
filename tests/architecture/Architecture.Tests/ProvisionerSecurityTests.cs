using Xunit;

namespace SecureIntegration.Architecture.Tests;

public sealed class ProvisionerSecurityTests
{
    private static readonly string Root = FindRepositoryRoot();

    [Fact]
    public void M5_ARCH_Synthetic_provisioner_uses_the_same_four_eyes_publication_boundary()
    {
        string source = File.ReadAllText(Path.Combine(Root, "tools", "m3", "Provisioner", "Program.cs"));

        Assert.Contains("RequestApprovalAsync", source, StringComparison.Ordinal);
        Assert.Contains("ApproveAsync", source, StringComparison.Ordinal);
        Assert.Contains("PublishApprovedAsync", source, StringComparison.Ordinal);
        Assert.DoesNotContain("connectorStore.PublishAsync", source, StringComparison.Ordinal);
        Assert.Contains("m3-editor", source, StringComparison.Ordinal);
        Assert.Contains("m3-approver", source, StringComparison.Ordinal);
    }

    [Fact]
    public void M5_ARCH_Selective_container_builds_include_linked_shared_sources_and_the_runtime_wire_contract()
    {
        string dockerfile = File.ReadAllText(Path.Combine(Root, "tools", "m3", "Provisioner", "Dockerfile"));

        Assert.Contains("COPY src/Shared/Security/BoundedJwtClaimValidation.cs src/Shared/Security/BoundedJwtClaimValidation.cs", dockerfile, StringComparison.Ordinal);
        Assert.Contains("COPY docs/api/runtime-wire-codes.json docs/api/runtime-wire-codes.json", dockerfile, StringComparison.Ordinal);
    }

    private static string FindRepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, ".git")) || File.Exists(Path.Combine(directory.FullName, "BrokerGateway.Core.slnx"))) return directory.FullName;
            directory = directory.Parent;
        }
        throw new InvalidOperationException("Repository root not found.");
    }
}

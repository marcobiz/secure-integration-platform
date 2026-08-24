using System.Diagnostics;
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
        Assert.Equal("'$(_ProductVersionExcluded)' != 'True'", props.Descendants("Version").Single().Parent?.Attribute("Condition")?.Value);

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
    public void ALPHA_VER_optional_pack_assembly_versions_are_not_rewritten_by_the_Core_product_version()
    {
        XDocument props = XDocument.Load(Path.Combine(Root, "Directory.Build.props"));
        string exclusion = props.Descendants("_ProductVersionExcluded").Single().Value;
        Assert.Contains("packs", exclusion, StringComparison.Ordinal);
        Assert.Contains("src/ConnectorPacks", exclusion, StringComparison.Ordinal);
    }

    [Fact]
    public void ALPHA_LIC_package_API_and_OCI_metadata_match_the_path_policy()
    {
        XDocument props = XDocument.Load(Path.Combine(Root, "Directory.Build.props"));
        Assert.Equal("MPL-2.0", props.Descendants("PackageLicenseExpression").Single().Value);
        Assert.Equal("https://github.com/marcobiz/secure-integration-platform", props.Descendants("RepositoryUrl").Single().Value);
        Assert.Equal("ApoCert S.r.l.", props.Descendants("Company").Single().Value);

        XDocument sdk = XDocument.Load(Path.Combine(Root, "sdk", "dotnet", "Broker.Sdk", "Broker.Sdk.csproj"));
        XDocument contracts = XDocument.Load(Path.Combine(Root, "src", "Shared", "SecureIntegration.Contracts", "SecureIntegration.Contracts.csproj"));
        Assert.Equal("Apache-2.0", sdk.Descendants("PackageLicenseExpression").Single().Value);
        Assert.Equal("Apache-2.0", contracts.Descendants("PackageLicenseExpression").Single().Value);

        using JsonDocument admin = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "src", "Admin", "Admin.Web", "package.json")));
        Assert.Equal("MPL-2.0", admin.RootElement.GetProperty("license").GetString());
        Assert.Contains("identifier: Apache-2.0", File.ReadAllText(Path.Combine(Root, "docs", "api", "gateway-openapi.yaml")), StringComparison.Ordinal);

        foreach (string relativePath in new[] { "src/Gateway/Gateway.Api/Dockerfile", "src/Gateway/Gateway.Migrations/Dockerfile" })
        {
            string dockerfile = File.ReadAllText(Path.Combine(Root, relativePath.Replace('/', Path.DirectorySeparatorChar)));
            Assert.Contains("org.opencontainers.image.licenses=\"MPL-2.0\"", dockerfile, StringComparison.Ordinal);
            Assert.Contains("org.opencontainers.image.vendor=\"ApoCert S.r.l.\"", dockerfile, StringComparison.Ordinal);
            Assert.Contains("COPY LICENSE NOTICE /licenses/", dockerfile, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ALPHA_LIC_five_artifact_license_expressions_are_exact_and_bound_to_release_metadata()
    {
        using JsonDocument template = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "deploy", "release-manifest.template.json")));
        JsonElement policy = template.RootElement.GetProperty("licensePolicy");
        JsonElement publication = template.RootElement.GetProperty("publication");
        JsonElement claims = template.RootElement.GetProperty("claims");
        Assert.Equal(2, template.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("public-technical-preview", template.RootElement.GetProperty("releaseChannel").GetString());
        Assert.Equal("pre-publication-candidate", publication.GetProperty("state").GetString());
        Assert.False(publication.GetProperty("occurred").GetBoolean());
        Assert.Equal("release-manifest.json", publication.GetProperty("publicManifestName").GetString());
        Assert.Equal(2, publication.GetProperty("publicSbomAssets").GetArrayLength());
        Assert.Equal(9, publication.GetProperty("internalEvidenceSboms").GetArrayLength());
        Assert.False(claims.TryGetProperty("publicReleaseGo", out _));
        Assert.False(claims.GetProperty("productionReady").GetBoolean());
        Assert.Equal("MPL-2.0", policy.GetProperty("default").GetString());
        Assert.Equal("Apache-2.0", policy.GetProperty("sdk").GetString());
        Assert.Equal("MPL-2.0 OR Apache-2.0", policy.GetProperty("genericReference").GetString());
        Assert.Equal("MPL-2.0 AND Apache-2.0", policy.GetProperty("coreSourceArchive").GetString());

        string writer = File.ReadAllText(Path.Combine(Root, "eng", "Build-AlphaReleaseArtifacts.ps1"));
        string validator = File.ReadAllText(Path.Combine(Root, "eng", "Test-AlphaReleaseArtifacts.ps1"));
        Assert.Contains("$record['licenseExpression']", writer, StringComparison.Ordinal);
        Assert.Contains("ALPHA_ARTIFACT_MANIFEST_LICENSE_MISMATCH", validator, StringComparison.Ordinal);
        Assert.Contains("ALPHA_ARTIFACT_NUGET_LICENSE_MISMATCH", validator, StringComparison.Ordinal);
        Assert.Contains("ALPHA_ARTIFACT_CORE_LICENSE_CONTENT_INVALID", validator, StringComparison.Ordinal);
        Assert.Contains("ALPHA_ARTIFACT_ADMIN_LICENSE_CONTENT_INVALID", validator, StringComparison.Ordinal);
        Assert.Contains("ALPHA_ARTIFACT_SBOM_SUBJECT_LICENSE_MISMATCH", validator, StringComparison.Ordinal);
    }

    [Fact]
    public void ALPHA_LIC_all_tracked_paths_canonical_texts_and_publishable_placeholders_pass_the_gate()
    {
        AssertPowerShellScriptPass("eng/Test-LicensePolicy.Tests.ps1", "ALPHA_LIC_license_policy_self_tests PASS");
        AssertPowerShellScriptPass("eng/Test-LicensePolicy.ps1", "LICENSE_POLICY_PASS");
    }

    [Fact]
    public void ALPHA_DCO_current_PR_range_gate_has_positive_negative_and_non_retroactive_tests()
    {
        AssertPowerShellScriptPass("eng/Test-DcoSignoff.Tests.ps1", "ALPHA_DCO_self_tests PASS");
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
        Assert.Contains("eng/AlphaReleaseContainerArchive.psm1", allowlist, StringComparison.Ordinal);
        Assert.Contains("eng/AlphaReleaseEvidenceContract.psm1", allowlist, StringComparison.Ordinal);
        Assert.Contains("eng/Test-AlphaReleaseContainerBinding.ps1", allowlist, StringComparison.Ordinal);
        Assert.Contains("eng/Write-AlphaReleaseEvidence.ps1", allowlist, StringComparison.Ordinal);
    }

    [Fact]
    public void ALPHA_ART_container_tar_identity_is_bound_to_loaded_image_and_sbom_subject()
    {
        string validator = File.ReadAllText(Path.Combine(Root, "eng", "Test-AlphaReleaseArtifacts.ps1"));
        Assert.Contains("Get-AlphaReleaseContainerTarIdentity", validator, StringComparison.Ordinal);
        Assert.Contains("ALPHA_ARTIFACT_TAR_IMAGE_ID_MISMATCH", validator, StringComparison.Ordinal);
        Assert.Contains("ALPHA_ARTIFACT_TAR_SUBJECT_IDENTITY_MISMATCH", validator, StringComparison.Ordinal);
        AssertPowerShellTestPass("eng/Test-AlphaReleaseContainerTarInspection.ps1", "Identity", "ALPHA_ART_CONTAINER_TAR_IDENTITY_PASS");
    }

    [Fact]
    public void ALPHA_ART_rejects_preexisting_candidate_image_tags_without_mutation()
    {
        string validator = File.ReadAllText(Path.Combine(Root, "eng", "Test-AlphaReleaseArtifacts.ps1"));
        string harness = File.ReadAllText(Path.Combine(Root, "eng", "Test-AlphaReleaseContainerBinding.ps1"));
        Assert.Contains("ALPHA_ART_CANDIDATE_IMAGE_TAG_PREEXISTING", validator, StringComparison.Ordinal);
        Assert.Contains("PreexistingGatewayTag", harness, StringComparison.Ordinal);
        Assert.Contains("PreexistingMigrationsTag", harness, StringComparison.Ordinal);
        Assert.Contains("BothPreexistingTags", harness, StringComparison.Ordinal);
        Assert.Contains("ALPHA_ART_CONTAINER_PREEXISTING_TAG_NEGATIVES_PASS", harness, StringComparison.Ordinal);
    }

    [Fact]
    public void ALPHA_ART_rejects_swapped_container_tar_bytes_with_preloaded_tags()
    {
        string harness = File.ReadAllText(Path.Combine(Root, "eng", "Test-AlphaReleaseContainerBinding.ps1"));
        Assert.Contains("SwappedTarEmptyDaemon", harness, StringComparison.Ordinal);
        Assert.Contains("SwappedTarPreloadedTags", harness, StringComparison.Ordinal);
        Assert.Contains("ALPHA_ART_CONTAINER_SWAPPED_TAR_NEGATIVES_PASS", harness, StringComparison.Ordinal);
        AssertPowerShellTestPass("eng/Test-AlphaReleaseContainerTarInspection.ps1", "SwappedAndWrongRepoTag", "ALPHA_ART_CONTAINER_TAR_SWAPPED_AND_REPOTAG_NEGATIVES_PASS");
    }

    [Fact]
    public void ALPHA_ART_rejects_tar_config_and_sbom_subject_identity_mismatch()
    {
        string validator = File.ReadAllText(Path.Combine(Root, "eng", "Test-AlphaReleaseArtifacts.ps1"));
        string harness = File.ReadAllText(Path.Combine(Root, "eng", "Test-AlphaReleaseContainerBinding.ps1"));
        Assert.Contains("boundImageIds -cnotcontains $declaredImageId", validator, StringComparison.Ordinal);
        Assert.Contains("$loadedImageId -cne [string]$identity.imageId", validator, StringComparison.Ordinal);
        Assert.Contains("ALPHA_ARTIFACT_BINDING_SOURCE_ID_NOT_BOUND_TO_TAR", harness, StringComparison.Ordinal);
        Assert.Contains("RegeneratedManifestAndSbomForWrongTarRole", harness, StringComparison.Ordinal);
        AssertPowerShellTestPass("eng/Test-AlphaReleaseContainerTarInspection.ps1", "ConfigDigestAndRole", "ALPHA_ART_CONTAINER_TAR_CONFIG_DIGEST_AND_ROLE_NEGATIVES_PASS");
    }

    [Fact]
    public void ALPHA_ART_evidence_rejects_stale_or_cross_run_normalized_digest()
    {
        string writer = File.ReadAllText(Path.Combine(Root, "eng", "Write-AlphaReleaseEvidence.ps1"));
        string contract = File.ReadAllText(Path.Combine(Root, "eng", "AlphaReleaseEvidenceContract.psm1"));
        Assert.Contains("-ReleaseSetOnly", writer, StringComparison.Ordinal);
        Assert.Contains("ALPHA_ART_EVIDENCE_NORMALIZED_DIGEST_MISMATCH", contract, StringComparison.Ordinal);
        AssertPowerShellTestPass("eng/Test-AlphaReleaseEvidenceConsistency.ps1", "StaleOrCrossRun", "ALPHA_ART_EVIDENCE_STALE_OR_CROSS_RUN_NEGATIVES_PASS");
    }

    [Fact]
    public void ALPHA_ART_evidence_rejects_unknown_duplicate_or_resealed_supplemental_identity()
    {
        string contract = File.ReadAllText(Path.Combine(Root, "eng", "AlphaReleaseEvidenceContract.psm1"));
        string writer = File.ReadAllText(Path.Combine(Root, "eng", "Write-AlphaReleaseEvidence.ps1"));
        string validator = File.ReadAllText(Path.Combine(Root, "eng", "Test-AlphaReleaseEvidence.ps1"));
        Assert.Contains("Assert-AlphaReleaseEvidenceRecordInventory", writer, StringComparison.Ordinal);
        Assert.Contains("Assert-AlphaReleaseEvidenceRecordInventory", validator, StringComparison.Ordinal);
        Assert.Contains("ALPHA_ART_EVIDENCE_RECORD_UNKNOWN", contract, StringComparison.Ordinal);
        Assert.Contains("ALPHA_ART_EVIDENCE_RECORD_DUPLICATE", contract, StringComparison.Ordinal);
        Assert.Contains("ExpectedNormalizedDigest", validator, StringComparison.Ordinal);
        AssertPowerShellTestPass("eng/Test-AlphaReleaseEvidenceConsistency.ps1", "ClosedInventory", "ALPHA_ART_EVIDENCE_CLOSED_INVENTORY_NEGATIVES_PASS");
    }

    [Fact]
    public void ALPHA_ART_release_set_requires_exact_artifact_manifest_checksum_bijection()
    {
        AssertPowerShellTestPass("eng/Test-AlphaReleaseSetBijection.ps1", "ArtifactBijection", "ALPHA_ART_RELEASE_SET_EXACT_BIJECTION_PASS");
    }

    [Fact]
    public void ALPHA_ART_release_set_rejects_missing_and_unexpected_artifacts()
    {
        AssertPowerShellTestPass("eng/Test-AlphaReleaseSetBijection.ps1", "ArtifactMissingUnexpected", "ALPHA_ART_RELEASE_SET_MISSING_UNEXPECTED_NEGATIVES_PASS");
    }

    [Fact]
    public void ALPHA_ART_release_set_requires_exact_sbom_subject_bijection()
    {
        AssertPowerShellTestPass("eng/Test-AlphaReleaseSetBijection.ps1", "SbomBijection", "ALPHA_ART_RELEASE_SET_EXACT_SBOM_SUBJECT_BIJECTION_PASS");
    }

    [Fact]
    public void ALPHA_ART_release_set_rejects_wrong_or_extra_sbom_association()
    {
        AssertPowerShellTestPass("eng/Test-AlphaReleaseSetBijection.ps1", "SbomWrongExtra", "ALPHA_ART_RELEASE_SET_WRONG_EXTRA_SBOM_NEGATIVES_PASS");
    }

    [Fact]
    public void ALPHA_ART_future_publication_contract_rejects_ambiguous_state_and_sbom_inventories()
    {
        AssertPowerShellTestPass("eng/Test-AlphaReleaseSetBijection.ps1", "PublicationContract", "ALPHA_ART_FUTURE_PUBLICATION_CONTRACT_NEGATIVES_PASS");
    }

    [Fact]
    public void ALPHA_REL_post_release_truth_and_future_publication_contract_are_closed()
    {
        AssertPowerShellTestPass("eng/Test-PostReleaseTruth.ps1", "FutureContract", "POST_RELEASE_TRUTH_FUTURE_CONTRACT_PASS");
    }

    [Fact]
    public void CORE_INVENTORY_rejects_drive_qualified_paths_cross_host()
    {
        AssertPowerShellTestPass("eng/Test-CoreExportInventoryDeterminism.ps1", "DriveQualifiedPaths", "CORE_INVENTORY_DRIVE_QUALIFIED_PATH_NEGATIVE_PASS");
    }

    [Fact]
    public void CORE_INVENTORY_rejects_ads_style_path_identities()
    {
        AssertPowerShellTestPass("eng/Test-CoreExportInventoryDeterminism.ps1", "AdsPaths", "CORE_INVENTORY_ADS_PATH_NEGATIVE_PASS");
    }

    private static void AssertPowerShellTestPass(string relativeScript, string testName, string expectedMarker)
    {
        string host = OperatingSystem.IsWindows() ? "powershell.exe" : "pwsh";
        ProcessStartInfo startInfo = new()
        {
            FileName = host,
            WorkingDirectory = Root,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        if (OperatingSystem.IsWindows()) startInfo.Environment.Remove("PSModulePath");
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-File");
        startInfo.ArgumentList.Add(Path.Combine(Root, relativeScript.Replace('/', Path.DirectorySeparatorChar)));
        startInfo.ArgumentList.Add("-TestName");
        startInfo.ArgumentList.Add(testName);

        using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException("PowerShell test process did not start.");
        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
        Task<string> stderrTask = process.StandardError.ReadToEndAsync();
        bool exited = process.WaitForExit(120_000);
        if (!exited)
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
        }
        string stdout = stdoutTask.GetAwaiter().GetResult();
        string stderr = stderrTask.GetAwaiter().GetResult();
        Assert.True(exited, $"PowerShell test timed out: {relativeScript} {testName}");
        Assert.True(process.ExitCode == 0, $"PowerShell test failed: {relativeScript} {testName}; stderr={stderr}");
        Assert.Contains(expectedMarker, stdout, StringComparison.Ordinal);
    }

    private static void AssertPowerShellScriptPass(string relativeScript, string expectedMarker)
    {
        string host = OperatingSystem.IsWindows() ? "powershell.exe" : "pwsh";
        ProcessStartInfo startInfo = new()
        {
            FileName = host,
            WorkingDirectory = Root,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        if (OperatingSystem.IsWindows()) startInfo.Environment.Remove("PSModulePath");
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-File");
        startInfo.ArgumentList.Add(Path.Combine(Root, relativeScript.Replace('/', Path.DirectorySeparatorChar)));

        using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException("PowerShell test process did not start.");
        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
        Task<string> stderrTask = process.StandardError.ReadToEndAsync();
        bool exited = process.WaitForExit(120_000);
        if (!exited)
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
        }
        string stdout = stdoutTask.GetAwaiter().GetResult();
        string stderr = stderrTask.GetAwaiter().GetResult();
        Assert.True(exited, $"PowerShell test timed out: {relativeScript}");
        Assert.True(process.ExitCode == 0, $"PowerShell test failed: {relativeScript}; stderr={stderr}");
        Assert.Contains(expectedMarker, stdout, StringComparison.Ordinal);
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

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Tools.ConnectorProvisioning;
using SecureIntegration.Tools.Fse2.OfficialTestProvisioner;
using Xunit;
using ProvisionerProgram = SecureIntegration.Tools.Fse2.OfficialTestProvisioner.Program;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Integration.Tests;

public sealed class Fse2ProvisionerResumabilityIntegrationTests
{
    private static readonly JsonSerializerOptions WireJson = CreateJson();

    [Fact]
    public async Task PROVISIONER_rate_limit_after_Validated_returns_bounded_resumable_state()
    {
        Scenario scenario = await Scenario.CreateAsync(rateLimitBindingOnce: true);

        ProvisionerProgram.ProvisioningException failure = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(
            () => ProvisionerProgram.ConfigureAsync(scenario.Security, scenario.SecurityContext));

        ConnectorProvisioningRateLimitResult result = Assert.IsType<ConnectorProvisioningRateLimitResult>(failure.RateLimitResult);
        Assert.Equal("BGW-PROVISIONING-RATE-LIMITED", result.Code);
        Assert.Equal(ConnectorProvisioningCurrentState.Validated, result.CurrentState);
        Assert.Equal(ConnectorProvisioningPhase.BindingConfiguration, result.NextRequiredPhase);
        Assert.True(result.RetrySafe);
        Assert.Equal(37, result.RetryAfterSeconds);
        Assert.Equal("fse2-officialtest configure <operational-plan.json>", result.SupportedCommand);
        Assert.Equal(1, scenario.Backend.ImportCount);
        Assert.Equal(1, scenario.Backend.StoredValidationCount);
        Assert.Equal(1, scenario.Backend.BindingAttemptCount);
        Assert.Equal(SimulatedProvisioningState.Validated, scenario.Backend.State);
    }

    [Fact]
    public async Task PROVISIONER_same_plan_resumes_from_Validated_and_reaches_Published_Active()
    {
        Scenario scenario = await Scenario.CreateAsync(rateLimitBindingOnce: true);
        _ = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(
            () => ProvisionerProgram.ConfigureAsync(scenario.Security, scenario.SecurityContext));

        await ProvisionerProgram.ConfigureAsync(scenario.Security, scenario.SecurityContext);
        Assert.Equal(1, scenario.Backend.ImportCount);
        Assert.Equal(1, scenario.Backend.StoredValidationCount);
        Assert.Equal(2, scenario.Backend.BindingAttemptCount);
        await scenario.CompleteAsync();

        ProvisionerProgram.DiscoveredProvisioningState final = await ProvisionerProgram.DiscoverProvisioningStateAsync(
            scenario.Approver,
            await ProvisionerProgram.PreflightAsync(scenario.Approver, scenario.Plan));
        Assert.Equal(ConnectorProvisioningCurrentState.PublishedActive, final.Snapshot.CurrentState);
        Assert.Null(final.Snapshot.NextRequiredPhase);
        Assert.Equal("Published", final.VersionState);
        Assert.Equal("Active", final.BindingState);
    }

    [Fact]
    public Task PROVISIONER_rate_limit_after_Validated_remains_resumable() =>
        PROVISIONER_rate_limit_after_Validated_returns_bounded_resumable_state();

    [Fact]
    public Task PROVISIONER_same_plan_resume_still_reaches_Published_Active() =>
        PROVISIONER_same_plan_resumes_from_Validated_and_reaches_Published_Active();

    [Fact]
    public async Task PROVISIONER_reentry_after_Published_is_verify_only_noop()
    {
        Scenario scenario = await Scenario.CreateAsync();
        await scenario.ReachPublishedAsync();
        int before = scenario.Backend.SuccessfulMutationCount;

        await ProvisionerProgram.ConfigureAsync(scenario.Security, scenario.SecurityContext);
        await ProvisionerProgram.GrantAsync(scenario.Security, scenario.SecurityContext);
        await ProvisionerProgram.ProposeAsync(scenario.Editor, await ProvisionerProgram.PreflightAsync(scenario.Editor, scenario.Plan));
        await ProvisionerProgram.ApproveAsync(
            scenario.Approver,
            await ProvisionerProgram.PreflightAsync(scenario.Approver, scenario.Plan),
            scenario.Backend.ApprovalRequestId,
            scenario.Backend.ApprovalDigest);
        await ProvisionerProgram.PublishAsync(
            scenario.Approver,
            await ProvisionerProgram.PreflightAsync(scenario.Approver, scenario.Plan),
            expectedPublicationRevision: 0);

        Assert.Equal(before, scenario.Backend.SuccessfulMutationCount);
        Assert.Equal(SimulatedProvisioningState.Published, scenario.Backend.State);
    }

    [Fact]
    public async Task PROVISIONER_resume_rejects_definition_checksum_drift_before_mutation()
    {
        Scenario scenario = await Scenario.CreateAsync();
        await ProvisionerProgram.ConfigureAsync(scenario.Security, scenario.SecurityContext);
        int before = scenario.Backend.SuccessfulMutationCount;
        scenario.Backend.DefinitionChecksumDrift = true;

        ProvisionerProgram.ProvisioningException failure = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(
            () => ProvisionerProgram.GrantAsync(scenario.Security, scenario.SecurityContext));

        Assert.Equal("BGW-PROVISIONING-IDENTITY-DRIFT", failure.Code);
        Assert.Equal(before, scenario.Backend.SuccessfulMutationCount);
        AssertNoRuntimeEffects(scenario.Backend);
    }

    [Fact]
    public async Task PROVISIONER_resume_rejects_installation_environment_drift_before_mutation()
    {
        Scenario scenario = await Scenario.CreateAsync();
        await ProvisionerProgram.ConfigureAsync(scenario.Security, scenario.SecurityContext);
        int before = scenario.Backend.SuccessfulMutationCount;
        scenario.Backend.InstallationEnvironmentDrift = true;

        ProvisionerProgram.ProvisioningException failure = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(
            () => ProvisionerProgram.GrantAsync(scenario.Security, scenario.SecurityContext));

        Assert.Equal("FSE2_OFFICIALTEST_INSTALLATION_AUTHORITY_DRIFT", failure.Code);
        Assert.Equal(before, scenario.Backend.SuccessfulMutationCount);
        AssertNoRuntimeEffects(scenario.Backend);
    }

    [Fact]
    public async Task PROVISIONER_resume_rejects_binding_or_provider_revision_drift_before_mutation()
    {
        Scenario binding = await Scenario.CreateAsync();
        await ProvisionerProgram.ConfigureAsync(binding.Security, binding.SecurityContext);
        int bindingBefore = binding.Backend.SuccessfulMutationCount;
        binding.Backend.BindingProviderRevisionDrift = true;
        ProvisionerProgram.ProvisioningException bindingFailure = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(
            () => ProvisionerProgram.GrantAsync(binding.Security, binding.SecurityContext));
        Assert.Equal("BGW-PROVISIONING-IDENTITY-DRIFT", bindingFailure.Code);
        Assert.Equal(bindingBefore, binding.Backend.SuccessfulMutationCount);

        Scenario provider = await Scenario.CreateAsync();
        await ProvisionerProgram.ConfigureAsync(provider.Security, provider.SecurityContext);
        int providerBefore = provider.Backend.SuccessfulMutationCount;
        provider.Backend.ProviderCatalogRevisionDrift = true;
        ProvisionerProgram.ProvisioningException providerFailure = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(
            () => ProvisionerProgram.GrantAsync(provider.Security, provider.SecurityContext));
        Assert.Equal("FSE2_OFFICIALTEST_PROVIDER_AUTHORITY_DRIFT", providerFailure.Code);
        Assert.Equal(providerBefore, provider.Backend.SuccessfulMutationCount);
        AssertNoRuntimeEffects(binding.Backend);
        AssertNoRuntimeEffects(provider.Backend);
    }

    [Fact]
    public async Task PROVISIONER_rate_limit_does_not_bypass_four_eyes_or_role_separation()
    {
        Scenario scenario = await Scenario.CreateAsync(rateLimitBindingOnce: true);
        _ = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(
            () => ProvisionerProgram.ConfigureAsync(scenario.Security, scenario.SecurityContext));
        ProvisionerProgram.ProvisioningContext editorContext = await ProvisionerProgram.PreflightAsync(scenario.Editor, scenario.Plan);

        ProvisionerProgram.ProvisioningException roleDenied = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(
            () => ProvisionerProgram.ConfigureAsync(scenario.Editor, editorContext));
        Assert.Equal("FSE2_OFFICIALTEST_ADMIN_REJECTED_403", roleDenied.Code);
        Assert.Equal(SimulatedProvisioningState.Validated, scenario.Backend.State);

        await ProvisionerProgram.ConfigureAsync(scenario.Security, scenario.SecurityContext);
        await ProvisionerProgram.GrantAsync(scenario.Security, scenario.SecurityContext);
        await ProvisionerProgram.ProposeAsync(scenario.Editor, editorContext);
        ProvisionerProgram.ProvisioningException selfApproval = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(
            () => ProvisionerProgram.ApproveAsync(
                scenario.Editor,
                editorContext,
                scenario.Backend.ApprovalRequestId,
                scenario.Backend.ApprovalDigest));
        Assert.Equal("FSE2_OFFICIALTEST_ADMIN_REJECTED_403", selfApproval.Code);
        Assert.Equal(SimulatedProvisioningState.Requested, scenario.Backend.State);
    }

    [Fact]
    public async Task PROVISIONER_rate_limit_result_contains_no_raw_response_cookie_token_or_secret()
    {
        Scenario scenario = await Scenario.CreateAsync(rateLimitBindingOnce: true);
        ProvisionerProgram.ProvisioningException failure = await Assert.ThrowsAsync<ProvisionerProgram.ProvisioningException>(
            () => ProvisionerProgram.ConfigureAsync(scenario.Security, scenario.SecurityContext));

        string serialized = JsonSerializer.Serialize(failure.RateLimitResult, WireJson);
        Assert.Contains("BGW-PROVISIONING-RATE-LIMITED", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(SimulatedBackend.SecretCanary, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("Authorization", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("responseBody", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("exception", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.InRange(serialized.Length, 1, 2048);
        ConnectorProvisioningRateLimitResult invalidDelay = ConnectorProvisioningStateMachine.RateLimited(
            failure.RateLimitResult is null
                ? throw new InvalidOperationException("Synthetic rate-limit result missing.")
                : new ConnectorProvisioningSnapshot(
                    failure.RateLimitResult.CurrentState,
                    failure.RateLimitResult.CompletedPhases,
                    failure.RateLimitResult.NextRequiredPhase,
                    failure.RateLimitResult.RetrySafe),
            TimeSpan.FromHours(2),
            "synthetic provision <plan>");
        Assert.Null(invalidDelay.RetryAfterSeconds);
        AssertNoRuntimeEffects(scenario.Backend);
    }

    [Fact]
    public async Task PROVISIONER_clean_state_supported_path_still_reaches_Published_Active()
    {
        Scenario scenario = await Scenario.CreateAsync();

        await scenario.ReachPublishedAsync();

        Assert.Equal(SimulatedProvisioningState.Published, scenario.Backend.State);
        Assert.Equal(7, scenario.Backend.SuccessfulMutationCount);
        Assert.Equal(1, scenario.Backend.ImportCount);
        Assert.Equal(1, scenario.Backend.PublishCount);
        AssertNoRuntimeEffects(scenario.Backend);
    }

    [Fact]
    public void PROVISIONER_resumability_is_connector_neutral()
    {
        ConnectorProvisioningIdentity expected = NeutralIdentity("synthetic-neutral", Guid.Parse("10101010-1010-1010-1010-101010101010"));
        ConnectorProvisioningSnapshot snapshot = ConnectorProvisioningStateMachine.Evaluate(
            expected,
            NeutralIdentity("synthetic-neutral", Guid.Parse("10101010-1010-1010-1010-101010101010")),
            [ConnectorProvisioningPhase.DefinitionImported, ConnectorProvisioningPhase.StoredValidation]);

        Assert.Equal(ConnectorProvisioningCurrentState.Validated, snapshot.CurrentState);
        Assert.Equal(ConnectorProvisioningPhase.BindingConfiguration, snapshot.NextRequiredPhase);
        ConnectorProvisioningIdentityDriftException applicationDrift = Assert.Throws<ConnectorProvisioningIdentityDriftException>(() =>
            ConnectorProvisioningStateMachine.Evaluate(
                expected,
                NeutralIdentity("synthetic-neutral", Guid.Parse("20202020-2020-2020-2020-202020202020")),
                [ConnectorProvisioningPhase.DefinitionImported]));
        Assert.Equal("BGW-PROVISIONING-IDENTITY-DRIFT", applicationDrift.Message);
        Assert.DoesNotContain("FSE2", typeof(ConnectorProvisioningStateMachine).AssemblyQualifiedName!, StringComparison.OrdinalIgnoreCase);
    }

    private static ConnectorProvisioningIdentity NeutralIdentity(string connectorId, Guid applicationId) => new(
        connectorId,
        "3.4.5",
        new string('A', 64),
        Guid.Parse("30303030-3030-3030-3030-303030303030"),
        new string('B', 64),
        new string('C', 64),
        applicationId,
        [new("certificate", "neutral-provider", "certificate-one", "7", 4, 9)]);

    private static void AssertNoRuntimeEffects(SimulatedBackend backend)
    {
        Assert.Equal(0, backend.SigningCount);
        Assert.Equal(0, backend.DnsCount);
        Assert.Equal(0, backend.HttpsCount);
        Assert.Equal(0, backend.TransportCount);
        Assert.Equal(0, backend.NetworkCount);
    }

    private sealed class Scenario
    {
        private Scenario(Fse2OfficialTestOperationalPlan plan, SimulatedBackend backend)
        {
            Plan = plan;
            Backend = backend;
            Security = backend.Api("security");
            Editor = backend.Api("editor");
            Approver = backend.Api("approver");
        }

        internal Fse2OfficialTestOperationalPlan Plan { get; }
        internal SimulatedBackend Backend { get; }
        internal SimulatedApi Security { get; }
        internal SimulatedApi Editor { get; }
        internal SimulatedApi Approver { get; }
        internal ProvisionerProgram.ProvisioningContext SecurityContext { get; private set; } = null!;

        internal static async Task<Scenario> CreateAsync(bool rateLimitBindingOnce = false)
        {
            Fse2OfficialTestOperationalPlan plan = PlanFactory();
            Scenario scenario = new(plan, new SimulatedBackend(plan) { RateLimitBindingOnce = rateLimitBindingOnce });
            scenario.SecurityContext = await ProvisionerProgram.PreflightAsync(scenario.Security, plan);
            scenario.Backend.Compiled = scenario.SecurityContext.Compiled;
            return scenario;
        }

        internal async Task CompleteAsync()
        {
            await ProvisionerProgram.GrantAsync(Security, SecurityContext);
            await ProvisionerProgram.ProposeAsync(Editor, await ProvisionerProgram.PreflightAsync(Editor, Plan));
            await ProvisionerProgram.ApproveAsync(
                Approver,
                await ProvisionerProgram.PreflightAsync(Approver, Plan),
                Backend.ApprovalRequestId,
                Backend.ApprovalDigest);
            await ProvisionerProgram.PublishAsync(
                Approver,
                await ProvisionerProgram.PreflightAsync(Approver, Plan),
                expectedPublicationRevision: 0);
        }

        internal async Task ReachPublishedAsync()
        {
            await ProvisionerProgram.ConfigureAsync(Security, SecurityContext);
            await CompleteAsync();
        }
    }

    private enum SimulatedProvisioningState
    {
        Missing,
        Draft,
        Validated,
        Bound,
        Granted,
        Requested,
        Approved,
        Published
    }

    private sealed class SimulatedBackend(Fse2OfficialTestOperationalPlan plan)
    {
        internal const string SecretCanary = "SECRET-CANARY-MUST-NEVER-LEAVE-BACKEND";
        private static readonly Guid ApplicationId = Guid.Parse("66666666-6666-6666-6666-666666666666");
        private static readonly Guid SecurityId = Guid.Parse("77777777-7777-7777-7777-777777777777");
        private static readonly Guid EditorId = Guid.Parse("88888888-8888-8888-8888-888888888888");
        private static readonly Guid ApproverId = Guid.Parse("99999999-9999-9999-9999-999999999999");
        private bool rateLimitConsumed;

        internal SimulatedProvisioningState State { get; private set; }
        internal Fse2OfficialTestCompiledConfiguration Compiled { get; set; } = null!;
        internal bool RateLimitBindingOnce { get; init; }
        internal bool DefinitionChecksumDrift { get; set; }
        internal bool InstallationEnvironmentDrift { get; set; }
        internal bool BindingProviderRevisionDrift { get; set; }
        internal bool ProviderCatalogRevisionDrift { get; set; }
        internal Guid ApprovalRequestId { get; } = Guid.Parse("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA");
        internal string ApprovalDigest { get; } = new('D', 64);
        internal int SuccessfulMutationCount { get; private set; }
        internal int ImportCount { get; private set; }
        internal int StoredValidationCount { get; private set; }
        internal int BindingAttemptCount { get; private set; }
        internal int PublishCount { get; private set; }
        internal int SigningCount { get; }
        internal int DnsCount { get; }
        internal int HttpsCount { get; }
        internal int TransportCount { get; }
        internal int NetworkCount { get; }

        internal SimulatedApi Api(string role) => role switch
        {
            "security" => new(this, role, SecurityId),
            "editor" => new(this, role, EditorId),
            "approver" => new(this, role, ApproverId),
            _ => throw new InvalidOperationException("Unknown synthetic role.")
        };

        internal Task<JsonElement> GetAsync(string relative)
        {
            if (relative.StartsWith("admin/api/v1/installations?", StringComparison.Ordinal))
                return Value(new
                {
                    items = new[] { new { id = plan.InstallationId, tenantId = plan.TenantId, applicationId = ApplicationId,
                        environmentId = InstallationEnvironmentDrift ? Guid.Parse("ABABABAB-ABAB-ABAB-ABAB-ABABABABABAB") : plan.EnvironmentId,
                        status = "Active", installationKind = "Broker" } }, total = 1, offset = 0, limit = 100
                });
            if (relative.StartsWith("admin/api/v1/environments?", StringComparison.Ordinal))
                return Value(new { items = new[] { new { id = plan.EnvironmentId } }, total = 1, offset = 0, limit = 100 });
            if (relative.StartsWith("admin/api/v1/provider-resources:resolve?", StringComparison.Ordinal))
            {
                Fse2OfficialTestProviderReference reference = relative.Contains("resourceId=officialtest-a1", StringComparison.Ordinal) ? plan.A1 : plan.S1;
                long revision = ProviderCatalogRevisionDrift ? reference.CatalogRevision + 1 : reference.CatalogRevision;
                char digest = reference == plan.A1 ? 'A' : 'B';
                return Value(new
                {
                    id = Guid.NewGuid(), providerId = reference.ProviderId, resourceId = reference.ResourceId, version = reference.Version,
                    revision, publicMetadataRevision = reference.PublicMetadataRevision, environmentId = plan.EnvironmentId,
                    resourceType = "ClientCertificate", status = "Active", connectorScope = Fse2OfficialTestCanonicalDefinition.ConnectorId,
                    operationScope = Fse2OfficialTestCanonicalDefinition.OperationId, checksumSha256 = new string(digest, 64),
                    certificateMetadata = new { subjectPublicKeyInfoSha256 = new string(digest, 64), subjectCommonName = "Synthetic certificate" }
                });
            }
            if (relative.StartsWith("admin/api/v1/connectors?", StringComparison.Ordinal))
            {
                object[] items = State == SimulatedProvisioningState.Missing ? [] : [new
                {
                    connectorId = Fse2OfficialTestCanonicalDefinition.ConnectorId,
                    displayName = "Synthetic FSE2",
                    versions = 1,
                    publishedVersion = State == SimulatedProvisioningState.Published ? Fse2OfficialTestCanonicalDefinition.ConnectorVersion : null,
                    publicationRevision = State == SimulatedProvisioningState.Published ? 1 : 0
                }];
                return Value(new { items, total = items.Length, offset = 0, limit = 100 });
            }
            if (relative.StartsWith(VersionPath() + "s?", StringComparison.Ordinal))
                throw new InvalidOperationException("Synthetic version route mismatch.");
            if (relative.StartsWith($"admin/api/v1/connectors/{Fse2OfficialTestCanonicalDefinition.ConnectorId}/versions?", StringComparison.Ordinal))
            {
                object[] items = State == SimulatedProvisioningState.Missing ? [] : [VersionResource()];
                return Value(new { items, total = items.Length, offset = 0, limit = 100 });
            }
            if (relative == VersionPath()) return Value(VersionResource());
            if (relative.StartsWith(VersionPath() + "/bindings?", StringComparison.Ordinal))
            {
                object[] items = State < SimulatedProvisioningState.Bound ? [] : [BindingResource()];
                return Value(new { items, total = items.Length, offset = 0, limit = 10 });
            }
            if (relative.StartsWith("admin/api/v1/grants?", StringComparison.Ordinal))
            {
                object[] items = State < SimulatedProvisioningState.Granted ? [] : [new
                {
                    id = Guid.Parse("BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB"), installationId = plan.InstallationId, tenantId = plan.TenantId,
                    connectorId = Fse2OfficialTestCanonicalDefinition.ConnectorId, operationId = Fse2OfficialTestCanonicalDefinition.OperationId,
                    enabled = true, validFrom = new DateTimeOffset(2026, 8, 30, 0, 0, 0, TimeSpan.Zero), validUntil = (DateTimeOffset?)null
                }];
                return Value(new { items, total = items.Length, offset = 0, limit = 100 });
            }
            if (relative == VersionPath() + "/approval-review")
                return Value(new { digestSha256 = ApprovalDigest, artifact = new { operations = new[] { new { operationId = Fse2OfficialTestCanonicalDefinition.OperationId } } } });
            if (relative == VersionPath() + "/approvals?offset=0&limit=100")
            {
                object[] items = State < SimulatedProvisioningState.Requested ? [] : [new
                {
                    id = ApprovalRequestId, connectorVersionId = Guid.Parse("CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC"),
                    checksumSha256 = Compiled.CanonicalDefinitionSha256, bindingDigestSha256 = ApprovalDigest, requestedBy = EditorId,
                    approvedBy = State >= SimulatedProvisioningState.Approved ? ApproverId : (Guid?)null, rejectedBy = (Guid?)null,
                    status = State >= SimulatedProvisioningState.Approved ? "Approved" : "Requested", requestedAt = new DateTimeOffset(2026, 8, 30, 0, 0, 0, TimeSpan.Zero)
                }];
                return Value(new { items, total = items.Length, offset = 0, limit = 100 });
            }
            throw new InvalidOperationException("Unexpected synthetic GET: " + relative);
        }

        internal Task<byte[]> GetBytesAsync(string relative)
        {
            if (relative != VersionPath() + "/definition" || State == SimulatedProvisioningState.Missing)
                throw new InvalidOperationException("Unexpected synthetic definition read.");
            return Task.FromResult(Encoding.UTF8.GetBytes(Compiled.CanonicalDefinition));
        }

        internal Task<JsonElement> MutateAsync(string role, Guid principalId, string relative, object? body)
        {
            if (relative == "admin/api/v1/connectors:validate")
            {
                RequireRole(role, "security");
                return Value(new { valid = true, checksumSha256 = Compiled.CanonicalDefinitionSha256 });
            }
            if (relative == "admin/api/v1/connectors:import")
            {
                RequireRole(role, "security");
                RequireState(SimulatedProvisioningState.Missing);
                State = SimulatedProvisioningState.Draft;
                ImportCount++;
                SuccessfulMutationCount++;
                return Value(VersionResource());
            }
            if (relative == VersionPath() + ":validate")
            {
                RequireRole(role, "security");
                RequireState(SimulatedProvisioningState.Draft);
                State = SimulatedProvisioningState.Validated;
                StoredValidationCount++;
                SuccessfulMutationCount++;
                return Value(VersionResource());
            }
            if (relative.EndsWith("/bindings", StringComparison.Ordinal))
            {
                RequireRole(role, "security");
                RequireState(SimulatedProvisioningState.Validated);
                BindingAttemptCount++;
                if (RateLimitBindingOnce && !rateLimitConsumed)
                {
                    rateLimitConsumed = true;
                    throw new ConnectorProvisioningRateLimitException(TimeSpan.FromSeconds(37));
                }
                State = SimulatedProvisioningState.Bound;
                SuccessfulMutationCount++;
                return Value(new { revision = 1 });
            }
            if (relative == "admin/api/v1/grants")
            {
                RequireRole(role, "security");
                RequireState(SimulatedProvisioningState.Bound);
                State = SimulatedProvisioningState.Granted;
                SuccessfulMutationCount++;
                return Value(new
                {
                    id = Guid.Parse("BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB"), installationId = plan.InstallationId, tenantId = plan.TenantId,
                    connectorId = Fse2OfficialTestCanonicalDefinition.ConnectorId, operationId = Fse2OfficialTestCanonicalDefinition.OperationId,
                    enabled = true, validFrom = new DateTimeOffset(2026, 8, 30, 0, 0, 0, TimeSpan.Zero), validUntil = (DateTimeOffset?)null
                });
            }
            if (relative == VersionPath() + "/approval-requests")
            {
                RequireRole(role, "editor");
                RequireState(SimulatedProvisioningState.Granted);
                State = SimulatedProvisioningState.Requested;
                SuccessfulMutationCount++;
                return Value(new { id = ApprovalRequestId, status = "Requested" });
            }
            if (relative == VersionPath() + "/approvals")
            {
                RequireRole(role, "approver");
                if (principalId == EditorId) throw Denied();
                RequireState(SimulatedProvisioningState.Requested);
                State = SimulatedProvisioningState.Approved;
                SuccessfulMutationCount++;
                return Value(new { id = ApprovalRequestId, status = "Approved" });
            }
            if (relative == VersionPath() + ":publish")
            {
                RequireRole(role, "approver");
                RequireState(SimulatedProvisioningState.Approved);
                State = SimulatedProvisioningState.Published;
                PublishCount++;
                SuccessfulMutationCount++;
                return Value(VersionResource());
            }
            throw new InvalidOperationException("Unexpected synthetic mutation: " + relative);
        }

        private object VersionResource() => new
        {
            connectorId = Fse2OfficialTestCanonicalDefinition.ConnectorId,
            version = Fse2OfficialTestCanonicalDefinition.ConnectorVersion,
            schemaVersion = "1.0",
            state = State == SimulatedProvisioningState.Draft ? "Draft" : State == SimulatedProvisioningState.Published ? "Published" : "Validated",
            checksumSha256 = DefinitionChecksumDrift ? new string('F', 64) : Compiled.CanonicalDefinitionSha256,
            rowVersion = Math.Max(1, (int)State + 1),
            createdAt = new DateTimeOffset(2026, 8, 30, 0, 0, 0, TimeSpan.Zero),
            publishedAt = State == SimulatedProvisioningState.Published ? new DateTimeOffset(2026, 8, 30, 0, 1, 0, TimeSpan.Zero) : (DateTimeOffset?)null
        };

        private object BindingResource()
        {
            object Reference(Fse2OfficialTestProviderReference reference) => new
            {
                providerId = reference.ProviderId, resourceId = reference.ResourceId, version = reference.Version,
                catalogRevision = BindingProviderRevisionDrift ? reference.CatalogRevision + 1 : reference.CatalogRevision,
                publicMetadataRevision = reference.PublicMetadataRevision
            };
            string endpointChecksum = ConnectorBindingDigests.Component(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [Fse2OfficialTestCanonicalDefinition.EndpointBinding] = plan.Endpoint.AbsoluteUri
            });
            return new
            {
                state = State == SimulatedProvisioningState.Published ? "Active" : "Draft", environmentId = plan.EnvironmentId,
                endpointChecksumSha256 = endpointChecksum, checksumSha256 = new string('C', 64),
                certificateResources = new Dictionary<string, object>
                {
                    [Fse2OfficialTestCanonicalDefinition.MutualTlsBinding] = Reference(plan.A1),
                    [Fse2OfficialTestCanonicalDefinition.SigningBinding] = Reference(plan.S1)
                },
                secretResources = new Dictionary<string, object>()
            };
        }

        private static void RequireRole(string actual, string expected)
        {
            if (!string.Equals(actual, expected, StringComparison.Ordinal)) throw Denied();
        }

        private void RequireState(SimulatedProvisioningState expected)
        {
            if (State != expected) throw new ProvisionerProgram.ProvisioningException("FSE2_OFFICIALTEST_ADMIN_REJECTED_409", inputFailure: false);
        }

        private static ProvisionerProgram.ProvisioningException Denied() =>
            new("FSE2_OFFICIALTEST_ADMIN_REJECTED_403", inputFailure: false);
    }

    private sealed class SimulatedApi(SimulatedBackend backend, string role, Guid principalId) : IOfficialTestAdminApi
    {
        public Guid PrincipalId { get; } = principalId;
        public Task<JsonElement> GetAsync(string relative) => backend.GetAsync(relative);
        public Task<byte[]> GetBytesAsync(string relative) => backend.GetBytesAsync(relative);
        public Task<JsonElement> MutateAsync(HttpMethod method, string relative, object? body, long? ifMatch = null) =>
            backend.MutateAsync(role, PrincipalId, relative, body);
        public void Dispose() { }
    }

    private static Fse2OfficialTestOperationalPlan PlanFactory()
    {
        Guid tenant = Guid.Parse("22222222-2222-2222-2222-222222222222");
        Guid installation = Guid.Parse("33333333-3333-3333-3333-333333333333");
        Guid environment = Guid.Parse("11111111-1111-1111-1111-111111111111");
        string json = $$"""
            {
              "schemaVersion":"1.0",
              "tenantId":"{{tenant:D}}",
              "installationId":"{{installation:D}}",
              "environmentId":"{{environment:D}}",
              "officialTestEndpoint":"{{Fse2OfficialTestCanonicalDefinition.OfficialTestEndpoint}}",
              "organization":{"identifier":"12345678903","assigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2","description":"Synthetic Organization","domainId":"synthetic-organization"},
              "locality":{"name":"Synthetic Locality","assigningAuthorityOid":"2.16.840.1.113883.2.9.4.1.2","code":"SYNTHETIC"},
              "a1":{"providerId":"synthetic-provider","resourceId":"officialtest-a1","version":"1","catalogRevision":1,"publicMetadataRevision":1},
              "s1":{"providerId":"synthetic-provider","resourceId":"officialtest-s1","version":"1","catalogRevision":1,"publicMetadataRevision":1},
              "expectedBindingRevision":null
            }
            """;
        return Fse2OfficialTestOperationalization.ParsePlan(Encoding.UTF8.GetBytes(json));
    }

    private static Task<JsonElement> Value<T>(T value) => Task.FromResult(JsonSerializer.SerializeToElement(value, WireJson));
    private static string VersionPath() =>
        $"admin/api/v1/connectors/{Fse2OfficialTestCanonicalDefinition.ConnectorId}/versions/{Fse2OfficialTestCanonicalDefinition.ConnectorVersion}";

    private static JsonSerializerOptions CreateJson()
    {
        JsonSerializerOptions options = new(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}

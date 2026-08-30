using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecureIntegration.ConnectorPacks.Healthcare.FSE2;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Tools.ConnectorProvisioning;

namespace SecureIntegration.Tools.Fse2.OfficialTestProvisioner;

internal interface IOfficialTestAdminApi : IDisposable
{
    Guid PrincipalId { get; }
    Task<JsonElement> GetAsync(string relative);
    Task<byte[]> GetBytesAsync(string relative);
    Task<JsonElement> MutateAsync(HttpMethod method, string relative, object? body, long? ifMatch = null);
}

internal static class Program
{
    private static readonly JsonSerializerOptions Json = CreateJson();

    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
        {
            Usage();
            return args.Length == 0 ? 2 : 0;
        }

        string? supportedCommand = null;
        try
        {
            if (args[0] == "plan" && args.Length == 2)
            {
                Fse2OfficialTestOperationalPlan plan = ReadPlan(args[1]);
                Print(Fse2OfficialTestOperationalization.Plan(plan));
                return 0;
            }

            if (args[0] == "reduce-failure-evidence" && args.Length == 3)
            {
                if (!Guid.TryParseExact(args[2], "D", out Guid correlationId) || correlationId == Guid.Empty)
                    throw Failure("FSE2_EVIDENCE_CORRELATION_INVALID", inputFailure: true);
                using JsonDocument audit = JsonDocument.Parse(ReadBounded(args[1], 1024 * 1024, "FSE2_EVIDENCE_AUDIT_INPUT_INVALID"));
                Print(Fse2FailureEvidenceReducer.Reduce(audit.RootElement, correlationId));
                return 0;
            }

            Command command = ParseCommand(args);
            supportedCommand = SupportedCommand(command.Name);
            Fse2OfficialTestOperationalPlan operationalPlan = ReadPlan(command.PlanPath);
            using AdminApi api = await AdminApi.CreateAsync().ConfigureAwait(false);
            ProvisioningContext context = await PreflightAsync(api, operationalPlan).ConfigureAwait(false);

            switch (command.Name)
            {
                case "configure":
                    await ConfigureAsync(api, context).ConfigureAwait(false);
                    break;
                case "grant":
                    await GrantAsync(api, context).ConfigureAwait(false);
                    break;
                case "propose":
                    await ProposeAsync(api, context).ConfigureAwait(false);
                    break;
                case "approve":
                    await ApproveAsync(api, context, command.ApprovalRequestId!.Value, command.ExpectedApprovalDigest!).ConfigureAwait(false);
                    break;
                case "publish":
                    await PublishAsync(api, context, command.ExpectedPublicationRevision!.Value).ConfigureAwait(false);
                    break;
                case "verify":
                    await VerifyAndPrintAsync(api, context, "Published", "Active").ConfigureAwait(false);
                    break;
                default:
                    throw Failure("FSE2_OFFICIALTEST_COMMAND_INVALID");
            }
            return 0;
        }
        catch (Fse2OfficialTestOperationalizationException exception)
        {
            Console.Error.WriteLine(exception.SafeCode);
            return 2;
        }
        catch (ConnectorProvisioningRateLimitException exception)
        {
            ConnectorProvisioningSnapshot unknown = new(
                ConnectorProvisioningCurrentState.Unknown,
                Array.Empty<ConnectorProvisioningPhase>(),
                null,
                RetrySafe: false);
            Console.Error.WriteLine(JsonSerializer.Serialize(
                ConnectorProvisioningStateMachine.RateLimited(
                    unknown,
                    exception.RetryAfter,
                    supportedCommand ?? "fse2-officialtest <command> <operational-plan.json>"),
                Json));
            return 1;
        }
        catch (ProvisioningException exception)
        {
            Console.Error.WriteLine(exception.RateLimitResult is null
                ? exception.Code
                : JsonSerializer.Serialize(exception.RateLimitResult, Json));
            return exception.InputFailure ? 2 : 1;
        }
        catch (Exception exception) when (exception is IOException or JsonException or HttpRequestException or TaskCanceledException or FormatException or OverflowException)
        {
            Console.Error.WriteLine("FSE2_OFFICIALTEST_PROVISIONING_FAILED");
            return 1;
        }
    }

    internal static async Task ConfigureAsync(IOfficialTestAdminApi api, ProvisioningContext context)
    {
        Fse2OfficialTestCompiledConfiguration compiled = context.Compiled;
        DiscoveredProvisioningState? discovered = null;
        try
        {
            while (true)
            {
                discovered = await DiscoverProvisioningStateAsync(api, context).ConfigureAwait(false);
                if (HasCompleted(discovered.Snapshot, ConnectorProvisioningPhase.BindingConfiguration))
                {
                    Print(Result("configured", compiled, RequireVerification(discovered)));
                    return;
                }

                switch (discovered.Snapshot.NextRequiredPhase)
                {
                    case ConnectorProvisioningPhase.DefinitionImported:
                        using (JsonDocument definition = JsonDocument.Parse(compiled.CanonicalDefinition))
                        {
                            JsonElement validated = await api.MutateAsync(HttpMethod.Post, "admin/api/v1/connectors:validate",
                                new ConnectorImportRequest(definition.RootElement.Clone())).ConfigureAwait(false);
                            if (!validated.GetProperty("valid").GetBoolean() ||
                                !string.Equals(validated.GetProperty("checksumSha256").GetString(), compiled.CanonicalDefinitionSha256, StringComparison.Ordinal))
                                throw Failure("FSE2_OFFICIALTEST_SERVER_VALIDATION_DRIFT");
                            discovered = await DiscoverProvisioningStateAsync(api, context).ConfigureAwait(false);
                            if (discovered.Snapshot.NextRequiredPhase != ConnectorProvisioningPhase.DefinitionImported)
                                break;
                            _ = await api.MutateAsync(HttpMethod.Post, "admin/api/v1/connectors:import",
                                new ConnectorImportRequest(definition.RootElement.Clone(), compiled.CanonicalDefinitionSha256)).ConfigureAwait(false);
                        }
                        break;
                    case ConnectorProvisioningPhase.StoredValidation:
                        JsonElement stored = await api.MutateAsync(HttpMethod.Post, VersionPath() + ":validate",
                            body: null, ifMatch: discovered.VersionRowVersion).ConfigureAwait(false);
                        if (!string.Equals(stored.GetProperty("state").GetString(), "Validated", StringComparison.Ordinal))
                            throw Failure("FSE2_OFFICIALTEST_VALIDATE_STORED_FAILED");
                        break;
                    case ConnectorProvisioningPhase.BindingConfiguration:
                        _ = await api.MutateAsync(HttpMethod.Put,
                            $"admin/api/v1/connectors/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorId)}/bindings",
                            compiled.BindingRequest,
                            context.EffectivePlan.ExpectedBindingRevision).ConfigureAwait(false);
                        break;
                    default:
                        throw Failure("BGW-PROVISIONING-SERVER-STATE-INVALID");
                }
            }
        }
        catch (ConnectorProvisioningRateLimitException exception)
        {
            throw RateLimitedFailure(exception, discovered, SupportedCommand("configure"));
        }
        catch (ConnectorProvisioningIdentityDriftException)
        {
            throw Failure("BGW-PROVISIONING-IDENTITY-DRIFT");
        }
    }

    internal static async Task GrantAsync(IOfficialTestAdminApi api, ProvisioningContext context)
    {
        DiscoveredProvisioningState? discovered = null;
        try
        {
            discovered = await DiscoverProvisioningStateAsync(api, context).ConfigureAwait(false);
            RequireCompleted(discovered.Snapshot, ConnectorProvisioningPhase.BindingConfiguration);
            if (HasCompleted(discovered.Snapshot, ConnectorProvisioningPhase.Grant))
            {
                Print(new { status = "grant-verified", installationId = context.Installation.Id, environmentId = context.Installation.EnvironmentId });
                return;
            }

            JsonElement created = await api.MutateAsync(HttpMethod.Post, "admin/api/v1/grants", new
            {
                tenantId = context.Installation.TenantId,
                installationId = context.Installation.Id,
                connectorId = Fse2OfficialTestCanonicalDefinition.ConnectorId,
                operationId = Fse2OfficialTestCanonicalDefinition.OperationId,
                validUntil = (DateTimeOffset?)null
            }).ConfigureAwait(false);
            InstallationGrantAuthority grant = GrantAuthority(created);
            RequireGrantCurrent(grant, context.Installation);
            discovered = await DiscoverProvisioningStateAsync(api, context).ConfigureAwait(false);
            RequireCompleted(discovered.Snapshot, ConnectorProvisioningPhase.Grant);
            Print(new { status = "granted", installationId = context.Installation.Id, environmentId = context.Installation.EnvironmentId });
        }
        catch (ConnectorProvisioningRateLimitException exception)
        {
            throw RateLimitedFailure(exception, discovered, SupportedCommand("grant"));
        }
        catch (ConnectorProvisioningIdentityDriftException) { throw Failure("BGW-PROVISIONING-IDENTITY-DRIFT"); }
    }

    internal static async Task ProposeAsync(IOfficialTestAdminApi api, ProvisioningContext context)
    {
        Fse2OfficialTestCompiledConfiguration compiled = context.Compiled;
        DiscoveredProvisioningState? discovered = null;
        try
        {
            discovered = await DiscoverProvisioningStateAsync(api, context).ConfigureAwait(false);
            RequireCompleted(discovered.Snapshot, ConnectorProvisioningPhase.Grant);
            if (!HasCompleted(discovered.Snapshot, ConnectorProvisioningPhase.Proposal))
            {
                _ = await api.MutateAsync(HttpMethod.Post, VersionPath() + "/approval-requests", body: null).ConfigureAwait(false);
                discovered = await DiscoverProvisioningStateAsync(api, context).ConfigureAwait(false);
            }
            RequireCompleted(discovered.Snapshot, ConnectorProvisioningPhase.Proposal);
            Print(new
            {
                status = "proposed",
                connectorId = Fse2OfficialTestCanonicalDefinition.ConnectorId,
                connectorVersion = Fse2OfficialTestCanonicalDefinition.ConnectorVersion,
                approvalRequestId = discovered.ApprovalRequestId,
                approvalDigestSha256 = discovered.ApprovalDigestSha256,
                canonicalDefinitionSha256 = compiled.CanonicalDefinitionSha256,
                operationProfileChecksumSha256 = compiled.OperationProfileChecksumSha256,
                bindingConfigurationDigestSha256 = compiled.BindingConfigurationDigestSha256,
                serverBindingChecksumSha256 = discovered.BindingChecksumSha256
            });
        }
        catch (ConnectorProvisioningRateLimitException exception)
        {
            throw RateLimitedFailure(exception, discovered, SupportedCommand("propose"));
        }
        catch (ConnectorProvisioningIdentityDriftException) { throw Failure("BGW-PROVISIONING-IDENTITY-DRIFT"); }
    }

    internal static async Task ApproveAsync(
        IOfficialTestAdminApi api,
        ProvisioningContext context,
        Guid approvalRequestId,
        string expectedApprovalDigest)
    {
        Fse2OfficialTestCompiledConfiguration compiled = context.Compiled;
        DiscoveredProvisioningState? discovered = null;
        try
        {
            discovered = await DiscoverProvisioningStateAsync(api, context).ConfigureAwait(false);
            RequireCompleted(discovered.Snapshot, ConnectorProvisioningPhase.Proposal);
            if (discovered.ApprovalRequestId != approvalRequestId ||
                !IsSha256(expectedApprovalDigest) ||
                !string.Equals(discovered.ApprovalDigestSha256, expectedApprovalDigest, StringComparison.Ordinal))
                throw Failure("FSE2_OFFICIALTEST_APPROVAL_DIGEST_STALE", inputFailure: true);
            if (!HasCompleted(discovered.Snapshot, ConnectorProvisioningPhase.Approval))
            {
                JsonElement approved = await api.MutateAsync(HttpMethod.Post, VersionPath() + "/approvals",
                    new ConnectorApprovalAcceptanceRequest(approvalRequestId, expectedApprovalDigest)).ConfigureAwait(false);
                if (!string.Equals(approved.GetProperty("status").GetString(), "Approved", StringComparison.Ordinal))
                    throw Failure("FSE2_OFFICIALTEST_APPROVAL_FAILED");
                discovered = await DiscoverProvisioningStateAsync(api, context).ConfigureAwait(false);
            }
            RequireCompleted(discovered.Snapshot, ConnectorProvisioningPhase.Approval);
            Print(new
            {
                status = "approved",
                approvalRequestId,
                approvalDigestSha256 = expectedApprovalDigest,
                canonicalDefinitionSha256 = compiled.CanonicalDefinitionSha256,
                operationProfileChecksumSha256 = compiled.OperationProfileChecksumSha256,
                bindingConfigurationDigestSha256 = compiled.BindingConfigurationDigestSha256
            });
        }
        catch (ConnectorProvisioningRateLimitException exception)
        {
            throw RateLimitedFailure(exception, discovered, SupportedCommand("approve"));
        }
        catch (ConnectorProvisioningIdentityDriftException) { throw Failure("BGW-PROVISIONING-IDENTITY-DRIFT"); }
    }

    internal static async Task PublishAsync(
        IOfficialTestAdminApi api,
        ProvisioningContext context,
        long expectedPublicationRevision)
    {
        Fse2OfficialTestCompiledConfiguration compiled = context.Compiled;
        if (expectedPublicationRevision < 0) throw Failure("FSE2_OFFICIALTEST_PUBLICATION_REVISION_INVALID", inputFailure: true);
        DiscoveredProvisioningState? discovered = null;
        try
        {
            discovered = await DiscoverProvisioningStateAsync(api, context).ConfigureAwait(false);
            RequireCompleted(discovered.Snapshot, ConnectorProvisioningPhase.Approval);
            if (!HasCompleted(discovered.Snapshot, ConnectorProvisioningPhase.Publication))
            {
                await RequireCurrentApproverAsync(api, compiled).ConfigureAwait(false);
                JsonElement published = await api.MutateAsync(HttpMethod.Post, VersionPath() + ":publish",
                    new ConnectorVersionActionRequest(discovered.VersionRowVersion, expectedPublicationRevision), discovered.VersionRowVersion).ConfigureAwait(false);
                if (!string.Equals(published.GetProperty("state").GetString(), "Published", StringComparison.Ordinal))
                    throw Failure("FSE2_OFFICIALTEST_PUBLICATION_FAILED");
                discovered = await DiscoverProvisioningStateAsync(api, context).ConfigureAwait(false);
            }
            RequireCompleted(discovered.Snapshot, ConnectorProvisioningPhase.Verification);
            Print(Result("published", compiled, RequireVerification(discovered)));
        }
        catch (ConnectorProvisioningRateLimitException exception)
        {
            throw RateLimitedFailure(exception, discovered, SupportedCommand("publish"));
        }
        catch (ConnectorProvisioningIdentityDriftException) { throw Failure("BGW-PROVISIONING-IDENTITY-DRIFT"); }
    }

    internal static async Task VerifyAndPrintAsync(
        IOfficialTestAdminApi api,
        ProvisioningContext context,
        string expectedVersionState,
        string expectedBindingState)
    {
        ServerVerification verified = await VerifyServerAsync(api, context, expectedVersionState, expectedBindingState).ConfigureAwait(false);
        Print(Result("verified", context.Compiled, verified));
    }

    private static object Result(string status, Fse2OfficialTestCompiledConfiguration compiled, ServerVerification verified) => new
    {
        status,
        connectorId = Fse2OfficialTestCanonicalDefinition.ConnectorId,
        connectorVersion = Fse2OfficialTestCanonicalDefinition.ConnectorVersion,
        operationId = Fse2OfficialTestCanonicalDefinition.OperationId,
        canonicalDefinitionSha256 = compiled.CanonicalDefinitionSha256,
        operationProfileChecksumSha256 = compiled.OperationProfileChecksumSha256,
        bindingConfigurationDigestSha256 = compiled.BindingConfigurationDigestSha256,
        serverBindingChecksumSha256 = verified.BindingChecksumSha256,
        versionState = verified.VersionState,
        bindingState = verified.BindingState
    };

    internal static async Task<DiscoveredProvisioningState> DiscoverProvisioningStateAsync(
        IOfficialTestAdminApi api,
        ProvisioningContext context)
    {
        await RequireInstallationCurrentAsync(api, context.Installation).ConfigureAwait(false);
        await RequireEnvironmentCurrentAsync(api, context.Installation.EnvironmentId).ConfigureAwait(false);
        await RequirePublicAuthorityCurrentAsync(api, context.EffectivePlan, context.PublicAuthority).ConfigureAwait(false);

        ConnectorProvisioningIdentity expected = ProvisioningIdentity(context);
        JsonElement[] connectors = (await ReadPagedItemsAsync(
            api,
            offset => $"admin/api/v1/connectors?offset={offset}&limit=100",
            "FSE2_OFFICIALTEST_CONNECTOR_CATALOG_TOO_LARGE").ConfigureAwait(false))
            .Where(value => string.Equals(value.GetProperty("connectorId").GetString(), Fse2OfficialTestCanonicalDefinition.ConnectorId, StringComparison.Ordinal))
            .ToArray();
        if (connectors.Length > 1) throw Failure("BGW-PROVISIONING-SERVER-STATE-INVALID");

        JsonElement[] versions = (await ReadPagedItemsAsync(
            api,
            offset => $"admin/api/v1/connectors/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorId)}/versions?offset={offset}&limit=100",
            "FSE2_OFFICIALTEST_VERSION_CATALOG_TOO_LARGE").ConfigureAwait(false))
            .Where(value =>
                string.Equals(value.GetProperty("connectorId").GetString(), Fse2OfficialTestCanonicalDefinition.ConnectorId, StringComparison.Ordinal) &&
                string.Equals(value.GetProperty("version").GetString(), Fse2OfficialTestCanonicalDefinition.ConnectorVersion, StringComparison.Ordinal))
            .ToArray();
        if (versions.Length > 1) throw Failure("BGW-PROVISIONING-SERVER-STATE-INVALID");

        InstallationGrantAuthority[] grants = await ReadExactGrantsAsync(api, context.Installation).ConfigureAwait(false);
        if (grants.Length > 1) throw Failure("FSE2_OFFICIALTEST_GRANT_AUTHORITY_AMBIGUOUS");
        if (grants.Length == 1) RequireGrantCurrent(grants[0], context.Installation);

        if (versions.Length == 0)
        {
            if (grants.Length != 0) throw Failure("BGW-PROVISIONING-SERVER-STATE-INVALID");
            ConnectorProvisioningSnapshot missing = ConnectorProvisioningStateMachine.Evaluate(expected, null, []);
            return new(missing, 0, null, null, null, null, null);
        }

        JsonElement version = versions[0];
        string versionState = version.GetProperty("state").GetString() ?? string.Empty;
        if (versionState is not ("Draft" or "Validated" or "Published") ||
            !string.Equals(version.GetProperty("checksumSha256").GetString(), context.Compiled.CanonicalDefinitionSha256, StringComparison.Ordinal))
            throw new ConnectorProvisioningIdentityDriftException();
        long rowVersion = PositiveLong(version, "rowVersion");
        byte[] storedDefinition = await api.GetBytesAsync(VersionPath() + "/definition").ConfigureAwait(false);
        try { Fse2OfficialTestOperationalization.VerifyDefinitionReadback(storedDefinition, context.Compiled); }
        catch (Fse2OfficialTestOperationalizationException) { throw new ConnectorProvisioningIdentityDriftException(); }

        List<ConnectorProvisioningPhase> completed = [ConnectorProvisioningPhase.DefinitionImported];
        if (versionState is "Validated" or "Published") completed.Add(ConnectorProvisioningPhase.StoredValidation);

        string bindingPath = $"admin/api/v1/connectors/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorId)}/versions/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorVersion)}/bindings?environmentId={context.EffectivePlan.EnvironmentId:D}&offset=0&limit=10";
        JsonElement bindingPage = await api.GetAsync(bindingPath).ConfigureAwait(false);
        JsonElement[] bindings = bindingPage.GetProperty("items").EnumerateArray().Select(value => value.Clone()).ToArray();
        if (bindings.Length > 1) throw Failure("FSE2_OFFICIALTEST_BINDING_READBACK_DRIFT");
        string? bindingChecksum = null;
        string? bindingState = null;
        ApprovalReviewResult? review = null;
        Guid? approvalRequestId = null;
        string? approvalStatus = null;

        if (bindings.Length == 1)
        {
            if (versionState == "Draft") throw Failure("BGW-PROVISIONING-SERVER-STATE-INVALID");
            JsonElement binding = bindings[0];
            bindingState = binding.GetProperty("state").GetString();
            string expectedBindingState = versionState == "Published" ? "Active" : "Draft";
            if (!string.Equals(bindingState, expectedBindingState, StringComparison.Ordinal) ||
                binding.GetProperty("environmentId").GetGuid() != context.EffectivePlan.EnvironmentId)
                throw new ConnectorProvisioningIdentityDriftException();
            string expectedEndpointDigest = ConnectorBindingDigests.Component(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [Fse2OfficialTestCanonicalDefinition.EndpointBinding] = context.EffectivePlan.Endpoint.AbsoluteUri
            });
            if (!string.Equals(binding.GetProperty("endpointChecksumSha256").GetString(), expectedEndpointDigest, StringComparison.Ordinal))
                throw new ConnectorProvisioningIdentityDriftException();
            JsonElement certificates = binding.GetProperty("certificateResources");
            try
            {
                VerifyReference(certificates.GetProperty(Fse2OfficialTestCanonicalDefinition.MutualTlsBinding), context.EffectivePlan.A1, "A1");
                VerifyReference(certificates.GetProperty(Fse2OfficialTestCanonicalDefinition.SigningBinding), context.EffectivePlan.S1, "S1");
            }
            catch (ProvisioningException) { throw new ConnectorProvisioningIdentityDriftException(); }
            if (binding.GetProperty("secretResources").EnumerateObject().Any())
                throw new ConnectorProvisioningIdentityDriftException();
            bindingChecksum = binding.GetProperty("checksumSha256").GetString();
            if (!IsSha256(bindingChecksum ?? string.Empty)) throw Failure("FSE2_OFFICIALTEST_SERVER_RESPONSE_INVALID");
            completed.Add(ConnectorProvisioningPhase.BindingConfiguration);

            if (grants.Length == 1) completed.Add(ConnectorProvisioningPhase.Grant);
            JsonElement approvalsPage = await api.GetAsync(VersionPath() + "/approvals?offset=0&limit=100").ConfigureAwait(false);
            JsonElement[] activeApprovals = approvalsPage.GetProperty("items").EnumerateArray()
                .Where(value => value.GetProperty("status").GetString() is "Requested" or "Approved")
                .ToArray();
            if (activeApprovals.Length > 1) throw Failure("BGW-PROVISIONING-SERVER-STATE-INVALID");
            if (activeApprovals.Length == 1)
            {
                if (grants.Length != 1) throw Failure("BGW-PROVISIONING-SERVER-STATE-INVALID");
                JsonElement approval = activeApprovals[0];
                if (!string.Equals(approval.GetProperty("checksumSha256").GetString(), context.Compiled.CanonicalDefinitionSha256, StringComparison.Ordinal))
                    throw new ConnectorProvisioningIdentityDriftException();
                approvalRequestId = RequiredGuid(approval, "id");
                approvalStatus = approval.GetProperty("status").GetString();
                review = await ReadReviewAsync(api).ConfigureAwait(false);
                if (!string.Equals(approval.GetProperty("bindingDigestSha256").GetString(), review.DigestSha256, StringComparison.Ordinal))
                    throw new ConnectorProvisioningIdentityDriftException();
                completed.Add(ConnectorProvisioningPhase.Proposal);
                if (approvalStatus == "Approved") completed.Add(ConnectorProvisioningPhase.Approval);
            }
        }
        else if (grants.Length != 0)
        {
            throw Failure("BGW-PROVISIONING-SERVER-STATE-INVALID");
        }

        if (versionState == "Published")
        {
            if (bindingState != "Active" || approvalStatus != "Approved" || connectors.Length != 1 ||
                !string.Equals(connectors[0].GetProperty("publishedVersion").GetString(), Fse2OfficialTestCanonicalDefinition.ConnectorVersion, StringComparison.Ordinal))
                throw Failure("BGW-PROVISIONING-SERVER-STATE-INVALID");
            completed.Add(ConnectorProvisioningPhase.Publication);
            completed.Add(ConnectorProvisioningPhase.Verification);
        }
        else if (connectors.Length == 1 && connectors[0].GetProperty("publishedVersion").ValueKind == JsonValueKind.String &&
            string.Equals(connectors[0].GetProperty("publishedVersion").GetString(), Fse2OfficialTestCanonicalDefinition.ConnectorVersion, StringComparison.Ordinal))
        {
            throw Failure("BGW-PROVISIONING-SERVER-STATE-INVALID");
        }

        ConnectorProvisioningSnapshot snapshot = ConnectorProvisioningStateMachine.Evaluate(expected, ProvisioningIdentity(context), completed);
        return new(snapshot, rowVersion, versionState, bindingState, bindingChecksum, approvalRequestId, review?.DigestSha256);
    }

    private static ConnectorProvisioningIdentity ProvisioningIdentity(ProvisioningContext context) => new(
        Fse2OfficialTestCanonicalDefinition.ConnectorId,
        Fse2OfficialTestCanonicalDefinition.ConnectorVersion,
        context.Compiled.CanonicalDefinitionSha256,
        context.Installation.EnvironmentId,
        context.Compiled.BindingConfigurationDigestSha256,
        context.Compiled.OperationProfileChecksumSha256,
        context.Installation.ApplicationId,
        [ProviderRevision(Fse2OfficialTestCanonicalDefinition.MutualTlsBinding, context.PublicAuthority.A1.Reference),
         ProviderRevision(Fse2OfficialTestCanonicalDefinition.SigningBinding, context.PublicAuthority.S1.Reference)]);

    private static ConnectorProvisioningProviderRevision ProviderRevision(string binding, Fse2OfficialTestProviderReference reference) =>
        new(binding, reference.ProviderId, reference.ResourceId, reference.Version, reference.CatalogRevision, reference.PublicMetadataRevision);

    private static bool HasCompleted(ConnectorProvisioningSnapshot snapshot, ConnectorProvisioningPhase phase) =>
        snapshot.CompletedPhases.Contains(phase);

    private static void RequireCompleted(ConnectorProvisioningSnapshot snapshot, ConnectorProvisioningPhase phase)
    {
        if (!HasCompleted(snapshot, phase)) throw Failure("BGW-PROVISIONING-PHASE-REQUIRED");
    }

    private static ServerVerification RequireVerification(DiscoveredProvisioningState discovered)
    {
        if (discovered.VersionState is null || discovered.BindingState is null || discovered.BindingChecksumSha256 is null)
            throw Failure("BGW-PROVISIONING-SERVER-STATE-INVALID");
        return new(discovered.VersionState, discovered.BindingState, discovered.BindingChecksumSha256);
    }

    private static ProvisioningException RateLimitedFailure(
        ConnectorProvisioningRateLimitException exception,
        DiscoveredProvisioningState? discovered,
        string command)
    {
        ConnectorProvisioningSnapshot snapshot = discovered?.Snapshot ?? new(
            ConnectorProvisioningCurrentState.Unknown,
            Array.Empty<ConnectorProvisioningPhase>(),
            null,
            RetrySafe: false);
        return new ProvisioningException(
            "BGW-PROVISIONING-RATE-LIMITED",
            inputFailure: false,
            ConnectorProvisioningStateMachine.RateLimited(snapshot, exception.RetryAfter, command));
    }

    internal static async Task<ServerVerification> VerifyServerAsync(
        IOfficialTestAdminApi api,
        ProvisioningContext context,
        string expectedVersionState,
        string expectedBindingState)
    {
        Fse2OfficialTestOperationalPlan plan = context.EffectivePlan;
        Fse2OfficialTestResolvedProviderAuthority publicAuthority = context.PublicAuthority;
        Fse2OfficialTestCompiledConfiguration compiled = context.Compiled;
        await RequireInstallationCurrentAsync(api, context.Installation).ConfigureAwait(false);
        await RequirePublicAuthorityCurrentAsync(api, plan, publicAuthority).ConfigureAwait(false);
        JsonElement current = await api.GetAsync(VersionPath()).ConfigureAwait(false);
        if (!string.Equals(current.GetProperty("state").GetString(), expectedVersionState, StringComparison.Ordinal) ||
            !string.Equals(current.GetProperty("checksumSha256").GetString(), compiled.CanonicalDefinitionSha256, StringComparison.Ordinal))
            throw Failure("FSE2_OFFICIALTEST_VERSION_READBACK_DRIFT");

        byte[] storedDefinition = await api.GetBytesAsync(VersionPath() + "/definition").ConfigureAwait(false);
        Fse2OfficialTestOperationalization.VerifyDefinitionReadback(storedDefinition, compiled);

        string bindingPath = $"admin/api/v1/connectors/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorId)}/versions/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorVersion)}/bindings?environmentId={plan.EnvironmentId:D}&offset=0&limit=10";
        JsonElement page = await api.GetAsync(bindingPath).ConfigureAwait(false);
        JsonElement[] bindings = page.GetProperty("items").EnumerateArray().ToArray();
        if (bindings.Length != 1) throw Failure("FSE2_OFFICIALTEST_BINDING_READBACK_DRIFT");
        JsonElement binding = bindings[0];
        if (!string.Equals(binding.GetProperty("state").GetString(), expectedBindingState, StringComparison.Ordinal) ||
            binding.GetProperty("environmentId").GetGuid() != plan.EnvironmentId)
            throw Failure("FSE2_OFFICIALTEST_BINDING_READBACK_DRIFT");
        string expectedEndpointDigest = ConnectorBindingDigests.Component(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [Fse2OfficialTestCanonicalDefinition.EndpointBinding] = plan.Endpoint.AbsoluteUri
        });
        if (!string.Equals(binding.GetProperty("endpointChecksumSha256").GetString(), expectedEndpointDigest, StringComparison.Ordinal))
            throw Failure("FSE2_OFFICIALTEST_ENDPOINT_READBACK_DRIFT");
        JsonElement certificates = binding.GetProperty("certificateResources");
        VerifyReference(certificates.GetProperty(Fse2OfficialTestCanonicalDefinition.MutualTlsBinding), plan.A1, "A1");
        VerifyReference(certificates.GetProperty(Fse2OfficialTestCanonicalDefinition.SigningBinding), plan.S1, "S1");
        if (binding.GetProperty("secretResources").EnumerateObject().Any())
            throw Failure("FSE2_OFFICIALTEST_GENERIC_SECRET_BINDING_PRESENT");
        return new(expectedVersionState, expectedBindingState, binding.GetProperty("checksumSha256").GetString()!);
    }

    private static void VerifyReference(JsonElement actual, Fse2OfficialTestProviderReference expected, string role)
    {
        string? version = actual.GetProperty("version").ValueKind == JsonValueKind.Null ? null : actual.GetProperty("version").GetString();
        if (!string.Equals(actual.GetProperty("providerId").GetString(), expected.ProviderId, StringComparison.Ordinal) ||
            !string.Equals(actual.GetProperty("resourceId").GetString(), expected.ResourceId, StringComparison.Ordinal) ||
            !string.Equals(version, expected.Version, StringComparison.Ordinal) ||
            actual.GetProperty("catalogRevision").GetInt64() != expected.CatalogRevision ||
            actual.GetProperty("publicMetadataRevision").GetInt64() != expected.PublicMetadataRevision)
            throw Failure($"FSE2_OFFICIALTEST_{role}_REVISION_DRIFT");
    }

    private static async Task<ApprovalReviewResult> ReadReviewAsync(IOfficialTestAdminApi api)
    {
        string path = VersionPath() + "/approval-review";
        JsonElement value = await api.GetAsync(path).ConfigureAwait(false);
        ApprovalReviewResult? review = value.Deserialize<ApprovalReviewResult>(Json);
        if (review is null || !IsSha256(review.DigestSha256) || review.Artifact.Operations.Count != 1 ||
            review.Artifact.Operations[0].OperationId != Fse2OfficialTestCanonicalDefinition.OperationId)
            throw Failure("FSE2_OFFICIALTEST_APPROVAL_REVIEW_INVALID");
        return review;
    }

    private static async Task RequireCurrentApproverAsync(IOfficialTestAdminApi api, Fse2OfficialTestCompiledConfiguration compiled)
    {
        JsonElement page = await api.GetAsync(VersionPath() + "/approvals?offset=0&limit=100").ConfigureAwait(false);
        Fse2OfficialTestApprovalAuthority[] approvals = page.GetProperty("items").EnumerateArray().Select(value => new Fse2OfficialTestApprovalAuthority(
            value.GetProperty("status").GetString() ?? string.Empty,
            value.GetProperty("checksumSha256").GetString() ?? string.Empty,
            value.GetProperty("requestedBy").GetGuid(),
            value.GetProperty("approvedBy").ValueKind == JsonValueKind.String ? value.GetProperty("approvedBy").GetGuid() : null)).ToArray();
        bool authorizedPublisher = Fse2OfficialTestOperationalization.IsCurrentPublisher(
            api.PrincipalId, compiled.CanonicalDefinitionSha256, approvals);
        if (!authorizedPublisher) throw Failure("FSE2_OFFICIALTEST_PUBLISHER_MUST_BE_DISTINCT_APPROVER");
    }

    private static Fse2OfficialTestOperationalPlan ReadPlan(string path) =>
        Fse2OfficialTestOperationalization.ParsePlan(ReadBounded(path, 64 * 1024, "FSE2_OFFICIALTEST_PLAN_FILE_INVALID"));

    internal static async Task<ProvisioningContext> PreflightAsync(
        IOfficialTestAdminApi api,
        Fse2OfficialTestOperationalPlan declaredPlan)
    {
        if (api.PrincipalId == Guid.Empty) throw Failure("FSE2_OFFICIALTEST_ADMIN_SESSION_INVALID", inputFailure: true);
        InstallationAuthority installation = await ResolveInstallationAuthorityAsync(api, declaredPlan).ConfigureAwait(false);
        await RequireEnvironmentCurrentAsync(api, installation.EnvironmentId).ConfigureAwait(false);
        Fse2OfficialTestOperationalPlan effectivePlan = declaredPlan with { EnvironmentId = installation.EnvironmentId };
        Fse2OfficialTestResolvedProviderAuthority publicAuthority = await ResolvePublicAuthorityAsync(api, effectivePlan).ConfigureAwait(false);
        Fse2OfficialTestCompiledConfiguration compiled = Fse2OfficialTestOperationalization.Compile(
            effectivePlan,
            publicAuthority.A1,
            publicAuthority.S1);
        return new(declaredPlan, effectivePlan, installation, publicAuthority, compiled);
    }

    private static async Task<InstallationAuthority> ResolveInstallationAuthorityAsync(
        IOfficialTestAdminApi api,
        Fse2OfficialTestOperationalPlan plan) =>
        await ResolveInstallationAuthorityAsync(
            api, plan.TenantId, plan.InstallationId, plan.EnvironmentId, initialPreflight: true).ConfigureAwait(false);

    private static async Task<InstallationAuthority> ResolveInstallationAuthorityAsync(
        IOfficialTestAdminApi api,
        Guid tenantId,
        Guid installationId,
        Guid assertedEnvironmentId,
        bool initialPreflight)
    {
        InstallationAuthority[] exact;
        try
        {
            exact = (await ReadPagedItemsAsync(
                api,
                offset => $"admin/api/v1/installations?tenantId={tenantId:D}&offset={offset}&limit=100",
                "FSE2_OFFICIALTEST_INSTALLATION_CATALOG_TOO_LARGE").ConfigureAwait(false))
                .Where(value => value.GetProperty("id").GetGuid() == installationId)
                .Select(InstallationAuthorityFrom)
                .ToArray();
        }
        catch (ProvisioningException exception) when (
            string.Equals(exception.Code, "FSE2_OFFICIALTEST_ADMIN_REJECTED_401", StringComparison.Ordinal) ||
            string.Equals(exception.Code, "FSE2_OFFICIALTEST_ADMIN_REJECTED_403", StringComparison.Ordinal))
        {
            throw Failure("FSE2_OFFICIALTEST_INSTALLATION_UNAVAILABLE");
        }
        if (exact.Length == 0) throw Failure("FSE2_OFFICIALTEST_INSTALLATION_UNAVAILABLE");
        if (exact.Length != 1) throw Failure("FSE2_OFFICIALTEST_INSTALLATION_AMBIGUOUS");
        InstallationAuthority installation = exact[0];
        if (installation.TenantId != tenantId || installation.Id != installationId)
            throw Failure("FSE2_OFFICIALTEST_INSTALLATION_AUTHORITY_MISMATCH");
        if (!string.Equals(installation.Status, "Active", StringComparison.Ordinal))
            throw Failure("FSE2_OFFICIALTEST_INSTALLATION_INACTIVE");
        if (installation.EnvironmentId != assertedEnvironmentId)
            throw Failure(initialPreflight
                ? "FSE2_OFFICIALTEST_INSTALLATION_ENVIRONMENT_MISMATCH"
                : "FSE2_OFFICIALTEST_INSTALLATION_AUTHORITY_DRIFT", inputFailure: initialPreflight);
        return installation;
    }

    private static async Task RequireInstallationCurrentAsync(
        IOfficialTestAdminApi api,
        InstallationAuthority expected)
    {
        InstallationAuthority current;
        try
        {
            current = await ResolveInstallationAuthorityAsync(
                api, expected.TenantId, expected.Id, expected.EnvironmentId, initialPreflight: false).ConfigureAwait(false);
        }
        catch (ProvisioningException exception) when (
            exception.Code.StartsWith("FSE2_OFFICIALTEST_INSTALLATION_", StringComparison.Ordinal) &&
            !string.Equals(exception.Code, "FSE2_OFFICIALTEST_INSTALLATION_CATALOG_TOO_LARGE", StringComparison.Ordinal))
        {
            throw Failure("FSE2_OFFICIALTEST_INSTALLATION_AUTHORITY_DRIFT");
        }
        if (current != expected) throw Failure("FSE2_OFFICIALTEST_INSTALLATION_AUTHORITY_DRIFT");
    }

    private static async Task RequireEnvironmentCurrentAsync(IOfficialTestAdminApi api, Guid environmentId)
    {
        JsonElement[] exact = (await ReadPagedItemsAsync(
            api,
            offset => $"admin/api/v1/environments?offset={offset}&limit=100",
            "FSE2_OFFICIALTEST_ENVIRONMENT_CATALOG_TOO_LARGE").ConfigureAwait(false))
            .Where(value => value.GetProperty("id").GetGuid() == environmentId)
            .ToArray();
        if (exact.Length != 1) throw Failure("FSE2_OFFICIALTEST_INSTALLATION_ENVIRONMENT_NOT_FOUND");
    }

    private static async Task<JsonElement[]> ReadPagedItemsAsync(
        IOfficialTestAdminApi api,
        Func<int, string> path,
        string tooLargeCode)
    {
        List<JsonElement> items = [];
        for (int offset = 0; offset <= 1000; offset += 100)
        {
            JsonElement page = await api.GetAsync(path(offset)).ConfigureAwait(false);
            JsonElement[] batch = page.GetProperty("items").EnumerateArray().Select(value => value.Clone()).ToArray();
            items.AddRange(batch);
            if (items.Count > 1000) throw Failure(tooLargeCode);
            if (batch.Length < 100) return items.ToArray();
        }
        throw Failure(tooLargeCode);
    }

    private static InstallationAuthority InstallationAuthorityFrom(JsonElement value) => new(
        RequiredGuid(value, "id"),
        RequiredGuid(value, "tenantId"),
        RequiredGuid(value, "applicationId"),
        RequiredGuid(value, "environmentId"),
        value.GetProperty("status").GetString() ?? string.Empty,
        value.GetProperty("installationKind").GetString() ?? string.Empty);

    private static async Task<InstallationGrantAuthority[]> ReadExactGrantsAsync(
        IOfficialTestAdminApi api,
        InstallationAuthority installation) =>
        (await ReadPagedItemsAsync(
            api,
            offset => $"admin/api/v1/grants?tenantId={installation.TenantId:D}&offset={offset}&limit=100",
            "FSE2_OFFICIALTEST_GRANT_CATALOG_TOO_LARGE").ConfigureAwait(false))
        .Select(GrantAuthority)
        .Where(value => value.InstallationId == installation.Id &&
            string.Equals(value.ConnectorId, Fse2OfficialTestCanonicalDefinition.ConnectorId, StringComparison.Ordinal) &&
            string.Equals(value.OperationId, Fse2OfficialTestCanonicalDefinition.OperationId, StringComparison.Ordinal))
        .ToArray();

    private static InstallationGrantAuthority GrantAuthority(JsonElement value) => new(
        RequiredGuid(value, "id"),
        RequiredGuid(value, "installationId"),
        RequiredGuid(value, "tenantId"),
        value.GetProperty("connectorId").GetString() ?? string.Empty,
        value.GetProperty("operationId").GetString() ?? string.Empty,
        value.GetProperty("enabled").GetBoolean(),
        value.GetProperty("validFrom").GetDateTimeOffset(),
        value.GetProperty("validUntil").ValueKind == JsonValueKind.String ? value.GetProperty("validUntil").GetDateTimeOffset() : null);

    private static void RequireGrantCurrent(InstallationGrantAuthority grant, InstallationAuthority installation)
    {
        if (grant.InstallationId != installation.Id || grant.TenantId != installation.TenantId || !grant.Enabled ||
            !string.Equals(grant.ConnectorId, Fse2OfficialTestCanonicalDefinition.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(grant.OperationId, Fse2OfficialTestCanonicalDefinition.OperationId, StringComparison.Ordinal) ||
            grant.ValidFrom > DateTimeOffset.UtcNow ||
            grant.ValidUntil is not null && grant.ValidUntil <= DateTimeOffset.UtcNow)
            throw Failure("FSE2_OFFICIALTEST_GRANT_AUTHORITY_DRIFT");
    }

    private static async Task<Fse2OfficialTestResolvedProviderAuthority> ResolvePublicAuthorityAsync(
        IOfficialTestAdminApi api,
        Fse2OfficialTestOperationalPlan plan)
    {
        Fse2OfficialTestProviderCatalogResource a1 = ProviderCatalogResource(
            await api.GetAsync(ExactProviderResourcePath(plan.EnvironmentId, plan.A1)).ConfigureAwait(false));
        Fse2OfficialTestProviderCatalogResource s1 = ProviderCatalogResource(
            await api.GetAsync(ExactProviderResourcePath(plan.EnvironmentId, plan.S1)).ConfigureAwait(false));
        return Fse2OfficialTestOperationalization.ResolveProviderAuthority(plan, [a1, s1]);
    }

    private static async Task RequirePublicAuthorityCurrentAsync(
        IOfficialTestAdminApi api,
        Fse2OfficialTestOperationalPlan plan,
        Fse2OfficialTestResolvedProviderAuthority expected)
    {
        Fse2OfficialTestResolvedProviderAuthority current;
        try { current = await ResolvePublicAuthorityAsync(api, plan).ConfigureAwait(false); }
        catch (Fse2OfficialTestOperationalizationException) { throw Failure("FSE2_OFFICIALTEST_PROVIDER_AUTHORITY_DRIFT"); }
        if (current != expected) throw Failure("FSE2_OFFICIALTEST_PROVIDER_AUTHORITY_DRIFT");
    }

    private static Fse2OfficialTestProviderCatalogResource ProviderCatalogResource(JsonElement value)
    {
        JsonElement metadata = value.GetProperty("certificateMetadata");
        string? subjectPublicKeyInfoSha256 = metadata.ValueKind == JsonValueKind.Object &&
            metadata.TryGetProperty("subjectPublicKeyInfoSha256", out JsonElement spki) && spki.ValueKind == JsonValueKind.String
                ? spki.GetString()
                : null;
        string? subjectCommonName = metadata.ValueKind == JsonValueKind.Object &&
            metadata.TryGetProperty("subjectCommonName", out JsonElement commonName) && commonName.ValueKind == JsonValueKind.String
                ? commonName.GetString()
                : null;
        return new(
            value.GetProperty("providerId").GetString() ?? string.Empty,
            value.GetProperty("resourceId").GetString() ?? string.Empty,
            value.GetProperty("version").ValueKind == JsonValueKind.Null ? null : value.GetProperty("version").GetString(),
            value.GetProperty("revision").GetInt64(),
            value.GetProperty("publicMetadataRevision").ValueKind == JsonValueKind.Null ? null : value.GetProperty("publicMetadataRevision").GetInt64(),
            value.GetProperty("environmentId").GetGuid(),
            value.GetProperty("resourceType").GetString() ?? string.Empty,
            value.GetProperty("status").GetString() ?? string.Empty,
            value.GetProperty("connectorScope").GetString() ?? string.Empty,
            value.GetProperty("operationScope").GetString() ?? string.Empty,
            value.GetProperty("checksumSha256").GetString() ?? string.Empty,
            subjectPublicKeyInfoSha256,
            subjectCommonName);
    }

    private static string ExactProviderResourcePath(Guid environmentId, Fse2OfficialTestProviderReference reference)
    {
        string version = reference.Version is null ? string.Empty : $"&version={Segment(reference.Version)}";
        return $"admin/api/v1/provider-resources:resolve?environmentId={environmentId:D}&resourceType=ClientCertificate&providerId={Segment(reference.ProviderId)}&resourceId={Segment(reference.ResourceId)}{version}&revision={reference.CatalogRevision}&publicMetadataRevision={reference.PublicMetadataRevision}";
    }

    private static byte[] ReadBounded(string path, long maximumBytes, string error)
    {
        FileInfo file = new(path);
        if (!file.Exists || file.Length < 2 || file.Length > maximumBytes || (file.Attributes & FileAttributes.ReparsePoint) != 0)
            throw Failure(error, true);
        return File.ReadAllBytes(file.FullName);
    }

    private static Command ParseCommand(string[] args) => args switch
    {
        ["configure", string plan] => new("configure", plan),
        ["grant", string plan] => new("grant", plan),
        ["propose", string plan] => new("propose", plan),
        ["verify", string plan] => new("verify", plan),
        ["approve", string plan, string requestId, string digest]
            when Guid.TryParseExact(requestId, "D", out Guid parsed) && parsed != Guid.Empty && IsSha256(digest) =>
            new("approve", plan, parsed, digest),
        ["publish", string plan, string revision]
            when long.TryParse(revision, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long parsed) && parsed >= 0 =>
            new("publish", plan, ExpectedPublicationRevision: parsed),
        _ => throw Failure("FSE2_OFFICIALTEST_COMMAND_INVALID", true)
    };

    private static string SupportedCommand(string command) => command switch
    {
        "configure" => "fse2-officialtest configure <operational-plan.json>",
        "grant" => "fse2-officialtest grant <operational-plan.json>",
        "propose" => "fse2-officialtest propose <operational-plan.json>",
        "approve" => "fse2-officialtest approve <operational-plan.json> <approval-request-id> <approval-digest-sha256>",
        "publish" => "fse2-officialtest publish <operational-plan.json> <expected-publication-revision>",
        "verify" => "fse2-officialtest verify <operational-plan.json>",
        _ => "fse2-officialtest <command> <operational-plan.json>"
    };

    private static long PositiveLong(JsonElement value, string name)
    {
        long parsed = value.GetProperty(name).GetInt64();
        return parsed >= 1 ? parsed : throw Failure("FSE2_OFFICIALTEST_SERVER_RESPONSE_INVALID");
    }

    private static Guid RequiredGuid(JsonElement value, string name)
    {
        Guid parsed = value.GetProperty(name).GetGuid();
        return parsed != Guid.Empty ? parsed : throw Failure("FSE2_OFFICIALTEST_SERVER_RESPONSE_INVALID");
    }

    private static string VersionPath() =>
        $"admin/api/v1/connectors/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorId)}/versions/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorVersion)}";

    private static string Segment(string value) => Uri.EscapeDataString(value);
    private static bool IsSha256(string value) => value.Length == 64 && value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static ProvisioningException Failure(string code, bool inputFailure = false) => new(code, inputFailure);
    private static void Print<T>(T value) => Console.WriteLine(JsonSerializer.Serialize(value, Json));

    private static JsonSerializerOptions CreateJson()
    {
        JsonSerializerOptions options = new(JsonSerializerDefaults.Web) { WriteIndented = true, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }

    private static void Usage() => Console.WriteLine("""
        fse2-officialtest plan <operational-plan.json>
        fse2-officialtest configure <operational-plan.json>
        fse2-officialtest grant <operational-plan.json>
        fse2-officialtest propose <operational-plan.json>
        fse2-officialtest approve <operational-plan.json> <approval-request-id> <approval-digest-sha256>
        fse2-officialtest publish <operational-plan.json> <expected-publication-revision>
        fse2-officialtest verify <operational-plan.json>
        fse2-officialtest reduce-failure-evidence <admin-audit-page.json> <correlation-id>

        Operational commands require FSE2_GATEWAY_URL, FSE2_ADMIN_SESSION_COOKIE and optionally
        FSE2_GATEWAY_CA_FILE. Public A1/S1 authority is read only from the authenticated Admin API.
        Plan and reduce-failure-evidence perform no write, certificate access, signing, DNS or HTTP.
        """);

    private sealed class AdminApi(
        HttpClient client,
        CookieContainer cookies,
        Guid principalId,
        X509Certificate2? customRoot) : IOfficialTestAdminApi
    {
        private string? csrf;
        public Guid PrincipalId { get; private set; } = principalId;

        internal static async Task<AdminApi> CreateAsync()
        {
            string gatewayText = Environment.GetEnvironmentVariable("FSE2_GATEWAY_URL", EnvironmentVariableTarget.Process) ?? string.Empty;
            string cookieText = Environment.GetEnvironmentVariable("FSE2_ADMIN_SESSION_COOKIE", EnvironmentVariableTarget.Process) ?? string.Empty;
            if (!Uri.TryCreate(gatewayText, UriKind.Absolute, out Uri? gateway) || gateway.Scheme != Uri.UriSchemeHttps ||
                string.IsNullOrWhiteSpace(cookieText) || cookieText.Any(character => character is '\r' or '\n'))
                throw Failure("FSE2_OFFICIALTEST_ADMIN_SESSION_REQUIRED", true);
            CookieContainer cookies = new();
            try { cookies.SetCookies(gateway, cookieText); }
            catch (CookieException) { throw Failure("FSE2_OFFICIALTEST_ADMIN_SESSION_INVALID", true); }

            string? caPath = Environment.GetEnvironmentVariable("FSE2_GATEWAY_CA_FILE", EnvironmentVariableTarget.Process);
            X509Certificate2? customRoot = LoadCustomRoot(caPath);
            HttpClientHandler handler = new()
            {
                AllowAutoRedirect = false,
                UseCookies = true,
                CookieContainer = cookies,
                UseProxy = false
            };
            if (customRoot is not null)
            {
                handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
                {
                    if (certificate is null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
                    using X509Chain chain = new();
                    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    chain.ChainPolicy.CustomTrustStore.Add(customRoot);
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    return chain.Build(certificate);
                };
            }
            HttpClient client = new(handler) { BaseAddress = gateway, Timeout = TimeSpan.FromSeconds(30) };
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            AdminApi api = new(client, cookies, Guid.Empty, customRoot);
            try
            {
                JsonElement me = await api.GetAsync("admin/auth/me").ConfigureAwait(false);
                api.PrincipalId = me.GetProperty("id").GetGuid();
                if (api.PrincipalId == Guid.Empty) throw Failure("FSE2_OFFICIALTEST_ADMIN_SESSION_INVALID");
                return api;
            }
            catch
            {
                api.Dispose();
                throw;
            }
        }

        public Task<JsonElement> GetAsync(string relative) => SendAsync(HttpMethod.Get, relative, null, null);

        public async Task<byte[]> GetBytesAsync(string relative)
        {
            using HttpRequestMessage request = new(HttpMethod.Get, relative);
            using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            RequireSuccess(response);
            return await ReadBoundedResponseAsync(response.Content).ConfigureAwait(false);
        }

        public Task<JsonElement> MutateAsync(HttpMethod method, string relative, object? body, long? ifMatch = null) =>
            SendAsync(method, relative, body, ifMatch);

        private async Task<JsonElement> SendAsync(HttpMethod method, string relative, object? body, long? ifMatch)
        {
            using HttpRequestMessage request = new(method, relative);
            if (method != HttpMethod.Get)
            {
                request.Headers.Add("X-CSRF-TOKEN", await CsrfAsync().ConfigureAwait(false));
                if (ifMatch is not null) request.Headers.IfMatch.Add(new EntityTagHeaderValue(FormattableString.Invariant($"\"{ifMatch.Value}\"")));
            }
            if (body is not null) request.Content = JsonContent.Create(body, options: Json);
            using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            RequireSuccess(response);
            byte[] bytes = await ReadBoundedResponseAsync(response.Content).ConfigureAwait(false);
            using JsonDocument document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 64 });
            return document.RootElement.Clone();
        }

        private static X509Certificate2? LoadCustomRoot(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return null;
            try
            {
                X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(ReadBounded(
                    path, 64 * 1024, "FSE2_OFFICIALTEST_GATEWAY_CA_FILE_INVALID"));
                X509BasicConstraintsExtension? constraints = certificate.Extensions
                    .OfType<X509BasicConstraintsExtension>().SingleOrDefault();
                if (certificate.HasPrivateKey || constraints is null || !constraints.CertificateAuthority)
                {
                    certificate.Dispose();
                    throw Failure("FSE2_OFFICIALTEST_GATEWAY_CA_FILE_INVALID", true);
                }
                return certificate;
            }
            catch (ProvisioningException) { throw; }
            catch (Exception exception) when (exception is CryptographicException or InvalidOperationException)
            {
                throw Failure("FSE2_OFFICIALTEST_GATEWAY_CA_FILE_INVALID", true);
            }
        }

        private static async Task<byte[]> ReadBoundedResponseAsync(HttpContent content)
        {
            const int maximumBytes = 1024 * 1024;
            await using Stream stream = await content.ReadAsStreamAsync().ConfigureAwait(false);
            using MemoryStream buffer = new();
            byte[] block = new byte[16 * 1024];
            while (true)
            {
                int read = await stream.ReadAsync(block).ConfigureAwait(false);
                if (read == 0) return buffer.ToArray();
                if (buffer.Length + read > maximumBytes) throw Failure("FSE2_OFFICIALTEST_SERVER_RESPONSE_TOO_LARGE");
                buffer.Write(block, 0, read);
            }
        }

        private async Task<string> CsrfAsync()
        {
            if (csrf is not null) return csrf;
            JsonElement result = await GetAsync("admin/auth/csrf").ConfigureAwait(false);
            csrf = result.GetProperty("token").GetString();
            if (string.IsNullOrWhiteSpace(csrf) || csrf.Length > 4096) throw Failure("FSE2_OFFICIALTEST_CSRF_INVALID");
            return csrf;
        }

        private static void RequireSuccess(HttpResponseMessage response)
        {
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
                throw new ConnectorProvisioningRateLimitException(ParseRetryAfter(response.Headers.RetryAfter));
            if (!response.IsSuccessStatusCode)
                throw Failure($"FSE2_OFFICIALTEST_ADMIN_REJECTED_{(int)response.StatusCode}");
            if (response.Content.Headers.ContentLength is > 1024 * 1024)
                throw Failure("FSE2_OFFICIALTEST_SERVER_RESPONSE_TOO_LARGE");
        }

        private static TimeSpan? ParseRetryAfter(RetryConditionHeaderValue? retryAfter)
        {
            if (retryAfter?.Delta is { } delta) return delta;
            return retryAfter?.Date is { } date ? date - DateTimeOffset.UtcNow : null;
        }

        public void Dispose()
        {
            client.Dispose();
            customRoot?.Dispose();
            GC.KeepAlive(cookies);
        }
    }

    private sealed record Command(
        string Name,
        string PlanPath,
        Guid? ApprovalRequestId = null,
        string? ExpectedApprovalDigest = null,
        long? ExpectedPublicationRevision = null);
    internal sealed record InstallationAuthority(
        Guid Id,
        Guid TenantId,
        Guid ApplicationId,
        Guid EnvironmentId,
        string Status,
        string InstallationKind);
    internal sealed record InstallationGrantAuthority(
        Guid Id,
        Guid InstallationId,
        Guid TenantId,
        string ConnectorId,
        string OperationId,
        bool Enabled,
        DateTimeOffset ValidFrom,
        DateTimeOffset? ValidUntil);
    internal sealed record ProvisioningContext(
        Fse2OfficialTestOperationalPlan DeclaredPlan,
        Fse2OfficialTestOperationalPlan EffectivePlan,
        InstallationAuthority Installation,
        Fse2OfficialTestResolvedProviderAuthority PublicAuthority,
        Fse2OfficialTestCompiledConfiguration Compiled);
    internal sealed record DiscoveredProvisioningState(
        ConnectorProvisioningSnapshot Snapshot,
        long VersionRowVersion,
        string? VersionState,
        string? BindingState,
        string? BindingChecksumSha256,
        Guid? ApprovalRequestId,
        string? ApprovalDigestSha256);
    internal sealed record ServerVerification(string VersionState, string BindingState, string BindingChecksumSha256);
    internal sealed class ProvisioningException(
        string code,
        bool inputFailure,
        ConnectorProvisioningRateLimitResult? rateLimitResult = null) : Exception(code)
    {
        internal string Code { get; } = code;
        internal bool InputFailure { get; } = inputFailure;
        internal ConnectorProvisioningRateLimitResult? RateLimitResult { get; } = rateLimitResult;
    }
}

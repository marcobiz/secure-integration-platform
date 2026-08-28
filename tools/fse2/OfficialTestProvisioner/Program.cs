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

namespace SecureIntegration.Tools.Fse2.OfficialTestProvisioner;

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

        try
        {
            if (args[0] == "plan" && args.Length == 2)
            {
                Fse2OfficialTestOperationalPlan plan = ReadPlan(args[1]);
                Print(Fse2OfficialTestOperationalization.Plan(plan));
                return 0;
            }

            Command command = ParseCommand(args);
            Fse2OfficialTestOperationalPlan operationalPlan = ReadPlan(command.PlanPath);
            using AdminApi api = await AdminApi.CreateAsync().ConfigureAwait(false);
            Fse2OfficialTestResolvedProviderAuthority publicAuthority = await ResolvePublicAuthorityAsync(api, operationalPlan).ConfigureAwait(false);
            Fse2OfficialTestCompiledConfiguration compiled = Fse2OfficialTestOperationalization.Compile(
                operationalPlan,
                publicAuthority.A1,
                publicAuthority.S1);

            switch (command.Name)
            {
                case "configure":
                    await ConfigureAsync(api, operationalPlan, publicAuthority, compiled).ConfigureAwait(false);
                    break;
                case "propose":
                    await ProposeAsync(api, operationalPlan, publicAuthority, compiled).ConfigureAwait(false);
                    break;
                case "approve":
                    await ApproveAsync(api, operationalPlan, publicAuthority, compiled, command.ApprovalRequestId!.Value, command.ExpectedApprovalDigest!).ConfigureAwait(false);
                    break;
                case "publish":
                    await PublishAsync(api, operationalPlan, publicAuthority, compiled, command.ExpectedPublicationRevision!.Value).ConfigureAwait(false);
                    break;
                case "verify":
                    await VerifyAndPrintAsync(api, operationalPlan, publicAuthority, compiled, "Published", "Active").ConfigureAwait(false);
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
        catch (ProvisioningException exception)
        {
            Console.Error.WriteLine(exception.Code);
            return exception.InputFailure ? 2 : 1;
        }
        catch (Exception exception) when (exception is IOException or JsonException or HttpRequestException or TaskCanceledException or FormatException or OverflowException)
        {
            Console.Error.WriteLine("FSE2_OFFICIALTEST_PROVISIONING_FAILED");
            return 1;
        }
    }

    private static async Task ConfigureAsync(
        AdminApi api,
        Fse2OfficialTestOperationalPlan plan,
        Fse2OfficialTestResolvedProviderAuthority publicAuthority,
        Fse2OfficialTestCompiledConfiguration compiled)
    {
        await RequirePublicAuthorityCurrentAsync(api, plan, publicAuthority).ConfigureAwait(false);
        using JsonDocument definition = JsonDocument.Parse(compiled.CanonicalDefinition);
        JsonElement validated = await api.MutateAsync(HttpMethod.Post, "admin/api/v1/connectors:validate",
            new ConnectorImportRequest(definition.RootElement.Clone())).ConfigureAwait(false);
        if (!validated.GetProperty("valid").GetBoolean() ||
            !string.Equals(validated.GetProperty("checksumSha256").GetString(), compiled.CanonicalDefinitionSha256, StringComparison.Ordinal))
            throw Failure("FSE2_OFFICIALTEST_SERVER_VALIDATION_DRIFT");

        await RequirePublicAuthorityCurrentAsync(api, plan, publicAuthority).ConfigureAwait(false);
        JsonElement imported = await api.MutateAsync(HttpMethod.Post, "admin/api/v1/connectors:import",
            new ConnectorImportRequest(definition.RootElement.Clone(), compiled.CanonicalDefinitionSha256)).ConfigureAwait(false);
        long importedRowVersion = PositiveLong(imported, "rowVersion");
        await RequirePublicAuthorityCurrentAsync(api, plan, publicAuthority).ConfigureAwait(false);
        JsonElement stored = await api.MutateAsync(HttpMethod.Post,
            $"admin/api/v1/connectors/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorId)}/versions/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorVersion)}:validate",
            body: null,
            ifMatch: importedRowVersion).ConfigureAwait(false);
        if (!string.Equals(stored.GetProperty("state").GetString(), "Validated", StringComparison.Ordinal))
            throw Failure("FSE2_OFFICIALTEST_VALIDATE_STORED_FAILED");

        await RequirePublicAuthorityCurrentAsync(api, plan, publicAuthority).ConfigureAwait(false);
        _ = await api.MutateAsync(HttpMethod.Put,
            $"admin/api/v1/connectors/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorId)}/bindings",
            compiled.BindingRequest,
            plan.ExpectedBindingRevision).ConfigureAwait(false);
        ServerVerification verified = await VerifyServerAsync(api, plan, publicAuthority, compiled, "Validated", "Draft").ConfigureAwait(false);
        Print(Result("configured", compiled, verified));
    }

    private static async Task ProposeAsync(
        AdminApi api,
        Fse2OfficialTestOperationalPlan plan,
        Fse2OfficialTestResolvedProviderAuthority publicAuthority,
        Fse2OfficialTestCompiledConfiguration compiled)
    {
        ServerVerification verified = await VerifyServerAsync(api, plan, publicAuthority, compiled, "Validated", "Draft").ConfigureAwait(false);
        ApprovalReviewResult review = await ReadReviewAsync(api).ConfigureAwait(false);
        await RequirePublicAuthorityCurrentAsync(api, plan, publicAuthority).ConfigureAwait(false);
        JsonElement requested = await api.MutateAsync(HttpMethod.Post,
            $"admin/api/v1/connectors/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorId)}/versions/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorVersion)}/approval-requests",
            body: null).ConfigureAwait(false);
        Guid requestId = RequiredGuid(requested, "id");
        Print(new
        {
            status = "proposed",
            connectorId = Fse2OfficialTestCanonicalDefinition.ConnectorId,
            connectorVersion = Fse2OfficialTestCanonicalDefinition.ConnectorVersion,
            approvalRequestId = requestId,
            approvalDigestSha256 = review.DigestSha256,
            canonicalDefinitionSha256 = compiled.CanonicalDefinitionSha256,
            operationProfileChecksumSha256 = compiled.OperationProfileChecksumSha256,
            bindingConfigurationDigestSha256 = compiled.BindingConfigurationDigestSha256,
            serverBindingChecksumSha256 = verified.BindingChecksumSha256
        });
    }

    private static async Task ApproveAsync(
        AdminApi api,
        Fse2OfficialTestOperationalPlan plan,
        Fse2OfficialTestResolvedProviderAuthority publicAuthority,
        Fse2OfficialTestCompiledConfiguration compiled,
        Guid approvalRequestId,
        string expectedApprovalDigest)
    {
        _ = await VerifyServerAsync(api, plan, publicAuthority, compiled, "Validated", "Draft").ConfigureAwait(false);
        ApprovalReviewResult review = await ReadReviewAsync(api).ConfigureAwait(false);
        if (!IsSha256(expectedApprovalDigest) || !string.Equals(review.DigestSha256, expectedApprovalDigest, StringComparison.Ordinal))
            throw Failure("FSE2_OFFICIALTEST_APPROVAL_DIGEST_STALE", inputFailure: true);
        await RequirePublicAuthorityCurrentAsync(api, plan, publicAuthority).ConfigureAwait(false);
        JsonElement approved = await api.MutateAsync(HttpMethod.Post,
            $"admin/api/v1/connectors/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorId)}/versions/{Segment(Fse2OfficialTestCanonicalDefinition.ConnectorVersion)}/approvals",
            new ConnectorApprovalAcceptanceRequest(approvalRequestId, expectedApprovalDigest)).ConfigureAwait(false);
        if (!string.Equals(approved.GetProperty("status").GetString(), "Approved", StringComparison.Ordinal))
            throw Failure("FSE2_OFFICIALTEST_APPROVAL_FAILED");
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

    private static async Task PublishAsync(
        AdminApi api,
        Fse2OfficialTestOperationalPlan plan,
        Fse2OfficialTestResolvedProviderAuthority publicAuthority,
        Fse2OfficialTestCompiledConfiguration compiled,
        long expectedPublicationRevision)
    {
        if (expectedPublicationRevision < 0) throw Failure("FSE2_OFFICIALTEST_PUBLICATION_REVISION_INVALID", inputFailure: true);
        _ = await VerifyServerAsync(api, plan, publicAuthority, compiled, "Validated", "Draft").ConfigureAwait(false);
        await RequireCurrentApproverAsync(api, compiled).ConfigureAwait(false);
        await RequirePublicAuthorityCurrentAsync(api, plan, publicAuthority).ConfigureAwait(false);
        JsonElement current = await api.GetAsync(VersionPath()).ConfigureAwait(false);
        long rowVersion = PositiveLong(current, "rowVersion");
        JsonElement published = await api.MutateAsync(HttpMethod.Post, VersionPath() + ":publish",
            new ConnectorVersionActionRequest(rowVersion, expectedPublicationRevision), rowVersion).ConfigureAwait(false);
        if (!string.Equals(published.GetProperty("state").GetString(), "Published", StringComparison.Ordinal))
            throw Failure("FSE2_OFFICIALTEST_PUBLICATION_FAILED");
        ServerVerification verified = await VerifyServerAsync(api, plan, publicAuthority, compiled, "Published", "Active").ConfigureAwait(false);
        Print(Result("published", compiled, verified));
    }

    private static async Task VerifyAndPrintAsync(
        AdminApi api,
        Fse2OfficialTestOperationalPlan plan,
        Fse2OfficialTestResolvedProviderAuthority publicAuthority,
        Fse2OfficialTestCompiledConfiguration compiled,
        string expectedVersionState,
        string expectedBindingState)
    {
        ServerVerification verified = await VerifyServerAsync(api, plan, publicAuthority, compiled, expectedVersionState, expectedBindingState).ConfigureAwait(false);
        Print(Result("verified", compiled, verified));
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

    private static async Task<ServerVerification> VerifyServerAsync(
        AdminApi api,
        Fse2OfficialTestOperationalPlan plan,
        Fse2OfficialTestResolvedProviderAuthority publicAuthority,
        Fse2OfficialTestCompiledConfiguration compiled,
        string expectedVersionState,
        string expectedBindingState)
    {
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

    private static async Task<ApprovalReviewResult> ReadReviewAsync(AdminApi api)
    {
        string path = VersionPath() + "/approval-review";
        JsonElement value = await api.GetAsync(path).ConfigureAwait(false);
        ApprovalReviewResult? review = value.Deserialize<ApprovalReviewResult>(Json);
        if (review is null || !IsSha256(review.DigestSha256) || review.Artifact.Operations.Count != 1 ||
            review.Artifact.Operations[0].OperationId != Fse2OfficialTestCanonicalDefinition.OperationId)
            throw Failure("FSE2_OFFICIALTEST_APPROVAL_REVIEW_INVALID");
        return review;
    }

    private static async Task RequireCurrentApproverAsync(AdminApi api, Fse2OfficialTestCompiledConfiguration compiled)
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

    private static async Task<Fse2OfficialTestResolvedProviderAuthority> ResolvePublicAuthorityAsync(
        AdminApi api,
        Fse2OfficialTestOperationalPlan plan)
    {
        List<Fse2OfficialTestProviderCatalogResource> resources = [];
        const int limit = 100;
        int offset = 0;
        int? expectedTotal = null;
        do
        {
            JsonElement page = await api.GetAsync(
                $"admin/api/v1/provider-resources?environmentId={plan.EnvironmentId:D}&resourceType=ClientCertificate&offset={offset}&limit={limit}").ConfigureAwait(false);
            int total = page.GetProperty("total").GetInt32();
            if (total < 0 || total > 1000 || (expectedTotal is not null && total != expectedTotal.Value))
                throw Failure("FSE2_OFFICIALTEST_PROVIDER_CATALOG_RESPONSE_INVALID");
            expectedTotal = total;
            JsonElement[] items = page.GetProperty("items").EnumerateArray().ToArray();
            if (items.Length > limit || offset + items.Length > total)
                throw Failure("FSE2_OFFICIALTEST_PROVIDER_CATALOG_RESPONSE_INVALID");
            resources.AddRange(items.Select(ProviderCatalogResource));
            offset += items.Length;
            if (items.Length == 0 && offset < total)
                throw Failure("FSE2_OFFICIALTEST_PROVIDER_CATALOG_RESPONSE_INVALID");
        }
        while (offset < expectedTotal!.Value);
        return Fse2OfficialTestOperationalization.ResolveProviderAuthority(plan, resources);
    }

    private static async Task RequirePublicAuthorityCurrentAsync(
        AdminApi api,
        Fse2OfficialTestOperationalPlan plan,
        Fse2OfficialTestResolvedProviderAuthority expected)
    {
        Fse2OfficialTestResolvedProviderAuthority current = await ResolvePublicAuthorityAsync(api, plan).ConfigureAwait(false);
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
        fse2-officialtest propose <operational-plan.json>
        fse2-officialtest approve <operational-plan.json> <approval-request-id> <approval-digest-sha256>
        fse2-officialtest publish <operational-plan.json> <expected-publication-revision>
        fse2-officialtest verify <operational-plan.json>

        Operational commands require FSE2_GATEWAY_URL, FSE2_ADMIN_SESSION_COOKIE and optionally
        FSE2_GATEWAY_CA_FILE. Public A1/S1 authority is read only from the authenticated Admin API.
        Plan performs no write, certificate access, signing, DNS or HTTP.
        """);

    private sealed class AdminApi(
        HttpClient client,
        CookieContainer cookies,
        Guid principalId,
        X509Certificate2? customRoot) : IDisposable
    {
        private string? csrf;
        internal Guid PrincipalId { get; private set; } = principalId;

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

        internal Task<JsonElement> GetAsync(string relative) => SendAsync(HttpMethod.Get, relative, null, null);

        internal async Task<byte[]> GetBytesAsync(string relative)
        {
            using HttpRequestMessage request = new(HttpMethod.Get, relative);
            using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            RequireSuccess(response);
            return await ReadBoundedResponseAsync(response.Content).ConfigureAwait(false);
        }

        internal Task<JsonElement> MutateAsync(HttpMethod method, string relative, object? body, long? ifMatch = null) =>
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
            if (!response.IsSuccessStatusCode)
                throw Failure($"FSE2_OFFICIALTEST_ADMIN_REJECTED_{(int)response.StatusCode}");
            if (response.Content.Headers.ContentLength is > 1024 * 1024)
                throw Failure("FSE2_OFFICIALTEST_SERVER_RESPONSE_TOO_LARGE");
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
    private sealed record ServerVerification(string VersionState, string BindingState, string BindingChecksumSha256);
    private sealed class ProvisioningException(string code, bool inputFailure) : Exception(code)
    {
        internal string Code { get; } = code;
        internal bool InputFailure { get; } = inputFailure;
    }
}

using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using SecureIntegration.ConnectorPacks.Healthcare.FSE2;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Tools.Fse2.OfficialTestProvisioner;

internal static partial class Program
{
    // This entrypoint deliberately cannot invoke a document publication operation.
    internal static readonly IReadOnlyList<string> PilotOperations = Array.AsReadOnly(new[]
        { "validate-fhir", "validate-cda", "get-status-by-workflow", "get-status-by-trace" });
    internal sealed record PilotSettings(Fse2OfficialTestOrganization Organization, Fse2OfficialTestLocality Locality);
    internal sealed record PilotState(Guid CorrelationId, string Operation, int? GatewayHttpStatus,
        int? UpstreamHttpStatus, string? Workflow, string? Trace, string Classification, int EventCount)
    {
        public string? SafeGatewayCode { get; init; }
    }

    private static async Task<int> RunPilotAsync(string[] args)
    {
        if (args.Length is < 2 or > 3 || args[0] is not
            ("configure" or "propose" or "approve" or "verify" or "validate-fhir" or "validate-cda" or "status-workflow" or "status-trace" or "audit"))
            throw Failure("FSE2_PILOT_COMMAND_INVALID", true);
        string phase = args[0];
        string root = Environment.GetEnvironmentVariable("FSE2_PILOT_ARTIFACT_ROOT")
            ?? throw Failure("FSE2_PILOT_START_REQUIRED", true);
        PilotSettings settings = JsonSerializer.Deserialize<PilotSettings>(ReadBounded(args[1], 16384, "FSE2_PILOT_SETTINGS_INVALID"), Json)
            ?? throw Failure("FSE2_PILOT_SETTINGS_INVALID", true);
        ValidatePilotSettings(settings);
        using JsonDocument bootstrap = JsonDocument.Parse(ReadBounded(Path.Combine(root, "raw", "provisioning.json"), 65536, "FSE2_PILOT_START_REQUIRED"));
        JsonElement data = bootstrap.RootElement;
        Guid tenant = RequiredGuid(data, "tenantId");
        Guid installation = RequiredGuid(data, "directInstallationId");
        Guid environment = RequiredGuid(data, "environmentId");
        string statePath = Path.Combine(root, "fse2-last-call.json");
        PilotState? previous = File.Exists(statePath)
            ? JsonSerializer.Deserialize<PilotState>(ReadBounded(statePath, 8192, "FSE2_PILOT_STATE_INVALID"), Json) : null;

        using X509Certificate2 certificate = X509Certificate2.CreateFromPemFile(
            Path.Combine(root, "raw", "certificates", "onboarding-driver.crt"),
            Path.Combine(root, "raw", "certificates", "onboarding-driver.key"));
        using ECDsa key = certificate.GetECDsaPrivateKey() ?? throw Failure("FSE2_PILOT_CLIENT_KEY_INVALID");
        using X509Certificate2 ca = X509CertificateLoader.LoadCertificateFromFile(
            Path.Combine(root, "raw", "certificates", "ca.crt"));
        using HttpClient client = PilotClient(certificate, ca);

        if (phase is "validate-fhir" or "validate-cda" or "status-workflow" or "status-trace")
        {
            Fse2Request request = phase switch
            {
                "validate-fhir" => await PilotFhirRequestAsync().ConfigureAwait(false),
                "validate-cda" => await PilotCdaRequestAsync().ConfigureAwait(false),
                "status-workflow" => Fse2Request.GetStatusByWorkflow(args.Length == 3 ? args[2] : previous?.Workflow
                    ?? throw Failure("FSE2_PILOT_WORKFLOW_MISSING_USE_SUCCESSFUL_VALIDATION", true)),
                _ => Fse2Request.GetStatusByTrace(args.Length == 3 ? args[2] : previous?.Trace
                    ?? throw Failure("FSE2_PILOT_TRACE_MISSING", true))
            };
            string operation = phase.StartsWith("status-", StringComparison.Ordinal) ? "get-" + phase.Replace("status-", "status-by-", StringComparison.Ordinal) : phase;
            Guid correlation = Guid.NewGuid();
            // Write intent before dispatch. A timeout is ambiguous: resuming never repeats this call.
            PilotState pending = new(correlation, operation, null, null,
                phase == "status-workflow" ? request.ResourceIdentifier : null,
                phase == "status-trace" ? request.ResourceIdentifier : phase == "status-workflow" && previous?.Workflow == request.ResourceIdentifier ? previous?.Trace : null,
                "DISPATCH_PENDING", 0);
            File.WriteAllBytes(statePath, JsonSerializer.SerializeToUtf8Bytes(pending, Json));
            PilotState result = await PilotInvokeAsync(client, key, request, pending).ConfigureAwait(false);
            File.WriteAllBytes(statePath, JsonSerializer.SerializeToUtf8Bytes(result, Json));
            Print(result);
            return result.GatewayHttpStatus == 200 ? 0 : 1;
        }

        using AdminApi api = await AdminApi.CreateAsync().ConfigureAwait(false);
        if (phase == "audit")
        {
            Guid correlation = args.Length == 3 ? Guid.ParseExact(args[2], "D") : previous?.CorrelationId
                ?? throw Failure("FSE2_PILOT_CALL_MISSING", true);
            JsonElement[] records = await ReadPagedItemsAsync(api,
                offset => $"admin/api/v1/audit?tenantId={tenant:D}&offset={offset}&limit=100", "FSE2_PILOT_AUDIT_LIMIT").ConfigureAwait(false);
            JsonElement[] invocation = records.Where(item => item.GetProperty("action").GetString() == "operation.invoke" &&
                item.TryGetProperty("correlationId", out JsonElement id) && id.TryGetGuid(out Guid value) && value == correlation).ToArray();
            int success = invocation.Count(item => item.GetProperty("outcome").GetString() == "success");
            int failure = invocation.Count(item => item.GetProperty("outcome").GetString() == "failure");
            Fse2FailureDiagnosticsEvidence? diagnostics = failure == 1 && invocation[0].TryGetProperty("failureDiagnostics", out JsonElement d) && d.ValueKind == JsonValueKind.Object
                ? Fse2FailureEvidenceReducer.Reduce(JsonSerializer.SerializeToElement(new { items = invocation }), correlation) : null;
            Print(new { correlationId = correlation, successAudit = success, failureAudit = failure, diagnostics });
            return success + failure == 1 ? 0 : 1;
        }

        JsonElement[] installations = await ReadPagedItemsAsync(api,
            offset => $"admin/api/v1/installations?tenantId={tenant:D}&offset={offset}&limit=100", "FSE2_PILOT_INSTALLATION_LIMIT").ConfigureAwait(false);
        JsonElement selected = installations.Single(item => item.GetProperty("id").GetGuid() == installation);
        if (selected.GetProperty("status").GetString() != "Active")
        {
            if (phase != "configure") throw Failure("FSE2_PILOT_CONFIGURE_REQUIRED");
            await PilotEnrollAsync(client, key, certificate, data).ConfigureAwait(false);
        }
        JsonElement[] resources = await ReadPagedItemsAsync(api,
            offset => $"admin/api/v1/provider-resources?environmentId={environment:D}&resourceType=ClientCertificate&offset={offset}&limit=100",
            "FSE2_PILOT_PROVIDER_LIMIT").ConfigureAwait(false);
        Fse2OfficialTestProviderReference Reference(string id)
        {
            Fse2OfficialTestProviderCatalogResource resource = resources.Select(ProviderCatalogResource).Single(item =>
                item.ProviderId == "local-pkcs12" && item.ResourceId == id && item.EnvironmentId == environment &&
                item.ConnectorScope == Fse2CurrentSpec.ConnectorId && item.Status == "Active");
            return new(resource.ProviderId, resource.ResourceId, resource.Version, resource.CatalogRevision,
                resource.PublicMetadataRevision ?? throw Failure("FSE2_PILOT_PROVIDER_NOT_READY"));
        }
        Fse2OfficialTestOperationalPlan plan = new(tenant, installation, environment,
            new Uri(Fse2OfficialTestCanonicalDefinition.OfficialTestEndpoint), settings.Organization, settings.Locality,
            Reference("fse2-auth"), Reference("fse2-sign"), null) { UsesCurrentSpec = true };
        ProvisioningContext context = (await PreflightAsync(api, plan).ConfigureAwait(false)) with { ValidationStatusOnly = true };
        switch (phase)
        {
            case "configure":
                await ConfigureAsync(api, context).ConfigureAwait(false);
                await GrantAsync(api, context).ConfigureAwait(false);
                break;
            case "propose": await ProposeAsync(api, context).ConfigureAwait(false); break;
            case "approve":
                DiscoveredProvisioningState state = await DiscoverProvisioningStateAsync(api, context).ConfigureAwait(false);
                await ApproveAsync(api, context, state.ApprovalRequestId ?? throw Failure("FSE2_PILOT_PROPOSE_REQUIRED"),
                    state.ApprovalDigestSha256 ?? throw Failure("FSE2_PILOT_PROPOSE_REQUIRED")).ConfigureAwait(false);
                JsonElement[] connectors = await ReadPagedItemsAsync(api, offset => $"admin/api/v1/connectors?offset={offset}&limit=100",
                    "FSE2_PILOT_CONNECTOR_LIMIT").ConfigureAwait(false);
                long revision = connectors.Single(item => item.GetProperty("connectorId").GetString() == plan.ConnectorId).GetProperty("publicationRevision").GetInt64();
                await PublishAsync(api, context, revision).ConfigureAwait(false);
                break;
            case "verify":
                await VerifyAndPrintAsync(api, context, "Published", "Active").ConfigureAwait(false);
                // The existing Broker-only read authenticates Direct before denying its role.
                // This proves mTLS/BGW1 without an upstream document dispatch or a new API.
                using (HttpResponseMessage response = await PilotSendAsync(client, key, HttpMethod.Get, "/v1/broker-policy", []).ConfigureAwait(false))
                {
                    string code = ReducePilotFailure(await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false));
                    if (response.StatusCode != HttpStatusCode.Forbidden || code != "BGW-AUTHZ-OPERATION-DENIED")
                        throw Failure(code);
                    Print(new { status = "runtime-authenticated", documentDispatch = 0 });
                }
                break;
        }
        return 0;
    }

    internal static void ValidatePilotSettings(PilotSettings settings)
    {
        if (settings.Organization is null || settings.Locality is null) throw Failure("FSE2_PILOT_SETTINGS_INVALID", true);
        string? domain = settings.Organization.DomainId;
        if (domain is not { Length: 3 } || !domain.All(char.IsAsciiDigit))
            throw Failure("FSE2_PILOT_USE_ASSIGNED_ORGANIZATION_DOMAIN_CODE", true);
    }

    private static HttpClient PilotClient(X509Certificate2 certificate, X509Certificate2 ca)
    {
        Uri gateway = new(Environment.GetEnvironmentVariable("FSE2_GATEWAY_URL") ?? "https://localhost:8443/");
        if (!gateway.IsLoopback || gateway.Scheme != "https" || gateway.AbsolutePath != "/" || gateway.Query.Length != 0 || gateway.UserInfo.Length != 0)
            throw Failure("FSE2_PILOT_LOCAL_GATEWAY_REQUIRED", true);
        HttpClientHandler handler = new() { AllowAutoRedirect = false, UseCookies = false, UseProxy = false };
        handler.ClientCertificates.Add(certificate);
        handler.ServerCertificateCustomValidationCallback = (_, server, _, errors) =>
        {
            if (server is null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
            using X509Chain chain = new();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(ca);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(server);
        };
        return new(handler) { BaseAddress = gateway, Timeout = TimeSpan.FromSeconds(45), MaxResponseContentBufferSize = 1024 * 1024 };
    }

    private static async Task PilotEnrollAsync(HttpClient client, ECDsa signer, X509Certificate2 certificate, JsonElement bootstrap)
    {
        Guid activation = RequiredGuid(bootstrap, "directActivationCodeId");
        using HttpResponseMessage challengeResponse = await client.PostAsJsonAsync("v1/enrollments/challenges", new
            { activationCodeId = activation, publicKeySpki = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()) }).ConfigureAwait(false);
        if (!challengeResponse.IsSuccessStatusCode) throw Failure("FSE2_PILOT_ENROLLMENT_CHALLENGE_FAILED_RESTART_IF_EXPIRED");
        using JsonDocument challengeDocument = JsonDocument.Parse(await challengeResponse.Content.ReadAsByteArrayAsync().ConfigureAwait(false));
        JsonElement challenge = challengeDocument.RootElement;
        Guid challengeId = RequiredGuid(challenge, "challengeId");
        byte[] proof = Encoding.UTF8.GetBytes(FormattableString.Invariant($"BGW-ENROLL1\n{challengeId:D}\n{challenge.GetProperty("challenge").GetString()}\n{activation:D}"));
        using HttpResponseMessage activated = await client.PostAsJsonAsync("v1/enrollments:activate", new
        {
            challengeId, activationCode = bootstrap.GetProperty("directActivationCode").GetString(),
            clientCertificate = Convert.ToBase64String(certificate.RawData),
            proofSignature = PilotEncode(signer.SignData(proof, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            clientVersion = "1.0.0"
        }).ConfigureAwait(false);
        if (!activated.IsSuccessStatusCode) throw Failure("FSE2_PILOT_ENROLLMENT_FAILED_CHECK_INSTALLATION");
    }

    private static async Task<PilotState> PilotInvokeAsync(HttpClient client, ECDsa key, Fse2Request request, PilotState pending)
    {
        if (!PilotOperations.Contains(pending.Operation, StringComparer.Ordinal)) throw Failure("FSE2_PILOT_OPERATION_DENIED");
        string target = $"/v1/connectors/{Fse2CurrentSpec.ConnectorId}/operations/{pending.Operation}:invoke";
        byte[] payload = request.SerializeAuthorizedPayload();
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(new { protocolVersion = "1.0", correlationId = pending.CorrelationId,
            payload = new { contentType = "application/vnd.bgw.fse2+json", encoding = "base64", data = Convert.ToBase64String(payload) } }, Json);
        try
        {
            using HttpResponseMessage response = await PilotSendAsync(client, key, HttpMethod.Post, target, body).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK)
                return pending with { GatewayHttpStatus = (int)response.StatusCode, Classification = "FAILURE_CHECK_AUDIT",
                    SafeGatewayCode = ReducePilotFailure(await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false)) };
            byte[] responseBytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            try { return ReducePilotSuccess(responseBytes, pending); }
            finally { CryptographicOperations.ZeroMemory(responseBytes); }
        }
        finally { CryptographicOperations.ZeroMemory(payload); CryptographicOperations.ZeroMemory(body); }
    }

    private static async Task<HttpResponseMessage> PilotSendAsync(HttpClient client, ECDsa key, HttpMethod method, string target, byte[] body)
    {
        using HttpRequestMessage message = CreatePilotMessage(key, method, target, body);
        return await client.SendAsync(message).ConfigureAwait(false);
    }

    internal static HttpRequestMessage CreatePilotMessage(ECDsa key, HttpMethod method, string target, byte[] body)
    {
        string timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
        string nonce = PilotEncode(RandomNumberGenerator.GetBytes(16));
        string hash = PilotEncode(SHA256.HashData(body));
        string signature = PilotEncode(key.SignData(Encoding.UTF8.GetBytes(RuntimeIdentityService.BuildSigningInput(method.Method, target, timestamp, nonce, hash)),
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        HttpRequestMessage message = new(method, target);
        if (method == HttpMethod.Post) { message.Content = new ByteArrayContent(body); message.Content.Headers.ContentType = new("application/json"); }
        message.Headers.Add("X-BG-Timestamp", timestamp);
        message.Headers.Add("X-BG-Nonce", nonce);
        message.Headers.Add("X-BG-Content-SHA256", hash);
        message.Headers.Add("X-BG-Signature", signature);
        message.Headers.Add("traceparent", $"00-{Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant()}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant()}-01");
        return message;
    }

    internal static string ReducePilotFailure(byte[] bytes)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(bytes);
            string? code = document.RootElement.TryGetProperty("code", out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
            return code is not null && BackendRuntimeWireCodes.IsPublished(RuntimeWireCodeKind.Reason, code) ? code : "FSE2_PILOT_GATEWAY_REJECTED";
        }
        catch (JsonException) { return "FSE2_PILOT_GATEWAY_REJECTED"; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static PilotState ReducePilotSuccess(byte[] bytes, PilotState pending)
    {
        using JsonDocument envelope = JsonDocument.Parse(bytes);
        if (RequiredGuid(envelope.RootElement, "correlationId") != pending.CorrelationId) throw Failure("FSE2_PILOT_RESPONSE_INVALID");
        JsonElement result = envelope.RootElement.GetProperty("result");
        if (result.GetProperty("encoding").GetString() != "base64") throw Failure("FSE2_PILOT_RESPONSE_INVALID");
        byte[] data = Convert.FromBase64String(result.GetProperty("data").GetString()!);
        try
        {
            Fse2Response normalized = JsonSerializer.Deserialize<Fse2Response>(data, Json) ?? throw Failure("FSE2_PILOT_RESPONSE_INVALID");
            if (normalized.CorrelationId != pending.CorrelationId) throw Failure("FSE2_PILOT_RESPONSE_INVALID");
            if (normalized.WorkflowInstanceId is not null) _ = Fse2Request.GetStatusByWorkflow(normalized.WorkflowInstanceId);
            if (normalized.TraceId is not null) _ = Fse2Request.GetStatusByTrace(normalized.TraceId);
            bool status = pending.Operation.StartsWith("get-status-", StringComparison.Ordinal);
            string? workflow = status ? pending.Workflow : normalized.WorkflowInstanceId;
            string? trace = status ? pending.Trace : normalized.TraceId;
            return pending with { GatewayHttpStatus = 200, UpstreamHttpStatus = normalized.StatusCode, Workflow = workflow, Trace = trace,
                Classification = normalized.StatusClassification switch { Fse2StatusClassification.Found => "FOUND", Fse2StatusClassification.NotFound => "NOT_FOUND", _ => "VALIDATED" },
                EventCount = normalized.WorkflowEvents.Count };
        }
        finally { CryptographicOperations.ZeroMemory(data); }
    }

    private static string PilotEncode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static async Task<byte[]> PilotDatasetAsync(string repository, string commit, string path, string sha256)
    {
        using HttpClient client = new(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
            { Timeout = TimeSpan.FromSeconds(30), MaxResponseContentBufferSize = 1024 * 1024 };
        string url = $"https://raw.githubusercontent.com/ministero-salute/{repository}/{commit}/{string.Join('/', path.Split('/').Select(Uri.EscapeDataString))}";
        using HttpResponseMessage response = await client.GetAsync(url).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw Failure("FSE2_PILOT_FROZEN_DATASET_UNAVAILABLE");
        byte[] bytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        if (!string.Equals(Convert.ToHexString(SHA256.HashData(bytes)), sha256, StringComparison.Ordinal))
            throw Failure("FSE2_PILOT_FROZEN_DATASET_HASH_MISMATCH");
        return bytes;
    }

    private static async Task<Fse2Request> PilotFhirRequestAsync()
    {
        byte[] bytes = await PilotDatasetAsync("it-fse-support", "4d2691dcdc051fa5a842e2cac074226bb50373d2", "doc/esempi/FHIR/RAP.json",
            "5FBEB57A5250FBFB3E6F028C834316CCA1546109CB5A2EE34A748E22C0F880DF").ConfigureAwait(false);
        return BuildPilotFhirRequest(bytes);
    }

    internal static Fse2Request BuildPilotFhirRequest(byte[] bytes)
    {
        using JsonDocument bundle = JsonDocument.Parse(bytes);
        JsonElement[] resources = bundle.RootElement.GetProperty("entry").EnumerateArray().Select(item => item.GetProperty("resource")).ToArray();
        JsonElement person = resources.Single(item => item.GetProperty("resourceType").GetString() == "Patient").GetProperty("identifier")[0];
        string identifier = person.GetProperty("value").GetString()!;
        if (!identifier.StartsWith("PROVA", StringComparison.Ordinal)) throw Failure("FSE2_PILOT_SYNTHETIC_DATASET_REQUIRED");
        string oid = person.GetProperty("system").GetString()!;
        if (!oid.StartsWith("urn:oid:", StringComparison.Ordinal)) throw Failure("FSE2_PILOT_DATASET_IDENTIFIER_INVALID");
        string code = resources.Single(item => item.GetProperty("resourceType").GetString() == "Composition").GetProperty("type").GetProperty("coding")
            .EnumerateArray().Single(item => item.GetProperty("system").GetString() == "http://loinc.org").GetProperty("code").GetString()!;
        return Fse2Request.ForCurrentSpec(Fse2Operation.ValidateFhir, bytes, "{\"mode\":\"RESOURCE\",\"activity\":\"VERIFICA\"}"u8.ToArray(), "application/json",
            clinicalClaims: Fse2ClinicalClaims.CreatePerson(identifier, oid[8..], true, $"('{code}^^2.16.840.1.113883.6.1')"));
    }

    private static async Task<Fse2Request> PilotCdaRequestAsync()
    {
        const string commit = "d937255fd7e9c079c5641c537da17fe98a2f2259";
        byte[] pdf = await PilotDatasetAsync("it-fse-accreditamento", commit,
            "GATEWAY/A1#111#DAVINCI.CARE/DaVinci Healthcare/DaVinci/3.3/FILES/PSS476.pdf",
            "129BE437228376B897B8D176DE099CA165714901DA3CB7B78EE2F9B68F4A252E").ConfigureAwait(false);
        byte[] xml = await PilotDatasetAsync("it-fse-accreditamento", commit,
            "Test Case/Validazione/Documenti XML Casi OK/8 - Casi OK Profilo Sanitario Sintetico/PSS476.xml",
            "7B54299D5AD7E87CA7D5569E98ADAC2D687D3E9432FD4D015194E733A2ADAABD").ConfigureAwait(false);
        return BuildPilotCdaRequest(pdf, xml);
    }

    internal static Fse2Request BuildPilotCdaRequest(byte[] pdf, byte[] xml)
    {
        try
        {
            using MemoryStream stream = new(xml);
            using XmlReader reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            XElement document = XElement.Load(reader);
            XNamespace ns = "urn:hl7-org:v3";
            XElement person = document.Element(ns + "recordTarget")!.Element(ns + "patientRole")!.Element(ns + "id")!;
            string identifier = person.Attribute("extension")!.Value;
            // Case 476 is selected exclusively by its frozen official test-case hashes.
            // Its synthetic fiscal identifier need not have the FHIR example's PROVA prefix.
            string code = document.Element(ns + "code")!.Attribute("code")!.Value;
            return Fse2Request.ForCurrentSpec(Fse2Operation.ValidateCda, pdf,
                "{\"healthDataFormat\":\"CDA\",\"mode\":\"ATTACHMENT\",\"activity\":\"VERIFICA\"}"u8.ToArray(), "application/pdf",
                clinicalClaims: Fse2ClinicalClaims.CreatePerson(identifier, person.Attribute("root")!.Value, true, $"('{code}^^2.16.840.1.113883.6.1')"));
        }
        finally { CryptographicOperations.ZeroMemory(xml); }
    }
}

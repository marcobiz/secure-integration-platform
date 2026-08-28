using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

/// <summary>Stable public-safe source artefact for the single OfficialTest operation in scope.</summary>
public static class Fse2OfficialTestCanonicalDefinition
{
    private const string ResourceName =
        "SecureIntegration.ConnectorPacks.Healthcare.FSE2.Definitions.fse2-officialtest-validate-cda.connector.json";

    private static readonly byte[] Bytes = Read();

    public const string ConnectorId = "fse2-officialtest-validate-cda";
    public const string ConnectorVersion = "1.0.0";
    public const string OperationId = "validate-cda";
    public const string EndpointBinding = "officialtest-gateway";
    public const string MutualTlsBinding = "a1-mtls-certificate";
    public const string SigningBinding = "s1-signing-certificate";
    public const string ApplicationId = "secure-integration-platform";
    public const string ApplicationVendor = "ApoCert S.r.l.";
    public const string ApplicationVersion = "0.1.0-alpha.1";
    public const string OfficialTestAudience =
        "https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1";
    public const string OfficialTestEndpoint = OfficialTestAudience + "/";

    /// <summary>Returns an independent copy of the exact repository bytes.</summary>
    public static byte[] GetSourceBytes() => Bytes.ToArray();

    /// <summary>SHA-256 of the exact repository bytes, including formatting and final newline.</summary>
    public static string SourceSha256 { get; } = Convert.ToHexString(SHA256.HashData(Bytes));

    private static byte[] Read()
    {
        using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException("FSE2_OFFICIALTEST_CANONICAL_DEFINITION_MISSING");
        using MemoryStream copy = new();
        stream.CopyTo(copy);
        return copy.ToArray();
    }
}

/// <summary>Logical provider reference and expected public revision supplied by the protected plan.</summary>
public sealed record Fse2OfficialTestProviderReference(
    string ProviderId,
    string ResourceId,
    string? Version,
    long CatalogRevision,
    long PublicMetadataRevision)
{
    internal ProviderResourceReference ToGatewayReference() =>
        new(ProviderId, ResourceId, ProviderResourceType.ClientCertificate, Version, PublicMetadataRevision);
}

/// <summary>Organization claims supplied only through the protected administrative plan.</summary>
public sealed record Fse2OfficialTestOrganization(
    string Identifier,
    string AssigningAuthorityOid,
    string Description,
    string DomainId);

/// <summary>Locality claims supplied only through the protected administrative plan.</summary>
public sealed record Fse2OfficialTestLocality(string Name, string AssigningAuthorityOid, string Code);

/// <summary>
/// Strict external plan. It contains logical references and expected revisions, never P12 bytes,
/// passwords, private keys, tokens, authorization headers or principal authority.
/// </summary>
public sealed record Fse2OfficialTestOperationalPlan(
    Guid EnvironmentId,
    Uri Endpoint,
    Fse2OfficialTestOrganization Organization,
    Fse2OfficialTestLocality Locality,
    Fse2OfficialTestProviderReference A1,
    Fse2OfficialTestProviderReference S1,
    long? ExpectedBindingRevision);

/// <summary>Public material resolved server-side from one exact provider-catalog revision.</summary>
public sealed record Fse2OfficialTestResolvedCertificate(
    Fse2OfficialTestProviderReference Reference,
    string SubjectPublicKeyInfoSha256,
    string SubjectCommonName,
    string CatalogChecksumSha256);

/// <summary>Public-only provider-catalog projection returned by the authenticated Admin API.</summary>
public sealed record Fse2OfficialTestProviderCatalogResource(
    string ProviderId,
    string ResourceId,
    string? Version,
    long CatalogRevision,
    long? PublicMetadataRevision,
    Guid EnvironmentId,
    string ResourceType,
    string Status,
    string ConnectorScope,
    string OperationScope,
    string CatalogChecksumSha256,
    string? SubjectPublicKeyInfoSha256,
    string? SubjectCommonName);

/// <summary>Exact, unique A1/S1 public authority resolved from the server catalog.</summary>
public sealed record Fse2OfficialTestResolvedProviderAuthority(
    Fse2OfficialTestResolvedCertificate A1,
    Fse2OfficialTestResolvedCertificate S1);

/// <summary>Redacted approval fields used by the supported provisioner's publisher gate.</summary>
public sealed record Fse2OfficialTestApprovalAuthority(
    string Status,
    string ChecksumSha256,
    Guid RequestedBy,
    Guid? ApprovedBy);

/// <summary>Explicit side-effect counters used by plan and negative qualification.</summary>
public sealed record Fse2OfficialTestSideEffectCounters(
    int WorkflowStore,
    int Signing,
    int Dns,
    int Https,
    int Transport,
    int Network)
{
    public static Fse2OfficialTestSideEffectCounters Zero { get; } = new(0, 0, 0, 0, 0, 0);
}

/// <summary>Redacted dry-run output. Endpoint and provider identifiers are represented only by digests.</summary>
public sealed record Fse2OfficialTestPlanResult(
    string ConnectorId,
    string ConnectorVersion,
    string OperationId,
    Guid EnvironmentId,
    string CanonicalSourceSha256,
    string OperationalPlanDigestSha256,
    string OperationProfileChecksumSha256,
    string EndpointDigestSha256,
    string A1ReferenceDigestSha256,
    string S1ReferenceDigestSha256,
    Fse2OfficialTestSideEffectCounters Counters);

/// <summary>Exact checksum-specific artefacts submitted through the existing Admin API.</summary>
public sealed record Fse2OfficialTestCompiledConfiguration(
    string CanonicalDefinition,
    string CanonicalDefinitionSha256,
    string OperationProfileChecksumSha256,
    string BindingConfigurationDigestSha256,
    ConnectorBindingRequest BindingRequest);

/// <summary>Stable public-safe operationalization error.</summary>
public sealed class Fse2OfficialTestOperationalizationException(string code) : Exception(code)
{
    public string SafeCode { get; } = code;
}

/// <summary>
/// Vertical-only compiler for OfficialTest validate-cda. It has no store, signing, DNS, HTTP,
/// transport, secret-value or private-key dependency. Administrative callers cannot pass runtime
/// authority through a Gateway invocation.
/// </summary>
public static class Fse2OfficialTestOperationalization
{
    private const string SchemaVersion = "1.0";
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    /// <summary>Parses the bounded external plan and rejects every undeclared field.</summary>
    public static Fse2OfficialTestOperationalPlan ParsePlan(ReadOnlyMemory<byte> utf8Json)
    {
        try
        {
            if (utf8Json.IsEmpty || utf8Json.Length > 64 * 1024)
                throw Denied("FSE2_OFFICIALTEST_PLAN_SIZE_INVALID");
            using JsonDocument document = JsonDocument.Parse(utf8Json, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 6
            });
            JsonElement root = Object(document.RootElement, "FSE2_OFFICIALTEST_PLAN_INVALID");
            ExactProperties(root,
                ["schemaVersion", "environmentId", "officialTestEndpoint", "organization", "locality", "a1", "s1", "expectedBindingRevision"]);
            if (!string.Equals(String(root, "schemaVersion", 8), SchemaVersion, StringComparison.Ordinal))
                throw Denied("FSE2_OFFICIALTEST_PLAN_SCHEMA_UNSUPPORTED");
            if (!Guid.TryParseExact(String(root, "environmentId", 36), "D", out Guid environmentId) || environmentId == Guid.Empty)
                throw Denied("FSE2_OFFICIALTEST_ENVIRONMENT_INVALID");
            if (!Uri.TryCreate(String(root, "officialTestEndpoint", 512), UriKind.Absolute, out Uri? endpoint))
                throw Denied("FSE2_OFFICIALTEST_ENDPOINT_INVALID");

            JsonElement organization = ChildObject(root, "organization");
            ExactProperties(organization, ["identifier", "assigningAuthorityOid", "description", "domainId"]);
            JsonElement locality = ChildObject(root, "locality");
            ExactProperties(locality, ["name", "assigningAuthorityOid", "code"]);
            return Validate(new(
                environmentId,
                endpoint,
                new(String(organization, "identifier", 11), String(organization, "assigningAuthorityOid", 128),
                    String(organization, "description", 128), String(organization, "domainId", 128)),
                new(String(locality, "name", 128), String(locality, "assigningAuthorityOid", 128), String(locality, "code", 32)),
                Provider(root, "a1"),
                Provider(root, "s1"),
                NullableRevision(root, "expectedBindingRevision")));
        }
        catch (Fse2OfficialTestOperationalizationException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidOperationException or JsonException or KeyNotFoundException or OverflowException)
        {
            throw Denied("FSE2_OFFICIALTEST_PLAN_INVALID");
        }
    }

    /// <summary>
    /// Produces only redacted identifiers and digests. This method has no side-effecting dependency
    /// and therefore cannot write, open P12 material, sign, resolve DNS or issue HTTP.
    /// </summary>
    public static Fse2OfficialTestPlanResult Plan(Fse2OfficialTestOperationalPlan value)
    {
        value = Validate(value);
        JsonObject extension = Extension(value);
        Fse2PublishedOrganizationProfile profile = Fse2PublishedOrganizationProfile.ParseJson(
            Encoding.UTF8.GetBytes(extension.ToJsonString()), Fse2OfficialTestCanonicalDefinition.OperationId);
        return new(
            Fse2OfficialTestCanonicalDefinition.ConnectorId,
            Fse2OfficialTestCanonicalDefinition.ConnectorVersion,
            Fse2OfficialTestCanonicalDefinition.OperationId,
            value.EnvironmentId,
            Fse2OfficialTestCanonicalDefinition.SourceSha256,
            Digest(PlanAuthority(value)),
            profile.OperationProfileChecksumSha256,
            Digest(value.Endpoint.AbsoluteUri),
            Digest(ReferenceAuthority(value.A1)),
            Digest(ReferenceAuthority(value.S1)),
            Fse2OfficialTestSideEffectCounters.Zero);
    }

    /// <summary>
    /// Compiles the exact Connector Definition after a server-side provisioner has resolved public
    /// A1/S1 metadata. No credential value or private material is accepted by this API.
    /// </summary>
    public static Fse2OfficialTestCompiledConfiguration Compile(
        Fse2OfficialTestOperationalPlan value,
        Fse2OfficialTestResolvedCertificate a1,
        Fse2OfficialTestResolvedCertificate s1)
    {
        value = Validate(value);
        ValidateResolved("A1", value.A1, a1);
        ValidateResolved("S1", value.S1, s1);
        if (FixedEquals(a1.SubjectPublicKeyInfoSha256, s1.SubjectPublicKeyInfoSha256))
            throw Denied("FSE2_OFFICIALTEST_A1_S1_NOT_DISTINCT");

        JsonNode parsed = JsonNode.Parse(Fse2OfficialTestCanonicalDefinition.GetSourceBytes(), documentOptions: new() { MaxDepth = 32 })
            ?? throw Denied("FSE2_OFFICIALTEST_CANONICAL_DEFINITION_INVALID");
        JsonObject root = parsed.AsObject();
        JsonObject operation = root["operations"]![0]!.AsObject();
        JsonObject extension = Extension(value);
        operation["extensionConfiguration"] = extension;
        Fse2PublishedOrganizationProfile profile = Fse2PublishedOrganizationProfile.ParseJson(
            Encoding.UTF8.GetBytes(extension.ToJsonString()), Fse2OfficialTestCanonicalDefinition.OperationId);

        JsonArray slots = operation["authorizedCapabilities"]!["signingSlots"]!.AsArray();
        int signingRevision = CheckedRevision(value.S1.PublicMetadataRevision);
        foreach (JsonNode? slotNode in slots)
        {
            JsonObject slot = slotNode!.AsObject();
            JsonObject signing = slot["signing"]!.AsObject();
            string slotName = slot["slot"]!.GetValue<string>();
            signing["revision"] = signingRevision;
            signing["publicKeySpkiSha256"] = s1.SubjectPublicKeyInfoSha256;
            signing["issuer"] = (slotName == Fse2PublishedOrganizationProfile.AuthorizationSigningSlotName ? "auth:" : "integrity:") + s1.SubjectCommonName;
            signing["audience"] = profile.Audience;
            signing["fixedSubject"] = profile.SubjectCx;
        }
        JsonObject transport = operation["authorizedCapabilities"]!["restrictedTransport"]!.AsObject();
        transport["revision"] = CheckedRevision(value.A1.PublicMetadataRevision);
        transport["clientCertificateSpkiSha256"] = a1.SubjectPublicKeyInfoSha256;

        using JsonDocument compiledDocument = JsonDocument.Parse(root.ToJsonString(), new JsonDocumentOptions { MaxDepth = 32 });
        string canonical = ConnectorCanonicalJson.Canonicalize(compiledDocument.RootElement);
        ValidateCompiledDefinition(canonical, profile);

        Dictionary<string, ProviderResourceReference> certificates = new(StringComparer.Ordinal)
        {
            [Fse2OfficialTestCanonicalDefinition.MutualTlsBinding] = value.A1.ToGatewayReference(),
            [Fse2OfficialTestCanonicalDefinition.SigningBinding] = value.S1.ToGatewayReference()
        };
        ConnectorBindingRequest binding = new(
            value.EnvironmentId,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [Fse2OfficialTestCanonicalDefinition.EndpointBinding] = value.Endpoint.AbsoluteUri
            },
            new Dictionary<string, ProviderResourceReference>(StringComparer.Ordinal),
            value.ExpectedBindingRevision,
            certificates,
            Fse2OfficialTestCanonicalDefinition.ConnectorVersion);
        string bindingDigest = Digest(new
        {
            plan = PlanAuthority(value),
            a1CatalogChecksumSha256 = a1.CatalogChecksumSha256,
            s1CatalogChecksumSha256 = s1.CatalogChecksumSha256,
            a1SpkiSha256 = a1.SubjectPublicKeyInfoSha256,
            s1SpkiSha256 = s1.SubjectPublicKeyInfoSha256
        });
        return new(canonical, ConnectorCanonicalJson.Checksum(canonical), profile.OperationProfileChecksumSha256, bindingDigest, binding);
    }

    /// <summary>
    /// Resolves the exact A1/S1 public identities from an authenticated Admin API catalog page.
    /// External files are not accepted as authority and no private material is represented here.
    /// </summary>
    public static Fse2OfficialTestResolvedProviderAuthority ResolveProviderAuthority(
        Fse2OfficialTestOperationalPlan value,
        IEnumerable<Fse2OfficialTestProviderCatalogResource> resources)
    {
        value = Validate(value);
        ArgumentNullException.ThrowIfNull(resources);
        Fse2OfficialTestProviderCatalogResource[] snapshot = resources.Take(1001).ToArray();
        if (snapshot.Length > 1000) throw Denied("FSE2_OFFICIALTEST_PROVIDER_CATALOG_TOO_LARGE");
        return new(
            ResolveProviderCertificate("A1", value, value.A1, snapshot),
            ResolveProviderCertificate("S1", value, value.S1, snapshot));
    }

    /// <summary>
    /// Requires the caller to be the distinct approver of an approval that remains current.
    /// Binding changes are atomically represented by the server as Invalidated approval status;
    /// this predicate deliberately consumes that single server-owned state machine.
    /// </summary>
    public static bool IsCurrentPublisher(
        Guid principalId,
        string canonicalDefinitionSha256,
        IEnumerable<Fse2OfficialTestApprovalAuthority> approvals)
    {
        if (principalId == Guid.Empty || !IsSha256(canonicalDefinitionSha256)) return false;
        ArgumentNullException.ThrowIfNull(approvals);
        return approvals.Any(value =>
            string.Equals(value.Status, "Approved", StringComparison.Ordinal) &&
            FixedEquals(value.ChecksumSha256, canonicalDefinitionSha256) &&
            value.ApprovedBy == principalId &&
            value.RequestedBy != principalId);
    }

    /// <summary>Verifies an Admin read-back against the exact locally compiled authority.</summary>
    public static void VerifyDefinitionReadback(
        ReadOnlyMemory<byte> utf8Json,
        Fse2OfficialTestCompiledConfiguration expected)
    {
        ArgumentNullException.ThrowIfNull(expected);
        try
        {
            if (utf8Json.IsEmpty || utf8Json.Length > 1024 * 1024)
                throw Denied("FSE2_OFFICIALTEST_DEFINITION_READBACK_INVALID");
            using JsonDocument definition = JsonDocument.Parse(utf8Json, new JsonDocumentOptions { MaxDepth = 32 });
            string canonical = ConnectorCanonicalJson.Canonicalize(definition.RootElement);
            if (!string.Equals(canonical, expected.CanonicalDefinition, StringComparison.Ordinal) ||
                !string.Equals(ConnectorCanonicalJson.Checksum(canonical), expected.CanonicalDefinitionSha256, StringComparison.Ordinal))
                throw Denied("FSE2_OFFICIALTEST_DEFINITION_READBACK_DRIFT");
            JsonElement operation = definition.RootElement.GetProperty("operations").EnumerateArray().Single();
            Fse2PublishedOrganizationProfile profile = Fse2PublishedOrganizationProfile.ParseJson(
                Encoding.UTF8.GetBytes(operation.GetProperty("extensionConfiguration").GetRawText()),
                Fse2OfficialTestCanonicalDefinition.OperationId);
            if (!string.Equals(profile.OperationProfileChecksumSha256, expected.OperationProfileChecksumSha256, StringComparison.Ordinal))
                throw Denied("FSE2_OFFICIALTEST_OPERATION_PROFILE_DRIFT");
        }
        catch (Fse2OfficialTestOperationalizationException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or JsonException)
        {
            throw Denied("FSE2_OFFICIALTEST_DEFINITION_READBACK_INVALID");
        }
    }

    private static Fse2OfficialTestOperationalPlan Validate(Fse2OfficialTestOperationalPlan value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.EnvironmentId == Guid.Empty) throw Denied("FSE2_OFFICIALTEST_ENVIRONMENT_INVALID");
        if (!string.Equals(value.Endpoint.AbsoluteUri, Fse2OfficialTestCanonicalDefinition.OfficialTestEndpoint, StringComparison.Ordinal))
            throw Denied("FSE2_OFFICIALTEST_ENDPOINT_DENIED");
        Fse2OperationCatalog.ValidateBaseEndpoint(value.Endpoint);
        ValidateProvider(value.A1);
        ValidateProvider(value.S1);
        if (SameReference(value.A1, value.S1)) throw Denied("FSE2_OFFICIALTEST_A1_S1_NOT_DISTINCT");
        if (value.ExpectedBindingRevision is <= 0) throw Denied("FSE2_OFFICIALTEST_BINDING_REVISION_INVALID");
        _ = Fse2PublishedOrganizationProfile.ParseJson(
            Encoding.UTF8.GetBytes(Extension(value).ToJsonString()), Fse2OfficialTestCanonicalDefinition.OperationId);
        return value;
    }

    private static JsonObject Extension(Fse2OfficialTestOperationalPlan value) => new()
    {
        ["profile"] = "fse2-organization-v1",
        ["environmentClass"] = "officialTest",
        ["activity"] = "VERIFICA",
        ["acceptMediaType"] = "application/json",
        ["organizationIdentifier"] = value.Organization.Identifier,
        ["organizationAssigningAuthorityOid"] = value.Organization.AssigningAuthorityOid,
        ["organizationDescription"] = value.Organization.Description,
        ["organizationDomainId"] = value.Organization.DomainId,
        ["localityName"] = value.Locality.Name,
        ["localityAssigningAuthorityOid"] = value.Locality.AssigningAuthorityOid,
        ["localityCode"] = value.Locality.Code,
        ["subjectRole"] = "DAP",
        ["applicationId"] = Fse2OfficialTestCanonicalDefinition.ApplicationId,
        ["applicationVendor"] = Fse2OfficialTestCanonicalDefinition.ApplicationVendor,
        ["applicationVersion"] = Fse2OfficialTestCanonicalDefinition.ApplicationVersion,
        ["maximumDocumentBytes"] = 1048576
    };

    private static Fse2OfficialTestResolvedCertificate ResolveProviderCertificate(
        string role,
        Fse2OfficialTestOperationalPlan plan,
        Fse2OfficialTestProviderReference expected,
        IReadOnlyList<Fse2OfficialTestProviderCatalogResource> snapshot)
    {
        Fse2OfficialTestProviderCatalogResource[] logical = snapshot.Where(value =>
            string.Equals(value.ProviderId, expected.ProviderId, StringComparison.Ordinal) &&
            string.Equals(value.ResourceId, expected.ResourceId, StringComparison.Ordinal)).ToArray();
        if (logical.Length == 0) throw Denied($"FSE2_OFFICIALTEST_{role}_PROVIDER_AUTHORITY_MISSING");

        Fse2OfficialTestProviderCatalogResource[] exact = logical.Where(value =>
            string.Equals(value.Version, expected.Version, StringComparison.Ordinal) &&
            value.CatalogRevision == expected.CatalogRevision &&
            value.PublicMetadataRevision == expected.PublicMetadataRevision &&
            value.EnvironmentId == plan.EnvironmentId).ToArray();
        if (exact.Length == 0) throw Denied($"FSE2_OFFICIALTEST_{role}_PROVIDER_AUTHORITY_MISMATCH");
        if (exact.Length != 1) throw Denied($"FSE2_OFFICIALTEST_{role}_PROVIDER_AUTHORITY_AMBIGUOUS");

        Fse2OfficialTestProviderCatalogResource selected = exact[0];
        if (!string.Equals(selected.ResourceType, "ClientCertificate", StringComparison.Ordinal) ||
            !string.Equals(selected.ConnectorScope, Fse2OfficialTestCanonicalDefinition.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(selected.OperationScope, Fse2OfficialTestCanonicalDefinition.OperationId, StringComparison.Ordinal))
            throw Denied($"FSE2_OFFICIALTEST_{role}_PROVIDER_AUTHORITY_MISMATCH");
        if (!string.Equals(selected.Status, "Active", StringComparison.Ordinal))
            throw Denied($"FSE2_OFFICIALTEST_{role}_PROVIDER_AUTHORITY_INACTIVE");
        if (!IsSha256(selected.CatalogChecksumSha256) || selected.CatalogChecksumSha256.All(character => character == '0') ||
            selected.SubjectPublicKeyInfoSha256 is null || !IsSha256(selected.SubjectPublicKeyInfoSha256) || selected.SubjectPublicKeyInfoSha256.All(character => character == '0') ||
            string.IsNullOrWhiteSpace(selected.SubjectCommonName) || selected.SubjectCommonName.Length > 128 ||
            selected.SubjectCommonName != selected.SubjectCommonName.Trim() ||
            selected.SubjectCommonName.Any(character => char.IsControl(character) || character is '^' or '&'))
            throw Denied($"FSE2_OFFICIALTEST_{role}_PROVIDER_PUBLIC_METADATA_INVALID");
        return new(expected, selected.SubjectPublicKeyInfoSha256, selected.SubjectCommonName, selected.CatalogChecksumSha256);
    }

    private static void ValidateCompiledDefinition(string canonical, Fse2PublishedOrganizationProfile profile)
    {
        using JsonDocument document = JsonDocument.Parse(canonical);
        JsonElement root = document.RootElement;
        if (!string.Equals(root.GetProperty("connectorId").GetString(), Fse2OfficialTestCanonicalDefinition.ConnectorId, StringComparison.Ordinal) ||
            !string.Equals(root.GetProperty("version").GetString(), Fse2OfficialTestCanonicalDefinition.ConnectorVersion, StringComparison.Ordinal))
            throw Denied("FSE2_OFFICIALTEST_DEFINITION_IDENTITY_DRIFT");
        JsonElement[] operations = root.GetProperty("operations").EnumerateArray().ToArray();
        if (operations.Length != 1 || !string.Equals(operations[0].GetProperty("operationId").GetString(), Fse2OfficialTestCanonicalDefinition.OperationId, StringComparison.Ordinal))
            throw Denied("FSE2_OFFICIALTEST_OPERATION_SCOPE_DRIFT");
        JsonElement operation = operations[0];
        JsonElement capabilities = operation.GetProperty("authorizedCapabilities");
        JsonElement[] slots = capabilities.GetProperty("signingSlots").EnumerateArray().ToArray();
        if (slots.Length != 2 || slots.Any(slot => !string.Equals(slot.GetProperty("signing").GetProperty("keyBinding").GetString(), Fse2OfficialTestCanonicalDefinition.SigningBinding, StringComparison.Ordinal)) ||
            !string.Equals(operation.GetProperty("authentication").GetProperty("certificateBinding").GetString(), Fse2OfficialTestCanonicalDefinition.MutualTlsBinding, StringComparison.Ordinal) ||
            !string.Equals(operation.GetProperty("pathResolution").GetString(), "appendToBasePath", StringComparison.Ordinal) ||
            operation.GetProperty("maximumRetries").GetInt32() != 0 || operation.GetProperty("redirectPolicy").GetString() != "deny" ||
            operation.GetProperty("allowedClientHeaders").GetArrayLength() != 0 || profile.Operation.RequiresAttachmentHash)
            throw Denied("FSE2_OFFICIALTEST_ACTIVATION_COMPOSITION_DRIFT");
        JsonElement integrity = slots.Single(slot => slot.GetProperty("slot").GetString() == Fse2PublishedOrganizationProfile.IntegritySigningSlotName);
        if (integrity.GetProperty("signing").GetProperty("allowedClaims").EnumerateArray().Any(value => value.GetString() == "attachment_hash"))
            throw Denied("FSE2_OFFICIALTEST_ATTACHMENT_HASH_PRESENT");
    }

    private static Fse2OfficialTestProviderReference Provider(JsonElement root, string name)
    {
        JsonElement value = ChildObject(root, name);
        ExactProperties(value, ["providerId", "resourceId", "version", "catalogRevision", "publicMetadataRevision"]);
        return new(
            String(value, "providerId", 128),
            String(value, "resourceId", 128),
            NullableString(value, "version", 128),
            Revision(value, "catalogRevision"),
            Revision(value, "publicMetadataRevision"));
    }

    private static void ValidateProvider(Fse2OfficialTestProviderReference value)
    {
        ArgumentNullException.ThrowIfNull(value);
        ProviderResourceReferenceValidator.Validate(value.ToGatewayReference());
        if (value.CatalogRevision < 1 || value.PublicMetadataRevision < 1 || value.PublicMetadataRevision > int.MaxValue)
            throw Denied("FSE2_OFFICIALTEST_PROVIDER_REVISION_INVALID");
    }

    private static void ValidateResolved(string role, Fse2OfficialTestProviderReference expected, Fse2OfficialTestResolvedCertificate actual)
    {
        ArgumentNullException.ThrowIfNull(actual);
        if (actual.Reference != expected)
            throw Denied($"FSE2_OFFICIALTEST_{role}_REVISION_DRIFT");
        if (!IsSha256(actual.SubjectPublicKeyInfoSha256) || actual.SubjectPublicKeyInfoSha256.All(character => character == '0') ||
            !IsSha256(actual.CatalogChecksumSha256) || string.IsNullOrWhiteSpace(actual.SubjectCommonName) ||
            actual.SubjectCommonName.Length > 128 || actual.SubjectCommonName != actual.SubjectCommonName.Trim() ||
            actual.SubjectCommonName.Any(character => char.IsControl(character) || character is '^' or '&'))
            throw Denied($"FSE2_OFFICIALTEST_{role}_PUBLIC_METADATA_INVALID");
    }

    private static object PlanAuthority(Fse2OfficialTestOperationalPlan value) => new
    {
        schemaVersion = SchemaVersion,
        environmentId = value.EnvironmentId.ToString("D"),
        endpoint = value.Endpoint.AbsoluteUri,
        organization = value.Organization,
        locality = value.Locality,
        a1 = ReferenceAuthority(value.A1),
        s1 = ReferenceAuthority(value.S1),
        expectedBindingRevision = value.ExpectedBindingRevision
    };

    private static object ReferenceAuthority(Fse2OfficialTestProviderReference value) => new
    {
        value.ProviderId,
        value.ResourceId,
        value.Version,
        value.CatalogRevision,
        value.PublicMetadataRevision
    };

    private static bool SameReference(Fse2OfficialTestProviderReference left, Fse2OfficialTestProviderReference right) =>
        string.Equals(left.ProviderId, right.ProviderId, StringComparison.Ordinal) &&
        string.Equals(left.ResourceId, right.ResourceId, StringComparison.Ordinal) &&
        string.Equals(left.Version, right.Version, StringComparison.Ordinal);

    private static string Digest<T>(T value)
    {
        byte[] serialized = value is string text ? Encoding.UTF8.GetBytes(text) : JsonSerializer.SerializeToUtf8Bytes(value, WebJson);
        return Convert.ToHexString(SHA256.HashData(serialized));
    }

    private static bool FixedEquals(string left, string right)
    {
        if (!IsSha256(left) || !IsSha256(right)) return false;
        return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(left), Convert.FromHexString(right));
    }

    private static bool IsSha256(string value) => value.Length == 64 && value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static int CheckedRevision(long value) => value is >= 1 and <= int.MaxValue ? (int)value : throw Denied("FSE2_OFFICIALTEST_PROVIDER_REVISION_INVALID");

    private static JsonElement Object(JsonElement value, string error) =>
        value.ValueKind == JsonValueKind.Object ? value : throw Denied(error);

    private static JsonElement ChildObject(JsonElement root, string name) =>
        Object(root.GetProperty(name), "FSE2_OFFICIALTEST_PLAN_INVALID");

    private static void ExactProperties(JsonElement value, IReadOnlyCollection<string> expected)
    {
        HashSet<string> names = new(StringComparer.Ordinal);
        foreach (JsonProperty property in value.EnumerateObject())
            if (!names.Add(property.Name)) throw Denied("FSE2_OFFICIALTEST_PLAN_DUPLICATE_PROPERTY");
        if (!names.SetEquals(expected)) throw Denied("FSE2_OFFICIALTEST_PLAN_PROPERTY_DENIED");
    }

    private static string String(JsonElement root, string name, int maximumLength)
    {
        JsonElement value = root.GetProperty(name);
        if (value.ValueKind != JsonValueKind.String) throw Denied("FSE2_OFFICIALTEST_PLAN_VALUE_INVALID");
        string result = value.GetString()!;
        if (string.IsNullOrWhiteSpace(result) || result.Length > maximumLength || result != result.Trim() || result.Any(char.IsControl))
            throw Denied("FSE2_OFFICIALTEST_PLAN_VALUE_INVALID");
        return result;
    }

    private static string? NullableString(JsonElement root, string name, int maximumLength)
    {
        JsonElement value = root.GetProperty(name);
        return value.ValueKind == JsonValueKind.Null ? null : String(root, name, maximumLength);
    }

    private static long Revision(JsonElement root, string name)
    {
        JsonElement value = root.GetProperty(name);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out long revision) || revision < 1)
            throw Denied("FSE2_OFFICIALTEST_PROVIDER_REVISION_INVALID");
        return revision;
    }

    private static long? NullableRevision(JsonElement root, string name)
    {
        JsonElement value = root.GetProperty(name);
        if (value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out long revision) || revision < 1)
            throw Denied("FSE2_OFFICIALTEST_BINDING_REVISION_INVALID");
        return revision;
    }

    private static Fse2OfficialTestOperationalizationException Denied(string code) => new(code);
}

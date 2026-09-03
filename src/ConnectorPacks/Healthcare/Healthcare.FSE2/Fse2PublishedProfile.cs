using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

/// <summary>
/// Immutable FSE2 Organization projection parsed only from the initially authorized Published
/// extension configuration. Operation routing remains owned by the exact Core authorization context.
/// </summary>
public sealed class Fse2PublishedOrganizationProfile
{
    public const int TokenLifetimeSeconds = 300;
    public const string AuthorizationSigningSlotName = "authorization";
    public const string IntegritySigningSlotName = "integrity";
    public const string IntegrityHeaderName = "FSE-JWT-Signature";
    public const string ValidateCdaActivity = "VERIFICA";
    public const string ValidateCdaPublicationActivity = "VALIDATION";
    public const string OfficialAcceptMediaType = "application/json";

    private static readonly HashSet<string> AllowedProperties = new(StringComparer.Ordinal)
    {
        "profile", "environmentClass", "organizationIdentifier", "organizationAssigningAuthorityOid",
        "organizationDescription", "organizationDomainId", "localityName", "localityAssigningAuthorityOid",
        "localityCode", "subjectRole", "applicationId", "applicationVendor", "applicationVersion",
        "maximumDocumentBytes", "activity", "acceptMediaType"
    };
    private static readonly HashSet<string> RequiredProperties = AllowedProperties
        .Where(value => value is not ("activity" or "acceptMediaType"))
        .ToHashSet(StringComparer.Ordinal);

    private Fse2PublishedOrganizationProfile() { }

    public required Fse2EnvironmentClass EnvironmentClass { get; init; }
    public required string OrganizationIdentifier { get; init; }
    public required string OrganizationAssigningAuthorityOid { get; init; }
    public required string OrganizationDescription { get; init; }
    public required string OrganizationDomainId { get; init; }
    public required string LocalityName { get; init; }
    public required string LocalityAssigningAuthorityOid { get; init; }
    public required string LocalityCode { get; init; }
    public required string Locality { get; init; }
    public required string SubjectRole { get; init; }
    public required string SubjectCx { get; init; }
    public required string ApplicationId { get; init; }
    public required string ApplicationVendor { get; init; }
    public required string ApplicationVersion { get; init; }
    public string? Activity { get; init; }
    public string? AcceptMediaType { get; init; }
    public required Fse2OperationDescriptor Operation { get; init; }
    public ConnectorSigningSlotKey AuthorizationSigningSlot { get; } = ConnectorSigningSlotKey.Parse(AuthorizationSigningSlotName);
    public ConnectorSigningSlotKey IntegritySigningSlot { get; } = ConnectorSigningSlotKey.Parse(IntegritySigningSlotName);
    public required int MaximumDocumentBytes { get; init; }
    public required string SharedOrganizationProfileChecksumSha256 { get; init; }
    public required string OperationProfileChecksumSha256 { get; init; }

    public string Audience => EnvironmentClass switch
    {
        Fse2EnvironmentClass.Synthetic => "https://fse2.synthetic.test/gateway/v1",
        Fse2EnvironmentClass.OfficialTest => "https://modipa-val.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1",
        Fse2EnvironmentClass.Production => "https://modipa.fse.salute.gov.it/govway/rest/in/FSE/gateway/v1",
        _ => throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_ENVIRONMENT_DENIED")
    };

    /// <summary>Parses a defensive copy for the exact operation already authorized by Core.</summary>
    public static Fse2PublishedOrganizationProfile Parse(
        AuthorizedPublishedExtensionConfiguration configuration,
        string operationId)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        using Stream stream = configuration.OpenJsonStream();
        using MemoryStream copy = new();
        stream.CopyTo(copy);
        return ParseJson(copy.ToArray(), operationId);
    }

    /// <summary>Validates connector configuration without accepting operation authority from JSON.</summary>
    public static Fse2PublishedOrganizationProfile ParseJson(ReadOnlyMemory<byte> utf8Json, string operationId)
    {
        try
        {
            Fse2OperationDescriptor operation = Fse2OperationCatalog.Get(operationId);
            using JsonDocument document = JsonDocument.Parse(utf8Json, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 6
            });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new JsonException();
            ValidateProperties(root);

            if (!string.Equals(RequiredString(root, "profile", 64), "fse2-organization-v1", StringComparison.Ordinal))
                throw new JsonException();
            Fse2EnvironmentClass environment = RequiredString(root, "environmentClass", 32) switch
            {
                "synthetic" => Fse2EnvironmentClass.Synthetic,
                "officialTest" => Fse2EnvironmentClass.OfficialTest,
                "production" => Fse2EnvironmentClass.Production,
                _ => throw new JsonException()
            };
            if (environment == Fse2EnvironmentClass.Production &&
                operation.Availability != Fse2OperationAvailability.ProductionAvailable)
                throw new JsonException();

            string organizationIdentifier = Fse2Validation.ValidateItalianSubjectIdentifier(RequiredString(root, "organizationIdentifier", 16));
            string organizationAuthority = Fse2Validation.ValidateOid(RequiredString(root, "organizationAssigningAuthorityOid", 128));
            string organizationDescription = Fse2Validation.ValidateOrganizationName(RequiredString(root, "organizationDescription", 128));
            string organizationDomainId = SafeIdentifier(RequiredString(root, "organizationDomainId", 128));
            string localityName = RequiredString(root, "localityName", 128);
            string localityAuthority = Fse2Validation.ValidateOid(RequiredString(root, "localityAssigningAuthorityOid", 128));
            string localityCode = RequiredString(root, "localityCode", 32);
            string locality = Fse2IheFormatter.FormatLocalityXon(localityName, localityAuthority, localityCode);
            string role = RequiredString(root, "subjectRole", 16);
            if (!string.Equals(role, "DAP", StringComparison.Ordinal)) throw new JsonException();
            int maximumDocumentBytes = root.GetProperty("maximumDocumentBytes").GetInt32();
            if (maximumDocumentBytes is < 1 or > 15 * 1024 * 1024) throw new JsonException();
            string? activity = OptionalString(root, "activity", 32);
            string? acceptMediaType = OptionalString(root, "acceptMediaType", 128);
            if (activity is not null && !IsSupportedValidateCdaActivity(activity) ||
                acceptMediaType is not null && !string.Equals(acceptMediaType, OfficialAcceptMediaType, StringComparison.Ordinal))
                throw new JsonException();

            Fse2PublishedOrganizationProfile profile = new()
            {
                EnvironmentClass = environment,
                OrganizationIdentifier = organizationIdentifier,
                OrganizationAssigningAuthorityOid = organizationAuthority,
                OrganizationDescription = organizationDescription,
                OrganizationDomainId = organizationDomainId,
                LocalityName = localityName,
                LocalityAssigningAuthorityOid = localityAuthority,
                LocalityCode = localityCode,
                Locality = locality,
                SubjectRole = role,
                SubjectCx = Fse2IheFormatter.FormatSubjectCx(organizationIdentifier, organizationAuthority),
                ApplicationId = SafeApplicationValue(RequiredString(root, "applicationId", 128)),
                ApplicationVendor = SafeApplicationValue(RequiredString(root, "applicationVendor", 128)),
                ApplicationVersion = SafeApplicationValue(RequiredString(root, "applicationVersion", 128)),
                Activity = activity,
                AcceptMediaType = acceptMediaType,
                Operation = operation,
                MaximumDocumentBytes = maximumDocumentBytes,
                SharedOrganizationProfileChecksumSha256 = string.Empty,
                OperationProfileChecksumSha256 = string.Empty
            };
            string sharedChecksum = Hash(profile.WriteSharedProfile);
            return new()
            {
                EnvironmentClass = profile.EnvironmentClass,
                OrganizationIdentifier = profile.OrganizationIdentifier,
                OrganizationAssigningAuthorityOid = profile.OrganizationAssigningAuthorityOid,
                OrganizationDescription = profile.OrganizationDescription,
                OrganizationDomainId = profile.OrganizationDomainId,
                LocalityName = profile.LocalityName,
                LocalityAssigningAuthorityOid = profile.LocalityAssigningAuthorityOid,
                LocalityCode = profile.LocalityCode,
                Locality = profile.Locality,
                SubjectRole = profile.SubjectRole,
                SubjectCx = profile.SubjectCx,
                ApplicationId = profile.ApplicationId,
                ApplicationVendor = profile.ApplicationVendor,
                ApplicationVersion = profile.ApplicationVersion,
                Activity = profile.Activity,
                AcceptMediaType = profile.AcceptMediaType,
                Operation = operation,
                MaximumDocumentBytes = profile.MaximumDocumentBytes,
                SharedOrganizationProfileChecksumSha256 = sharedChecksum,
                OperationProfileChecksumSha256 = Hash(writer => profile.WriteOperationProfile(writer, sharedChecksum, operation))
            };
        }
        catch (Fse2ConnectorException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidOperationException or JsonException or KeyNotFoundException or OverflowException)
        {
            throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_PUBLISHED_PROFILE_INVALID");
        }
    }

    public string CalculateOperationProfileChecksum(Fse2OperationDescriptor operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        return Hash(writer => WriteOperationProfile(writer, SharedOrganizationProfileChecksumSha256, operation));
    }

    private void WriteSharedProfile(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        writer.WriteString("profile", "fse2-organization-v1");
        writer.WriteString("environmentClass", EnvironmentClass.ToString());
        writer.WriteString("organizationIdentifier", OrganizationIdentifier);
        writer.WriteString("organizationAssigningAuthorityOid", OrganizationAssigningAuthorityOid);
        writer.WriteString("organizationDescription", OrganizationDescription);
        writer.WriteString("organizationDomainId", OrganizationDomainId);
        writer.WriteString("localityName", LocalityName);
        writer.WriteString("localityAssigningAuthorityOid", LocalityAssigningAuthorityOid);
        writer.WriteString("localityCode", LocalityCode);
        writer.WriteString("subjectRole", SubjectRole);
        writer.WriteString("applicationId", ApplicationId);
        writer.WriteString("applicationVendor", ApplicationVendor);
        writer.WriteString("applicationVersion", ApplicationVersion);
        if (Activity is not null) writer.WriteString("activity", Activity);
        if (AcceptMediaType is not null) writer.WriteString("acceptMediaType", AcceptMediaType);
        writer.WriteNumber("maximumDocumentBytes", MaximumDocumentBytes);
        writer.WriteEndObject();
    }

    private void WriteOperationProfile(Utf8JsonWriter writer, string sharedChecksum, Fse2OperationDescriptor operation)
    {
        writer.WriteStartObject();
        writer.WriteString("sharedOrganizationProfileChecksumSha256", sharedChecksum);
        writer.WriteString("operationId", operation.OperationId);
        writer.WriteString("method", operation.Method.Method);
        writer.WriteString("pathTemplate", operation.PathTemplate);
        writer.WriteString("bodyMode", operation.HasDocument || operation.HasJsonBody ? "required" : "none");
        writer.WriteString("pathParameterName", operation.PathParameterName);
        writer.WriteString("availability", operation.Availability.ToString());
        writer.WriteBoolean("requiresAttachmentHash", operation.RequiresAttachmentHash);
        writer.WriteString("activity", Activity);
        writer.WriteString("acceptMediaType", AcceptMediaType);
        writer.WriteEndObject();
    }

    private static string Hash(Action<Utf8JsonWriter> write)
    {
        using MemoryStream canonical = new();
        using (Utf8JsonWriter writer = new(canonical)) write(writer);
        return Convert.ToHexStringLower(SHA256.HashData(canonical.ToArray()));
    }

    private static void ValidateProperties(JsonElement root)
    {
        HashSet<string> observed = new(StringComparer.Ordinal);
        foreach (JsonProperty property in root.EnumerateObject())
            if (!AllowedProperties.Contains(property.Name) || !observed.Add(property.Name)) throw new JsonException();
        if (RequiredProperties.Any(value => !observed.Contains(value))) throw new JsonException();
    }

    private static string RequiredString(JsonElement root, string name, int maximumLength)
    {
        JsonElement property = root.GetProperty(name);
        if (property.ValueKind != JsonValueKind.String) throw new JsonException();
        string value = property.GetString()!;
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value != value.Trim() || value.Any(char.IsControl) ||
            !value.IsNormalized(NormalizationForm.FormC))
            throw new JsonException();
        return value;
    }

    private static string? OptionalString(JsonElement root, string name, int maximumLength) =>
        root.TryGetProperty(name, out JsonElement value) ? RequiredString(root, name, maximumLength) : null;

    private static string SafeIdentifier(string value) => Fse2Validation.IsSafeIdentifier(value) ? value : throw new JsonException();

    internal static bool IsSupportedValidateCdaActivity(string value) =>
        string.Equals(value, ValidateCdaActivity, StringComparison.Ordinal) ||
        string.Equals(value, ValidateCdaPublicationActivity, StringComparison.Ordinal);

    private static string SafeApplicationValue(string value) =>
        !value.Any(character => character is '^' or '&') ? value : throw new JsonException();
}

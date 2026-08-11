using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

/// <summary>
/// Immutable FSE2 Organization projection parsed only from the initially authorized Published
/// extension configuration. It is configuration, not a second dispatch authority.
/// </summary>
public sealed class Fse2PublishedOrganizationProfile
{
    private static readonly HashSet<string> AllowedProperties = new(StringComparer.Ordinal)
    {
        "profile", "environmentClass", "organizationIdentifier", "organizationAssigningAuthorityOid",
        "organizationDescription", "organizationDomainId", "localityName", "localityAssigningAuthorityOid",
        "localityCode", "subjectRole", "applicationId", "applicationVendor", "applicationVersion",
        "operationId", "method", "relativePath", "requestContentType", "resourceIdentifier",
        "multipartBoundary", "authorizationSigningSlot", "integritySigningSlot", "maximumDocumentBytes"
    };

    private Fse2PublishedOrganizationProfile() { }

    public required Fse2EnvironmentClass EnvironmentClass { get; init; }
    public required string OrganizationIdentifier { get; init; }
    public required string OrganizationAssigningAuthorityOid { get; init; }
    public required string OrganizationDescription { get; init; }
    public required string OrganizationDomainId { get; init; }
    public required string Locality { get; init; }
    public required string SubjectRole { get; init; }
    public required string SubjectCx { get; init; }
    public required string ApplicationId { get; init; }
    public required string ApplicationVendor { get; init; }
    public required string ApplicationVersion { get; init; }
    public required Fse2OperationDescriptor Operation { get; init; }
    public required string RequestContentType { get; init; }
    public string? ResourceIdentifier { get; init; }
    public string? MultipartBoundary { get; init; }
    public required ConnectorSigningSlotKey AuthorizationSigningSlot { get; init; }
    public required ConnectorSigningSlotKey IntegritySigningSlot { get; init; }
    public required int MaximumDocumentBytes { get; init; }
    public required string ProfileChecksumSha256 { get; init; }

    /// <summary>Parses a defensive copy of the exact Published extension JSON.</summary>
    public static Fse2PublishedOrganizationProfile Parse(AuthorizedPublishedExtensionConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        using Stream stream = configuration.OpenJsonStream();
        using MemoryStream copy = new();
        stream.CopyTo(copy);
        return ParseJson(copy.ToArray());
    }

    /// <summary>Validates FSE2-specific configuration without granting any runtime authority.</summary>
    public static Fse2PublishedOrganizationProfile ParseJson(ReadOnlyMemory<byte> utf8Json)
    {
        try
        {
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
            string organizationIdentifier = Fse2Validation.ValidateItalianVatNumber(RequiredString(root, "organizationIdentifier", 11));
            string organizationAuthority = Fse2Validation.ValidateOid(RequiredString(root, "organizationAssigningAuthorityOid", 128));
            string organizationDescription = Fse2Validation.ValidateOrganizationName(RequiredString(root, "organizationDescription", 128));
            string organizationDomainId = SafeIdentifier(RequiredString(root, "organizationDomainId", 128));
            string locality = Fse2IheFormatter.FormatLocalityXon(
                RequiredString(root, "localityName", 128),
                RequiredString(root, "localityAssigningAuthorityOid", 128),
                RequiredString(root, "localityCode", 32));
            string role = RequiredString(root, "subjectRole", 16);
            if (!string.Equals(role, "DAP", StringComparison.Ordinal)) throw new JsonException();

            Fse2OperationDescriptor operation = Fse2OperationCatalog.Get(RequiredString(root, "operationId", 64));
            if (!string.Equals(operation.Method.Method, RequiredString(root, "method", 16), StringComparison.Ordinal) ||
                !string.Equals(operation.RelativePath, RequiredString(root, "relativePath", 512), StringComparison.Ordinal))
                throw new JsonException();
            if (environment == Fse2EnvironmentClass.Production && operation.Availability != Fse2OperationAvailability.ProductionAvailable)
                throw new JsonException();

            string requestContentType = RequiredString(root, "requestContentType", 256);
            string? resourceIdentifier = OptionalString(root, "resourceIdentifier", 512);
            if (operation.RequiresResourceIdentifier != (resourceIdentifier is not null)) throw new JsonException();
            if (resourceIdentifier is not null) resourceIdentifier = operation.Operation switch
            {
                Fse2Operation.GetStatusByWorkflow => Fse2Validation.ValidateWorkflowId(resourceIdentifier),
                Fse2Operation.GetStatusByTrace => Fse2Validation.ValidateTraceId(resourceIdentifier),
                _ => Fse2Validation.ValidateDocumentId(resourceIdentifier)
            };

            string? boundary = OptionalString(root, "multipartBoundary", 64);
            if (operation.HasDocument)
            {
                if (!IsSafeBoundary(boundary) ||
                    !string.Equals(requestContentType, $"multipart/form-data; boundary={boundary}", StringComparison.Ordinal))
                    throw new JsonException();
            }
            else if (boundary is not null || !string.Equals(requestContentType, "application/json", StringComparison.Ordinal))
            {
                throw new JsonException();
            }

            int maximumDocumentBytes = root.GetProperty("maximumDocumentBytes").GetInt32();
            if (maximumDocumentBytes is < 1 or > 15 * 1024 * 1024) throw new JsonException();

            return new()
            {
                EnvironmentClass = environment,
                OrganizationIdentifier = organizationIdentifier,
                OrganizationAssigningAuthorityOid = organizationAuthority,
                OrganizationDescription = organizationDescription,
                OrganizationDomainId = organizationDomainId,
                Locality = locality,
                SubjectRole = role,
                SubjectCx = Fse2IheFormatter.FormatOrganizationCx(organizationIdentifier, organizationAuthority),
                ApplicationId = SafeApplicationValue(RequiredString(root, "applicationId", 128)),
                ApplicationVendor = SafeApplicationValue(RequiredString(root, "applicationVendor", 128)),
                ApplicationVersion = SafeApplicationValue(RequiredString(root, "applicationVersion", 128)),
                Operation = operation,
                RequestContentType = requestContentType,
                ResourceIdentifier = resourceIdentifier,
                MultipartBoundary = boundary,
                AuthorizationSigningSlot = ConnectorSigningSlotKey.Parse(RequiredString(root, "authorizationSigningSlot", ConnectorSigningSlotKey.MaximumLength)),
                IntegritySigningSlot = ConnectorSigningSlotKey.Parse(RequiredString(root, "integritySigningSlot", ConnectorSigningSlotKey.MaximumLength)),
                MaximumDocumentBytes = maximumDocumentBytes,
                ProfileChecksumSha256 = Convert.ToHexStringLower(SHA256.HashData(utf8Json.Span))
            };
        }
        catch (Fse2ConnectorException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidOperationException or JsonException or KeyNotFoundException or OverflowException)
        {
            throw new Fse2ConnectorException(Fse2ErrorCategory.PolicyDenied, "FSE2_PUBLISHED_PROFILE_INVALID");
        }
    }

    private static void ValidateProperties(JsonElement root)
    {
        HashSet<string> observed = new(StringComparer.Ordinal);
        foreach (JsonProperty property in root.EnumerateObject())
            if (!AllowedProperties.Contains(property.Name) || !observed.Add(property.Name)) throw new JsonException();
        string[] required =
        [
            "profile", "environmentClass", "organizationIdentifier", "organizationAssigningAuthorityOid",
            "organizationDescription", "organizationDomainId", "localityName", "localityAssigningAuthorityOid",
            "localityCode", "subjectRole", "applicationId", "applicationVendor", "applicationVersion",
            "operationId", "method", "relativePath", "requestContentType", "authorizationSigningSlot",
            "integritySigningSlot", "maximumDocumentBytes"
        ];
        if (required.Any(value => !observed.Contains(value))) throw new JsonException();
    }

    private static string RequiredString(JsonElement root, string name, int maximumLength)
    {
        JsonElement property = root.GetProperty(name);
        if (property.ValueKind != JsonValueKind.String) throw new JsonException();
        string value = property.GetString()!;
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value != value.Trim() || value.Any(char.IsControl))
            throw new JsonException();
        return value;
    }

    private static string? OptionalString(JsonElement root, string name, int maximumLength)
    {
        if (!root.TryGetProperty(name, out JsonElement property) || property.ValueKind == JsonValueKind.Null) return null;
        if (property.ValueKind != JsonValueKind.String) throw new JsonException();
        return RequiredString(root, name, maximumLength);
    }

    private static string SafeIdentifier(string value) => Fse2Validation.IsSafeIdentifier(value) ? value : throw new JsonException();

    private static string SafeApplicationValue(string value) =>
        value.Normalize(NormalizationForm.FormC) == value && !value.Any(character => character is '^' or '&')
            ? value
            : throw new JsonException();

    private static bool IsSafeBoundary(string? value) => value is { Length: >= 16 and <= 64 } &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
}

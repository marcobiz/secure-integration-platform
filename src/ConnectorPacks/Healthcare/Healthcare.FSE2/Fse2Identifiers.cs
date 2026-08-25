using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

internal static class Fse2OfficialIdentifierBounds
{
    internal const int TraceIdMaximumLength = 100;
    internal const int SpanIdMaximumLength = 100;
    internal const int WorkflowInstanceIdMaximumLength = 256;
}

/// <summary>Strict FSE2-only CX and XON formatting. This is not a general IHE framework.</summary>
public static partial class Fse2IheFormatter
{
    public static string FormatOrganizationCx(string organizationIdentifier, string assigningAuthorityOid)
    {
        string identifier = Fse2Validation.ValidateItalianVatNumber(organizationIdentifier);
        string authority = Fse2Validation.ValidateOid(assigningAuthorityOid);
        return $"{identifier}^^^&{authority}&ISO";
    }

    public static string FormatPersonCx(string taxIdentifier, string assigningAuthorityOid)
    {
        string identifier = Fse2Validation.ValidateItalianTaxIdentifier(taxIdentifier);
        string authority = Fse2Validation.ValidateOid(assigningAuthorityOid);
        return $"{identifier}^^^&{authority}&ISO";
    }

    public static string FormatLocalityXon(string organizationName, string assigningAuthorityOid, string organizationCode)
    {
        string name = Fse2Validation.ValidateOrganizationName(organizationName);
        string authority = Fse2Validation.ValidateOid(assigningAuthorityOid);
        string code = Fse2Validation.ValidateOrganizationCode(organizationCode);
        return $"{name}^^^^^&{authority}&ISO^^^^{code}";
    }

    public static void ValidateCx(string value, bool organization)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        string[] fields = value.Split('^');
        if (fields.Length != 4 || fields[1].Length != 0 || fields[2].Length != 0) throw new ArgumentException("FSE2_CX_INVALID", nameof(value));
        string[] authority = fields[3].Split('&');
        if (authority.Length != 3 || authority[0].Length != 0 || authority[2] != "ISO") throw new ArgumentException("FSE2_CX_AUTHORITY_INVALID", nameof(value));
        if (organization) _ = Fse2Validation.ValidateItalianVatNumber(fields[0]);
        else _ = Fse2Validation.ValidateItalianTaxIdentifier(fields[0]);
        _ = Fse2Validation.ValidateOid(authority[1]);
        string canonical = organization ? FormatOrganizationCx(fields[0], authority[1]) : FormatPersonCx(fields[0], authority[1]);
        if (!string.Equals(canonical, value, StringComparison.Ordinal)) throw new ArgumentException("FSE2_CX_NON_CANONICAL", nameof(value));
    }

    public static void ValidateXon(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        string[] fields = value.Split('^');
        if (fields.Length != 10 || fields.Skip(1).Take(4).Any(field => field.Length != 0) || fields.Skip(6).Take(3).Any(field => field.Length != 0))
            throw new ArgumentException("FSE2_XON_INVALID", nameof(value));
        string[] authority = fields[5].Split('&');
        if (authority.Length != 3 || authority[0].Length != 0 || authority[2] != "ISO") throw new ArgumentException("FSE2_XON_AUTHORITY_INVALID", nameof(value));
        string canonical = FormatLocalityXon(fields[0], authority[1], fields[9]);
        if (!string.Equals(canonical, value, StringComparison.Ordinal)) throw new ArgumentException("FSE2_XON_NON_CANONICAL", nameof(value));
    }
}

/// <summary>FSE2 validation and exact-byte hashing helpers.</summary>
public static partial class Fse2Validation
{
    private static readonly int[] OddTaxDigitMap = [1, 0, 5, 7, 9, 13, 15, 17, 19, 21];
    private static readonly int[] OddTaxLetterMap = [1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23];

    public static string ComputeAttachmentHash(ReadOnlyMemory<byte> exactDocumentBytes) =>
        Convert.ToHexStringLower(SHA256.HashData(exactDocumentBytes.Span));

    public static string ValidateItalianVatNumber(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (!VatRegex().IsMatch(value)) throw new ArgumentException("FSE2_ORGANIZATION_IDENTIFIER_INVALID", nameof(value));
        int sum = 0;
        for (int i = 0; i < 10; i++)
        {
            int digit = value[i] - '0';
            if ((i & 1) == 0) sum += digit;
            else { int doubled = digit * 2; sum += doubled > 9 ? doubled - 9 : doubled; }
        }
        if ((10 - (sum % 10)) % 10 != value[10] - '0') throw new ArgumentException("FSE2_ORGANIZATION_IDENTIFIER_CHECKSUM", nameof(value));
        return value;
    }

    public static string ValidateItalianTaxIdentifier(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (!TaxIdentifierRegex().IsMatch(value) || value.Normalize(NormalizationForm.FormC) != value)
            throw new ArgumentException("FSE2_PERSON_IDENTIFIER_INVALID", nameof(value));
        int checksum = 0;
        for (int index = 0; index < 15; index++)
        {
            char character = value[index];
            int ordinal = character is >= '0' and <= '9' ? character - '0' : character - 'A';
            checksum += (index & 1) == 0
                ? (character is >= '0' and <= '9' ? OddTaxDigitMap[ordinal] : OddTaxLetterMap[ordinal])
                : ordinal;
        }
        if ((char)('A' + checksum % 26) != value[15])
            throw new ArgumentException("FSE2_PERSON_IDENTIFIER_CHECKSUM", nameof(value));
        return value;
    }

    public static string ValidateOid(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 128) throw new ArgumentException("FSE2_OID_INVALID", nameof(value));
        string[] arcs = value.Split('.', StringSplitOptions.None);
        if (arcs.Length < 2) throw new ArgumentException("FSE2_OID_INVALID", nameof(value));
        foreach (string arc in arcs)
        {
            if (arc.Length is 0 or > 39 || arc.Any(character => character is < '0' or > '9'))
                throw new ArgumentException("FSE2_OID_INVALID", nameof(value));
            if (arc.Length > 1 && arc[0] == '0') throw new ArgumentException("FSE2_OID_NON_CANONICAL", nameof(value));
        }
        if (arcs[0].Length != 1 || arcs[0][0] is < '0' or > '2')
            throw new ArgumentException("FSE2_OID_INVALID", nameof(value));
        if (arcs[0][0] is '0' or '1' && (arcs[1].Length > 2 || !int.TryParse(arcs[1], out int second) || second > 39))
            throw new ArgumentException("FSE2_OID_INVALID", nameof(value));
        return value;
    }

    public static string ValidateOrganizationName(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 128 || value != value.Trim() || value.Normalize(NormalizationForm.FormC) != value || value.Any(character => char.IsControl(character) || character is '^' or '&'))
            throw new ArgumentException("FSE2_ORGANIZATION_NAME_INVALID", nameof(value));
        return value;
    }

    public static string ValidateOrganizationCode(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (!OrganizationCodeRegex().IsMatch(value)) throw new ArgumentException("FSE2_ORGANIZATION_CODE_INVALID", nameof(value));
        return value;
    }

    public static string ValidateDocumentId(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 256 || !(DocumentOidRegex().IsMatch(value) || DocumentHexRegex().IsMatch(value))) throw new ArgumentException("FSE2_DOCUMENT_ID_INVALID", nameof(value));
        return value;
    }

    public static string ValidateWorkflowId(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > Fse2OfficialIdentifierBounds.WorkflowInstanceIdMaximumLength ||
            value != value.Trim() ||
            value.Any(character => char.IsControl(character) || character is '/' or '?' or '#' or '\\'))
            throw new ArgumentException("FSE2_WORKFLOW_ID_INVALID", nameof(value));
        return value;
    }

    public static string ValidateTraceId(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > Fse2OfficialIdentifierBounds.TraceIdMaximumLength || !TraceRegex().IsMatch(value))
            throw new ArgumentException("FSE2_TRACE_ID_INVALID", nameof(value));
        return value;
    }

    public static string ValidateResourceHl7Type(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (!ResourceTypeRegex().IsMatch(value)) throw new ArgumentException("FSE2_RESOURCE_HL7_TYPE_INVALID", nameof(value));
        return value;
    }

    public static void ValidateJsonObject(ReadOnlyMemory<byte> value) => ValidateJsonObject(value, operation: null);

    internal static void ValidateJsonObject(ReadOnlyMemory<byte> value, Fse2Operation operation) => ValidateJsonObject(value, (Fse2Operation?)operation);

    private static void ValidateJsonObject(ReadOnlyMemory<byte> value, Fse2Operation? operation)
    {
        if (value.IsEmpty || value.Length > 1024 * 1024) throw new ArgumentException("FSE2_REQUEST_BODY_INVALID", nameof(value));
        try
        {
            using JsonDocument document = JsonDocument.Parse(value, new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 32 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw new JsonException();
            if (document.RootElement.EnumerateObject().Any(property =>
                property.Name.Equals("attachment_hash", StringComparison.OrdinalIgnoreCase) ||
                property.Name.Equals("attachmentHash", StringComparison.OrdinalIgnoreCase) ||
                property.Name.Equals("attachment_hash_algorithm", StringComparison.OrdinalIgnoreCase) ||
                property.Name.Equals("attachmentHashAlgorithm", StringComparison.OrdinalIgnoreCase) ||
                property.Name.Equals("attachment_hash_input", StringComparison.OrdinalIgnoreCase) ||
                property.Name.Equals("attachmentHashInput", StringComparison.OrdinalIgnoreCase)))
                throw new JsonException();
            if (operation is Fse2Operation.Create or Fse2Operation.Replace)
                ValidatePublicationWorkflowInstanceId(value.Span);
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException)
        {
            throw new ArgumentException("FSE2_REQUEST_BODY_INVALID", nameof(value));
        }
    }

    private static void ValidatePublicationWorkflowInstanceId(ReadOnlySpan<byte> value)
    {
        const string propertyName = "workflowInstanceId";
        Utf8JsonReader reader = new(value, new JsonReaderOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 32 });
        bool observed = false;
        while (reader.Read())
        {
            if (reader.TokenType != JsonTokenType.PropertyName || reader.CurrentDepth != 1) continue;

            string? observedName = reader.GetString();
            if (!string.Equals(observedName, propertyName, StringComparison.OrdinalIgnoreCase)) continue;
            if (observed || reader.ValueIsEscaped || !string.Equals(observedName, propertyName, StringComparison.Ordinal))
                throw new JsonException();

            observed = true;
            if (!reader.Read() || reader.TokenType != JsonTokenType.String) throw new JsonException();
            _ = ValidateWorkflowId(reader.GetString()!);
        }
    }

    internal static bool IsSafeIdentifier(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 128 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');
    internal static bool IsSha256(string? value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);
    internal static bool IsSafeCode(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 96 && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    [GeneratedRegex("^[0-9]{11}$", RegexOptions.CultureInvariant)] private static partial Regex VatRegex();
    [GeneratedRegex("^[A-Z0-9]{16}$", RegexOptions.CultureInvariant)] private static partial Regex TaxIdentifierRegex();
    [GeneratedRegex("^[0-9]+(?:\\.[0-9]+)+$", RegexOptions.CultureInvariant)] private static partial Regex OidRegex();
    [GeneratedRegex("^[A-Z0-9][A-Z0-9._-]{1,31}$", RegexOptions.CultureInvariant)] private static partial Regex OrganizationCodeRegex();
    [GeneratedRegex("^[0-9]+(?:\\.[0-9]+)+(?:\\^[A-Za-z0-9._-]{1,128})?$", RegexOptions.CultureInvariant)] private static partial Regex DocumentOidRegex();
    [GeneratedRegex("^[a-f0-9]{24}$", RegexOptions.CultureInvariant)] private static partial Regex DocumentHexRegex();
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]*$", RegexOptions.CultureInvariant)] private static partial Regex TraceRegex();
    [GeneratedRegex("^\\('[0-9A-Za-z.-]{1,32}\\^\\^[0-9]+(?:\\.[0-9]+)+ '\\)$", RegexOptions.IgnorePatternWhitespace | RegexOptions.CultureInvariant)] private static partial Regex ResourceTypeRegex();
}

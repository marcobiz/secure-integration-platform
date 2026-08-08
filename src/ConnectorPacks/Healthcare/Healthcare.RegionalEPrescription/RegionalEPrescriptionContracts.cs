using System.Collections.ObjectModel;

namespace SecureIntegration.ConnectorPacks.Healthcare.RegionalEPrescription;

/// <summary>Business operations proven common at the public regional process level.</summary>
public enum RegionalEPrescriptionOperation
{
    /// <summary>Locate a prescription from its server-approved regional route.</summary>
    Lookup,
    /// <summary>Record a dispensing outcome through the server-approved regional route.</summary>
    Dispense
}

/// <summary>An opaque prescription reference. Concrete regional formatting remains profile-specific.</summary>
public sealed record PrescriptionReference
{
    /// <summary>Creates a bounded, printable reference without assigning regional semantics.</summary>
    public PrescriptionReference(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 128 || value.Any(char.IsControl))
        {
            throw new ArgumentException("PRESCRIPTION_REFERENCE_INVALID", nameof(value));
        }

        Value = value;
    }

    /// <summary>Opaque value supplied as healthcare business input.</summary>
    public string Value { get; }

    /// <inheritdoc />
    public override string ToString() => "[PRESCRIPTION_REFERENCE]";
}

/// <summary>Allowed scalar shape for one explicitly declared profile extension.</summary>
public enum RegionalExtensionValueKind
{
    /// <summary>Bounded printable text.</summary>
    Text,
    /// <summary>Invariant base-10 integer.</summary>
    WholeNumber,
    /// <summary>Lowercase JSON-compatible boolean.</summary>
    Boolean,
    /// <summary>ISO 8601 calendar date.</summary>
    Date
}

/// <summary>One profile-owned extension field definition.</summary>
public sealed record RegionalExtensionField(string Name, RegionalExtensionValueKind Kind, bool Required = false, int MaximumLength = 256)
{
    /// <summary>Validates a field definition before it becomes part of a profile schema.</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Name) || Name.Length > 64 || !Name.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_'))
        {
            throw new ArgumentException("REGIONAL_EXTENSION_NAME_INVALID", nameof(Name));
        }

        if (MaximumLength is < 1 or > 2048)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumLength), "REGIONAL_EXTENSION_LIMIT_INVALID");
        }
        if (!Enum.IsDefined(Kind)) throw new ArgumentOutOfRangeException(nameof(Kind), "REGIONAL_EXTENSION_KIND_INVALID");
    }
}

/// <summary>
/// Controlled profile-specific scalar values. Every key must be declared by the selected server-owned profile.
/// </summary>
public sealed class RegionalExtensionSet
{
    private const int MaximumFields = 32;
    private const int MaximumAggregateLength = 8192;
    private static readonly IReadOnlyDictionary<string, string> EmptyValues =
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.Ordinal));

    private RegionalExtensionSet(IReadOnlyDictionary<string, string> values) => Values = values;

    /// <summary>No profile-specific fields.</summary>
    public static RegionalExtensionSet Empty { get; } = new(EmptyValues);

    /// <summary>Validated values exposed without arbitrary object graphs.</summary>
    public IReadOnlyDictionary<string, string> Values { get; }

    /// <summary>
    /// Copies bounded scalar input. Field semantics are validated later against the selected
    /// server-owned compiled profile; a caller cannot supply that schema.
    /// </summary>
    public static RegionalExtensionSet Create(IReadOnlyDictionary<string, string> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count > MaximumFields) throw new ArgumentException("REGIONAL_EXTENSION_COUNT_EXCEEDED", nameof(values));

        Dictionary<string, string> validated = new(StringComparer.Ordinal);
        int aggregateLength = 0;
        foreach ((string name, string value) in values)
        {
            if (string.IsNullOrWhiteSpace(name) || name.Length > 64 || !name.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_'))
            {
                throw new ArgumentException("REGIONAL_EXTENSION_NAME_INVALID", nameof(values));
            }

            ArgumentNullException.ThrowIfNull(value);
            if (value.Length > 2048 || value.Any(char.IsControl)) throw new ArgumentException("REGIONAL_EXTENSION_VALUE_INVALID", nameof(values));
            aggregateLength = checked(aggregateLength + name.Length + value.Length);
            if (aggregateLength > MaximumAggregateLength) throw new ArgumentException("REGIONAL_EXTENSION_AGGREGATE_EXCEEDED", nameof(values));
            validated.Add(name, value);
        }

        return new RegionalExtensionSet(new ReadOnlyDictionary<string, string>(validated));
    }

    internal void ValidateAgainst(IReadOnlyList<RegionalExtensionField> schema)
    {
        ArgumentNullException.ThrowIfNull(schema);
        if (schema.Count > MaximumFields) throw new ArgumentException("REGIONAL_EXTENSION_SCHEMA_COUNT_EXCEEDED", nameof(schema));

        Dictionary<string, RegionalExtensionField> definitions = new(StringComparer.Ordinal);
        foreach (RegionalExtensionField field in schema)
        {
            field.Validate();
            if (!definitions.TryAdd(field.Name, field)) throw new ArgumentException("REGIONAL_EXTENSION_SCHEMA_DUPLICATE", nameof(schema));
        }

        foreach (RegionalExtensionField required in definitions.Values.Where(field => field.Required))
        {
            if (!Values.ContainsKey(required.Name)) throw new ArgumentException("REGIONAL_EXTENSION_REQUIRED", nameof(schema));
        }

        foreach ((string name, string value) in Values)
        {
            if (!definitions.TryGetValue(name, out RegionalExtensionField? definition)) throw new ArgumentException("REGIONAL_EXTENSION_NOT_ALLOWED", nameof(schema));
            ValidateValue(definition, value);
        }
    }

    private static void ValidateValue(RegionalExtensionField definition, string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length > definition.MaximumLength || value.Any(char.IsControl))
        {
            throw new ArgumentException("REGIONAL_EXTENSION_VALUE_INVALID", definition.Name);
        }

        bool valid = definition.Kind switch
        {
            RegionalExtensionValueKind.Text => true,
            RegionalExtensionValueKind.WholeNumber => long.TryParse(value, System.Globalization.NumberStyles.AllowLeadingSign, System.Globalization.CultureInfo.InvariantCulture, out _),
            RegionalExtensionValueKind.Boolean => value is "true" or "false",
            RegionalExtensionValueKind.Date => DateOnly.TryParseExact(value, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out _),
            _ => false
        };

        if (!valid)
        {
            throw new ArgumentException("REGIONAL_EXTENSION_VALUE_INVALID", definition.Name);
        }
    }
}

/// <summary>Base class for client-visible healthcare commands. It deliberately has no profile, region, route or auth fields.</summary>
public abstract record RegionalEPrescriptionCommand(PrescriptionReference Prescription, RegionalExtensionSet Extensions)
{
    /// <summary>Common operation represented by this command.</summary>
    public abstract RegionalEPrescriptionOperation Operation { get; }
}

/// <summary>Minimal lookup input common to the characterized public regional processes.</summary>
public sealed record PrescriptionLookupRequest(PrescriptionReference Prescription, RegionalExtensionSet Extensions)
    : RegionalEPrescriptionCommand(Prescription, Extensions)
{
    /// <inheritdoc />
    public override RegionalEPrescriptionOperation Operation => RegionalEPrescriptionOperation.Lookup;
}

/// <summary>Minimal dispense input; all unconfirmed clinical and regional wire fields remain outside the common model.</summary>
public sealed record DispenseRequest(PrescriptionReference Prescription, RegionalExtensionSet Extensions)
    : RegionalEPrescriptionCommand(Prescription, Extensions)
{
    /// <inheritdoc />
    public override RegionalEPrescriptionOperation Operation => RegionalEPrescriptionOperation.Dispense;
}

/// <summary>Normalized availability that does not erase an upstream safe code.</summary>
public enum PrescriptionAvailability
{
    /// <summary>The prescription is available for the requested workflow.</summary>
    Available,
    /// <summary>The prescription exists but is not available for the requested workflow.</summary>
    Unavailable
}

/// <summary>Allowlisted non-sensitive regional outcome or fault code.</summary>
public sealed record RegionalSafeCode
{
    /// <summary>Creates a bounded code that cannot contain payload or credential material.</summary>
    public RegionalSafeCode(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length > 64 || !value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'))
        {
            throw new ArgumentException("SAFE_REGIONAL_CODE_INVALID", nameof(value));
        }

        Value = value;
    }

    /// <summary>Sanitized profile-specific code.</summary>
    public string Value { get; }
}

/// <summary>Typed base for every normalized regional ePrescription response.</summary>
public abstract record RegionalEPrescriptionResponse(PrescriptionReference Prescription, RegionalExtensionSet Extensions);

/// <summary>Minimal normalized lookup result.</summary>
public sealed record PrescriptionLookupResult(PrescriptionReference Prescription, PrescriptionAvailability Availability, RegionalSafeCode? SafeRegionalCode, RegionalExtensionSet Extensions)
    : RegionalEPrescriptionResponse(Prescription, Extensions);

/// <summary>Normalized dispensing disposition.</summary>
public enum DispenseDisposition
{
    /// <summary>The regional service accepted the dispensing transition.</summary>
    Accepted,
    /// <summary>The regional service rejected the dispensing transition.</summary>
    Rejected
}

/// <summary>Minimal normalized dispense result.</summary>
public sealed record DispenseOutcome(PrescriptionReference Prescription, DispenseDisposition Disposition, RegionalSafeCode? SafeRegionalCode, RegionalExtensionSet Extensions)
    : RegionalEPrescriptionResponse(Prescription, Extensions);

/// <summary>Normalized cross-profile failure categories supported by the foundation.</summary>
public enum RegionalEPrescriptionErrorCategory
{
    /// <summary>The reference was not found.</summary>
    NotFound,
    /// <summary>New external authorization or session completion is required.</summary>
    AuthenticationRequired,
    /// <summary>The requested workflow transition is not valid.</summary>
    InvalidState,
    /// <summary>The regional authority rejected the operation.</summary>
    Rejected,
    /// <summary>The upstream service is temporarily unavailable.</summary>
    TemporaryUnavailable,
    /// <summary>The Published profile is disabled or not implementable from current official specifications.</summary>
    ProfileUnavailable
}

/// <summary>Sanitized failure. Raw regional responses and secrets are never retained.</summary>
public sealed class RegionalEPrescriptionException : Exception
{
    /// <summary>Creates a sanitized failure from a normalized category and optional allowlisted regional code.</summary>
    public RegionalEPrescriptionException(RegionalEPrescriptionErrorCategory category, string? safeRegionalCode = null)
        : base($"REGIONAL_EPRESCRIPTION_{category.ToString().ToUpperInvariant()}")
    {
        if (!Enum.IsDefined(category)) throw new ArgumentOutOfRangeException(nameof(category), "REGIONAL_EPRESCRIPTION_CATEGORY_INVALID");
        Category = category;
        SafeRegionalCode = safeRegionalCode is null ? null : new RegionalSafeCode(safeRegionalCode);
    }

    /// <summary>Normalized failure category.</summary>
    public RegionalEPrescriptionErrorCategory Category { get; }

    /// <summary>Allowlisted non-sensitive code, separate from the normalized category.</summary>
    public RegionalSafeCode? SafeRegionalCode { get; }
}

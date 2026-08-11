using System.Text;

namespace SecureIntegration.Gateway.Application;

internal static class PublishedPathTemplate
{
    internal const int MaximumPlaceholders = 8;
    internal const int MaximumParameterNameLength = 32;
    internal const int MaximumParameterValueUtf8Bytes = 512;

    internal static IReadOnlyList<string> Validate(string template, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(template, parameterName);
        if (template.Length is < 1 or > 1024 || template[0] != '/' ||
            template.StartsWith("//", StringComparison.Ordinal) || template.Any(char.IsControl) ||
            template.Contains('\\', StringComparison.Ordinal) || template.Contains('?', StringComparison.Ordinal) ||
            template.Contains('#', StringComparison.Ordinal) || template.Contains('%', StringComparison.Ordinal))
            throw new ArgumentException("Published path template is invalid.", parameterName);

        HashSet<string> placeholders = new(StringComparer.Ordinal);
        string[] segments = template.Split('/');
        for (int index = 1; index < segments.Length; index++)
        {
            string segment = segments[index];
            if (segment.Length == 0)
            {
                if (index != segments.Length - 1) throw new ArgumentException("Published path template contains an empty segment.", parameterName);
                continue;
            }
            if (segment is "." or "..") throw new ArgumentException("Published path template contains traversal.", parameterName);
            bool hasBrace = segment.Contains('{', StringComparison.Ordinal) || segment.Contains('}', StringComparison.Ordinal);
            if (hasBrace)
            {
                if (segment.Length < 3 || segment[0] != '{' || segment[^1] != '}' ||
                    segment[1..^1].Contains('{', StringComparison.Ordinal) || segment[1..^1].Contains('}', StringComparison.Ordinal))
                    throw new ArgumentException("Published path placeholders must occupy a whole segment.", parameterName);
                string name = ValidateParameterName(segment[1..^1], parameterName);
                if (placeholders.Count >= MaximumPlaceholders || !placeholders.Add(name))
                    throw new ArgumentException("Published path placeholders are duplicated or excessive.", parameterName);
                continue;
            }
            if (segment.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '.' and not '_' and not '~'))
                throw new ArgumentException("Published path template literal segment is not canonical.", parameterName);
        }
        return placeholders.Order(StringComparer.Ordinal).ToArray();
    }

    internal static string ValidateParameterName(string value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (value.Length is < 1 or > MaximumParameterNameLength || value[0] is not (>= 'a' and <= 'z') ||
            value[^1] is not (>= 'a' and <= 'z') and not (>= '0' and <= '9') ||
            value.Any(character => character is not (>= 'a' and <= 'z') and not (>= '0' and <= '9') and not '-' and not '_'))
            throw new ArgumentException("Published path parameter name is not canonical.", parameterName);
        return value;
    }

    internal static string ValidateParameterValue(string value, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(value, parameterName);
        if (string.IsNullOrWhiteSpace(value) || !value.IsNormalized(NormalizationForm.FormC) ||
            Encoding.UTF8.GetByteCount(value) > MaximumParameterValueUtf8Bytes || value.Any(char.IsControl) ||
            value.Contains('/', StringComparison.Ordinal) || value.Contains('\\', StringComparison.Ordinal) ||
            value.Contains('%', StringComparison.Ordinal) || value.Contains('?', StringComparison.Ordinal) ||
            value.Contains('#', StringComparison.Ordinal) || value is "." or "..")
            throw new ArgumentException("Published path parameter value is invalid.", parameterName);
        return value;
    }

    internal static Uri Project(Uri baseEndpoint, string template, IReadOnlyList<AuthorizedConnectorPathParameter> values)
    {
        ArgumentNullException.ThrowIfNull(baseEndpoint);
        ArgumentNullException.ThrowIfNull(values);
        IReadOnlyList<string> expected = Validate(template, nameof(template));
        Dictionary<string, string> supplied = new(StringComparer.Ordinal);
        int count = 0;
        foreach (AuthorizedConnectorPathParameter value in values)
        {
            if (value is null || ++count > MaximumPlaceholders || !supplied.TryAdd(
                    ValidateParameterName(value.Name, nameof(values)), ValidateParameterValue(value.Value, nameof(values))))
                throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
        }
        if (expected.Count != supplied.Count || expected.Any(name => !supplied.ContainsKey(name)))
            throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
        if (!baseEndpoint.IsAbsoluteUri || !string.IsNullOrEmpty(baseEndpoint.UserInfo) ||
            !string.IsNullOrEmpty(baseEndpoint.Query) || !string.IsNullOrEmpty(baseEndpoint.Fragment))
            throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);

        string path = string.Join('/', template.Split('/').Select(segment =>
            segment.Length >= 3 && segment[0] == '{' && segment[^1] == '}' &&
            supplied.TryGetValue(segment[1..^1], out string? value)
                ? Uri.EscapeDataString(value)
                : segment));
        Uri projected;
        try { projected = new Uri(baseEndpoint.GetLeftPart(UriPartial.Authority) + path, UriKind.Absolute); }
        catch (UriFormatException) { throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409); }
        if (!string.Equals(projected.Scheme, baseEndpoint.Scheme, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(projected.IdnHost, baseEndpoint.IdnHost, StringComparison.OrdinalIgnoreCase) ||
            projected.Port != baseEndpoint.Port || !string.Equals(projected.AbsolutePath, path, StringComparison.Ordinal) ||
            !string.IsNullOrEmpty(projected.Query) || !string.IsNullOrEmpty(projected.Fragment) || !string.IsNullOrEmpty(projected.UserInfo))
            throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
        return projected;
    }
}

namespace SecureIntegration.Gateway.Application;

/// <summary>Strict RFC 4648 base64url helper without padding.</summary>
public static class Base64Url
{
    /// <summary>Encodes bytes without padding.</summary>
    public static string Encode(ReadOnlySpan<byte> value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Decodes a strict unpadded base64url value.</summary>
    public static byte[] Decode(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.IndexOfAny(['+', '/', '=']) >= 0) throw new FormatException("Invalid base64url value.");
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 0 => string.Empty, 2 => "==", 3 => "=", _ => throw new FormatException("Invalid base64url length.") };
        return Convert.FromBase64String(padded);
    }
}

using System.Text.Json;

namespace SecureIntegration.Gateway.Application;

/// <summary>
/// Immutable bounded copy of the current operation's Published extension configuration. The view
/// contains configuration data only; its internal Published authority stamp is never exposed.
/// </summary>
public sealed class AuthorizedPublishedExtensionConfiguration
{
    internal const int MaximumJsonBytes = 32 * 1024;
    internal const int MaximumDepth = 8;
    private readonly byte[] json;

    internal AuthorizedPublishedExtensionConfiguration(ReadOnlySpan<byte> json)
    {
        if (json.Length is < 2 or > MaximumJsonBytes)
            throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-CORRUPT", 503);
        try
        {
            using JsonDocument document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions { MaxDepth = MaximumDepth });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new JsonException();
        }
        catch (JsonException)
        {
            throw new GatewayException("BGW-CONNECTOR-CONFIGURATION-CORRUPT", 503);
        }
        this.json = json.ToArray();
    }

    /// <summary>Length of the copied UTF-8 JSON object.</summary>
    public int JsonLength => json.Length;

    /// <summary>Opens an independent read-only stream over a defensive copy of the Published JSON.</summary>
    public Stream OpenJsonStream() => new MemoryStream(json.ToArray(), writable: false);

    internal AuthorizedPublishedExtensionConfiguration Copy() => new(json);

    internal static AuthorizedPublishedExtensionConfiguration Empty() => new("{}"u8);

    /// <inheritdoc />
    public override string ToString() => $"AuthorizedPublishedExtensionConfiguration(JsonLength={JsonLength}, Redacted=True)";
}

/// <summary>
/// Compact token created by the exact current invocation's server-owned signing policy. The token
/// carries no reusable key, provider or signing capability.
/// </summary>
public sealed class AuthorizedConnectorSignedToken
{
    private readonly object authority;

    internal AuthorizedConnectorSignedToken(object authority, string compactToken)
    {
        if (string.IsNullOrWhiteSpace(compactToken) || compactToken.Length > 64 * 1024 || compactToken.Any(char.IsControl))
            throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
        this.authority = authority;
        CompactToken = compactToken;
    }

    internal string CompactToken { get; }

    internal bool IsOwnedBy(object candidate) => ReferenceEquals(authority, candidate);

    /// <inheritdoc />
    public override string ToString() => "AuthorizedConnectorSignedToken(Redacted=True)";
}

/// <summary>
/// Bounded protocol body for the current Published restricted-transport capability. Endpoint,
/// method, content type, Authorization semantics and mTLS identity remain server-owned.
/// </summary>
public sealed class AuthorizedConnectorRestrictedTransportRequest
{
    private const int MaximumBodyBytes = 16 * 1024 * 1024;
    private readonly byte[] body;

    /// <summary>Creates a body that must use a token signed by the same current capability bridge.</summary>
    public AuthorizedConnectorRestrictedTransportRequest(
        ReadOnlyMemory<byte> body,
        AuthorizedConnectorSignedToken signedToken)
    {
        ArgumentNullException.ThrowIfNull(signedToken);
        if (body.Length is < 1 or > MaximumBodyBytes)
            throw new ArgumentOutOfRangeException(nameof(body));
        this.body = body.ToArray();
        SignedToken = signedToken;
    }

    /// <summary>Copied protocol-body length.</summary>
    public int BodyLength => body.Length;

    internal ReadOnlyMemory<byte> Body => body;
    internal AuthorizedConnectorSignedToken SignedToken { get; }

    /// <inheritdoc />
    public override string ToString() => $"AuthorizedConnectorRestrictedTransportRequest(BodyLength={BodyLength}, Redacted=True)";
}

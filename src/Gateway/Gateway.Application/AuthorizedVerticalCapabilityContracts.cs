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

    internal AuthorizedConnectorSignedToken(
        object authority,
        ConnectorSigningSlotKey signingSlot,
        string compactToken)
    {
        ArgumentNullException.ThrowIfNull(signingSlot);
        if (string.IsNullOrWhiteSpace(compactToken) || compactToken.Length > 64 * 1024 || compactToken.Any(char.IsControl))
            throw new GatewayException("BGW-EGRESS-AUTHENTICATION", 409);
        this.authority = authority;
        SigningSlot = signingSlot;
        CompactToken = compactToken;
    }

    internal ConnectorSigningSlotKey SigningSlot { get; }
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
    private readonly byte[]? body;
    private readonly AuthorizedConnectorPathParameter[] pathParameters;

    /// <summary>
    /// Creates a bodyless request without dynamic path parameters. Core accepts it only when the
    /// exact Published transport body mode is NONE.
    /// </summary>
    public AuthorizedConnectorRestrictedTransportRequest()
        : this(null, null, [], true)
    {
    }

    /// <summary>
    /// Creates a bodyless request with a bounded immutable collection of opaque Published path
    /// segment values. No URI, query, method or header authority is accepted.
    /// </summary>
    public AuthorizedConnectorRestrictedTransportRequest(
        IReadOnlyCollection<AuthorizedConnectorPathParameter> pathParameters)
        : this(null, null, pathParameters, true)
    {
    }

    /// <summary>
    /// Creates a body whose signed-token projections are supplied only by the current capability
    /// bridge from tokens generated for the exact Published signing slots.
    /// </summary>
    public AuthorizedConnectorRestrictedTransportRequest(ReadOnlyMemory<byte> body)
        : this(body, null, [], true)
    {
    }

    /// <summary>Creates a required body plus bounded opaque values for an exact Published path template.</summary>
    public AuthorizedConnectorRestrictedTransportRequest(
        ReadOnlyMemory<byte> body,
        IReadOnlyCollection<AuthorizedConnectorPathParameter> pathParameters)
        : this(body, null, pathParameters, true)
    {
    }

    /// <summary>
    /// Creates a body and retains the historical same-invocation token proof. Core still derives
    /// every actual outbound projection from the exact Published signing slots.
    /// </summary>
    public AuthorizedConnectorRestrictedTransportRequest(
        ReadOnlyMemory<byte> body,
        AuthorizedConnectorSignedToken signedToken)
        : this(body, signedToken ?? throw new ArgumentNullException(nameof(signedToken)), [], true)
    {
    }

    /// <summary>
    /// Creates a required body, historical same-invocation token proof and bounded opaque values for
    /// an exact Published path template.
    /// </summary>
    public AuthorizedConnectorRestrictedTransportRequest(
        ReadOnlyMemory<byte> body,
        AuthorizedConnectorSignedToken signedToken,
        IReadOnlyCollection<AuthorizedConnectorPathParameter> pathParameters)
        : this(body, signedToken ?? throw new ArgumentNullException(nameof(signedToken)), pathParameters, true)
    {
    }

    private AuthorizedConnectorRestrictedTransportRequest(
        ReadOnlyMemory<byte>? body,
        AuthorizedConnectorSignedToken? signedToken,
        IReadOnlyCollection<AuthorizedConnectorPathParameter> pathParameters,
        bool _)
    {
        ArgumentNullException.ThrowIfNull(pathParameters);
        if (body is { Length: < 1 or > MaximumBodyBytes })
            throw new ArgumentOutOfRangeException(nameof(body));
        this.body = body?.ToArray();
        List<AuthorizedConnectorPathParameter> parameters = [];
        HashSet<string> names = new(StringComparer.Ordinal);
        int count = 0;
        foreach (AuthorizedConnectorPathParameter parameter in pathParameters)
        {
            if (parameter is null || ++count > PublishedPathTemplate.MaximumPlaceholders || !names.Add(parameter.Name))
                throw new ArgumentException("Published path parameters are invalid, duplicated or excessive.", nameof(pathParameters));
            parameters.Add(parameter.Copy());
        }
        this.pathParameters = parameters.ToArray();
        SignedToken = signedToken;
    }

    /// <summary>Copied protocol-body length.</summary>
    public int BodyLength => body?.Length ?? 0;
    /// <summary>Number of copied opaque path-segment values.</summary>
    public int PathParameterCount => pathParameters.Length;

    internal bool HasBody => body is not null;
    internal ReadOnlyMemory<byte> Body => body ?? ReadOnlyMemory<byte>.Empty;
    internal IReadOnlyList<AuthorizedConnectorPathParameter> PathParameters => pathParameters;
    internal AuthorizedConnectorSignedToken? SignedToken { get; }

    /// <inheritdoc />
    public override string ToString() => $"AuthorizedConnectorRestrictedTransportRequest(BodyLength={BodyLength}, PathParameterCount={PathParameterCount}, Redacted=True)";
}

/// <summary>
/// One immutable opaque value for a whole-segment placeholder declared by the exact Published path
/// template. It carries no URI, scheme, host, port, query, fragment, method or header authority.
/// </summary>
public sealed class AuthorizedConnectorPathParameter
{
    /// <summary>Creates one canonical-name opaque path-segment value.</summary>
    public AuthorizedConnectorPathParameter(string name, string value)
    {
        Name = PublishedPathTemplate.ValidateParameterName(name, nameof(name));
        Value = PublishedPathTemplate.ValidateParameterValue(value, nameof(value));
    }

    /// <summary>Exact canonical Published placeholder name.</summary>
    public string Name { get; }
    /// <summary>Opaque segment value; Core validates and encodes it exactly once.</summary>
    public string Value { get; }

    internal AuthorizedConnectorPathParameter Copy() => new(Name, Value);

    /// <inheritdoc />
    public override string ToString() => $"AuthorizedConnectorPathParameter(Name={Name}, Redacted=True)";
}

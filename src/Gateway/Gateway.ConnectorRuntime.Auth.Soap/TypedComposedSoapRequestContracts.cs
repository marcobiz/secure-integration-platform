using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Xml;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>
/// Compiled request adapter for one exact Published composed-SOAP business operation. It receives
/// no envelope, endpoint, HTTP, credential, provider, session or transport authority.
/// </summary>
public interface ITypedComposedSoapRequestAdapter
{
    /// <summary>Logical adapter identifier selected by the exact Published operation.</summary>
    string AdapterId { get; }
    /// <summary>Closed logical adapter type selected by the exact Published operation.</summary>
    string AdapterType { get; }
    /// <summary>Static bounded names that Published must map exactly to server-owned bindings.</summary>
    IReadOnlySet<string> RequiredServerOwnedInputs => TypedComposedSoapRequestAdapterDefaults.NoServerOwnedInputs;
    /// <summary>
    /// Writes only children of the exact request element already opened by hardened Core. The
    /// callback is synchronous; retained context, payload streams and binding inputs are invalid
    /// after it returns.
    /// </summary>
    void WriteRequest(XmlWriter writer, TypedComposedSoapRequestContext context);
}

/// <summary>
/// Callback-scoped view of a Core-copied business payload, safe Published metadata and exact
/// write-only binding inputs. It deliberately contains no wire or provider selector.
/// </summary>
public sealed class TypedComposedSoapRequestContext
{
    private readonly object synchronization = new();
    private byte[] businessPayload;
    private int state = 1;

    internal TypedComposedSoapRequestContext(
        ComposedSoapAuthorityState authority,
        ReadOnlyMemory<byte> payload,
        AuthorizedConnectorBindingInputs serverOwnedInputs)
    {
        Authority = authority ?? throw new ArgumentNullException(nameof(authority));
        if (payload.Length > authority.SessionAuthority.MaximumRequestBytes)
            throw TypedComposedSoapRequestFailures.RequestRejected();
        businessPayload = payload.ToArray();
        BusinessPayloadLength = businessPayload.Length;
        ServerOwnedInputs = serverOwnedInputs ?? throw new ArgumentNullException(nameof(serverOwnedInputs));
    }

    private ComposedSoapAuthorityState Authority { get; }

    /// <summary>Authenticated Tenant identity.</summary>
    public Guid TenantId => Authority.SessionAuthority.TenantId;
    /// <summary>Authenticated Installation identity.</summary>
    public Guid InstallationId => Authority.SessionAuthority.InstallationId;
    /// <summary>Authenticated Application identity.</summary>
    public Guid ApplicationId => Authority.SessionAuthority.ApplicationId;
    /// <summary>Published Connector identifier.</summary>
    public string ConnectorId => Authority.SessionAuthority.ConnectorId;
    /// <summary>Exact Published Connector version.</summary>
    public string ConnectorVersion => Authority.SessionAuthority.ConnectorVersion;
    /// <summary>Authorized Published operation.</summary>
    public string OperationId => Authority.SessionAuthority.OperationId;
    /// <summary>Authenticated correlation identifier.</summary>
    public Guid CorrelationId => Authority.SessionAuthority.CorrelationId;
    /// <summary>Checksum of the immutable Published Connector definition.</summary>
    public string PublishedPolicyChecksum => Convert.ToHexString(Authority.SessionAuthority.Snapshot.Version.ChecksumSha256);
    /// <summary>Length of the bounded Core-copied business payload.</summary>
    public int BusinessPayloadLength { get; }
    /// <summary>Exact Published-declared input set, writable only to the current Core XML writer.</summary>
    public AuthorizedConnectorBindingInputs ServerOwnedInputs { get; }

    /// <summary>
    /// Opens an independent read-only, repeatable view of the business payload during the exact
    /// synchronous adapter callback. The backing copy is cleared when the callback ends.
    /// </summary>
    public Stream OpenBusinessPayloadStream()
    {
        lock (synchronization)
        {
            if (state != 1) throw TypedComposedSoapRequestFailures.RequestRejected();
            return new MemoryStream(businessPayload, writable: false);
        }
    }

    internal void Clear()
    {
        lock (synchronization)
        {
            if (state == 2) return;
            state = 2;
            CryptographicOperations.ZeroMemory(businessPayload);
            businessPayload = [];
        }
    }

    /// <inheritdoc />
    public override string ToString() =>
        $"TypedComposedSoapRequestContext(ConnectorId={ConnectorId}, OperationId={OperationId}, CorrelationId={CorrelationId:D}, BusinessPayloadLength={BusinessPayloadLength}, Redacted=True)";
}

/// <summary>Immutable bounded startup registry for composed-SOAP request adapters.</summary>
internal sealed class TypedComposedSoapRequestAdapterRegistry
{
    private const int MaximumAdapters = 256;
    private readonly Dictionary<(string Id, string Type), RegisteredTypedComposedSoapRequestAdapter> adapters;

    /// <summary>Snapshots exact adapter identity and required inputs during trusted composition.</summary>
    internal TypedComposedSoapRequestAdapterRegistry(IEnumerable<ITypedComposedSoapRequestAdapter> values)
    {
        adapters = [];
        foreach (ITypedComposedSoapRequestAdapter value in values ?? throw new ArgumentNullException(nameof(values)))
        {
            string[] requiredSnapshot = value.RequiredServerOwnedInputs?.ToArray()
                ?? throw TypedComposedSoapRequestFailures.Configuration();
            if (adapters.Count >= MaximumAdapters ||
                !TypedSessionHandshakeValidation.Identifier(value.AdapterId) ||
                !TypedSessionHandshakeValidation.Identifier(value.AdapterType) ||
                requiredSnapshot.Length > AuthorizedConnectorBindingInputs.MaximumInputs ||
                requiredSnapshot.Any(name => !TypedSessionHandshakeValidation.Identifier(name)))
                throw TypedComposedSoapRequestFailures.Configuration();
            FrozenSet<string> required = requiredSnapshot.ToFrozenSet(StringComparer.Ordinal);
            if (required.Count != requiredSnapshot.Length ||
                !adapters.TryAdd((value.AdapterId, value.AdapterType), new(value, required)))
                throw TypedComposedSoapRequestFailures.Configuration();
        }
    }

    internal RegisteredTypedComposedSoapRequestAdapter Required(string id, string type) =>
        adapters.TryGetValue((id, type), out RegisteredTypedComposedSoapRequestAdapter? value)
            ? value
            : throw TypedComposedSoapRequestFailures.AdapterUnavailable();
}

internal sealed record RegisteredTypedComposedSoapRequestAdapter(
    ITypedComposedSoapRequestAdapter Adapter,
    IReadOnlySet<string> RequiredServerOwnedInputs);

internal sealed record TypedComposedSoapRequestAuthority(
    ITypedComposedSoapRequestAdapter Adapter,
    SoapElementRule RequestElement,
    IReadOnlyList<ServerOwnedBindingInputReference> BindingInputs,
    long MaximumRequestBytes,
    string SecurityFingerprint);

internal sealed class TypedComposedSoapRequestSnapshot : IDisposable
{
    private byte[] bytes;
    private int disposed;

    internal TypedComposedSoapRequestSnapshot(byte[] bytes) => this.bytes = bytes ?? throw new ArgumentNullException(nameof(bytes));

    internal ReadOnlyMemory<byte> Bytes => Volatile.Read(ref disposed) == 0
        ? bytes
        : throw new ObjectDisposedException(nameof(TypedComposedSoapRequestSnapshot));

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        CryptographicOperations.ZeroMemory(bytes);
        bytes = [];
    }
}

internal static class TypedComposedSoapRequestAdapterDefaults
{
    internal static readonly IReadOnlySet<string> NoServerOwnedInputs =
        Array.Empty<string>().ToFrozenSet(StringComparer.Ordinal);
}

internal static class TypedComposedSoapRequestFailures
{
    internal static SoapAuthException Configuration() => new("SOAP-TYPED-COMPOSED-CONFIGURATION");
    internal static SoapAuthException AdapterUnavailable() => new("SOAP-TYPED-COMPOSED-ADAPTER-UNAVAILABLE");
    internal static SoapAuthException BindingInputUnavailable() => new("SOAP-TYPED-COMPOSED-BINDING-INPUT-UNAVAILABLE");
    internal static SoapAuthException RequestRejected() => new("SOAP-TYPED-COMPOSED-REQUEST-REJECTED");
}

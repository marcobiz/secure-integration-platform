using System.Security.Cryptography;
using System.Xml;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>
/// Immutable bounded server-owned input set resolved for one exact adapter call. Values can only be
/// written through the Core-owned XML writer and are cleared when that synchronous call ends.
/// </summary>
public sealed class AuthorizedConnectorBindingInputs
{
    internal const int MaximumInputs = 16;
    internal const int MaximumValueCharacters = 4_096;
    internal const int MaximumTotalValueCharacters = 32_768;

    private readonly Dictionary<string, char[]> values;
    private readonly object synchronization = new();
    private CoreOwnedAdapterXmlWriter? boundWriter;
    private int state;

    internal AuthorizedConnectorBindingInputs(IReadOnlyDictionary<string, string> resolved)
    {
        ArgumentNullException.ThrowIfNull(resolved);
        if (resolved.Count > MaximumInputs) throw TypedSessionHandshakeFailures.BindingInputRejected();
        values = new(StringComparer.Ordinal);
        int total = 0;
        try
        {
            foreach ((string name, string value) in resolved.OrderBy(item => item.Key, StringComparer.Ordinal))
            {
                if (!TypedSessionHandshakeValidation.Identifier(name) || string.IsNullOrWhiteSpace(value) ||
                    value.Length > MaximumValueCharacters || value.Any(character => character is '\r' or '\n' or '\0' || char.IsControl(character)) ||
                    !values.TryAdd(name, value.ToCharArray()))
                    throw TypedSessionHandshakeFailures.BindingInputRejected();
                total = checked(total + value.Length);
                if (total > MaximumTotalValueCharacters) throw TypedSessionHandshakeFailures.BindingInputRejected();
            }
        }
        catch
        {
            ClearValues();
            throw;
        }
    }

    /// <summary>Exact number of Published-declared and adapter-required values.</summary>
    public int Count => values.Count;

    /// <summary>Returns whether the exact declared name is present; it never reveals a value.</summary>
    public bool Contains(string name)
    {
        lock (synchronization)
            return state == 1 && values.ContainsKey(name);
    }

    /// <summary>
    /// Writes the required value only as text of the current Core-owned XML element. Attribute
    /// emission is denied so stateful XML APIs cannot retain or reveal the value. No string,
    /// provider reference or mutable backing buffer is returned to the adapter.
    /// </summary>
    public void WriteRequiredXmlValue(string name)
    {
        lock (synchronization)
        {
            if (state != 1 || boundWriter is null || !values.TryGetValue(name, out char[]? value))
                throw TypedSessionHandshakeFailures.BindingInputRejected();
            boundWriter.WriteAuthorizedElementValue(value);
        }
    }

    internal IDisposable BindToCoreWriter(XmlWriter writer)
    {
        ArgumentNullException.ThrowIfNull(writer);
        if (writer is not CoreOwnedAdapterXmlWriter coreWriter)
            throw TypedSessionHandshakeFailures.BindingInputRejected();
        lock (synchronization)
        {
            if (state != 0 || boundWriter is not null)
                throw TypedSessionHandshakeFailures.BindingInputRejected();
            boundWriter = coreWriter;
            state = 1;
            return new BindingScope(this);
        }
    }

    internal void Clear()
    {
        lock (synchronization)
        {
            if (state == 2) return;
            state = 2;
            boundWriter = null;
            ClearValues();
        }
    }

    private void ClearValues()
    {
        foreach (char[] value in values.Values)
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(value.AsSpan()));
        values.Clear();
    }

    /// <inheritdoc />
    public override string ToString() => $"AuthorizedConnectorBindingInputs(Count={values.Count}, Redacted=True)";

    private sealed class BindingScope(AuthorizedConnectorBindingInputs owner) : IDisposable
    {
        private int disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0)
                owner.Clear();
        }
    }
}

internal sealed record ServerOwnedBindingInputReference(
    string Name,
    string LogicalBindingId,
    string ProviderReference);

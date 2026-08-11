using System.Xml;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>
/// Callback-scoped serialized proxy over the Core-owned writer. Authorized binding values use the
/// same lock and may be emitted only as element text, so adapter-visible XML state can never retain
/// a secret as <c>xml:lang</c>, <c>xml:space</c> or a namespace URI.
/// </summary>
internal sealed class CoreOwnedAdapterXmlWriter(XmlWriter inner) : XmlWriter
{
    private readonly object synchronization = new();
    private bool active = true;
    private bool attributeOpen;

    internal void WriteAuthorizedElementValue(char[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        lock (synchronization)
        {
            EnsureActive();
            if (attributeOpen || inner.WriteState is not (WriteState.Element or WriteState.Content))
                throw TypedSessionHandshakeFailures.BindingInputRejected();
            inner.WriteChars(value, 0, value.Length);
        }
    }

    internal void CompleteCallback()
    {
        lock (synchronization)
        {
            active = false;
            attributeOpen = false;
        }
    }

    public override XmlWriterSettings? Settings => Read(() => inner.Settings);
    public override WriteState WriteState => Read(() => inner.WriteState);
    public override string XmlLang => Read(() => inner.XmlLang ?? string.Empty);
    public override XmlSpace XmlSpace => Read(() => inner.XmlSpace);

    public override void Flush() => Write(inner.Flush);
    public override string? LookupPrefix(string ns) => Read(() => inner.LookupPrefix(ns));
    public override void WriteBase64(byte[] buffer, int index, int count) => Write(() => inner.WriteBase64(buffer, index, count));
    public override void WriteCData(string? text) => Write(() => inner.WriteCData(text));
    public override void WriteCharEntity(char ch) => Write(() => inner.WriteCharEntity(ch));
    public override void WriteChars(char[] buffer, int index, int count) => Write(() => inner.WriteChars(buffer, index, count));
    public override void WriteComment(string? text) => Write(() => inner.WriteComment(text));
    public override void WriteDocType(string name, string? pubid, string? sysid, string? subset) =>
        Write(() => inner.WriteDocType(name, pubid, sysid, subset));

    public override void WriteEndAttribute()
    {
        lock (synchronization)
        {
            EnsureActive();
            inner.WriteEndAttribute();
            attributeOpen = false;
        }
    }

    public override void WriteEndDocument() => Write(inner.WriteEndDocument);
    public override void WriteEndElement() => Write(inner.WriteEndElement);
    public override void WriteEntityRef(string name) => Write(() => inner.WriteEntityRef(name));
    public override void WriteFullEndElement() => Write(inner.WriteFullEndElement);
    public override void WriteProcessingInstruction(string name, string? text) =>
        Write(() => inner.WriteProcessingInstruction(name, text));
    public override void WriteRaw(char[] buffer, int index, int count) => Write(() => inner.WriteRaw(buffer, index, count));
    public override void WriteRaw(string data) => Write(() => inner.WriteRaw(data));

    public override void WriteStartAttribute(string? prefix, string localName, string? ns)
    {
        lock (synchronization)
        {
            EnsureActive();
            inner.WriteStartAttribute(prefix, localName, ns);
            attributeOpen = true;
        }
    }

    public override void WriteStartDocument() => Write(inner.WriteStartDocument);
    public override void WriteStartDocument(bool standalone) => Write(() => inner.WriteStartDocument(standalone));
    public override void WriteStartElement(string? prefix, string localName, string? ns) =>
        Write(() => inner.WriteStartElement(prefix, localName, ns));
    public override void WriteString(string? text) => Write(() => inner.WriteString(text));
    public override void WriteSurrogateCharEntity(char lowChar, char highChar) =>
        Write(() => inner.WriteSurrogateCharEntity(lowChar, highChar));
    public override void WriteWhitespace(string? ws) => Write(() => inner.WriteWhitespace(ws));

    public override void Close() => CompleteCallback();

    protected override void Dispose(bool disposing)
    {
        if (disposing) CompleteCallback();
        base.Dispose(disposing);
    }

    private T Read<T>(Func<T> action)
    {
        lock (synchronization)
        {
            EnsureActive();
            return action();
        }
    }

    private void Write(Action action)
    {
        lock (synchronization)
        {
            EnsureActive();
            action();
            attributeOpen = inner.WriteState == WriteState.Attribute;
        }
    }

    private void EnsureActive()
    {
        if (!active) throw TypedSessionHandshakeFailures.BindingInputRejected();
    }
}

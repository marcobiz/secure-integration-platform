using System.Net.Http.Headers;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>Hardened request/response bridge for registered typed session-handshake adapters.</summary>
internal static class TypedSessionHandshakeXmlBoundary
{
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static byte[] SerializeRequest(TypedSessionHandshakeAuthorityState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        byte[] fragment = SerializeAdapterFragment(state);
        XDocument fragmentDocument = SoapXmlBoundary.LoadHardened(fragment, state.Operation.MaximumRequestBytes, CancellationToken.None);
        XElement wrapper = fragmentDocument.Root ?? throw TypedSessionHandshakeFailures.AdapterRejected();
        if (wrapper.Name != XName.Get("AdapterPayload", "urn:secure-integration:typed-session-handshake:internal") ||
            wrapper.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration))
            throw TypedSessionHandshakeFailures.AdapterRejected();

        try
        {
            using BoundedWriteStream output = new(state.Operation.MaximumRequestBytes);
            using (XmlWriter writer = XmlWriter.Create(output, Settings()))
            {
                string envelopeNamespace = SoapXmlBoundary.EnvelopeNamespace(state.Operation.Version);
                writer.WriteStartElement("soap", "Envelope", envelopeNamespace);
                writer.WriteStartElement("soap", "Body", envelopeNamespace);
                writer.WriteStartElement("op", state.Operation.RequestElement.LocalName, state.Operation.RequestElement.NamespaceUri);
                foreach (XNode node in wrapper.Nodes()) node.WriteTo(writer);
                writer.WriteEndElement();
                writer.WriteEndElement();
                writer.WriteEndElement();
            }
            if (output.Length > state.Operation.MaximumRequestBytes) throw new SoapAuthException("SOAP-REQUEST-TOO-LARGE");
            return output.ToArray();
        }
        catch (SoapAuthException) { throw; }
        catch (Exception exception) when (exception is XmlException or InvalidOperationException or ArgumentException)
        {
            throw TypedSessionHandshakeFailures.AdapterRejected();
        }
    }

    internal static TypedSessionHandshakeAdapterOutcome ParseResponse(
        TypedSessionHandshakeAuthorityState state,
        ExternalResponse response,
        CancellationToken cancellationToken)
    {
        XElement payload = SoapXmlBoundary.ParseTypedPayload(state.Operation, response,
            new Dictionary<(string LocalName, string NamespaceUri), SoapFaultCategory>(), cancellationToken);
        try
        {
            using XmlReader reader = payload.CreateReader();
            if (reader.MoveToContent() != XmlNodeType.Element) throw TypedSessionHandshakeFailures.AdapterRejected();
            TypedSessionHandshakeAdapterOutcome outcome = state.ResponseAdapter.ReadResponse(reader, new(state))
                ?? throw TypedSessionHandshakeFailures.AdapterRejected();
            cancellationToken.ThrowIfCancellationRequested();
            return outcome;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception) { throw TypedSessionHandshakeFailures.AdapterRejected(); }
    }

    internal static void ApplyHttpHeaders(HttpRequestMessage request, SoapOperationProfile operation, byte[] envelope)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Content is not null || request.Headers.Contains("SOAPAction")) throw new SoapAuthException("SOAP-HTTP-POLICY-VIOLATION");
        request.Content = new ByteArrayContent(envelope);
        if (operation.Version == SoapEnvelopeVersion.Soap11)
        {
            request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("text/xml; charset=utf-8");
            request.Headers.TryAddWithoutValidation("SOAPAction", '"' + operation.Action + '"');
        }
        else
        {
            request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/soap+xml; charset=utf-8; action=\"" + operation.Action + "\"");
        }
    }

    private static byte[] SerializeAdapterFragment(TypedSessionHandshakeAuthorityState state)
    {
        try
        {
            using BoundedWriteStream fragment = new(state.Operation.MaximumRequestBytes);
            using (XmlWriter writer = XmlWriter.Create(fragment, Settings()))
            {
                writer.WriteStartElement("core", "AdapterPayload", "urn:secure-integration:typed-session-handshake:internal");
                try { state.RequestAdapter.WriteRequest(writer, new(state)); }
                catch (SoapAuthException exception) when (string.Equals(exception.Code, "SOAP-REQUEST-TOO-LARGE", StringComparison.Ordinal)) { throw; }
                catch (Exception) { throw TypedSessionHandshakeFailures.AdapterRejected(); }
                writer.WriteEndElement();
            }
            if (fragment.Length > state.Operation.MaximumRequestBytes) throw new SoapAuthException("SOAP-REQUEST-TOO-LARGE");
            return fragment.ToArray();
        }
        catch (SoapAuthException) { throw; }
        catch (Exception exception) when (exception is XmlException or InvalidOperationException or ArgumentException)
        {
            throw TypedSessionHandshakeFailures.AdapterRejected();
        }
    }

    private static XmlWriterSettings Settings() => new()
    {
        Encoding = Utf8,
        OmitXmlDeclaration = true,
        Indent = false,
        NewLineHandling = NewLineHandling.None,
        CheckCharacters = true,
        CloseOutput = false
    };

    private sealed class BoundedWriteStream(long maximumBytes) : Stream
    {
        private readonly MemoryStream inner = new();

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => throw new NotSupportedException(); }

        internal byte[] ToArray() => inner.ToArray();
        public override void Flush() => inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            Ensure(count);
            inner.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Ensure(buffer.Length);
            inner.Write(buffer);
        }

        public override void WriteByte(byte value)
        {
            Ensure(1);
            inner.WriteByte(value);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) inner.Dispose();
            base.Dispose(disposing);
        }

        private void Ensure(int count)
        {
            if (count < 0 || inner.Length + count > maximumBytes) throw new SoapAuthException("SOAP-REQUEST-TOO-LARGE");
        }
    }
}

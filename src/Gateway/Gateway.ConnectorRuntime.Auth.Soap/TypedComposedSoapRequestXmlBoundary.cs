using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>Hardened Core-owned XML boundary for one compiled composed-SOAP request adapter.</summary>
internal static class TypedComposedSoapRequestXmlBoundary
{
    private const string InternalNamespace = "urn:secure-integration:typed-composed-soap:internal";
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static TypedComposedSoapRequestSnapshot Serialize(
        ComposedSoapAuthorityState state,
        ReadOnlyMemory<byte> businessPayload,
        AuthorizedConnectorBindingInputs serverOwnedInputs,
        CancellationToken cancellationToken)
    {
        TypedComposedSoapRequestAuthority authority = state.TypedRequest
            ?? throw TypedComposedSoapRequestFailures.RequestRejected();
        byte[] fragment = [];
        TypedComposedSoapRequestContext? context = null;
        try
        {
            using (ClearingBoundedWriteStream output = new(authority.MaximumRequestBytes))
            {
                using (XmlWriter writer = XmlWriter.Create(output, Settings()))
                {
                    writer.WriteStartElement("core", "AdapterPayload", InternalNamespace);
                    context = new(state, businessPayload, serverOwnedInputs);
                    try
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        using (serverOwnedInputs.BindToCoreWriter(writer))
                            authority.Adapter.WriteRequest(writer, context);
                        cancellationToken.ThrowIfCancellationRequested();
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        throw new OperationCanceledException(cancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                        throw TypedComposedSoapRequestFailures.RequestRejected();
                    }
                    catch (SoapAuthException exception) when (string.Equals(exception.Code, "SOAP-REQUEST-TOO-LARGE", StringComparison.Ordinal))
                    {
                        throw;
                    }
                    catch (Exception)
                    {
                        throw TypedComposedSoapRequestFailures.RequestRejected();
                    }
                    finally
                    {
                        context.Clear();
                    }
                    writer.WriteEndElement();
                }
                fragment = output.ToArray();
            }

            XDocument document = SoapXmlBoundary.LoadHardened(fragment, authority.MaximumRequestBytes, cancellationToken);
            XElement wrapper = document.Root ?? throw TypedComposedSoapRequestFailures.RequestRejected();
            if (wrapper.Name != XName.Get("AdapterPayload", InternalNamespace) ||
                wrapper.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration))
                throw TypedComposedSoapRequestFailures.RequestRejected();

            using ClearingBoundedWriteStream envelope = new(authority.MaximumRequestBytes);
            using (XmlWriter writer = XmlWriter.Create(envelope, Settings()))
            {
                string envelopeNamespace = SoapXmlBoundary.EnvelopeNamespace(state.SoapHttp.Version);
                writer.WriteStartElement("soap", "Envelope", envelopeNamespace);
                writer.WriteStartElement("soap", "Body", envelopeNamespace);
                writer.WriteStartElement("op", authority.RequestElement.LocalName, authority.RequestElement.NamespaceUri);
                foreach (XNode node in wrapper.Nodes()) node.WriteTo(writer);
                writer.WriteEndElement();
                writer.WriteEndElement();
                writer.WriteEndElement();
            }
            return new(envelope.ToArray());
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw TypedComposedSoapRequestFailures.RequestRejected();
        }
        catch (SoapAuthException)
        {
            throw;
        }
        catch (Exception exception) when (exception is XmlException or InvalidOperationException or ArgumentException)
        {
            throw TypedComposedSoapRequestFailures.RequestRejected();
        }
        finally
        {
            context?.Clear();
            CryptographicOperations.ZeroMemory(fragment);
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

    private sealed class ClearingBoundedWriteStream(long maximumBytes) : Stream
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
            if (disposing)
            {
                if (inner.TryGetBuffer(out ArraySegment<byte> buffer) && buffer.Array is not null)
                    CryptographicOperations.ZeroMemory(buffer.Array.AsSpan(buffer.Offset, buffer.Count));
                inner.Dispose();
            }
            base.Dispose(disposing);
        }

        private void Ensure(int count)
        {
            if (count < 0 || inner.Length + count > maximumBytes)
                throw new SoapAuthException("SOAP-REQUEST-TOO-LARGE");
        }
    }
}

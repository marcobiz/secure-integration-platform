using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace SecureIntegration.ConnectorPacks.Healthcare.SistemaTs;

internal static class SistemaTsBusinessXml
{
    private static readonly XNamespace Soap11 = "http://schemas.xmlsoap.org/soap/envelope/";

    internal static void ValidateRequest(SistemaTsBusinessOperation operation, byte[] payload) =>
        Validate(operation, payload, request: true);

    internal static void ValidateResponse(SistemaTsBusinessOperation operation, byte[] payload) =>
        Validate(operation, payload, request: false);

    internal static byte[] SerializeRequest(SistemaTsBusinessOperation operation, IReadOnlyList<SistemaTsXmlValue> values) =>
        Serialize(operation, values, request: true);

    internal static byte[] SerializeResponse(SistemaTsBusinessOperation operation, IReadOnlyList<SistemaTsXmlValue> values) =>
        Serialize(operation, values, request: false);

    private static void Validate(SistemaTsBusinessOperation operation, byte[] payload, bool request)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(payload);
        try
        {
            using MemoryStream source = new(payload, writable: false);
            using XmlReader reader = XmlReader.Create(source, ReaderSettings());
            XDocument document = XDocument.Load(reader, LoadOptions.None);
            if (HasNonElementContent(document)) throw Malformed();
            XElement envelope = document.Root ?? throw Malformed();
            RequireNameAndNoAttributes(envelope, Soap11 + "Envelope");
            XElement[] envelopeChildren = envelope.Elements().ToArray();
            if (envelopeChildren.Length != 1 || envelopeChildren[0].Name != Soap11 + "Body" ||
                HasNonElementContent(envelope)) throw Malformed();
            XElement body = envelopeChildren[0];
            RequireNoAttributes(body);
            XElement[] bodyChildren = body.Elements().ToArray();
            if (bodyChildren.Length != 1 || HasNonElementContent(body)) throw Malformed();

            XName rootName = XName.Get(request ? operation.RequestRoot : operation.ResponseRoot,
                request ? operation.RequestNamespace : operation.ResponseNamespace);
            XElement root = bodyChildren[0];
            RequireNameAndNoAttributes(root, rootName);
            int nodes = 1;
            ValidateSequence(root, request ? operation.RequestElements : operation.ResponseElements, 1, ref nodes);
        }
        catch (Exception exception) when (exception is XmlException or InvalidOperationException or ArgumentException or FormatException)
        {
            throw new InvalidOperationException("Sistema TS SOAP payload is outside the frozen contract.");
        }
    }

    private static byte[] Serialize(SistemaTsBusinessOperation operation, IReadOnlyList<SistemaTsXmlValue> values, bool request)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(values);
        string rootNamespace = request ? operation.RequestNamespace : operation.ResponseNamespace;
        string rootName = request ? operation.RequestRoot : operation.ResponseRoot;
        IReadOnlyList<SistemaTsXmlElementSpec> specifications = request ? operation.RequestElements : operation.ResponseElements;
        int nodes = 1;
        XElement root = new(XName.Get(rootName, rootNamespace));
        foreach (XElement child in BuildSequence(values, specifications, 1, ref nodes)) root.Add(child);
        XDocument document = new(new XElement(Soap11 + "Envelope", new XElement(Soap11 + "Body", root)));
        using MemoryStream output = new();
        using (XmlWriter writer = XmlWriter.Create(output, new XmlWriterSettings
        {
            Encoding = new UTF8Encoding(false, true),
            OmitXmlDeclaration = true,
            Indent = false,
            NamespaceHandling = NamespaceHandling.OmitDuplicates
        }))
        {
            document.WriteTo(writer);
        }
        byte[] result = output.ToArray();
        if (request) ValidateRequest(operation, result); else ValidateResponse(operation, result);
        return result;
    }

    private static void ValidateSequence(XElement parent, IReadOnlyList<SistemaTsXmlElementSpec> specifications,
        int depth, ref int nodes)
    {
        if (depth > 16 || HasNonElementContent(parent)) throw Malformed();
        XElement[] children = parent.Elements().ToArray();
        int childIndex = 0;
        foreach (SistemaTsXmlElementSpec specification in specifications)
        {
            int count = 0;
            XName expectedName = XName.Get(specification.Name, specification.NamespaceUri);
            while (childIndex < children.Length && children[childIndex].Name == expectedName)
            {
                if (++count > specification.MaximumOccurs) throw Malformed();
                ValidateElement(children[childIndex++], specification, depth, ref nodes);
            }
            if (count < specification.MinimumOccurs) throw Malformed();
        }
        if (childIndex != children.Length) throw Malformed();
    }

    private static void ValidateElement(XElement element, SistemaTsXmlElementSpec specification, int depth, ref int nodes)
    {
        if (depth > 16 || ++nodes > 512 || element.Name != XName.Get(specification.Name, specification.NamespaceUri))
            throw Malformed();
        RequireNoAttributes(element);
        if (specification.Scalar is not null)
        {
            if (specification.Children is not null || element.Elements().Any()) throw Malformed();
            XNode[] nodesInElement = element.Nodes().ToArray();
            if (nodesInElement.Any(node => node is not XText)) throw Malformed();
            string value = string.Concat(nodesInElement.Cast<XText>().Select(text => text.Value));
            ValidateScalar(value, specification.Scalar);
            return;
        }
        if (specification.Children is null) throw Malformed();
        ValidateSequence(element, specification.Children, depth + 1, ref nodes);
    }

    private static ReadOnlyCollection<XElement> BuildSequence(IReadOnlyList<SistemaTsXmlValue> values,
        IReadOnlyList<SistemaTsXmlElementSpec> specifications, int depth, ref int nodes)
    {
        if (depth > 16) throw Malformed();
        List<XElement> elements = [];
        int valueIndex = 0;
        foreach (SistemaTsXmlElementSpec specification in specifications)
        {
            int count = 0;
            while (valueIndex < values.Count && string.Equals(values[valueIndex].Name, specification.Name, StringComparison.Ordinal))
            {
                if (++count > specification.MaximumOccurs) throw Malformed();
                elements.Add(BuildElement(values[valueIndex++], specification, depth, ref nodes));
            }
            if (count < specification.MinimumOccurs) throw Malformed();
        }
        if (valueIndex != values.Count) throw Malformed();
        return elements.AsReadOnly();
    }

    private static XElement BuildElement(SistemaTsXmlValue value, SistemaTsXmlElementSpec specification,
        int depth, ref int nodes)
    {
        if (++nodes > 512 || !string.Equals(value.Name, specification.Name, StringComparison.Ordinal)) throw Malformed();
        XElement element = new(XName.Get(specification.Name, specification.NamespaceUri));
        if (specification.Scalar is not null)
        {
            if (value.Children is { Count: > 0 }) throw Malformed();
            string text = value.Text ?? string.Empty;
            ValidateScalar(text, specification.Scalar);
            element.Value = text;
            return element;
        }
        if (specification.Children is null || !string.IsNullOrEmpty(value.Text)) throw Malformed();
        IReadOnlyList<SistemaTsXmlValue> children = value.Children ?? [];
        foreach (XElement child in BuildSequence(children, specification.Children, depth + 1, ref nodes)) element.Add(child);
        return element;
    }

    private static void ValidateScalar(string value, SistemaTsXmlScalar scalar)
    {
        if (value.Length < scalar.MinimumLength || value.Length > scalar.MaximumLength || ContainsControl(value) ||
            scalar.AllowedValues is not null && !scalar.AllowedValues.Contains(value)) throw Malformed();
        switch (scalar.LexicalKind)
        {
            case SistemaTsXmlLexicalKind.String:
                return;
            case SistemaTsXmlLexicalKind.AsciiDigits:
                if (value.Any(character => !char.IsAsciiDigit(character))) throw Malformed();
                return;
            case SistemaTsXmlLexicalKind.AsciiAlphanumeric:
                if (value.Any(character => !char.IsAsciiLetterOrDigit(character))) throw Malformed();
                return;
            case SistemaTsXmlLexicalKind.NonNegativeIntegerMaximumThreeDigits:
                if (value.Any(character => !char.IsAsciiDigit(character)) || value.Length > 1 && value[0] == '0') throw Malformed();
                return;
            case SistemaTsXmlLexicalKind.Base64:
                byte[] decoded;
                try { decoded = Convert.FromBase64String(value); }
                catch (FormatException) { throw Malformed(); }
                CryptographicOperations.ZeroMemory(decoded);
                return;
            default:
                throw Malformed();
        }
    }

    private static XmlReaderSettings ReaderSettings() => new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersInDocument = 16 * 1024 * 1024,
        MaxCharactersFromEntities = 0,
        IgnoreComments = false,
        IgnoreProcessingInstructions = false
    };

    private static void RequireNameAndNoAttributes(XElement element, XName expected)
    {
        if (element.Name != expected) throw Malformed();
        RequireNoAttributes(element);
    }

    private static void RequireNoAttributes(XElement element)
    {
        if (element.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)) throw Malformed();
    }

    private static bool HasNonElementContent(XContainer container) => container.Nodes().Any(node => node switch
    {
        XElement => false,
        XText text => !string.IsNullOrWhiteSpace(text.Value),
        _ => true
    });

    private static bool ContainsControl(string value) => value.Any(character =>
        character is < ' ' and not ('\t' or '\r' or '\n') || character is >= '\u007f' and <= '\u009f');

    private static InvalidOperationException Malformed() => new("Malformed Sistema TS XML.");
}

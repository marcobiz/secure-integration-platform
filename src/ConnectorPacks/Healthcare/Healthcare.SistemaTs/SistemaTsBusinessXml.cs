using System.Xml;
using System.Xml.Linq;

namespace SecureIntegration.ConnectorPacks.Healthcare.SistemaTs;

internal static class SistemaTsBusinessXml
{
    private static readonly XNamespace Soap11 = "http://schemas.xmlsoap.org/soap/envelope/";
    private static readonly XNamespace CommonData = "http://tipodati.xsd.dem.sanita.finanze.it";

    internal static void ValidateRequest(SistemaTsBusinessOperation operation, ReadOnlySpan<byte> payload) =>
        Validate(operation, payload, request: true);

    internal static void ValidateResponse(SistemaTsBusinessOperation operation, ReadOnlySpan<byte> payload) =>
        Validate(operation, payload, request: false);

    private static void Validate(SistemaTsBusinessOperation operation, ReadOnlySpan<byte> payload, bool request)
    {
        try
        {
            using MemoryStream source = new(payload.ToArray(), writable: false);
            using XmlReader reader = XmlReader.Create(source, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 16 * 1024 * 1024,
                MaxCharactersFromEntities = 0,
                IgnoreComments = false,
                IgnoreProcessingInstructions = false
            });
            XDocument document = XDocument.Load(reader, LoadOptions.None);
            XElement envelope = document.Root ?? throw Malformed();
            RequireNameAndNoAttributes(envelope, Soap11 + "Envelope");
            XElement[] envelopeChildren = envelope.Elements().ToArray();
            if (envelopeChildren.Length != 1 || envelopeChildren[0].Name != Soap11 + "Body") throw Malformed();
            XElement body = envelopeChildren[0];
            RequireNoAttributes(body);
            XElement[] bodyChildren = body.Elements().ToArray();
            if (bodyChildren.Length != 1 || HasNonElementContent(document) || HasNonElementContent(body)) throw Malformed();

            XName rootName = XName.Get(request ? operation.RequestRoot : operation.ResponseRoot,
                request ? operation.RequestNamespace : operation.ResponseNamespace);
            XElement root = bodyChildren[0];
            RequireNameAndNoAttributes(root, rootName);
            ValidateOrderedFields(root, request ? operation.RequestFields : operation.ResponseFields, rootName.Namespace,
                request ? null : operation.ResultField);
            int nodes = 0;
            ValidateTree(root, rootName.Namespace, 0, ref nodes);
        }
        catch (Exception exception) when (exception is XmlException or InvalidOperationException or ArgumentException)
        {
            throw new InvalidOperationException("Sistema TS SOAP payload is outside the frozen contract.");
        }
    }

    private static void ValidateOrderedFields(XElement root, IReadOnlyList<SistemaTsXmlField> fields,
        XNamespace rootNamespace, string? requiredResult)
    {
        XElement[] children = root.Elements().ToArray();
        int fieldIndex = 0;
        bool resultSeen = false;
        foreach (XElement child in children)
        {
            while (fieldIndex < fields.Count && !fields[fieldIndex].Required &&
                   !Matches(child, fields[fieldIndex], rootNamespace)) fieldIndex++;
            if (fieldIndex >= fields.Count || !Matches(child, fields[fieldIndex], rootNamespace)) throw Malformed();
            if (child.Name.LocalName == requiredResult)
            {
                string code = child.Value;
                if (code.Length is < 1 or > 4 || !code.All(char.IsAsciiDigit)) throw Malformed();
                resultSeen = true;
            }
            fieldIndex++;
        }
        while (fieldIndex < fields.Count && !fields[fieldIndex].Required) fieldIndex++;
        if (fieldIndex != fields.Count || requiredResult is not null && !resultSeen) throw Malformed();
    }

    private static bool Matches(XElement element, SistemaTsXmlField field, XNamespace rootNamespace) =>
        element.Name.LocalName == field.Name && element.Name.Namespace == rootNamespace;

    private static void ValidateTree(XElement element, XNamespace rootNamespace, int depth, ref int nodes)
    {
        if (depth > 16 || ++nodes > 512) throw Malformed();
        RequireNoAttributes(element);
        if (element.Name.Namespace != rootNamespace && element.Name.Namespace != CommonData) throw Malformed();
        XNode[] content = element.Nodes().ToArray();
        bool hasElements = content.Any(node => node is XElement);
        foreach (XNode node in content)
        {
            if (node is XElement child) ValidateTree(child, rootNamespace, depth + 1, ref nodes);
            else if (node is XText text)
            {
                if (hasElements && !string.IsNullOrWhiteSpace(text.Value) || text.Value.Length > 16_384 || ContainsControl(text.Value))
                    throw Malformed();
            }
            else throw Malformed();
        }
    }

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

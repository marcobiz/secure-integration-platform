using System.Collections.ObjectModel;
using System.Net.Http.Headers;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>Deterministic serializer and hardened parser used only behind the opaque session client.</summary>
internal static class SoapXmlBoundary
{
    private const int MaximumDepth = 32;
    private const int MaximumNodes = 10_000;
    private const int MaximumAttributesPerElement = 32;
    private const int MaximumAttributes = 1_024;
    private const int MaximumExtractedCharacters = 65_536;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    /// <summary>Creates a bounded deterministic SOAP request for one allowlisted operation.</summary>
    internal static byte[] SerializeRequest(SoapOperationProfile operation, IReadOnlyDictionary<string, string>? values, SoapElementRule? sessionHeader, string? sessionValue)
    {
        ArgumentNullException.ThrowIfNull(operation);
        values ??= new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.Ordinal));
        if (values.Keys.Any(key => !operation.RequestFields.ContainsKey(key)) || operation.RequestFields.Keys.Any(key => !values.ContainsKey(key)))
            throw new SoapAuthException("SOAP-REQUEST-FIELD-MISMATCH");
        if ((sessionHeader is null) != (sessionValue is null)) throw new SoapAuthException("SOAP-SESSION-PLACEMENT-INVALID");
        if (sessionValue is { Length: > 4096 }) throw new SoapAuthException("SOAP-SESSION-INVALID");

        using MemoryStream output = new();
        XmlWriterSettings settings = new()
        {
            Encoding = Utf8,
            OmitXmlDeclaration = true,
            Indent = false,
            NewLineHandling = NewLineHandling.None,
            CheckCharacters = true,
            CloseOutput = false
        };
        using (XmlWriter writer = XmlWriter.Create(output, settings))
        {
            string envelopeNamespace = EnvelopeNamespace(operation.Version);
            writer.WriteStartElement("soap", "Envelope", envelopeNamespace);
            if (sessionHeader is not null)
            {
                writer.WriteStartElement("soap", "Header", envelopeNamespace);
                writer.WriteElementString("auth", sessionHeader.LocalName, sessionHeader.NamespaceUri, sessionValue);
                writer.WriteEndElement();
            }
            writer.WriteStartElement("soap", "Body", envelopeNamespace);
            writer.WriteStartElement("op", operation.RequestElement.LocalName, operation.RequestElement.NamespaceUri);
            foreach (SoapFieldRule field in operation.RequestFields.Values)
            {
                string value = values[field.LogicalName];
                if (value.Length > field.MaximumCharacters) throw new SoapAuthException("SOAP-REQUEST-FIELD-TOO-LARGE");
                writer.WriteElementString("f", field.Element.LocalName, field.Element.NamespaceUri, value);
            }
            writer.WriteEndElement();
            writer.WriteEndElement();
            writer.WriteEndElement();
        }
        if (output.Length > operation.MaximumRequestBytes) throw new SoapAuthException("SOAP-REQUEST-TOO-LARGE");
        return output.ToArray();
    }

    /// <summary>Applies the exact version-specific HTTP content type and SOAP action policy.</summary>
    internal static void ApplyHttpHeaders(HttpRequestMessage request, SoapOperationProfile operation, byte[] envelope)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(envelope);
        new SoapHttpRequestMetadata(operation.Version, operation.Action).Apply(request, envelope);
    }

    /// <summary>Validates a bounded caller-produced SOAP envelope against Published HTTP metadata.</summary>
    internal static byte[] ValidateRequestEnvelope(ReadOnlyMemory<byte> envelope, SoapHttpRequestMetadata metadata, long maximumRequestBytes)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        if (envelope.IsEmpty || envelope.Length > maximumRequestBytes || maximumRequestBytes is < 1 or > 16 * 1024 * 1024)
            throw new SoapAuthException("SOAP-REQUEST-INVALID");
        byte[] copy = envelope.ToArray();
        XDocument document = LoadHardened(copy, maximumRequestBytes, CancellationToken.None);
        string envelopeNamespace = EnvelopeNamespace(metadata.Version);
        XElement root = document.Root ?? throw new SoapAuthException("SOAP-XML-MALFORMED");
        if (root.Name != XName.Get("Envelope", envelopeNamespace) || root.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration) || HasSignificantText(root))
            throw new SoapAuthException("SOAP-ENVELOPE-NAMESPACE");
        XElement[] structural = root.Elements().ToArray();
        if (structural.Length != 1 || structural[0].Name != XName.Get("Body", envelopeNamespace) ||
            structural[0].Attributes().Any(attribute => !attribute.IsNamespaceDeclaration) || HasSignificantText(structural[0]) || structural[0].Elements().Count() != 1)
            throw new SoapAuthException("SOAP-ENVELOPE-STRUCTURE");
        return copy;
    }

    /// <summary>Parses one bounded response and returns only values allowlisted by the compiled profile.</summary>
    internal static SoapDecodedResponse ParseResponse(
        SoapOperationProfile operation,
        ExternalResponse response,
        SoapElementRule? sessionElement,
        SoapElementRule? challengeElement,
        IReadOnlyDictionary<(string LocalName, string NamespaceUri), SoapFaultCategory> faultRules) =>
        ParseResponse(operation, response, sessionElement, challengeElement, faultRules, CancellationToken.None);

    /// <summary>Parses one bounded response under the effective request deadline.</summary>
    internal static SoapDecodedResponse ParseResponse(
        SoapOperationProfile operation,
        ExternalResponse response,
        SoapElementRule? sessionElement,
        SoapElementRule? challengeElement,
        IReadOnlyDictionary<(string LocalName, string NamespaceUri), SoapFaultCategory> faultRules,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(response);
        if (response.Body.LongLength > operation.MaximumResponseBytes) throw new SoapAuthException("SOAP-RESPONSE-TOO-LARGE");
        ValidateContentType(operation.Version, response.ContentType);
        cancellationToken.ThrowIfCancellationRequested();
        XDocument document = LoadHardened(response.Body, operation.MaximumResponseBytes, cancellationToken);
        string envelopeNamespace = EnvelopeNamespace(operation.Version);
        XElement envelope = document.Root ?? throw new SoapAuthException("SOAP-XML-MALFORMED");
        if (envelope.Name != XName.Get("Envelope", envelopeNamespace)) throw new SoapAuthException("SOAP-ENVELOPE-NAMESPACE");
        if (envelope.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)) throw new SoapAuthException("SOAP-ENVELOPE-ATTRIBUTE");
        XElement[] structural = envelope.Elements().ToArray();
        if (structural.Length is < 1 or > 2 || structural.Count(element => element.Name == XName.Get("Body", envelopeNamespace)) != 1 || structural.Any(element => element.Name != XName.Get("Body", envelopeNamespace) && element.Name != XName.Get("Header", envelopeNamespace)))
            throw new SoapAuthException("SOAP-ENVELOPE-STRUCTURE");
        XElement body = structural.Single(element => element.Name == XName.Get("Body", envelopeNamespace));
        XElement[] payloads = body.Elements().ToArray();
        if (payloads.Length != 1) throw new SoapAuthException("SOAP-BODY-STRUCTURE");
        XElement payload = payloads[0];
        if (payload.Name == XName.Get("Fault", envelopeNamespace)) throw ParseFault(payload, operation.Version, faultRules, cancellationToken);
        if (response.StatusCode is < 200 or >= 300) throw new SoapAuthException("SOAP-UPSTREAM-HTTP");
        if (payload.Name != XName.Get(operation.ResponseElement.LocalName, operation.ResponseElement.NamespaceUri)) throw new SoapAuthException("SOAP-RESPONSE-NAMESPACE");

        Dictionary<string, string> mapped = new(StringComparer.Ordinal);
        string? session = null;
        string? challenge = null;
        HashSet<XName> seen = [];
        foreach (XElement child in payload.Elements())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!seen.Add(child.Name) || child.HasElements || child.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)) throw new SoapAuthException("SOAP-RESPONSE-STRUCTURE");
            string value = BoundedValue(child);
            SoapFieldRule? mappedField = operation.ResponseFields.Values.SingleOrDefault(field => child.Name == XName.Get(field.Element.LocalName, field.Element.NamespaceUri));
            if (mappedField is not null)
            {
                if (value.Length > mappedField.MaximumCharacters) throw new SoapAuthException("SOAP-RESPONSE-FIELD-TOO-LARGE");
                mapped.Add(mappedField.LogicalName, value);
            }
            else if (sessionElement is not null && child.Name == XName.Get(sessionElement.LocalName, sessionElement.NamespaceUri)) session = RequireSensitiveValue(value, "SOAP-SESSION-INVALID");
            else if (challengeElement is not null && child.Name == XName.Get(challengeElement.LocalName, challengeElement.NamespaceUri)) challenge = RequireSensitiveValue(value, "SOAP-CHALLENGE-INVALID");
            else throw new SoapAuthException("SOAP-RESPONSE-UNEXPECTED-ELEMENT");
        }
        return new SoapDecodedResponse(new ReadOnlyDictionary<string, string>(mapped), session, challenge);
    }

    private static XDocument LoadHardened(byte[] body, long maximumCharacters, CancellationToken cancellationToken)
    {
        XmlReaderSettings settings = new()
        {
            Async = false,
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 0,
            MaxCharactersInDocument = maximumCharacters,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
            IgnoreWhitespace = true,
            CloseInput = false
        };
        try
        {
            using MemoryStream input = new(body, writable: false);
            using XmlReader reader = XmlReader.Create(input, settings);
            int nodes = 0;
            int attributes = 0;
            while (reader.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (++nodes > MaximumNodes || reader.Depth > MaximumDepth) throw new SoapAuthException("SOAP-XML-COMPLEXITY");
                if (reader.NodeType == XmlNodeType.Element)
                {
                    if (reader.AttributeCount > MaximumAttributesPerElement || (attributes += reader.AttributeCount) > MaximumAttributes) throw new SoapAuthException("SOAP-XML-COMPLEXITY");
                }
            }
            input.Position = 0;
            using XmlReader documentReader = XmlReader.Create(input, settings);
            XDocument document = XDocument.Load(documentReader, LoadOptions.None);
            cancellationToken.ThrowIfCancellationRequested();
            return document;
        }
        catch (SoapAuthException) { throw; }
        catch (XmlException) { throw new SoapAuthException("SOAP-XML-MALFORMED"); }
        catch (DecoderFallbackException) { throw new SoapAuthException("SOAP-XML-MALFORMED"); }
    }

    private static SoapFaultException ParseFault(XElement fault, SoapEnvelopeVersion version, IReadOnlyDictionary<(string LocalName, string NamespaceUri), SoapFaultCategory> rules, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (fault.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration) || HasSignificantText(fault)) throw FaultStructure();
        XElement valueElement = version == SoapEnvelopeVersion.Soap11 ? ValidateSoap11Fault(fault) : ValidateSoap12Fault(fault);
        (string LocalName, string NamespaceUri)? code = ParseQualifiedName(valueElement);
        if (code is null) throw FaultStructure();
        return rules.TryGetValue(code.Value, out SoapFaultCategory category)
            ? new SoapFaultException(category)
            : new SoapFaultException(SoapFaultCategory.Unknown);
    }

    private static XElement ValidateSoap11Fault(XElement fault)
    {
        XName faultCode = XName.Get("faultcode");
        XName faultString = XName.Get("faultstring");
        XName faultActor = XName.Get("faultactor");
        XName detail = XName.Get("detail");
        XElement[] children = fault.Elements().ToArray();
        int index = 0;
        XElement code = TakeRequired(children, ref index, faultCode);
        XElement text = TakeRequired(children, ref index, faultString);
        ValidateSimpleFaultElement(code, allowXmlLang: false);
        ValidateSimpleFaultElement(text, allowXmlLang: false);
        if (index < children.Length && children[index].Name == faultActor) ValidateSimpleFaultElement(children[index++], allowXmlLang: false);
        if (index < children.Length && children[index].Name == detail)
        {
            if (children[index].Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)) throw FaultStructure();
            index++;
        }
        if (index != children.Length) throw FaultStructure();
        return code;
    }

    private static XElement ValidateSoap12Fault(XElement fault)
    {
        XNamespace soap = EnvelopeNamespace(SoapEnvelopeVersion.Soap12);
        XElement[] children = fault.Elements().ToArray();
        int index = 0;
        XElement code = TakeRequired(children, ref index, soap + "Code");
        XElement reason = TakeRequired(children, ref index, soap + "Reason");
        if (index < children.Length && children[index].Name == soap + "Node") ValidateSimpleFaultElement(children[index++], allowXmlLang: false);
        if (index < children.Length && children[index].Name == soap + "Role") ValidateSimpleFaultElement(children[index++], allowXmlLang: false);
        if (index < children.Length && children[index].Name == soap + "Detail")
        {
            if (children[index].Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)) throw FaultStructure();
            index++;
        }
        if (index != children.Length || code.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration) || reason.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration) || HasSignificantText(code) || HasSignificantText(reason)) throw FaultStructure();

        XElement[] codeChildren = code.Elements().ToArray();
        if (codeChildren.Length != 1 || codeChildren[0].Name != soap + "Value") throw FaultStructure();
        ValidateSimpleFaultElement(codeChildren[0], allowXmlLang: false);

        XElement[] reasonChildren = reason.Elements().ToArray();
        if (reasonChildren.Length != 1 || reasonChildren[0].Name != soap + "Text") throw FaultStructure();
        ValidateSimpleFaultElement(reasonChildren[0], allowXmlLang: true);
        return codeChildren[0];
    }

    private static XElement TakeRequired(XElement[] children, ref int index, XName expected)
    {
        if (index >= children.Length || children[index].Name != expected) throw FaultStructure();
        return children[index++];
    }

    private static void ValidateSimpleFaultElement(XElement element, bool allowXmlLang)
    {
        if (element.HasElements) throw FaultStructure();
        XAttribute[] nonNamespaceAttributes = element.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration).ToArray();
        if (!allowXmlLang && nonNamespaceAttributes.Length != 0) throw FaultStructure();
        if (allowXmlLang && (nonNamespaceAttributes.Length != 1 || nonNamespaceAttributes[0].Name != XNamespace.Xml + "lang" || string.IsNullOrWhiteSpace(nonNamespaceAttributes[0].Value))) throw FaultStructure();
        _ = BoundedValue(element);
    }

    private static bool HasSignificantText(XElement element) => element.Nodes().OfType<XText>().Any(text => !string.IsNullOrWhiteSpace(text.Value));
    private static SoapAuthException FaultStructure() => new("SOAP-FAULT-STRUCTURE");

    private static (string LocalName, string NamespaceUri)? ParseQualifiedName(XElement element)
    {
        string value = element.Value.Trim();
        if (value.Length == 0 || value.Length > 200) return null;
        int separator = value.IndexOf(':', StringComparison.Ordinal);
        if (separator < 0) return (value, element.GetDefaultNamespace().NamespaceName);
        if (separator == 0 || separator == value.Length - 1 || value.IndexOf(':', separator + 1) >= 0) return null;
        XNamespace? xmlNamespace = element.GetNamespaceOfPrefix(value[..separator]);
        return xmlNamespace is null ? null : (value[(separator + 1)..], xmlNamespace.NamespaceName);
    }

    private static void ValidateContentType(SoapEnvelopeVersion version, string contentType)
    {
        if (!MediaTypeHeaderValue.TryParse(contentType, out MediaTypeHeaderValue? parsed)) throw new SoapAuthException("SOAP-CONTENT-TYPE");
        string expected = version == SoapEnvelopeVersion.Soap11 ? "text/xml" : "application/soap+xml";
        if (!string.Equals(parsed.MediaType, expected, StringComparison.OrdinalIgnoreCase)) throw new SoapAuthException("SOAP-CONTENT-TYPE");
        NameValueHeaderValue? charset = parsed.Parameters.SingleOrDefault(parameter => string.Equals(parameter.Name, "charset", StringComparison.OrdinalIgnoreCase));
        if (charset is not null && !string.Equals(charset.Value?.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase)) throw new SoapAuthException("SOAP-CONTENT-TYPE");
    }

    private static string BoundedValue(XElement element)
    {
        string value = element.Value;
        if (value.Length > MaximumExtractedCharacters) throw new SoapAuthException("SOAP-RESPONSE-FIELD-TOO-LARGE");
        return value;
    }

    private static string RequireSensitiveValue(string value, string code) => !string.IsNullOrWhiteSpace(value) && value.Length <= 4096 ? value : throw new SoapAuthException(code);

    internal static string EnvelopeNamespace(SoapEnvelopeVersion version) => version == SoapEnvelopeVersion.Soap11
        ? "http://schemas.xmlsoap.org/soap/envelope/"
        : "http://www.w3.org/2003/05/soap-envelope";
}

/// <summary>Internal decoded response containing only explicitly selected values.</summary>
internal sealed record SoapDecodedResponse(IReadOnlyDictionary<string, string> Values, string? SessionValue, string? ChallengeValue);

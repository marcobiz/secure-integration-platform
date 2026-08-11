using System.Xml;

namespace SecureIntegration.ConnectorPacks.Healthcare.SistemaTs;

internal static class SistemaTsSessionXml
{
    internal static SistemaTsSessionResponse ReadCreateResponse(XmlReader reader)
    {
        MoveToContent(reader);
        RequireElement(reader, "CreateAuthRes", SistemaTsSessionProtocol.AuthenticationNamespace);
        bool empty = reader.IsEmptyElement;
        reader.ReadStartElement();
        if (empty) throw Malformed();

        string outcome = ReadRequiredText(reader, "codEsito", SistemaTsSessionProtocol.AuthenticationNamespace, 16);
        ReadOptionalDiagnostics(reader, allowTokenInformation: false, out _);
        RequireEnd(reader);
        return new(string.Equals(outcome, "0", StringComparison.Ordinal));
    }

    internal static SistemaTsCheckTokenResponse ReadCheckTokenResponse(XmlReader reader)
    {
        MoveToContent(reader);
        RequireElement(reader, "CheckTokenRes", SistemaTsSessionProtocol.AuthenticationNamespace);
        bool empty = reader.IsEmptyElement;
        reader.ReadStartElement();
        if (empty) throw Malformed();

        string outcome = ReadRequiredText(reader, "codEsito", SistemaTsSessionProtocol.AuthenticationNamespace, 16);
        ReadOptionalDiagnostics(reader, allowTokenInformation: true, out TokenInformation? token);
        RequireEnd(reader);
        bool accepted = string.Equals(outcome, "0", StringComparison.Ordinal) && token is { State: "0" } &&
            token.ExpiresAt > token.StartsAt;
        return new(accepted, accepted ? token!.ExpiresAt : null);
    }

    private static void ReadOptionalDiagnostics(XmlReader reader, bool allowTokenInformation, out TokenInformation? token)
    {
        token = null;
        if (IsElement(reader, "errori", SistemaTsSessionProtocol.AuthenticationNamespace))
            ReadErrors(reader);
        if (allowTokenInformation && IsElement(reader, "infoToken", SistemaTsSessionProtocol.AuthenticationNamespace))
            token = ReadTokenInformation(reader);
        if (IsElement(reader, "info", SistemaTsSessionProtocol.AuthenticationNamespace))
            ReadInformation(reader);
        if (IsElement(reader, "comunicazioni", SistemaTsSessionProtocol.AuthenticationNamespace))
            ReadCommunications(reader);
    }

    private static TokenInformation ReadTokenInformation(XmlReader reader)
    {
        RequireElement(reader, "infoToken", SistemaTsSessionProtocol.AuthenticationNamespace);
        reader.ReadStartElement();
        string state = ReadRequiredText(reader, "stato", SistemaTsSessionProtocol.DataNamespace, 16);
        _ = ReadRequiredText(reader, "descrizione", SistemaTsSessionProtocol.DataNamespace, 256);
        string starts = ReadRequiredText(reader, "dataInizioValidita", SistemaTsSessionProtocol.DataNamespace, 64);
        string expires = ReadRequiredText(reader, "dataFineValidita", SistemaTsSessionProtocol.DataNamespace, 64);
        RequireEnd(reader);
        return new(state, ParseDate(starts), ParseDate(expires));
    }

    private static void ReadErrors(XmlReader reader)
    {
        RequireElement(reader, "errori", SistemaTsSessionProtocol.AuthenticationNamespace);
        bool empty = reader.IsEmptyElement;
        reader.ReadStartElement();
        if (empty) throw Malformed();
        int count = 0;
        while (IsElement(reader, "errore", SistemaTsSessionProtocol.DataNamespace))
        {
            if (++count > 32) throw Malformed();
            reader.ReadStartElement();
            _ = ReadOptionalText(reader, "tipoErrore", SistemaTsSessionProtocol.DataNamespace, 1);
            _ = ReadRequiredText(reader, "codEsito", SistemaTsSessionProtocol.DataNamespace, 16);
            _ = ReadOptionalText(reader, "descrEsito", SistemaTsSessionProtocol.DataNamespace, 256);
            RequireEnd(reader);
        }
        if (count == 0) throw Malformed();
        RequireEnd(reader);
    }

    private static void ReadInformation(XmlReader reader)
    {
        RequireElement(reader, "info", SistemaTsSessionProtocol.AuthenticationNamespace);
        reader.ReadStartElement();
        _ = ReadRequiredText(reader, "chiave", SistemaTsSessionProtocol.DataNamespace, 256);
        _ = ReadRequiredText(reader, "valore", SistemaTsSessionProtocol.DataNamespace, 256);
        RequireEnd(reader);
    }

    private static void ReadCommunications(XmlReader reader)
    {
        RequireElement(reader, "comunicazioni", SistemaTsSessionProtocol.AuthenticationNamespace);
        bool empty = reader.IsEmptyElement;
        reader.ReadStartElement();
        if (empty) throw Malformed();
        int count = 0;
        while (IsElement(reader, "comunicazione", SistemaTsSessionProtocol.DataNamespace))
        {
            if (++count > 32) throw Malformed();
            reader.ReadStartElement();
            _ = ReadRequiredText(reader, "codice", SistemaTsSessionProtocol.DataNamespace, 256);
            _ = ReadRequiredText(reader, "messaggio", SistemaTsSessionProtocol.DataNamespace, 512);
            RequireEnd(reader);
        }
        if (count == 0) throw Malformed();
        RequireEnd(reader);
    }

    private static string ReadRequiredText(XmlReader reader, string localName, string namespaceUri, int maximumLength)
    {
        RequireElement(reader, localName, namespaceUri);
        string value = reader.ReadElementContentAsString();
        if (value.Length is 0 || value.Length > maximumLength || ContainsControl(value)) throw Malformed();
        return value;
    }

    private static string? ReadOptionalText(XmlReader reader, string localName, string namespaceUri, int maximumLength) =>
        IsElement(reader, localName, namespaceUri) ? ReadRequiredText(reader, localName, namespaceUri, maximumLength) : null;

    private static DateTimeOffset ParseDate(string value)
    {
        try
        {
            return XmlConvert.ToDateTimeOffset(value).ToUniversalTime();
        }
        catch (FormatException)
        {
            throw Malformed();
        }
    }

    private static void MoveToContent(XmlReader reader)
    {
        if (reader.ReadState == ReadState.Initial) reader.MoveToContent();
        else while (reader.NodeType is XmlNodeType.Whitespace or XmlNodeType.SignificantWhitespace) reader.Read();
    }

    private static void RequireElement(XmlReader reader, string localName, string namespaceUri)
    {
        MoveToContent(reader);
        if (!IsElement(reader, localName, namespaceUri) || HasNonNamespaceAttributes(reader)) throw Malformed();
    }

    private static bool IsElement(XmlReader reader, string localName, string namespaceUri) =>
        reader.NodeType == XmlNodeType.Element && reader.LocalName == localName && reader.NamespaceURI == namespaceUri;

    private static void RequireEnd(XmlReader reader)
    {
        MoveToContent(reader);
        if (reader.NodeType != XmlNodeType.EndElement) throw Malformed();
        reader.ReadEndElement();
    }

    private static bool HasNonNamespaceAttributes(XmlReader reader)
    {
        if (!reader.HasAttributes) return false;
        while (reader.MoveToNextAttribute())
            if (reader.NamespaceURI != "http://www.w3.org/2000/xmlns/") { reader.MoveToElement(); return true; }
        reader.MoveToElement();
        return false;
    }

    private static bool ContainsControl(string value) => value.Any(character =>
        character is < ' ' and not ('\t' or '\r' or '\n') || character is >= '\u007f' and <= '\u009f');

    private static XmlException Malformed() => new("Sistema TS session response is malformed.");

    private sealed record TokenInformation(string State, DateTimeOffset StartsAt, DateTimeOffset ExpiresAt);
}

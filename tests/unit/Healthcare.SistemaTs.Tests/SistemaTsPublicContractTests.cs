using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using SecureIntegration.ConnectorPacks.Healthcare.SistemaTs;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.Tests;

public sealed class SistemaTsPublicContractTests
{
    private const string Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string Common = "http://tipodati.xsd.dem.sanita.finanze.it";

    [Fact]
    public void HC_W1_SISTEMATS_CT_module_and_adapter_metadata_are_exact_and_constructor_closed()
    {
        SistemaTsExecutionStrategy strategy = new();
        Assert.Equal("healthcare-sistema-ts-eprescription", strategy.Key.Value);
        Assert.Equal([GatewayAuthenticationKind.Basic], strategy.SupportedAuthenticationKinds.OrderBy(value => value));
        Assert.Equal("healthcare-sistema-ts", new SistemaTsExecutionModule().Id.Value);
        Assert.All(typeof(SistemaTsExecutionModule).GetConstructors(), constructor => Assert.Empty(constructor.GetParameters()));

        SistemaTsCreateSessionRequestAdapter request = new();
        SistemaTsCheckTokenAdapter validator = new();
        Assert.Equal("sistema-ts-create-session-request", request.AdapterId);
        Assert.Equal("compiled-sistema-ts-create-v0.1", request.AdapterType);
        Assert.Equal(["codice-asl", "codice-fiscale", "codice-regione", "codice-ssa", "identificativo-tipo", "identificativo-valore", "user-id"],
            request.RequiredServerOwnedInputs.Order(StringComparer.Ordinal));
        Assert.Equal(["codice-fiscale", "identificativo-tipo", "identificativo-valore", "user-id"],
            validator.RequiredServerOwnedInputs.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void HC_W1_SISTEMATS_CT_Published_definition_exposes_only_session_create_while_business_composition_is_blocked()
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(AppContext.BaseDirectory, "Samples", "sistema-ts.connector.json")));
        ValidatedConnectorDefinition validated = new ConnectorDefinitionValidator().ValidateRequired(document.RootElement);
        using JsonDocument canonical = JsonDocument.Parse(validated.CanonicalJson);
        JsonElement[] operations = canonical.RootElement.GetProperty("operations").EnumerateArray().ToArray();
        JsonElement operation = Assert.Single(operations);
        Assert.Equal("session-create", operation.GetProperty("operationId").GetString());
        Assert.Equal("healthcare-sistema-ts-eprescription", operation.GetProperty("executionStrategy").GetString());
        Assert.Equal("basic", operation.GetProperty("authentication").GetProperty("kind").GetString());
        Assert.Equal(0, operation.GetProperty("maximumRetries").GetInt32());
        Assert.Empty(operation.GetProperty("allowedClientHeaders").EnumerateArray());
    }

    [Fact]
    public void HC_W1_SISTEMATS_UT_nested_create_response_is_external_admission_only_and_duplicate_is_denied()
    {
        object accepted = ParseSession("ReadCreateResponse", """
            <aut:CreateAuthRes xmlns:aut="http://authservice.xsd.wsdl.auth.a2f.sts.sanita.finanze.it" xmlns:dat="http://datatype.xsd.wsdl.auth.a2f.sts.sanita.finanze.it">
              <aut:codEsito>0</aut:codEsito><aut:comunicazioni><dat:comunicazione><dat:codice>AP02</dat:codice><dat:messaggio>handoff</dat:messaggio></dat:comunicazione></aut:comunicazioni>
            </aut:CreateAuthRes>
            """);
        Assert.True((bool)accepted.GetType().GetProperty("Success")!.GetValue(accepted)!);
        AssertSessionMalformed("ReadCreateResponse", """
            <aut:CreateAuthRes xmlns:aut="http://authservice.xsd.wsdl.auth.a2f.sts.sanita.finanze.it"><aut:codEsito>0</aut:codEsito><aut:codEsito>0</aut:codEsito></aut:CreateAuthRes>
            """);
    }

    [Fact]
    public void HC_W1_SISTEMATS_UT_checkToken_exact_xs_dateTime_expiry_and_rejection()
    {
        object accepted = ParseSession("ReadCheckTokenResponse", CheckTokenResponse(
            "2026-08-11T08:00:00Z", "2026-08-11T08:10:00+00:00"));
        Assert.True((bool)accepted.GetType().GetProperty("Valid")!.GetValue(accepted)!);

        object rejected = ParseSession("ReadCheckTokenResponse", """
            <aut:CheckTokenRes xmlns:aut="http://authservice.xsd.wsdl.auth.a2f.sts.sanita.finanze.it" xmlns:dat="http://datatype.xsd.wsdl.auth.a2f.sts.sanita.finanze.it">
              <aut:codEsito>1</aut:codEsito><aut:errori><dat:errore><dat:tipoErrore>E</dat:tipoErrore><dat:codEsito>401</dat:codEsito><dat:descrEsito>rejected</dat:descrEsito></dat:errore></aut:errori>
            </aut:CheckTokenRes>
            """);
        Assert.False((bool)rejected.GetType().GetProperty("Valid")!.GetValue(rejected)!);
    }

    [Theory]
    [InlineData("08/11/2026 08:00:00")]
    [InlineData("2026/08/11T08:00:00Z")]
    [InlineData("Tue, 11 Aug 2026 08:00:00 GMT")]
    [InlineData("2026-08-11 08:00:00")]
    public void HC_W1_SISTEMATS_UT_checkToken_rejects_non_xs_dateTime_lexical_forms(string invalid)
    {
        AssertSessionMalformed("ReadCheckTokenResponse", CheckTokenResponse(invalid, "2026-08-11T08:10:00Z"));
        AssertSessionMalformed("ReadCheckTokenResponse", CheckTokenResponse("2026-08-11T08:00:00Z", invalid));
    }

    [Theory]
    [MemberData(nameof(ValidBusinessDocuments))]
    public void HC_W1_SISTEMATS_UT_all_frozen_business_requests_and_responses_match_exact_contract(
        string operation, string request, string response)
    {
        ValidateBusiness("ValidateRequest", operation, request, shouldPass: true);
        ValidateBusiness("ValidateResponse", operation, response, shouldPass: true);
    }

    [Theory]
    [MemberData(nameof(InvalidBusinessDocuments))]
    public void HC_W1_SISTEMATS_UT_real_XSD_sequence_nested_simple_and_facet_violations_are_denied(
        string operation, bool request, string xml)
    {
        ValidateBusiness(request ? "ValidateRequest" : "ValidateResponse", operation, xml, shouldPass: false);
    }

    [Theory]
    [MemberData(nameof(ValidBusinessDocuments))]
    public void HC_W1_SISTEMATS_UT_connector_local_serializer_round_trips_all_frozen_request_and_response_shapes(
        string operationName, string request, string response)
    {
        Type catalog = ProductAssembly().GetType(
            "SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.SistemaTsOperationCatalog", throwOnError: true)!;
        object operation = catalog.GetField(operationName, BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;
        RoundTripSerialized("SerializeRequest", "ValidateRequest", operation, request);
        RoundTripSerialized("SerializeResponse", "ValidateResponse", operation, response);
    }

    [Theory]
    [InlineData("Visualizza", "5")]
    [InlineData("Invio", "6")]
    [InlineData("Sospendi", "3")]
    public void HC_W1_SISTEMATS_UT_documented_operation_value_domain_is_enforced(string operation, string value)
    {
        string request = operation switch
        {
            "Visualizza" => VisualizzaRequest().Replace(">1</req:tipoOperazione>", $">{value}</req:tipoOperazione>", StringComparison.Ordinal),
            "Invio" => InvioRequest().Replace(">1</req:tipoOperazione>", $">{value}</req:tipoOperazione>", StringComparison.Ordinal),
            "Sospendi" => SospendiRequest().Replace(">1</req:tipoOperazione>", $">{value}</req:tipoOperazione>", StringComparison.Ordinal),
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };
        ValidateBusiness("ValidateRequest", operation, request, shouldPass: false);
    }

    private static void RoundTripSerialized(string serializeMethod, string validateMethod, object operation, string xml)
    {
        Type valueType = ProductAssembly().GetType(
            "SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.SistemaTsXmlValue", throwOnError: true)!;
        XDocument source = XDocument.Parse(xml);
        XElement sourceRoot = source.Root!.Element(XName.Get("Body", Soap))!.Elements().Single();
        Array values = Values(sourceRoot.Elements(), valueType);
        Type serializer = ProductAssembly().GetType(
            "SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.SistemaTsBusinessXml", throwOnError: true)!;
        byte[] payload = (byte[])serializer.GetMethod(serializeMethod, BindingFlags.Static | BindingFlags.NonPublic)!
            .Invoke(null, [operation, values])!;
        serializer.GetMethod(validateMethod, BindingFlags.Static | BindingFlags.NonPublic)!.Invoke(null, [operation, payload]);
        XElement emittedRoot = XDocument.Parse(Encoding.UTF8.GetString(payload)).Root!
            .Element(XName.Get("Body", Soap))!.Elements().Single();
        Assert.Equal(ElementSignature(sourceRoot), ElementSignature(emittedRoot));
    }

    private static Array Values(IEnumerable<XElement> elements, Type valueType)
    {
        XElement[] source = elements.ToArray();
        Array values = Array.CreateInstance(valueType, source.Length);
        for (int index = 0; index < source.Length; index++)
        {
            XElement element = source[index];
            Array? children = element.HasElements ? Values(element.Elements(), valueType) : null;
            values.SetValue(Activator.CreateInstance(valueType, element.Name.LocalName,
                element.HasElements ? null : element.Value, children), index);
        }
        return values;
    }

    public static TheoryData<string, string, string> ValidBusinessDocuments() => new()
    {
        { "Visualizza", VisualizzaRequest(), VisualizzaResponse() },
        { "Invio", InvioRequest(), InvioResponse() },
        { "Sospendi", SospendiRequest(), SospendiResponse() },
        { "Annulla", AnnullaRequest(), AnnullaResponse() }
    };

    public static TheoryData<string, bool, string> InvalidBusinessDocuments() => new()
    {
        { "Visualizza", true, VisualizzaRequest().Replace("<req:nre>123456789012345</req:nre>", $"<req:nre><td:unexpected xmlns:td=\"{Common}\">123</td:unexpected></req:nre>", StringComparison.Ordinal) },
        { "Visualizza", true, VisualizzaRequest().Replace("<req:tipoOperazione>1</req:tipoOperazione>", "<req:tipoOperazione>12</req:tipoOperazione>", StringComparison.Ordinal) },
        { "Visualizza", false, Envelope($"<res:VisualizzaErogatoRicevuta xmlns:res=\"http://visualizzaerogatoricevuta.xsd.dem.sanita.finanze.it\"><res:codEsitoVisualizzazione>0000</res:codEsitoVisualizzazione><res:ElencoErroriRicette><td:Unexpected xmlns:td=\"{Common}\" /></res:ElencoErroriRicette></res:VisualizzaErogatoRicevuta>") },
        { "Invio", true, InvioRequest().Replace("<td:raw>01012345678901281726123110LOT1</td:raw><td:GTIN>01234567890123</td:GTIN>", "<td:GTIN>01234567890123</td:GTIN><td:raw>01012345678901281726123110LOT1</td:raw>", StringComparison.Ordinal) },
        { "Invio", true, InvioRequest().Replace("<td:prezzo>12.50</td:prezzo>", string.Empty, StringComparison.Ordinal) },
        { "Invio", true, InvioRequest().Replace("2026-08-11 08:00:00", "2026-8-11", StringComparison.Ordinal) },
        { "Invio", false, Response("http://invioerogatoricevuta.xsd.dem.sanita.finanze.it", "InvioErogatoRicevuta", "codEsitoInserimento").Replace("0000", "0", StringComparison.Ordinal) },
        { "Sospendi", true, SospendiRequest().Replace("<req:tipoOperazione>1</req:tipoOperazione>", "<req:tipoOperazione>12</req:tipoOperazione>", StringComparison.Ordinal) },
        { "Sospendi", false, Envelope("<res:SospendiErogatoRicevuta xmlns:res=\"http://sospendierogatoricevuta.xsd.dem.sanita.finanze.it\"><res:codEsitoSospensione>0000</res:codEsitoSospensione><res:ElencoComunicazioni /></res:SospendiErogatoRicevuta>") },
        { "Annulla", true, AnnullaRequest().Replace("<req:codAnnullamento>TEST</req:codAnnullamento>", $"<req:codAnnullamento><td:codice xmlns:td=\"{Common}\">TEST</td:codice></req:codAnnullamento>", StringComparison.Ordinal) },
        { "Annulla", false, Response("http://annullaerogatoricevuta.xsd.dem.sanita.finanze.it", "AnnullaErogatoRicevuta", "codEsitoAnnullamento").Replace("codEsitoAnnullamento", "codEsitoInserimento", StringComparison.Ordinal) }
    };

    private static string VisualizzaRequest() => Envelope("""
        <req:VisualizzaErogatoRichiesta xmlns:req="http://visualizzaerogatorichiesta.xsd.dem.sanita.finanze.it">
          <req:pinCode>server-pin</req:pinCode><req:codiceRegioneErogatore>120</req:codiceRegioneErogatore>
          <req:codiceAslErogatore>201</req:codiceAslErogatore><req:codiceSsaErogatore>000001</req:codiceSsaErogatore>
          <req:nre>123456789012345</req:nre><req:tipoOperazione>1</req:tipoOperazione>
        </req:VisualizzaErogatoRichiesta>
        """);

    private static string InvioRequest() => Envelope($"""
        <req:InvioErogatoRichiesta xmlns:req="http://invioerogatorichiesta.xsd.dem.sanita.finanze.it" xmlns:td="{Common}">
          <req:pinCode>server-pin</req:pinCode><req:codiceRegioneErogatore>120</req:codiceRegioneErogatore>
          <req:codiceAslErogatore>201</req:codiceAslErogatore><req:codiceSsaErogatore>000001</req:codiceSsaErogatore>
          <req:nre>123456789012345</req:nre><req:tipoOperazione>1</req:tipoOperazione><req:dataSpedizione>2026-08-11 08:00:00</req:dataSpedizione>
          <req:ElencoDettagliPrescrInviiErogato><td:DettaglioPrescrizioneInvioErogato>
            <td:codProdPrestErog>012345678</td:codProdPrestErog><td:dataMatrix><td:raw>01012345678901281726123110LOT1</td:raw><td:GTIN>01234567890123</td:GTIN><td:authToken>synthetic-auth-token</td:authToken></td:dataMatrix>
            <td:prezzo>12.50</td:prezzo><td:quantitaErogata>1</td:quantitaErogata><td:dataIniErog>2026-08-11 08:00:00</td:dataIniErog><td:dataFineErog>2026-08-11 08:30:00</td:dataFineErog>
          </td:DettaglioPrescrizioneInvioErogato></req:ElencoDettagliPrescrInviiErogato>
        </req:InvioErogatoRichiesta>
        """);

    private static string SospendiRequest() => Envelope("""
        <req:SospendiErogatoRichiesta xmlns:req="http://sospendierogatorichiesta.xsd.dem.sanita.finanze.it">
          <req:pinCode>server-pin</req:pinCode><req:codiceRegioneErogatore>120</req:codiceRegioneErogatore>
          <req:codiceAslErogatore>201</req:codiceAslErogatore><req:codiceSsaErogatore>000001</req:codiceSsaErogatore>
          <req:nre>123456789012345</req:nre><req:tipoOperazione>1</req:tipoOperazione>
        </req:SospendiErogatoRichiesta>
        """);

    private static string AnnullaRequest() => Envelope("""
        <req:AnnullaErogatoRichiesta xmlns:req="http://annullaerogatorichiesta.xsd.dem.sanita.finanze.it">
          <req:pinCode>server-pin</req:pinCode><req:codiceRegioneErogatore>120</req:codiceRegioneErogatore>
          <req:codiceAslErogatore>201</req:codiceAslErogatore><req:codiceSsaErogatore>000001</req:codiceSsaErogatore>
          <req:nre>123456789012345</req:nre><req:codAnnullamento>TEST</req:codAnnullamento>
        </req:AnnullaErogatoRichiesta>
        """);

    private static string VisualizzaResponse() => Envelope($"""
        <res:VisualizzaErogatoRicevuta xmlns:res="http://visualizzaerogatoricevuta.xsd.dem.sanita.finanze.it" xmlns:td="{Common}">
          <res:nre>123456789012345</res:nre><res:dataSpedizione>2026-08-11 08:00:00</res:dataSpedizione>
          <res:ElencoDettagliPrescrVisualErogato><td:DettaglioPrescrizioneVisualErogato>
            <td:statoPresc>3</td:statoPresc><td:quantita>1</td:quantita><td:dataMatrix>
              <td:raw>01012345678901281726123110LOT1</td:raw><td:GTIN>01234567890123</td:GTIN>
            </td:dataMatrix><td:numsedute>12</td:numsedute>
          </td:DettaglioPrescrizioneVisualErogato></res:ElencoDettagliPrescrVisualErogato>
          <res:codEsitoVisualizzazione>0000</res:codEsitoVisualizzazione>
          <res:ElencoErroriRicette><td:ErroreRicetta><td:codEsito>0001</td:codEsito><td:esito>warning</td:esito></td:ErroreRicetta></res:ElencoErroriRicette>
          <res:ElencoComunicazioni><td:Comunicazione><td:codice>C01</td:codice><td:messaggio>synthetic</td:messaggio></td:Comunicazione></res:ElencoComunicazioni>
          <res:flagPromemoria>0</res:flagPromemoria><res:pdfPromemoria>cGRm</res:pdfPromemoria>
        </res:VisualizzaErogatoRicevuta>
        """);

    private static string InvioResponse() => Envelope($"""
        <res:InvioErogatoRicevuta xmlns:res="http://invioerogatoricevuta.xsd.dem.sanita.finanze.it" xmlns:td="{Common}">
          <res:nre>123456789012345</res:nre><res:dataRicezione>2026-08-11 08:31:00</res:dataRicezione>
          <res:codAutenticazione>synthetic-auth</res:codAutenticazione><res:codEsitoInserimento>0000</res:codEsitoInserimento>
          <res:ElencoErroriRicette><td:ErroreRicetta><td:codEsito>0001</td:codEsito><td:tipoErrore>W</td:tipoErrore></td:ErroreRicetta></res:ElencoErroriRicette>
          <res:ElencoComunicazioni><td:Comunicazione><td:codice>C01</td:codice><td:messaggio>synthetic</td:messaggio></td:Comunicazione></res:ElencoComunicazioni>
          <res:calcoloEffettuato>1</res:calcoloEffettuato><res:ticketTotale>2.00</res:ticketTotale>
          <res:ElencoDettagliTicket><td:DettaglioTicket><td:codProdPrestErog>012345678</td:codProdPrestErog>
            <td:progrPresc>1</td:progrPresc><td:ticketConfezione>2.00</td:ticketConfezione>
            <td:diffGenerico>0.00</td:diffGenerico><td:prezzo>12.50</td:prezzo>
          </td:DettaglioTicket></res:ElencoDettagliTicket>
        </res:InvioErogatoRicevuta>
        """);

    private static string SospendiResponse() => Envelope($"""
        <res:SospendiErogatoRicevuta xmlns:res="http://sospendierogatoricevuta.xsd.dem.sanita.finanze.it" xmlns:td="{Common}">
          <res:codEsitoSospensione>0000</res:codEsitoSospensione>
          <res:ElencoErroriRicette><td:ErroreRicetta><td:codEsito>0001</td:codEsito></td:ErroreRicetta></res:ElencoErroriRicette>
          <res:ElencoComunicazioni><td:Comunicazione><td:codice>C01</td:codice><td:messaggio>synthetic</td:messaggio></td:Comunicazione></res:ElencoComunicazioni>
        </res:SospendiErogatoRicevuta>
        """);

    private static string AnnullaResponse() => Envelope($"""
        <res:AnnullaErogatoRicevuta xmlns:res="http://annullaerogatoricevuta.xsd.dem.sanita.finanze.it" xmlns:td="{Common}">
          <res:nre>123456789012345</res:nre><res:dataRicezione>2026-08-11 08:31:00</res:dataRicezione>
          <res:codAutenticazione>synthetic-auth</res:codAutenticazione><res:codEsitoAnnullamento>0000</res:codEsitoAnnullamento>
          <res:ElencoErroriRicette><td:ErroreRicetta><td:codEsito>0001</td:codEsito></td:ErroreRicetta></res:ElencoErroriRicette>
          <res:ElencoComunicazioni><td:Comunicazione><td:codice>C01</td:codice><td:messaggio>synthetic</td:messaggio></td:Comunicazione></res:ElencoComunicazioni>
        </res:AnnullaErogatoRicevuta>
        """);

    private static string Response(string ns, string root, string result) =>
        Envelope($"<res:{root} xmlns:res=\"{ns}\"><res:{result}>0000</res:{result}></res:{root}>");

    private static string Envelope(string payload) =>
        $"<soap:Envelope xmlns:soap=\"{Soap}\"><soap:Body>{payload}</soap:Body></soap:Envelope>";

    private static string ElementSignature(XElement element) =>
        $"{{{element.Name.NamespaceName}}}{element.Name.LocalName}[{string.Join('|', element.Elements().Select(ElementSignature))}]={(element.HasElements ? string.Empty : element.Value)}";

    private static string CheckTokenResponse(string starts, string expires) => $"""
        <aut:CheckTokenRes xmlns:aut="http://authservice.xsd.wsdl.auth.a2f.sts.sanita.finanze.it" xmlns:dat="http://datatype.xsd.wsdl.auth.a2f.sts.sanita.finanze.it">
          <aut:codEsito>0</aut:codEsito><aut:infoToken><dat:stato>0</dat:stato><dat:descrizione>valid</dat:descrizione><dat:dataInizioValidita>{starts}</dat:dataInizioValidita><dat:dataFineValidita>{expires}</dat:dataFineValidita></aut:infoToken>
        </aut:CheckTokenRes>
        """;

    private static void ValidateBusiness(string methodName, string operationName, string xml, bool shouldPass)
    {
        Type catalog = ProductAssembly().GetType(
            "SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.SistemaTsOperationCatalog", throwOnError: true)!;
        object operation = catalog.GetField(operationName, BindingFlags.Static | BindingFlags.NonPublic)!.GetValue(null)!;
        Type validator = ProductAssembly().GetType(
            "SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.SistemaTsBusinessXml", throwOnError: true)!;
        MethodInfo method = validator.GetMethod(methodName, BindingFlags.Static | BindingFlags.NonPublic)!;
        if (shouldPass)
        {
            method.Invoke(null, [operation, Encoding.UTF8.GetBytes(xml)]);
            return;
        }
        TargetInvocationException exception = Assert.Throws<TargetInvocationException>(
            () => method.Invoke(null, [operation, Encoding.UTF8.GetBytes(xml)]));
        Assert.IsType<InvalidOperationException>(exception.InnerException);
    }

    private static object ParseSession(string methodName, string xml)
    {
        Type parser = ProductAssembly().GetType(
            "SecureIntegration.ConnectorPacks.Healthcare.SistemaTs.SistemaTsSessionXml", throwOnError: true)!;
        MethodInfo method = parser.GetMethod(methodName, BindingFlags.Static | BindingFlags.NonPublic)!;
        using StringReader text = new(xml);
        using XmlReader reader = XmlReader.Create(text, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        return method.Invoke(null, [reader])!;
    }

    private static void AssertSessionMalformed(string methodName, string xml)
    {
        TargetInvocationException exception = Assert.Throws<TargetInvocationException>(() => ParseSession(methodName, xml));
        Assert.IsType<XmlException>(exception.InnerException);
    }

    private static Assembly ProductAssembly() => typeof(SistemaTsExecutionModule).Assembly;
}

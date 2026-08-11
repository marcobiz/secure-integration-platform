using System.Collections.Frozen;
using System.Collections.ObjectModel;

namespace SecureIntegration.ConnectorPacks.Healthcare.SistemaTs;

internal enum SistemaTsRetryClassification { NoAutomaticRetry }

internal enum SistemaTsXmlLexicalKind
{
    String,
    AsciiDigits,
    AsciiAlphanumeric,
    NonNegativeIntegerMaximumThreeDigits,
    Base64
}

internal sealed record SistemaTsXmlScalar(
    int MinimumLength,
    int MaximumLength,
    SistemaTsXmlLexicalKind LexicalKind = SistemaTsXmlLexicalKind.String,
    IReadOnlySet<string>? AllowedValues = null);

internal sealed record SistemaTsXmlElementSpec(
    string Name,
    string NamespaceUri,
    int MinimumOccurs,
    int MaximumOccurs,
    SistemaTsXmlScalar? Scalar,
    IReadOnlyList<SistemaTsXmlElementSpec>? Children);

internal sealed record SistemaTsXmlValue(
    string Name,
    string? Text = null,
    IReadOnlyList<SistemaTsXmlValue>? Children = null);

internal sealed record SistemaTsBusinessOperation(
    string OperationId,
    string SoapAction,
    string RequestNamespace,
    string RequestRoot,
    IReadOnlyList<SistemaTsXmlElementSpec> RequestElements,
    string ResponseNamespace,
    string ResponseRoot,
    IReadOnlyList<SistemaTsXmlElementSpec> ResponseElements,
    string ResultField,
    SistemaTsRetryClassification RetryClassification);

internal static class SistemaTsOperationCatalog
{
    private const int MaximumText = 16_384;
    private const string Common = "http://tipodati.xsd.dem.sanita.finanze.it";

    internal static readonly (string OperationId, string SoapAction) SessionCreate =
        ("session-create", "http://wsdl.auth.a2f.sts.sanita.finanze.it/create");

    internal static readonly SistemaTsBusinessOperation Visualizza = VisualizzaOperation();
    internal static readonly SistemaTsBusinessOperation Invio = InvioOperation();
    internal static readonly SistemaTsBusinessOperation Sospendi = SospendiOperation();
    internal static readonly SistemaTsBusinessOperation Annulla = AnnullaOperation();

    private static readonly FrozenDictionary<string, SistemaTsBusinessOperation> Operations =
        new[] { Visualizza, Invio, Sospendi, Annulla }.ToFrozenDictionary(value => value.OperationId, StringComparer.Ordinal);

    internal static IReadOnlyCollection<SistemaTsBusinessOperation> All => Operations.Values;

    internal static SistemaTsBusinessOperation Required(string operationId) => Operations.TryGetValue(operationId, out var value)
        ? value
        : throw new InvalidOperationException("Sistema TS operation is not in the frozen catalog.");

    private static SistemaTsBusinessOperation VisualizzaOperation()
    {
        const string request = "http://visualizzaerogatorichiesta.xsd.dem.sanita.finanze.it";
        const string response = "http://visualizzaerogatoricevuta.xsd.dem.sanita.finanze.it";
        return new(
            "visualizza-erogato",
            "http://visualizzaerogato.wsdl.dem.sanita.finanze.it/VisualizzaErogato",
            request,
            "VisualizzaErogatoRichiesta",
            Elements(
                Text(request, "pinCode"), Text(request, "codiceRegioneErogatore"),
                Text(request, "codiceAslErogatore"), Text(request, "codiceSsaErogatore"),
                Text(request, "pwd", required: false, maximum: 16), Text(request, "nre", maximum: 15),
                Text(request, "cfAssistito", required: false),
                Allowed(request, "tipoOperazione", "1", "2", "3", "4")),
            response,
            "VisualizzaErogatoRicevuta",
            Elements(
                Text(response, "nre", false, maximum: 15), Text(response, "cfMedico1", false, maximum: 16),
                Text(response, "cfMedico2", false, maximum: 16), Text(response, "codRegione", false, 3, 3),
                Text(response, "codASLAo", false), Text(response, "codStruttura", false),
                Text(response, "codSpecializzazione", false, maximum: 1), Text(response, "testata1", false),
                Text(response, "testata2", false), Text(response, "tipoRic", false, maximum: 2),
                Text(response, "codiceAss", false), Text(response, "cognNome", false), Text(response, "indirizzo", false),
                Text(response, "oscuramDati", false), Text(response, "numTessSasn", false), Text(response, "socNavigaz", false),
                Text(response, "tipoPrescrizione", false, maximum: 1), Text(response, "ricettaInterna", false),
                Text(response, "codEsenzione", false), Text(response, "nonEsente", false), Text(response, "reddito", false),
                Text(response, "codDiagnosi", false), Text(response, "descrizioneDiagnosi", false),
                Text(response, "dataCompilazione", false, maximum: 19), Text(response, "tipoVisita", false, maximum: 1),
                Text(response, "dispReg", false), Text(response, "provAssistito", false), Text(response, "aslAssistito", false),
                Text(response, "indicazionePrescr", false, 1, 1), Text(response, "altro", false, 1, 1),
                Text(response, "classePriorita", false, maximum: 1), Text(response, "statoEstero", false),
                Text(response, "istituzCompetente", false), Text(response, "numIdentPers", false), Text(response, "numIdentTess", false),
                Text(response, "dataNascitaEstero", false, maximum: 19), Text(response, "dataScadTessera", false, maximum: 19),
                Text(response, "statoProcesso", false), Text(response, "chiusuraDiff", false), Text(response, "chiusuraForzata", false),
                Text(response, "prescrizioneFruita", false), Text(response, "tipoErogazioneSpec", false), Text(response, "ticket", false),
                Text(response, "quotaFissa", false), Text(response, "franchigia", false), Text(response, "galDirChiamAltro", false),
                Text(response, "dataSpedizione", false, maximum: 19), Text(response, "dispRic1", false, maximum: 256),
                Text(response, "dispRic2", false, maximum: 256), Text(response, "dispRic3", false, maximum: 256),
                Complex(response, "ElencoDettagliPrescrVisualErogato", false,
                    Elements(Repeated(Common, "DettaglioPrescrizioneVisualErogato", 1, VisualizzaDetail()))),
                Text(response, "codAutenticazioneMedico", false), Text(response, "codAutenticazioneErogatore", false),
                Digits(response, "codEsitoVisualizzazione", 4, 4), ErrorList(response), Communications(response),
                Text(response, "codEseNaz", false), Text(response, "flagPromemoria", false, maximum: 1),
                Scalar(response, "pdfPromemoria", false, new(0, MaximumText, SistemaTsXmlLexicalKind.Base64))),
            "codEsitoVisualizzazione",
            SistemaTsRetryClassification.NoAutomaticRetry);
    }

    private static ReadOnlyCollection<SistemaTsXmlElementSpec> VisualizzaDetail() => Elements(
        Text(Common, "statoPresc"), Text(Common, "codProdPrest", false), Text(Common, "descrProdPrest", false),
        Text(Common, "codGruppoEquival", false), Text(Common, "descrGruppoEquival", false), Text(Common, "testoLibero", false),
        Text(Common, "descrTestoLiberoNote", false), Text(Common, "nonSost", false), Text(Common, "motivazNote", false),
        Text(Common, "codMotivazione", false), Text(Common, "notaProd", false), Digits(Common, "quantita", 1, MaximumText),
        Text(Common, "prescrizione1", false), Text(Common, "prescrizione2", false), Text(Common, "codProdPrestErog", false),
        Text(Common, "descrProdPrestErog", false), Text(Common, "flagErog", false), Text(Common, "motivazSostProd", false),
        Text(Common, "targa", false), Text(Common, "dichTargaDoppia", false, maximum: 1),
        Complex(Common, "dataMatrix", false, DataMatrix(includeAuthToken: false)), Text(Common, "codBranca", false),
        Text(Common, "tipoErogazioneFarm", false), Text(Common, "prezzo", false), Text(Common, "ticketConfezione", false),
        Text(Common, "diffGenerico", false), Text(Common, "quantitaErogata", false), Text(Common, "dataIniErog", false, maximum: 19),
        Text(Common, "dataFineErog", false, maximum: 19), Text(Common, "prezzoRimborso", false), Text(Common, "onereProd", false),
        Text(Common, "scontoSSN", false), Text(Common, "extraScontoIndustria", false), Text(Common, "extraScontoPayback", false),
        Text(Common, "extraScontoDL31052010", false), Text(Common, "codPresidio", false), Text(Common, "codReparto", false),
        Text(Common, "dispFust1", false, maximum: 256), Text(Common, "dispFust2", false, maximum: 256),
        Text(Common, "dispFust3", false, maximum: 256), Text(Common, "codCatalogoPrescr", false),
        Text(Common, "tipoAccesso", false, maximum: 1), Text(Common, "codNomenclNaz", false), Text(Common, "codCatalogoErog", false),
        Text(Common, "garanziaTempiMax", false, maximum: 1), Text(Common, "dataPrenotazione", false, maximum: 19),
        Text(Common, "numeroNota", false), Text(Common, "condErogabilita", false), Text(Common, "approprPrescrittiva", false),
        Text(Common, "patologia", false), Text(Common, "tipoAmbulatorio", false),
        Scalar(Common, "numsedute", false, new(1, 3, SistemaTsXmlLexicalKind.NonNegativeIntegerMaximumThreeDigits)));

    private static SistemaTsBusinessOperation InvioOperation()
    {
        const string request = "http://invioerogatorichiesta.xsd.dem.sanita.finanze.it";
        const string response = "http://invioerogatoricevuta.xsd.dem.sanita.finanze.it";
        return new(
            "invio-erogato",
            "http://invioerogato.wsdl.dem.sanita.finanze.it/InvioErogato",
            request,
            "InvioErogatoRichiesta",
            Elements(
                Text(request, "pinCode"), Text(request, "codiceRegioneErogatore"), Text(request, "codiceAslErogatore"),
                Text(request, "codiceSsaErogatore"), Text(request, "pwd", false, maximum: 16), Text(request, "nre", maximum: 15),
                Text(request, "cfAssistito", false), Allowed(request, "tipoOperazione", "1", "2", "3", "4", "5"),
                Text(request, "prescrizioneFruita", false), Text(request, "tipoErogazioneSpec", false), Text(request, "ticket", false),
                Text(request, "quotaFissa", false), Text(request, "franchigia", false), Text(request, "galDirChiamAltro", false),
                Text(request, "reddito", false), Text(request, "dataSpedizione", minimum: 19, maximum: 19),
                Text(request, "dispRic1", false, maximum: 256), Text(request, "dispRic2", false, maximum: 256),
                Text(request, "dispRic3", false, maximum: 256),
                Complex(request, "ElencoDettagliPrescrInviiErogato", false,
                    Elements(Repeated(Common, "DettaglioPrescrizioneInvioErogato", 0, InvioDetail())))),
            response,
            "InvioErogatoRicevuta",
            Elements(
                Text(response, "nre", false, maximum: 15), Text(response, "dataRicezione", false, 19, 19),
                Text(response, "codAutenticazione", false), Digits(response, "codEsitoInserimento", 4, 4),
                ErrorList(response), Communications(response), Text(response, "calcoloEffettuato", false),
                Text(response, "ticketTotale", false),
                Complex(response, "ElencoDettagliTicket", false,
                    Elements(Repeated(Common, "DettaglioTicket", 1, Elements(
                        Text(Common, "codProdPrestErog"), Text(Common, "progrPresc"), Text(Common, "ticketConfezione"),
                        Text(Common, "diffGenerico"), Text(Common, "prezzo")))))),
            "codEsitoInserimento",
            SistemaTsRetryClassification.NoAutomaticRetry);
    }

    private static ReadOnlyCollection<SistemaTsXmlElementSpec> InvioDetail() => Elements(
        Text(Common, "codProdPrest", false), Text(Common, "codGruppoEquival", false), Text(Common, "descrTestoLiberoNote", false),
        Text(Common, "codProdPrestErog"), Text(Common, "descrProdPrestErog", false), Text(Common, "flagErog", false),
        Text(Common, "motivazSostProd", false), Text(Common, "targa", false), Text(Common, "dichTargaDoppia", false, maximum: 1),
        Complex(Common, "dataMatrix", false, DataMatrix(includeAuthToken: true)), Text(Common, "codBranca", false),
        Text(Common, "tipoErogazioneFarm", false), Text(Common, "prezzo"), Text(Common, "ticketConfezione", false),
        Text(Common, "diffGenerico", false), Text(Common, "quantitaErogata"), Text(Common, "dataIniErog", minimum: 19, maximum: 19),
        Text(Common, "dataFineErog", minimum: 19, maximum: 19), Text(Common, "prezzoRimborso", false), Text(Common, "onereProd", false),
        Text(Common, "scontoSSN", false), Text(Common, "extraScontoIndustria", false), Text(Common, "extraScontoPayback", false),
        Text(Common, "extraScontoDL31052010", false), Text(Common, "codPresidio", false), Text(Common, "codReparto", false),
        Text(Common, "dispFust1", false, maximum: 256), Text(Common, "dispFust2", false, maximum: 256),
        Text(Common, "dispFust3", false, maximum: 256), Text(Common, "codCatalogoPrescr", false),
        Text(Common, "codCatalogoErog", false), Text(Common, "garanziaTempiMax", false, maximum: 1),
        Text(Common, "dataPrenotazione", false, 19, 19));

    private static SistemaTsBusinessOperation SospendiOperation()
    {
        const string request = "http://sospendierogatorichiesta.xsd.dem.sanita.finanze.it";
        const string response = "http://sospendierogatoricevuta.xsd.dem.sanita.finanze.it";
        return new(
            "sospendi-erogato",
            "http://visualizzaerogato.wsdl.dem.sanita.finanze.it/SospendiErogato",
            request,
            "SospendiErogatoRichiesta",
            Elements(Text(request, "pinCode"), Text(request, "codiceRegioneErogatore"), Text(request, "codiceAslErogatore"),
                Text(request, "codiceSsaErogatore"), Text(request, "pwd", false, maximum: 16), Text(request, "nre", maximum: 15),
                Text(request, "cfAssistito", false), Allowed(request, "tipoOperazione", "1", "2")),
            response,
            "SospendiErogatoRicevuta",
            Elements(Digits(response, "codEsitoSospensione", 4, 4), ErrorList(response), Communications(response)),
            "codEsitoSospensione",
            SistemaTsRetryClassification.NoAutomaticRetry);
    }

    private static SistemaTsBusinessOperation AnnullaOperation()
    {
        const string request = "http://annullaerogatorichiesta.xsd.dem.sanita.finanze.it";
        const string response = "http://annullaerogatoricevuta.xsd.dem.sanita.finanze.it";
        return new(
            "annulla-erogato",
            "http://annullaerogato.wsdl.dem.sanita.finanze.it/AnnullaErogato",
            request,
            "AnnullaErogatoRichiesta",
            Elements(Text(request, "pinCode"), Text(request, "codiceRegioneErogatore"), Text(request, "codiceAslErogatore"),
                Text(request, "codiceSsaErogatore"), Text(request, "pwd", false, maximum: 16), Text(request, "nre", maximum: 15),
                Text(request, "cfAssistito", false), Text(request, "codAnnullamento")),
            response,
            "AnnullaErogatoRicevuta",
            Elements(Text(response, "nre", false, maximum: 15), Text(response, "dataRicezione", false, 19, 19),
                Text(response, "codAutenticazione", false), Digits(response, "codEsitoAnnullamento", 4, 4),
                ErrorList(response), Communications(response)),
            "codEsitoAnnullamento",
            SistemaTsRetryClassification.NoAutomaticRetry);
    }

    private static ReadOnlyCollection<SistemaTsXmlElementSpec> DataMatrix(bool includeAuthToken)
    {
        List<SistemaTsXmlElementSpec> fields =
        [
            Text(Common, "raw", false, 1, 128), Digits(Common, "GTIN", 14, 14, false),
            Scalar(Common, "lottoId", false, new(1, 20, SistemaTsXmlLexicalKind.AsciiAlphanumeric)),
            Digits(Common, "lottoScadenza", 6, 6, false),
            Scalar(Common, "seriale", false, new(1, 20, SistemaTsXmlLexicalKind.AsciiAlphanumeric)),
            Digits(Common, "NHRNAI", 3, 3, false),
            Scalar(Common, "NHRN", false, new(1, 20, SistemaTsXmlLexicalKind.AsciiAlphanumeric))
        ];
        if (includeAuthToken) fields.Add(Text(Common, "authToken", false, minimum: 1));
        return fields.AsReadOnly();
    }

    private static SistemaTsXmlElementSpec ErrorList(string parentNamespace) =>
        Complex(parentNamespace, "ElencoErroriRicette", false,
            Elements(Repeated(Common, "ErroreRicetta", 1, Elements(
                Digits(Common, "codEsito", 4, 4), Text(Common, "esito", false),
                Text(Common, "progPresc", false), Text(Common, "tipoErrore", false)))));

    private static SistemaTsXmlElementSpec Communications(string parentNamespace) =>
        Complex(parentNamespace, "ElencoComunicazioni", false,
            Elements(Repeated(Common, "Comunicazione", 1, Elements(Text(Common, "codice"), Text(Common, "messaggio")))));

    private static SistemaTsXmlElementSpec Text(string ns, string name, bool required = true,
        int minimum = 0, int maximum = MaximumText) => Scalar(ns, name, required, new(minimum, maximum));

    private static SistemaTsXmlElementSpec Digits(string ns, string name, int minimum, int maximum,
        bool required = true) => Scalar(ns, name, required, new(minimum, maximum, SistemaTsXmlLexicalKind.AsciiDigits));

    private static SistemaTsXmlElementSpec Allowed(string ns, string name, params string[] values) =>
        Scalar(ns, name, true, new(1, 1, AllowedValues: values.ToFrozenSet(StringComparer.Ordinal)));

    private static SistemaTsXmlElementSpec Scalar(string ns, string name, bool required, SistemaTsXmlScalar scalar) =>
        new(name, ns, required ? 1 : 0, 1, scalar, null);

    private static SistemaTsXmlElementSpec Complex(string ns, string name, bool required,
        IReadOnlyList<SistemaTsXmlElementSpec> children) => new(name, ns, required ? 1 : 0, 1, null, children);

    private static SistemaTsXmlElementSpec Repeated(string ns, string name, int minimum,
        IReadOnlyList<SistemaTsXmlElementSpec> children) => new(name, ns, minimum, int.MaxValue, null, children);

    private static ReadOnlyCollection<SistemaTsXmlElementSpec> Elements(params SistemaTsXmlElementSpec[] values) => Array.AsReadOnly(values);
}

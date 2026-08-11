using System.Collections.Frozen;
using System.Collections.ObjectModel;

namespace SecureIntegration.ConnectorPacks.Healthcare.SistemaTs;

internal enum SistemaTsRetryClassification { NoAutomaticRetry }

internal sealed record SistemaTsXmlField(string Name, bool Required);

internal sealed record SistemaTsBusinessOperation(
    string OperationId,
    string SoapAction,
    string RequestNamespace,
    string RequestRoot,
    IReadOnlyList<SistemaTsXmlField> RequestFields,
    string ResponseNamespace,
    string ResponseRoot,
    IReadOnlyList<SistemaTsXmlField> ResponseFields,
    string ResultField,
    SistemaTsRetryClassification RetryClassification);

internal static class SistemaTsOperationCatalog
{
    internal static readonly (string OperationId, string SoapAction) SessionCreate =
        ("session-create", "http://wsdl.auth.a2f.sts.sanita.finanze.it/create");

    internal static readonly SistemaTsBusinessOperation Visualizza = new(
        "visualizza-erogato",
        "http://visualizzaerogato.wsdl.dem.sanita.finanze.it/VisualizzaErogato",
        "http://visualizzaerogatorichiesta.xsd.dem.sanita.finanze.it", "VisualizzaErogatoRichiesta",
        Fields(("pinCode", true), ("codiceRegioneErogatore", true), ("codiceAslErogatore", true),
            ("codiceSsaErogatore", true), ("pwd", false), ("nre", true), ("cfAssistito", false), ("tipoOperazione", true)),
        "http://visualizzaerogatoricevuta.xsd.dem.sanita.finanze.it", "VisualizzaErogatoRicevuta",
        Fields(("nre", false), ("cfMedico1", false), ("cfMedico2", false), ("codRegione", false),
            ("codASLAo", false), ("codStruttura", false), ("codSpecializzazione", false), ("testata1", false),
            ("testata2", false), ("tipoRic", false), ("codiceAss", false), ("cognNome", false), ("indirizzo", false),
            ("oscuramDati", false), ("numTessSasn", false), ("socNavigaz", false), ("tipoPrescrizione", false),
            ("ricettaInterna", false), ("codEsenzione", false), ("nonEsente", false), ("reddito", false),
            ("codDiagnosi", false), ("descrizioneDiagnosi", false), ("dataCompilazione", false), ("tipoVisita", false),
            ("dispReg", false), ("provAssistito", false), ("aslAssistito", false), ("indicazionePrescr", false),
            ("altro", false), ("classePriorita", false), ("statoEstero", false), ("istituzCompetente", false),
            ("numIdentPers", false), ("numIdentTess", false), ("dataNascitaEstero", false), ("dataScadTessera", false),
            ("statoProcesso", false), ("chiusuraDiff", false), ("chiusuraForzata", false), ("prescrizioneFruita", false),
            ("tipoErogazioneSpec", false), ("ticket", false), ("quotaFissa", false), ("franchigia", false),
            ("galDirChiamAltro", false), ("dataSpedizione", false), ("dispRic1", false), ("dispRic2", false),
            ("dispRic3", false), ("ElencoDettagliPrescrVisualErogato", false), ("codAutenticazioneMedico", false),
            ("codAutenticazioneErogatore", false), ("codEsitoVisualizzazione", true), ("ElencoErroriRicette", false),
            ("ElencoComunicazioni", false), ("codEseNaz", false), ("flagPromemoria", false), ("pdfPromemoria", false)),
        "codEsitoVisualizzazione", SistemaTsRetryClassification.NoAutomaticRetry);

    internal static readonly SistemaTsBusinessOperation Invio = new(
        "invio-erogato", "http://invioerogato.wsdl.dem.sanita.finanze.it/InvioErogato",
        "http://invioerogatorichiesta.xsd.dem.sanita.finanze.it", "InvioErogatoRichiesta",
        Fields(("pinCode", true), ("codiceRegioneErogatore", true), ("codiceAslErogatore", true),
            ("codiceSsaErogatore", true), ("pwd", false), ("nre", true), ("cfAssistito", false),
            ("tipoOperazione", true), ("prescrizioneFruita", false), ("tipoErogazioneSpec", false),
            ("ticket", false), ("quotaFissa", false), ("franchigia", false), ("galDirChiamAltro", false), ("reddito", false),
            ("dataSpedizione", true), ("dispRic1", false), ("dispRic2", false), ("dispRic3", false),
            ("ElencoDettagliPrescrInviiErogato", false)),
        "http://invioerogatoricevuta.xsd.dem.sanita.finanze.it", "InvioErogatoRicevuta",
        Fields(("nre", false), ("dataRicezione", false), ("codAutenticazione", false),
            ("codEsitoInserimento", true), ("ElencoErroriRicette", false), ("ElencoComunicazioni", false),
            ("calcoloEffettuato", false), ("ticketTotale", false), ("ElencoDettagliTicket", false)),
        "codEsitoInserimento", SistemaTsRetryClassification.NoAutomaticRetry);

    internal static readonly SistemaTsBusinessOperation Sospendi = new(
        "sospendi-erogato", "http://visualizzaerogato.wsdl.dem.sanita.finanze.it/SospendiErogato",
        "http://sospendierogatorichiesta.xsd.dem.sanita.finanze.it", "SospendiErogatoRichiesta",
        Fields(("pinCode", true), ("codiceRegioneErogatore", true), ("codiceAslErogatore", true),
            ("codiceSsaErogatore", true), ("pwd", false), ("nre", true), ("cfAssistito", false), ("tipoOperazione", true)),
        "http://sospendierogatoricevuta.xsd.dem.sanita.finanze.it", "SospendiErogatoRicevuta",
        Fields(("codEsitoSospensione", true), ("ElencoErroriRicette", false), ("ElencoComunicazioni", false)),
        "codEsitoSospensione", SistemaTsRetryClassification.NoAutomaticRetry);

    internal static readonly SistemaTsBusinessOperation Annulla = new(
        "annulla-erogato", "http://annullaerogato.wsdl.dem.sanita.finanze.it/AnnullaErogato",
        "http://annullaerogatorichiesta.xsd.dem.sanita.finanze.it", "AnnullaErogatoRichiesta",
        Fields(("pinCode", true), ("codiceRegioneErogatore", true), ("codiceAslErogatore", true),
            ("codiceSsaErogatore", true), ("pwd", false), ("nre", true), ("cfAssistito", false), ("codAnnullamento", true)),
        "http://annullaerogatoricevuta.xsd.dem.sanita.finanze.it", "AnnullaErogatoRicevuta",
        Fields(("nre", false), ("dataRicezione", false), ("codAutenticazione", false),
            ("codEsitoAnnullamento", true), ("ElencoErroriRicette", false), ("ElencoComunicazioni", false)),
        "codEsitoAnnullamento", SistemaTsRetryClassification.NoAutomaticRetry);

    private static readonly FrozenDictionary<string, SistemaTsBusinessOperation> Operations =
        new[] { Visualizza, Invio, Sospendi, Annulla }.ToFrozenDictionary(value => value.OperationId, StringComparer.Ordinal);

    internal static SistemaTsBusinessOperation Required(string operationId) => Operations.TryGetValue(operationId, out var value)
        ? value
        : throw new InvalidOperationException("Sistema TS operation is not in the frozen catalog.");

    private static ReadOnlyCollection<SistemaTsXmlField> Fields(params (string Name, bool Required)[] values) =>
        Array.AsReadOnly(values.Select(value => new SistemaTsXmlField(value.Name, value.Required)).ToArray());
}

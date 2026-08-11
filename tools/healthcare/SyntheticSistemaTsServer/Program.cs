using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace SecureIntegration.Healthcare.SyntheticSistemaTsServer;

/// <summary>Expected synthetic credentials, candidate and official server-owned identity values.</summary>
public sealed record SyntheticSistemaTsOptions(
    string Username,
    string Password,
    string Candidate,
    IReadOnlyDictionary<string, string> ServerOwnedFields);

/// <summary>Wire-level request counters for the isolated Sistema TS test authority.</summary>
public sealed class SyntheticSistemaTsCounters
{
    private int create;
    private int checkToken;
    private int visualizza;
    private int invio;
    private int sospendi;
    private int annulla;
    private int generic;
    private int rejected;

    /// <summary>Accepted create calls.</summary>
    public int Create => Volatile.Read(ref create);
    /// <summary>Accepted checkToken calls.</summary>
    public int CheckToken => Volatile.Read(ref checkToken);
    /// <summary>Accepted VisualizzaErogato calls.</summary>
    public int Visualizza => Volatile.Read(ref visualizza);
    /// <summary>Accepted InvioErogato calls.</summary>
    public int Invio => Volatile.Read(ref invio);
    /// <summary>Accepted SospendiErogato calls.</summary>
    public int Sospendi => Volatile.Read(ref sospendi);
    /// <summary>Accepted AnnullaErogato calls.</summary>
    public int Annulla => Volatile.Read(ref annulla);
    /// <summary>Accepted business calls across the four frozen operations.</summary>
    public int Business => Visualizza + Invio + Sospendi + Annulla;
    /// <summary>Calls reaching the generic fallback.</summary>
    public int Generic => Volatile.Read(ref generic);
    /// <summary>Wire-policy rejections.</summary>
    public int Rejected => Volatile.Read(ref rejected);

    internal void CountCreate() => Interlocked.Increment(ref create);
    internal void CountCheckToken() => Interlocked.Increment(ref checkToken);
    internal void CountVisualizza() => Interlocked.Increment(ref visualizza);
    internal void CountInvio() => Interlocked.Increment(ref invio);
    internal void CountSospendi() => Interlocked.Increment(ref sospendi);
    internal void CountAnnulla() => Interlocked.Increment(ref annulla);
    internal void CountGeneric() => Interlocked.Increment(ref generic);
    internal void CountRejected() => Interlocked.Increment(ref rejected);
}

/// <summary>Running loopback HTTPS Sistema TS authority.</summary>
public sealed class SyntheticSistemaTsServerInstance(
    WebApplication application,
    Uri endpoint,
    SyntheticSistemaTsCounters counters) : IAsyncDisposable
{
    /// <summary>Dynamic HTTPS base endpoint.</summary>
    public Uri Endpoint { get; } = endpoint;
    /// <summary>Observed wire counters.</summary>
    public SyntheticSistemaTsCounters Counters { get; } = counters;

    /// <summary>Stops the isolated authority.</summary>
    public async ValueTask DisposeAsync()
    {
        await application.StopAsync().ConfigureAwait(false);
        await application.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>Starts a frozen-contract synthetic Sistema TS authority.</summary>
public static class SyntheticSistemaTsServerHost
{
    private const string Soap = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string Authentication = "http://authservice.xsd.wsdl.auth.a2f.sts.sanita.finanze.it";
    private const string Data = "http://datatype.xsd.wsdl.auth.a2f.sts.sanita.finanze.it";
    private const string Common = "http://tipodati.xsd.dem.sanita.finanze.it";
    private const string VisualizzaRequest = "http://visualizzaerogatorichiesta.xsd.dem.sanita.finanze.it";
    private const string VisualizzaResponse = "http://visualizzaerogatoricevuta.xsd.dem.sanita.finanze.it";
    private const string InvioRequest = "http://invioerogatorichiesta.xsd.dem.sanita.finanze.it";
    private const string InvioResponse = "http://invioerogatoricevuta.xsd.dem.sanita.finanze.it";
    private const string SospendiRequest = "http://sospendierogatorichiesta.xsd.dem.sanita.finanze.it";
    private const string SospendiResponse = "http://sospendierogatoricevuta.xsd.dem.sanita.finanze.it";
    private const string AnnullaRequest = "http://annullaerogatorichiesta.xsd.dem.sanita.finanze.it";
    private const string AnnullaResponse = "http://annullaerogatoricevuta.xsd.dem.sanita.finanze.it";
    private const string VisualizzaAction = "http://visualizzaerogato.wsdl.dem.sanita.finanze.it/VisualizzaErogato";
    private const string InvioAction = "http://invioerogato.wsdl.dem.sanita.finanze.it/InvioErogato";
    private const string SospendiAction = "http://visualizzaerogato.wsdl.dem.sanita.finanze.it/SospendiErogato";
    private const string AnnullaAction = "http://annullaerogato.wsdl.dem.sanita.finanze.it/AnnullaErogato";
    private const int MaximumBytes = 1_048_576;

    /// <summary>Starts HTTPS on a dynamic loopback port.</summary>
    public static async Task<SyntheticSistemaTsServerInstance> StartAsync(
        SyntheticSistemaTsOptions options,
        X509Certificate2 serverCertificate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(serverCertificate);
        RequireOptions(options);
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(server => server.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(serverCertificate)));
        WebApplication app = builder.Build();
        SyntheticSistemaTsCounters counters = new();

        app.MapPost("/sts", async (HttpRequest request, HttpResponse response, CancellationToken token) =>
        {
            if (!ValidBasic(request.Headers.Authorization.ToString(), options.Username, options.Password))
            {
                counters.CountRejected(); response.StatusCode = StatusCodes.Status401Unauthorized; return;
            }
            XElement? payload = await ReadPayloadAsync(request, response, token).ConfigureAwait(false);
            if (payload is null) { counters.CountRejected(); return; }
            if (HasExactAction(request, "http://wsdl.auth.a2f.sts.sanita.finanze.it/create") &&
                ValidCreate(payload, options.ServerOwnedFields))
            {
                counters.CountCreate();
                await WriteAsync(response,
                    $"<aut:CreateAuthRes xmlns:aut=\"{Authentication}\"><aut:codEsito>0</aut:codEsito><aut:comunicazioni><dat:comunicazione xmlns:dat=\"{Data}\"><dat:codice>AP02</dat:codice><dat:messaggio>interactive handoff</dat:messaggio></dat:comunicazione></aut:comunicazioni></aut:CreateAuthRes>", token).ConfigureAwait(false);
                return;
            }
            if (HasExactAction(request, "http://wsdl.auth.a2f.sts.sanita.finanze.it/checkToken") &&
                ValidCheckToken(payload, options))
            {
                counters.CountCheckToken();
                DateTimeOffset start = DateTimeOffset.UtcNow.AddSeconds(-5);
                DateTimeOffset expiry = DateTimeOffset.UtcNow.AddMinutes(5);
                await WriteAsync(response,
                    $"<aut:CheckTokenRes xmlns:aut=\"{Authentication}\"><aut:codEsito>0</aut:codEsito><aut:infoToken><dat:stato xmlns:dat=\"{Data}\">0</dat:stato><dat:descrizione xmlns:dat=\"{Data}\">valid</dat:descrizione><dat:dataInizioValidita xmlns:dat=\"{Data}\">{XmlConvert.ToString(start)}</dat:dataInizioValidita><dat:dataFineValidita xmlns:dat=\"{Data}\">{XmlConvert.ToString(expiry)}</dat:dataFineValidita></aut:infoToken></aut:CheckTokenRes>", token).ConfigureAwait(false);
                return;
            }
            counters.CountRejected(); response.StatusCode = StatusCodes.Status400BadRequest;
        });

        app.MapPost("/erogatore", async (HttpRequest request, HttpResponse response, CancellationToken token) =>
        {
            if (!ValidBasic(request.Headers.Authorization.ToString(), options.Username, options.Password))
            {
                counters.CountRejected(); response.StatusCode = StatusCodes.Status401Unauthorized; return;
            }
            if (request.Headers["Authorization2F"].Count != 1 ||
                !Fixed(request.Headers["Authorization2F"].ToString(), "Bearer " + options.Candidate))
            {
                counters.CountRejected(); response.StatusCode = StatusCodes.Status400BadRequest; return;
            }
            XElement? payload = await ReadPayloadAsync(request, response, token).ConfigureAwait(false);
            if (payload is null) { counters.CountRejected(); return; }

            if (HasExactAction(request, VisualizzaAction) && ExactElement(payload, ExpectedVisualizza(options)))
            {
                counters.CountVisualizza();
                await WriteBusinessAsync(response, VisualizzaResponse, "VisualizzaErogatoRicevuta", "codEsitoVisualizzazione", token).ConfigureAwait(false);
                return;
            }
            if (HasExactAction(request, InvioAction) && ExactElement(payload, ExpectedInvio(options)))
            {
                counters.CountInvio();
                await WriteBusinessAsync(response, InvioResponse, "InvioErogatoRicevuta", "codEsitoInserimento", token).ConfigureAwait(false);
                return;
            }
            if (HasExactAction(request, SospendiAction) && ExactElement(payload, ExpectedSospendi(options)))
            {
                counters.CountSospendi();
                await WriteBusinessAsync(response, SospendiResponse, "SospendiErogatoRicevuta", "codEsitoSospensione", token).ConfigureAwait(false);
                return;
            }
            if (HasExactAction(request, AnnullaAction) && ExactElement(payload, ExpectedAnnulla(options)))
            {
                counters.CountAnnulla();
                await WriteBusinessAsync(response, AnnullaResponse, "AnnullaErogatoRicevuta", "codEsitoAnnullamento", token).ConfigureAwait(false);
                return;
            }

            counters.CountRejected(); response.StatusCode = StatusCodes.Status400BadRequest;
        });

        app.MapPost("/{**path}", (HttpResponse response) =>
        {
            counters.CountGeneric(); response.StatusCode = StatusCodes.Status404NotFound;
        });
        await app.StartAsync(cancellationToken).ConfigureAwait(false);
        string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses.Single()
            ?? throw new InvalidOperationException("Synthetic Sistema TS server did not publish an address.");
        return new(app, new Uri(address), counters);
    }

    private static XElement ExpectedVisualizza(SyntheticSistemaTsOptions options)
    {
        XNamespace ns = VisualizzaRequest;
        return new(ns + "VisualizzaErogatoRichiesta",
            new XElement(ns + "pinCode", options.ServerOwnedFields["business-pin-code"]),
            new XElement(ns + "codiceRegioneErogatore", options.ServerOwnedFields["codice-regione"]),
            new XElement(ns + "codiceAslErogatore", options.ServerOwnedFields["codice-asl"]),
            new XElement(ns + "codiceSsaErogatore", options.ServerOwnedFields["codice-ssa"]),
            new XElement(ns + "nre", "123456789012345"),
            new XElement(ns + "tipoOperazione", "1"));
    }

    private static XElement ExpectedInvio(SyntheticSistemaTsOptions options)
    {
        XNamespace ns = InvioRequest;
        XNamespace common = Common;
        return new(ns + "InvioErogatoRichiesta",
            new XElement(ns + "pinCode", options.ServerOwnedFields["business-pin-code"]),
            new XElement(ns + "codiceRegioneErogatore", options.ServerOwnedFields["codice-regione"]),
            new XElement(ns + "codiceAslErogatore", options.ServerOwnedFields["codice-asl"]),
            new XElement(ns + "codiceSsaErogatore", options.ServerOwnedFields["codice-ssa"]),
            new XElement(ns + "nre", "123456789012345"),
            new XElement(ns + "tipoOperazione", "1"),
            new XElement(ns + "dataSpedizione", "2026-08-11 08:00:00"),
            new XElement(ns + "ElencoDettagliPrescrInviiErogato",
                new XElement(common + "DettaglioPrescrizioneInvioErogato",
                    new XElement(common + "codProdPrestErog", "012345678"),
                    new XElement(common + "dataMatrix",
                        new XElement(common + "raw", "01012345678901281726123110LOT1"),
                        new XElement(common + "GTIN", "01234567890123"),
                        new XElement(common + "authToken", "synthetic-auth-token")),
                    new XElement(common + "prezzo", "12.50"),
                    new XElement(common + "quantitaErogata", "1"),
                    new XElement(common + "dataIniErog", "2026-08-11 08:00:00"),
                    new XElement(common + "dataFineErog", "2026-08-11 08:30:00"))));
    }

    private static XElement ExpectedSospendi(SyntheticSistemaTsOptions options)
    {
        XNamespace ns = SospendiRequest;
        return new(ns + "SospendiErogatoRichiesta",
            new XElement(ns + "pinCode", options.ServerOwnedFields["business-pin-code"]),
            new XElement(ns + "codiceRegioneErogatore", options.ServerOwnedFields["codice-regione"]),
            new XElement(ns + "codiceAslErogatore", options.ServerOwnedFields["codice-asl"]),
            new XElement(ns + "codiceSsaErogatore", options.ServerOwnedFields["codice-ssa"]),
            new XElement(ns + "nre", "123456789012345"),
            new XElement(ns + "tipoOperazione", "1"));
    }

    private static XElement ExpectedAnnulla(SyntheticSistemaTsOptions options)
    {
        XNamespace ns = AnnullaRequest;
        return new(ns + "AnnullaErogatoRichiesta",
            new XElement(ns + "pinCode", options.ServerOwnedFields["business-pin-code"]),
            new XElement(ns + "codiceRegioneErogatore", options.ServerOwnedFields["codice-regione"]),
            new XElement(ns + "codiceAslErogatore", options.ServerOwnedFields["codice-asl"]),
            new XElement(ns + "codiceSsaErogatore", options.ServerOwnedFields["codice-ssa"]),
            new XElement(ns + "nre", "123456789012345"),
            new XElement(ns + "codAnnullamento", "TEST"));
    }

    private static bool ValidCreate(XElement payload, IReadOnlyDictionary<string, string> fields)
    {
        XNamespace aut = Authentication;
        XNamespace dat = Data;
        if (payload.Name != aut + "CreateAuthReq") return false;
        XElement[] values = payload.Elements().ToArray();
        if (!values.Select(value => value.Name).SequenceEqual(
                [aut + "userId", aut + "identificativo", aut + "cfUtente", aut + "codRegione", aut + "codAslAo", aut + "codSsa", aut + "contesto", aut + "applicazione"])) return false;
        XElement[] identifier = values[1].Elements().ToArray();
        return identifier.Select(value => value.Name).SequenceEqual([dat + "tipo", dat + "valore"]) &&
            Fixed(values[0].Value, fields["user-id"]) && Fixed(identifier[0].Value, fields["identificativo-tipo"]) &&
            Fixed(identifier[1].Value, fields["identificativo-valore"]) && Fixed(values[2].Value, fields["codice-fiscale"]) &&
            Fixed(values[3].Value, fields["codice-regione"]) && Fixed(values[4].Value, fields["codice-asl"]) &&
            Fixed(values[5].Value, fields["codice-ssa"]) && values[6].Value == "RICETTA-DEM" && values[7].Value == "EROGATORE";
    }

    private static bool ValidCheckToken(XElement payload, SyntheticSistemaTsOptions options)
    {
        XNamespace aut = Authentication;
        XNamespace dat = Data;
        if (payload.Name != aut + "CheckTokenReq") return false;
        XElement[] values = payload.Elements().ToArray();
        if (!values.Select(value => value.Name).SequenceEqual(
                [aut + "userId", aut + "identificativo", aut + "cfUtente", aut + "token", aut + "contesto", aut + "applicazione"])) return false;
        XElement[] identifier = values[1].Elements().ToArray();
        return identifier.Select(value => value.Name).SequenceEqual([dat + "tipo", dat + "valore"]) &&
            Fixed(values[0].Value, options.ServerOwnedFields["user-id"]) &&
            Fixed(identifier[0].Value, options.ServerOwnedFields["identificativo-tipo"]) &&
            Fixed(identifier[1].Value, options.ServerOwnedFields["identificativo-valore"]) &&
            Fixed(values[2].Value, options.ServerOwnedFields["codice-fiscale"]) && Fixed(values[3].Value, options.Candidate) &&
            values[4].Value == "RICETTA-DEM" && values[5].Value == "EROGATORE";
    }

    private static bool ExactElement(XElement actual, XElement expected)
    {
        if (actual.Name != expected.Name || actual.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)) return false;
        XElement[] actualChildren = actual.Elements().ToArray();
        XElement[] expectedChildren = expected.Elements().ToArray();
        if (actualChildren.Length != expectedChildren.Length) return false;
        if (actualChildren.Length == 0) return Fixed(actual.Value, expected.Value);
        if (HasNonElementContent(actual)) return false;
        for (int index = 0; index < actualChildren.Length; index++)
            if (!ExactElement(actualChildren[index], expectedChildren[index])) return false;
        return true;
    }

    private static async Task<XElement?> ReadPayloadAsync(HttpRequest request, HttpResponse response, CancellationToken token)
    {
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out MediaTypeHeaderValue? type) ||
            !string.Equals(type.MediaType, "text/xml", StringComparison.OrdinalIgnoreCase) ||
            type.Parameters.Count != 1 ||
            !string.Equals(type.CharSet?.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase))
        {
            response.StatusCode = StatusCodes.Status415UnsupportedMediaType; return null;
        }
        try
        {
            using MemoryStream bytes = new();
            await request.Body.CopyToAsync(bytes, token).ConfigureAwait(false);
            if (bytes.Length > MaximumBytes) throw new InvalidDataException();
            bytes.Position = 0;
            using XmlReader reader = XmlReader.Create(bytes, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaximumBytes,
                MaxCharactersFromEntities = 0,
                IgnoreComments = false,
                IgnoreProcessingInstructions = false
            });
            XDocument document = XDocument.Load(reader);
            if (HasNonElementContent(document)) throw new XmlException();
            XElement envelope = document.Root ?? throw new XmlException();
            if (envelope.Name != XName.Get("Envelope", Soap) ||
                envelope.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration) || HasNonElementContent(envelope))
                throw new XmlException();
            XElement[] envelopeChildren = envelope.Elements().ToArray();
            if (envelopeChildren.Length != 1 || envelopeChildren[0].Name != XName.Get("Body", Soap)) throw new XmlException();
            XElement body = envelopeChildren[0];
            if (body.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration) || HasNonElementContent(body)) throw new XmlException();
            return body.Elements().Single();
        }
        catch (Exception exception) when (exception is XmlException or InvalidOperationException or InvalidDataException)
        {
            response.StatusCode = StatusCodes.Status400BadRequest; return null;
        }
    }

    private static bool HasExactAction(HttpRequest request, string action)
    {
        Microsoft.Extensions.Primitives.StringValues values = request.Headers["SOAPAction"];
        return values.Count == 1 && Fixed(values[0] ?? string.Empty, '"' + action + '"');
    }

    private static async Task WriteBusinessAsync(HttpResponse response, string ns, string root, string result,
        CancellationToken token) => await WriteAsync(response,
        $"<res:{root} xmlns:res=\"{ns}\"><res:{result}>0000</res:{result}></res:{root}>", token).ConfigureAwait(false);

    private static async Task WriteAsync(HttpResponse response, string payload, CancellationToken token)
    {
        response.StatusCode = StatusCodes.Status200OK;
        response.ContentType = "text/xml; charset=utf-8";
        await response.WriteAsync($"<soap:Envelope xmlns:soap=\"{Soap}\"><soap:Body>{payload}</soap:Body></soap:Envelope>", token).ConfigureAwait(false);
    }

    private static bool ValidBasic(string value, string user, string password)
    {
        if (!value.StartsWith("Basic ", StringComparison.Ordinal)) return false;
        try { return Fixed(Encoding.UTF8.GetString(Convert.FromBase64String(value[6..])), user + ":" + password); }
        catch (FormatException) { return false; }
    }

    private static bool HasNonElementContent(XContainer container) => container.Nodes().Any(node => node switch
    {
        XElement => false,
        XText text => !string.IsNullOrWhiteSpace(text.Value),
        _ => true
    });

    private static bool Fixed(string left, string right)
    {
        byte[] a = Encoding.UTF8.GetBytes(left);
        byte[] b = Encoding.UTF8.GetBytes(right);
        try { return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b); }
        finally { CryptographicOperations.ZeroMemory(a); CryptographicOperations.ZeroMemory(b); }
    }

    private static void RequireOptions(SyntheticSistemaTsOptions options)
    {
        string[] required = ["user-id", "identificativo-tipo", "identificativo-valore", "codice-fiscale",
            "codice-regione", "codice-asl", "codice-ssa", "business-pin-code"];
        if (required.Any(name => !options.ServerOwnedFields.TryGetValue(name, out string? value) || string.IsNullOrEmpty(value)))
            throw new ArgumentException("Synthetic Sistema TS options are incomplete.", nameof(options));
    }
}

internal static class Program
{
    private static void Main() => throw new InvalidOperationException("Started only by integration tests.");
}

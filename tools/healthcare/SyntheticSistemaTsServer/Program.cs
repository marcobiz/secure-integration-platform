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
/// <param name="Username">Expected Basic username.</param>
/// <param name="Password">Expected Basic password.</param>
/// <param name="Candidate">Expected externally admitted ID-session.</param>
/// <param name="ServerOwnedFields">Expected CreateAuth/checkToken server-owned values.</param>
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
    private int business;
    private int generic;
    private int rejected;
    /// <summary>Accepted create calls.</summary>
    public int Create => Volatile.Read(ref create);
    /// <summary>Accepted checkToken calls.</summary>
    public int CheckToken => Volatile.Read(ref checkToken);
    /// <summary>Accepted business calls.</summary>
    public int Business => Volatile.Read(ref business);
    /// <summary>Calls reaching the generic fallback.</summary>
    public int Generic => Volatile.Read(ref generic);
    /// <summary>Wire-policy rejections.</summary>
    public int Rejected => Volatile.Read(ref rejected);
    internal void CountCreate() => Interlocked.Increment(ref create);
    internal void CountCheckToken() => Interlocked.Increment(ref checkToken);
    internal void CountBusiness() => Interlocked.Increment(ref business);
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
    private const string VisualizzaRequest = "http://visualizzaerogatorichiesta.xsd.dem.sanita.finanze.it";
    private const string VisualizzaResponse = "http://visualizzaerogatoricevuta.xsd.dem.sanita.finanze.it";
    private const int MaximumBytes = 1_048_576;

    /// <summary>Starts HTTPS on a dynamic loopback port.</summary>
    public static async Task<SyntheticSistemaTsServerInstance> StartAsync(
        SyntheticSistemaTsOptions options,
        X509Certificate2 serverCertificate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(serverCertificate);
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
            string action = ReadAction(request);
            if (action == "http://wsdl.auth.a2f.sts.sanita.finanze.it/create" && ValidCreate(payload, options.ServerOwnedFields))
            {
                counters.CountCreate();
                await WriteAsync(response, $"<aut:CreateAuthRes xmlns:aut=\"{Authentication}\"><aut:codEsito>0</aut:codEsito><aut:comunicazioni><dat:comunicazione xmlns:dat=\"{Data}\"><dat:codice>AP02</dat:codice><dat:messaggio>interactive handoff</dat:messaggio></dat:comunicazione></aut:comunicazioni></aut:CreateAuthRes>", token).ConfigureAwait(false);
                return;
            }
            if (action == "http://wsdl.auth.a2f.sts.sanita.finanze.it/checkToken" && ValidCheckToken(payload, options))
            {
                counters.CountCheckToken();
                DateTimeOffset start = DateTimeOffset.UtcNow.AddSeconds(-5);
                DateTimeOffset expiry = DateTimeOffset.UtcNow.AddMinutes(5);
                await WriteAsync(response, $"<aut:CheckTokenRes xmlns:aut=\"{Authentication}\"><aut:codEsito>0</aut:codEsito><aut:infoToken><dat:stato xmlns:dat=\"{Data}\">0</dat:stato><dat:descrizione xmlns:dat=\"{Data}\">valid</dat:descrizione><dat:dataInizioValidita xmlns:dat=\"{Data}\">{start:O}</dat:dataInizioValidita><dat:dataFineValidita xmlns:dat=\"{Data}\">{expiry:O}</dat:dataFineValidita></aut:infoToken></aut:CheckTokenRes>", token).ConfigureAwait(false);
                return;
            }
            counters.CountRejected(); response.StatusCode = StatusCodes.Status400BadRequest;
        });

        app.MapPost("/erogatore", async (HttpRequest request, HttpResponse response, CancellationToken token) =>
        {
            XElement? payload = await ReadPayloadAsync(request, response, token).ConfigureAwait(false);
            if (payload is null || !ValidBasic(request.Headers.Authorization.ToString(), options.Username, options.Password) ||
                request.Headers["Authorization2F"].Count != 1 || !Fixed(request.Headers["Authorization2F"].ToString(), "Bearer " + options.Candidate) ||
                ReadAction(request) != "http://visualizzaerogato.wsdl.dem.sanita.finanze.it/VisualizzaErogato" || !ValidVisualizza(payload))
            {
                counters.CountRejected(); response.StatusCode = StatusCodes.Status400BadRequest; return;
            }
            counters.CountBusiness();
            await WriteAsync(response, $"<res:VisualizzaErogatoRicevuta xmlns:res=\"{VisualizzaResponse}\"><res:nre>123456789012345</res:nre><res:codEsitoVisualizzazione>0</res:codEsitoVisualizzazione></res:VisualizzaErogatoRicevuta>", token).ConfigureAwait(false);
        });

        app.MapPost("/{**path}", (HttpResponse response) => { counters.CountGeneric(); response.StatusCode = StatusCodes.Status404NotFound; });
        await app.StartAsync(cancellationToken).ConfigureAwait(false);
        string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses.Single()
            ?? throw new InvalidOperationException("Synthetic Sistema TS server did not publish an address.");
        return new(app, new Uri(address), counters);
    }

    private static bool ValidCreate(XElement payload, IReadOnlyDictionary<string, string> fields)
    {
        XNamespace aut = Authentication;
        XNamespace dat = Data;
        if (payload.Name != aut + "CreateAuthReq") return false;
        XElement[] values = payload.Elements().ToArray();
        if (!values.Select(value => value.Name).SequenceEqual([aut + "userId", aut + "identificativo", aut + "cfUtente", aut + "codRegione", aut + "codAslAo", aut + "codSsa", aut + "contesto", aut + "applicazione"])) return false;
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
        if (!values.Select(value => value.Name).SequenceEqual([aut + "userId", aut + "identificativo", aut + "cfUtente", aut + "token", aut + "contesto", aut + "applicazione"])) return false;
        XElement[] identifier = values[1].Elements().ToArray();
        return identifier.Select(value => value.Name).SequenceEqual([dat + "tipo", dat + "valore"]) &&
            Fixed(values[0].Value, options.ServerOwnedFields["user-id"]) && Fixed(identifier[0].Value, options.ServerOwnedFields["identificativo-tipo"]) &&
            Fixed(identifier[1].Value, options.ServerOwnedFields["identificativo-valore"]) && Fixed(values[2].Value, options.ServerOwnedFields["codice-fiscale"]) &&
            Fixed(values[3].Value, options.Candidate) && values[4].Value == "RICETTA-DEM" && values[5].Value == "EROGATORE";
    }

    private static bool ValidVisualizza(XElement payload)
    {
        XNamespace request = VisualizzaRequest;
        return payload.Name == request + "VisualizzaErogatoRichiesta" && payload.Elements().Select(value => value.Name).SequenceEqual([
            request + "pinCode", request + "codiceRegioneErogatore", request + "codiceAslErogatore", request + "codiceSsaErogatore",
            request + "nre", request + "tipoOperazione"]);
    }

    private static async Task<XElement?> ReadPayloadAsync(HttpRequest request, HttpResponse response, CancellationToken token)
    {
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out MediaTypeHeaderValue? type) || type.MediaType != "text/xml")
        { response.StatusCode = StatusCodes.Status415UnsupportedMediaType; return null; }
        try
        {
            using MemoryStream bytes = new();
            await request.Body.CopyToAsync(bytes, token).ConfigureAwait(false);
            if (bytes.Length > MaximumBytes) throw new InvalidDataException();
            bytes.Position = 0;
            using XmlReader reader = XmlReader.Create(bytes, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaximumBytes });
            XDocument document = XDocument.Load(reader);
            XElement envelope = document.Root ?? throw new XmlException();
            if (envelope.Name != XName.Get("Envelope", Soap) || envelope.Elements(XName.Get("Header", Soap)).Any()) throw new XmlException();
            return envelope.Elements(XName.Get("Body", Soap)).Single().Elements().Single();
        }
        catch (Exception exception) when (exception is XmlException or InvalidOperationException or InvalidDataException)
        { response.StatusCode = StatusCodes.Status400BadRequest; return null; }
    }

    private static string ReadAction(HttpRequest request)
    {
        Microsoft.Extensions.Primitives.StringValues values = request.Headers["SOAPAction"];
        return values.Count == 1 ? values[0]?.Trim('"') ?? string.Empty : string.Empty;
    }

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

    private static bool Fixed(string left, string right)
    {
        byte[] a = Encoding.UTF8.GetBytes(left); byte[] b = Encoding.UTF8.GetBytes(right);
        try { return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b); }
        finally { CryptographicOperations.ZeroMemory(a); CryptographicOperations.ZeroMemory(b); }
    }
}

internal static class Program
{
    private static void Main() => throw new InvalidOperationException("Started only by integration tests.");
}

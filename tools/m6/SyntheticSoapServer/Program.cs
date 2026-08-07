using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace SecureIntegration.M6.SyntheticSoapServer;

/// <summary>Configuration for one isolated synthetic Basic/SOAP/session server.</summary>
public sealed record SyntheticSoapServerOptions(string Username, string Password, bool RequireChallenge, TimeSpan SessionLifetime, TimeSpan TimeoutDelay);

/// <summary>Thread-safe counters exposed only to the synthetic test harness.</summary>
public sealed class SyntheticSoapCounters
{
    private int login;
    private int challenge;
    private int business;
    private int logout;

    /// <summary>Login request count.</summary>
    public int Login => Volatile.Read(ref login);
    /// <summary>Challenge completion count.</summary>
    public int Challenge => Volatile.Read(ref challenge);
    /// <summary>Business request count.</summary>
    public int Business => Volatile.Read(ref business);
    /// <summary>Logout request count.</summary>
    public int Logout => Volatile.Read(ref logout);

    internal void Count(string operation)
    {
        if (operation == "Login") Interlocked.Increment(ref login);
        else if (operation == "CompleteChallenge") Interlocked.Increment(ref challenge);
        else if (operation == "BusinessOperation") Interlocked.Increment(ref business);
        else if (operation == "Logout") Interlocked.Increment(ref logout);
    }
}

/// <summary>Running local HTTPS SOAP server used by real-HTTP integration tests.</summary>
public sealed class SyntheticSoapServerInstance(WebApplication application, Uri endpoint, SyntheticSoapCounters counters) : IAsyncDisposable
{
    /// <summary>Dynamically assigned HTTPS service endpoint.</summary>
    public Uri Endpoint { get; } = endpoint;
    /// <summary>Operation counters.</summary>
    public SyntheticSoapCounters Counters { get; } = counters;

    /// <summary>Stops and disposes the server.</summary>
    public async ValueTask DisposeAsync()
    {
        await application.StopAsync().ConfigureAwait(false);
        await application.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>Starts the isolated synthetic server on a real loopback TLS socket.</summary>
public static class SyntheticSoapServerHost
{
    private const string OperationNamespace = "urn:synthetic:session";
    private const string FaultNamespace = "urn:synthetic:fault";
    private const int MaximumRequestBytes = 1_048_576;

    /// <summary>Starts HTTPS on a dynamically assigned loopback port.</summary>
    public static async Task<SyntheticSoapServerInstance> StartAsync(SyntheticSoapServerOptions options, X509Certificate2 serverCertificate, CancellationToken cancellationToken)
    {
        Validate(options);
        ArgumentNullException.ThrowIfNull(serverCertificate);
        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(server => server.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(serverCertificate)));
        WebApplication app = builder.Build();
        ConcurrentDictionary<string, DateTimeOffset> sessions = new(StringComparer.Ordinal);
        ConcurrentDictionary<string, bool> challenges = new(StringComparer.Ordinal);
        SyntheticSoapCounters counters = new();
        int expireBusinessOnce = 0;

        app.MapPost("/service", async (HttpRequest request, HttpResponse response, CancellationToken token) =>
        {
            if (!ValidBasic(request.Headers.Authorization.ToString(), options.Username, options.Password))
            {
                response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
            byte[] body;
            try { body = await ReadBoundedAsync(request.Body, MaximumRequestBytes, token).ConfigureAwait(false); }
            catch (InvalidDataException) { response.StatusCode = StatusCodes.Status413PayloadTooLarge; return; }

            ParsedRequest parsed;
            try { parsed = Parse(body); }
            catch (Exception exception) when (exception is XmlException or InvalidOperationException or ArgumentException) { response.StatusCode = StatusCodes.Status400BadRequest; return; }
            if (!ValidHttpPolicy(request, parsed)) { response.StatusCode = StatusCodes.Status415UnsupportedMediaType; return; }
            counters.Count(parsed.Operation);
            SoapVersion version = parsed.Version;

            if (parsed.Operation == "Login")
            {
                if (options.RequireChallenge)
                {
                    string challenge = Opaque();
                    challenges[challenge] = true;
                    await WriteSoapAsync(response, version, ResponseElement("LoginResponse", "Challenge", challenge), StatusCodes.Status200OK, token).ConfigureAwait(false);
                    return;
                }
                await WriteSoapAsync(response, version, ResponseElement("LoginResponse", "SessionId", NewSession(sessions, options.SessionLifetime)), StatusCodes.Status200OK, token).ConfigureAwait(false);
                return;
            }
            if (parsed.Operation == "CompleteChallenge")
            {
                string challenge = parsed.Fields.GetValueOrDefault("Challenge") ?? string.Empty;
                string artifact = parsed.Fields.GetValueOrDefault("Artifact") ?? string.Empty;
                if (!challenges.TryRemove(challenge, out _) || !Fixed(artifact, "123456"))
                {
                    await WriteFaultAsync(response, version, "AuthenticationDenied", token).ConfigureAwait(false);
                    return;
                }
                await WriteSoapAsync(response, version, ResponseElement("CompleteChallengeResponse", "SessionId", NewSession(sessions, options.SessionLifetime)), StatusCodes.Status200OK, token).ConfigureAwait(false);
                return;
            }

            string session = parsed.Session ?? string.Empty;
            bool validSession = sessions.TryGetValue(session, out DateTimeOffset expiry) && expiry > DateTimeOffset.UtcNow;
            if (!validSession)
            {
                sessions.TryRemove(session, out _);
                await WriteFaultAsync(response, version, expiry == default ? "InvalidSession" : "SessionExpired", token).ConfigureAwait(false);
                return;
            }
            if (parsed.Operation == "Logout")
            {
                sessions.TryRemove(session, out _);
                await WriteSoapAsync(response, version, $"<op:LogoutResponse xmlns:op=\"{OperationNamespace}\"/>", StatusCodes.Status200OK, token).ConfigureAwait(false);
                return;
            }
            if (parsed.Operation != "BusinessOperation") { response.StatusCode = StatusCodes.Status400BadRequest; return; }

            string payload = parsed.Fields.GetValueOrDefault("Payload") ?? string.Empty;
            if (payload == "expire-once" && Interlocked.CompareExchange(ref expireBusinessOnce, 1, 0) == 0)
            {
                sessions.TryRemove(session, out _);
                await WriteFaultAsync(response, version, "SessionExpired", token).ConfigureAwait(false);
                return;
            }
            if (payload == "fault") { await WriteFaultAsync(response, version, "BusinessRejected", token).ConfigureAwait(false); return; }
            if (payload == "malformed")
            {
                response.StatusCode = StatusCodes.Status200OK;
                response.ContentType = ContentType(version);
                await response.WriteAsync("<not-closed>", token).ConfigureAwait(false);
                return;
            }
            if (payload == "oversize")
            {
                await WriteSoapAsync(response, version, ResponseElement("BusinessOperationResponse", "Result", new string('x', 2_000_000)), StatusCodes.Status200OK, token).ConfigureAwait(false);
                return;
            }
            if (payload == "timeout") await Task.Delay(options.TimeoutDelay, token).ConfigureAwait(false);
            await WriteSoapAsync(response, version, ResponseElement("BusinessOperationResponse", "Result", "accepted"), StatusCodes.Status200OK, token).ConfigureAwait(false);
        });

        await app.StartAsync(cancellationToken).ConfigureAwait(false);
        string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()?.Addresses.Single()
            ?? throw new InvalidOperationException("Synthetic SOAP server did not publish an address.");
        return new(app, new Uri(new Uri(address), "/service"), counters);
    }

    private static ParsedRequest Parse(byte[] body)
    {
        XmlReaderSettings settings = new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersFromEntities = 0, MaxCharactersInDocument = MaximumRequestBytes };
        using MemoryStream input = new(body, writable: false);
        using XmlReader reader = XmlReader.Create(input, settings);
        XDocument document = XDocument.Load(reader, LoadOptions.None);
        XElement envelope = document.Root ?? throw new XmlException();
        SoapVersion version = envelope.Name.NamespaceName switch
        {
            "http://schemas.xmlsoap.org/soap/envelope/" => SoapVersion.Soap11,
            "http://www.w3.org/2003/05/soap-envelope" => SoapVersion.Soap12,
            _ => throw new XmlException()
        };
        XNamespace soap = envelope.Name.Namespace;
        XElement bodyElement = envelope.Elements(soap + "Body").Single();
        XElement operation = bodyElement.Elements().Single();
        if (operation.Name.NamespaceName != OperationNamespace) throw new XmlException();
        XElement? header = envelope.Elements(soap + "Header").SingleOrDefault();
        XElement? session = header?.Elements().SingleOrDefault();
        if (session is not null && session.Name != XName.Get("Session", OperationNamespace)) throw new XmlException();
        Dictionary<string, string> fields = operation.Elements().ToDictionary(element => element.Name.LocalName, element => element.Value, StringComparer.Ordinal);
        return new(version, operation.Name.LocalName, session?.Value, fields);
    }

    private static bool ValidHttpPolicy(HttpRequest request, ParsedRequest parsed)
    {
        string action = "urn:synthetic:" + parsed.Operation;
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out MediaTypeHeaderValue? contentType)) return false;
        if (parsed.Version == SoapVersion.Soap11)
            return string.Equals(contentType.MediaType, "text/xml", StringComparison.OrdinalIgnoreCase) && Fixed(request.Headers["SOAPAction"].ToString().Trim('"'), action);
        NameValueHeaderValue? actionParameter = contentType.Parameters.SingleOrDefault(parameter => string.Equals(parameter.Name, "action", StringComparison.OrdinalIgnoreCase));
        return string.Equals(contentType.MediaType, "application/soap+xml", StringComparison.OrdinalIgnoreCase) && Fixed(actionParameter?.Value?.Trim('"') ?? string.Empty, action) && !request.Headers.ContainsKey("SOAPAction");
    }

    private static async Task<byte[]> ReadBoundedAsync(Stream input, int maximumBytes, CancellationToken cancellationToken)
    {
        using MemoryStream output = new();
        byte[] buffer = new byte[16_384];
        while (true)
        {
            int read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) return output.ToArray();
            if (output.Length + read > maximumBytes) throw new InvalidDataException();
            output.Write(buffer, 0, read);
        }
    }

    private static async Task WriteFaultAsync(HttpResponse response, SoapVersion version, string code, CancellationToken token)
    {
        string fault = version == SoapVersion.Soap11
            ? $"<soap:Fault xmlns:soap=\"{EnvelopeNamespace(version)}\" xmlns:f=\"{FaultNamespace}\"><faultcode>f:{code}</faultcode><faultstring>synthetic fault</faultstring></soap:Fault>"
            : $"<soap:Fault xmlns:soap=\"{EnvelopeNamespace(version)}\" xmlns:f=\"{FaultNamespace}\"><soap:Code><soap:Value>f:{code}</soap:Value></soap:Code><soap:Reason><soap:Text xml:lang=\"en\">synthetic fault</soap:Text></soap:Reason></soap:Fault>";
        await WriteSoapAsync(response, version, fault, StatusCodes.Status500InternalServerError, token).ConfigureAwait(false);
    }

    private static async Task WriteSoapAsync(HttpResponse response, SoapVersion version, string payload, int status, CancellationToken token)
    {
        response.StatusCode = status;
        response.ContentType = ContentType(version);
        await response.WriteAsync($"<soap:Envelope xmlns:soap=\"{EnvelopeNamespace(version)}\"><soap:Body>{payload}</soap:Body></soap:Envelope>", token).ConfigureAwait(false);
    }

    private static string ResponseElement(string response, string field, string value) => $"<op:{response} xmlns:op=\"{OperationNamespace}\"><op:{field}>{WebUtility.HtmlEncode(value)}</op:{field}></op:{response}>";
    private static string NewSession(ConcurrentDictionary<string, DateTimeOffset> sessions, TimeSpan lifetime) { string value = Opaque(); sessions[value] = DateTimeOffset.UtcNow.Add(lifetime); return value; }
    private static string Opaque() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static string ContentType(SoapVersion version) => version == SoapVersion.Soap11 ? "text/xml; charset=utf-8" : "application/soap+xml; charset=utf-8";
    private static string EnvelopeNamespace(SoapVersion version) => version == SoapVersion.Soap11 ? "http://schemas.xmlsoap.org/soap/envelope/" : "http://www.w3.org/2003/05/soap-envelope";

    private static bool ValidBasic(string value, string username, string password)
    {
        if (!value.StartsWith("Basic ", StringComparison.Ordinal)) return false;
        byte[] decoded;
        try { decoded = Convert.FromBase64String(value[6..]); }
        catch (FormatException) { return false; }
        try { return Fixed(Encoding.UTF8.GetString(decoded), username + ":" + password); }
        finally { CryptographicOperations.ZeroMemory(decoded); }
    }

    private static bool Fixed(string left, string right)
    {
        byte[] leftBytes = Encoding.UTF8.GetBytes(left);
        byte[] rightBytes = Encoding.UTF8.GetBytes(right);
        try { return leftBytes.Length == rightBytes.Length && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes); }
        finally { CryptographicOperations.ZeroMemory(leftBytes); CryptographicOperations.ZeroMemory(rightBytes); }
    }

    private static void Validate(SyntheticSoapServerOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.Username) || options.Username.Contains(':', StringComparison.Ordinal) || string.IsNullOrEmpty(options.Password) || options.SessionLifetime <= TimeSpan.Zero || options.TimeoutDelay <= TimeSpan.Zero)
            throw new ArgumentException("Invalid synthetic SOAP server configuration.", nameof(options));
    }

    private enum SoapVersion { Soap11, Soap12 }
    private sealed record ParsedRequest(SoapVersion Version, string Operation, string? Session, IReadOnlyDictionary<string, string> Fields);
}

internal static class Program
{
    private static void Main() => throw new InvalidOperationException("The synthetic SOAP server is started only by the controlled test harness.");
}

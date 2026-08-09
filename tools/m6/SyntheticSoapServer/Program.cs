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
public sealed record SyntheticSoapServerOptions(
    string Username,
    string Password,
    bool RequireChallenge,
    TimeSpan SessionLifetime,
    TimeSpan TimeoutDelay,
    bool RequireExternalAdmission = false,
    string ExternalSessionCandidate = "synthetic-external-session")
{
    /// <summary>Optional neutral custom header required by the composed SOAP endpoint.</summary>
    public string? OpaqueSessionHeaderName { get; init; }

    /// <summary>Expected opaque value for the composed SOAP endpoint.</summary>
    public string? OpaqueSessionValue { get; init; }
}

/// <summary>Thread-safe counters exposed only to the synthetic test harness.</summary>
public sealed class SyntheticSoapCounters
{
    private int login;
    private int challenge;
    private int business;
    private int logout;
    private int composed;
    private int composedAccepted;
    private int basicRejected;
    private int opaqueSessionRejected;
    private int soapPolicyRejected;
    private readonly TaskCompletionSource<bool> composedAcceptedObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int createSession;
    private int validateSession;
    private readonly TaskCompletionSource<bool> bodyHeadersFlushed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<bool> releaseStalledBody = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Login request count.</summary>
    public int Login => Volatile.Read(ref login);
    /// <summary>Challenge completion count.</summary>
    public int Challenge => Volatile.Read(ref challenge);
    /// <summary>Business request count.</summary>
    public int Business => Volatile.Read(ref business);
    /// <summary>Logout request count.</summary>
    public int Logout => Volatile.Read(ref logout);
    /// <summary>Requests reaching the composed SOAP endpoint.</summary>
    public int Composed => Volatile.Read(ref composed);
    /// <summary>Composed requests passing Basic, session, SOAP HTTP and XML validation.</summary>
    public int ComposedAccepted => Volatile.Read(ref composedAccepted);
    /// <summary>Composed requests rejected for missing or wrong Basic.</summary>
    public int BasicRejected => Volatile.Read(ref basicRejected);
    /// <summary>Composed requests rejected for missing, wrong or duplicate opaque session header.</summary>
    public int OpaqueSessionRejected => Volatile.Read(ref opaqueSessionRejected);
    /// <summary>Composed requests rejected for SOAP action, content type, version or envelope policy.</summary>
    public int SoapPolicyRejected => Volatile.Read(ref soapPolicyRejected);
    /// <summary>Completes when a composed request has passed request-side authentication and SOAP validation.</summary>
    public Task WaitForComposedAcceptedAsync(CancellationToken cancellationToken) => composedAcceptedObserved.Task.WaitAsync(cancellationToken);
    /// <summary>Typed nested session-handshake request count.</summary>
    public int CreateSession => Volatile.Read(ref createSession);
    /// <summary>Typed external-session validation request count.</summary>
    public int ValidateSession => Volatile.Read(ref validateSession);
    /// <summary>Completes after the stalled-body scenario has flushed its response headers.</summary>
    public Task WaitForBodyHeadersFlushedAsync(CancellationToken cancellationToken) => bodyHeadersFlushed.Task.WaitAsync(cancellationToken);

    internal void Count(string operation)
    {
        if (operation == "Login") Interlocked.Increment(ref login);
        else if (operation == "CompleteChallenge") Interlocked.Increment(ref challenge);
        else if (operation == "BusinessOperation") Interlocked.Increment(ref business);
        else if (operation == "Logout") Interlocked.Increment(ref logout);
        else if (operation == "CreateSession") Interlocked.Increment(ref createSession);
        else if (operation == "ValidateSession") Interlocked.Increment(ref validateSession);
    }

    internal void SignalBodyHeadersFlushed() => bodyHeadersFlushed.TrySetResult(true);
    internal Task WaitForStalledBodyReleaseAsync(CancellationToken cancellationToken) => releaseStalledBody.Task.WaitAsync(cancellationToken);
    internal void ReleaseStalledBody() => releaseStalledBody.TrySetResult(true);
    internal void CountComposed() => Interlocked.Increment(ref composed);
    internal void CountComposedAccepted()
    {
        Interlocked.Increment(ref composedAccepted);
        composedAcceptedObserved.TrySetResult(true);
    }
    internal void CountBasicRejected() => Interlocked.Increment(ref basicRejected);
    internal void CountOpaqueSessionRejected() => Interlocked.Increment(ref opaqueSessionRejected);
    internal void CountSoapPolicyRejected() => Interlocked.Increment(ref soapPolicyRejected);
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
        Counters.ReleaseStalledBody();
        await application.StopAsync().ConfigureAwait(false);
        await application.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>Starts the isolated synthetic server on a real loopback TLS socket.</summary>
public static class SyntheticSoapServerHost
{
    private const string OperationNamespace = "urn:synthetic:session";
    private const string FaultNamespace = "urn:synthetic:fault";
    private const string TypedSessionNamespace = "urn:synthetic:typed-session";
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

            if (parsed.Operation == "CreateSession")
            {
                if (!ValidCreateSessionRequest(parsed.Payload)) { response.StatusCode = StatusCodes.Status400BadRequest; return; }
                if (options.RequireExternalAdmission)
                {
                    string externalRequired = $"<s:CreateSessionResponse xmlns:s=\"{TypedSessionNamespace}\"><s:Result><s:Status>external_admission_required</s:Status><s:Admission><s:Provenance>interactive_handoff</s:Provenance></s:Admission></s:Result></s:CreateSessionResponse>";
                    await WriteSoapAsync(response, version, externalRequired, StatusCodes.Status200OK, token).ConfigureAwait(false);
                    return;
                }
                string issued = NewSession(sessions, options.SessionLifetime);
                DateTimeOffset issuedExpiry = sessions[issued];
                string issuedResponse = $"<s:CreateSessionResponse xmlns:s=\"{TypedSessionNamespace}\"><s:Result><s:Status>issued</s:Status><s:Session><s:Value>{WebUtility.HtmlEncode(issued)}</s:Value><s:ExpiresAt>{issuedExpiry:O}</s:ExpiresAt></s:Session></s:Result></s:CreateSessionResponse>";
                await WriteSoapAsync(response, version, issuedResponse, StatusCodes.Status200OK, token).ConfigureAwait(false);
                return;
            }
            if (parsed.Operation == "ValidateSession")
            {
                string? candidate = ReadValidationCandidate(parsed.Payload);
                if (candidate is null || !Fixed(candidate, options.ExternalSessionCandidate))
                {
                    string rejected = $"<s:ValidateSessionResponse xmlns:s=\"{TypedSessionNamespace}\"><s:Validation><s:Status>rejected</s:Status></s:Validation></s:ValidateSessionResponse>";
                    await WriteSoapAsync(response, version, rejected, StatusCodes.Status200OK, token).ConfigureAwait(false);
                    return;
                }
                DateTimeOffset validationExpiry = DateTimeOffset.UtcNow.Add(options.SessionLifetime);
                sessions[candidate] = validationExpiry;
                string valid = $"<s:ValidateSessionResponse xmlns:s=\"{TypedSessionNamespace}\"><s:Validation><s:Status>valid</s:Status><s:ExpiresAt>{validationExpiry:O}</s:ExpiresAt></s:Validation></s:ValidateSessionResponse>";
                await WriteSoapAsync(response, version, valid, StatusCodes.Status200OK, token).ConfigureAwait(false);
                return;
            }

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
            if (payload == "body-stalled")
            {
                response.StatusCode = StatusCodes.Status200OK;
                response.ContentType = ContentType(version);
                response.ContentLength = 512;
                await response.StartAsync(token).ConfigureAwait(false);
                await response.Body.FlushAsync(token).ConfigureAwait(false);
                counters.SignalBodyHeadersFlushed();
                await counters.WaitForStalledBodyReleaseAsync(token).ConfigureAwait(false);
                return;
            }
            if (payload == "timeout") await Task.Delay(options.TimeoutDelay, token).ConfigureAwait(false);
            await WriteSoapAsync(response, version, ResponseElement("BusinessOperationResponse", "Result", "accepted"), StatusCodes.Status200OK, token).ConfigureAwait(false);
        });

        app.MapPost("/composed", async (HttpRequest request, HttpResponse response, CancellationToken token) =>
        {
            if (options.OpaqueSessionHeaderName is null || options.OpaqueSessionValue is null)
            {
                response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }
            counters.CountComposed();
            if (!ValidBasic(request.Headers.Authorization.ToString(), options.Username, options.Password))
            {
                counters.CountBasicRejected();
                response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
            Microsoft.Extensions.Primitives.StringValues sessionValues = request.Headers[options.OpaqueSessionHeaderName!];
            if (sessionValues.Count != 1 || sessionValues[0]?.Contains(',', StringComparison.Ordinal) == true || !Fixed(sessionValues[0] ?? string.Empty, options.OpaqueSessionValue!))
            {
                counters.CountOpaqueSessionRejected();
                response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
            byte[] body;
            try { body = await ReadBoundedAsync(request.Body, MaximumRequestBytes, token).ConfigureAwait(false); }
            catch (InvalidDataException) { counters.CountSoapPolicyRejected(); response.StatusCode = StatusCodes.Status413PayloadTooLarge; return; }
            ParsedRequest parsed;
            try { parsed = Parse(body); }
            catch (Exception exception) when (exception is XmlException or InvalidOperationException or ArgumentException)
            {
                counters.CountSoapPolicyRejected();
                response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }
            if (!ValidHttpPolicy(request, parsed) || parsed.Session is not null || parsed.Operation != "BusinessOperation")
            {
                counters.CountSoapPolicyRejected();
                response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
                return;
            }
            counters.CountComposedAccepted();
            string payload = parsed.Fields.GetValueOrDefault("Payload") ?? string.Empty;
            if (payload == "fault") { await WriteFaultAsync(response, parsed.Version, "BusinessRejected", token).ConfigureAwait(false); return; }
            if (payload == "malformed-fault")
            {
                string malformed = parsed.Version == SoapVersion.Soap11
                    ? $"<soap:Fault xmlns:soap=\"{EnvelopeNamespace(parsed.Version)}\" xmlns:f=\"{FaultNamespace}\"><faultcode>f:BusinessRejected</faultcode><faultcode>f:Other</faultcode><faultstring>synthetic fault</faultstring></soap:Fault>"
                    : $"<soap:Fault xmlns:soap=\"{EnvelopeNamespace(parsed.Version)}\" xmlns:f=\"{FaultNamespace}\"><soap:Code><soap:Value>f:BusinessRejected</soap:Value><soap:Value>f:Other</soap:Value></soap:Code><soap:Reason><soap:Text xml:lang=\"en\">synthetic fault</soap:Text></soap:Reason></soap:Fault>";
                await WriteSoapAsync(response, parsed.Version, malformed, StatusCodes.Status500InternalServerError, token).ConfigureAwait(false);
                return;
            }
            if (payload == "timeout") await Task.Delay(options.TimeoutDelay, token).ConfigureAwait(false);
            await WriteSoapAsync(response, parsed.Version, ResponseElement("BusinessOperationResponse", "Result", "accepted"), StatusCodes.Status200OK, token).ConfigureAwait(false);
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
        if (operation.Name.NamespaceName != OperationNamespace && operation.Name.NamespaceName != TypedSessionNamespace) throw new XmlException();
        XElement? header = envelope.Elements(soap + "Header").SingleOrDefault();
        XElement? session = header?.Elements().SingleOrDefault();
        if (session is not null && session.Name != XName.Get("Session", OperationNamespace)) throw new XmlException();
        Dictionary<string, string> fields = operation.Elements().ToDictionary(element => element.Name.LocalName, element => element.Value, StringComparer.Ordinal);
        string operationName = operation.Name.LocalName switch
        {
            "CreateSessionRequest" => "CreateSession",
            "ValidateSessionRequest" => "ValidateSession",
            _ => operation.Name.LocalName
        };
        return new(version, operationName, session?.Value, fields, operation);
    }

    private static bool ValidHttpPolicy(HttpRequest request, ParsedRequest parsed)
    {
        string action = "urn:synthetic:" + parsed.Operation;
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out MediaTypeHeaderValue? contentType)) return false;
        NameValueHeaderValue[] charsetParameters = contentType.Parameters.Where(parameter => string.Equals(parameter.Name, "charset", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (charsetParameters.Length != 1 || !string.Equals(charsetParameters[0].Value?.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase)) return false;
        if (parsed.Version == SoapVersion.Soap11)
        {
            Microsoft.Extensions.Primitives.StringValues soapActions = request.Headers["SOAPAction"];
            return string.Equals(contentType.MediaType, "text/xml", StringComparison.OrdinalIgnoreCase) && contentType.Parameters.Count == 1 &&
                soapActions.Count == 1 && soapActions[0]?.Contains(',', StringComparison.Ordinal) != true && Fixed(soapActions[0] ?? string.Empty, '"' + action + '"');
        }
        NameValueHeaderValue[] actionParameters = contentType.Parameters.Where(parameter => string.Equals(parameter.Name, "action", StringComparison.OrdinalIgnoreCase)).ToArray();
        return string.Equals(contentType.MediaType, "application/soap+xml", StringComparison.OrdinalIgnoreCase) && contentType.Parameters.Count == 2 && actionParameters.Length == 1 &&
            Fixed(actionParameters[0].Value ?? string.Empty, '"' + action + '"') && !request.Headers.ContainsKey("SOAPAction");
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

    private static bool ValidCreateSessionRequest(XElement request)
    {
        XNamespace session = TypedSessionNamespace;
        if (request.Name != session + "CreateSessionRequest" || request.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)) return false;
        XElement[] root = request.Elements().ToArray();
        if (root.Length != 1 || root[0].Name != session + "ClientContext") return false;
        XElement[] context = root[0].Elements().ToArray();
        if (context.Length != 2 || context[0].Name != session + "Identity" || context[1].Name != session + "Policy") return false;
        XElement[] identity = context[0].Elements().ToArray();
        XElement[] policy = context[1].Elements().ToArray();
        return identity.Select(value => value.Name).SequenceEqual([session + "Tenant", session + "Installation", session + "Application"]) &&
            identity.All(value => !value.HasElements && !string.IsNullOrWhiteSpace(value.Value)) &&
            policy.Select(value => value.Name).SequenceEqual([session + "Profile", session + "PublishedChecksum"]) &&
            Fixed(policy[0].Value, "typed-session") && policy[1].Value.Length == 64;
    }

    private static string? ReadValidationCandidate(XElement request)
    {
        XNamespace session = TypedSessionNamespace;
        if (request.Name != session + "ValidateSessionRequest" || request.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)) return null;
        XElement[] root = request.Elements().ToArray();
        if (root.Length != 1 || root[0].Name != session + "Candidate") return null;
        XElement[] candidate = root[0].Elements().ToArray();
        return candidate.Length == 2 && candidate[0].Name == session + "Provenance" && candidate[1].Name == session + "OpaqueValue" &&
            Fixed(candidate[0].Value, "interactive_handoff") && !candidate[1].HasElements
            ? candidate[1].Value
            : null;
    }
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
        if (string.IsNullOrWhiteSpace(options.Username) || options.Username.Contains(':', StringComparison.Ordinal) || string.IsNullOrEmpty(options.Password) ||
            options.SessionLifetime <= TimeSpan.Zero || options.TimeoutDelay <= TimeSpan.Zero ||
            string.IsNullOrWhiteSpace(options.ExternalSessionCandidate) || options.ExternalSessionCandidate.Length > 16_384 || options.ExternalSessionCandidate.Any(char.IsControl))
            throw new ArgumentException("Invalid synthetic SOAP server configuration.", nameof(options));
        if ((options.OpaqueSessionHeaderName is null) != (options.OpaqueSessionValue is null) ||
            options.OpaqueSessionHeaderName is not null && (!options.OpaqueSessionHeaderName.All(character => char.IsAsciiLetterOrDigit(character) || character is '-') || string.IsNullOrEmpty(options.OpaqueSessionValue)))
            throw new ArgumentException("Invalid synthetic composed SOAP configuration.", nameof(options));
    }

    private enum SoapVersion { Soap11, Soap12 }
    private sealed record ParsedRequest(SoapVersion Version, string Operation, string? Session, IReadOnlyDictionary<string, string> Fields, XElement Payload);
}

internal static class Program
{
    private static void Main() => throw new InvalidOperationException("The synthetic SOAP server is started only by the controlled test harness.");
}

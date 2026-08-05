using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SecureIntegration.Gateway.Application;

if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
{
    Usage();
    return args.Length == 0 ? 2 : 0;
}

string? key = Environment.GetEnvironmentVariable("GATEWAY_ADMIN_API_KEY", EnvironmentVariableTarget.Process);
if (string.IsNullOrWhiteSpace(key))
{
    Console.Error.WriteLine("CONNECTOR_CLI_ADMIN_KEY_REQUIRED");
    return 2;
}
string baseAddress = Environment.GetEnvironmentVariable("CONNECTOR_GATEWAY_URL", EnvironmentVariableTarget.Process) ?? "http://127.0.0.1:8080/";
if (!Uri.TryCreate(baseAddress, UriKind.Absolute, out Uri? gateway) || (gateway.Scheme != Uri.UriSchemeHttps && !gateway.IsLoopback))
{
    Console.Error.WriteLine("CONNECTOR_CLI_GATEWAY_URL_INVALID");
    return 2;
}

string? caPath = Environment.GetEnvironmentVariable("CONNECTOR_GATEWAY_CA_FILE", EnvironmentVariableTarget.Process);
using X509Certificate2? customRoot = string.IsNullOrWhiteSpace(caPath) ? null : X509CertificateLoader.LoadCertificateFromFile(caPath);
using HttpClientHandler handler = new() { AllowAutoRedirect = false, UseCookies = false, UseProxy = false };
if (customRoot is not null)
{
    handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
    {
        if (certificate is null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(customRoot);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(certificate);
    };
}
using HttpClient client = new(handler) { BaseAddress = gateway, Timeout = TimeSpan.FromSeconds(30) };
client.DefaultRequestHeaders.Add("X-Admin-Key", key);
client.DefaultRequestHeaders.Add("X-Admin-Actor", Environment.GetEnvironmentVariable("CONNECTOR_ADMIN_ACTOR") ?? "connector-cli");
JsonSerializerOptions json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

try
{
    switch (args[0])
    {
        case "validate" when args.Length == 2:
            using (JsonDocument document = ReadDefinition(args[1]))
                await PrintAsync(await SendAsync(HttpMethod.Post, "admin/v1/connectors:validate", new ConnectorImportRequest(document.RootElement.Clone())));
            break;
        case "import" when args.Length is 2 or 3:
            using (JsonDocument document = ReadDefinition(args[1]))
                await PrintAsync(await SendAsync(HttpMethod.Post, "admin/v1/connectors:import", new ConnectorImportRequest(document.RootElement.Clone(), args.Length == 3 ? args[2] : null)));
            break;
        case "list" when args.Length == 1:
            await PrintAsync(await SendAsync(HttpMethod.Get, "admin/v1/connectors"));
            break;
        case "show" when args.Length == 3:
            await PrintAsync(await SendAsync(HttpMethod.Get, $"admin/v1/connectors/{Segment(args[1])}/versions/{Segment(args[2])}"));
            break;
        case "export" when args.Length is 3 or 4:
        {
            HttpResponseMessage response = await SendAsync(HttpMethod.Get, $"admin/v1/connectors/{Segment(args[1])}/versions/{Segment(args[2])}:export");
            string content = await response.Content.ReadAsStringAsync();
            if (args.Length == 4) await File.WriteAllTextAsync(args[3], content + Environment.NewLine, new UTF8Encoding(false));
            else Console.WriteLine(content);
            break;
        }
        case "versions" when args.Length == 2:
            await PrintAsync(await SendAsync(HttpMethod.Get, $"admin/v1/connectors/{Segment(args[1])}/versions"));
            break;
        case "publish" when args.Length == 5:
            await PrintAsync(await SendAsync(HttpMethod.Post, $"admin/v1/connectors/{Segment(args[1])}/versions/{Segment(args[2])}:publish", new ConnectorVersionActionRequest(ParseLong(args[3]), ParseLong(args[4]))));
            break;
        case "rollback" when args.Length == 4:
            await PrintAsync(await SendAsync(HttpMethod.Post, $"admin/v1/connectors/{Segment(args[1])}:rollback", new ConnectorRollbackRequest(args[2], ParseLong(args[3]))));
            break;
        case "retire" when args.Length == 4:
            await PrintAsync(await SendAsync(HttpMethod.Post, $"admin/v1/connectors/{Segment(args[1])}/versions/{Segment(args[2])}:retire", new ConnectorVersionActionRequest(ParseLong(args[3]))));
            break;
        case "test" when args.Length == 4:
            await PrintAsync(await SendAsync(HttpMethod.Post, $"admin/v1/connectors/{Segment(args[1])}:test", new ConnectorTestRequest(Guid.Parse(args[3]), args[2])));
            break;
        default:
            Usage();
            return 2;
    }
}
catch (Exception exception) when (exception is IOException or JsonException or HttpRequestException or FormatException or TaskCanceledException)
{
    Console.Error.WriteLine("CONNECTOR_CLI_FAILED");
    return 1;
}
return 0;

async Task<HttpResponseMessage> SendAsync(HttpMethod method, string relative, object? body = null)
{
    using HttpRequestMessage request = new(method, relative);
    if (body is not null) request.Content = JsonContent.Create(body, options: json);
    HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
    if (!response.IsSuccessStatusCode)
    {
        string problem = await response.Content.ReadAsStringAsync();
        Console.Error.WriteLine(problem.Length <= 8192 ? problem : "CONNECTOR_CLI_ERROR_RESPONSE_TOO_LARGE");
        response.Dispose();
        throw new HttpRequestException("Connector Admin API rejected the request.");
    }
    return response;
}

async Task PrintAsync(HttpResponseMessage response)
{
    using (response)
    {
        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStreamAsync());
        Console.WriteLine(JsonSerializer.Serialize(document.RootElement, json));
    }
}

static JsonDocument ReadDefinition(string path)
{
    FileInfo file = new(path);
    if (!file.Exists || file.Length > 1024 * 1024) throw new IOException("Connector definition file is missing or too large.");
    return JsonDocument.Parse(File.ReadAllBytes(file.FullName), new JsonDocumentOptions { MaxDepth = 32 });
}

static long ParseLong(string value) => long.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long parsed) && parsed >= 0 ? parsed : throw new FormatException();
static string Segment(string value) => Uri.EscapeDataString(value);

static void Usage() => Console.WriteLine("""
    connector validate <file.json>
    connector import <file.json> [expected-sha256]
    connector list
    connector show <connector-id> <version>
    connector export <connector-id> <version> [output.json]
    connector versions <connector-id>
    connector publish <connector-id> <version> <row-version> <publication-revision>
    connector rollback <connector-id> <target-version> <active-row-version>
    connector retire <connector-id> <version> <row-version>
    connector test <connector-id> <operation-id> <environment-id>

    Environment: CONNECTOR_GATEWAY_URL, CONNECTOR_GATEWAY_CA_FILE,
                 GATEWAY_ADMIN_API_KEY, CONNECTOR_ADMIN_ACTOR.
    """);

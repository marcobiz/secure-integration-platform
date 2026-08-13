using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.HttpOverrides;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Logging.AddJsonConsole();
builder.WebHost.ConfigureKestrel(options => options.ConfigureHttpsDefaults(https =>
{
    https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
    https.AllowAnyClientCertificate();
}));
bool useAzureCertificateForwarding = !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID"));
if (useAzureCertificateForwarding) builder.Services.AddCertificateForwarding(options => options.CertificateHeader = "X-ARR-ClientCert");
WebApplication app = builder.Build();
if (useAzureCertificateForwarding) app.UseCertificateForwarding();

string expectedApiKey = Required("M3_VENDOR_API_KEY", 16);
string expectedThumbprint = NormalizeThumbprint(Required("M3_VENDOR_CLIENT_THUMBPRINT", 40));
string controlToken = Required("M3_VENDOR_CONTROL_TOKEN", 32);
long accepted = 0;
long denied = 0;
AcceptedRequestMetadata? lastAccepted = null;

app.MapGet("/health/ready", () => Results.Ok(new { status = "healthy" }));
app.MapPost("/vendor/orders", async (HttpContext context, CancellationToken cancellationToken) =>
{
    X509Certificate2? certificate = await context.Connection.GetClientCertificateAsync(cancellationToken).ConfigureAwait(false);
    bool certificateAccepted = certificate is not null && FixedEquals(NormalizeThumbprint(certificate.Thumbprint), expectedThumbprint);
    bool keyAccepted = FixedEquals(context.Request.Headers["X-Vendor-Api-Key"].ToString(), expectedApiKey);
    if (!certificateAccepted || !keyAccepted)
    {
        Interlocked.Increment(ref denied);
        return Results.Json(new { code = "M3-VENDOR-AUTH-DENIED" }, statusCode: 403);
    }
    if (context.Request.ContentLength > 1024 * 1024) return Results.StatusCode(413);
    using MemoryStream sink = new();
    await context.Request.Body.CopyToAsync(sink, cancellationToken).ConfigureAwait(false);
    byte[] requestBytes = sink.ToArray();
    Interlocked.Exchange(ref lastAccepted, new AcceptedRequestMetadata(
        context.Request.Method,
        context.Request.Path.Value ?? string.Empty,
        context.Request.ContentType ?? string.Empty,
        requestBytes.Length,
        Convert.ToHexString(SHA256.HashData(requestBytes)),
        Convert.ToHexString(SHA256.HashData(certificate!.RawData))));
    CryptographicOperations.ZeroMemory(requestBytes);
    Interlocked.Increment(ref accepted);
    return Results.Ok(new { accepted = true, requestBytes = sink.Length, vendorReference = "synthetic-order" });
});
app.MapPost("/vendor/redirect", () => Results.Redirect("https://metadata.invalid/latest/meta-data/", permanent: false));
app.MapGet("/m3/stats", (HttpContext context) =>
{
    if (!FixedEquals(context.Request.Headers["X-M3-Control-Token"].ToString(), controlToken)) return Results.Unauthorized();
    return Results.Ok(new { accepted = Interlocked.Read(ref accepted), denied = Interlocked.Read(ref denied), lastAccepted = Volatile.Read(ref lastAccepted) });
});
app.Run();

static string Required(string name, int minimumLength)
{
    string? value = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);
    if (string.IsNullOrWhiteSpace(value) || value.Length < minimumLength || value.Any(character => character is '\r' or '\n')) throw new InvalidOperationException($"Required synthetic setting {name} is missing or invalid.");
    return value;
}

static string NormalizeThumbprint(string value) => value.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
static bool FixedEquals(string left, string right)
{
    byte[] leftBytes = Encoding.UTF8.GetBytes(left);
    byte[] rightBytes = Encoding.UTF8.GetBytes(right);
    return leftBytes.Length == rightBytes.Length && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
}

/// <summary>Entry point marker.</summary>
public partial class Program;

internal sealed record AcceptedRequestMetadata(
    string Method,
    string Path,
    string ContentType,
    long BodyBytes,
    string BodySha256,
    string ClientCertificateSha256);

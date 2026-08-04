using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Logging.AddJsonConsole();
WebApplication app = builder.Build();

string token = RequiredSecret("M3_SYNTHETIC_VAULT_TOKEN", 32);
Dictionary<string, string> secrets = new(StringComparer.Ordinal)
{
    ["vendor-api-key"] = RequiredSecret("M3_VENDOR_API_KEY", 16),
    ["vendor-client-certificate"] = RequiredSecret("M3_VENDOR_CLIENT_PFX_BASE64", 100),
    ["vendor-wrong-client-certificate"] = RequiredSecret("M3_WRONG_VENDOR_CLIENT_PFX_BASE64", 100),
    ["activation-hmac"] = RequiredSecret("M3_ACTIVATION_HMAC_BASE64", 40)
};
ConcurrentDictionary<string, long> reads = new(StringComparer.Ordinal);
bool available = true;

app.Use(async (context, next) =>
{
    if (!FixedEquals(context.Request.Headers["X-M3-Vault-Token"].ToString(), token))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsJsonAsync(new { code = "M3-VAULT-AUTH-DENIED" }).ConfigureAwait(false);
        return;
    }
    await next(context).ConfigureAwait(false);
});
app.MapGet("/health/ready", () => available ? Results.Ok(new { status = "healthy" }) : Results.StatusCode(503));
app.MapGet("/v1/secrets/{name}", (string name) =>
{
    if (!available) return Results.Json(new { code = "M3-VAULT-UNAVAILABLE" }, statusCode: 503);
    if (!secrets.TryGetValue(name, out string? value)) return Results.Json(new { code = "M3-VAULT-NOT-FOUND" }, statusCode: 404);
    reads.AddOrUpdate(name, 1, static (_, current) => current + 1);
    return Results.Ok(new { value });
});
app.MapGet("/m3/stats", () => Results.Ok(new { available, reads = reads.OrderBy(value => value.Key).ToDictionary() }));
app.MapPut("/m3/availability/{state}", (string state) =>
{
    if (!bool.TryParse(state, out bool requested)) return Results.BadRequest(new { code = "M3-CONTROL-INVALID" });
    available = requested;
    return Results.Ok(new { available });
});
app.Run();

static string RequiredSecret(string name, int minimumLength)
{
    string? value = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process);
    if (string.IsNullOrWhiteSpace(value) || value.Length < minimumLength || value.Any(character => character is '\r' or '\n')) throw new InvalidOperationException($"Required synthetic setting {name} is missing or invalid.");
    return value;
}

static bool FixedEquals(string left, string right)
{
    byte[] leftBytes = Encoding.UTF8.GetBytes(left);
    byte[] rightBytes = Encoding.UTF8.GetBytes(right);
    return leftBytes.Length == rightBytes.Length && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
}

/// <summary>Entry point marker.</summary>
public partial class Program;

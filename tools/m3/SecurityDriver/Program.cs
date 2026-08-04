using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

string gatewayBase = Required("M3_GATEWAY_BASE_ADDRESS");
string provisioningPath = Required("M3_PROVISIONING_FILE");
string certificatePath = Required("M3_SECURITY_DRIVER_PFX");
string certificatePassword = Required("M3_CERTIFICATE_PASSWORD");
string vaultToken = Required("M3_SYNTHETIC_VAULT_TOKEN");
string adminConnection = Required("M3_POSTGRES_ADMIN_CONNECTION");
string outputPath = Required("M3_SECURITY_OUTPUT");
using JsonDocument provisioning = JsonDocument.Parse(await File.ReadAllBytesAsync(provisioningPath).ConfigureAwait(false));
JsonElement root = provisioning.RootElement;
Guid installationId = root.GetProperty("securityInstallationId").GetGuid();
Guid tenantId = root.GetProperty("securityTenantId").GetGuid();
Guid activationCodeId = root.GetProperty("securityActivationCodeId").GetGuid();
string activationCode = root.GetProperty("securityActivationCode").GetString() ?? throw new InvalidOperationException("Security activation code missing.");
using X509Certificate2 certificate = X509CertificateLoader.LoadPkcs12FromFile(certificatePath, certificatePassword, X509KeyStorageFlags.EphemeralKeySet);
using ECDsa privateKey = certificate.GetECDsaPrivateKey() ?? throw new InvalidOperationException("Security driver certificate has no ECDSA private key.");
using HttpClient bootstrap = new() { BaseAddress = new Uri(gatewayBase), Timeout = TimeSpan.FromSeconds(15) };
using HttpClient authenticated = CreateClient(new Uri(gatewayBase), certificate);
List<Scenario> scenarios = [];

await EnrollAsync().ConfigureAwait(false);
byte[] normalBody = InvokeBody();
Result positive = await SendSignedAsync(authenticated, "m3-vendor", "submit", normalBody).ConfigureAwait(false);
bool sanitized = positive.Status == HttpStatusCode.OK && ResponseIsSanitized(positive.Body);
Record("M3-P01", true, "BGW-ENROLLMENT-OK");
Record("M3-P03-P07", sanitized, positive.Code);

SignedRequest invalid = Sign("m3-vendor", "submit", normalBody);
invalid.Headers["X-BG-Signature"] = Base64Url(RandomNumberGenerator.GetBytes(64));
Result invalidSignature = await SendAsync(authenticated, invalid).ConfigureAwait(false);
Record("M3-N02", invalidSignature.Status == HttpStatusCode.Unauthorized && invalidSignature.Code == "BGW-AUTHN-SIGNATURE", invalidSignature.Code);

SignedRequest replay = Sign("m3-vendor", "submit", normalBody);
Result replayFirst = await SendAsync(authenticated, replay).ConfigureAwait(false);
Result replaySecond = await SendAsync(authenticated, replay).ConfigureAwait(false);
Record("M3-N03", replayFirst.Status == HttpStatusCode.OK && replaySecond.Status == HttpStatusCode.Unauthorized && replaySecond.Code == "BGW-AUTHN-REPLAY", replaySecond.Code);

Result tenantOverride = await SendSignedAsync(authenticated, "m3-vendor", "submit", InvokeBody(("tenantId", Guid.NewGuid().ToString("D")))).ConfigureAwait(false);
Record("M3-N04", tenantOverride.Status == HttpStatusCode.BadRequest && tenantOverride.Code == "BGW-PROTOCOL-JSON", tenantOverride.Code);
Result connectorDenied = await SendSignedAsync(authenticated, "not-granted", "submit", normalBody).ConfigureAwait(false);
Record("M3-N05", connectorDenied.Status is HttpStatusCode.NotFound or HttpStatusCode.Forbidden, connectorDenied.Code);
Result operationDenied = await SendSignedAsync(authenticated, "m3-vendor", "not-granted", normalBody).ConfigureAwait(false);
Record("M3-N06", operationDenied.Status is HttpStatusCode.NotFound or HttpStatusCode.Forbidden, operationDenied.Code);
Result urlOverride = await SendSignedAsync(authenticated, "m3-vendor", "submit", InvokeBody(("url", "https://attacker.example.invalid/"))).ConfigureAwait(false);
Record("M3-N07", urlOverride.Status == HttpStatusCode.BadRequest && urlOverride.Code == "BGW-PROTOCOL-JSON", urlOverride.Code);

Result loopback = await SendSignedAsync(authenticated, "m3-vendor", "loopback", normalBody).ConfigureAwait(false);
Result privateAddress = await SendSignedAsync(authenticated, "m3-vendor", "private", normalBody).ConfigureAwait(false);
Result metadata = await SendSignedAsync(authenticated, "m3-vendor", "metadata", normalBody).ConfigureAwait(false);
Record("M3-N08", new[] { loopback, privateAddress, metadata }.All(result => result.Status == HttpStatusCode.Forbidden && result.Code == "BGW-EGRESS-DESTINATION-DENIED"), $"{loopback.Code}/{privateAddress.Code}/{metadata.Code}");
Result dnsOverride = await SendSignedAsync(authenticated, "m3-vendor", "submit", InvokeBody(("resolvedAddress", "169.254.169.254"))).ConfigureAwait(false);
Record("M3-N09", dnsOverride.Status == HttpStatusCode.BadRequest && dnsOverride.Code == "BGW-PROTOCOL-JSON", dnsOverride.Code);
Result secretOverride = await SendSignedAsync(authenticated, "m3-vendor", "submit", InvokeBody(("secretReference", "synthetic-vault://vault.m3.test/arbitrary"))).ConfigureAwait(false);
Record("M3-N10", secretOverride.Status == HttpStatusCode.BadRequest && secretOverride.Code == "BGW-PROTOCOL-JSON", secretOverride.Code);
Result redirect = await SendSignedAsync(authenticated, "m3-vendor", "redirect", normalBody).ConfigureAwait(false);
Record("M3-N11", redirect.Status == HttpStatusCode.BadGateway && redirect.Code == "BGW-EGRESS-REDIRECT-DENIED", redirect.Code);
Result wrongCertificate = await SendSignedAsync(authenticated, "m3-vendor", "wrong-certificate", normalBody).ConfigureAwait(false);
Record("M3-N12", wrongCertificate.Status == HttpStatusCode.BadGateway && wrongCertificate.Code == "BGW-EGRESS-UPSTREAM-REJECTED", wrongCertificate.Code);

await SetVaultAvailabilityAsync(false).ConfigureAwait(false);
try
{
    Result unavailable = await SendSignedAsync(authenticated, "m3-vendor", "submit", normalBody).ConfigureAwait(false);
    Record("M3-N13", unavailable.Status == HttpStatusCode.ServiceUnavailable && unavailable.Code.StartsWith("BGW-VAULT-", StringComparison.Ordinal), unavailable.Code);
}
finally { await SetVaultAvailabilityAsync(true).ConfigureAwait(false); }

await SetDatabaseAvailabilityAsync(false).ConfigureAwait(false);
try
{
    Result unavailable = await SendSignedAsync(authenticated, "m3-vendor", "submit", normalBody).ConfigureAwait(false);
    Record("M3-N14", unavailable.Status == HttpStatusCode.InternalServerError && unavailable.Code == "BGW-INTERNAL", unavailable.Code);
}
finally { await SetDatabaseAvailabilityAsync(true).ConfigureAwait(false); }

await RevokeAsync().ConfigureAwait(false);
Result revoked = await SendSignedAsync(authenticated, "m3-vendor", "submit", normalBody).ConfigureAwait(false);
Record("M3-N01", revoked.Status == HttpStatusCode.Forbidden && revoked.Code == "BGW-INSTALLATION-REVOKED", revoked.Code);

bool passed = scenarios.All(scenario => scenario.Passed);
Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(new { schemaVersion = 1, passed, scenarios }, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true })).ConfigureAwait(false);
return passed ? 0 : 1;

async Task EnrollAsync()
{
    string spki = Convert.ToBase64String(privateKey.ExportSubjectPublicKeyInfo());
    using HttpResponseMessage challengeResponse = await bootstrap.PostAsJsonAsync("/v1/enrollments/challenges", new { activationCodeId, publicKeySpki = spki }).ConfigureAwait(false);
    challengeResponse.EnsureSuccessStatusCode();
    Challenge challenge = await challengeResponse.Content.ReadFromJsonAsync<Challenge>().ConfigureAwait(false) ?? throw new InvalidOperationException("Enrollment challenge missing.");
    byte[] proof = Encoding.UTF8.GetBytes(FormattableString.Invariant($"BGW-ENROLL1\n{challenge.ChallengeId:D}\n{challenge.ChallengeValue}\n{activationCodeId:D}"));
    string signature = Base64Url(privateKey.SignData(proof, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    using HttpResponseMessage response = await bootstrap.PostAsJsonAsync("/v1/enrollments:activate", new { challengeId = challenge.ChallengeId, activationCode, clientCertificate = Convert.ToBase64String(certificate.RawData), proofSignature = signature, brokerVersion = "1.0.0" }).ConfigureAwait(false);
    response.EnsureSuccessStatusCode();
}

void Record(string id, bool passed, string code) => scenarios.Add(new Scenario(id, passed, passed ? "PASS" : "FAIL", code));

async Task SetVaultAvailabilityAsync(bool value)
{
    using HttpClient control = new() { BaseAddress = new Uri("https://localhost:18444"), Timeout = TimeSpan.FromSeconds(10) };
    using HttpRequestMessage request = new(HttpMethod.Put, "/m3/availability/" + value.ToString(CultureInfo.InvariantCulture).ToLowerInvariant());
    request.Headers.TryAddWithoutValidation("X-M3-Vault-Token", vaultToken);
    using HttpResponseMessage response = await control.SendAsync(request).ConfigureAwait(false);
    response.EnsureSuccessStatusCode();
}

async Task SetDatabaseAvailabilityAsync(bool available)
{
    NpgsqlConnectionStringBuilder builder = new(adminConnection) { Database = "postgres" };
    await using NpgsqlConnection connection = new(builder.ConnectionString);
    await connection.OpenAsync().ConfigureAwait(false);
    string sql = available
        ? "ALTER DATABASE broker_gateway_m3 WITH ALLOW_CONNECTIONS true"
        : "ALTER DATABASE broker_gateway_m3 WITH ALLOW_CONNECTIONS false; SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='broker_gateway_m3'";
    await using NpgsqlCommand command = new(sql, connection);
    await command.ExecuteNonQueryAsync().ConfigureAwait(false);
    if (available) await Task.Delay(500).ConfigureAwait(false);
}

async Task RevokeAsync()
{
    await using NpgsqlConnection connection = new(adminConnection);
    await connection.OpenAsync().ConfigureAwait(false);
    await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync().ConfigureAwait(false);
    await using (NpgsqlCommand context = new("SELECT set_config('app.tenant_id',$1,true)", connection, transaction))
    {
        context.Parameters.AddWithValue(tenantId.ToString("D"));
        await context.ExecuteNonQueryAsync().ConfigureAwait(false);
    }
    await using (NpgsqlCommand command = new("UPDATE gateway.installation SET status='revoked',revoked_at=now(),revocation_reason='m3 negative scenario' WHERE id=$1; UPDATE gateway.installation_credential SET status='revoked',revoked_at=now() WHERE installation_id=$1", connection, transaction))
    {
        command.Parameters.AddWithValue(installationId);
        await command.ExecuteNonQueryAsync().ConfigureAwait(false);
    }
    await transaction.CommitAsync().ConfigureAwait(false);
}

SignedRequest Sign(string connector, string operation, byte[] body)
{
    string target = $"/v1/connectors/{Uri.EscapeDataString(connector)}/operations/{Uri.EscapeDataString(operation)}:invoke";
    string timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'", CultureInfo.InvariantCulture);
    string nonce = Base64Url(RandomNumberGenerator.GetBytes(16));
    string digest = Base64Url(SHA256.HashData(body));
    string input = string.Join('\n', "BGW1", "POST", target, timestamp, nonce, digest);
    string signature = Base64Url(privateKey.SignData(Encoding.UTF8.GetBytes(input), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    return new(target, body, new Dictionary<string, string>(StringComparer.Ordinal) { ["X-BG-Timestamp"] = timestamp, ["X-BG-Nonce"] = nonce, ["X-BG-Content-SHA256"] = digest, ["X-BG-Signature"] = signature, ["traceparent"] = $"00-{Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant()}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant()}-01" });
}

async Task<Result> SendSignedAsync(HttpClient client, string connector, string operation, byte[] body) => await SendAsync(client, Sign(connector, operation, body)).ConfigureAwait(false);
static async Task<Result> SendAsync(HttpClient client, SignedRequest signed)
{
    using HttpRequestMessage request = new(HttpMethod.Post, signed.Target) { Content = new ByteArrayContent(signed.Body) };
    request.Content.Headers.ContentType = new("application/json");
    foreach ((string name, string value) in signed.Headers) request.Headers.TryAddWithoutValidation(name, value);
    using HttpResponseMessage response = await client.SendAsync(request).ConfigureAwait(false);
    byte[] body = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
    string code = response.IsSuccessStatusCode ? "BGW-OK" : ReadCode(body);
    return new(response.StatusCode, code, body);
}

static byte[] InvokeBody(params (string Name, string Value)[] extras)
{
    JsonObject root = new()
    {
        ["protocolVersion"] = "1.0",
        ["payload"] = new JsonObject { ["contentType"] = "application/json", ["encoding"] = "base64", ["data"] = Convert.ToBase64String("{\"synthetic\":true}"u8) },
        ["correlationId"] = Guid.NewGuid().ToString("D")
    };
    foreach ((string name, string value) in extras) root[name] = value;
    return Encoding.UTF8.GetBytes(root.ToJsonString());
}

static bool ResponseIsSanitized(byte[] body)
{
    try
    {
        using JsonDocument envelope = JsonDocument.Parse(body);
        string encoded = envelope.RootElement.GetProperty("result").GetProperty("data").GetString() ?? string.Empty;
        string value = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
        return value.Contains("\"accepted\":true", StringComparison.Ordinal) && !value.Contains("api", StringComparison.OrdinalIgnoreCase) && !value.Contains("certificate", StringComparison.OrdinalIgnoreCase) && !value.Contains("secret", StringComparison.OrdinalIgnoreCase);
    }
    catch (Exception exception) when (exception is JsonException or FormatException or InvalidOperationException) { return false; }
}

static string ReadCode(byte[] body)
{
    try { using JsonDocument document = JsonDocument.Parse(body); return document.RootElement.GetProperty("code").GetString() ?? "BGW-UNKNOWN"; }
    catch (Exception exception) when (exception is JsonException or InvalidOperationException or KeyNotFoundException) { return "BGW-INVALID-ERROR"; }
}

static HttpClient CreateClient(Uri origin, X509Certificate2 certificate)
{
    HttpClientHandler handler = new() { AllowAutoRedirect = false, UseCookies = false, UseProxy = false };
    handler.ClientCertificates.Add(certificate);
    return new HttpClient(handler) { BaseAddress = origin, Timeout = TimeSpan.FromSeconds(15) };
}
static string Required(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : throw new InvalidOperationException(name + " is required.");
static string Base64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

sealed record Challenge(Guid ChallengeId, [property: System.Text.Json.Serialization.JsonPropertyName("challenge")] string ChallengeValue, DateTimeOffset ExpiresAt);
sealed record SignedRequest(string Target, byte[] Body, Dictionary<string, string> Headers);
sealed record Result(HttpStatusCode Status, string Code, byte[] Body);
sealed record Scenario(string Id, bool Passed, string Status, string Code);

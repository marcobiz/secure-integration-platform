using System.Globalization;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

string gateway = Required("DIRECT_GATEWAY_URL").TrimEnd('/');
Guid activationCodeId = Guid.Parse(Required("DIRECT_GATEWAY_ACTIVATION_CODE_ID"));
string activationCode = Required("DIRECT_GATEWAY_ACTIVATION_CODE");
string connectorId = Required("DIRECT_GATEWAY_CONNECTOR_ID");
string operationId = Required("DIRECT_GATEWAY_OPERATION_ID");
string clientVersion = Environment.GetEnvironmentVariable("DIRECT_GATEWAY_CLIENT_VERSION") ?? "1.0.0";

using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
CertificateRequest certificateRequest = new("CN=Secure Integration Direct Client Sample", key, HashAlgorithmName.SHA256);
certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
OidCollection usages = new();
usages.Add(new Oid("1.3.6.1.5.5.7.3.2"));
certificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
using X509Certificate2 certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(30));

using HttpClientHandler handler = new();
handler.ClientCertificates.Add(certificate);
using HttpClient client = new(handler) { BaseAddress = new Uri(gateway, UriKind.Absolute), Timeout = TimeSpan.FromSeconds(30) };

byte[] spki = key.ExportSubjectPublicKeyInfo();
ChallengeResponse challenge = await PostAsync<ChallengeRequest, ChallengeResponse>(client, "/v1/enrollments/challenges", new(activationCodeId, Convert.ToBase64String(spki)));
byte[] challengeBytes = Decode(challenge.Challenge);
byte[] activationProof = Encoding.UTF8.GetBytes(FormattableString.Invariant($"BGW-ENROLL1\n{challenge.ChallengeId:D}\n{challenge.Challenge}\n{activationCodeId:D}"));
byte[] activationSignature = key.SignData(activationProof, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
_ = await PostAsync<ActivationRequest, EnrollmentResult>(client, "/v1/enrollments:activate", new(challenge.ChallengeId, activationCode, Convert.ToBase64String(certificate.RawData), Encode(activationSignature), clientVersion));
CryptographicOperations.ZeroMemory(challengeBytes);

string target = $"/v1/connectors/{Uri.EscapeDataString(connectorId)}/operations/{Uri.EscapeDataString(operationId)}:invoke";
Guid correlationId = Guid.NewGuid();
byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new { message = "direct-gateway-sample" });
byte[] requestBody = JsonSerializer.SerializeToUtf8Bytes(new
{
    protocolVersion = "1.0",
    payload = new { contentType = "application/json", encoding = "base64", data = Convert.ToBase64String(payload) },
    correlationId
});
string timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
string nonce = Encode(RandomNumberGenerator.GetBytes(16));
string contentHash = Encode(SHA256.HashData(requestBody));
string signingInput = string.Join('\n', "BGW1", "POST", target, timestamp, nonce, contentHash);
string signature = Encode(key.SignData(Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
using HttpRequestMessage invoke = new(HttpMethod.Post, target) { Content = new ByteArrayContent(requestBody) };
invoke.Content.Headers.ContentType = new("application/json");
invoke.Headers.TryAddWithoutValidation("X-BG-Timestamp", timestamp);
invoke.Headers.TryAddWithoutValidation("X-BG-Nonce", nonce);
invoke.Headers.TryAddWithoutValidation("X-BG-Content-SHA256", contentHash);
invoke.Headers.TryAddWithoutValidation("X-BG-Signature", signature);
invoke.Headers.TryAddWithoutValidation("traceparent", $"00-{Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant()}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant()}-01");
using HttpResponseMessage response = await client.SendAsync(invoke);
response.EnsureSuccessStatusCode();
InvokeResponse result = await response.Content.ReadFromJsonAsync<InvokeResponse>() ?? throw new InvalidOperationException("Gateway returned no result.");
if (!string.Equals(result.Result.Encoding, "base64", StringComparison.Ordinal)) throw new InvalidOperationException("Gateway returned an unsupported result encoding.");
Console.WriteLine(Encoding.UTF8.GetString(Convert.FromBase64String(result.Result.Data)));

static async Task<TResponse> PostAsync<TRequest, TResponse>(HttpClient client, string target, TRequest request)
{
    using HttpResponseMessage response = await client.PostAsJsonAsync(target, request);
    response.EnsureSuccessStatusCode();
    return await response.Content.ReadFromJsonAsync<TResponse>() ?? throw new InvalidOperationException("Gateway returned no response document.");
}

static string Required(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : throw new InvalidOperationException($"Required environment variable {name} is missing.");
static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/').PadRight((value.Length + 3) / 4 * 4, '='));

internal sealed record ChallengeRequest(Guid ActivationCodeId, string PublicKeySpki);
internal sealed record ChallengeResponse(Guid ChallengeId, string Challenge, DateTimeOffset ExpiresAt);
internal sealed record ActivationRequest(Guid ChallengeId, string ActivationCode, string ClientCertificate, string ProofSignature, string ClientVersion);
internal sealed record EnrollmentResult(Guid InstallationId, Guid TenantId, Guid ApplicationId, DateTimeOffset CredentialExpiresAt, DateTimeOffset RenewalStartsAt);
internal sealed record GatewayPayload(string ContentType, string Encoding, string Data);
internal sealed record InvokeResponse(Guid CorrelationId, string ConnectorVersion, GatewayPayload Result);

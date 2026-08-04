using System.Text;
using System.Text.Json;
using SecureIntegration.Broker.Sdk;
using SecureIntegration.Contracts;

if (args.Length != 2 || args[0] != "--output") throw new InvalidOperationException("Usage: LegacySimulator --output <redacted-report.json>");
string pipeName = Environment.GetEnvironmentVariable("M3_BROKER_PIPE_NAME") ?? "SecureIntegration.Broker.M3";
string applicationId = Environment.GetEnvironmentVariable("M3_APPLICATION_REGISTRATION_ID") ?? "m3-legacy-simulator";
BrokerClient client = new(new BrokerClientOptions { PipeName = pipeName, ApplicationRegistrationId = applicationId, OperationTimeout = TimeSpan.FromSeconds(45) });
List<object> scenarios = [];
bool passed = true;
try
{
    InvokeGatewayResult result = await client.InvokeGatewayAsync(new InvokeGatewayRequest
    {
        ConnectorId = "m3-vendor",
        OperationId = "submit",
        ContentType = "application/json",
        PayloadBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { synthetic = true, canary = Environment.GetEnvironmentVariable("M3_PAYLOAD_CANARY") ?? "M3-PAYLOAD-CANARY-MISSING" })))
    }).ConfigureAwait(false);
    string response = Encoding.UTF8.GetString(Convert.FromBase64String(result.PayloadBase64));
    using JsonDocument responseJson = JsonDocument.Parse(response);
    bool sanitized = responseJson.RootElement.GetProperty("accepted").GetBoolean() && !response.Contains("api", StringComparison.OrdinalIgnoreCase) && !response.Contains("certificate", StringComparison.OrdinalIgnoreCase);
    scenarios.Add(new { id = "M3-P02-P07", status = sanitized ? "PASS" : "FAIL", connectorVersion = result.ConnectorVersion });
    passed &= sanitized;

    try
    {
        _ = await client.InvokeGatewayAsync(new InvokeGatewayRequest { ConnectorId = "m3-vendor", OperationId = "not-granted", PayloadBase64 = "e30=" }).ConfigureAwait(false);
        scenarios.Add(new { id = "M3-N06", status = "FAIL", code = "unexpected-success" });
        passed = false;
    }
    catch (BrokerClientException exception)
    {
        bool denied = exception.Code == "operation_not_granted";
        scenarios.Add(new { id = "M3-N06", status = denied ? "PASS" : "FAIL", code = exception.Code });
        passed &= denied;
    }
}
catch (Exception exception)
{
    scenarios.Add(new { id = "M3-P02-P07", status = "FAIL", code = exception is BrokerClientException broker ? broker.Code : "simulator-failed" });
    passed = false;
}

Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(args[1]))!);
await File.WriteAllTextAsync(args[1], JsonSerializer.Serialize(new { schemaVersion = 1, passed, scenarios }, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true })).ConfigureAwait(false);
return passed ? 0 : 1;

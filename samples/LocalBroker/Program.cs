using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using System.Net;
using SecureIntegration.Broker.Sdk;
using SecureIntegration.Contracts;
using SecureIntegration.Samples.LocalBroker;

// Credential values are runtime input only. Neither plaintext, ciphertext nor keys are printed.
if (args.Length != 5 || args[0] is not ("status" or "protect" or "verify" or "denied" or "invoke" or "set-credential" or "use-credential"))
{
    Console.Error.WriteLine("Usage: LocalBroker <status|protect|verify|denied|invoke|set-credential|use-credential> <service> <pipe> <application> <envelope-file-or-dash>");
    return 2;
}
try
{
    Stopwatch elapsed = Stopwatch.StartNew();
    BrokerClient client = new(new BrokerClientOptions { ServiceName = args[1], PipeName = args[2], ApplicationRegistrationId = args[3] });
    if (args[0] is "set-credential" or "use-credential")
    {
        if (args[0] == "set-credential")
        {
            using TextReader? redirectedInput = Console.IsInputRedirected
                ? new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: false)
                : null;
            byte[] input = CredentialExample.ReadInput(redirectedInput);
            try { await CredentialExample.ConfigureAsync(client, args[4], input, CancellationToken.None); }
            finally { CryptographicOperations.ZeroMemory(input); }
            Console.WriteLine("CREDENTIAL_SAVED");
        }
        else
        {
            byte[] plaintext = await CredentialExample.ReadAsync(client, args[4], CancellationToken.None);
            try
            {
                // Integration seam: replace the old password constant/configuration read here.
                // Give these options to YOUR existing client; this sample sends no HTTP request.
                using HttpClientHandler applicationClientOptions = new()
                {
                    Credentials = new NetworkCredential(Environment.UserName, new UTF8Encoding(false, true).GetString(plaintext))
                };
                Console.WriteLine("CREDENTIAL_LOADED_FOR_APPLICATION (no external authentication performed)");
            }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
        }
        return 0;
    }
    using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(30));
    if (args[0] == "denied")
    {
        try { _ = await client.GetStatusAsync(deadline.Token); }
        catch (IOException) { Console.WriteLine("UNAUTHORIZED_CLIENT=DENIED"); return 0; }
        throw new InvalidOperationException("Unauthorized application was accepted.");
    }
    BrokerStatus status = await client.GetStatusAsync(deadline.Token);
    if (args[0] == "invoke")
    {
        if (!status.GatewayConfigured) throw new InvalidOperationException("Gateway is not configured.");
        InvokeGatewayResult result = await client.InvokeGatewayAsync(new InvokeGatewayRequest
        {
            ConnectorId = "sample-secure-service", OperationId = "submit", ContentType = "application/json",
            PayloadBase64 = Convert.ToBase64String("{\"synthetic\":true,\"message\":\"local-broker-sample\"}"u8)
        }, deadline.Token);
        using JsonDocument response = JsonDocument.Parse(Convert.FromBase64String(result.PayloadBase64));
        if (!response.RootElement.GetProperty("accepted").GetBoolean()) throw new InvalidOperationException("Synthetic service did not accept.");
    }
    if (args[0] == "protect")
    {
        byte[] synthetic = "local-broker-synthetic-sample-v1"u8.ToArray();
        try
        {
            ProtectedDataResult result = await client.ProtectDataAsync(new ProtectDataRequest
            {
                Purpose = "sample", ContentType = "text/plain", PlaintextBase64 = Convert.ToBase64String(synthetic)
            }, deadline.Token);
            await using FileStream file = new(args[4], FileMode.CreateNew, FileAccess.Write, FileShare.None);
            await file.WriteAsync(Convert.FromBase64String(result.EnvelopeBase64), deadline.Token);
        }
        finally { CryptographicOperations.ZeroMemory(synthetic); }
    }
    if (args[0] == "verify")
    {
        byte[] envelope = await File.ReadAllBytesAsync(args[4], deadline.Token);
        UnprotectedDataResult result = await client.UnprotectDataAsync(new UnprotectDataRequest
        {
            Purpose = "sample", ContentType = "text/plain", EnvelopeBase64 = Convert.ToBase64String(envelope)
        }, deadline.Token);
        byte[] recovered = Convert.FromBase64String(result.PlaintextBase64);
        try { if (!recovered.AsSpan().SequenceEqual("local-broker-synthetic-sample-v1"u8)) throw new InvalidOperationException("Roundtrip failed."); }
        finally { CryptographicOperations.ZeroMemory(recovered); }
        await ExpectDenied("other-purpose", "text/plain", envelope);
        await ExpectDenied("sample", "application/json", envelope);
        envelope[^1] ^= 1;
        await ExpectDenied("sample", "text/plain", envelope);

        async Task ExpectDenied(string purpose, string contentType, byte[] value)
        {
            try
            {
                _ = await client.UnprotectDataAsync(new UnprotectDataRequest { Purpose = purpose, ContentType = contentType, EnvelopeBase64 = Convert.ToBase64String(value) }, deadline.Token);
            }
            catch (BrokerClientException failure) when (failure.Code == (purpose == "sample" && contentType == "text/plain" ? "authentication_failed" : "data_context_not_granted")) { return; }
            throw new InvalidOperationException("Invalid context or tampering was accepted.");
        }
    }
    Console.WriteLine($"{args[0].ToUpperInvariant()}=PASS GATEWAY={(status.GatewayConfigured ? "ENABLED" : "DISABLED")} ELAPSED_MS={elapsed.ElapsedMilliseconds}");
    return 0;
}
catch (BrokerClientException exception) { Console.Error.WriteLine($"{exception.Code} RETRYABLE={exception.Retryable}"); return 1; }
catch (InvalidOperationException exception) when (exception.Message is "CREDENTIAL_INPUT_INVALID" or "CREDENTIAL_PATH_DENIED" or
    "CREDENTIAL_OWNER_UNAVAILABLE" or "CREDENTIAL_OWNERSHIP_DENIED" or "CREDENTIAL_PARENT_REQUIRED" or "CREDENTIAL_ENVELOPE_INVALID")
{
    Console.Error.WriteLine(exception.Message);
    return 1;
}
catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or OperationCanceledException or InvalidOperationException or FormatException or JsonException or KeyNotFoundException or ArgumentException or System.Security.SecurityException)
{
    Console.Error.WriteLine("LOCAL_BROKER_SAMPLE_FAILED");
    return 1;
}

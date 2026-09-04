using System.Diagnostics;
using System.Security.Cryptography;
using SecureIntegration.Broker.Sdk;
using SecureIntegration.Contracts;

// Only synthetic data. Neither plaintext, ciphertext nor keys are printed.
if (args.Length != 5 || args[0] is not ("status" or "protect" or "verify" or "denied"))
{
    Console.Error.WriteLine("Usage: LocalBroker <status|protect|verify|denied> <service> <pipe> <application> <envelope-file>");
    return 2;
}
try
{
    Stopwatch elapsed = Stopwatch.StartNew();
    BrokerClient client = new(new BrokerClientOptions { ServiceName = args[1], PipeName = args[2], ApplicationRegistrationId = args[3] });
    using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(30));
    if (args[0] == "denied")
    {
        try { _ = await client.GetStatusAsync(deadline.Token); }
        catch (IOException) { Console.WriteLine("UNAUTHORIZED_CLIENT=DENIED"); return 0; }
        throw new InvalidOperationException("Unauthorized application was accepted.");
    }
    BrokerStatus status = await client.GetStatusAsync(deadline.Token);
    if (status.GatewayConfigured) throw new InvalidOperationException("Standalone requires Gateway disabled.");
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
    Console.WriteLine($"{args[0].ToUpperInvariant()}=PASS GATEWAY=DISABLED ELAPSED_MS={elapsed.ElapsedMilliseconds}");
    return 0;
}
catch (BrokerClientException exception) { Console.Error.WriteLine(exception.Code); return 1; }
catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or OperationCanceledException or InvalidOperationException or FormatException)
{
    Console.Error.WriteLine("LOCAL_BROKER_SAMPLE_FAILED");
    return 1;
}

# Direct Gateway client sample

This minimal .NET client proves that an enrolled `Direct` Installation can call the
Gateway without installing or simulating the Local Broker. It creates an in-memory
ECDSA P-256 ClientAuth identity, completes the normal one-time enrollment and sends a
signed BGW1 request over mTLS. TLS certificate validation remains enabled.

Provision a Direct Installation and operation grant through the Admin API/UI, trust the
Gateway's development CA on the client host, then set these process-local variables:

```powershell
$env:DIRECT_GATEWAY_URL = 'https://gateway.example.test:8443'
$env:DIRECT_GATEWAY_ACTIVATION_CODE_ID = '<one-time activation id>'
$env:DIRECT_GATEWAY_ACTIVATION_CODE = '<one-time activation code>'
$env:DIRECT_GATEWAY_CONNECTOR_ID = 'synthetic'
$env:DIRECT_GATEWAY_OPERATION_ID = 'echo'
dotnet run --project samples/DirectGatewayClient/DirectGatewayClient.csproj
```

Do not put activation material in a file, command history, source control or logs. The
sample contains no vendor credential, destination or provider locator and prints only the
sanitized application response returned by the Gateway. Its client private key is scoped
to the process; a production Direct client must use an appropriate non-exportable or
otherwise protected client-side key store.


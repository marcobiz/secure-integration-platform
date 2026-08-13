# Direct Gateway client sample

This minimal .NET client proves that an enrolled `Direct` Installation can call the
Gateway without installing or simulating the Local Broker. It creates an in-memory
ECDSA P-256 ClientAuth identity, completes the normal one-time enrollment and sends a
signed BGW1 request over mTLS. TLS certificate validation remains enabled.

The supported alpha quickstart provisions a one-time synthetic Direct Installation and
operation grant, passes the activation only through process-local variables, and supplies
the per-run CA without changing the host trust store. To run the sample manually, provision
a Direct Installation and operation grant through the Admin API/UI, then set:

```powershell
$env:DIRECT_GATEWAY_URL = 'https://gateway.example.test:8443'
$env:DIRECT_GATEWAY_ACTIVATION_CODE_ID = '<one-time activation id>'
$env:DIRECT_GATEWAY_ACTIVATION_CODE = '<one-time activation code>'
$env:DIRECT_GATEWAY_CA_FILE = '<path to the trusted synthetic CA PEM>'
$env:DIRECT_GATEWAY_CONNECTOR_ID = 'sample-secure-service'
$env:DIRECT_GATEWAY_OPERATION_ID = 'submit'
dotnet run --project samples/DirectGatewayClient/DirectGatewayClient.csproj
```

Do not put activation material in a file, command history, source control or logs. The
sample contains no vendor credential, destination or provider locator and prints only the
sanitized application response returned by the Gateway. Its client private key is scoped
to the process; a production Direct client must use an appropriate non-exportable or
otherwise protected client-side key store.

For the complete no-cloud path, use
[`Invoke-AlphaGoldenPath.ps1`](../../tools/alpha/Invoke-AlphaGoldenPath.ps1) as described in
the [alpha golden-path runbook](../../docs/operations/ALPHA-GOLDEN-PATH.md). It removes the
per-run activation, certificates, containers, network and volume even when the run fails.

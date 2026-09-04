# First Secure Layer vertical slice — report

## Scope

The test `E2E_CON_SecureLayer_success_boundaries_failures_timeout_and_replay` executes this flow:

```text
legacy simulator (.NET SDK)
  -> Named Pipe Local Broker
  -> HTTPS/mTLS Gateway harness
  -> synthetic in-memory Vendor Secret provider
  -> HTTPS/mTLS external REST mock
```

The Gateway and synthetic provider exist exclusively in the E2E suite. They are not an early M2 implementation: there is no PostgreSQL, Tenant/Installation registry, enrollment, revocation, Azure Key Vault, Admin API or central deployment.

## Automated evidence

- success with a pre-built JSON body and ConnectorVersion `1.0.0`;
- Broker client certificate verified by the Gateway and Gateway certificate verified by the external mock;
- vendor API key applied only by the Gateway harness;
- no API key in SDK input, Broker-Gateway payload, result or platform audit;
- ungranted Connector/operation denied before external network access;
- no URL or secret reference field in `InvokeGatewayRequest` input;
- untrusted server certificate rejected;
- propagated deadline and redacted `deadline_exceeded` response;
- nonce reuse on the same connection rejected by closing the pipe;
- services, certificates and directories are synthetic and created/destroyed by the test.

## Reproduction

```powershell
.\.dotnet\dotnet.exe test tests\e2e\VerticalSlice.Tests\VerticalSlice.Tests.csproj --configuration Release
```

The test requires Windows and uses no real external credentials or services.

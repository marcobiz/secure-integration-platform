# Primo vertical slice Secure Layer — rapporto

## Perimetro

Il test `E2E_CON_SecureLayer_success_boundaries_failures_timeout_and_replay` esegue il flusso:

```text
legacy simulator (.NET SDK)
  -> Named Pipe Local Broker
  -> HTTPS/mTLS Gateway harness
  -> synthetic in-memory Vendor Secret provider
  -> HTTPS/mTLS external REST mock
```

Il Gateway e il provider sintetico vivono esclusivamente nella suite E2E. Non costituiscono l'implementazione anticipata di M2: non sono presenti PostgreSQL, registry Tenant/Installation, enrollment, revoca, Azure Key Vault, Admin API o deployment centrale.

## Evidenze automatiche

- successo con body JSON pre-costruito e ConnectorVersion `1.0.0`;
- certificato client Broker verificato dal Gateway e certificato Gateway verificato dal mock esterno;
- API key vendor applicata soltanto dal Gateway harness;
- assenza della API key in input SDK, payload Broker-Gateway, risultato e audit della piattaforma;
- Connector/operation non concesso negato prima della rete esterna;
- nessun campo URL o secret reference nell'input `InvokeGatewayRequest`;
- certificato server non trusted rifiutato;
- deadline propagata e risposta redatta `deadline_exceeded`;
- riuso del nonce sulla stessa connessione rifiutato chiudendo la pipe;
- servizi, certificati e directory sono sintetici e creati/distrutti dal test.

## Riproduzione

```powershell
.\.dotnet\dotnet.exe test tests\e2e\VerticalSlice.Tests\VerticalSlice.Tests.csproj --configuration Release
```

Il test richiede Windows e non usa credenziali o servizi esterni reali.

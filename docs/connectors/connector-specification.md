# Connector specification

## Scopo

Un Connector descrive un insieme limitato di operazioni verso un servizio esterno. Non descrive workflow generici e non accetta codice o URL dal client.

La fonte machine-readable è [connector-definition.schema.json](connector-definition.schema.json).

## Source of truth e lifecycle

- La configurazione viene convertita in JSON e validata.
- RFC 8785 produce la rappresentazione canonica e SHA-256 il checksum.
- `connector_version.configuration_json` è source of truth.
- `connector_operation` è una proiezione transazionale.
- Lifecycle: Draft → Validated → Approved → Published → Superseded → Retired.
- Il runtime usa soltanto versioni Published referenziate dal deployment attivo.
- Published è immutabile; il rollback crea una nuova deployment revision.

## Validazione multilivello

1. JSON parse con limiti.
2. JSON Schema 2020-12.
3. Semantic validation: ID univoci, endpointRef esistenti, path placeholder definiti.
4. Security validation: HTTPS, endpoint policy, auth/location e secret class coerenti.
5. Binding validation nell'Environment target.
6. Runtime/plugin compatibility.
7. Test connection sintetico opzionale, senza valori o payload reali.

## Regole non esprimibili interamente in JSON Schema

- `operationId` deve essere univoco nel Connector.
- Ogni `endpointRef` e `tokenEndpointRef` deve esistere.
- Ogni placeholder del path deve avere una policy e viceversa.
- Retry >0 è ammesso solo per method idempotente o idempotency `required` supportata dal servizio.
- Vendor Secret richiede execution `gateway`.
- Smart card, VPN e certificato non esportabile richiedono `broker`.
- `approvedPrivate` richiede Environment policy approvata dal SecurityAdministrator.
- API key in query è warning high-risk e richiede approvazione esplicita; header è default.
- `none` è ammesso solo quando endpoint e servizio sono pubblici per design e il grant resta necessario.
- JWT issuer/audience/lifetime e allowed claims non sono client-controlled.
- Header `Authorization`, `Cookie`, `Host`, forwarding e hop-by-hop non possono essere client allowlistati.

## Secure Layer

Il legacy costruisce il body. Il runtime può:

- validare media type, schema, size e XML safety;
- applicare Basic/API key/mTLS/OAuth/HMAC/JWT;
- aggiungere header definiti;
- inviare a method/path fissati;
- validare e restituire la response.

Esempio: [secure-layer.example.json](examples/secure-layer.example.json).

## Managed Connector

Il legacy invia un payload di dominio/protocollare. `managedHandler` seleziona un built-in handler o un plugin già distribuito e firmato. Il Connector costruisce request, gestisce autenticazione e normalizza gli errori.

Esempio: [managed-connector.example.json](examples/managed-connector.example.json).

## Secret binding

La ConnectorDefinition usa logical name. La tabella `secret_binding` associa logical name a provider/location/scope.

Esempio logico:

```text
vendor-api-key
  class: vendor
  location: vault
  environment: prod
  allowed connector: healthcare.synthetic-secure
  allowed operation: submit-document
  provider ref: server-side only
```

Il runtime verifica binding e operation prima di chiedere il valore al provider. Il Broker non vede binding di Vendor Secret.

## Endpoint policy

- `baseUri` definita dall'amministratore e non sovrascrivibile.
- Porta 443 default.
- Nessun userinfo, fragment o IP literal.
- DNS/IP ricontrollati al connect.
- Path parameter percent-encoded come singolo segmento salvo template esplicito.
- Redirect false.
- Client header allowlist; header sensibili sempre runtime-owned.

## Plugin contract

```csharp
public interface IManagedConnectorPlugin
{
    string PluginId { get; }
    Version ContractVersion { get; }
    ValueTask<ValidationResult> ValidateConfigurationAsync(
        JsonElement configuration,
        CancellationToken cancellationToken);
    ValueTask<ValidationResult> ValidateRequestAsync(
        ConnectorRequest request,
        CancellationToken cancellationToken);
    ValueTask<ConnectorResult> ExecuteAsync(
        ConnectorExecutionContext context,
        CancellationToken cancellationToken);
    RedactedAuditRecord RedactForAudit(ConnectorExecutionSummary summary);
    ValueTask<HealthResult> HealthCheckAsync(
        ConnectorHealthContext context,
        CancellationToken cancellationToken);
}
```

Il context offre `IRestrictedOutboundClient`, `ISecretOperationService`, clock, correlation e redacted logger. Non espone raw connection string o `ISecretProvider` generico. Questo riduce misuse accidentale ma non sandboxa codice full-trust.

## Packaging Connector Pack

```text
connector-pack/
  pack-manifest.json
  definitions/*.json
  schemas/*.json
  plugins/*        # opzionale, firmato
  tests/*
  docs/*
  checksums.sha256
  signature.p7s
```

Manifest: pack ID/version, runtime compatibility, file hash, publisher, Connector inclusi e provenance. La pipeline valida schema, firma, test e assenza di segreti prima del deployment.


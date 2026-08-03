# Gateway API specification

La specifica machine-readable è [gateway-openapi.yaml](gateway-openapi.yaml). Questo documento contiene le regole che non devono essere delegate alla sola validazione sintattica OpenAPI.

## Autenticazione

- Runtime: certificato ClientAuth per Installation, validato contro `installation_credential`, più firma ECDSA dell'envelope.
- Enrollment activation: TLS server authentication, activation code e proof-of-possession.
- Enrollment renewal: identità Installation corrente e proof della nuova chiave.
- Admin: Entra OIDC e app roles.

In Azure App Service il certificato inoltrato viene accettato solo dopo certificate forwarding middleware e validazione applicativa. Un header `X-ARR-ClientCert` ricevuto fuori dal trusted hosting path non costituisce identità.

## Firma runtime

Header obbligatori:

- `X-BG-Timestamp`: UTC RFC 3339, tolleranza ±5 minuti.
- `X-BG-Nonce`: 128 bit casuali Base64url, monouso per 10 minuti.
- `X-BG-Content-SHA256`: digest Base64url del body esatto.
- `X-BG-Signature`: ECDSA P-256/SHA-256 sul canonical signing input.
- `traceparent`: W3C Trace Context.

Signing input, con LF e senza spazi aggiuntivi:

```text
BGW1
<HTTP_METHOD>
<NORMALIZED_PATH_AND_QUERY>
<X-BG-Timestamp>
<X-BG-Nonce>
<X-BG-Content-SHA256>
```

Query parameter duplicati, path non normalizzabili o digest mismatch sono rifiutati. La normalizzazione non decodifica e ricodifica segmenti in modo ambiguo.

## Invoke

`POST /v1/connectors/{connectorId}/operations/{operationId}:invoke`

Il client seleziona soltanto identificativi già autorizzati. Non può inviare URL, method, vault reference, algoritmo o execution strategy.

Payload JSON standard ≤16 MiB. Per binari si usa `multipart/related`: prima parte metadata JSON, seconda parte binaria; limite complessivo 64 MiB e streaming senza buffering completo.

## Idempotency

- Key ASCII 1–128 caratteri.
- Scope: Installation + Connector + operation + key.
- Conservazione: hash della key, request hash, stato, correlation ID e scadenza; mai response sensibile.
- Stessa key con request hash diverso: `409 BGW-IDEMPOTENCY-CONFLICT`.
- Duplicato in corso: `202` con correlation ID originale.
- Duplicato completato: non viene reinvocato; ritorna status metadata. Il risultato è recuperabile solo se il Connector definisce un'operation di status.

## Error model

RFC 9457 Problem Details con:

- `code`: codice stabile e documentato;
- `correlationId`;
- `retryable`;
- `retryAfterMs` opzionale;
- `details` con soli riferimenti di campo e reason code.

Categorie:

| Prefix | Categoria |
|---|---|
| `BGW-PROTOCOL` | versione/framing/content type |
| `BGW-AUTHN` | certificato, firma, nonce o enrollment |
| `BGW-AUTHZ` | grant, Tenant o Application |
| `BGW-VALIDATION` | payload/configurazione |
| `BGW-CONNECTOR` | stato/versione/plugin |
| `BGW-EGRESS` | endpoint/SSRF/TLS/limits |
| `BGW-VAULT` | provider o secret unavailable |
| `BGW-EXTERNAL` | risposta servizio esterno |
| `BGW-TIMEOUT` | timeout/cancellation |
| `BGW-IDEMPOTENCY` | conflict/in-progress/completed |
| `BGW-INSTALLATION` | revoked/expired/incompatible |

Stack trace, endpoint interni, vaultRef, payload e valori sensibili non vengono restituiti.

## Versioning

- Major version nel path (`/v1`) e nei content type.
- Evoluzioni additive entro la major.
- Campi sconosciuti rifiutati, salvo `extensions` namespaced.
- Deprecation annunciata tramite documentazione e header `Sunset`/`Deprecation` quando applicabile.
- Il Gateway pubblica min/max Broker protocol in `/v1/broker-policy`.


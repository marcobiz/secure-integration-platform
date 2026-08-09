# Connector Definition JSON v1

La fonte machine-readable è [connector-definition.schema.json](connector-definition.schema.json), JSON Schema Draft 2020-12. Il sample eseguibile è [sample-secure-service.connector.json](examples/sample-secure-service.connector.json).

## Confine del formato

Una definizione dichiara:

- `schemaVersion`, identità e versione semantica;
- nomi logici di endpoint e segreti;
- operation REST con method/path fissi;
- limiti request/response e timeout;
- autenticazione REST built-in `none`, `basic`, `apiKey`, `mtls` o `apiKeyAndMtls`, profili OAuth capability-bound e modalita opt-in `opaqueSessionHttp`/`soapBasicOpaqueSession` applicate dal Gateway;
- redirect deny, client header allowlist, idempotenza e retry limitato.

Non contiene URI, secret value, provider reference, tenant, codice, script, espressioni o workflow. Il client runtime seleziona soltanto `connectorId` e `operationId`; endpoint, credenziali e versione Published sono risolti server-side.

## Lifecycle

| Stato | Uso amministrativo | Invocabile |
|---|---|---|
| Draft | import iniziale | No |
| Validated | schema e semantica verificati | No |
| Published | versione attiva e immutabile | Sì |
| Superseded | versione già pubblicata sostituita | No; può essere rollback target |
| Retired | revocata definitivamente | No |

Importare nuovamente la stessa versione è rifiutato. Validazione, publish, rollback e retire richiedono la `rowVersion` osservata; publish richiede anche `publicationRevision`. Il rollback riattiva una versione Superseded già pubblicata e non crea una copia.

## Canonicalizzazione e checksum

Gli object member sono ordinati ordinalmente, il whitespace insignificante è rimosso e gli interi sono normalizzati. JSON v1 non accetta numeri non interi. SHA-256 uppercase del JSON UTF-8 canonico accompagna import/export e rileva trasferimenti o storage corrotti.

## Binding server-side

Per ogni Environment, l'amministratore associa i logical name a URI HTTPS endpoint e riferimenti opachi del Secret Provider. I valori non sono restituiti dall'export e non compaiono nell'audit. Binding assente, Connector non Published, operation assente o store non disponibile falliscono chiusi.

## Cache runtime

Lo snapshot Published ha TTL configurabile. Prima di ogni invocazione il Gateway legge uno stamp ridotto (`version`, checksum, publication revision e binding revision). Se lo stamp cambia, la cache viene invalidata e ricaricata; se il caricamento fallisce non viene usato lo snapshot precedente. Publish, rollback, retire e modifica binding invalidano inoltre la cache locale.

## Regole semantiche aggiuntive

- ogni logical binding e `operationId` è univoco;
- ogni riferimento usato dall'operation deve essere dichiarato;
- header sensibili o hop-by-hop non possono essere client-controlled;
- `opaqueSessionHttp` usa soltanto una placement custom tipizzata (`headerName`, `valueFormat`, eventuale `fixedScheme`) e non puo usare Authorization, SOAPAction, Content-Type, routing, proxy, forwarding, tracing o correlation header;
- `soapBasicOpaqueSession` richiede POST, binding logici username/password/session, placement opaque e `soapHttp` tipizzato (`version` 1.1/1.2 e action assoluta); Content-Type e SOAPAction sono derivati e non esiste un header bag;
- retry richiede operazione idempotente o idempotency key obbligatoria;
- redirect è sempre `deny` in v1;
- endpoint e path non sono sovrascrivibili dal payload;
- grant Installation/Connector/operation è deny-by-default.

## Fuori perimetro M4 e delle capability generiche

YAML, UI, plugin, scripting, workflow arbitrario, SAML, WS-Security, XML-DSig, provider cloud aggiuntivi e connector reali. Le capability OAuth/SOAP/session generiche non qualificano automaticamente alcun profilo esterno production. I vecchi esempi managed/secure-layer descrivono analisi pre-M4 e non sono Connector Definition v1 eseguibili.

# Connector Runtime authentication contract

## Freeze per M6

Questo documento congela il confine che i moduli di autenticazione Connector successivi
possono assumere. Distingue due direzioni indipendenti:

```mermaid
sequenceDiagram
  participant C as Broker or Direct Client
  participant I as Inbound authentication
  participant R as Connector Runtime
  participant A as Outbound auth module
  participant V as Vendor/Public Service
  C->>I: mTLS + signed BGW1 request
  I->>I: derive Tenant/Application/Installation
  I->>R: GatewayClientPrincipal + authorized operation
  R->>A: server-owned binding dependencies
  A->>V: vendor authentication over restricted egress
  V-->>R: bounded response
  R-->>C: sanitized application response
```

### Inbound: client verso Gateway

Responsabilita del Gateway Core:

- autenticare certificate/PoP/BGW1;
- derivare Tenant, Application, Installation, Environment e caller kind dal registry;
- verificare stato, revoca, replay e grant;
- produrre il `GatewayClientPrincipal` provider-neutral;
- impedire che il client selezioni endpoint o credential binding.

Il Connector Runtime riceve un caller gia autenticato. M6 non deve reinterpretare il
certificato inbound, fidarsi di Tenant/Application nel payload o creare un principal
alternativo.

### Outbound: Gateway verso servizio vendor/pubblico

Responsabilita di un auth module Connector:

- consumare esclusivamente `OperationBindingDependencies` pubblicate e approvate;
- richiedere capability provider strette (secret use, certificate use, signing o MAC)
  senza introdurre un `GetSecret` per client/Broker/UI;
- applicare credenziali solo alla richiesta outbound autorizzata;
- non restituire password, API key, token non necessari, private key, PFX o locator;
- rispettare restricted egress, timeout, redirect, header e redaction comuni.

Per OAuth Authorization Code il Connector fornisce soltanto un logical profile ID. Il
runtime crea una `OAuthAuthorizedInvocation` non costruibile dal Connector dopo grant e
autenticazione. `PublishedOAuthAuthorityResolver` combina quella capability, il relativo
`GatewayClientPrincipal` e lo snapshot Published corrente con le
`OperationBindingDependencies`, la binding revision e la provider resource esatta. Il
risultato e una `OAuthResolvedExecutionContext` immutabile, con costruttore non pubblico;
raw profile, endpoint, client ID, scope/audience e provider locator non fanno parte della
superficie Connector-facing.

La capability di secret use e scoped al solo provider reference risolto per quel binding.
Il client OAuth non riceve un `ISecretValueProvider` generico e non accetta reference dal
consumer.

Per l'estensione generica Phase 2, la stessa capability risolve Authorization Code oppure
Client Credentials dal `kind` Published. Authorization Code usa `NONE` solo per compatibilita
esplicitamente pubblicata; `S256_REQUIRED` genera e conserva il verifier nel tentativo one-time.
Client Credentials riusa lo stesso token-session store e la stessa reference opaca. Il Connector
continua a fornire solo il logical profile ID e non puo selezionare grant, modalita PKCE, token
endpoint, client identity, secret, scope, audience, resource o client-auth method.

## Contratto minimo stabile

Un writer M6 puo dipendere da:

- `GatewayClientPrincipal` gia autenticato;
- Connector e operation ID gia autorizzati;
- Environment e Tenant derivati server-side;
- ConnectorVersion Published e binding revision immutabili;
- `OperationBindingDependencies` con riferimenti logici;
- capability provider-neutral e trasporto ristretto;
- correlation ID e audit sink metadata-only.

Una token session outbound e legata a ConnectorVersion, operation, Environment, endpoint
e binding revision, scope/audience, provider resource revision e resource stamp. Il bearer
non puo essere attached a un `HttpRequestMessage` del consumer: il modulo costruisce la
request verso il protected-resource endpoint Published, inietta il bearer immediatamente
prima del dispatch e usa sempre `IRestrictedTransport`.

L'authorization endpoint e un confine differente: `BeginAuthorizationAsync` valida il
Published HTTPS endpoint e produce una navigation per external user agent, senza fetch
server-side. Token endpoint e protected-resource endpoint sono invece sempre dereferenziati
dal Gateway tramite restricted transport.

Non puo dipendere da:

- presenza del Local Broker;
- `InstallationKind` per cambiare business logic o auth outbound;
- URL, provider reference, secret/certificate binding forniti dal caller;
- accesso diretto a PostgreSQL, Vault o filesystem dal frontend/client;
- secret value nel principal, audit o risposta.

## Compatibilita

BGW1 e le route runtime restano il contratto inbound corrente per Broker e Direct. Nuovi
metodi inbound futuri devono terminare nello stesso `GatewayClientPrincipal`; nuovi auth
module outbound devono innestarsi dopo authorization e publication resolution. Qualsiasi
deviazione richiede ADR, threat-model update e test positivi/negativi.

## Implementazione Track A sintetica

`Gateway.ConnectorRuntime.Auth.Soap` implementa AP-01/AP-02/AP-07 senza modificare il
contratto inbound. Il runtime costruisce `ConnectorAuthExecutionContext`,
`SoapEndpointBinding` e `SoapSessionProfile` soltanto dopo grant, publication e binding
resolution. Il connector dichiara operazioni, QName, action, mapping di campi bounded,
estrazione/placement sessione, fault di expiry e policy di retry; non riceve un raw HTTP
client, un parser configurabile o un motore di scripting.

Le sole reference restituibili al runtime sono opache. Username, password, challenge
state upstream e session value restano nell'assembly e non sono parte di cache key,
audit, errori o risposta. La cache include Tenant/Installation/Application,
Connector/version, Environment, binding revision, endpoint revision, credential revision
e profile. Per key esistono al massimo una interaction e una session generation corrente;
la promotion dopo challenge è atomica, il digest precedente non è più risolvibile e il
numero globale di key è limitato a 256 con sweep lazy delle entry scadute.

`ISoapSessionResourceStampProvider` è obbligatorio: prima della risoluzione e subito prima
dell'uso il client confronta lo stamp server-side corrente con credential resource
revision/status `Active`, binding revision ed endpoint revision. Un disable o rotate
fallisce prima di secret provider, DNS o transport. La deadline effettiva resta collegata
fino al completamento del response body bounded e del parsing XML. Il subset Fault SOAP
1.1/1.2 ha struttura e cardinalità esatte; un Fault ambiguo produce
`SOAP-FAULT-STRUCTURE` e non può attivare la riacquisizione di sessione.

Il server Kestrel sotto `tools/m6/SyntheticSoapServer` e i test associati qualificano
esclusivamente il profilo sintetico. Non costituiscono caratterizzazione o conformità
SOGEI e non autorizzano un connector healthcare production.

## M6 Wave 2 certificate/signing implementation note

The certificate/signing primitive consumes the frozen outbound side only. Its public
methods accept an immutable server-derived execution context, a named profile and
logical binding IDs fixed by that profile. A protected resolver produces the exact
ConnectorVersion/operation/profile/Environment/endpoint/catalog-revision binding;
provider locators never appear in `SignJwtAsync` or
`PurposeBoundMutualTlsSender.SendAsync`. The signing call accepts only a logical policy ID
and allowlisted business claims; the mTLS call owns certificate resolution and one-shot
transport attachment and never returns an `X509Certificate2` handle.
The implementation does not inspect the inbound certificate, create another principal,
branch on `InstallationKind`, or fall back to the Broker when central custody is absent.

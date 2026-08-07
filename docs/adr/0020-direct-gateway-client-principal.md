# ADR-0020: Direct Gateway Access e principal runtime unificato

**Stato:** Accepted

## Contesto

Fino a M5 l'unico client runtime del Gateway era il Local Broker. Tuttavia enrollment,
mTLS, firma BGW1, replay protection, grants e risoluzione Tenant/Application erano gia
concetti di `Installation`, non proprieta del processo Broker. Un secondo runtime o un
secondo protocollo avrebbe duplicato controlli security-critical.

## Decisione

- `InstallationKind` distingue `Broker` e `Direct`; le righe M5 esistenti sono migrate
  additivamente a `Broker`.
- entrambi i tipi usano ClientAuth mTLS, chiave ECDSA P-256, PoP di enrollment, BGW1,
  timestamp, nonce, renewal, overlap e revoca esistenti;
- `BrokerVersion` resta compatibile e soggetta alla policy Application per le
  installazioni Broker; una Direct installation usa `ClientVersion` e non puo inviare
  `BrokerVersion`;
- l'autenticazione produce un solo `GatewayClientPrincipal`, derivato esclusivamente
  dal registry server-side;
- Connector Runtime, grants, binding, provider, cache, restricted egress e audit
  consumano quel principal e non creano pipeline specifiche per il caller;
- `/v1/broker-policy` resta intenzionalmente Broker-only; enrollment, renewal e invoke
  mantengono le route esistenti;
- le richieste runtime non contengono Tenant, Application, destinazione, provider o
  riferimenti a secret/certificati.

## Conseguenze

Un'applicazione moderna puo invocare il Gateway senza installare o simulare il Broker,
ma deve custodire la propria chiave client. Il furto della chiave di una Direct
installation resta un rischio del client endpoint e richiede revoca/rotazione. Non
cambia la trusted computing base del Gateway e non nasce un nuovo `GetSecret`.

## Alternative escluse

BGW2, `DirectConnectorRuntime`, bearer token statici, Tenant/Application forniti dal
client, Named Pipe o DPAPI nel percorso Direct e binding tardivi scelti dal caller.

# Sviluppare un Connector

**Pubblico:** sviluppatori di Connector e maintainer del runtime.
**Stato:** CURRENT.

Un Connector è una definition JSON dichiarativa e versionata, più un’eventuale
estensione compilata strettamente necessaria a un protocollo non esprimibile dal runtime
esistente. Non è un workflow engine e non contiene endpoint concreti, credenziali,
provider locator, tenant, script o codice dinamico.

## Percorso minimo

1. Leggere [anatomia minima](minimal-connector-anatomy.md).
2. Copiare il
   [sample REST](../connectors/examples/sample-secure-service.connector.json).
3. Validare contro lo
   [schema](../connectors/connector-definition.schema.json) e le regole della
   [specifica](../connectors/connector-specification.md).
4. Implementare il [golden path](golden-path.md) da stato pulito fino alla prima chiamata.
5. Aggiungere test positivi e negativi soltanto per i confini realmente introdotti.

## Regole di prodotto

- Il caller seleziona soltanto Connector e operation già autorizzati. Tenant,
  Installation, Environment, endpoint, provider e credenziali restano server-owned.
- Lifecycle: `Draft → Validated → Published → Superseded → Retired`; Published è
  immutabile e richiede four-eyes sul checksum/digest esatto.
- Grant deny-by-default e binding completi precedono ogni invocation.
- La procedura di prima adozione è funzionalità del Connector: deve esistere un unico
  `plan → apply → verify` idempotente o workflow Admin equivalente.
- Nessun adottante deve conoscere migrazioni, tabelle, test fixture, milestone o
  struttura interna della repository.
- Se lo stesso attrito di onboarding compare in un secondo Connector, risolverlo al più
  stretto confine condiviso; non duplicare runbook o bootstrap verticali.

Il riferimento SDK è [docs/connectors/connector-sdk.md](../connectors/connector-sdk.md).
Le regole di semplicità e compensazione sono in
[docs/internal/complexity-governance.md](../internal/complexity-governance.md).

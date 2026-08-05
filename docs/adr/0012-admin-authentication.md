# ADR-0012: Autenticazione Admin provider-neutral

**Stato:** Accepted (aggiornato da M4)

## Contesto

Il Gateway Core deve poter essere eseguito senza Azure. Il contratto Admin non può quindi dipendere da tipi, claim o SDK Entra, pur mantenendo un confine di autenticazione obbligatorio.

## Decisione

L'Admin API espone un confine di autorizzazione provider-neutral. In produzione il deployment deve collegarlo a un identity provider OIDC e a policy/ruoli amministrativi; il Core non sceglie il provider. Non esistono account o password amministrative locali.

M4 include una modalità `DevelopmentApiKey` esclusivamente per ambienti `Development`, `Testing`, `M3Testing` e `M4Testing`. La chiave arriva soltanto da una variabile d'ambiente, viene confrontata in tempo costante, non è accettata dalla CLI come argomento e la modalità è rifiutata in `Production`. La modalità predefinita è `Disabled` e fallisce chiusa.

La separazione editor/approver e le policy four-eyes restano un controllo di qualificazione del deployment di produzione, non un'autenticazione specifica del Core M4.

## Conseguenze

- Il quick start locale non richiede Azure né credenziali cloud.
- I Deployment Pack possono integrare Entra o un altro provider OIDC senza cambiare i contratti Connector.
- `DevelopmentApiKey` non è una modalità supportata per produzione.
- Audit, optimistic concurrency e Published immutabile restano obbligatori anche in sviluppo.

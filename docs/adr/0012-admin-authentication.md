# ADR-0012: Autenticazione Admin provider-neutral

**Stato:** Accepted (aggiornato da M5)

## Contesto

Il Gateway Core deve poter essere eseguito senza Azure. Il contratto Admin non può quindi dipendere da tipi, claim o SDK Entra, pur mantenendo un confine di autenticazione obbligatorio.

## Decisione

L'Admin API espone un confine di autorizzazione provider-neutral. In produzione il deployment deve collegarlo a un identity provider OIDC e a policy/ruoli amministrativi; il Core non sceglie il provider. Non esistono account o password amministrative locali.

M4 include una modalità `DevelopmentApiKey` esclusivamente per ambienti `Development`, `Testing`, `M3Testing` e `M4Testing`. La chiave arriva soltanto da una variabile d'ambiente, viene confrontata in tempo costante, non è accettata dalla CLI come argomento e la modalità è rifiutata in `Production`. La modalità predefinita è `Disabled` e fallisce chiusa.

M5 usa Authorization Code Flow server-side con PKCE, state e nonce. ID token e callback sono validati dal middleware OIDC; i token non sono salvati nel browser. Il browser riceve soltanto un cookie `__Host-` HttpOnly, Secure, SameSite=Lax con scadenza/sliding window, e tutte le mutazioni richiedono antiforgery associato alla sessione.

Il principal stabile è `(issuer, subject)`; email e display name non sono chiavi. Ruoli globali o tenant-scoped sono persistiti server-side. La policy four-eyes lega la decisione a version id e checksum e nega creator/requester/editor coincidenti. Production rifiuta configurazioni OIDC incomplete e DevelopmentAuth; quest'ultima usa soltanto identità sintetiche fisse, loopback/Compose e ambiente Development.

## Conseguenze

La four-eyes approval M5 e vincolata sia al checksum canonico della ConnectorVersion sia al digest delle revisioni endpoint/secret/certificate. Il publish PostgreSQL verifica e blocca entrambi nella stessa transazione; l'attore che ha creato una revisione binding non puo approvare quel bundle. `DevelopmentAuth` verifica il peer socket con `RemoteIpAddress` loopback e il Compose locale espone il Gateway soltanto su `127.0.0.1`; Host e header forwarded client-controlled non costituiscono autorita.

- Il quick start locale non richiede Azure né credenziali cloud.
- I Deployment Pack possono integrare Entra o un altro provider OIDC senza cambiare i contratti Connector.
- `DevelopmentApiKey` legacy e `DevelopmentAuth` non sono modalità supportate per produzione.
- Audit, optimistic concurrency e Published immutabile restano obbligatori anche in sviluppo.
- La UI same-origin non conserva access/refresh token in Web Storage e non abilita CORS permissivo.

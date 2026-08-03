# Executive architecture

## Problema

I prodotti on-premise e legacy analizzati implementano flussi di integrazione funzionanti, ma spesso distribuiscono Vendor Secret, riusano chiavi fra installazioni, espongono servizi locali senza autorizzazione e affidano Tenant/Operator a parametri controllati dal client. Una riscrittura completa avrebbe costo e rischio regressivo elevati.

## Soluzione

La Secure Integration Platform inserisce un confine di sicurezza nei punti in cui il legacy legge o usa un segreto:

```text
Legacy → SDK/COM/C ABI/CLI → Local Broker → Gateway → Vault/External Service
```

- Il **Local Broker** protegge segreti, chiavi, certificati e operazioni che devono restare locali.
- Il **Gateway** deriva l'identità dell'Installation, applica grants, usa Vendor Secret nel Vault e controlla l'egress.
- Il **Connector Framework** descrive soltanto operazioni limitate e sicure; non è un workflow engine.
- L'**Admin Plane** versiona, approva, pubblica e revoca configurazioni e Installation.

## Modalità operative

### Secure Layer

Il legacy mantiene UI, payload e flusso funzionale. Local Broker/Gateway eseguono solo cifratura, HMAC, firma, token exchange, mTLS e credential injection. È il percorso predefinito per la prima migrazione.

### Managed Connector

Il legacy invia un'operazione e un payload più astratto. Il Connector gestisce protocollo, autenticazione, serializzazione e normalizzazione. Si adotta quando l'integrazione è condivisa, frequentemente variabile o economicamente riutilizzabile.

## Garanzie

- Nessun Vendor Secret distribuito al legacy o al Local Broker.
- Identità e revoca distinte per Installation.
- Tenant derivato server-side.
- Segreti locali isolati sotto service identity Windows e DPAPI CurrentUser.
- Endpoint, metodi, header e secret binding risolti da configurazione pubblicata.
- Audit redatto e correlation ID end-to-end.
- Operazioni locali disponibili offline.
- Rollback Connector atomico.

## Limiti espliciti

- Un amministratore locale o SYSTEM può generalmente compromettere un Broker in esecuzione.
- Malware capace di iniettarsi in un processo autorizzato può abusarne delle capability.
- Un Gateway compromesso può usare le permission concesse alla propria Managed Identity.
- Plugin in-process firmati restano full-trust.
- SQL injection, backdoor, parsing insicuro, IAM server-side e dipendenze vulnerabili richiedono remediation separate.

## MVP

- Windows service, Named Pipe, autorizzazione Application, DPAPI/AES-GCM e SDK .NET.
- Installation Registry, enrollment, mTLS, revoca e binding Tenant.
- PostgreSQL, Azure Key Vault, egress ristretto e container Gateway.
- Connector Secure Layer, JSON Schema, lifecycle e rollback.
- Vertical slice sintetico legacy → Broker → Gateway → Vault → mock service.

## Release 1

- Admin UI Entra OIDC.
- C ABI, COM e CLI x86/x64.
- OAuth2, PKCE, JWT, HMAC, SOAP/XML e session handling.
- Esempio Secure Layer e Managed Connector sanitari sintetici.
- MSI, Bicep, SBOM, signing e operational pack.


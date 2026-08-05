# Requisiti, non-goals e criteri di accettazione

## Obiettivo di prodotto

Rimuovere segreti hardcoded e credenziali distribuite dai software legacy con il minor numero possibile di modifiche al codice esistente, preservando i flussi già funzionanti e impedendo che il Gateway diventi un proxy arbitrario.

## Terminologia normativa

- **Local Broker:** servizio Windows locale che protegge segreti/chiavi, espone IPC controllato e comunica con il Gateway.
- **Local Proxy:** sinonimo commerciale di Local Broker; non è un proxy HTTP trasparente o MITM.
- **Gateway:** servizio centrale che autentica, autorizza, usa credenziali centralizzate e invoca servizi esterni.
- **Vault:** conservazione di segreti, certificati e chiavi; provider iniziale Azure Key Vault.
- **Secure Layer:** il legacy mantiene logica e payload; la piattaforma esegue solo operazioni sensibili.
- **Managed Connector:** la piattaforma gestisce una parte sostanziale o completa dell'integrazione.
- **Connector Pack:** definizioni, plugin, test e documentazione riutilizzabili per un servizio o verticale.
- **Installation:** singola installazione autorizzata presso un cliente.
- **Application:** prodotto o componente autorizzato a usare il Local Broker.
- **Tenant:** organizzazione a cui appartiene l'Installation.
- **Operator:** utente finale che compie l'operazione.
- **Vendor/Tenant/Operator/Session Secret:** classi di segreto definite dal relativo proprietario e ciclo di vita.

## Requisiti funzionali

| ID | Requisito |
|---|---|
| FR-001 | Registrare Tenant, Application, Installation ed Environment. |
| FR-002 | Enrollment, rinnovo, revoca e reinstallazione con identità distinta per Installation. |
| FR-003 | Autorizzazione Local Broker per Application e operazione. |
| FR-004 | Put/Delete local secret senza API GetSecret predefinita. |
| FR-005 | Protect/Unprotect data con key versioning e AEAD. |
| FR-006 | HMAC, firma e uso certificato vincolati a Connector/operation. |
| FR-007 | Invocazione Gateway con Tenant derivato dall'identità autenticata. |
| FR-008 | Secure Layer con payload JSON, XML o binario pre-costruito. |
| FR-009 | Managed Connector con richiesta di dominio o protocollare. |
| FR-010 | Execution strategy `gateway`, `broker` e `hybrid`. |
| FR-011 | Secret binding logici con valori esclusivamente nel Vault/Broker. |
| FR-012 | Connector lifecycle Draft/Validated/Published/Superseded/Retired. |
| FR-013 | Pubblicazione, promozione e rollback atomico. |
| FR-014 | Admin UI/API OIDC e RBAC. |
| FR-015 | SDK .NET, COM, C ABI e CLI sottili. |
| FR-016 | Audit amministrativo e operativo redatto. |
| FR-017 | Health, metrics, tracing e diagnostics offline. |
| FR-018 | Funzionamento offline per operazioni esclusivamente locali. |

## Requisiti non funzionali

| ID | Requisito |
|---|---|
| NFR-001 | Nessun segreto in repository, database, log, errori o telemetria. |
| NFR-002 | Deny-by-default per IPC, grants, egress, binding e plugin. |
| NFR-003 | TLS moderno con hostname validation sempre attiva. |
| NFR-004 | Payload standard 16 MiB, streaming controllato 64 MiB. |
| NFR-005 | Timeout, retry idempotente e circuit breaker espliciti. |
| NFR-006 | Correlation ID e W3C trace context end-to-end. |
| NFR-007 | Configurazioni pubblicate immutabili e checksum canonico. |
| NFR-008 | Build riproducibile per quanto ragionevole, SBOM e artefatti firmabili. |
| NFR-009 | Compatibilità x86/x64 e .NET Framework 4.7.2+ per gli adapter iniziali. |
| NFR-010 | Payload applicativi non persistiti centralmente per default. |

## Non-goals

- Forward proxy generico, MITM, ESB, BPM o scripting engine.
- IAM, EDR, PKI o zero-trust platform general purpose.
- Protezione completa contro amministratore locale/SYSTEM.
- Esecuzione sicura di plugin non fidati nello stesso processo.
- Correzione automatica di SQLi, XXE, backdoor, IDOR o CVE.
- Multi-cloud attivo, AKS, Redis, service mesh o HSM obbligatorio nell'MVP.

## Criteri di accettazione globali

| ID | Criterio |
|---|---|
| AC-001 | Nessun Vendor Secret è presente nel client. |
| AC-002 | Il Local Broker usa una service identity Windows separata. |
| AC-003 | Un processo non autorizzato non usa il Local Broker. |
| AC-004 | Il gestionale non legge i blob DPAPI del servizio. |
| AC-005 | Le chiavi locali differiscono per Installation. |
| AC-006 | I segreti non compaiono nei log. |
| AC-007 | Il Gateway non restituisce segreti. |
| AC-008 | Il Local Broker non accede direttamente al Vault. |
| AC-009 | Il client non sceglie URL arbitrari. |
| AC-010 | Il client non sceglie secret reference arbitrarie. |
| AC-011 | Il Tenant deriva dall'Installation autenticata. |
| AC-012 | Un'Installation non impersona un altro Tenant. |
| AC-013 | Revoca Installation verificata end-to-end. |
| AC-014 | Connector versionati. |
| AC-015 | Rollback atomico verificato. |
| AC-016 | Configurazioni validate con schema e policy. |
| AC-017 | Runtime limitato a versioni Published. |
| AC-018 | Gateway distribuibile come container. |
| AC-019 | Local Broker installabile e aggiornabile via MSI. |
| AC-020 | Sorgenti e build instructions completi. |
| AC-021 | Test end-to-end ripetibili con mock. |
| AC-022 | SDK .NET e almeno un adapter legacy aggiuntivo. |
| AC-023 | Esempio Secure Layer. |
| AC-024 | Esempio Managed Connector. |
| AC-025 | Runbook operativo e diagnostica. |
| AC-026 | Threat model aggiornato. |
| AC-027 | SBOM per tutti gli artefatti. |
| AC-028 | Artefatti firmabili e signature verification testata. |
| AC-029 | Nel pilot, vecchie credenziali rimosse o revocate. |
| AC-030 | Nel pilot, vecchio bypass ed egress diretto disabilitati. |

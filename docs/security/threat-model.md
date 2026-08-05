# Threat model STRIDE

## Asset

- Vendor, Tenant, Operator e Session Secret.
- Local Data Key e dati locali cifrati.
- Installation identity e grants.
- ConnectorVersion e deployment attivi.
- Admin identities e audit trail.
- Payload applicativi in transito.
- Artefatti di release e plugin.

## Attori e livelli di fiducia

- Operator legittimo.
- Application legacy autorizzata, considerata potenzialmente vulnerabile.
- Processo locale non autorizzato/malware same-user.
- Amministratore locale/SYSTEM.
- Local Broker e Gateway trusted computing base.
- Amministratore della piattaforma con ruolo limitato.
- Insider privilegiato/collusivo.
- Servizio esterno e rete non fidati.
- Pipeline e publisher degli artefatti.

## Matrice delle minacce

| ID | Categoria | Scenario | Controlli | Stato/residuo |
|---|---|---|---|---|
| TM-001 | S/E | Legacy compromesso invoca operation lecite per scopo malevolo. | Operation grants, payload constraints, rate limit, audit. | Parziale: può abusare delle capability legittime. |
| TM-002 | S/E | Malware same-user apre la pipe. | Pipe ACL, PID, handle, path, publisher/hash, manifest. | Parziale: injection nell'app autorizzata resta possibile. |
| TM-003 | S | Nome processo o registration ID falsificati. | Identità composita e manifest service-only. | Mitigato contro processi non privilegiati. |
| TM-004 | I/D | Copia di DB/blob locali. | ACL, DPAPI CurrentUser, AES-GCM per Installation. | Mitigato; perdita profilo impatta recovery. |
| TM-005 | T/E | Sostituzione Broker o DLL. | Program Files ACL, Authenticode, installer firmato. | Admin/SYSTEM fuori scope forte. |
| TM-006 | S | Clonazione della Installation. | CNG non esportabile, PoP, registry e reinstall enrollment. | Mitigato salvo clone completo con privilegi elevati. |
| TM-007 | S/R | Replay di richiesta Gateway. | Timestamp, nonce, body hash, ECDSA signature, idempotency. | Mitigato entro limiti di cache/clock. |
| TM-008 | S/E | Client dichiara altro Tenant/Installation. | Identità derivata dal certificato; campi ignorati/rifiutati. | Mitigato. |
| TM-009 | I/E | Query cross-Tenant per bug. | Composite FK, RLS, query filters, negative tests. | Mitigato con defense in depth. |
| TM-010 | I | Furto database Gateway. | Nessun secret value, encryption at rest, DB roles. | Metadata/audit restano sensibili. |
| TM-011 | I/E | Gateway compromesso usa Vault. | Managed Identity least privilege, secret scope, alert e rotation. | Parziale: TCB compromessa. |
| TM-012 | I/E | Vault compromesso. | RBAC, versioning, network restriction, audit e revocation. | Rischio residuo esterno alla piattaforma. |
| TM-013 | E/I | SSRF verso rete privata/metadata. | Config server-side, DNS/IP validation, no redirect, restricted client. | Mitigato; eccezioni private richiedono review. |
| TM-014 | T | Header/path injection. | Typed builder, encoding, allowlist e limits. | Mitigato. |
| TM-015 | T/I | XXE, entity expansion o signature wrapping. | Parser sicuro, limits, schema, ID uniqueness e tests. | Mitigato per moduli implementati. |
| TM-016 | E | Plugin malevolo. | Pipeline-only, CMS signature, publisher allowlist, review. | Parziale: plugin in-process è full-trust. |
| TM-017 | T/E | Update o MSI manomesso/rollback. | Signature, manifest, anti-rollback e secure updater. | MVP manuale; completo in hardening. |
| TM-018 | I/R | Secret o PII nei log. | Structured redaction, prohibited-field tests e scanning. | Mitigato; nuove integrazioni richiedono test. |
| TM-019 | E | Insider pubblica endpoint o binding malevolo. | RBAC, four-eyes, security validation e audit append-only. | Collusione privilegiata resta residua. |
| TM-020 | D | Flood IPC o Gateway. | Concurrency, size/time/rate limits e circuit breaker. | DDoS volumetrico richiede protezione infrastrutturale. |
| TM-021 | R | Operator nega un'operazione. | Correlation e audit metadata. | Non equivale a firma legale dell'Operator. |
| TM-022 | I | Backup rubato. | Stesse protezioni del dato, Vault escluso dal DB, backup encryption. | Metadata exposure residua. |
| TM-023 | T/E | Versione Draft/Retired o cache stale invocata dopo revoca. | Published-only catalog, stamp store a ogni invoke, TTL, invalidazione e no stale-on-error. | PostgreSQL indisponibile causa fail-closed/disponibilità ridotta. |
| TM-024 | T/R | Publish concorrenti o modifica di una versione già Published. | Row version, publication revision, unique Published e trigger DB di immutabilità. | Un amministratore DB privilegiato resta parte della TCB. |
| TM-025 | I/E | Connector/export/client seleziona URI o provider reference arbitrari. | Definition solo logica, binding server-side, export senza binding, runtime request chiusa. | Un amministratore binding autorizzato può configurare destinazioni approvate errate. |

## Analisi degli scenari obbligatori

### Amministratore locale/SYSTEM

Non è una minaccia completamente mitigata. Può sostituire binari, effettuare debugging, leggere memoria o abusare di un processo autorizzato. Il prodotto dichiara esplicitamente questo limite e protegge soprattutto contro processi non privilegiati, malware same-user non iniettato e furto offline.

### Cross-Tenant

Il client non fornisce un Tenant autorevole. Certificato/SPKI → Installation → Tenant costituisce la catena server-side. Composite foreign key e RLS impediscono associazioni incoerenti anche in presenza di errori applicativi.

### Gateway/Vault compromise

Il Gateway è trusted computing base e necessariamente vede temporaneamente i segreti che usa. Si riduce il blast radius con Managed Identity, permission per namespace, memoria breve, niente persistence/log e rotazione. Non è possibile dichiarare la minaccia eliminata.

### Plugin

La firma prova provenienza, non innocuità. Un plugin approvato viene trattato come parte del Gateway. Plugin third-party non fidati richiederebbero processo/container isolato e non sono supportati nell'MVP.

### Insider amministrativo

M4 applica autenticazione al confine Admin, optimistic concurrency, immutabilità e audit redatto, ma il Core non implementa ancora four-eyes. Il Deployment Pack di produzione deve aggiungere OIDC/RBAC e separazione editor/approver. Un amministratore autorizzato dei binding può comunque deviare traffico verso una destinazione permessa: review e audit restano necessari.

## Criteri di revisione

Il threat model deve essere riesaminato quando:

- viene aggiunto un auth/protocol adapter;
- compare un nuovo execution handoff ibrido;
- si modifica enrollment/recovery;
- si accettano plugin third-party;
- cambia hosting o TLS termination;
- si introduce persistenza di payload o Operator Secret;
- viene selezionato un pilot reale.

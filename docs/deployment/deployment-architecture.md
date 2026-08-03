# Deployment e packaging

## Local Broker

### Artefatti

- Windows service x64.
- MSI WiX Toolset 7 firmabile.
- SDK .NET NuGet.
- DLL C ABI e COM x86/x64.
- CLI e diagnostics tool.
- Application manifest e configuration template.
- Migration/repair tool e documentazione unattended install.

### Installazione

L'MSI:

1. verifica versione Windows e prerequisiti;
2. installa binari in Program Files;
3. crea virtual service account/service SID e local group client;
4. crea ProgramData e ACL esplicite;
5. registra il servizio con delayed automatic start e recovery policy;
6. inizializza metadata senza creare segreti vendor;
7. installa manifest Application solo se firmati/forniti dal package;
8. esegue health check locale;
9. effettua rollback completo in caso di errore.

Upgrade conserva state, CNG key e DPAPI blob. Downgrade non compatibile è rifiutato; rollback usa il precedente MSI solo se la matrice storage/protocol lo consente.

### File permission

- Program Files: read/execute utenti autorizzati, write TrustedInstaller/Administrators.
- ProgramData config non sensibile: read service/admin.
- State/keys/cache/audit: service, SYSTEM e Administrators; nessun client diretto.
- Pipe: service + local client group, con autorizzazione applicativa ulteriore.

## Gateway container

- Multi-stage build pinned su .NET 10.
- Runtime image chiseled/minimal, non-root e read-only filesystem.
- Solo directory temporanea dedicata scrivibile.
- Nessun shell/tool di build nell'immagine runtime.
- `/health/live` non controlla dipendenze.
- `/health/ready` controlla DB, Vault metadata e cache config, senza invocare servizi esterni costosi.
- Migrazioni database come tool/job distinto, non all'avvio.

## Azure production profile

| Componente | Scelta |
|---|---|
| Compute | Linux Azure App Service for Containers, Premium plan per production. |
| Registry | Azure Container Registry con immutable tags/repository policy. |
| Vault | Azure Key Vault, RBAC e Managed Identity. |
| Database | PostgreSQL Flexible Server 18, zone-redundant per profilo critical. |
| Network | VNet integration, DB private access/firewall, Vault network policy. |
| Observability | Application Insights + Log Analytics dopo redaction. |
| IaC | Bicep modules e environment parameter files. |
| Identity | User-assigned Managed Identity per Environment. |

App Service ha client certificate mode opzionale a livello TLS per permettere enrollment/Admin sullo stesso processo; le runtime route richiedono certificate authentication applicativa e request signature. Nel self-hosted si usano listener Kestrel distinti.

### Environment isolation

- Subscription o resource group separati per dev/test/preprod/prod.
- Key Vault e Managed Identity distinti.
- Nessuna promozione copiando secret value; si promuovono logical binding e si predispone il valore nel Vault target.
- Database distinti; fixture sintetiche soltanto fuori produzione.
- ConnectorVersion promossa mantenendo checksum e provenance.

### Private Endpoint e WAF

- Private Endpoint per DB/Vault raccomandato nel profilo regulated/critical, non obbligatorio per lo sviluppo.
- WAF/Front Door viene introdotto quando esiste un requisito DDoS, geo-routing o public Admin exposure; non sostituisce l'autenticazione del Gateway.

## Self-hosted

Docker Compose di sviluppo/valutazione:

- Gateway;
- PostgreSQL 18;
- mock external service;
- opzionale OpenTelemetry collector.

Il provider produttivo iniziale resta Azure Key Vault. Su infrastruttura non Azure, la credenziale di accesso al Vault viene fornita tramite workload identity/federation o secret esterno al repository. Il LocalDevelopment provider rifiuta `Production`.

## Bicep modules

```text
/deploy/azure-bicep
  main.bicep
  modules/app-service.bicep
  modules/container-registry.bicep
  modules/key-vault.bicep
  modules/postgresql.bicep
  modules/observability.bicep
  modules/network.bicep
  environments/*.bicepparam
```

What-if, lint e policy check precedono ogni apply. Output sensibili non vengono stampati dalla pipeline.

## Release e signing

- Build unsigned ripetibile disponibile senza credenziali esterne.
- Pipeline production firma PE/MSI/NuGet con certificato custodito esternamente.
- Container firmato Cosign con OIDC/keyless o chiave del cliente.
- Plugin/Connector Pack con detached CMS signature.
- SBOM SPDX JSON e CycloneDX JSON.
- Release manifest: versione, commit, toolchain, artifact hash, signature, SBOM e compatibility.

## Rollout

1. Migration expand compatibile.
2. Deploy preprod e smoke/security tests.
3. Production slot/canary con readiness.
4. Switch controllato e monitoraggio error rate/latency.
5. Rollback immagine se necessario; schema resta backward-compatible.
6. Connector deployment e rollback sono indipendenti dall'immagine.

## Backup e DR

- PostgreSQL PITR retention predefinita 35 giorni in produzione.
- Backup/restore test periodico in Environment isolato.
- Key Vault soft delete e purge protection in produzione.
- Bicep e Connector definitions consentono ricostruzione del control plane.
- Local Broker recovery segue ADR-0014.
- RPO/RTO contrattuali vengono fissati prima del pilot; il profilo critical abilita HA zone-redundant e strategia cross-region.


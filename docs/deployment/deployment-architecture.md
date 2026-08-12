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

- Multi-stage build pinned sulla patch .NET approvata tramite tag esatto e digest
  della manifest list; i tag mobili non sono ammessi.
- Runtime image chiseled/minimal, non-root e read-only filesystem.
- Solo directory temporanea dedicata scrivibile.
- Nessun shell/tool di build nell'immagine runtime.
- `/health/live` non controlla dipendenze.
- `/health/ready` controlla DB, Vault metadata e cache config, senza invocare servizi esterni costosi.
- Migrazioni database come tool/job distinto, non all'avvio.

### Provenance delle base image .NET

`global.json` seleziona SDK `10.0.302` con `rollForward: latestPatch`. Un tag mobile
come `sdk:10.0` può spostarsi a una feature band successiva e rendere il build
deterministicamente non eseguibile anche quando commit e lock file non cambiano. Per
questo ogni `FROM mcr.microsoft.com/dotnet/...` deve usare insieme un tag patch
leggibile e il digest della manifest list nel formato
`repository:exact-tag@sha256:manifest-list-digest`; il tag senza digest e il digest
senza tag sono entrambi vietati.

Pin approvati:

| Famiglia | Riferimento |
|---|---|
| SDK non-Alpine | `mcr.microsoft.com/dotnet/sdk:10.0.302@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0` |
| SDK Alpine | `mcr.microsoft.com/dotnet/sdk:10.0.302-alpine3.24@sha256:979da27fc87dc255f4675b7642556cdcba9307459f8891f85f3cc26edcd7e766` |
| ASP.NET non-Alpine | `mcr.microsoft.com/dotnet/aspnet:10.0.11@sha256:207cc51496778557731c81ff670333d8ade4a4fec22768fd1be8e78474a84ecf` |
| Runtime non-Alpine | `mcr.microsoft.com/dotnet/runtime:10.0.11@sha256:acad02eb5c4fbf57d15296f9c08d56cd4036e915bdae5b4dd48a06523d452617` |
| ASP.NET Alpine | `mcr.microsoft.com/dotnet/aspnet:10.0.11-alpine3.24@sha256:c4b29bf368004ad9076c1ab9bc91fb373561e3905b4345637e14e8b8c57e3be8` |
| Runtime Alpine | `mcr.microsoft.com/dotnet/runtime:10.0.11-alpine3.24@sha256:216f4e2027da6ae806e0bc4b448669ac0faa00125908e308f31dd70598e58136` |

`eng/validate-container-base-images.ps1` è il controllo canonico fail-closed. L'inventario
repository ammesso è esattamente: `src/Gateway/Gateway.Api/Dockerfile`,
`src/Gateway/Gateway.Migrations/Dockerfile`, `packs/deployment/azure/Dockerfile`,
`tools/m3/VendorMock/Dockerfile`, `tools/m3/SyntheticVault/Dockerfile` e
`tools/m3/Provisioner/Dockerfile`. Il confronto dei path Git-tracked è normalizzato,
ordinale ed esatto: un file mancante, aggiuntivo o ambiguo fallisce anche se non contiene
un `FROM` .NET. Il parser accetta soltanto `FROM [--platform=<literal>] <reference>
[AS <stage>]`; per i `FROM` .NET `--platform` è vietato e qualsiasi sintassi non parsata,
ARG o interpolazione fallisce. Restano obbligatori il mapping ordinato delle 12 occorrenze,
l'allowlist tag/digest e l'allineamento SDK con `global.json`.

`eng/build.ps1` esegue sempre il validator e la CI lo espone prima di ogni build container
interessato. Il job General `gateway-container` costruisce obbligatoriamente anche
`packs/deployment/azure/Dockerfile` con `--pull --no-cache`, applica la label
`org.opencontainers.image.revision` dell'exact candidate SHA e verifica sia label sia
image ID indipendentemente dalle immagini Gateway e Migrations.

### Aggiornamento intenzionale dei pin

1. Se cambia l'SDK, approvare prima la modifica separata di `global.json`; altrimenti
   il tag SDK deve mantenere esattamente `10.0.302`, inclusa ogni variante distro.
2. Interrogare MCR per il tag patch scelto e registrare il digest della manifest list,
   non il digest platform-specific. Verificare almeno tutte le architetture già
   supportate (`linux/amd64`, `linux/arm/v7`, `linux/arm64`).
3. Eseguire l'immagine con pull forzato e verificare `dotnet --version` oppure
   `dotnet --list-runtimes`. Aggiornare tag e digest insieme nei Dockerfile e
   nell'allowlist del validator nello stesso commit reviewable.
4. Eseguire `eng/validate-container-base-images.ps1 -SelfTest`, quindi costruire tutti
   i sei Dockerfile con `--pull` e, per la qualificazione, senza affidarsi soltanto
   alla cache locale.
5. Rieseguire non-root/read-only, health/readiness, shutdown, TLS, secret scan,
   vulnerability inventory, SBOM, cleanup e tutti i container/quick-start gate
   General e M5/Admin sulla nuova exact head.

Un nuovo Dockerfile Git-tracked richiede una modifica intenzionale dell'inventario e del
mapping nel validator, i relativi test end-to-end e la qualifica completa del nuovo build;
non può essere introdotto come file non ancora coperto dal controllo.

Non si usa `--pull=false`, non si installa una seconda SDK nel build e non si effettua
un rerun same-SHA per mascherare un drift già osservato. La failure main che motiva
l'aggiornamento resta parte dell'evidenza di release.

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
